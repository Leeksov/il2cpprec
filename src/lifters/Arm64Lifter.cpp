#include <il2cpprec/lifters/Arm64Lifter.hpp>

#include <capstone/arm64.h>

#include <cctype>
#include <cmath>
#include <cstring>
#include <utility>

namespace il2cpprec {
namespace {

ExpressionPtr floatingConstant(double value, ScalarType type) {
    if (type.bits == 32) {
        const auto narrowed = static_cast<float>(value);
        uint32_t bits = 0;
        std::memcpy(&bits, &narrowed, sizeof(bits));
        return constant(bits, type);
    }
    uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return constant(bits, type);
}

ExpressionPtr maskFor(uint16_t bits, ScalarType type) {
    const auto mask = bits >= 64 ? ~uint64_t{0} : (uint64_t{1} << bits) - 1;
    return constant(mask, type);
}

ExpressionPtr coerce(ExpressionPtr value, ScalarType type) {
    if (!value) return unknown(type);
    if (value->type.kind == type.kind && value->type.bits == type.bits) return value;
    return cast(std::move(value), type);
}

bool hasRegister(const Operand& operand) {
    return operand.kind == OperandKind::Register && !operand.reg.empty();
}

bool hasOperands(const NativeInstruction& instruction, size_t count) {
    return instruction.operands.size() >= count;
}

bool isVectorRegister(const Operand& operand) {
    return hasRegister(operand) && (operand.reg[0] == 'v' || operand.reg[0] == 'q');
}

bool hasVectorRegister(const NativeInstruction& instruction) {
    for (const auto& operand : instruction.operands) {
        if (isVectorRegister(operand)) return true;
    }
    return false;
}

bool hasPreIndexWriteback(const NativeInstruction& instruction) {
    return instruction.text.find("]!") != std::string::npos;
}

bool hasExtendedRegisterOperand(const NativeInstruction& instruction) {
    return instruction.text.find(", sxt") != std::string::npos ||
        instruction.text.find(", uxt") != std::string::npos;
}

bool hasVectorLaneOperand(const NativeInstruction& instruction) {
    static constexpr const char* lanes[] = {".b[", ".h[", ".s[", ".d["};
    for (const auto* lane : lanes) {
        if (instruction.text.find(lane) != std::string::npos) return true;
    }
    return false;
}

struct VectorShape {
    uint16_t laneBits = 0;
    uint16_t laneCount = 0;
};

VectorShape vectorShape(const NativeInstruction& instruction) {
    if (!instruction.operands.empty()) {
        const auto& arrangement = instruction.operands[0].arrangement;
        const auto bits = static_cast<uint16_t>(arrangement.elementSize * 8);
        if ((bits == 8 || bits == 16 || bits == 32 || bits == 64) &&
            arrangement.elementCount != 0 && bits * arrangement.elementCount <= 128) {
            return {bits, arrangement.elementCount};
        }
    }
    const auto vector = instruction.text.find('v');
    if (vector == std::string::npos) return {};
    const auto dot = instruction.text.find('.', vector);
    if (dot == std::string::npos) return {};
    size_t end = dot + 1;
    uint16_t count = 0;
    while (end < instruction.text.size() && std::isdigit(static_cast<unsigned char>(instruction.text[end]))) {
        count = static_cast<uint16_t>(count * 10 + (instruction.text[end] - '0'));
        ++end;
    }
    if (count == 0 || end >= instruction.text.size()) return {};
    uint16_t bits = 0;
    switch (instruction.text[end]) {
    case 'b': bits = 8; break;
    case 'h': bits = 16; break;
    case 's': bits = 32; break;
    case 'd': bits = 64; break;
    default: return {};
    }
    if (count * bits > 128) return {};
    return {bits, count};
}

int vectorLaneIndex(const NativeInstruction& instruction) {
    const auto open = instruction.text.find('[');
    if (open == std::string::npos) return -1;
    size_t end = open + 1;
    int index = 0;
    while (end < instruction.text.size() && std::isdigit(static_cast<unsigned char>(instruction.text[end]))) {
        index = index * 10 + (instruction.text[end] - '0');
        ++end;
    }
    return end > open + 1 && end < instruction.text.size() && instruction.text[end] == ']' ? index : -1;
}

bool isControlFlow(uint32_t id) {
    return id == ARM64_INS_B || id == ARM64_INS_BR || id == ARM64_INS_BL || id == ARM64_INS_BLR ||
        id == ARM64_INS_RET || id == ARM64_INS_CBZ || id == ARM64_INS_CBNZ ||
        id == ARM64_INS_TBZ || id == ARM64_INS_TBNZ;
}

} // namespace

struct Arm64Lifter::RegisterInfo {
    std::string canonical;
    uint16_t bits = 64;
    bool floatingPoint = false;
    bool zero = false;
};

ScalarType Arm64Lifter::pointerType() { return ScalarType::pointer(64); }
ScalarType Arm64Lifter::uintType(uint16_t bits) { return ScalarType::uintBits(bits); }
ScalarType Arm64Lifter::intType(uint16_t bits) { return ScalarType::intBits(bits); }
ScalarType Arm64Lifter::floatType(uint16_t bits) { return ScalarType::floatBits(bits); }

Arm64Lifter::RegisterInfo Arm64Lifter::registerInfo(const std::string& name) const {
    if (name == "lr") return {"x30", 64};
    if (name == "fp") return {"x29", 64};
    if (name == "wsp") return {"sp", 32};
    if (name == "sp") return {"sp", 64};
    if (name == "wzr") return {"zr", 32, false, true};
    if (name == "xzr") return {"zr", 64, false, true};
    if (name.size() > 1 && std::isdigit(static_cast<unsigned char>(name[1]))) {
        const auto suffix = name.substr(1);
        switch (name[0]) {
        case 'w': return {'x' + suffix, 32};
        case 'x': return {name, 64};
        case 'b': return {'v' + suffix, 8};
        case 'h': return {'v' + suffix, 16};
        case 's': return {'v' + suffix, 32, true};
        case 'd': return {'v' + suffix, 64, true};
        case 'q':
        case 'v': return {'v' + suffix, 128};
        default: break;
        }
    }
    return {name, 64};
}

ExpressionPtr Arm64Lifter::rawVector(const RegisterInfo& info) const {
    return reg(info.canonical, ScalarType::vectorBits(128));
}

ExpressionPtr Arm64Lifter::rawToFloat(ExpressionPtr value, uint16_t bits) const {
    if (bits != 32 && bits != 64) return unknown(floatType(bits));
    value = coerce(std::move(value), uintType(bits));
    return unary(bits == 32 ? "global::System.BitConverter.UInt32BitsToSingle" :
        "global::System.BitConverter.UInt64BitsToDouble", std::move(value), floatType(bits));
}

ExpressionPtr Arm64Lifter::floatToRaw(ExpressionPtr value, uint16_t bits) const {
    if (bits != 32 && bits != 64) return unknown(uintType(bits));
    value = coerce(std::move(value), floatType(bits));
    return unary(bits == 32 ? "global::System.BitConverter.SingleToUInt32Bits" :
        "global::System.BitConverter.DoubleToUInt64Bits", std::move(value), uintType(bits));
}

ExpressionPtr Arm64Lifter::readRegister(const std::string& name) const {
    const auto info = registerInfo(name);
    if (info.zero) return constant(0, uintType(info.bits));
    if (info.canonical.size() > 1 && info.canonical[0] == 'v') {
        auto value = rawVector(info);
        if (info.bits == 128) return value;
        value = cast(value, uintType(64));
        if (info.bits < 64) value = cast(value, uintType(info.bits));
        return info.floatingPoint ? rawToFloat(std::move(value), info.bits) : value;
    }
    const auto value = reg(info.canonical, pointerType());
    return info.bits < 64 ? cast(value, uintType(info.bits)) : value;
}

Statement Arm64Lifter::assignRegister(const Operand& destination, ExpressionPtr value) const {
    const auto info = registerInfo(destination.reg);
    Statement result;
    result.kind = Statement::Kind::Assign;
    if (info.canonical.size() > 1 && info.canonical[0] == 'v') {
        result.destination = rawVector(info);
        if (info.floatingPoint) value = floatToRaw(std::move(value), info.bits);
        if (info.bits < 64) value = coerce(std::move(value), uintType(info.bits));
        result.value = coerce(std::move(value), ScalarType::vectorBits(128));
        return result;
    }
    result.destination = reg(info.canonical, pointerType());
    if (info.bits < 64) value = coerce(std::move(value), uintType(info.bits));
    result.value = coerce(std::move(value), pointerType());
    return result;
}

bool Arm64Lifter::addAssignment(const Operand& destination, ExpressionPtr value) {
    if (!hasRegister(destination) || !value) return false;
    const auto info = registerInfo(destination.reg);
    if (info.zero) return true;
    add(assignRegister(destination, std::move(value)));
    return true;
}

bool Arm64Lifter::addVectorAssignment(const Operand& destination, ExpressionPtr value) {
    if (!hasRegister(destination)) return false;
    const auto info = registerInfo(destination.reg);
    if (info.canonical.size() <= 1 || info.canonical[0] != 'v') return false;
    Statement statement;
    statement.kind = Statement::Kind::Assign;
    statement.destination = rawVector(info);
    statement.value = coerce(std::move(value), ScalarType::vectorBits(128));
    add(std::move(statement));
    return true;
}

ExpressionPtr Arm64Lifter::replicateLane(ExpressionPtr value, uint16_t bits, uint16_t laneCount) const {
    if (laneCount == 0 || (bits != 8 && bits != 16 && bits != 32 && bits != 64) || bits * laneCount > 128) {
        return unknown(ScalarType::vectorBits(128));
    }
    value = coerce(std::move(value), uintType(bits));
    auto result = coerce(std::move(value), ScalarType::vectorBits(128));
    const auto vectorType = ScalarType::vectorBits(128);
    for (uint16_t shift = bits; shift < bits * laneCount; shift = static_cast<uint16_t>(shift * 2)) {
        result = binary("|", result, binary("<<", result, constant(shift, intType(32)), vectorType), vectorType);
    }
    return result;
}

ExpressionPtr Arm64Lifter::unsignedMultiplyHigh(ExpressionPtr left, ExpressionPtr right) const {
    const auto u64 = uintType(64);
    const auto u32 = uintType(32);
    left = coerce(std::move(left), u64);
    right = coerce(std::move(right), u64);
    const auto low32 = [u32](ExpressionPtr value) { return coerce(std::move(value), u32); };
    const auto high32 = [u64, u32](ExpressionPtr value) {
        return binary(">>", std::move(value), constant(32, u32), u64);
    };
    auto a0 = coerce(low32(left), u64);
    auto a1 = high32(left);
    auto b0 = coerce(low32(right), u64);
    auto b1 = high32(right);
    auto p00 = binary("*", a0, b0, u64);
    auto p01 = binary("*", a0, b1, u64);
    auto p10 = binary("*", a1, b0, u64);
    auto p11 = binary("*", a1, b1, u64);
    auto middle = binary("+", high32(p00), binary("+", coerce(low32(p01), u64), coerce(low32(p10), u64), u64), u64);
    auto result = binary("+", p11, high32(middle), u64);
    result = binary("+", result, high32(p01), u64);
    result = binary("+", result, high32(p10), u64);
    return result;
}

ScalarType Arm64Lifter::operandType(const Operand& operand, ScalarType fallback) const {
    if (operand.kind == OperandKind::Register) {
        const auto info = registerInfo(operand.reg);
        if (info.bits == 128) return ScalarType::vectorBits(128);
        return info.floatingPoint ? floatType(info.bits) : uintType(info.bits);
    }
    if (operand.kind == OperandKind::FloatingPoint) {
        if (fallback.kind == ScalarKind::FloatingPoint && fallback.bits != 0) return fallback;
        return floatType(operand.size ? static_cast<uint16_t>(operand.size * 8) : 64);
    }
    if (fallback.bits != 0) return fallback;
    return operand.size ? uintType(static_cast<uint16_t>(operand.size * 8)) : pointerType();
}

ExpressionPtr Arm64Lifter::applyShift(ExpressionPtr value, const Shift& shift) const {
    if (shift.type == ARM64_SFT_INVALID || shift.value == 0) return value;
    const auto bits = value->type.bits == 0 ? uint16_t{64} : value->type.bits;
    const auto amountValue = shift.value;
    if (amountValue >= bits || bits > 64) {
        return unary("unsupported_arm64_shift", value, value->type);
    }
    const auto amount = constant(amountValue, uintType(bits));
    const auto unsignedValue = coerce(value, uintType(bits));
    switch (shift.type) {
    case ARM64_SFT_LSL:
        return binary("<<", unsignedValue, amount, uintType(bits));
    case ARM64_SFT_MSL: {
        const auto lowMask = (uint64_t{1} << amountValue) - 1;
        return binary("|", binary("<<", unsignedValue, amount, uintType(bits)), constant(lowMask, uintType(bits)), uintType(bits));
    }
    case ARM64_SFT_LSR:
        return binary(">>", unsignedValue, amount, uintType(bits));
    case ARM64_SFT_ASR:
        return binary(">>", cast(unsignedValue, intType(bits)), amount, intType(bits));
    case ARM64_SFT_ROR: {
        const auto right = binary(">>", unsignedValue, amount, uintType(bits));
        const auto left = binary("<<", unsignedValue, constant(bits - amountValue, uintType(bits)), uintType(bits));
        return binary("|", right, left, uintType(bits));
    }
    default:
        return unary("unsupported_arm64_shift", value, value->type);
    }
}

ExpressionPtr Arm64Lifter::valueOf(const Operand& operand, ScalarType fallback) const {
    const auto type = operandType(operand, fallback);
    ExpressionPtr value;
    switch (operand.kind) {
    case OperandKind::Register:
        value = readRegister(operand.reg);
        break;
    case OperandKind::Immediate:
        value = constant(static_cast<uint64_t>(operand.immediate), type);
        break;
    case OperandKind::Memory:
        value = load(addressOf(operand), type);
        break;
    case OperandKind::FloatingPoint:
        value = floatingConstant(operand.floatingPoint, type);
        break;
    }
    if (!value) return unknown(type);
    if (fallback.bits != 0 && operand.kind != OperandKind::Memory) value = coerce(value, fallback);
    return applyShift(value, operand.shift);
}

ExpressionPtr Arm64Lifter::addressOf(const Operand& operand) const {
    ExpressionPtr address;
    if (!operand.memoryBase.empty()) address = coerce(readRegister(operand.memoryBase), pointerType());
    if (!operand.memoryIndex.empty()) {
        auto index = readRegister(operand.memoryIndex);
        index = applyShift(index, operand.shift);
        index = coerce(index, pointerType());
        if (operand.scale != 1) {
            index = binary("*", index, constant(static_cast<uint64_t>(operand.scale), pointerType()), pointerType());
        }
        address = address ? binary("+", address, index, pointerType()) : index;
    }
    if (operand.displacement != 0 || !address) {
        const auto displacement = constant(static_cast<uint64_t>(operand.displacement), pointerType());
        address = address ? binary("+", address, displacement, pointerType()) : displacement;
    }
    return address ? address : constant(0, pointerType());
}

void Arm64Lifter::add(Statement statement) {
    statement.address = instructionAddress_;
    statements_->push_back(std::move(statement));
}

void Arm64Lifter::addStore(ExpressionPtr address, ExpressionPtr value) {
    Statement statement;
    statement.kind = Statement::Kind::Store;
    statement.destination = std::move(address);
    statement.value = std::move(value);
    add(std::move(statement));
}

void Arm64Lifter::addUnsupported(const NativeInstruction& instruction) {
    Statement statement;
    statement.kind = Statement::Kind::Call;
    const auto mnemonic = instruction.mnemonic.empty() ? std::string("unknown") : instruction.mnemonic;
    statement.target = reg("RuntimeCalls.Unsupported_" + mnemonic, pointerType());
    statement.arguments = {constant(instruction.address, pointerType())};
    add(std::move(statement));
}

ExpressionPtr Arm64Lifter::saveTemporary(const char* role, ExpressionPtr value) {
    if (!value) value = unknown(pointerType());
    auto destination = reg("__arm64_" + std::string(role) + "_" + std::to_string(instructionAddress_), value->type);
    Statement statement;
    statement.kind = Statement::Kind::Assign;
    statement.destination = destination;
    statement.value = std::move(value);
    add(std::move(statement));
    return destination;
}

void Arm64Lifter::addWriteback(const Operand& memory, const Operand& offset) {
    if (memory.kind != OperandKind::Memory || memory.memoryBase.empty() || offset.kind != OperandKind::Immediate) return;
    const auto base = readRegister(memory.memoryBase);
    Operand destination;
    destination.kind = OperandKind::Register;
    destination.reg = memory.memoryBase;
    destination.size = 8;
    addAssignment(destination, binary("+", base, constant(static_cast<uint64_t>(offset.immediate), pointerType()), pointerType()));
}

void Arm64Lifter::addInstructionWriteback(const NativeInstruction& instruction, size_t memoryIndex, size_t offsetIndex, ExpressionPtr savedAddress) {
    const auto& memory = instruction.operands[memoryIndex];
    const bool preIndex = hasPreIndexWriteback(instruction);
    if (!preIndex && instruction.operands.size() <= offsetIndex) return;
    if (savedAddress) {
        ExpressionPtr value = savedAddress;
        if (!preIndex) {
            const auto& offset = instruction.operands[offsetIndex];
            if (offset.kind != OperandKind::Immediate) return;
            value = binary("+", savedAddress, constant(static_cast<uint64_t>(offset.immediate), pointerType()), pointerType());
        }
        Operand destination;
        destination.kind = OperandKind::Register;
        destination.reg = memory.memoryBase;
        destination.size = 8;
        addAssignment(destination, value);
        return;
    }
    if (preIndex) {
        Operand offset;
        offset.kind = OperandKind::Immediate;
        offset.immediate = memory.displacement;
        addWriteback(memory, offset);
    } else {
        addWriteback(memory, instruction.operands[offsetIndex]);
    }
}

void Arm64Lifter::addBranch(const NativeInstruction& instruction, ExpressionPtr branchCondition) {
    Statement statement;
    statement.kind = branchCondition ? Statement::Kind::ConditionalBranch : Statement::Kind::Branch;
    statement.condition = std::move(branchCondition);
    const auto& target = instruction.operands.back();
    statement.target = target.kind == OperandKind::Immediate
        ? constant(static_cast<uint64_t>(target.immediate), pointerType())
        : coerce(valueOf(target, pointerType()), pointerType());
    add(std::move(statement));
}

void Arm64Lifter::addCall(const NativeInstruction& instruction) {
    const auto& targetOperand = instruction.operands.back();
    ExpressionPtr target;
    if (targetOperand.kind == OperandKind::Immediate) {
        target = constant(static_cast<uint64_t>(targetOperand.immediate), pointerType());
    } else {
        target = saveTemporary("call_target", coerce(valueOf(targetOperand, pointerType()), pointerType()));
    }

    Operand linkRegister;
    linkRegister.kind = OperandKind::Register;
    linkRegister.reg = "x30";
    linkRegister.size = 8;
    addAssignment(linkRegister, constant(instructionAddress_ + instructionSize_, pointerType()));

    Statement statement;
    statement.kind = Statement::Kind::Call;
    statement.destination = reg("x0", pointerType());
    statement.target = std::move(target);
    for (int index = 0; index < 8; ++index) {
        statement.arguments.push_back(readRegister('x' + std::to_string(index)));
    }
    add(std::move(statement));
}

void Arm64Lifter::invalidateFlags() {
    flagsLeft_.reset();
    flagsRight_.reset();
    flagsResult_.reset();
    flagsKind_ = FlagsKind::None;
    floatingPointFlags_ = false;
    conditionalCondition_.reset();
    conditionalNzcv_ = 0;
}

void Arm64Lifter::setCompareOperands(ExpressionPtr left, ExpressionPtr right, bool floatingPoint) {
    flagsLeft_ = std::move(left);
    flagsRight_ = std::move(right);
    floatingPointFlags_ = floatingPoint;
    flagsKind_ = floatingPoint ? FlagsKind::None : FlagsKind::Subtract;
    if (!flagsLeft_ || !flagsRight_ || floatingPoint) {
        flagsResult_.reset();
        if (!floatingPoint) flagsKind_ = FlagsKind::None;
    } else {
        const auto bits = flagsLeft_->type.bits == 0 ? uint16_t{64} : flagsLeft_->type.bits;
        const auto type = uintType(bits);
        flagsResult_ = binary("-", coerce(flagsLeft_, type), coerce(flagsRight_, type), type);
    }
    conditionalCondition_.reset();
    conditionalNzcv_ = 0;
}

void Arm64Lifter::setAddCompare(ExpressionPtr left, ExpressionPtr right) {
    flagsLeft_ = std::move(left);
    flagsRight_ = std::move(right);
    floatingPointFlags_ = false;
    flagsKind_ = FlagsKind::Add;
    if (!flagsLeft_ || !flagsRight_) {
        flagsResult_.reset();
        flagsKind_ = FlagsKind::None;
    } else {
        const auto bits = flagsLeft_->type.bits == 0 ? uint16_t{64} : flagsLeft_->type.bits;
        const auto type = uintType(bits);
        flagsResult_ = binary("+", coerce(flagsLeft_, type), coerce(flagsRight_, type), type);
    }
    conditionalCondition_.reset();
    conditionalNzcv_ = 0;
}

void Arm64Lifter::setLogicalCompare(ExpressionPtr result) {
    if (!result) {
        invalidateFlags();
        return;
    }
    const auto bits = result->type.bits == 0 ? uint16_t{64} : result->type.bits;
    flagsResult_ = coerce(std::move(result), uintType(bits));
    flagsLeft_ = flagsResult_;
    flagsRight_ = constant(0, uintType(bits));
    flagsKind_ = FlagsKind::Logical;
    floatingPointFlags_ = false;
    conditionalCondition_.reset();
    conditionalNzcv_ = 0;
}

void Arm64Lifter::setConditionalCompare(ExpressionPtr left, ExpressionPtr right, uint32_t conditionCode, uint8_t nzcv, bool addition) {
    auto precedingCondition = condition(conditionCode);
    if (addition) {
        setAddCompare(std::move(left), std::move(right));
    } else {
        setCompareOperands(std::move(left), std::move(right));
    }
    conditionalCondition_ = std::move(precedingCondition);
    conditionalNzcv_ = nzcv;
}

bool Arm64Lifter::conditionAvailable(uint32_t conditionCode) const {
    if (conditionCode == ARM64_CC_AL || conditionCode == ARM64_CC_NV) return true;
    if (!flagsLeft_ || !flagsRight_) return false;
    return floatingPointFlags_ || (flagsResult_ && flagsKind_ != FlagsKind::None);
}

ExpressionPtr Arm64Lifter::integerCondition(uint32_t conditionCode) const {
    const auto boolean = ScalarType::boolean();
    if (conditionCode == ARM64_CC_AL || conditionCode == ARM64_CC_NV) return constant(1, boolean);
    if (!conditionAvailable(conditionCode) || floatingPointFlags_) return unknown(boolean);

    const auto bits = flagsResult_->type.bits == 0 ? uint16_t{64} : flagsResult_->type.bits;
    const auto type = uintType(bits);
    const auto signedType = intType(bits);
    const auto result = coerce(flagsResult_, type);
    const auto left = coerce(flagsLeft_, type);
    const auto right = coerce(flagsRight_, type);
    const auto isNegative = [boolean, signedType](ExpressionPtr value) {
        const auto valueBits = value->type.bits;
        auto raw = coerce(std::move(value), uintType(valueBits));
        return binary("<", cast(std::move(raw), signedType), constant(0, signedType), boolean);
    };
    const auto n = isNegative(result);
    const auto z = binary("==", result, constant(0, type), boolean);
    ExpressionPtr c;
    ExpressionPtr v;
    if (flagsKind_ == FlagsKind::Logical) {
        c = constant(0, boolean);
        v = constant(0, boolean);
    } else {
        const auto leftNegative = isNegative(left);
        const auto resultNegative = isNegative(result);
        if (flagsKind_ == FlagsKind::Subtract) {
            c = binary(">=", left, right, boolean);
            const auto rightNegative = isNegative(right);
            v = binary("&&", binary("!=", leftNegative, rightNegative, boolean),
                binary("!=", resultNegative, leftNegative, boolean), boolean);
        } else {
            c = binary("<", result, left, boolean);
            const auto rightNegative = isNegative(right);
            v = binary("&&", binary("==", leftNegative, rightNegative, boolean),
                binary("!=", resultNegative, leftNegative, boolean), boolean);
        }
    }

    switch (conditionCode) {
    case ARM64_CC_EQ: return z;
    case ARM64_CC_NE: return unary("!", z, boolean);
    case ARM64_CC_HS: return c;
    case ARM64_CC_LO: return unary("!", c, boolean);
    case ARM64_CC_MI: return n;
    case ARM64_CC_PL: return unary("!", n, boolean);
    case ARM64_CC_VS: return v;
    case ARM64_CC_VC: return unary("!", v, boolean);
    case ARM64_CC_HI: return binary("&&", c, unary("!", z, boolean), boolean);
    case ARM64_CC_LS: return binary("||", unary("!", c, boolean), z, boolean);
    case ARM64_CC_GE: return binary("==", n, v, boolean);
    case ARM64_CC_LT: return binary("!=", n, v, boolean);
    case ARM64_CC_GT: return binary("&&", unary("!", z, boolean), binary("==", n, v, boolean), boolean);
    case ARM64_CC_LE: return binary("||", z, binary("!=", n, v, boolean), boolean);
    default: return unknown(boolean);
    }
}

ExpressionPtr Arm64Lifter::floatingCondition(uint32_t conditionCode) const {
    const auto boolean = ScalarType::boolean();
    if (conditionCode == ARM64_CC_AL || conditionCode == ARM64_CC_NV) return constant(1, boolean);
    if (!conditionAvailable(conditionCode) || !floatingPointFlags_) return unknown(boolean);
    const auto unordered = binary("||", binary("!=", flagsLeft_, flagsLeft_, boolean),
        binary("!=", flagsRight_, flagsRight_, boolean), boolean);
    const auto ordered = unary("!", unordered, boolean);
    switch (conditionCode) {
    case ARM64_CC_EQ: return binary("==", flagsLeft_, flagsRight_, boolean);
    case ARM64_CC_NE: return binary("||", binary("!=", flagsLeft_, flagsRight_, boolean), unordered, boolean);
    case ARM64_CC_HS: return binary("||", binary(">=", flagsLeft_, flagsRight_, boolean), unordered, boolean);
    case ARM64_CC_LO: return binary("<", flagsLeft_, flagsRight_, boolean);
    case ARM64_CC_MI: return binary("<", flagsLeft_, flagsRight_, boolean);
    case ARM64_CC_PL: return binary("||", binary(">=", flagsLeft_, flagsRight_, boolean), unordered, boolean);
    case ARM64_CC_VS: return unordered;
    case ARM64_CC_VC: return ordered;
    case ARM64_CC_HI: return binary("||", binary(">", flagsLeft_, flagsRight_, boolean), unordered, boolean);
    case ARM64_CC_LS: return binary("<=", flagsLeft_, flagsRight_, boolean);
    case ARM64_CC_GE: return binary(">=", flagsLeft_, flagsRight_, boolean);
    case ARM64_CC_LT: return binary("||", binary("<", flagsLeft_, flagsRight_, boolean), unordered, boolean);
    case ARM64_CC_GT: return binary(">", flagsLeft_, flagsRight_, boolean);
    case ARM64_CC_LE: return binary("||", binary("<=", flagsLeft_, flagsRight_, boolean), unordered, boolean);
    default: return unknown(boolean);
    }
}

ExpressionPtr Arm64Lifter::conditionFromNzcv(uint32_t conditionCode) const {
    const auto boolean = ScalarType::boolean();
    const auto flag = [this, boolean](uint8_t bit) {
        return constant((conditionalNzcv_ >> bit) & 1, boolean);
    };
    const auto n = flag(3);
    const auto z = flag(2);
    const auto c = flag(1);
    const auto v = flag(0);
    switch (conditionCode) {
    case ARM64_CC_EQ: return z;
    case ARM64_CC_NE: return unary("!", z, boolean);
    case ARM64_CC_HS: return c;
    case ARM64_CC_LO: return unary("!", c, boolean);
    case ARM64_CC_MI: return n;
    case ARM64_CC_PL: return unary("!", n, boolean);
    case ARM64_CC_VS: return v;
    case ARM64_CC_VC: return unary("!", v, boolean);
    case ARM64_CC_HI: return binary("&&", c, unary("!", z, boolean), boolean);
    case ARM64_CC_LS: return binary("||", unary("!", c, boolean), z, boolean);
    case ARM64_CC_GE: return binary("==", n, v, boolean);
    case ARM64_CC_LT: return binary("!=", n, v, boolean);
    case ARM64_CC_GT: return binary("&&", unary("!", z, boolean), binary("==", n, v, boolean), boolean);
    case ARM64_CC_LE: return binary("||", z, binary("!=", n, v, boolean), boolean);
    case ARM64_CC_AL:
    case ARM64_CC_NV: return constant(1, boolean);
    default: return unknown(boolean);
    }
}

ExpressionPtr Arm64Lifter::condition(uint32_t conditionCode) const {
    auto result = floatingPointFlags_ ? floatingCondition(conditionCode) : integerCondition(conditionCode);
    if (!conditionalCondition_ || conditionCode == ARM64_CC_AL || conditionCode == ARM64_CC_NV) return result;
    return select(conditionalCondition_, result, conditionFromNzcv(conditionCode), ScalarType::boolean());
}

bool Arm64Lifter::liftMove(const NativeInstruction& instruction) {
    const auto& ops = instruction.operands;
    switch (instruction.id) {
    case ARM64_INS_MOV:
    case ARM64_INS_MOVZ:
        if (!hasOperands(instruction, 2)) return false;
        if (hasVectorRegister(instruction)) return false;
        return addAssignment(ops[0], valueOf(ops[1], operandType(ops[0])));
    case ARM64_INS_MOVI: {
        if (!hasOperands(instruction, 2) || ops[1].kind != OperandKind::Immediate) return false;
        auto shape = vectorShape(instruction);
        if (shape.laneCount == 0 && ops[0].reg.size() > 1 && ops[0].reg[0] == 'd') shape = {64, 1};
        if (shape.laneCount == 0) return false;
        return addVectorAssignment(ops[0], replicateLane(valueOf(ops[1]), shape.laneBits, shape.laneCount));
    }
    case ARM64_INS_MOVN:
    case ARM64_INS_MVNI: {
        if (!hasOperands(instruction, 2) || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        return addAssignment(ops[0], unary("~", valueOf(ops[1], type), type));
    }
    case ARM64_INS_MOVK: {
        if (!hasOperands(instruction, 2) || ops[1].kind != OperandKind::Immediate || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        const auto bits = type.bits == 0 ? uint16_t{64} : type.bits;
        const auto shift = ops[1].shift.value;
        if (shift >= bits || shift % 16 != 0) return false;
        const auto fieldMask = uint64_t{0xFFFF} << shift;
        const auto oldValue = binary("&", readRegister(ops[0].reg), constant(~fieldMask, type), type);
        const auto newValue = binary("&", valueOf(ops[1], type), constant(fieldMask, type), type);
        return addAssignment(ops[0], binary("|", oldValue, newValue, type));
    }
    case ARM64_INS_ADR:
    case ARM64_INS_ADRP:
        if (!hasOperands(instruction, 2) || ops[1].kind != OperandKind::Immediate || hasVectorRegister(instruction)) return false;
        return addAssignment(ops[0], constant(static_cast<uint64_t>(ops[1].immediate), pointerType()));
    case ARM64_INS_FMOV: {
        if (!hasOperands(instruction, 2) || hasVectorRegister(instruction)) return false;
        const auto destinationType = operandType(ops[0]);
        const auto sourceType = operandType(ops[1]);
        const bool destinationFloating = destinationType.kind == ScalarKind::FloatingPoint;
        const bool sourceFloating = sourceType.kind == ScalarKind::FloatingPoint;
        if (!destinationFloating && !sourceFloating) return false;
        if (destinationFloating && sourceFloating) {
            if (ops[1].kind == OperandKind::FloatingPoint) {
                return addAssignment(ops[0], valueOf(ops[1], destinationType));
            }
            if (destinationType.bits != sourceType.bits) return false;
            return addAssignment(ops[0], valueOf(ops[1], destinationType));
        }
        if ((destinationType.bits != 32 && destinationType.bits != 64) ||
            sourceType.bits != destinationType.bits) return false;
        if (destinationFloating) {
            const auto raw = coerce(valueOf(ops[1]), uintType(destinationType.bits));
            const char* operation = destinationType.bits == 32
                ? "global::System.BitConverter.UInt32BitsToSingle"
                : "global::System.BitConverter.UInt64BitsToDouble";
            return addAssignment(ops[0], unary(operation, raw, destinationType));
        }
        const char* operation = sourceType.bits == 32
            ? "global::System.BitConverter.SingleToUInt32Bits"
            : "global::System.BitConverter.DoubleToUInt64Bits";
        return addAssignment(ops[0], unary(operation, valueOf(ops[1], sourceType), uintType(sourceType.bits)));
    }
    case ARM64_INS_DUP: {
        if (!hasOperands(instruction, 2) || !hasRegister(ops[1])) return false;
        const auto shape = vectorShape(instruction);
        if (shape.laneCount == 0) return false;
        const auto sourceInfo = registerInfo(ops[1].reg);
        ExpressionPtr source;
        const auto laneIndex = ops[1].laneIndex >= 0 ? ops[1].laneIndex : vectorLaneIndex(instruction);
        if (laneIndex >= 0) {
            if (sourceInfo.bits != 128 || laneIndex >= shape.laneCount) return false;
            source = readRegister(ops[1].reg);
            const auto shift = static_cast<uint16_t>(laneIndex * shape.laneBits);
            if (shift != 0) source = binary(">>", source, constant(shift, intType(32)), ScalarType::vectorBits(128));
            source = coerce(source, uintType(shape.laneBits));
        } else {
            if (sourceInfo.floatingPoint || sourceInfo.bits < shape.laneBits ||
                (sourceInfo.bits != 32 && sourceInfo.bits != 64)) return false;
            source = coerce(valueOf(ops[1]), uintType(shape.laneBits));
        }
        return addVectorAssignment(ops[0], replicateLane(source, shape.laneBits, shape.laneCount));
    }
    case ARM64_INS_UMOV:
    case ARM64_INS_SMOV:
        return false;
    default:
        return false;
    }
}

bool Arm64Lifter::liftArithmetic(const NativeInstruction& instruction) {
    const auto& ops = instruction.operands;
    switch (instruction.id) {
    case ARM64_INS_ADDS:
    case ARM64_INS_SUBS:
    case ARM64_INS_ANDS:
    case ARM64_INS_BICS: {
        if (!hasOperands(instruction, 3) || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        auto left = saveTemporary("flags_left", valueOf(ops[1], type));
        auto right = saveTemporary("flags_right", valueOf(ops[2], type));
        if (instruction.id == ARM64_INS_BICS) right = saveTemporary("flags_inverted", unary("~", right, type));
        ExpressionPtr value;
        if (instruction.id == ARM64_INS_ADDS) value = binary("+", left, right, type);
        else if (instruction.id == ARM64_INS_SUBS) value = binary("-", left, right, type);
        else value = binary("&", left, right, type);
        auto result = saveTemporary("flags_result", value);
        if (instruction.id == ARM64_INS_ADDS) setAddCompare(left, right);
        else if (instruction.id == ARM64_INS_SUBS) setCompareOperands(left, right);
        else setLogicalCompare(result);
        return addAssignment(ops[0], result);
    }
    case ARM64_INS_ADD:
    case ARM64_INS_SUB:
    case ARM64_INS_AND:
    case ARM64_INS_ORR:
    case ARM64_INS_EOR:
    case ARM64_INS_BIC:
    case ARM64_INS_ORN:
    case ARM64_INS_MUL:
    case ARM64_INS_SDIV:
    case ARM64_INS_UDIV: {
        if (!hasOperands(instruction, 3) || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        auto left = valueOf(ops[1], type);
        auto right = valueOf(ops[2], type);
        ExpressionPtr value;
        switch (instruction.id) {
        case ARM64_INS_ADD: value = binary("+", left, right, type); break;
        case ARM64_INS_SUB: value = binary("-", left, right, type); break;
        case ARM64_INS_AND: value = binary("&", left, right, type); break;
        case ARM64_INS_ORR: value = binary("|", left, right, type); break;
        case ARM64_INS_EOR: value = binary("^", left, right, type); break;
        case ARM64_INS_BIC: value = binary("&", left, unary("~", right, type), type); break;
        case ARM64_INS_ORN: value = binary("|", left, unary("~", right, type), type); break;
        case ARM64_INS_MUL: value = binary("*", left, right, type); break;
        case ARM64_INS_SDIV:
            value = binary("/", cast(left, intType(type.bits)), cast(right, intType(type.bits)), intType(type.bits));
            break;
        default:
            value = binary("/", cast(left, uintType(type.bits)), cast(right, uintType(type.bits)), uintType(type.bits));
            break;
        }
        return addAssignment(ops[0], std::move(value));
    }
    case ARM64_INS_SMULL:
    case ARM64_INS_UMULL: {
        if (!hasOperands(instruction, 3) || hasVectorRegister(instruction) ||
            operandType(ops[0]).bits != 64 || operandType(ops[1]).bits != 32 || operandType(ops[2]).bits != 32) return false;
        const bool isSigned = instruction.id == ARM64_INS_SMULL;
        const auto sourceType = isSigned ? intType(32) : uintType(32);
        const auto productType = isSigned ? intType(64) : uintType(64);
        auto left = cast(cast(valueOf(ops[1]), sourceType), productType);
        auto right = cast(cast(valueOf(ops[2]), sourceType), productType);
        return addAssignment(ops[0], binary("*", left, right, productType));
    }
    case ARM64_INS_SMULH:
    case ARM64_INS_UMULH: {
        if (!hasOperands(instruction, 3) || hasVectorRegister(instruction) ||
            operandType(ops[0]).bits != 64 || operandType(ops[1]).bits != 64 || operandType(ops[2]).bits != 64) return false;
        auto left = valueOf(ops[1], uintType(64));
        auto right = valueOf(ops[2], uintType(64));
        auto high = unsignedMultiplyHigh(left, right);
        if (instruction.id == ARM64_INS_SMULH) {
            const auto boolean = ScalarType::boolean();
            const auto signedLeft = cast(left, intType(64));
            const auto signedRight = cast(right, intType(64));
            const auto leftNegative = binary("<", signedLeft, constant(0, intType(64)), boolean);
            const auto rightNegative = binary("<", signedRight, constant(0, intType(64)), boolean);
            high = binary("-", high, select(leftNegative, right, constant(0, uintType(64)), uintType(64)), uintType(64));
            high = binary("-", high, select(rightNegative, left, constant(0, uintType(64)), uintType(64)), uintType(64));
        }
        return addAssignment(ops[0], high);
    }
    case ARM64_INS_MADD:
    case ARM64_INS_MSUB: {
        if (!hasOperands(instruction, 4) || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        const auto product = binary("*", valueOf(ops[1], type), valueOf(ops[2], type), type);
        return addAssignment(ops[0], binary(instruction.id == ARM64_INS_MADD ? "+" : "-",
            valueOf(ops[3], type), product, type));
    }
    case ARM64_INS_NEG:
    case ARM64_INS_MVN:
    case ARM64_INS_NOT:
    case ARM64_INS_ABS: {
        if (!hasOperands(instruction, 2) || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        const auto source = valueOf(ops[1], type);
        if (instruction.id == ARM64_INS_NEG) return addAssignment(ops[0], unary("-", source, type));
        if (instruction.id == ARM64_INS_ABS) return addAssignment(ops[0], unary("abs", source, type));
        return addAssignment(ops[0], unary("~", source, type));
    }
    case ARM64_INS_NEGS: {
        if (!hasOperands(instruction, 2) || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        auto zero = constant(0, type);
        auto source = saveTemporary("flags_right", valueOf(ops[1], type));
        auto result = saveTemporary("flags_result", binary("-", zero, source, type));
        setCompareOperands(zero, source);
        return addAssignment(ops[0], result);
    }
    case ARM64_INS_EXT: {
        if (!hasOperands(instruction, 4) || ops[3].kind != OperandKind::Immediate) return false;
        const auto shape = vectorShape(instruction);
        const auto width = static_cast<uint16_t>(shape.laneBits * shape.laneCount);
        if ((width != 64 && width != 128) || ops[3].immediate < 0 || ops[3].immediate >= width / 8) return false;
        const auto amount = static_cast<uint16_t>(ops[3].immediate * 8);
        const auto vectorType = ScalarType::vectorBits(128);
        const auto u64 = uintType(64);
        auto first = saveTemporary("ext_first", valueOf(ops[1], vectorType));
        auto second = saveTemporary("ext_second", valueOf(ops[2], vectorType));
        const auto half = [u64, vectorType](ExpressionPtr value, bool upper) {
            if (upper) value = binary(">>", value, constant(64, intType(32)), vectorType);
            return cast(value, u64);
        };
        const auto splice = [u64](ExpressionPtr lower, ExpressionPtr upper, uint16_t shift) {
            if (shift == 0) return lower;
            return binary("|", binary(">>", lower, constant(shift, intType(32)), u64),
                binary("<<", upper, constant(64 - shift, intType(32)), u64), u64);
        };
        auto firstLow = half(first, false);
        auto secondLow = half(second, false);
        if (width == 64) {
            return addVectorAssignment(ops[0], cast(splice(firstLow, secondLow, amount), vectorType));
        }
        auto firstHigh = half(first, true);
        auto secondHigh = half(second, true);
        ExpressionPtr low;
        ExpressionPtr high;
        if (amount < 64) {
            low = splice(firstLow, firstHigh, amount);
            high = splice(firstHigh, secondLow, amount);
        } else {
            low = splice(firstHigh, secondLow, amount - 64);
            high = splice(secondLow, secondHigh, amount - 64);
        }
        auto result = binary("|", cast(low, vectorType),
            binary("<<", cast(high, vectorType), constant(64, intType(32)), vectorType), vectorType);
        return addVectorAssignment(ops[0], result);
    }
    default:
        return false;
    }
}

bool Arm64Lifter::liftShift(const NativeInstruction& instruction) {
    const auto& ops = instruction.operands;
    switch (instruction.id) {
    case ARM64_INS_LSL:
    case ARM64_INS_LSR:
    case ARM64_INS_ASR:
    case ARM64_INS_SHL:
    case ARM64_INS_USHR:
    case ARM64_INS_SSHR:
    case ARM64_INS_ROR:
    case ARM64_INS_RORV: {
        if (!hasOperands(instruction, 3) || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        const auto bits = type.bits;
        if (bits != 32 && bits != 64) return false;
        auto source = coerce(valueOf(ops[1], type), uintType(bits));
        auto amount = valueOf(ops[2], uintType(bits));
        if (ops[2].kind == OperandKind::Register) {
            amount = binary("&", amount, constant(bits - 1, uintType(bits)), uintType(bits));
        } else if (ops[2].kind != OperandKind::Immediate || ops[2].immediate < 0 ||
            static_cast<uint64_t>(ops[2].immediate) >= bits) {
            return false;
        }
        switch (instruction.id) {
        case ARM64_INS_LSL:
        case ARM64_INS_SHL:
            return addAssignment(ops[0], binary("<<", source, amount, type));
        case ARM64_INS_LSR:
        case ARM64_INS_USHR:
            return addAssignment(ops[0], binary(">>", source, amount, type));
        case ARM64_INS_ASR:
        case ARM64_INS_SSHR:
            return addAssignment(ops[0], binary(">>", cast(source, intType(bits)), amount, intType(bits)));
        default: {
            const auto inverse = binary("&", binary("-", constant(bits, uintType(bits)), amount, uintType(bits)),
                constant(bits - 1, uintType(bits)), uintType(bits));
            const auto right = binary(">>", source, amount, type);
            const auto left = binary("<<", source, inverse, type);
            return addAssignment(ops[0], binary("|", right, left, type));
        }
        }
    }
    case ARM64_INS_EXTR: {
        if (!hasOperands(instruction, 4) || ops[3].kind != OperandKind::Immediate || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        const auto bits = type.bits;
        if ((bits != 32 && bits != 64) || ops[3].immediate < 0 || static_cast<uint64_t>(ops[3].immediate) >= bits) return false;
        const auto amount = static_cast<uint16_t>(ops[3].immediate);
        if (amount == 0) return addAssignment(ops[0], valueOf(ops[2], type));
        const auto high = binary("<<", valueOf(ops[1], type), constant(bits - amount, type), type);
        const auto low = binary(">>", valueOf(ops[2], type), constant(amount, type), type);
        return addAssignment(ops[0], binary("|", high, low, type));
    }
    default:
        return false;
    }
}

bool Arm64Lifter::liftBitfield(const NativeInstruction& instruction) {
    const auto& ops = instruction.operands;
    switch (instruction.id) {
    case ARM64_INS_UBFX:
    case ARM64_INS_SBFX:
    case ARM64_INS_UBFIZ:
    case ARM64_INS_SBFIZ:
    case ARM64_INS_BFI:
    case ARM64_INS_BFXIL: {
        if (!hasOperands(instruction, 4) || ops[2].kind != OperandKind::Immediate || ops[3].kind != OperandKind::Immediate) return false;
        const auto type = operandType(ops[0]);
        const auto bits = type.bits;
        if (bits != 32 && bits != 64) return false;
        const auto lsb = static_cast<uint16_t>(ops[2].immediate);
        const auto width = static_cast<uint16_t>(ops[3].immediate);
        if (ops[2].immediate < 0 || ops[3].immediate < 0 || width == 0 || lsb >= bits || width > bits - lsb) return false;
        const auto widthMask = width == 64 ? ~uint64_t{0} : (uint64_t{1} << width) - 1;
        const auto source = valueOf(ops[1], type);
        if (instruction.id == ARM64_INS_UBFX || instruction.id == ARM64_INS_SBFX) {
            ExpressionPtr extracted = binary("&", binary(">>", source, constant(lsb, type), type), constant(widthMask, type), type);
            if (instruction.id == ARM64_INS_SBFX) extracted = cast(cast(extracted, intType(width)), intType(bits));
            return addAssignment(ops[0], extracted);
        }
        if (instruction.id == ARM64_INS_UBFIZ || instruction.id == ARM64_INS_SBFIZ) {
            ExpressionPtr inserted = binary("&", source, constant(widthMask, type), type);
            if (instruction.id == ARM64_INS_SBFIZ) inserted = cast(cast(inserted, intType(width)), intType(bits));
            inserted = binary("<<", inserted, constant(lsb, type), type);
            return addAssignment(ops[0], binary("&", inserted, constant(widthMask << lsb, type), type));
        }
        if (instruction.id == ARM64_INS_BFI) {
            const auto fieldMask = widthMask << lsb;
            const auto preserved = binary("&", readRegister(ops[0].reg), constant(~fieldMask, type), type);
            const auto inserted = binary("&", binary("<<", source, constant(lsb, type), type), constant(fieldMask, type), type);
            return addAssignment(ops[0], binary("|", preserved, inserted, type));
        }
        const auto extracted = binary("&", binary(">>", source, constant(lsb, type), type), constant(widthMask, type), type);
        const auto preserved = binary("&", readRegister(ops[0].reg), constant(~widthMask, type), type);
        return addAssignment(ops[0], binary("|", preserved, extracted, type));
    }
    default:
        return false;
    }
}

bool Arm64Lifter::liftExtend(const NativeInstruction& instruction) {
    if (!hasOperands(instruction, 2) || !hasRegister(instruction.operands[1])) return false;
    uint16_t sourceBits = 0;
    bool isSigned = false;
    switch (instruction.id) {
    case ARM64_INS_SXTB: sourceBits = 8; isSigned = true; break;
    case ARM64_INS_SXTH: sourceBits = 16; isSigned = true; break;
    case ARM64_INS_SXTW: sourceBits = 32; isSigned = true; break;
    case ARM64_INS_UXTB: sourceBits = 8; break;
    case ARM64_INS_UXTH: sourceBits = 16; break;
    case ARM64_INS_UXTW: sourceBits = 32; break;
    default: return false;
    }
    const auto destinationBits = operandType(instruction.operands[0]).bits;
    if ((destinationBits != 32 && destinationBits != 64) || sourceBits > destinationBits) return false;
    auto value = coerce(valueOf(instruction.operands[1]), uintType(sourceBits));
    value = cast(value, isSigned ? intType(sourceBits) : uintType(sourceBits));
    value = cast(value, isSigned ? intType(destinationBits) : uintType(destinationBits));
    return addAssignment(instruction.operands[0], value);
}

bool Arm64Lifter::liftFloatingPoint(const NativeInstruction& instruction) {
    const auto& ops = instruction.operands;
    switch (instruction.id) {
    case ARM64_INS_FADD:
    case ARM64_INS_FSUB:
    case ARM64_INS_FMUL:
    case ARM64_INS_FDIV: {
        if (!hasOperands(instruction, 3)) return false;
        const auto type = operandType(ops[0]);
        if ((type.bits != 32 && type.bits != 64) || type.kind != ScalarKind::FloatingPoint ||
            operandType(ops[1]).kind != ScalarKind::FloatingPoint || operandType(ops[2]).kind != ScalarKind::FloatingPoint ||
            operandType(ops[1]).bits != type.bits || operandType(ops[2]).bits != type.bits) return false;
        const char* operation = "+";
        if (instruction.id == ARM64_INS_FSUB) operation = "-";
        else if (instruction.id == ARM64_INS_FMUL) operation = "*";
        else if (instruction.id == ARM64_INS_FDIV) operation = "/";
        return addAssignment(ops[0], binary(operation, valueOf(ops[1], type), valueOf(ops[2], type), type));
    }
    case ARM64_INS_FMAX:
    case ARM64_INS_FMIN:
    case ARM64_INS_FNMUL: {
        if (!hasOperands(instruction, 3)) return false;
        const auto type = operandType(ops[0]);
        if (type.kind != ScalarKind::FloatingPoint || (type.bits != 32 && type.bits != 64) ||
            operandType(ops[1]).kind != ScalarKind::FloatingPoint || operandType(ops[2]).kind != ScalarKind::FloatingPoint ||
            operandType(ops[1]).bits != type.bits || operandType(ops[2]).bits != type.bits) return false;
        auto left = saveTemporary("fp_left", valueOf(ops[1], type));
        auto right = saveTemporary("fp_right", valueOf(ops[2], type));
        if (instruction.id == ARM64_INS_FNMUL) {
            return addAssignment(ops[0], unary("-", binary("*", left, right, type), type));
        }
        const auto boolean = ScalarType::boolean();
        auto leftNaN = binary("!=", left, left, boolean);
        auto rightNaN = binary("!=", right, right, boolean);
        auto ordered = binary(instruction.id == ARM64_INS_FMAX ? ">=" : "<=", left, right, boolean);
        auto result = select(ordered, left, right, type);
        auto zero = floatingConstant(0.0, type);
        auto bothZero = binary("&&", binary("==", left, zero, boolean),
            binary("==", right, zero, boolean), boolean);
        const auto rawType = uintType(type.bits);
        auto zeroBits = binary(instruction.id == ARM64_INS_FMAX ? "&" : "|",
            floatToRaw(left, type.bits), floatToRaw(right, type.bits), rawType);
        result = select(bothZero, rawToFloat(zeroBits, type.bits), result, type);
        result = select(rightNaN, right, result, type);
        result = select(leftNaN, left, result, type);
        return addAssignment(ops[0], result);
    }
    case ARM64_INS_FSQRT: {
        if (!hasOperands(instruction, 2)) return false;
        const auto type = operandType(ops[0]);
        if (type.kind != ScalarKind::FloatingPoint || (type.bits != 32 && type.bits != 64) ||
            operandType(ops[1]).kind != ScalarKind::FloatingPoint || operandType(ops[1]).bits != type.bits) return false;
        return addAssignment(ops[0], unary("fsqrt", valueOf(ops[1], type), type));
    }
    case ARM64_INS_FABS: {
        if (!hasOperands(instruction, 2)) return false;
        const auto type = operandType(ops[0]);
        if (type.kind != ScalarKind::FloatingPoint || (type.bits != 32 && type.bits != 64) ||
            operandType(ops[1]).kind != ScalarKind::FloatingPoint || operandType(ops[1]).bits != type.bits) return false;
        auto raw = floatToRaw(valueOf(ops[1], type), type.bits);
        const auto mask = type.bits == 32 ? uint64_t{0x7fffffff} : uint64_t{0x7fffffffffffffff};
        raw = binary("&", raw, constant(mask, uintType(type.bits)), uintType(type.bits));
        return addAssignment(ops[0], rawToFloat(raw, type.bits));
    }
    case ARM64_INS_FNEG: {
        if (!hasOperands(instruction, 2)) return false;
        const auto type = operandType(ops[0]);
        if (type.kind != ScalarKind::FloatingPoint || (type.bits != 32 && type.bits != 64) ||
            operandType(ops[1]).kind != ScalarKind::FloatingPoint || operandType(ops[1]).bits != type.bits) return false;
        return addAssignment(ops[0], unary("-", valueOf(ops[1], type), type));
    }
    case ARM64_INS_FCVT: {
        if (!hasOperands(instruction, 2)) return false;
        const auto destinationType = operandType(ops[0]);
        const auto sourceType = operandType(ops[1]);
        if (destinationType.kind != ScalarKind::FloatingPoint || sourceType.kind != ScalarKind::FloatingPoint ||
            (destinationType.bits != 32 && destinationType.bits != 64) ||
            (sourceType.bits != 32 && sourceType.bits != 64)) return false;
        return addAssignment(ops[0], cast(valueOf(ops[1], sourceType), destinationType));
    }
    case ARM64_INS_FCVTZS:
    case ARM64_INS_FCVTZU: {
        if (!hasOperands(instruction, 2)) return false;
        const auto destinationBits = operandType(ops[0]).bits;
        const auto sourceType = operandType(ops[1]);
        if ((destinationBits != 32 && destinationBits != 64) ||
            sourceType.kind != ScalarKind::FloatingPoint || (sourceType.bits != 32 && sourceType.bits != 64) ||
            operandType(ops[0]).kind == ScalarKind::FloatingPoint) return false;
        const bool isSigned = instruction.id == ARM64_INS_FCVTZS;
        const auto destinationType = isSigned ? intType(destinationBits) : uintType(destinationBits);
        const auto boolean = ScalarType::boolean();
        auto source = saveTemporary("fcvtz_source", valueOf(ops[1], sourceType));
        if (ops.size() >= 3) {
            if (ops[2].kind != OperandKind::Immediate || ops[2].immediate < 0 || ops[2].immediate > 64) return false;
            auto scale = floatingConstant(std::ldexp(1.0, static_cast<int>(ops[2].immediate)), sourceType);
            source = saveTemporary("fcvtz_scaled", binary("*", source, scale, sourceType));
        }
        const auto high = floatingConstant(std::ldexp(1.0, isSigned ? destinationBits - 1 : destinationBits), sourceType);
        const auto maximum = isSigned ? (uint64_t{1} << (destinationBits - 1)) - 1 : maskFor(destinationBits, destinationType)->constant;
        ExpressionPtr result;
        if (isSigned) {
            const auto low = floatingConstant(-std::ldexp(1.0, destinationBits - 1), sourceType);
            const auto minimum = uint64_t{1} << (destinationBits - 1);
            result = select(binary(">=", source, high, boolean), constant(maximum, destinationType),
                select(binary("<", source, low, boolean), constant(minimum, destinationType),
                    cast(source, destinationType), destinationType), destinationType);
        } else {
            result = select(binary(">=", source, high, boolean), constant(maximum, destinationType),
                select(binary("<=", source, floatingConstant(0.0, sourceType), boolean), constant(0, destinationType),
                    cast(source, destinationType), destinationType), destinationType);
        }
        result = select(binary("!=", source, source, boolean), constant(0, destinationType), result, destinationType);
        return addAssignment(ops[0], result);
    }
    case ARM64_INS_SCVTF:
    case ARM64_INS_UCVTF: {
        if (!hasOperands(instruction, 2) || !hasRegister(ops[1]) || isVectorRegister(ops[1])) return false;
        const auto type = operandType(ops[0]);
        const auto sourceBits = operandType(ops[1]).bits;
        if (type.kind != ScalarKind::FloatingPoint || (type.bits != 32 && type.bits != 64) ||
            (sourceBits != 32 && sourceBits != 64)) return false;
        const auto sourceType = instruction.id == ARM64_INS_SCVTF ? intType(sourceBits) : uintType(sourceBits);
        auto value = cast(cast(valueOf(ops[1]), sourceType), type);
        if (ops.size() >= 3) {
            if (ops[2].kind != OperandKind::Immediate || ops[2].immediate < 0 || ops[2].immediate > 64) return false;
            const auto scale = floatingConstant(std::ldexp(1.0, static_cast<int>(ops[2].immediate)), type);
            value = binary("/", value, scale, type);
        }
        return addAssignment(ops[0], value);
    }
    case ARM64_INS_FCMP:
    case ARM64_INS_FCMPE: {
        if (!hasOperands(instruction, 2)) return false;
        const auto type = operandType(ops[0]);
        if (type.kind != ScalarKind::FloatingPoint || (type.bits != 32 && type.bits != 64)) return false;
        if (ops[1].kind != OperandKind::FloatingPoint &&
            (operandType(ops[1]).kind != ScalarKind::FloatingPoint || operandType(ops[1]).bits != type.bits)) return false;
        auto left = saveTemporary("float_flags_left", valueOf(ops[0], type));
        auto right = saveTemporary("float_flags_right", valueOf(ops[1], type));
        setCompareOperands(left, right, true);
        return true;
    }
    case ARM64_INS_FCCMP:
    case ARM64_INS_FCCMPE: {
        if (!hasOperands(instruction, 3) || ops[2].kind != OperandKind::Immediate) return false;
        const auto type = operandType(ops[0]);
        if (type.kind != ScalarKind::FloatingPoint || (type.bits != 32 && type.bits != 64)) return false;
        if (ops[1].kind != OperandKind::FloatingPoint &&
            (operandType(ops[1]).kind != ScalarKind::FloatingPoint || operandType(ops[1]).bits != type.bits)) return false;
        if (!conditionAvailable(instruction.conditionCode)) addUnsupported(instruction);
        auto precedingCondition = condition(instruction.conditionCode);
        auto left = saveTemporary("float_flags_left", valueOf(ops[0], type));
        auto right = saveTemporary("float_flags_right", valueOf(ops[1], type));
        setCompareOperands(left, right, true);
        conditionalCondition_ = std::move(precedingCondition);
        conditionalNzcv_ = static_cast<uint8_t>(ops[2].immediate);
        return true;
    }
    default:
        return false;
    }
}

bool Arm64Lifter::liftConditional(const NativeInstruction& instruction) {
    const auto& ops = instruction.operands;
    switch (instruction.id) {
    case ARM64_INS_CINC:
    case ARM64_INS_CNEG: {
        if (!hasOperands(instruction, 2) || hasVectorRegister(instruction)) return false;
        if (!conditionAvailable(instruction.conditionCode)) addUnsupported(instruction);
        const auto type = operandType(ops[0]);
        auto source = valueOf(ops[1], type);
        auto changed = instruction.id == ARM64_INS_CINC
            ? binary("+", source, constant(1, type), type)
            : unary("-", source, type);
        return addAssignment(ops[0], select(condition(instruction.conditionCode), changed, source, type));
    }
    case ARM64_INS_CSEL:
    case ARM64_INS_CSINC:
    case ARM64_INS_CSINV:
    case ARM64_INS_CSNEG:
    case ARM64_INS_FCSEL: {
        if (!hasOperands(instruction, 3) || hasVectorRegister(instruction)) return false;
        if (!conditionAvailable(instruction.conditionCode)) addUnsupported(instruction);
        const auto type = operandType(ops[0]);
        const auto ifTrue = valueOf(ops[1], type);
        auto ifFalse = valueOf(ops[2], type);
        switch (instruction.id) {
        case ARM64_INS_CSINC: ifFalse = binary("+", ifFalse, constant(1, type), type); break;
        case ARM64_INS_CSINV: ifFalse = unary("~", ifFalse, type); break;
        case ARM64_INS_CSNEG: ifFalse = unary("-", ifFalse, type); break;
        default: break;
        }
        return addAssignment(ops[0], select(condition(instruction.conditionCode), ifTrue, ifFalse, type));
    }
    case ARM64_INS_CSET:
    case ARM64_INS_CSETM: {
        if (!hasOperands(instruction, 1)) return false;
        if (!conditionAvailable(instruction.conditionCode)) addUnsupported(instruction);
        const auto type = operandType(ops[0]);
        const auto trueValue = instruction.id == ARM64_INS_CSET ? constant(1, type) : maskFor(type.bits, type);
        return addAssignment(ops[0], select(condition(instruction.conditionCode), trueValue, constant(0, type), type));
    }
    case ARM64_INS_CMP:
    case ARM64_INS_CMN:
    case ARM64_INS_TST: {
        if (!hasOperands(instruction, 2) || hasVectorRegister(instruction)) return false;
        const auto type = operandType(ops[0]);
        auto left = saveTemporary("flags_left", valueOf(ops[0], type));
        auto right = saveTemporary("flags_right", valueOf(ops[1], type));
        if (instruction.id == ARM64_INS_TST) {
            setLogicalCompare(saveTemporary("flags_result", binary("&", left, right, type)));
        } else if (instruction.id == ARM64_INS_CMN) {
            setAddCompare(left, right);
        } else {
            setCompareOperands(left, right);
        }
        return true;
    }
    case ARM64_INS_CCMP:
    case ARM64_INS_CCMN: {
        if (!hasOperands(instruction, 3) || ops[2].kind != OperandKind::Immediate || hasVectorRegister(instruction)) return false;
        if (!conditionAvailable(instruction.conditionCode)) addUnsupported(instruction);
        const auto type = operandType(ops[0]);
        auto left = saveTemporary("flags_left", valueOf(ops[0], type));
        auto right = saveTemporary("flags_right", valueOf(ops[1], type));
        setConditionalCompare(left, right, instruction.conditionCode, static_cast<uint8_t>(ops[2].immediate), instruction.id == ARM64_INS_CCMN);
        return true;
    }
    default:
        return false;
    }
}

bool Arm64Lifter::liftLoadStore(const NativeInstruction& instruction) {
    const auto& ops = instruction.operands;
    switch (instruction.id) {
    case ARM64_INS_LD1R: {
        if (!hasOperands(instruction, 2) || ops[1].kind != OperandKind::Memory ||
            (hasPreIndexWriteback(instruction) && ops.size() != 2)) return false;
        const auto shape = vectorShape(instruction);
        if (shape.laneCount == 0) return false;
        auto address = addressOf(ops[1]);
        ExpressionPtr savedAddress;
        if (hasPreIndexWriteback(instruction) || ops.size() > 2) {
            address = saveTemporary("ld1r_address", address);
            savedAddress = address;
        }
        auto lane = load(address, uintType(shape.laneBits));
        if (!addVectorAssignment(ops[0], replicateLane(lane, shape.laneBits, shape.laneCount))) return false;
        addInstructionWriteback(instruction, 1, 2, savedAddress);
        return true;
    }
    case ARM64_INS_LDR:
    case ARM64_INS_LDUR:
    case ARM64_INS_LDTR:
    case ARM64_INS_LDAR:
    case ARM64_INS_LDXR:
    case ARM64_INS_LDRB:
    case ARM64_INS_LDURB:
    case ARM64_INS_LDTRB:
    case ARM64_INS_LDARB:
    case ARM64_INS_LDXRB:
    case ARM64_INS_LDRH:
    case ARM64_INS_LDURH:
    case ARM64_INS_LDTRH:
    case ARM64_INS_LDARH:
    case ARM64_INS_LDXRH:
    case ARM64_INS_LDRSB:
    case ARM64_INS_LDURSB:
    case ARM64_INS_LDTRSB:
    case ARM64_INS_LDRSH:
    case ARM64_INS_LDURSH:
    case ARM64_INS_LDTRSH:
    case ARM64_INS_LDRSW:
    case ARM64_INS_LDURSW:
    case ARM64_INS_LDTRSW: {
        if (!hasOperands(instruction, 2) || (hasPreIndexWriteback(instruction) && ops.size() != 2)) return false;
        auto type = operandType(ops[0]);
        switch (instruction.id) {
        case ARM64_INS_LDRB:
        case ARM64_INS_LDURB:
        case ARM64_INS_LDTRB:
        case ARM64_INS_LDARB:
        case ARM64_INS_LDXRB: type = uintType(8); break;
        case ARM64_INS_LDRH:
        case ARM64_INS_LDURH:
        case ARM64_INS_LDTRH:
        case ARM64_INS_LDARH:
        case ARM64_INS_LDXRH: type = uintType(16); break;
        case ARM64_INS_LDRSB:
        case ARM64_INS_LDURSB:
        case ARM64_INS_LDTRSB: type = intType(8); break;
        case ARM64_INS_LDRSH:
        case ARM64_INS_LDURSH:
        case ARM64_INS_LDTRSH: type = intType(16); break;
        case ARM64_INS_LDRSW:
        case ARM64_INS_LDURSW:
        case ARM64_INS_LDTRSW: type = intType(32); break;
        default: break;
        }
        ExpressionPtr address;
        if (ops[1].kind == OperandKind::Memory) address = addressOf(ops[1]);
        else if (ops[1].kind == OperandKind::Immediate && !hasPreIndexWriteback(instruction) && ops.size() == 2) {
            address = constant(static_cast<uint64_t>(ops[1].immediate), pointerType());
        } else return false;
        ExpressionPtr savedAddress;
        if (ops[1].kind == OperandKind::Memory && (hasPreIndexWriteback(instruction) || ops.size() > 2)) {
            address = saveTemporary("load_address", address);
            savedAddress = address;
        }
        ExpressionPtr value = load(address, type);
        const auto destinationBits = operandType(ops[0]).bits;
        if (type.kind == ScalarKind::SignedInteger && destinationBits > type.bits) value = cast(value, intType(destinationBits));
        if (!addAssignment(ops[0], value)) return false;
        addInstructionWriteback(instruction, 1, 2, savedAddress);
        return true;
    }
    case ARM64_INS_STR:
    case ARM64_INS_STUR:
    case ARM64_INS_STTR:
    case ARM64_INS_STLR:
    case ARM64_INS_STRB:
    case ARM64_INS_STURB:
    case ARM64_INS_STTRB:
    case ARM64_INS_STLRB:
    case ARM64_INS_STRH:
    case ARM64_INS_STURH:
    case ARM64_INS_STTRH:
    case ARM64_INS_STLRH: {
        if (!hasOperands(instruction, 2) || ops[1].kind != OperandKind::Memory ||
            (hasPreIndexWriteback(instruction) && ops.size() != 2)) return false;
        auto type = operandType(ops[0]);
        switch (instruction.id) {
        case ARM64_INS_STRB:
        case ARM64_INS_STURB:
        case ARM64_INS_STTRB:
        case ARM64_INS_STLRB: type = uintType(8); break;
        case ARM64_INS_STRH:
        case ARM64_INS_STURH:
        case ARM64_INS_STTRH:
        case ARM64_INS_STLRH: type = uintType(16); break;
        default: break;
        }
        const auto address = addressOf(ops[1]);
        addStore(address, valueOf(ops[0], type));
        addInstructionWriteback(instruction, 1, 2);
        return true;
    }
    case ARM64_INS_PRFM:
        return true;
    default:
        return false;
    }
}

bool Arm64Lifter::liftPair(const NativeInstruction& instruction) {
    const auto& ops = instruction.operands;
    const auto isLoad = instruction.id == ARM64_INS_LDP || instruction.id == ARM64_INS_LDNP || instruction.id == ARM64_INS_LDPSW;
    const auto isStore = instruction.id == ARM64_INS_STP || instruction.id == ARM64_INS_STNP;
    if (!isLoad && !isStore) return false;
    if (!hasOperands(instruction, 3) || ops[2].kind != OperandKind::Memory ||
        (hasPreIndexWriteback(instruction) && ops.size() != 3)) return false;

    const auto base = saveTemporary("pair_address", addressOf(ops[2]));
    uint16_t offset = 0;
    for (size_t index = 0; index < 2; ++index) {
        auto type = operandType(ops[index]);
        if (instruction.id == ARM64_INS_LDPSW) type = intType(32);
        if (type.bits == 0 || type.bits % 8 != 0) return false;
        const auto width = static_cast<uint16_t>(type.bits / 8);
        const auto address = offset == 0 ? base : binary("+", base, constant(offset, pointerType()), pointerType());
        if (isLoad) {
            ExpressionPtr value = load(address, type);
            const auto destinationBits = operandType(ops[index]).bits;
            if (type.kind == ScalarKind::SignedInteger && destinationBits > type.bits) value = cast(value, intType(destinationBits));
            if (!addAssignment(ops[index], value)) return false;
        } else {
            addStore(address, valueOf(ops[index], type));
        }
        offset = static_cast<uint16_t>(offset + width);
    }
    addInstructionWriteback(instruction, 2, 3, base);
    return true;
}

bool Arm64Lifter::liftControlFlow(const NativeInstruction& instruction) {
    const auto& ops = instruction.operands;
    switch (instruction.id) {
    case ARM64_INS_NOP:
        return true;
    case ARM64_INS_BL:
        if (ops.size() != 1 || ops[0].kind != OperandKind::Immediate) return false;
        addCall(instruction);
        return true;
    case ARM64_INS_BLR:
        if (ops.size() != 1 || !hasRegister(ops[0])) return false;
        addCall(instruction);
        return true;
    case ARM64_INS_B:
        if (ops.size() != 1 || ops[0].kind != OperandKind::Immediate) return false;
        if (instruction.conditionCode != ARM64_CC_INVALID && instruction.conditionCode != ARM64_CC_AL &&
            instruction.conditionCode != ARM64_CC_NV && !conditionAvailable(instruction.conditionCode)) {
            addUnsupported(instruction);
        }
        addBranch(instruction, instruction.conditionCode == ARM64_CC_INVALID || instruction.conditionCode == ARM64_CC_AL || instruction.conditionCode == ARM64_CC_NV
            ? nullptr
            : condition(instruction.conditionCode));
        return true;
    case ARM64_INS_BR:
        if (ops.size() != 1 || !hasRegister(ops[0])) return false;
        addBranch(instruction);
        return true;
    case ARM64_INS_RET: {
        if (ops.size() > 1 || (!ops.empty() && !hasRegister(ops[0]))) return false;
        Statement result;
        result.kind = Statement::Kind::Return;
        result.value = readRegister("x0");
        add(std::move(result));
        return true;
    }
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ: {
        if (!hasOperands(instruction, 2) || !hasRegister(ops[0]) || ops[1].kind != OperandKind::Immediate) return false;
        const auto value = valueOf(ops[0]);
        addBranch(instruction, binary(instruction.id == ARM64_INS_CBZ ? "==" : "!=", value, constant(0, value->type), ScalarType::boolean()));
        return true;
    }
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ: {
        if (!hasOperands(instruction, 3) || !hasRegister(ops[0]) || ops[1].kind != OperandKind::Immediate ||
            ops[2].kind != OperandKind::Immediate) return false;
        const auto value = valueOf(ops[0]);
        if (ops[1].immediate < 0 || static_cast<uint64_t>(ops[1].immediate) >= value->type.bits) return false;
        const auto shifted = binary(">>", value, constant(static_cast<uint64_t>(ops[1].immediate), value->type), value->type);
        const auto bit = binary("&", shifted, constant(1, value->type), value->type);
        addBranch(instruction, binary(instruction.id == ARM64_INS_TBZ ? "==" : "!=", bit, constant(0, value->type), ScalarType::boolean()));
        return true;
    }
    default:
        return false;
    }
}

bool Arm64Lifter::lift(const NativeInstruction& instruction, std::vector<Statement>& statements) {
    if (hasPreviousInstruction_ &&
        instruction.address != previousInstructionAddress_ + previousInstructionSize_) {
        invalidateFlags();
    }

    std::vector<Statement> lifted;
    statements_ = &lifted;
    instructionAddress_ = instruction.address;
    instructionSize_ = instruction.size;

    bool handled = false;
    if (!hasExtendedRegisterOperand(instruction) &&
        (!hasVectorLaneOperand(instruction) || instruction.id == ARM64_INS_DUP)) {
        handled = liftMove(instruction)
            || liftArithmetic(instruction)
            || liftShift(instruction)
            || liftBitfield(instruction)
            || liftExtend(instruction)
            || liftFloatingPoint(instruction)
            || liftConditional(instruction)
            || liftLoadStore(instruction)
            || liftPair(instruction)
            || liftControlFlow(instruction);
    }
    if (!handled) {
        addUnsupported(instruction);
        invalidateFlags();
    } else if (isControlFlow(instruction.id)) {
        invalidateFlags();
    }

    statements_ = nullptr;
    previousInstructionAddress_ = instruction.address;
    previousInstructionSize_ = instruction.size;
    hasPreviousInstruction_ = true;
    for (auto& statement : lifted) statements.push_back(std::move(statement));
    return true;
}

} // namespace il2cpprec
