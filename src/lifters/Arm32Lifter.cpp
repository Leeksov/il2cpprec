#include <il2cpprec/lifters/Arm32Lifter.hpp>

#include <capstone/arm.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <string>
#include <utility>

namespace il2cpprec {

class Arm32Lifter::Impl {
public:
    explicit Impl(const FunctionImage& image) : image_(image) {
        output_.architecture = Architecture::Arm32;
        output_.address = image.address;
        output_.name = image.name;
    }

    RecoveredFunction run(std::vector<NativeInstruction> instructions) {
        instructions_ = std::move(instructions);
        collectBranchTargets();
        managedFloatBridge_ = needsManagedFloatBridge();
        if (managedFloatBridge_) {
            for (int index = 0; index < 2; ++index) {
                Statement statement;
                statement.address = image_.address;
                statement.kind = Statement::Kind::Assign;
                statement.destination = reg("s" + std::to_string(index), ScalarType::floatBits(32));
                const auto integer = cast(readRegister("r" + std::to_string(index)), signedWordType());
                statement.value = cast(integer, ScalarType::floatBits(32));
                add(std::move(statement));
            }
        }
        for (const auto& instruction : instructions_) {
            if (branchTargets_.contains(instruction.address) && !output_.blocks.empty() &&
                !output_.blocks.back().statements.empty()) {
                output_.blocks.push_back({instruction.address, {}});
                terminated_ = false;
            }
            if (!terminated_) {
                lift(instruction);
            }
        }
        for (auto& block : deferredBlocks_) output_.blocks.push_back(std::move(block));
        return std::move(output_);
    }

private:
    const FunctionImage& image_;
    RecoveredFunction output_;
    std::vector<NativeInstruction> instructions_;
    std::vector<BasicBlock> deferredBlocks_;
    std::set<uint64_t> branchTargets_;
    const NativeInstruction* currentInstruction_ = nullptr;
    ExpressionPtr flagN_;
    ExpressionPtr flagZ_;
    ExpressionPtr flagC_;
    ExpressionPtr flagV_;
    bool managedFloatBridge_ = false;
    bool terminated_ = false;

    static ScalarType wordType() { return ScalarType::uintBits(32); }
    static ScalarType doubleWordType() { return ScalarType::uintBits(64); }
    static ScalarType signedWordType() { return ScalarType::intBits(32); }
    static ScalarType pointerType() { return ScalarType::pointer(32); }

    BasicBlock& currentBlock() {
        if (output_.blocks.empty()) {
            output_.blocks.push_back({image_.address, {}});
        }
        return output_.blocks.back();
    }

    void add(Statement statement) {
        if (statement.kind == Statement::Kind::Return ||
            (statement.kind == Statement::Kind::Branch && !statement.condition)) {
            terminated_ = true;
        }
        currentBlock().statements.push_back(std::move(statement));
    }

    static ExpressionPtr readRegister(const std::string& name) {
        return reg(name, wordType());
    }

    bool isThumb() const { return image_.arm32Mode == Arm32Mode::Thumb; }

    uint32_t programCounterValue() const {
        const uint64_t offset = isThumb() ? 4 : 8;
        return static_cast<uint32_t>(currentInstruction_->address + offset);
    }

    ExpressionPtr readOperandRegister(const std::string& name) const {
        if (name == "pc" && currentInstruction_ != nullptr) {
            return constant(programCounterValue(), wordType());
        }
        return readRegister(name);
    }

    static bool isUnconditional(const NativeInstruction& instruction) {
        return instruction.conditionCode == ARM_CC_AL || instruction.conditionCode == ARM_CC_INVALID;
    }

    static bool updatesFlags(const NativeInstruction& instruction) {
        if (instruction.id == ARM_INS_MOVS || instruction.id == ARM_INS_SUBS) return true;
        if (instruction.id == ARM_INS_MLS) return false;
        auto mnemonic = instruction.mnemonic.substr(0, instruction.mnemonic.find('.'));
        if (!isUnconditional(instruction)) {
            const char* suffix = nullptr;
            switch (instruction.conditionCode) {
            case ARM_CC_EQ: suffix = "eq"; break;
            case ARM_CC_NE: suffix = "ne"; break;
            case ARM_CC_HS: suffix = "hs"; break;
            case ARM_CC_LO: suffix = "lo"; break;
            case ARM_CC_MI: suffix = "mi"; break;
            case ARM_CC_PL: suffix = "pl"; break;
            case ARM_CC_VS: suffix = "vs"; break;
            case ARM_CC_VC: suffix = "vc"; break;
            case ARM_CC_HI: suffix = "hi"; break;
            case ARM_CC_LS: suffix = "ls"; break;
            case ARM_CC_GE: suffix = "ge"; break;
            case ARM_CC_LT: suffix = "lt"; break;
            case ARM_CC_GT: suffix = "gt"; break;
            case ARM_CC_LE: suffix = "le"; break;
            default: break;
            }
            if (suffix != nullptr) {
                const std::string ending(suffix);
                if (mnemonic.size() >= ending.size() &&
                    mnemonic.compare(mnemonic.size() - ending.size(), ending.size(), ending) == 0) {
                    mnemonic.erase(mnemonic.size() - ending.size());
                }
            }
        }
        return !mnemonic.empty() && mnemonic.back() == 's';
    }

    static ExpressionPtr flagCondition(const ExpressionPtr& flag) {
        if (!flag) return unknown(ScalarType::boolean());
        return binary("!=", flag, constant(0, wordType()), ScalarType::boolean());
    }

    ExpressionPtr conditionFromArm(uint32_t conditionCode) const {
        if (conditionCode == ARM_CC_AL || conditionCode == ARM_CC_INVALID) {
            return constant(1, ScalarType::boolean());
        }
        const auto boolean = ScalarType::boolean();
        const auto n = flagCondition(flagN_);
        const auto z = flagCondition(flagZ_);
        const auto c = flagCondition(flagC_);
        const auto v = flagCondition(flagV_);
        const auto nEqualsV = binary("==", n, v, boolean);
        switch (conditionCode) {
        case ARM_CC_EQ: return z;
        case ARM_CC_NE: return unary("!", z, boolean);
        case ARM_CC_HS: return c;
        case ARM_CC_LO: return unary("!", c, boolean);
        case ARM_CC_MI: return n;
        case ARM_CC_PL: return unary("!", n, boolean);
        case ARM_CC_VS: return v;
        case ARM_CC_VC: return unary("!", v, boolean);
        case ARM_CC_HI: return binary("&&", c, unary("!", z, boolean), boolean);
        case ARM_CC_LS: return binary("||", unary("!", c, boolean), z, boolean);
        case ARM_CC_GE: return nEqualsV;
        case ARM_CC_LT: return unary("!", nEqualsV, boolean);
        case ARM_CC_GT: return binary("&&", unary("!", z, boolean), nEqualsV, boolean);
        case ARM_CC_LE: return binary("||", z, unary("!", nEqualsV, boolean), boolean);
        default: return unknown(boolean);
        }
    }

    ExpressionPtr condition(const NativeInstruction& instruction) const {
        return isUnconditional(instruction) ? nullptr : conditionFromArm(instruction.conditionCode);
    }

    ExpressionPtr carryValue() const {
        return select(flagCondition(flagC_), constant(1, wordType()), constant(0, wordType()), wordType());
    }

    ExpressionPtr prepareExecutionCondition(const NativeInstruction& instruction, bool materialize) {
        if (isUnconditional(instruction)) return nullptr;
        const auto original = condition(instruction);
        if (!materialize) return original;
        const auto name = "arm_cond_" + std::to_string(instruction.address);
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Assign;
        statement.destination = reg(name, wordType());
        statement.value = select(original, constant(1, wordType()), constant(0, wordType()), wordType());
        add(std::move(statement));
        return binary("!=", reg(name, wordType()), constant(0, wordType()), ScalarType::boolean());
    }

    void writeFlag(const NativeInstruction& instruction, const char* name, ExpressionPtr& slot,
                   ExpressionPtr value, const ExpressionPtr& executionCondition) {
        value = select(value, constant(1, wordType()), constant(0, wordType()), wordType());
        if (executionCondition) {
            value = select(executionCondition, value, slot ? slot : unknown(wordType()), wordType());
        }
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Assign;
        statement.destination = reg(name, wordType());
        statement.value = std::move(value);
        add(std::move(statement));
        slot = reg(name, wordType());
    }

    void setNzFlags(const NativeInstruction& instruction, const ExpressionPtr& result,
                    const ExpressionPtr& executionCondition) {
        const auto type = result->type;
        const auto signedType = ScalarType::intBits(type.bits);
        const auto negative = binary("<", cast(result, signedType), constant(0, signedType), ScalarType::boolean());
        const auto zero = binary("==", result, constant(0, type), ScalarType::boolean());
        writeFlag(instruction, "arm_n", flagN_, negative, executionCondition);
        writeFlag(instruction, "arm_z", flagZ_, zero, executionCondition);
    }

    void setArithmeticFlags(const NativeInstruction& instruction, const ExpressionPtr& left,
                            const ExpressionPtr& right, const ExpressionPtr& result, bool addition,
                            bool withCarry, const ExpressionPtr& executionCondition) {
        const auto left64 = cast(left, doubleWordType());
        const auto right64 = cast(right, doubleWordType());
        ExpressionPtr carry;
        if (addition) {
            auto sum = binary("+", left64, right64, doubleWordType());
            if (withCarry) sum = binary("+", sum, cast(carryValue(), doubleWordType()), doubleWordType());
            carry = binary(">", sum, constant(0xFFFFFFFFULL, doubleWordType()), ScalarType::boolean());
        } else {
            auto subtrahend = right64;
            if (withCarry) {
                const auto borrow = binary("-", constant(1, wordType()), carryValue(), wordType());
                subtrahend = binary("+", right64, cast(borrow, doubleWordType()), doubleWordType());
            }
            carry = binary(">=", left64, subtrahend, ScalarType::boolean());
        }
        ExpressionPtr signBits;
        if (addition) {
            const auto sameSign = unary("~", binary("^", left, right, wordType()), wordType());
            signBits = binary("&", sameSign, binary("^", left, result, wordType()), wordType());
        } else {
            signBits = binary("&", binary("^", left, right, wordType()),
                              binary("^", left, result, wordType()), wordType());
        }
        const auto overflow = binary("<", cast(signBits, signedWordType()), constant(0, signedWordType()),
                                       ScalarType::boolean());
        setNzFlags(instruction, result, executionCondition);
        writeFlag(instruction, "arm_v", flagV_, overflow, executionCondition);
        writeFlag(instruction, "arm_c", flagC_, carry, executionCondition);
    }

    void setLogicalFlags(const NativeInstruction& instruction, const ExpressionPtr& result,
                         const ExpressionPtr& shiftedCarry, const ExpressionPtr& executionCondition) {
        setNzFlags(instruction, result, executionCondition);
        if (shiftedCarry) writeFlag(instruction, "arm_c", flagC_, shiftedCarry, executionCondition);
    }

    struct ShiftResult {
        ExpressionPtr value;
        ExpressionPtr carry;
    };

    static ExpressionPtr bitAt(const ExpressionPtr& value, const ExpressionPtr& index) {
        const auto shifted = binary(">>", value, index, wordType());
        return binary("!=", binary("&", shifted, constant(1, wordType()), wordType()),
                      constant(0, wordType()), ScalarType::boolean());
    }

    static ExpressionPtr bitAt(const ExpressionPtr& value, uint32_t index) {
        return bitAt(value, constant(index, wordType()));
    }

    static bool supportedShift(const Shift& shift) {
        switch (shift.type) {
        case ARM_SFT_INVALID:
        case ARM_SFT_ASR:
        case ARM_SFT_LSL:
        case ARM_SFT_LSR:
        case ARM_SFT_ROR:
        case ARM_SFT_RRX:
        case ARM_SFT_ASR_REG:
        case ARM_SFT_LSL_REG:
        case ARM_SFT_LSR_REG:
        case ARM_SFT_ROR_REG:
            return true;
        default:
            return false;
        }
    }

    ShiftResult applyShift(ExpressionPtr value, const Shift& shift) const {
        if (shift.type == ARM_SFT_INVALID) return {value, nullptr};
        if (!supportedShift(shift)) return {};

        const bool registerShift = shift.type == ARM_SFT_ASR_REG || shift.type == ARM_SFT_LSL_REG ||
                                   shift.type == ARM_SFT_LSR_REG || shift.type == ARM_SFT_ROR_REG;
        const auto type = registerShift ? shift.type - ARM_SFT_ASR_REG + ARM_SFT_ASR : shift.type;
        const auto oldCarry = flagCondition(flagC_);
        const auto boolean = ScalarType::boolean();
        const auto falseValue = constant(0, boolean);
        if (type == ARM_SFT_RRX) {
            if (registerShift) return {};
            const auto result = binary("|", binary(">>", value, constant(1, wordType()), wordType()),
                                       binary("<<", carryValue(), constant(31, wordType()), wordType()), wordType());
            return {result, bitAt(value, 0)};
        }

        if (!registerShift) {
            uint32_t count = shift.value;
            if (count == 0 && type == ARM_SFT_LSL) return {value, nullptr};
            if (count == 0 && (type == ARM_SFT_LSR || type == ARM_SFT_ASR)) count = 32;
            if (count == 0 && type == ARM_SFT_ROR) return {};
            const auto amount = constant(count, wordType());
            ExpressionPtr result;
            ExpressionPtr carry;
            switch (type) {
            case ARM_SFT_LSL:
                result = count >= 32 ? constant(0, wordType()) : binary("<<", value, amount, wordType());
                if (count < 32) carry = bitAt(value, 32 - count);
                else if (count == 32) carry = bitAt(value, 0);
                else carry = falseValue;
                break;
            case ARM_SFT_LSR:
                result = count >= 32 ? constant(0, wordType()) : binary(">>", value, amount, wordType());
                if (count < 32) carry = bitAt(value, count - 1);
                else if (count == 32) carry = bitAt(value, 31);
                else carry = falseValue;
                break;
            case ARM_SFT_ASR:
                result = cast(binary(">>", cast(value, signedWordType()),
                                     constant(std::min(count, 31U), wordType()), signedWordType()), wordType());
                carry = bitAt(value, count == 0 ? 0 : std::min(count, 32U) - 1);
                break;
            case ARM_SFT_ROR: {
                const uint32_t rotate = count & 31U;
                if (rotate == 0) {
                    result = value;
                } else {
                    result = binary("|", binary(">>", value, constant(rotate, wordType()), wordType()),
                                    binary("<<", value, constant(32 - rotate, wordType()), wordType()), wordType());
                }
                carry = bitAt(result, 31);
                break;
            }
            default:
                return {};
            }
            return {result, carry};
        }

        const auto registerName = shiftRegisterName(shift.value);
        if (registerName.empty()) return {};
        const auto amount = binary("&", readOperandRegister(registerName), constant(0xFF, wordType()), wordType());
        const auto masked = binary("&", amount, constant(31, wordType()), wordType());
        const auto zeroAmount = binary("==", amount, constant(0, wordType()), boolean);
        const auto inRange = binary("<", amount, constant(32, wordType()), boolean);
        const auto is32 = binary("==", amount, constant(32, wordType()), boolean);
        ExpressionPtr result;
        ExpressionPtr carry;
        switch (type) {
        case ARM_SFT_LSL:
            result = select(inRange, binary("<<", value, masked, wordType()), constant(0, wordType()), wordType());
            carry = select(zeroAmount, oldCarry,
                           select(inRange, bitAt(value, binary("-", constant(32, wordType()), masked, wordType())),
                                  select(is32, bitAt(value, 0), falseValue, boolean), boolean), boolean);
            break;
        case ARM_SFT_LSR:
            result = select(inRange, binary(">>", value, masked, wordType()), constant(0, wordType()), wordType());
            carry = select(zeroAmount, oldCarry,
                           select(inRange, bitAt(value, binary("-", masked, constant(1, wordType()), wordType())),
                                  select(is32, bitAt(value, 31), falseValue, boolean), boolean), boolean);
            break;
        case ARM_SFT_ASR: {
            const auto arithmetic = cast(binary(">>", cast(value, signedWordType()), masked, signedWordType()), wordType());
            const auto saturated = cast(binary(">>", cast(value, signedWordType()), constant(31, wordType()),
                                               signedWordType()), wordType());
            result = select(inRange, arithmetic, saturated, wordType());
            carry = select(zeroAmount, oldCarry,
                           select(inRange, bitAt(value, binary("-", masked, constant(1, wordType()), wordType())),
                                  bitAt(value, 31), boolean), boolean);
            break;
        }
        case ARM_SFT_ROR:
            result = binary("|", binary(">>", value, masked, wordType()),
                            binary("<<", value, binary("&", binary("-", constant(32, wordType()), masked, wordType()),
                                                       constant(31, wordType()), wordType()), wordType()), wordType());
            carry = select(zeroAmount, oldCarry, bitAt(result, 31), boolean);
            break;
        default:
            return {};
        }
        return {result, carry};
    }

    static std::string shiftRegisterName(uint32_t id) {
        if (id >= ARM_REG_R0 && id <= ARM_REG_R12) return "r" + std::to_string(id - ARM_REG_R0);
        switch (id) {
        case ARM_REG_SP: return "sp";
        case ARM_REG_LR: return "lr";
        case ARM_REG_PC: return "pc";
        default: return {};
        }
    }

    std::string normalizedText() const {
        if (currentInstruction_ == nullptr) return {};
        std::string text = currentInstruction_->text;
        text.erase(std::remove_if(text.begin(), text.end(), [](unsigned char c) { return std::isspace(c) != 0; }), text.end());
        return text;
    }

    bool memoryIndexSubtracted(const Operand& operand) const {
        if (operand.memoryIndex.empty()) return false;
        const auto text = normalizedText();
        const auto open = text.find('[');
        const auto close = text.find(']', open);
        if (open == std::string::npos || close == std::string::npos) return false;
        return text.substr(open, close - open).find("-" + operand.memoryIndex) != std::string::npos;
    }

    ExpressionPtr memoryOffset(const Operand& operand) const {
        ExpressionPtr offset;
        if (!operand.memoryIndex.empty()) {
            auto shifted = applyShift(readOperandRegister(operand.memoryIndex), operand.shift);
            if (!shifted.value) return nullptr;
            offset = shifted.value;
            if (memoryIndexSubtracted(operand)) offset = unary("-", offset, wordType());
            if (operand.scale != 1) {
                offset = binary("*", offset, constant(static_cast<uint32_t>(operand.scale), wordType()), wordType());
            }
        }
        if (operand.displacement != 0 || !offset) {
            const auto displacement = constant(static_cast<uint32_t>(operand.displacement), wordType());
            offset = offset ? binary("+", offset, displacement, wordType()) : displacement;
        }
        return offset;
    }

    ExpressionPtr valueOf(const Operand& operand) const {
        switch (operand.kind) {
        case OperandKind::Register:
            return applyShift(readOperandRegister(operand.reg), operand.shift).value;
        case OperandKind::Immediate:
            return constant(static_cast<uint32_t>(operand.immediate), wordType());
        case OperandKind::Memory:
            return load(addressOf(operand), wordType());
        case OperandKind::FloatingPoint:
            return constant(static_cast<uint64_t>(operand.floatingPoint), ScalarType::floatBits(32));
        }
        return nullptr;
    }

    ExpressionPtr addressOf(const Operand& operand) const {
        ExpressionPtr address;
        if (!operand.memoryBase.empty()) {
            if (operand.memoryBase == "pc" && isThumb()) {
                address = constant(programCounterValue() & ~uint32_t{3}, pointerType());
            } else {
                address = cast(readOperandRegister(operand.memoryBase), pointerType());
            }
        }
        const auto offset = memoryOffset(operand);
        if (!offset) return nullptr;
        if (operand.memoryIndex.empty() && operand.displacement == 0 && address) return address;
        return address ? binary("+", address, cast(offset, pointerType()), pointerType())
                       : cast(offset, pointerType());
    }

    ExpressionPtr postIndexOffset(const Operand& operand) const {
        auto offset = valueOf(operand);
        if (!offset) return nullptr;
        const auto text = normalizedText();
        const auto post = text.find("],");
        if (post != std::string::npos) {
            size_t sign = post + 2;
            if (sign < text.size() && text[sign] == '#') ++sign;
            if (sign < text.size() && text[sign] == '-') offset = unary("-", offset, wordType());
        }
        return offset;
    }

    static bool hasWriteback(const NativeInstruction& instruction) {
        if (instruction.writeback == WritebackMode::PreIndex) return true;
        std::string text = instruction.text;
        text.erase(std::remove_if(text.begin(), text.end(), [](unsigned char c) { return std::isspace(c) != 0; }), text.end());
        return text.find('!') != std::string::npos;
    }

    ExpressionPtr decodedPostIndexOffset(const NativeInstruction& instruction) const {
        if (!instruction.writebackRegister.empty()) return readOperandRegister(instruction.writebackRegister);
        return constant(static_cast<uint32_t>(instruction.writebackOffset), wordType());
    }

    void addAssignmentWithCondition(const NativeInstruction& instruction, const std::string& destination,
                                    ExpressionPtr value, ExpressionPtr executionCondition) {
        if (destination.empty() || !value) return;
        if (destination == "pc") {
            addBranch(instruction, std::move(executionCondition), std::move(value));
            return;
        }
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Assign;
        statement.destination = readRegister(destination);
        statement.condition = executionCondition;
        if (executionCondition) {
            value = select(executionCondition, value, readRegister(destination), wordType());
        }
        statement.value = std::move(value);
        add(std::move(statement));
    }

    void addAssignment(const NativeInstruction& instruction, const std::string& destination, ExpressionPtr value) {
        addAssignmentWithCondition(instruction, destination, std::move(value), condition(instruction));
    }

    void addStore(const NativeInstruction& instruction, ExpressionPtr address, ExpressionPtr value) {
        if (!address || !value || value->type.bits == 0) {
            unsupported(instruction);
            return;
        }
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Store;
        statement.destination = std::move(address);
        statement.condition = condition(instruction);
        if (statement.condition) {
            value = select(statement.condition, value, load(statement.destination, value->type), value->type);
        }
        statement.value = std::move(value);
        add(std::move(statement));
    }

    bool addBranch(const NativeInstruction& instruction, ExpressionPtr branchCondition = nullptr,
                   ExpressionPtr explicitTarget = nullptr) {
        if (instruction.operands.empty() && !explicitTarget) return false;
        Statement statement;
        statement.address = instruction.address;
        statement.kind = branchCondition ? Statement::Kind::ConditionalBranch : Statement::Kind::Branch;
        statement.condition = std::move(branchCondition);
        if (explicitTarget) {
            statement.target = std::move(explicitTarget);
        } else {
            const auto& target = instruction.operands.back();
            statement.target = target.kind == OperandKind::Immediate
                                   ? constant(static_cast<uint64_t>(target.immediate), pointerType())
                                   : valueOf(target);
        }
        if (!statement.target) return false;
        add(std::move(statement));
        return true;
    }

    bool makeCallStatements(const NativeInstruction& instruction, std::vector<Statement>& statements) {
        if (instruction.operands.empty()) return false;
        Statement link;
        link.address = instruction.address;
        link.kind = Statement::Kind::Assign;
        link.destination = readRegister("lr");
        const uint32_t returnAddress = static_cast<uint32_t>(instruction.address + instruction.size);
        link.value = constant(returnAddress | (isThumb() ? 1U : 0U), wordType());
        statements.push_back(std::move(link));

        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Call;
        statement.destination = readRegister("r0");
        const auto& target = instruction.operands.back();
        statement.target = target.kind == OperandKind::Immediate
                               ? constant(static_cast<uint64_t>(target.immediate), pointerType())
                               : valueOf(target);
        if (!statement.target) return false;
        statement.arguments = {readRegister("r0"), readRegister("r1"), readRegister("r2"), readRegister("r3")};
        statements.push_back(std::move(statement));
        return true;
    }

    uint64_t syntheticBlockAddress() const {
        uint64_t candidate = 0xFFFFFF00ULL - deferredBlocks_.size();
        const auto used = [&](uint64_t address) {
            return std::any_of(instructions_.begin(), instructions_.end(), [&](const NativeInstruction& instruction) {
                return instruction.address == address;
            });
        };
        while (used(candidate)) --candidate;
        return candidate;
    }

    bool addCall(const NativeInstruction& instruction) {
        std::vector<Statement> call;
        if (!makeCallStatements(instruction, call)) return false;
        if (isUnconditional(instruction)) {
            for (auto& statement : call) add(std::move(statement));
            return true;
        }

        const auto callAddress = syntheticBlockAddress();
        const auto joinAddress = instruction.address + instruction.size;
        if (!addBranch(instruction, condition(instruction), constant(callAddress, pointerType()))) return false;
        addBranch(instruction, nullptr, constant(joinAddress, pointerType()));
        output_.blocks.push_back({joinAddress, {}});
        terminated_ = false;

        Statement join;
        join.address = instruction.address;
        join.kind = Statement::Kind::Branch;
        join.target = constant(joinAddress, pointerType());
        call.push_back(std::move(join));
        deferredBlocks_.push_back({callAddress, std::move(call)});
        return true;
    }

    void addReturn(const NativeInstruction& instruction) {
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Return;
        statement.value = managedFloatBridge_
            ? unary("global::System.BitConverter.SingleToUInt32Bits", reg("s0", ScalarType::floatBits(32)), wordType())
            : readRegister("r0");
        add(std::move(statement));
    }

    void unsupported(const NativeInstruction& instruction) {
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Call;
        statement.target = reg("RuntimeCalls.Unsupported_" + instruction.mnemonic, pointerType());
        statement.arguments = {constant(instruction.address, pointerType())};
        add(std::move(statement));
    }

    bool isDirectBranch(const NativeInstruction& instruction) const {
        return instruction.id == ARM_INS_B || instruction.id == ARM_INS_BX || instruction.id == ARM_INS_CBZ ||
               instruction.id == ARM_INS_CBNZ;
    }

    void collectBranchTargets() {
        for (const auto& instruction : instructions_) {
            if (!isDirectBranch(instruction) || instruction.operands.empty()) continue;
            const auto& target = instruction.operands.back();
            if (target.kind == OperandKind::Immediate) {
                branchTargets_.insert(static_cast<uint64_t>(target.immediate));
            }
        }
    }

    static ExpressionPtr zeroExtend(ExpressionPtr value, uint16_t bits) {
        return cast(cast(value, ScalarType::uintBits(bits)), wordType());
    }

    static ExpressionPtr signExtend(ExpressionPtr value, uint16_t bits) {
        return cast(cast(cast(value, ScalarType::intBits(bits)), signedWordType()), wordType());
    }

    static uint32_t bitMask(uint32_t width) {
        return width >= 32 ? 0xFFFFFFFFU : ((1U << width) - 1U);
    }

    static ScalarType vfpStorageType(const std::string& name) {
        if (name.size() < 2 || (name[0] != 's' && name[0] != 'd') ||
            !std::all_of(name.begin() + 1, name.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
            return ScalarType::unknown();
        }
        const int index = std::stoi(name.substr(1));
        if (name[0] == 's' && index >= 0 && index <= 31) return ScalarType::floatBits(32);
        if (name[0] == 'd' && index >= 0 && index <= 31) return ScalarType::floatBits(64);
        return ScalarType::unknown();
    }

    static ScalarType conversionType(const std::string& name) {
        if (name == "f32") return ScalarType::floatBits(32);
        if (name == "f64") return ScalarType::floatBits(64);
        if (name == "s32") return ScalarType::intBits(32);
        if (name == "u32") return wordType();
        return ScalarType::unknown();
    }

    static ExpressionPtr floatingConstant(double value, ScalarType type) {
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

    static ExpressionPtr floatFromBits(ExpressionPtr value, ScalarType type) {
        return unary(type.bits == 32 ? "global::System.BitConverter.UInt32BitsToSingle"
                                     : "global::System.BitConverter.UInt64BitsToDouble",
                     std::move(value), type);
    }

    static ExpressionPtr floatToBits(ExpressionPtr value, ScalarType type) {
        return unary(type.bits == 32 ? "global::System.BitConverter.SingleToUInt32Bits"
                                     : "global::System.BitConverter.DoubleToUInt64Bits",
                     std::move(value), type.bits == 32 ? wordType() : doubleWordType());
    }

    bool addVfpAssignment(const NativeInstruction& instruction, const Operand& destination, ExpressionPtr value) {
        if (destination.kind != OperandKind::Register || !value) return false;
        const auto storage = vfpStorageType(destination.reg);
        if (storage.bits == 0) return false;
        if (value->type.kind != ScalarKind::FloatingPoint) {
            if (value->type.bits != storage.bits) return false;
            value = floatFromBits(value, storage);
        }
        if (value->type.kind != storage.kind || value->type.bits != storage.bits) return false;
        const auto executionCondition = condition(instruction);
        if (executionCondition) {
            value = select(executionCondition, value, reg(destination.reg, storage), storage);
        }
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Assign;
        statement.destination = reg(destination.reg, storage);
        statement.condition = executionCondition;
        statement.value = std::move(value);
        add(std::move(statement));
        return true;
    }

    ExpressionPtr readVfpStorage(const Operand& operand) const {
        if (operand.kind != OperandKind::Register) return nullptr;
        const auto storage = vfpStorageType(operand.reg);
        return storage.bits == 0 ? nullptr : reg(operand.reg, storage);
    }

    ExpressionPtr readVfp(const Operand& operand, ScalarType semanticType) const {
        auto value = readVfpStorage(operand);
        if (!value) return nullptr;
        const auto storage = value->type;
        if (semanticType.kind == storage.kind && semanticType.bits == storage.bits) return value;
        if (semanticType.bits == storage.bits && semanticType.kind != ScalarKind::FloatingPoint) {
            value = floatToBits(value, storage);
            return cast(value, semanticType);
        }
        return nullptr;
    }

    ExpressionPtr readVfpBits(const Operand& operand) const {
        const auto value = readVfpStorage(operand);
        return value ? floatToBits(value, value->type) : nullptr;
    }

    int laneIndex(size_t operandIndex) const {
        if (currentInstruction_ == nullptr) return -1;
        if (operandIndex < currentInstruction_->operands.size() &&
            currentInstruction_->operands[operandIndex].laneIndex >= 0) {
            return currentInstruction_->operands[operandIndex].laneIndex;
        }
        const auto& text = currentInstruction_->text;
        size_t begin = text.find(' ');
        if (begin == std::string::npos) return -1;
        ++begin;
        for (size_t index = 0; index < operandIndex; ++index) {
            const auto comma = text.find(',', begin);
            if (comma == std::string::npos) return -1;
            begin = comma + 1;
        }
        const auto open = text.find('[', begin);
        const auto close = open == std::string::npos ? std::string::npos : text.find(']', open);
        if (open == std::string::npos || close == std::string::npos || close == open + 1) return -1;
        int lane = 0;
        for (size_t position = open + 1; position < close; ++position) {
            if (!std::isdigit(static_cast<unsigned char>(text[position]))) return -1;
            lane = lane * 10 + text[position] - '0';
            if (lane >= 16) return -1;
        }
        return lane;
    }

    ExpressionPtr readLane(const Operand& operand, int lane, uint32_t width) const {
        if (width != 8 && width != 16 && width != 32) return nullptr;
        if (lane < 0 || lane >= static_cast<int>(64 / width) || vfpStorageType(operand.reg).bits != 64) return nullptr;
        auto bits = readVfpBits(operand);
        if (lane != 0) bits = binary(">>", bits, constant(lane * width, doubleWordType()), doubleWordType());
        return cast(bits, ScalarType::uintBits(width));
    }

    bool writeLane(const NativeInstruction& instruction, const Operand& destination, int lane,
                   uint32_t width, ExpressionPtr value) {
        if (!value || width == 0 || width > 32 || lane < 0 ||
            lane >= static_cast<int>(64 / width) || vfpStorageType(destination.reg).bits != 64) return false;
        const auto shift = static_cast<uint32_t>(lane * width);
        const uint64_t laneMask = (uint64_t{1} << width) - 1;
        const auto mask = ~(laneMask << shift);
        const auto preserved = binary("&", readVfpBits(destination), constant(mask, doubleWordType()), doubleWordType());
        auto inserted = binary("&", cast(value, doubleWordType()), constant(laneMask, doubleWordType()), doubleWordType());
        if (shift != 0) inserted = binary("<<", inserted, constant(shift, doubleWordType()), doubleWordType());
        return addVfpAssignment(instruction, destination, binary("|", preserved, inserted, doubleWordType()));
    }

    static uint32_t neonWidth(const std::string& mnemonic) {
        const auto dot = mnemonic.rfind('.');
        if (dot == std::string::npos || dot + 1 >= mnemonic.size()) return 0;
        const bool typed = mnemonic[dot + 1] == 'i' || mnemonic[dot + 1] == 's' || mnemonic[dot + 1] == 'u';
        const auto suffix = mnemonic.substr(dot + (typed ? 2 : 1));
        if (suffix == "8") return 8;
        if (suffix == "16") return 16;
        if (suffix == "32") return 32;
        if (suffix == "64") return 64;
        return 0;
    }

    static ExpressionPtr splat(ExpressionPtr value, uint32_t width) {
        const auto mask = (uint64_t{1} << width) - 1;
        const auto lane = binary("&", cast(value, doubleWordType()), constant(mask, doubleWordType()), doubleWordType());
        ExpressionPtr result = constant(0, doubleWordType());
        for (uint32_t shift = 0; shift < 64; shift += width) {
            auto part = shift == 0 ? lane : binary("<<", lane, constant(shift, doubleWordType()), doubleWordType());
            result = binary("|", result, part, doubleWordType());
        }
        return result;
    }

    bool liftNeonMove(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() != 2) return false;
        const auto& mnemonic = instruction.mnemonic;
        if (ops[0].kind != OperandKind::Register || vfpStorageType(ops[0].reg).bits != 64) return false;
        if (ops[1].kind == OperandKind::Immediate &&
            (mnemonic.starts_with("vmov.i") || mnemonic.starts_with("vmvn.i"))) {
            const auto widthPosition = mnemonic.find(".i");
            if (widthPosition == std::string::npos) return false;
            const auto width = static_cast<uint32_t>(std::stoi(mnemonic.substr(widthPosition + 2)));
            if (width != 8 && width != 16 && width != 32 && width != 64) return false;
            const auto immediate = static_cast<uint64_t>(ops[1].immediate);
            uint64_t lane = width == 64 ? immediate : width == 32 ? immediate & 0xFFFFFFFFULL :
                width == 16 ? immediate & 0xFFFFULL : immediate & 0xFFULL;
            if (mnemonic.starts_with("vmvn")) lane = ~lane;
            if (width == 64) return addVfpAssignment(instruction, ops[0], constant(lane, doubleWordType()));
            const auto mask = width == 32 ? 0xFFFFFFFFULL : width == 16 ? 0xFFFFULL : 0xFFULL;
            lane &= mask;
            uint64_t replicated = 0;
            for (uint32_t shift = 0; shift < 64; shift += width) replicated |= lane << shift;
            return addVfpAssignment(instruction, ops[0], constant(replicated, doubleWordType()));
        }
        const auto destinationLane = laneIndex(0);
        const auto sourceLane = laneIndex(1);
        if (destinationLane >= 0 && ops[1].kind == OperandKind::Register) {
            const auto width = neonWidth(mnemonic);
            if (width != 8 && width != 16 && width != 32) return false;
            return writeLane(instruction, ops[0], destinationLane, width, readRegister(ops[1].reg));
        }
        if (ops[0].kind == OperandKind::Register && ops[1].kind == OperandKind::Register && sourceLane >= 0) {
            return false;
        }
        return false;
    }

    bool liftNeonDup(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto width = neonWidth(instruction.mnemonic);
        if (ops.size() != 2 || (width != 8 && width != 16 && width != 32) ||
            ops[0].kind != OperandKind::Register || vfpStorageType(ops[0].reg).bits != 64) return false;
        if (ops[1].kind != OperandKind::Register) return false;
        if (vfpStorageType(ops[1].reg).bits == 64) {
            const auto lane = readLane(ops[1], laneIndex(1), width);
            return lane && addVfpAssignment(instruction, ops[0], splat(lane, width));
        }
        return addVfpAssignment(instruction, ops[0], splat(readRegister(ops[1].reg), width));
    }

    bool liftNeonArithmetic(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto width = neonWidth(instruction.mnemonic);
        if ((width != 8 && width != 16 && width != 32 && width != 64) ||
            (ops.size() != 3 && !(ops.size() == 2 && instruction.id == ARM_INS_VMVN))) return false;
        for (const auto& operand : ops) {
            if (operand.kind != OperandKind::Register || vfpStorageType(operand.reg).bits != 64) return false;
        }
        if (instruction.id == ARM_INS_VMVN) {
            return addVfpAssignment(instruction, ops[0], unary("~", readVfpBits(ops[1]), doubleWordType()));
        }
        const char* operation = nullptr;
        switch (instruction.id) {
        case ARM_INS_VADD: operation = "+"; break;
        case ARM_INS_VSUB: operation = "-"; break;
        case ARM_INS_VMUL: operation = "*"; break;
        case ARM_INS_VAND: operation = "&"; break;
        case ARM_INS_VORR: operation = "|"; break;
        case ARM_INS_VEOR: operation = "^"; break;
        default: return false;
        }
        if (width == 64) {
            return addVfpAssignment(instruction, ops[0],
                binary(operation, readVfpBits(ops[1]), readVfpBits(ops[2]), doubleWordType()));
        }
        ExpressionPtr packed = constant(0, doubleWordType());
        for (uint32_t lane = 0; lane < 64 / width; ++lane) {
            const auto left = readLane(ops[1], lane, width);
            const auto right = readLane(ops[2], lane, width);
            if (!left || !right) return false;
            auto part = cast(binary(operation, left, right, ScalarType::uintBits(width)), doubleWordType());
            if (lane != 0) part = binary("<<", part, constant(lane * width, doubleWordType()), doubleWordType());
            packed = binary("|", packed, part, doubleWordType());
        }
        return addVfpAssignment(instruction, ops[0], packed);
    }

    bool liftVfpCompare(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() != 2) return false;
        const bool single = instruction.mnemonic.ends_with(".f32");
        const bool doublePrecision = instruction.mnemonic.ends_with(".f64");
        if (!single && !doublePrecision) return false;
        const auto type = ScalarType::floatBits(single ? 32 : 64);
        const auto left = readVfp(ops[0], type);
        ExpressionPtr right;
        if (ops[1].kind == OperandKind::Immediate && ops[1].immediate == 0) right = constant(0, type);
        else if (ops[1].kind == OperandKind::FloatingPoint) right = floatingConstant(ops[1].floatingPoint, type);
        else right = readVfp(ops[1], type);
        if (!left || !right) return false;
        const auto boolean = ScalarType::boolean();
        const auto unordered = binary("unordered", left, right, boolean);
        const auto less = binary("<", left, right, boolean);
        const auto equal = binary("==", left, right, boolean);
        const auto greater = binary(">", left, right, boolean);
        const auto executionCondition = prepareExecutionCondition(instruction, true);
        writeFlag(instruction, "arm_n", flagN_, less, executionCondition);
        writeFlag(instruction, "arm_z", flagZ_, equal, executionCondition);
        writeFlag(instruction, "arm_c", flagC_,
            binary("||", unordered, binary("||", greater, equal, boolean), boolean), executionCondition);
        writeFlag(instruction, "arm_v", flagV_, unordered, executionCondition);
        return true;
    }

    bool liftVfpSelect(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() != 3) return false;
        const bool single = instruction.mnemonic.ends_with(".f32");
        const bool doublePrecision = instruction.mnemonic.ends_with(".f64");
        if (!single && !doublePrecision) return false;
        uint32_t code = ARM_CC_INVALID;
        switch (instruction.id) {
        case ARM_INS_VSELEQ: code = ARM_CC_EQ; break;
        case ARM_INS_VSELGE: code = ARM_CC_GE; break;
        case ARM_INS_VSELGT: code = ARM_CC_GT; break;
        case ARM_INS_VSELVS: code = ARM_CC_VS; break;
        default: return false;
        }
        const auto type = ScalarType::floatBits(single ? 32 : 64);
        const auto left = readVfp(ops[1], type);
        const auto right = readVfp(ops[2], type);
        if (!left || !right) return false;
        return addVfpAssignment(instruction, ops[0], select(conditionFromArm(code), left, right, type));
    }

    bool liftVfpMemory(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2 || ops.size() > 3 || ops[0].kind != OperandKind::Register ||
            ops[1].kind != OperandKind::Memory) return false;
        const auto storage = vfpStorageType(ops[0].reg);
        if (storage.bits == 0) return false;
        const auto& memory = ops[1];
        const bool postIndex = instruction.writeback == WritebackMode::PostIndex || ops.size() == 3;
        const bool preIndex = hasWriteback(instruction);
        if (postIndex && preIndex) return false;
        const auto& base = memory.memoryBase;
        if (base.empty() || (base == "pc" && (postIndex || preIndex)) ||
            (instruction.id == ARM_INS_VLDR && base == ops[0].reg && (postIndex || preIndex))) return false;
        const auto address = addressOf(memory);
        if (!address) return false;
        if (instruction.id == ARM_INS_VLDR) addVfpAssignment(instruction, ops[0], load(address, storage));
        else addStore(instruction, address, readVfpStorage(ops[0]));
        if (postIndex || preIndex) {
            const auto offset = postIndex
                ? (ops.size() == 3 ? postIndexOffset(ops[2]) : decodedPostIndexOffset(instruction))
                : memoryOffset(memory);
            if (!offset) return false;
            addAssignment(instruction, base, binary("+", cast(readOperandRegister(base), pointerType()),
                cast(offset, pointerType()), pointerType()));
        }
        return true;
    }

    bool liftVfpStack(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.empty()) return false;
        const bool push = instruction.id == ARM_INS_VPUSH;
        uint32_t total = 0;
        for (const auto& operand : ops) {
            if (operand.kind != OperandKind::Register) return false;
            const auto storage = vfpStorageType(operand.reg);
            if (storage.bits == 0) return false;
            total += storage.bits / 8;
        }
        const auto oldStack = cast(readRegister("sp"), pointerType());
        const auto base = push
            ? binary("-", oldStack, constant(total, pointerType()), pointerType())
            : oldStack;
        uint32_t offset = 0;
        for (const auto& operand : ops) {
            const auto storage = vfpStorageType(operand.reg);
            const auto address = offset == 0 ? base : binary("+", base, constant(offset, pointerType()), pointerType());
            if (push) addStore(instruction, address, readVfpStorage(operand));
            else addVfpAssignment(instruction, operand, load(address, storage));
            offset += storage.bits / 8;
        }
        addAssignment(instruction, "sp", binary(push ? "-" : "+", oldStack, constant(total, pointerType()), pointerType()));
        return true;
    }

    bool liftVmrs(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        return ops.size() == 2 && ops[0].kind == OperandKind::Register && ops[1].kind == OperandKind::Register &&
            ops[0].reg == "apsr_nzcv" && ops[1].reg == "fpscr";
    }

    bool needsManagedFloatBridge() const {
        bool scalarAdd = false;
        bool explicitBinding = false;
        for (const auto& instruction : instructions_) {
            if (instruction.id == ARM_INS_VADD && instruction.mnemonic == "vadd.f32") scalarAdd = true;
            if (instruction.id == ARM_INS_VMOV || instruction.id == ARM_INS_VCVT || instruction.id == ARM_INS_VCVTR) {
                explicitBinding = true;
            }
        }
        return scalarAdd && !explicitBinding;
    }

    bool liftVfpArithmetic(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const bool single = instruction.mnemonic.ends_with(".f32");
        const bool doublePrecision = instruction.mnemonic.ends_with(".f64");
        if (!single && !doublePrecision) return false;
        const auto type = ScalarType::floatBits(single ? 32 : 64);
        for (const auto& operand : ops) {
            const auto storage = operand.kind == OperandKind::Register ? vfpStorageType(operand.reg) : ScalarType::unknown();
            if (storage.kind != ScalarKind::FloatingPoint || storage.bits != type.bits) return false;
        }
        if (ops.size() == 2 && (instruction.id == ARM_INS_VNEG || instruction.id == ARM_INS_VABS)) {
            if (instruction.id == ARM_INS_VNEG) {
                return addVfpAssignment(instruction, ops[0], unary("-", readVfp(ops[1], type), type));
            }
            const auto mask = single ? 0x7FFFFFFFULL : 0x7FFFFFFFFFFFFFFFULL;
            const auto bits = binary("&", readVfpBits(ops[1]), constant(mask, single ? wordType() : doubleWordType()),
                                     single ? wordType() : doubleWordType());
            return addVfpAssignment(instruction, ops[0], bits);
        }
        if (ops.size() != 3) return false;
        const char* operation = nullptr;
        switch (instruction.id) {
        case ARM_INS_VADD: operation = "+"; break;
        case ARM_INS_VSUB: operation = "-"; break;
        case ARM_INS_VMUL:
        case ARM_INS_VNMUL: operation = "*"; break;
        case ARM_INS_VDIV: operation = "/"; break;
        case ARM_INS_VMLA:
        case ARM_INS_VMLS: operation = "*"; break;
        default: return false;
        }
        auto value = binary(operation, readVfp(ops[1], type), readVfp(ops[2], type), type);
        if (instruction.id == ARM_INS_VMLA) value = binary("+", readVfp(ops[0], type), value, type);
        if (instruction.id == ARM_INS_VMLS) value = binary("-", readVfp(ops[0], type), value, type);
        if (instruction.id == ARM_INS_VNMUL) value = unary("-", value, type);
        return addVfpAssignment(instruction, ops[0], value);
    }

    bool liftVfpMove(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() == 2 && ops[0].kind == OperandKind::Register && ops[1].kind == OperandKind::Register &&
            vfpStorageType(ops[0].reg).bits == 0 && laneIndex(1) >= 0) {
            const auto width = neonWidth(instruction.mnemonic);
            const auto value = readLane(ops[1], laneIndex(1), width);
            if (!value) return false;
            const auto extended = instruction.mnemonic.starts_with("vmov.s")
                ? signExtend(value, width) : zeroExtend(value, width);
            addAssignment(instruction, ops[0].reg, extended);
            return true;
        }
        if (ops.size() == 2 && ops[0].kind == OperandKind::Register && vfpStorageType(ops[0].reg).bits == 64 &&
            (laneIndex(0) >= 0 || (ops[1].kind == OperandKind::Immediate &&
             (instruction.mnemonic.starts_with("vmov.i") || instruction.mnemonic.starts_with("vmvn.i"))))) {
            return liftNeonMove(instruction);
        }
        if (ops.size() == 2) {
            const auto destinationType = ops[0].kind == OperandKind::Register
                ? vfpStorageType(ops[0].reg) : ScalarType::unknown();
            const auto sourceType = ops[1].kind == OperandKind::Register
                ? vfpStorageType(ops[1].reg) : ScalarType::unknown();
            if (destinationType.bits != 0 && sourceType.bits != 0) {
                return destinationType.bits == sourceType.bits && addVfpAssignment(instruction, ops[0], readVfpStorage(ops[1]));
            }
            if (destinationType.bits == 32 && ops[1].kind == OperandKind::Register) {
                return addVfpAssignment(instruction, ops[0], floatFromBits(readRegister(ops[1].reg), destinationType));
            }
            if (destinationType.bits != 0 && ops[1].kind == OperandKind::FloatingPoint) {
                return addVfpAssignment(instruction, ops[0], floatingConstant(ops[1].floatingPoint, destinationType));
            }
            if (ops[0].kind == OperandKind::Register && destinationType.bits == 0 && sourceType.bits == 32) {
                addAssignment(instruction, ops[0].reg, floatToBits(readVfpStorage(ops[1]), sourceType));
                return true;
            }
            return false;
        }
        if (ops.size() == 3) {
            const auto firstVfp = ops[0].kind == OperandKind::Register ? vfpStorageType(ops[0].reg) : ScalarType::unknown();
            const auto lastVfp = ops[2].kind == OperandKind::Register ? vfpStorageType(ops[2].reg) : ScalarType::unknown();
            if (firstVfp.bits == 64 && ops[1].kind == OperandKind::Register && ops[2].kind == OperandKind::Register &&
                lastVfp.bits == 0) {
                const auto low = cast(readRegister(ops[1].reg), doubleWordType());
                const auto high = binary("<<", cast(readRegister(ops[2].reg), doubleWordType()),
                                         constant(32, doubleWordType()), doubleWordType());
                return addVfpAssignment(instruction, ops[0],
                    floatFromBits(binary("|", high, low, doubleWordType()), firstVfp));
            }
            if (lastVfp.bits == 64 && ops[0].kind == OperandKind::Register && ops[1].kind == OperandKind::Register &&
                firstVfp.bits == 0) {
                const auto bits = floatToBits(readVfpStorage(ops[2]), lastVfp);
                addAssignment(instruction, ops[0].reg, cast(bits, wordType()));
                addAssignment(instruction, ops[1].reg,
                    cast(binary(">>", bits, constant(32, doubleWordType()), doubleWordType()), wordType()));
                return true;
            }
        }
        return false;
    }

    bool liftVfpConvert(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() != 2 || ops[0].kind != OperandKind::Register || ops[1].kind != OperandKind::Register) return false;
        const auto firstDot = instruction.mnemonic.find('.');
        const auto secondDot = firstDot == std::string::npos ? std::string::npos : instruction.mnemonic.find('.', firstDot + 1);
        if (firstDot == std::string::npos || secondDot == std::string::npos) return false;
        const auto destinationType = conversionType(instruction.mnemonic.substr(firstDot + 1, secondDot - firstDot - 1));
        const auto sourceType = conversionType(instruction.mnemonic.substr(secondDot + 1));
        const auto destinationStorage = vfpStorageType(ops[0].reg);
        const auto sourceStorage = vfpStorageType(ops[1].reg);
        if (destinationType.bits == 0 || sourceType.bits == 0 || destinationStorage.bits == 0 || sourceStorage.bits == 0 ||
            destinationStorage.bits != destinationType.bits || sourceStorage.bits != sourceType.bits) return false;
        if (destinationType.kind != ScalarKind::FloatingPoint &&
            sourceType.kind != ScalarKind::FloatingPoint) return false;
        const auto source = readVfp(ops[1], sourceType);
        if (!source) return false;
        auto converted = source;
        if (destinationType.kind != ScalarKind::FloatingPoint && instruction.id == ARM_INS_VCVTR) {
            converted = unary("round_ties_even", converted, sourceType);
        }
        return addVfpAssignment(instruction, ops[0], cast(converted, destinationType));
    }

    bool liftVfp(const NativeInstruction& instruction) {
        if (instruction.id == ARM_INS_VDUP) return liftNeonDup(instruction);
        if (instruction.id == ARM_INS_VCMP || instruction.id == ARM_INS_VCMPE) return liftVfpCompare(instruction);
        if (instruction.id == ARM_INS_VSELEQ || instruction.id == ARM_INS_VSELGE ||
            instruction.id == ARM_INS_VSELGT || instruction.id == ARM_INS_VSELVS) return liftVfpSelect(instruction);
        if (instruction.id == ARM_INS_VLDR || instruction.id == ARM_INS_VSTR) return liftVfpMemory(instruction);
        if (instruction.id == ARM_INS_VPUSH || instruction.id == ARM_INS_VPOP) return liftVfpStack(instruction);
        if (instruction.id == ARM_INS_VMRS) return liftVmrs(instruction);
        if (instruction.id == ARM_INS_VCVT || instruction.id == ARM_INS_VCVTR) return liftVfpConvert(instruction);
        if (instruction.id == ARM_INS_VMOV) return liftVfpMove(instruction);
        if (instruction.id == ARM_INS_VMVN && !instruction.operands.empty() &&
            instruction.operands.back().kind == OperandKind::Immediate) return liftVfpMove(instruction);
        if (neonWidth(instruction.mnemonic) != 0) {
            return liftNeonArithmetic(instruction);
        }
        if (instruction.id == ARM_INS_VMVN) return liftVfpMove(instruction);
        return liftVfpArithmetic(instruction);
    }

    bool liftMove(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() != 2 || ops[0].kind != OperandKind::Register) return false;
        const bool flagUpdate = updatesFlags(instruction);
        if (ops[0].reg == "pc" && flagUpdate) return false;
        const auto shifted = applyShift(readOperandRegister(ops[1].reg), ops[1].shift);
        ExpressionPtr value;
        switch (instruction.id) {
        case ARM_INS_MOV:
        case ARM_INS_MOVS:
        case ARM_INS_MOVW:
        case ARM_INS_MVN:
            if (ops[1].kind != OperandKind::Register && ops[1].kind != OperandKind::Immediate) return false;
            value = ops[1].kind == OperandKind::Register ? shifted.value : valueOf(ops[1]);
            if (instruction.id == ARM_INS_MVN) value = unary("~", value, wordType());
            break;
        case ARM_INS_MOVT:
            if (ops[1].kind != OperandKind::Immediate) return false;
            value = binary("|", binary("&", readRegister(ops[0].reg), constant(0xFFFF, wordType()), wordType()),
                           binary("<<", valueOf(ops[1]), constant(16, wordType()), wordType()), wordType());
            break;
        default:
            return false;
        }
        if (!value) return false;
        const auto executionCondition = prepareExecutionCondition(instruction, flagUpdate);
        if (flagUpdate) setLogicalFlags(instruction, value, shifted.carry, executionCondition);
        if (ops[0].reg == "pc" && isUnconditional(instruction) &&
            ops[1].kind == OperandKind::Register && ops[1].reg == "lr" && ops[1].shift.type == ARM_SFT_INVALID) {
            addReturn(instruction);
        } else {
            addAssignmentWithCondition(instruction, ops[0].reg, value, executionCondition);
        }
        return true;
    }

    bool liftArithmetic(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2 || ops.size() > 3 || ops[0].kind != OperandKind::Register) return false;
        const bool unaryForm = instruction.id == ARM_INS_NEG;
        const auto left = unaryForm ? constant(0, wordType())
                                    : ops.size() == 2 ? readOperandRegister(ops[0].reg) : valueOf(ops[1]);
        const auto right = valueOf(ops.back());
        if (!left || !right) return false;
        ExpressionPtr value;
        bool addition = false;
        bool withCarry = false;
        bool logical = false;
        bool reverseSubtract = false;
        switch (instruction.id) {
        case ARM_INS_ADD:
        case ARM_INS_ADDW:
            addition = true;
            value = binary("+", left, right, wordType());
            break;
        case ARM_INS_ADC:
            addition = true;
            withCarry = true;
            value = binary("+", binary("+", left, right, wordType()), carryValue(), wordType());
            break;
        case ARM_INS_SUB:
        case ARM_INS_SUBS:
        case ARM_INS_SUBW:
        case ARM_INS_NEG:
            value = binary("-", left, right, wordType());
            break;
        case ARM_INS_SBC:
            withCarry = true;
            value = binary("-", binary("+", binary("-", left, right, wordType()), carryValue(), wordType()),
                           constant(1, wordType()), wordType());
            break;
        case ARM_INS_RSB:
            reverseSubtract = true;
            value = binary("-", right, left, wordType());
            break;
        case ARM_INS_RSC:
            reverseSubtract = true;
            withCarry = true;
            value = binary("-", binary("+", binary("-", right, left, wordType()), carryValue(), wordType()),
                           constant(1, wordType()), wordType());
            break;
        case ARM_INS_AND:
            logical = true;
            value = binary("&", left, right, wordType());
            break;
        case ARM_INS_ORR:
            logical = true;
            value = binary("|", left, right, wordType());
            break;
        case ARM_INS_EOR:
            logical = true;
            value = binary("^", left, right, wordType());
            break;
        case ARM_INS_BIC:
            logical = true;
            value = binary("&", left, unary("~", right, wordType()), wordType());
            break;
        case ARM_INS_ORN:
            logical = true;
            value = binary("|", left, unary("~", right, wordType()), wordType());
            break;
        case ARM_INS_MUL:
            value = binary("*", left, right, wordType());
            break;
        case ARM_INS_SDIV:
            value = cast(binary("/", cast(left, signedWordType()), cast(right, signedWordType()), signedWordType()),
                         wordType());
            break;
        case ARM_INS_UDIV:
            value = binary("/", left, right, wordType());
            break;
        default:
            return false;
        }
        const bool flagUpdate = updatesFlags(instruction);
        if (ops[0].reg == "pc" && flagUpdate) return false;
        const auto executionCondition = prepareExecutionCondition(instruction, flagUpdate);
        if (flagUpdate) {
            if (logical) {
                const auto shifted = ops.back().kind == OperandKind::Register
                                         ? applyShift(readOperandRegister(ops.back().reg), ops.back().shift)
                                         : ShiftResult{};
                setLogicalFlags(instruction, value, shifted.carry, executionCondition);
            } else if (instruction.id == ARM_INS_MUL) {
                setNzFlags(instruction, value, executionCondition);
            } else if (instruction.id != ARM_INS_SDIV && instruction.id != ARM_INS_UDIV) {
                setArithmeticFlags(instruction, reverseSubtract ? right : left, reverseSubtract ? left : right,
                                   value, addition, withCarry, executionCondition);
            }
        }
        addAssignmentWithCondition(instruction, ops[0].reg, value, executionCondition);
        return true;
    }

    bool liftMultiplyAccumulate(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() != 4 || ops[0].kind != OperandKind::Register) return false;
        const auto product = binary("*", valueOf(ops[1]), valueOf(ops[2]), wordType());
        const auto value = instruction.id == ARM_INS_MLA
                               ? binary("+", product, valueOf(ops[3]), wordType())
                               : binary("-", valueOf(ops[3]), product, wordType());
        const bool flagUpdate = updatesFlags(instruction);
        if (ops[0].reg == "pc" && flagUpdate) return false;
        const auto executionCondition = prepareExecutionCondition(instruction, flagUpdate);
        if (flagUpdate && instruction.id == ARM_INS_MLA) setNzFlags(instruction, value, executionCondition);
        addAssignmentWithCondition(instruction, ops[0].reg, value, executionCondition);
        return true;
    }

    bool liftSignedMultiplyHigh(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const bool wideHalf = instruction.id == ARM_INS_SMULWB || instruction.id == ARM_INS_SMULWT;
        const bool accumulate = instruction.id == ARM_INS_SMMLA || instruction.id == ARM_INS_SMMLAR ||
                                instruction.id == ARM_INS_SMMLS || instruction.id == ARM_INS_SMMLSR;
        if (ops.size() != (accumulate ? 4U : 3U) || ops[0].kind != OperandKind::Register) return false;
        const auto signed64 = ScalarType::intBits(64);
        auto left = cast(cast(valueOf(ops[1]), signedWordType()), signed64);
        ExpressionPtr right;
        if (wideHalf) {
            right = instruction.id == ARM_INS_SMULWB ? signExtend(valueOf(ops[2]), 16)
                : signExtend(binary(">>", valueOf(ops[2]), constant(16, wordType()), wordType()), 16);
            right = cast(right, signed64);
        } else {
            right = cast(cast(valueOf(ops[2]), signedWordType()), signed64);
        }
        auto value = binary("*", left, right, signed64);
        if (accumulate) {
            const auto accumulator = binary("<<", cast(cast(readRegister(ops[3].reg), signedWordType()), signed64),
                                            constant(32, signed64), signed64);
            value = instruction.id == ARM_INS_SMMLS || instruction.id == ARM_INS_SMMLSR
                ? binary("-", accumulator, value, signed64)
                : binary("+", value, accumulator, signed64);
        }
        if (instruction.id == ARM_INS_SMMULR || instruction.id == ARM_INS_SMMLAR || instruction.id == ARM_INS_SMMLSR) {
            value = binary("+", value, constant(0x80000000ULL, signed64), signed64);
        }
        value = binary(">>", value, constant(wideHalf ? 16 : 32, signed64), signed64);
        addAssignment(instruction, ops[0].reg, cast(value, wordType()));
        return true;
    }

    bool liftLongMultiply(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() != 4 || ops[0].kind != OperandKind::Register || ops[1].kind != OperandKind::Register ||
            ops[0].reg == "pc" || ops[1].reg == "pc" || ops[0].reg == ops[1].reg) return false;
        const bool isSigned = instruction.id == ARM_INS_SMULL || instruction.id == ARM_INS_SMLAL;
        ExpressionPtr left = valueOf(ops[2]);
        ExpressionPtr right = valueOf(ops[3]);
        if (isSigned) {
            left = cast(cast(left, signedWordType()), ScalarType::intBits(64));
            right = cast(cast(right, signedWordType()), ScalarType::intBits(64));
        } else {
            left = cast(left, doubleWordType());
            right = cast(right, doubleWordType());
        }
        auto product = binary("*", left, right, isSigned ? ScalarType::intBits(64) : doubleWordType());
        if (instruction.id == ARM_INS_UMLAL || instruction.id == ARM_INS_SMLAL) {
            const auto low = cast(readRegister(ops[0].reg), doubleWordType());
            const auto high = binary("<<", cast(readRegister(ops[1].reg), doubleWordType()),
                                     constant(32, doubleWordType()), doubleWordType());
            product = binary("+", cast(product, doubleWordType()), binary("|", high, low, doubleWordType()),
                             doubleWordType());
        }
        const bool flagUpdate = updatesFlags(instruction);
        const auto executionCondition = prepareExecutionCondition(instruction, flagUpdate);
        const auto suffix = std::to_string(instruction.address);
        const auto lowName = "arm_mul_lo_" + suffix;
        const auto highName = "arm_mul_hi_" + suffix;
        const auto lowValue = cast(product, wordType());
        const auto highValue = cast(binary(">>", cast(product, doubleWordType()), constant(32, doubleWordType()),
                                           doubleWordType()), wordType());
        addAssignmentWithCondition(instruction, lowName, lowValue, executionCondition);
        addAssignmentWithCondition(instruction, highName, highValue, executionCondition);
        if (flagUpdate) {
            const auto combined = binary("|", binary("<<", cast(readRegister(highName), doubleWordType()),
                                                       constant(32, doubleWordType()), doubleWordType()),
                                         cast(readRegister(lowName), doubleWordType()), doubleWordType());
            setNzFlags(instruction, combined, executionCondition);
        }
        addAssignmentWithCondition(instruction, ops[0].reg, readRegister(lowName), executionCondition);
        addAssignmentWithCondition(instruction, ops[1].reg, readRegister(highName), executionCondition);
        return true;
    }

    bool liftShift(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2 || ops.size() > 3 || ops[0].kind != OperandKind::Register ||
            ops[1].kind != OperandKind::Register) return false;
        Shift shift;
        switch (instruction.id) {
        case ARM_INS_LSL: shift.type = ARM_SFT_LSL; break;
        case ARM_INS_LSR: shift.type = ARM_SFT_LSR; break;
        case ARM_INS_ASR: shift.type = ARM_SFT_ASR; break;
        case ARM_INS_ROR: shift.type = ARM_SFT_ROR; break;
        case ARM_INS_RRX: shift.type = ARM_SFT_RRX; break;
        default: return false;
        }
        if (instruction.id == ARM_INS_RRX) {
            if (ops.size() != 2) return false;
        } else if (ops.size() == 2 && ops[1].shift.type != ARM_SFT_INVALID) {
            shift = ops[1].shift;
        } else {
            if (ops.size() != 3) return false;
            if (ops[2].kind == OperandKind::Immediate) {
                if (ops[2].immediate < 0) return false;
                shift.value = static_cast<uint32_t>(ops[2].immediate);
            } else if (ops[2].kind == OperandKind::Register) {
                shift.type = static_cast<uint32_t>(shift.type - ARM_SFT_ASR + ARM_SFT_ASR_REG);
                shift.value = registerId(ops[2].reg);
                if (shift.value == ARM_REG_INVALID) return false;
            } else {
                return false;
            }
        }
        const auto shifted = applyShift(readOperandRegister(ops[1].reg), shift);
        if (!shifted.value) return false;
        const bool flagUpdate = updatesFlags(instruction);
        if (ops[0].reg == "pc" && flagUpdate) return false;
        const auto executionCondition = prepareExecutionCondition(instruction, flagUpdate);
        if (flagUpdate) setLogicalFlags(instruction, shifted.value, shifted.carry, executionCondition);
        addAssignmentWithCondition(instruction, ops[0].reg, shifted.value, executionCondition);
        return true;
    }

    static uint32_t registerId(const std::string& name) {
        if (name.size() >= 2 && name[0] == 'r' &&
            std::all_of(name.begin() + 1, name.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
            const int number = std::stoi(name.substr(1));
            if (number >= 0 && number <= 12) return ARM_REG_R0 + number;
        }
        if (name == "sp") return ARM_REG_SP;
        if (name == "lr") return ARM_REG_LR;
        if (name == "pc") return ARM_REG_PC;
        return ARM_REG_INVALID;
    }

    void liftExtension(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2) return;
        const auto source = valueOf(ops.back());
        ExpressionPtr value;
        switch (instruction.id) {
        case ARM_INS_UXTB:
        case ARM_INS_UXTAB: value = zeroExtend(source, 8); break;
        case ARM_INS_UXTH:
        case ARM_INS_UXTAH: value = zeroExtend(source, 16); break;
        case ARM_INS_SXTB:
        case ARM_INS_SXTAB: value = signExtend(source, 8); break;
        case ARM_INS_SXTH:
        case ARM_INS_SXTAH: value = signExtend(source, 16); break;
        case ARM_INS_UXTB16:
            value = binary("&", source, constant(0x00FF00FF, wordType()), wordType());
            break;
        case ARM_INS_SXTB16: {
            const auto low = binary("&", signExtend(source, 8), constant(0xFFFF, wordType()), wordType());
            const auto high = binary("<<", binary("&", signExtend(binary(">>", source, constant(16, wordType()), wordType()), 8),
                                                  constant(0xFFFF, wordType()), wordType()),
                                     constant(16, wordType()), wordType());
            value = binary("|", low, high, wordType());
            break;
        }
        default:
            return;
        }
        if (ops.size() >= 3) {
            value = binary("+", valueOf(ops[1]), value, wordType());
        }
        addAssignment(instruction, ops[0].reg, value);
    }

    void liftReverse(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2) return;
        const auto source = valueOf(ops[1]);
        ExpressionPtr value;
        if (instruction.id == ARM_INS_REV16 || instruction.id == ARM_INS_REVSH) {
            value = binary("|", binary("<<", binary("&", source, constant(0x00FF00FF, wordType()), wordType()),
                                      constant(8, wordType()), wordType()),
                           binary("&", binary(">>", source, constant(8, wordType()), wordType()),
                                  constant(0x00FF00FF, wordType()), wordType()), wordType());
            if (instruction.id == ARM_INS_REVSH) value = signExtend(value, 16);
        } else {
            const auto b0 = binary("<<", binary("&", source, constant(0xFF, wordType()), wordType()),
                                   constant(24, wordType()), wordType());
            const auto b1 = binary("<<", binary("&", source, constant(0xFF00, wordType()), wordType()),
                                   constant(8, wordType()), wordType());
            const auto b2 = binary("&", binary(">>", source, constant(8, wordType()), wordType()),
                                   constant(0xFF00, wordType()), wordType());
            const auto b3 = binary(">>", source, constant(24, wordType()), wordType());
            value = binary("|", binary("|", b0, b1, wordType()), binary("|", b2, b3, wordType()), wordType());
        }
        addAssignment(instruction, ops[0].reg, value);
    }

    bool liftBitfield(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 3) return false;
        const size_t lsbIndex = instruction.id == ARM_INS_BFI || instruction.id == ARM_INS_UBFX ||
                                        instruction.id == ARM_INS_SBFX
                                    ? 2
                                    : 1;
        if (ops.size() <= lsbIndex + 1 || ops[lsbIndex].kind != OperandKind::Immediate ||
            ops[lsbIndex + 1].kind != OperandKind::Immediate) {
            return false;
        }
        if (ops[lsbIndex].immediate < 0 || ops[lsbIndex + 1].immediate < 0) return false;
        const auto lsb = static_cast<uint32_t>(ops[lsbIndex].immediate);
        const auto width = static_cast<uint32_t>(ops[lsbIndex + 1].immediate);
        if (lsb >= 32 || width == 0 || width > 32 - lsb) return false;

        ExpressionPtr value;
        if (instruction.id == ARM_INS_BFC || instruction.id == ARM_INS_BFI) {
            const auto mask = static_cast<uint32_t>(bitMask(width) << lsb);
            value = binary("&", readRegister(ops[0].reg), constant(~mask, wordType()), wordType());
            if (instruction.id == ARM_INS_BFI) {
                const auto inserted = binary("<<", binary("&", valueOf(ops[1]), constant(bitMask(width), wordType()), wordType()),
                                             constant(lsb, wordType()), wordType());
                value = binary("|", value, inserted, wordType());
            }
        } else {
            const auto shifted = binary(">>", valueOf(ops[1]), constant(lsb, wordType()), wordType());
            if (instruction.id == ARM_INS_UBFX) {
                value = binary("&", shifted, constant(bitMask(width), wordType()), wordType());
            } else {
                const auto high = binary("<<", valueOf(ops[1]), constant(32 - lsb - width, wordType()), wordType());
                value = cast(binary(">>", cast(high, signedWordType()), constant(32 - width, wordType()), wordType()),
                             wordType());
            }
        }
        addAssignment(instruction, ops[0].reg, value);
        return true;
    }

    static bool isLoad(uint32_t id) {
        switch (id) {
        case ARM_INS_LDR:
        case ARM_INS_LDRT:
        case ARM_INS_LDRB:
        case ARM_INS_LDRBT:
        case ARM_INS_LDRH:
        case ARM_INS_LDRHT:
        case ARM_INS_LDRSB:
        case ARM_INS_LDRSBT:
        case ARM_INS_LDRSH:
        case ARM_INS_LDRSHT:
        case ARM_INS_LDRD:
            return true;
        default:
            return false;
        }
    }

    static bool isStore(uint32_t id) {
        switch (id) {
        case ARM_INS_STR:
        case ARM_INS_STRT:
        case ARM_INS_STRB:
        case ARM_INS_STRBT:
        case ARM_INS_STRH:
        case ARM_INS_STRHT:
        case ARM_INS_STRD:
            return true;
        default:
            return false;
        }
    }

    static ScalarType memoryType(uint32_t id) {
        switch (id) {
        case ARM_INS_LDRB:
        case ARM_INS_LDRBT:
        case ARM_INS_STRB:
        case ARM_INS_STRBT:
            return ScalarType::uintBits(8);
        case ARM_INS_LDRH:
        case ARM_INS_LDRHT:
        case ARM_INS_STRH:
        case ARM_INS_STRHT:
            return ScalarType::uintBits(16);
        case ARM_INS_LDRSB:
        case ARM_INS_LDRSBT:
            return ScalarType::intBits(8);
        case ARM_INS_LDRSH:
        case ARM_INS_LDRSHT:
            return ScalarType::intBits(16);
        default:
            return wordType();
        }
    }

    bool liftMemory(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const bool doubleWidth = instruction.id == ARM_INS_LDRD || instruction.id == ARM_INS_STRD;
        const size_t memoryIndex = doubleWidth ? 2 : 1;
        if (ops.size() <= memoryIndex || ops[memoryIndex].kind != OperandKind::Memory ||
            ops[0].kind != OperandKind::Register || (doubleWidth && ops[1].kind != OperandKind::Register)) {
            return false;
        }
        if (ops.size() > memoryIndex + 2) return false;
        const auto& memory = ops[memoryIndex];
        const bool postIndex = instruction.writeback == WritebackMode::PostIndex || ops.size() == memoryIndex + 2;
        const bool preIndex = hasWriteback(instruction);
        if (postIndex && preIndex) return false;
        const auto& base = memory.memoryBase;
        if (base.empty() || (base == "pc" && (postIndex || preIndex))) return false;
        if (isLoad(instruction.id) && (postIndex || preIndex) &&
            (ops[0].reg == base || (doubleWidth && ops[1].reg == base))) return false;
        if (doubleWidth && (ops[0].reg == "pc" || ops[1].reg == "pc")) return false;
        const auto address = addressOf(memory);
        if (!address) return false;
        const auto type = memoryType(instruction.id);
        if (type.bits == 0) return false;
        ExpressionPtr pcTarget;
        if (isLoad(instruction.id)) {
            if (doubleWidth) {
                addAssignment(instruction, ops[0].reg, load(address, wordType()));
                const auto highAddress = binary("+", address, constant(4, pointerType()), pointerType());
                addAssignment(instruction, ops[1].reg, load(highAddress, wordType()));
            } else {
                ExpressionPtr value = load(address, type);
                if (type.kind == ScalarKind::SignedInteger) value = signExtend(value, type.bits);
                else if (type.bits < 32) value = zeroExtend(value, type.bits);
                if (ops[0].reg == "pc") {
                    pcTarget = reg("arm_pc_" + std::to_string(instruction.address), wordType());
                    addAssignment(instruction, pcTarget->name, value);
                } else {
                    addAssignment(instruction, ops[0].reg, value);
                }
            }
        } else if (doubleWidth) {
            addStore(instruction, address, valueOf(ops[0]));
            const auto highAddress = binary("+", address, constant(4, pointerType()), pointerType());
            addStore(instruction, highAddress, valueOf(ops[1]));
        } else {
            auto value = valueOf(ops[0]);
            if (type.bits < 32) value = cast(value, type);
            addStore(instruction, address, value);
        }

        if (postIndex || preIndex) {
            const auto offset = postIndex
                ? (ops.size() == memoryIndex + 2 ? postIndexOffset(ops.back()) : decodedPostIndexOffset(instruction))
                : memoryOffset(memory);
            if (!offset) return false;
            const auto updated = binary("+", cast(readOperandRegister(base), pointerType()),
                                        cast(offset, pointerType()), pointerType());
            addAssignment(instruction, base, updated);
        }
        if (pcTarget) {
            if (base == "sp" && isUnconditional(instruction)) addReturn(instruction);
            else addBranch(instruction, condition(instruction), pcTarget);
        }
        return true;
    }

    bool liftPush(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.empty()) return false;
        const auto oldStack = cast(readRegister("sp"), pointerType());
        const auto newStack = binary("-", oldStack, constant(ops.size() * 4, pointerType()), pointerType());
        for (size_t i = 0; i < ops.size(); ++i) {
            if (ops[i].kind != OperandKind::Register) return false;
            const auto address = i == 0 ? newStack
                                        : binary("+", newStack, constant(i * 4, pointerType()), pointerType());
            addStore(instruction, address, valueOf(ops[i]));
        }
        addAssignment(instruction, "sp", newStack);
        return true;
    }

    bool liftPop(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.empty()) return false;
        const auto oldStack = cast(readRegister("sp"), pointerType());
        ExpressionPtr pcTarget;
        for (size_t i = 0; i < ops.size(); ++i) {
            if (ops[i].kind != OperandKind::Register) return false;
            const auto address = i == 0 ? oldStack
                                        : binary("+", oldStack, constant(i * 4, pointerType()), pointerType());
            const auto value = load(address, wordType());
            if (ops[i].reg == "pc") {
                pcTarget = reg("arm_pc_" + std::to_string(instruction.address), wordType());
                addAssignment(instruction, pcTarget->name, value);
            } else {
                addAssignment(instruction, ops[i].reg, value);
            }
        }
        addAssignment(instruction, "sp",
                      binary("+", oldStack, constant(ops.size() * 4, pointerType()), pointerType()));
        if (pcTarget) {
            if (isUnconditional(instruction)) addReturn(instruction);
            else addBranch(instruction, condition(instruction), pcTarget);
        }
        return true;
    }

    static bool isMultipleLoad(uint32_t id) {
        return id == ARM_INS_LDM || id == ARM_INS_LDMDA || id == ARM_INS_LDMDB || id == ARM_INS_LDMIB;
    }

    static bool isMultipleStore(uint32_t id) {
        return id == ARM_INS_STM || id == ARM_INS_STMDA || id == ARM_INS_STMDB || id == ARM_INS_STMIB;
    }

    bool liftMultiple(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2 || ops[0].kind != OperandKind::Register || ops[0].reg == "pc") return false;
        const auto& baseName = ops[0].reg;
        const size_t count = ops.size() - 1;
        for (size_t i = 1; i < ops.size(); ++i) {
            if (ops[i].kind != OperandKind::Register) return false;
            if (isMultipleLoad(instruction.id) && ops[i].reg == baseName) return false;
        }
        const auto base = cast(readOperandRegister(baseName), pointerType());
        const bool increment = instruction.id == ARM_INS_LDM || instruction.id == ARM_INS_LDMIB ||
                               instruction.id == ARM_INS_STM || instruction.id == ARM_INS_STMIB;
        const bool before = instruction.id == ARM_INS_LDMIB || instruction.id == ARM_INS_LDMDB ||
                            instruction.id == ARM_INS_STMIB || instruction.id == ARM_INS_STMDB;
        ExpressionPtr start = base;
        if (increment && before) start = binary("+", base, constant(4, pointerType()), pointerType());
        if (!increment) {
            const auto distance = (count - (before ? 0 : 1)) * 4;
            start = binary("-", base, constant(distance, pointerType()), pointerType());
        }
        ExpressionPtr pcTarget;
        for (size_t i = 0; i < count; ++i) {
            const auto address = i == 0 ? start
                                        : binary("+", start, constant(i * 4, pointerType()), pointerType());
            if (isMultipleLoad(instruction.id)) {
                if (ops[i + 1].reg == "pc") {
                    pcTarget = reg("arm_pc_" + std::to_string(instruction.address), wordType());
                    addAssignment(instruction, pcTarget->name, load(address, wordType()));
                } else {
                    addAssignment(instruction, ops[i + 1].reg, load(address, wordType()));
                }
            } else {
                addStore(instruction, address, valueOf(ops[i + 1]));
            }
        }
        if (hasWriteback(instruction)) {
            const auto amount = constant(count * 4, pointerType());
            addAssignment(instruction, baseName,
                          binary(increment ? "+" : "-", base, amount, pointerType()));
        }
        if (pcTarget) {
            if (baseName == "sp" && isUnconditional(instruction)) addReturn(instruction);
            else addBranch(instruction, condition(instruction), pcTarget);
        }
        return true;
    }

    bool validOperands(const NativeInstruction& instruction) const {
        for (const auto& operand : instruction.operands) {
            if (!supportedShift(operand.shift)) return false;
            const bool registerShift = operand.shift.type == ARM_SFT_ASR_REG || operand.shift.type == ARM_SFT_LSL_REG ||
                                       operand.shift.type == ARM_SFT_LSR_REG || operand.shift.type == ARM_SFT_ROR_REG;
            if (registerShift && shiftRegisterName(operand.shift.value).empty()) return false;
            if (operand.kind == OperandKind::Register && operand.reg.empty()) return false;
        }
        return true;
    }

    bool liftCompare(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() != 2) return false;
        const auto left = valueOf(ops[0]);
        const auto right = valueOf(ops[1]);
        if (!left || !right) return false;
        const auto executionCondition = prepareExecutionCondition(instruction, true);
        if (instruction.id == ARM_INS_CMP || instruction.id == ARM_INS_CMN) {
            const bool addition = instruction.id == ARM_INS_CMN;
            const auto result = binary(addition ? "+" : "-", left, right, wordType());
            setArithmeticFlags(instruction, left, right, result, addition, false, executionCondition);
        } else {
            const auto result = binary(instruction.id == ARM_INS_TST ? "&" : "^", left, right, wordType());
            const auto shifted = ops[1].kind == OperandKind::Register
                                     ? applyShift(readOperandRegister(ops[1].reg), ops[1].shift)
                                     : ShiftResult{};
            setLogicalFlags(instruction, result, shifted.carry, executionCondition);
        }
        return true;
    }

    void lift(const NativeInstruction& instruction) {
        currentInstruction_ = &instruction;
        const auto& ops = instruction.operands;
        if (!validOperands(instruction)) {
            unsupported(instruction);
            return;
        }
        bool handled = false;
        switch (instruction.id) {
        case ARM_INS_NOP:
        case ARM_INS_IT:
            return;
        case ARM_INS_MOV:
        case ARM_INS_MOVS:
        case ARM_INS_MOVW:
        case ARM_INS_MOVT:
        case ARM_INS_MVN:
            handled = liftMove(instruction);
            break;
        case ARM_INS_ADR:
            if (ops.size() == 2 && ops[0].kind == OperandKind::Register && ops[1].kind == OperandKind::Immediate) {
                addAssignment(instruction, ops[0].reg, valueOf(ops[1]));
                handled = true;
            }
            break;
        case ARM_INS_ADD:
        case ARM_INS_ADDW:
        case ARM_INS_ADC:
        case ARM_INS_SUB:
        case ARM_INS_SUBS:
        case ARM_INS_SUBW:
        case ARM_INS_SBC:
        case ARM_INS_RSB:
        case ARM_INS_RSC:
        case ARM_INS_AND:
        case ARM_INS_ORR:
        case ARM_INS_EOR:
        case ARM_INS_BIC:
        case ARM_INS_ORN:
        case ARM_INS_MUL:
        case ARM_INS_SDIV:
        case ARM_INS_UDIV:
        case ARM_INS_NEG:
            handled = liftArithmetic(instruction);
            break;
        case ARM_INS_MLA:
        case ARM_INS_MLS:
            handled = liftMultiplyAccumulate(instruction);
            break;
        case ARM_INS_SMMUL:
        case ARM_INS_SMMULR:
        case ARM_INS_SMMLA:
        case ARM_INS_SMMLAR:
        case ARM_INS_SMMLS:
        case ARM_INS_SMMLSR:
        case ARM_INS_SMULWB:
        case ARM_INS_SMULWT:
            handled = liftSignedMultiplyHigh(instruction);
            break;
        case ARM_INS_UMULL:
        case ARM_INS_SMULL:
        case ARM_INS_UMLAL:
        case ARM_INS_SMLAL:
            handled = liftLongMultiply(instruction);
            break;
        case ARM_INS_LSL:
        case ARM_INS_LSR:
        case ARM_INS_ASR:
        case ARM_INS_ROR:
        case ARM_INS_RRX:
            handled = liftShift(instruction);
            break;
        case ARM_INS_UXTB:
        case ARM_INS_UXTH:
        case ARM_INS_SXTB:
        case ARM_INS_SXTH:
        case ARM_INS_UXTB16:
        case ARM_INS_SXTB16:
        case ARM_INS_UXTAB:
        case ARM_INS_UXTAH:
        case ARM_INS_SXTAB:
        case ARM_INS_SXTAH: {
            const bool accumulating = instruction.id == ARM_INS_UXTAB || instruction.id == ARM_INS_UXTAH ||
                                      instruction.id == ARM_INS_SXTAB || instruction.id == ARM_INS_SXTAH;
            if (ops.size() == (accumulating ? 3U : 2U) && ops[0].kind == OperandKind::Register) {
                liftExtension(instruction);
                handled = true;
            }
            break;
        }
        case ARM_INS_REV:
        case ARM_INS_REV16:
        case ARM_INS_REVSH:
            if (ops.size() == 2 && ops[0].kind == OperandKind::Register) {
                liftReverse(instruction);
                handled = true;
            }
            break;
        case ARM_INS_BFC:
        case ARM_INS_BFI:
        case ARM_INS_UBFX:
        case ARM_INS_SBFX:
            if (ops.size() == (instruction.id == ARM_INS_BFC ? 3U : 4U) && ops[0].kind == OperandKind::Register) {
                handled = liftBitfield(instruction);
            }
            break;
        case ARM_INS_PUSH:
            handled = liftPush(instruction);
            break;
        case ARM_INS_POP:
            handled = liftPop(instruction);
            break;
        case ARM_INS_LDM:
        case ARM_INS_LDMDA:
        case ARM_INS_LDMDB:
        case ARM_INS_LDMIB:
        case ARM_INS_STM:
        case ARM_INS_STMDA:
        case ARM_INS_STMDB:
        case ARM_INS_STMIB:
            handled = liftMultiple(instruction);
            break;
        case ARM_INS_VADD:
        case ARM_INS_VSUB:
        case ARM_INS_VMUL:
        case ARM_INS_VNMUL:
        case ARM_INS_VDIV:
        case ARM_INS_VMLA:
        case ARM_INS_VMLS:
        case ARM_INS_VMOV:
        case ARM_INS_VMVN:
        case ARM_INS_VDUP:
        case ARM_INS_VAND:
        case ARM_INS_VORR:
        case ARM_INS_VEOR:
        case ARM_INS_VCMP:
        case ARM_INS_VCMPE:
        case ARM_INS_VCVT:
        case ARM_INS_VCVTR:
        case ARM_INS_VSELEQ:
        case ARM_INS_VSELGE:
        case ARM_INS_VSELGT:
        case ARM_INS_VSELVS:
        case ARM_INS_VLDR:
        case ARM_INS_VSTR:
        case ARM_INS_VPUSH:
        case ARM_INS_VPOP:
        case ARM_INS_VMRS:
        case ARM_INS_VNEG:
        case ARM_INS_VABS:
            handled = liftVfp(instruction);
            break;
        case ARM_INS_BL:
        case ARM_INS_BLX:
            handled = addCall(instruction);
            break;
        case ARM_INS_B:
            if (ops.size() == 1) handled = addBranch(instruction, condition(instruction));
            break;
        case ARM_INS_BX:
            if (ops.size() == 1 && ops[0].kind == OperandKind::Register) {
                if (ops[0].reg == "lr" && isUnconditional(instruction)) {
                    addReturn(instruction);
                    handled = true;
                } else {
                    handled = addBranch(instruction, condition(instruction));
                }
            }
            break;
        case ARM_INS_CBZ:
        case ARM_INS_CBNZ:
            if (ops.size() == 2 && ops[0].kind == OperandKind::Register && ops[1].kind == OperandKind::Immediate) {
                const auto value = valueOf(ops[0]);
                handled = addBranch(instruction, binary(instruction.id == ARM_INS_CBZ ? "==" : "!=", value,
                                                        constant(0, wordType()), ScalarType::boolean()));
            }
            break;
        case ARM_INS_CMP:
        case ARM_INS_CMN:
        case ARM_INS_TST:
        case ARM_INS_TEQ:
            handled = liftCompare(instruction);
            break;
        default:
            if (isLoad(instruction.id) || isStore(instruction.id)) handled = liftMemory(instruction);
            break;
        }
        if (!handled) unsupported(instruction);
    }

};

Arm32Lifter::Arm32Lifter(const FunctionImage& image) : impl_(std::make_unique<Impl>(image)) {}
Arm32Lifter::~Arm32Lifter() = default;
Arm32Lifter::Arm32Lifter(Arm32Lifter&&) noexcept = default;
Arm32Lifter& Arm32Lifter::operator=(Arm32Lifter&&) noexcept = default;

RecoveredFunction Arm32Lifter::run(std::vector<NativeInstruction> instructions) {
    return impl_->run(std::move(instructions));
}

} // namespace il2cpprec
