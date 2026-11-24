#include <il2cpprec/lifters/X86Lifter.hpp>

#include <il2cpprec/Recovery.hpp>

#include <capstone/x86.h>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace il2cpprec {

class X86Lifter::Impl {
public:
    Impl(Architecture architecture, uint64_t address, std::string name)
        : pointerBits_(architecture == Architecture::X64 ? 64 : 32) {
        if (architecture != Architecture::X86 && architecture != Architecture::X64) {
            throw std::invalid_argument("X86Lifter requires an x86 or x64 architecture");
        }
        output_.architecture = architecture;
        output_.address = address;
        output_.name = std::move(name);
    }

    RecoveredFunction run(std::vector<NativeInstruction> instructions) {
        instructions_ = std::move(instructions);
        output_.blocks.clear();
        flags_ = {};
        terminated_ = false;
        collectBranchTargets();

        for (const auto& instruction : instructions_) {
            const bool isTarget = branchTargets_.contains(instruction.address);
            if (terminated_) {
                if (!isTarget) {
                    continue;
                }
                output_.blocks.push_back({instruction.address, {}});
            } else if (isTarget && !output_.blocks.empty() && !output_.blocks.back().statements.empty()) {
                output_.blocks.push_back({instruction.address, {}});
            }
            terminated_ = false;
            current_ = &instruction;
            lift(instruction);
        }
        current_ = nullptr;
        pruneUnusedFlagTemporaries();
        return std::move(output_);
    }

private:
    struct RegisterInfo {
        std::string canonical;
        uint16_t bits = 0;
        uint16_t offset = 0;
        bool vector = false;
        bool valid = false;
    };

    struct FlagState {
        ExpressionPtr carry;
        ExpressionPtr zero;
        ExpressionPtr sign;
        ExpressionPtr overflow;
        ExpressionPtr parity;
    };

    enum class Condition {
        Invalid,
        O,
        NO,
        B,
        AE,
        E,
        NE,
        BE,
        A,
        S,
        NS,
        P,
        NP,
        L,
        GE,
        LE,
        G
    };

    int pointerBits_;
    RecoveredFunction output_;
    std::vector<NativeInstruction> instructions_;
    std::set<uint64_t> branchTargets_;
    const NativeInstruction* current_ = nullptr;
    FlagState flags_;
    bool terminated_ = false;

    ScalarType pointerType() const { return ScalarType::pointer(pointerBits_); }
    ScalarType uintType(int bits) const { return ScalarType::uintBits(static_cast<uint16_t>(bits)); }
    ScalarType intType(int bits) const { return ScalarType::intBits(static_cast<uint16_t>(bits)); }
    ScalarType floatType(int bits) const { return ScalarType::floatBits(static_cast<uint16_t>(bits)); }
    ScalarType boolType() const { return ScalarType::boolean(); }

    int operandBits(const Operand& operand) const {
        if (operand.size != 0) {
            return operand.size * 8;
        }
        if (operand.kind == OperandKind::Register) {
            const auto info = registerInfo(operand.reg);
            if (info.valid) {
                return info.bits;
            }
        }
        return pointerBits_;
    }

    static std::string lower(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    RegisterInfo registerInfo(const std::string& input) const {
        const auto name = lower(input);
        if (name.empty()) {
            return {};
        }
        if (name.size() >= 2 && (name[0] == 'x' || name[0] == 'y' || name[0] == 'z') &&
            name.substr(0, 3) != "xmm" && name.substr(0, 3) != "ymm" && name.substr(0, 3) != "zmm") {
            return {};
        }
        if (name.rfind("xmm", 0) == 0 || name.rfind("ymm", 0) == 0 || name.rfind("zmm", 0) == 0) {
            const auto digits = name.substr(3);
            if (digits.empty() || !std::all_of(digits.begin(), digits.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
                return {};
            }
            return {"xmm" + digits, static_cast<uint16_t>(name[0] == 'x' ? 128 : name[0] == 'y' ? 256 : 512), 0, true, true};
        }
        if (name.rfind("mm", 0) == 0 && name.size() > 2) {
            return {name, 64, 0, true, true};
        }

        struct Alias {
            const char* name;
            const char* canonical;
            uint16_t bits;
            uint16_t offset;
        };
        static constexpr Alias aliases[] = {
            {"rax", "rax", 64, 0}, {"eax", "rax", 32, 0}, {"ax", "rax", 16, 0}, {"al", "rax", 8, 0}, {"ah", "rax", 8, 8},
            {"rbx", "rbx", 64, 0}, {"ebx", "rbx", 32, 0}, {"bx", "rbx", 16, 0}, {"bl", "rbx", 8, 0}, {"bh", "rbx", 8, 8},
            {"rcx", "rcx", 64, 0}, {"ecx", "rcx", 32, 0}, {"cx", "rcx", 16, 0}, {"cl", "rcx", 8, 0}, {"ch", "rcx", 8, 8},
            {"rdx", "rdx", 64, 0}, {"edx", "rdx", 32, 0}, {"dx", "rdx", 16, 0}, {"dl", "rdx", 8, 0}, {"dh", "rdx", 8, 8},
            {"rsi", "rsi", 64, 0}, {"esi", "rsi", 32, 0}, {"si", "rsi", 16, 0}, {"sil", "rsi", 8, 0},
            {"rdi", "rdi", 64, 0}, {"edi", "rdi", 32, 0}, {"di", "rdi", 16, 0}, {"dil", "rdi", 8, 0},
            {"rbp", "rbp", 64, 0}, {"ebp", "rbp", 32, 0}, {"bp", "rbp", 16, 0}, {"bpl", "rbp", 8, 0},
            {"rsp", "rsp", 64, 0}, {"esp", "rsp", 32, 0}, {"sp", "rsp", 16, 0}, {"spl", "rsp", 8, 0},
            {"rip", "rip", 64, 0}, {"eip", "rip", 32, 0}, {"ip", "rip", 16, 0}
        };
        for (const auto& alias : aliases) {
            if (name == alias.name) {
                std::string canonical = alias.canonical;
                if (pointerBits_ == 32) {
                    canonical = 'e' + canonical.substr(1);
                }
                return {canonical, static_cast<uint16_t>(pointerBits_ == 32 ? std::min<uint16_t>(alias.bits, 32) : alias.bits), alias.offset, false, true};
            }
        }
        if (name.size() >= 2 && name[0] == 'r' && std::isdigit(static_cast<unsigned char>(name[1]))) {
            size_t end = 1;
            while (end < name.size() && std::isdigit(static_cast<unsigned char>(name[end]))) {
                ++end;
            }
            const auto suffix = name.substr(end);
            uint16_t bits = 64;
            if (suffix == "d") bits = 32;
            else if (suffix == "w") bits = 16;
            else if (suffix == "b" || suffix == "l") bits = 8;
            else if (!suffix.empty()) return {};
            return {name.substr(0, end), static_cast<uint16_t>(pointerBits_ == 32 ? std::min<uint16_t>(bits, 32) : bits), 0, false, true};
        }
        return {name, static_cast<uint16_t>(pointerBits_), 0, false, true};
    }

    ExpressionPtr fullRegister(const RegisterInfo& info) const {
        return reg(info.canonical, uintType(info.vector ? 64 : pointerBits_));
    }

    ExpressionPtr readRegister(const std::string& input) const {
        const auto info = registerInfo(input);
        if (!info.valid) {
            return unknown(uintType(pointerBits_));
        }
        auto value = fullRegister(info);
        if (info.vector) {
            return value;
        }
        const auto fullBits = pointerBits_;
        if (info.offset != 0) {
            value = binary(">>", value, constant(info.offset, uintType(fullBits)), uintType(fullBits));
        }
        if (info.bits != fullBits || info.offset != 0) {
            value = cast(value, uintType(info.bits));
        }
        return value;
    }

    ExpressionPtr coerce(ExpressionPtr value, ScalarType type) const {
        if (!value) {
            return unknown(type);
        }
        if (value->type.kind == type.kind && value->type.bits == type.bits) {
            return value;
        }
        return cast(std::move(value), type);
    }

    ExpressionPtr zeroExtend(ExpressionPtr value, int fromBits, int toBits) const {
        value = coerce(std::move(value), uintType(fromBits));
        return fromBits == toBits ? value : cast(value, uintType(toBits));
    }

    ExpressionPtr signExtend(ExpressionPtr value, int fromBits, int toBits) const {
        value = cast(coerce(std::move(value), uintType(fromBits)), intType(fromBits));
        value = cast(value, intType(toBits));
        return cast(value, uintType(toBits));
    }

    Statement assignment(ExpressionPtr destination, ExpressionPtr value) const {
        Statement statement;
        statement.address = current_ ? current_->address : output_.address;
        statement.kind = Statement::Kind::Assign;
        statement.destination = std::move(destination);
        statement.value = std::move(value);
        return statement;
    }

    void add(Statement statement) {
        if (output_.blocks.empty()) {
            output_.blocks.push_back({current_ ? current_->address : output_.address, {}});
        }
        if (statement.kind == Statement::Kind::Branch || statement.kind == Statement::Kind::Return) {
            terminated_ = true;
        }
        output_.blocks.back().statements.push_back(std::move(statement));
    }

    static void collectRegisterReferences(const ExpressionPtr& expression, std::set<std::string>& references) {
        if (!expression) {
            return;
        }
        if (expression->kind == Expression::Kind::Register) {
            references.insert(expression->name);
        }
        for (const auto& argument : expression->arguments) {
            collectRegisterReferences(argument, references);
        }
    }

    static bool isFlagTemporaryAssignment(const Statement& statement) {
        return statement.kind == Statement::Kind::Assign && statement.destination &&
            statement.destination->kind == Expression::Kind::Register &&
            statement.destination->name.rfind("__x86_flags_", 0) == 0;
    }

    static void collectStatementReferences(const Statement& statement, std::set<std::string>& references) {
        collectRegisterReferences(statement.destination, references);
        collectRegisterReferences(statement.value, references);
        collectRegisterReferences(statement.condition, references);
        collectRegisterReferences(statement.target, references);
        for (const auto& argument : statement.arguments) {
            collectRegisterReferences(argument, references);
        }
    }

    void pruneUnusedFlagTemporaries() {
        std::set<std::string> references;
        for (const auto& block : output_.blocks) {
            for (const auto& statement : block.statements) {
                if (!isFlagTemporaryAssignment(statement)) {
                    collectStatementReferences(statement, references);
                }
            }
        }

        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto& block : output_.blocks) {
                for (const auto& statement : block.statements) {
                    if (!isFlagTemporaryAssignment(statement) || !references.contains(statement.destination->name)) {
                        continue;
                    }
                    const auto sizeBefore = references.size();
                    collectRegisterReferences(statement.value, references);
                    changed = changed || references.size() != sizeBefore;
                }
            }
        }

        for (auto& block : output_.blocks) {
            std::erase_if(block.statements, [&](const Statement& statement) {
                return isFlagTemporaryAssignment(statement) && !references.contains(statement.destination->name);
            });
        }
    }

    Statement assignRegister(const std::string& input, ExpressionPtr value) const {
        const auto info = registerInfo(input);
        if (!info.valid) {
            return assignment(reg(input, uintType(pointerBits_)), unknown(uintType(pointerBits_)));
        }
        const auto fullBits = info.vector ? info.bits : pointerBits_;
        const auto destination = fullRegister(info);
        if (info.vector && info.bits == fullBits) {
            if (value->type.bits != 0 && value->type.bits <= 64) {
                auto laneDestination = reg(info.canonical, uintType(64));
                return assignment(laneDestination, coerce(std::move(value), uintType(64)));
            }
            return assignment(destination, coerce(std::move(value), uintType(fullBits)));
        }
        if (!info.vector && info.bits == pointerBits_) {
            if (fullBits == 32) {
                value = cast(std::move(value), uintType(fullBits));
            }
            return assignment(destination, coerce(std::move(value), uintType(fullBits)));
        }
        if (!info.vector) {
            value = cast(std::move(value), uintType(info.bits));
        }
        if (!info.vector && info.bits == 32 && pointerBits_ == 64 && info.offset == 0) {
            return assignment(destination, zeroExtend(std::move(value), 32, 64));
        }

        auto oldValue = readRegister(info.canonical);
        const auto lowMask = maskConstant(info.bits, uintType(fullBits));
        auto preservedMask = unary("~", lowMask, uintType(fullBits));
        if (info.offset != 0) {
            preservedMask = unary("~", binary("<<", lowMask, constant(info.offset, uintType(fullBits)), uintType(fullBits)), uintType(fullBits));
        }
        auto preserved = binary("&", oldValue, preservedMask, uintType(fullBits));
        auto inserted = zeroExtend(std::move(value), info.bits, fullBits);
        if (info.offset != 0) {
            inserted = binary("<<", inserted, constant(info.offset, uintType(fullBits)), uintType(fullBits));
        }
        return assignment(destination, binary("|", preserved, inserted, uintType(fullBits)));
    }

    ExpressionPtr addressOf(const Operand& operand) const {
        ExpressionPtr address;
        if (!operand.memoryBase.empty()) {
            if (lower(operand.memoryBase) == "rip" || (pointerBits_ == 32 && lower(operand.memoryBase) == "eip")) {
                address = constant(current_ ? current_->address + current_->size : 0, pointerType());
            } else {
                address = coerce(readRegister(operand.memoryBase), pointerType());
            }
        }
        if (!operand.memoryIndex.empty()) {
            auto index = coerce(readRegister(operand.memoryIndex), pointerType());
            if (operand.scale != 1) {
                index = binary("*", index, constant(static_cast<uint64_t>(operand.scale), pointerType()), pointerType());
            }
            address = address ? binary("+", address, index, pointerType()) : index;
        }
        if (operand.displacement != 0 || !address) {
            auto displacement = constant(static_cast<uint64_t>(operand.displacement), pointerType());
            address = address ? binary("+", address, displacement, pointerType()) : displacement;
        }
        return address;
    }

    ExpressionPtr valueOf(const Operand& operand, ScalarType requested = {}) const {
        const auto bits = requested.bits == 0 ? operandBits(operand) : requested.bits;
        const auto type = requested.bits == 0 || requested.kind == ScalarKind::Unknown ? uintType(bits) : requested;
        switch (operand.kind) {
        case OperandKind::Register: {
            auto value = readRegister(operand.reg);
            return coerce(std::move(value), type);
        }
        case OperandKind::Immediate:
            return constant(static_cast<uint64_t>(operand.immediate), type);
        case OperandKind::Memory:
            return load(addressOf(operand), type);
        case OperandKind::FloatingPoint:
            return constant(static_cast<uint64_t>(operand.floatingPoint), type);
        }
        return unknown(type);
    }

    void writeOperand(const Operand& operand, ExpressionPtr value) {
        if (operand.kind == OperandKind::Register) {
            add(assignRegister(operand.reg, std::move(value)));
            return;
        }
        if (operand.kind == OperandKind::Memory) {
            Statement statement;
            statement.address = current_->address;
            statement.kind = Statement::Kind::Store;
            statement.destination = addressOf(operand);
            const auto bits = operandBits(operand);
            statement.value = bits <= 32 ? cast(std::move(value), uintType(bits)) : coerce(std::move(value), uintType(bits));
            add(std::move(statement));
        }
    }

    ExpressionPtr maskConstant(int bits, ScalarType type) const {
        const auto mask = bits >= 64 ? std::numeric_limits<uint64_t>::max() : (uint64_t{1} << bits) - 1;
        return constant(mask, type);
    }

    std::string temporary(const char* role) const {
        std::ostringstream name;
        name << "__x86_" << role << '_' << std::hex << (current_ ? current_->address : output_.address);
        return name.str();
    }

    ExpressionPtr saveTemporary(const char* role, ExpressionPtr value) {
        const auto originalType = value->type;
        auto storageType = originalType;
        const bool integer = originalType.kind == ScalarKind::UnsignedInteger ||
            originalType.kind == ScalarKind::SignedInteger || originalType.kind == ScalarKind::Pointer;
        if (integer && originalType.bits < pointerBits_) {
            storageType = uintType(pointerBits_);
        }
        auto destination = reg(temporary(role), storageType);
        add(assignment(destination, coerce(std::move(value), storageType)));
        return coerce(destination, originalType);
    }

    ExpressionPtr booleanConstant(bool value) const {
        auto zero = constant(0, uintType(1));
        return binary(value ? "==" : "!=", zero, zero, boolType());
    }

    ExpressionPtr booleanNot(ExpressionPtr value) const {
        return unary("!", coerce(std::move(value), boolType()), boolType());
    }

    ExpressionPtr booleanAnd(ExpressionPtr left, ExpressionPtr right) const {
        return binary("&&", coerce(std::move(left), boolType()), coerce(std::move(right), boolType()), boolType());
    }

    ExpressionPtr booleanOr(ExpressionPtr left, ExpressionPtr right) const {
        return binary("||", coerce(std::move(left), boolType()), coerce(std::move(right), boolType()), boolType());
    }

    ExpressionPtr isNegative(ExpressionPtr value) const {
        const auto bits = value->type.bits;
        return binary("<", cast(coerce(value, uintType(bits)), intType(bits)), constant(0, intType(bits)), boolType());
    }

    ExpressionPtr isZero(ExpressionPtr value) const {
        return binary("==", value, constant(0, value->type), boolType());
    }

    ExpressionPtr parityOf(ExpressionPtr value) const {
        const auto bits = value->type.bits;
        auto folded = cast(coerce(std::move(value), uintType(bits)), uintType(8));
        folded = binary("^", folded, binary(">>", folded, constant(4, uintType(8)), uintType(8)), uintType(8));
        folded = binary("^", folded, binary(">>", folded, constant(2, uintType(8)), uintType(8)), uintType(8));
        folded = binary("^", folded, binary(">>", folded, constant(1, uintType(8)), uintType(8)), uintType(8));
        return isZero(binary("&", folded, constant(1, uintType(8)), uintType(8)));
    }

    void setLogicalFlags(ExpressionPtr result) {
        auto saved = saveTemporary("flags_result", result);
        flags_.carry = booleanConstant(false);
        flags_.overflow = booleanConstant(false);
        flags_.zero = isZero(saved);
        flags_.sign = isNegative(saved);
        flags_.parity = parityOf(saved);
    }

    void setAddFlags(ExpressionPtr left, ExpressionPtr right, ExpressionPtr result, ExpressionPtr carryIn = nullptr, bool preserveCarry = false) {
        auto savedLeft = saveTemporary("flags_left", left);
        auto savedRight = saveTemporary("flags_right", right);
        auto savedResult = saveTemporary("flags_result", result);
        auto savedCarry = carryIn ? saveTemporary("flags_carry", carryIn) : nullptr;
        const auto bits = left->type.bits;
        auto signedLeft = cast(coerce(savedLeft, uintType(bits)), intType(bits));
        auto signedRight = cast(coerce(savedRight, uintType(bits)), intType(bits));
        auto signedResult = cast(coerce(savedResult, uintType(bits)), intType(bits));
        auto sameSign = binary("==", binary("<", signedLeft, constant(0, intType(bits)), boolType()), binary("<", signedRight, constant(0, intType(bits)), boolType()), boolType());
        auto resultSignDiffers = binary("!=", binary("<", signedLeft, constant(0, intType(bits)), boolType()), binary("<", signedResult, constant(0, intType(bits)), boolType()), boolType());
        flags_.overflow = booleanAnd(sameSign, resultSignDiffers);
        flags_.zero = isZero(savedResult);
        flags_.sign = isNegative(savedResult);
        flags_.parity = parityOf(savedResult);
        if (preserveCarry) {
            return;
        }
        auto carry = binary("<", coerce(savedResult, uintType(bits)), coerce(savedLeft, uintType(bits)), boolType());
        if (savedCarry) {
            auto carryAtBoundary = booleanAnd(binary("!=", savedCarry, constant(0, savedCarry->type), boolType()), binary("==", coerce(savedResult, uintType(bits)), coerce(savedLeft, uintType(bits)), boolType()));
            carry = booleanOr(carry, carryAtBoundary);
        }
        flags_.carry = carry;
    }

    void setSubtractFlags(ExpressionPtr left, ExpressionPtr right, ExpressionPtr result, ExpressionPtr borrowIn = nullptr, bool preserveCarry = false) {
        auto savedLeft = saveTemporary("flags_left", left);
        auto savedRight = saveTemporary("flags_right", right);
        auto savedResult = saveTemporary("flags_result", result);
        auto savedBorrow = borrowIn ? saveTemporary("flags_borrow", borrowIn) : nullptr;
        const auto bits = left->type.bits;
        auto signedLeft = cast(coerce(savedLeft, uintType(bits)), intType(bits));
        auto signedRight = cast(coerce(savedRight, uintType(bits)), intType(bits));
        auto signedResult = cast(coerce(savedResult, uintType(bits)), intType(bits));
        auto signDiffers = binary("!=", binary("<", signedLeft, constant(0, intType(bits)), boolType()), binary("<", signedRight, constant(0, intType(bits)), boolType()), boolType());
        auto resultSignDiffers = binary("!=", binary("<", signedLeft, constant(0, intType(bits)), boolType()), binary("<", signedResult, constant(0, intType(bits)), boolType()), boolType());
        flags_.overflow = booleanAnd(signDiffers, resultSignDiffers);
        flags_.zero = isZero(savedResult);
        flags_.sign = isNegative(savedResult);
        flags_.parity = parityOf(savedResult);
        if (preserveCarry) {
            return;
        }
        auto borrow = binary("<", coerce(savedLeft, uintType(bits)), coerce(savedRight, uintType(bits)), boolType());
        if (savedBorrow) {
            auto borrowAtBoundary = booleanAnd(binary("!=", savedBorrow, constant(0, savedBorrow->type), boolType()), binary("==", coerce(savedLeft, uintType(bits)), coerce(savedRight, uintType(bits)), boolType()));
            borrow = booleanOr(borrow, borrowAtBoundary);
        }
        flags_.carry = borrow;
    }

    void setMultiplyFlags(ExpressionPtr overflow) {
        flags_.carry = std::move(overflow);
        flags_.overflow = flags_.carry;
        flags_.zero = unknown(boolType());
        flags_.sign = unknown(boolType());
        flags_.parity = unknown(boolType());
    }

    void invalidateFlags() {
        flags_ = {};
    }

    ExpressionPtr condition(Condition code) const {
        auto available = [](const ExpressionPtr& value) { return value != nullptr; };
        auto missing = [&] { return unknown(boolType()); };
        switch (code) {
        case Condition::O: return available(flags_.overflow) ? flags_.overflow : missing();
        case Condition::NO: return available(flags_.overflow) ? booleanNot(flags_.overflow) : missing();
        case Condition::B: return available(flags_.carry) ? flags_.carry : missing();
        case Condition::AE: return available(flags_.carry) ? booleanNot(flags_.carry) : missing();
        case Condition::E: return available(flags_.zero) ? flags_.zero : missing();
        case Condition::NE: return available(flags_.zero) ? booleanNot(flags_.zero) : missing();
        case Condition::BE: return available(flags_.carry) && available(flags_.zero) ? booleanOr(flags_.carry, flags_.zero) : missing();
        case Condition::A: return available(flags_.carry) && available(flags_.zero) ? booleanAnd(booleanNot(flags_.carry), booleanNot(flags_.zero)) : missing();
        case Condition::S: return available(flags_.sign) ? flags_.sign : missing();
        case Condition::NS: return available(flags_.sign) ? booleanNot(flags_.sign) : missing();
        case Condition::P: return available(flags_.parity) ? flags_.parity : missing();
        case Condition::NP: return available(flags_.parity) ? booleanNot(flags_.parity) : missing();
        case Condition::L: return available(flags_.sign) && available(flags_.overflow) ? binary("!=", flags_.sign, flags_.overflow, boolType()) : missing();
        case Condition::GE: return available(flags_.sign) && available(flags_.overflow) ? binary("==", flags_.sign, flags_.overflow, boolType()) : missing();
        case Condition::LE: return available(flags_.zero) && available(flags_.sign) && available(flags_.overflow) ? booleanOr(flags_.zero, binary("!=", flags_.sign, flags_.overflow, boolType())) : missing();
        case Condition::G: return available(flags_.zero) && available(flags_.sign) && available(flags_.overflow) ? booleanAnd(booleanNot(flags_.zero), binary("==", flags_.sign, flags_.overflow, boolType())) : missing();
        default: return unknown(boolType());
        }
    }

    Condition conditionFor(uint32_t id) const {
        switch (id) {
        case X86_INS_JO: case X86_INS_SETO: case X86_INS_CMOVO: return Condition::O;
        case X86_INS_JNO: case X86_INS_SETNO: case X86_INS_CMOVNO: return Condition::NO;
        case X86_INS_JB: case X86_INS_SETB: case X86_INS_CMOVB: return Condition::B;
        case X86_INS_JAE: case X86_INS_SETAE: case X86_INS_CMOVAE: return Condition::AE;
        case X86_INS_JE: case X86_INS_SETE: case X86_INS_CMOVE: return Condition::E;
        case X86_INS_JNE: case X86_INS_SETNE: case X86_INS_CMOVNE: return Condition::NE;
        case X86_INS_JBE: case X86_INS_SETBE: case X86_INS_CMOVBE: return Condition::BE;
        case X86_INS_JA: case X86_INS_SETA: case X86_INS_CMOVA: return Condition::A;
        case X86_INS_JS: case X86_INS_SETS: case X86_INS_CMOVS: return Condition::S;
        case X86_INS_JNS: case X86_INS_SETNS: case X86_INS_CMOVNS: return Condition::NS;
        case X86_INS_JP: case X86_INS_SETP: case X86_INS_CMOVP: return Condition::P;
        case X86_INS_JNP: case X86_INS_SETNP: case X86_INS_CMOVNP: return Condition::NP;
        case X86_INS_JL: case X86_INS_SETL: case X86_INS_CMOVL: return Condition::L;
        case X86_INS_JGE: case X86_INS_SETGE: case X86_INS_CMOVGE: return Condition::GE;
        case X86_INS_JLE: case X86_INS_SETLE: case X86_INS_CMOVLE: return Condition::LE;
        case X86_INS_JG: case X86_INS_SETG: case X86_INS_CMOVG: return Condition::G;
        default: return Condition::Invalid;
        }
    }

    ExpressionPtr carryAs(int bits) const {
        if (!flags_.carry) {
            return unknown(uintType(bits));
        }
        return select(flags_.carry, constant(1, uintType(bits)), constant(0, uintType(bits)), uintType(bits));
    }

    ExpressionPtr shiftCount(const Operand& operand, int valueBits) const {
        auto count = coerce(valueOf(operand), uintType(valueBits));
        return binary("&", count, constant(valueBits == 64 ? 63 : 31, uintType(valueBits)), uintType(valueBits));
    }

    ExpressionPtr bitAt(ExpressionPtr value, ExpressionPtr index) const {
        const auto bits = value->type.bits;
        auto shifted = binary(">>", coerce(std::move(value), uintType(bits)), coerce(std::move(index), uintType(bits)), uintType(bits));
        return binary("!=", binary("&", shifted, constant(1, uintType(bits)), uintType(bits)), constant(0, uintType(bits)), boolType());
    }

    ExpressionPtr bitAt(ExpressionPtr value, int index) const {
        auto bitIndex = constant(index, value->type);
        return bitAt(std::move(value), std::move(bitIndex));
    }

    void setShiftFlags(uint32_t id, ExpressionPtr source, ExpressionPtr count, ExpressionPtr result, bool dynamicCount) {
        if (!dynamicCount && count->kind == Expression::Kind::Constant && count->constant == 0) {
            return;
        }
        auto savedSource = saveTemporary("flags_source", source);
        auto savedCount = saveTemporary("flags_count", count);
        auto savedResult = saveTemporary("flags_result", result);
        const auto bits = source->type.bits;
        auto nonzero = binary("!=", savedCount, constant(0, savedCount->type), boolType());
        auto preserve = [&](ExpressionPtr oldValue, ExpressionPtr newValue) {
            if (!dynamicCount) {
                return newValue;
            }
            return select(nonzero, newValue, oldValue ? oldValue : unknown(boolType()), boolType());
        };

        ExpressionPtr newCarry;
        if (id == X86_INS_SHL || id == X86_INS_SAL) {
            auto index = binary("-", constant(bits, savedCount->type), savedCount, savedCount->type);
            newCarry = bitAt(savedSource, index);
        } else {
            auto index = binary("-", savedCount, constant(1, savedCount->type), savedCount->type);
            newCarry = bitAt(savedSource, index);
        }
        auto positive = binary(">", savedCount, constant(0, savedCount->type), boolType());
        auto inRange = binary("<=", savedCount, constant(bits, savedCount->type), boolType());
        newCarry = select(booleanAnd(positive, inRange), newCarry, unknown(boolType()), boolType());
        flags_.carry = preserve(flags_.carry, newCarry);
        flags_.zero = preserve(flags_.zero, isZero(savedResult));
        flags_.sign = preserve(flags_.sign, isNegative(savedResult));
        flags_.parity = preserve(flags_.parity, parityOf(savedResult));

        ExpressionPtr newOverflow;
        if (id == X86_INS_SHL || id == X86_INS_SAL) {
            newOverflow = binary("!=", isNegative(savedResult), newCarry, boolType());
        } else if (id == X86_INS_SHR) {
            newOverflow = isNegative(savedSource);
        } else {
            newOverflow = booleanConstant(false);
        }
        auto countIsOne = binary("==", savedCount, constant(1, savedCount->type), boolType());
        newOverflow = select(countIsOne, newOverflow, unknown(boolType()), boolType());
        flags_.overflow = preserve(flags_.overflow, newOverflow);
    }

    void setRotateFlags(uint32_t id, ExpressionPtr count, ExpressionPtr result, bool dynamicCount) {
        if (!dynamicCount && count->kind == Expression::Kind::Constant && count->constant == 0) {
            return;
        }
        auto savedCount = saveTemporary("flags_count", count);
        auto savedResult = saveTemporary("flags_result", result);
        const auto bits = result->type.bits;
        auto effectiveCount = savedCount;
        if (bits < 32) {
            effectiveCount = binary("%", savedCount, constant(bits, savedCount->type), savedCount->type);
        }
        auto nonzero = binary("!=", effectiveCount, constant(0, savedCount->type), boolType());
        auto preserve = [&](ExpressionPtr oldValue, ExpressionPtr newValue) {
            return dynamicCount ? select(nonzero, newValue, oldValue ? oldValue : unknown(boolType()), boolType()) : newValue;
        };
        auto newCarry = id == X86_INS_ROL
            ? bitAt(savedResult, 0)
            : isNegative(savedResult);
        flags_.carry = preserve(flags_.carry, newCarry);
        auto secondBit = id == X86_INS_ROL ? bitAt(savedResult, 0) : bitAt(savedResult, bits - 2);
        auto newOverflow = binary("!=", isNegative(savedResult), secondBit, boolType());
        auto countIsOne = binary("==", savedCount, constant(1, savedCount->type), boolType());
        newOverflow = select(countIsOne, newOverflow, unknown(boolType()), boolType());
        flags_.overflow = preserve(flags_.overflow, newOverflow);
    }

    ExpressionPtr vectorPartRegister(const RegisterInfo& info, int part) const {
        auto name = info.canonical;
        if (part != 0) {
            name += "__part" + std::to_string(part);
        }
        return reg(std::move(name), uintType(64));
    }

    int vectorPartCount(const RegisterInfo& info) const {
        return std::max(1, (info.bits + 63) / 64);
    }

    ExpressionPtr readVectorRaw(const Operand& operand, int bits, int lane = 0) const {
        if (bits == 0) {
            bits = operandBits(operand);
        }
        if (operand.kind == OperandKind::Memory) {
            auto address = addressOf(operand);
            if (lane != 0) {
                address = binary("+", address, constant(lane * bits / 8, pointerType()), pointerType());
            }
            return load(address, uintType(bits));
        }
        if (operand.kind == OperandKind::Register) {
            const auto info = registerInfo(operand.reg);
            if (info.valid && info.vector) {
                const auto offset = lane * bits;
                auto value = vectorPartRegister(info, offset / 64);
                if (const auto shift = offset % 64; shift != 0) {
                    value = binary(">>", value, constant(shift, uintType(64)), uintType(64));
                }
                return coerce(value, uintType(bits));
            }
        }
        auto value = valueOf(operand);
        const auto sourceBits = value->type.bits;
        if (lane != 0) {
            value = binary(">>", value, constant(lane * bits, uintType(sourceBits)), uintType(sourceBits));
        }
        return coerce(value, uintType(bits));
    }

    ExpressionPtr rawToFloat(ExpressionPtr value, int bits) const {
        return unary(bits == 32 ? "global::System.BitConverter.UInt32BitsToSingle" : "global::System.BitConverter.UInt64BitsToDouble",
            coerce(std::move(value), uintType(bits)), floatType(bits));
    }

    ExpressionPtr floatToRaw(ExpressionPtr value, int bits) const {
        return unary(bits == 32 ? "global::System.BitConverter.SingleToUInt32Bits" : "global::System.BitConverter.DoubleToUInt64Bits",
            coerce(std::move(value), floatType(bits)), uintType(bits));
    }

    ExpressionPtr roundToInteger(ExpressionPtr value) const {
        return unary("global::System.Math.Round", value, value->type);
    }

    ExpressionPtr readVectorFloat(const Operand& operand, int bits, int lane = 0) const {
        return rawToFloat(readVectorRaw(operand, bits, lane), bits);
    }

    Operand registerOperand(const char* name) const {
        Operand operand;
        operand.kind = OperandKind::Register;
        operand.reg = name;
        return operand;
    }

    ExpressionPtr vectorWithLane(const Operand& destination, ExpressionPtr value, int bits, int lane, bool zeroUpper) const {
        const auto info = registerInfo(destination.reg);
        const auto offset = lane * bits;
        const auto part = offset / 64;
        const auto shift = offset % 64;
        auto raw = coerce(std::move(value), uintType(bits));
        auto result = zeroUpper ? constant(0, uintType(64)) : vectorPartRegister(info, part);
        auto laneMask = binary("<<", maskConstant(bits, uintType(64)), constant(shift, uintType(64)), uintType(64));
        auto preserved = binary("&", result, unary("~", laneMask, uintType(64)), uintType(64));
        auto inserted = binary("<<", zeroExtend(std::move(raw), bits, 64), constant(shift, uintType(64)), uintType(64));
        return binary("|", preserved, inserted, uintType(64));
    }

    void writeVectorPart(const Operand& destination, int part, ExpressionPtr value) {
        value = coerce(std::move(value), uintType(64));
        if (destination.kind == OperandKind::Register) {
            const auto info = registerInfo(destination.reg);
            if (info.valid && info.vector) {
                add(assignment(vectorPartRegister(info, part), value));
            }
            return;
        }
        if (destination.kind == OperandKind::Memory) {
            auto address = addressOf(destination);
            if (part != 0) {
                address = binary("+", address, constant(part * 8, pointerType()), pointerType());
            }
            Statement statement;
            statement.address = current_->address;
            statement.kind = Statement::Kind::Store;
            statement.destination = std::move(address);
            statement.value = std::move(value);
            add(std::move(statement));
        }
    }

    void writeVectorLane(const Operand& destination, ExpressionPtr value, int bits, int lane, bool zeroUpper) {
        const auto info = registerInfo(destination.reg);
        const auto part = lane * bits / 64;
        add(assignment(vectorPartRegister(info, part), vectorWithLane(destination, std::move(value), bits, lane, zeroUpper)));
        if (zeroUpper) {
            for (int other = 0; other < vectorPartCount(info); ++other) {
                if (other != part) {
                    add(assignment(vectorPartRegister(info, other), constant(0, uintType(64))));
                }
            }
        }
    }

    int vectorWidth(const Operand& operand) const {
        const auto info = registerInfo(operand.reg);
        return info.valid && info.vector ? info.bits : 128;
    }

    int vectorLaneCount(const Operand& operand, int bits) const {
        return vectorWidth(operand) / bits;
    }

    void finishAvxVector(const Operand& destination) {
        const auto info = registerInfo(destination.reg);
        for (int part = vectorPartCount(info); part < 4; ++part) {
            add(assignment(vectorPartRegister(info, part), constant(0, uintType(64))));
        }
    }

    void writeWholeVector(const Operand& destination, const Operand& source, bool avx) {
        const auto parts = vectorPartCount(registerInfo(destination.reg));
        for (int part = 0; part < parts; ++part) {
            writeVectorPart(destination, part, readVectorRaw(source, 64, part));
        }
        if (avx) {
            finishAvxVector(destination);
        }
    }

    void copyVectorLanes(const Operand& destination, const Operand& source, int bits, int firstLane) {
        for (int lane = firstLane; lane < vectorLaneCount(destination, bits); ++lane) {
            writeVectorLane(destination, readVectorRaw(source, bits, lane), bits, lane, false);
        }
    }

    ExpressionPtr byteSwap(ExpressionPtr value, int bits) const {
        value = coerce(std::move(value), uintType(bits));
        ExpressionPtr result = constant(0, uintType(bits));
        for (int byte = 0; byte < bits / 8; ++byte) {
            auto part = binary("&", binary(">>", value, constant(byte * 8, uintType(bits)), uintType(bits)), constant(0xff, uintType(bits)), uintType(bits));
            part = binary("<<", part, constant(bits - 8 - byte * 8, uintType(bits)), uintType(bits));
            result = binary("|", result, part, uintType(bits));
        }
        return result;
    }

    ExpressionPtr directTarget(const Operand& operand) const {
        return constant(static_cast<uint64_t>(operand.immediate), pointerType());
    }

    void addBranch(const NativeInstruction& instruction, ExpressionPtr branchCondition = nullptr) {
        if (instruction.operands.empty()) {
            unsupported(instruction);
            return;
        }
        Statement statement;
        statement.address = instruction.address;
        statement.kind = branchCondition ? Statement::Kind::ConditionalBranch : Statement::Kind::Branch;
        statement.condition = std::move(branchCondition);
        const auto& target = instruction.operands.back();
        statement.target = target.kind == OperandKind::Immediate ? directTarget(target) : valueOf(target, pointerType());
        add(std::move(statement));
    }

    void addCall(const NativeInstruction& instruction) {
        if (instruction.operands.empty()) {
            unsupported(instruction);
            return;
        }
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Call;
        statement.destination = reg(pointerBits_ == 64 ? "rax" : "eax", uintType(pointerBits_));
        const auto& target = instruction.operands.back();
        statement.target = target.kind == OperandKind::Immediate ? directTarget(target) : valueOf(target, pointerType());
        if (pointerBits_ == 64) {
            statement.arguments = {
                readRegister("rcx"), readRegister("rdx"), readRegister("r8"), readRegister("r9"),
                reg("xmm0", uintType(64)), reg("xmm1", uintType(64)),
                reg("xmm2", uintType(64)), reg("xmm3", uintType(64))
            };
        } else {
            statement.arguments = {readRegister("ecx"), readRegister("edx")};
        }
        auto stack = readRegister(pointerBits_ == 64 ? "rsp" : "esp");
        for (int index = 0; index < 4; ++index) {
            auto address = index == 0 ? stack : binary("+", stack,
                constant(static_cast<uint64_t>(index * pointerBits_ / 8), pointerType()), pointerType());
            statement.arguments.push_back(load(address, uintType(pointerBits_)));
        }
        add(std::move(statement));
        invalidateFlags();
    }

    void unsupported(const NativeInstruction& instruction) {
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Call;
        statement.target = reg("RuntimeCalls.Unsupported_" + instruction.mnemonic, pointerType());
        statement.arguments = {constant(instruction.address, pointerType())};
        add(std::move(statement));
        invalidateFlags();
    }

    static bool isDirectBranch(uint32_t id) {
        switch (id) {
        case X86_INS_JMP: case X86_INS_JO: case X86_INS_JNO: case X86_INS_JB: case X86_INS_JAE:
        case X86_INS_JE: case X86_INS_JNE: case X86_INS_JBE: case X86_INS_JA: case X86_INS_JS:
        case X86_INS_JNS: case X86_INS_JP: case X86_INS_JNP: case X86_INS_JL: case X86_INS_JGE:
        case X86_INS_JLE: case X86_INS_JG: case X86_INS_JCXZ: case X86_INS_JECXZ: case X86_INS_JRCXZ:
        case X86_INS_LOOP: case X86_INS_LOOPE: case X86_INS_LOOPNE:
            return true;
        default:
            return false;
        }
    }

    void collectBranchTargets() {
        for (const auto& instruction : instructions_) {
            if (isDirectBranch(instruction.id) && !instruction.operands.empty()) {
                const auto& target = instruction.operands.back();
                if (target.kind == OperandKind::Immediate) {
                    branchTargets_.insert(static_cast<uint64_t>(target.immediate));
                }
            }
        }
    }

    void liftMove(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2) {
            return;
        }
        auto value = valueOf(ops[1]);
        const auto destinationBits = operandBits(ops[0]);
        const auto sourceBits = operandBits(ops[1]);
        if (instruction.id == X86_INS_MOVZX) {
            value = zeroExtend(std::move(value), sourceBits, destinationBits);
        } else if (instruction.id == X86_INS_MOVSX || instruction.id == X86_INS_MOVSXD) {
            value = signExtend(std::move(value), sourceBits, destinationBits);
        } else if (instruction.id == X86_INS_MOVBE) {
            value = byteSwap(std::move(value), destinationBits);
        }
        writeOperand(ops[0], std::move(value));
    }

    void liftBinary(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2) {
            return;
        }
        auto left = valueOf(ops[0]);
        auto right = coerce(valueOf(ops[1]), uintType(left->type.bits));
        const auto bits = left->type.bits;
        ExpressionPtr result;
        switch (instruction.id) {
        case X86_INS_ADD: result = binary("+", left, right, uintType(bits)); break;
        case X86_INS_ADC: {
            auto carry = carryAs(bits);
            result = binary("+", binary("+", left, right, uintType(bits)), carry, uintType(bits));
            setAddFlags(left, right, result, carry);
            break;
        }
        case X86_INS_SUB: result = binary("-", left, right, uintType(bits)); break;
        case X86_INS_SBB: {
            auto borrow = carryAs(bits);
            result = binary("-", binary("-", left, right, uintType(bits)), borrow, uintType(bits));
            setSubtractFlags(left, right, result, borrow);
            break;
        }
        case X86_INS_AND: result = binary("&", left, right, uintType(bits)); break;
        case X86_INS_OR: result = binary("|", left, right, uintType(bits)); break;
        case X86_INS_XOR: result = binary("^", left, right, uintType(bits)); break;
        case X86_INS_XADD: result = binary("+", left, right, uintType(bits)); break;
        default: return;
        }

        if (instruction.id == X86_INS_XADD) {
            auto oldLeft = saveTemporary("xadd_destination", left);
            auto oldRight = saveTemporary("xadd_source", right);
            auto savedResult = saveTemporary("xadd_result", result);
            setAddFlags(oldLeft, oldRight, savedResult);
            writeOperand(ops[1], oldLeft);
            writeOperand(ops[0], savedResult);
            return;
        }

        if (instruction.id == X86_INS_ADD) setAddFlags(left, right, result);
        else if (instruction.id == X86_INS_SUB) setSubtractFlags(left, right, result);
        else if (instruction.id == X86_INS_AND || instruction.id == X86_INS_OR || instruction.id == X86_INS_XOR) setLogicalFlags(result);
        writeOperand(ops[0], std::move(result));
    }

    void liftShift(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2) {
            return;
        }
        auto source = valueOf(ops[0]);
        const auto bits = source->type.bits;
        if (ops[1].kind == OperandKind::Immediate) {
            const auto immediateCount = static_cast<uint64_t>(ops[1].immediate) & (bits == 64 ? 63 : 31);
            const bool rotate = instruction.id == X86_INS_ROL || instruction.id == X86_INS_ROR;
            if (immediateCount == 0 || (rotate && immediateCount % bits == 0)) {
                return;
            }
        }
        auto count = shiftCount(ops[1], bits);
        const bool dynamicCount = ops[1].kind != OperandKind::Immediate;
        ExpressionPtr result;
        if (instruction.id == X86_INS_ROL || instruction.id == X86_INS_ROR) {
            auto rotateCount = count;
            if (bits < 32) {
                rotateCount = binary("%", count, constant(bits, uintType(bits)), uintType(bits));
            }
            auto inverse = binary("-", constant(bits, uintType(bits)), rotateCount, uintType(bits));
            auto forward = instruction.id == X86_INS_ROL
                ? binary("<<", source, rotateCount, uintType(bits))
                : binary(">>", source, rotateCount, uintType(bits));
            auto backward = instruction.id == X86_INS_ROL
                ? binary(">>", source, inverse, uintType(bits))
                : binary("<<", source, inverse, uintType(bits));
            result = binary("|", forward, backward, uintType(bits));
            result = select(binary("==", rotateCount, constant(0, uintType(bits)), boolType()), source, result, uintType(bits));
            setRotateFlags(instruction.id, count, result, dynamicCount);
        } else {
            switch (instruction.id) {
            case X86_INS_SHL:
            case X86_INS_SAL:
                result = binary("<<", source, count, uintType(bits));
                break;
            case X86_INS_SHR:
                result = binary(">>", source, count, uintType(bits));
                break;
            case X86_INS_SAR:
                result = cast(binary(">>", cast(source, intType(bits)), count, intType(bits)), uintType(bits));
                break;
            default:
                return;
            }
            result = select(binary("==", count, constant(0, uintType(bits)), boolType()), source, result, uintType(bits));
            setShiftFlags(instruction.id, source, count, result, dynamicCount);
        }
        writeOperand(ops[0], std::move(result));
    }

    void liftMultiply(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.empty()) {
            return;
        }
        const bool isSigned = instruction.id == X86_INS_IMUL;
        if (ops.size() >= 2) {
            auto left = valueOf(ops.size() == 2 ? ops[0] : ops[1]);
            auto right = coerce(valueOf(ops.size() == 2 ? ops[1] : ops[2]), left->type);
            const auto bits = left->type.bits;
            auto wideLeft = isSigned ? cast(cast(left, intType(bits)), intType(bits * 2)) : zeroExtend(left, bits, bits * 2);
            auto wideRight = isSigned ? cast(cast(right, intType(bits)), intType(bits * 2)) : zeroExtend(right, bits, bits * 2);
            auto product = binary("*", wideLeft, wideRight, isSigned ? intType(bits * 2) : uintType(bits * 2));
            auto savedProduct = saveTemporary("multiply_product", product);
            auto low = cast(savedProduct, uintType(bits));
            auto extendedLow = isSigned ? cast(cast(low, intType(bits)), intType(bits * 2)) : cast(low, uintType(bits * 2));
            auto overflow = binary("!=", coerce(savedProduct, extendedLow->type), extendedLow, boolType());
            setMultiplyFlags(overflow);
            writeOperand(ops[0], std::move(low));
            return;
        }

        const auto bits = operandBits(ops[0]);
        const char* lowName = bits == 8 ? "al" : bits == 16 ? "ax" : bits == 32 ? "eax" : "rax";
        const char* highName = bits == 16 ? "dx" : bits == 32 ? "edx" : "rdx";
        auto left = readRegister(lowName);
        auto right = coerce(valueOf(ops[0]), uintType(bits));
        ExpressionPtr product;
        if (bits == 8) {
            product = binary("*", isSigned ? signExtend(left, 8, 16) : zeroExtend(left, 8, 16), isSigned ? signExtend(right, 8, 16) : zeroExtend(right, 8, 16), uintType(16));
            auto savedProduct = saveTemporary("multiply_product", product);
            writeOperand(registerOperand("ax"), savedProduct);
            auto extendedLow = isSigned ? signExtend(cast(savedProduct, uintType(8)), 8, 16) : zeroExtend(cast(savedProduct, uintType(8)), 8, 16);
            setMultiplyFlags(binary("!=", savedProduct, extendedLow, boolType()));
            return;
        }

        auto wideLeft = isSigned ? cast(cast(left, intType(bits)), intType(bits * 2)) : zeroExtend(left, bits, bits * 2);
        auto wideRight = isSigned ? cast(cast(right, intType(bits)), intType(bits * 2)) : zeroExtend(right, bits, bits * 2);
        product = binary("*", wideLeft, wideRight, isSigned ? intType(bits * 2) : uintType(bits * 2));
        auto savedProduct = saveTemporary("multiply_product", product);
        auto low = cast(savedProduct, uintType(bits));
        auto high = cast(binary(">>", cast(savedProduct, uintType(bits * 2)), constant(bits, uintType(bits * 2)), uintType(bits * 2)), uintType(bits));
        auto extendedLow = isSigned ? cast(cast(low, intType(bits)), intType(bits * 2)) : cast(low, uintType(bits * 2));
        setMultiplyFlags(binary("!=", coerce(savedProduct, extendedLow->type), extendedLow, boolType()));
        add(assignRegister(lowName, low));
        add(assignRegister(highName, high));
    }

    void liftDivide64(ExpressionPtr divisor, bool isSigned) {
        const auto type = uintType(64);
        auto originalHigh = saveTemporary("divide_high", readRegister("rdx"));
        auto originalLow = saveTemporary("divide_low", readRegister("rax"));
        divisor = saveTemporary("divide_divisor", coerce(std::move(divisor), type));
        auto high = originalHigh;
        auto low = originalLow;
        ExpressionPtr dividendNegative;
        ExpressionPtr divisorNegative;
        if (isSigned) {
            dividendNegative = isNegative(originalHigh);
            divisorNegative = isNegative(divisor);
            auto lowNonzero = binary("!=", originalLow, constant(0, type), boolType());
            auto borrow = select(lowNonzero, constant(1, type), constant(0, type), type);
            auto absoluteHigh = binary("-", unary("-", originalHigh, type), borrow, type);
            high = saveTemporary("divide_high_absolute", select(dividendNegative, absoluteHigh, originalHigh, type));
            low = saveTemporary("divide_low_absolute", select(dividendNegative, unary("-", originalLow, type), originalLow, type));
            divisor = saveTemporary("divide_divisor_absolute", select(divisorNegative, unary("-", divisor, type), divisor, type));
        }

        auto remainder = saveTemporary("divide_remainder_work", binary("%", high, divisor, type));
        auto quotient = saveTemporary("divide_quotient_work", constant(0, type));
        for (int bit = 63; bit >= 0; --bit) {
            auto carry = saveTemporary("divide_carry", select(bitAt(remainder, 63), constant(1, type), constant(0, type), type));
            auto inputBit = select(bitAt(low, bit), constant(1, type), constant(0, type), type);
            auto shifted = binary("|", binary("<<", remainder, constant(1, type), type), inputBit, type);
            remainder = saveTemporary("divide_remainder_work", shifted);
            auto reduce = booleanOr(
                binary("!=", carry, constant(0, type), boolType()),
                binary(">=", remainder, divisor, boolType()));
            auto quotientBit = select(reduce, constant(1, type), constant(0, type), type);
            quotient = saveTemporary("divide_quotient_work",
                binary("|", binary("<<", quotient, constant(1, type), type), quotientBit, type));
            remainder = saveTemporary("divide_remainder_work",
                select(reduce, binary("-", remainder, divisor, type), remainder, type));
        }

        if (isSigned) {
            auto quotientNegative = binary("!=", dividendNegative, divisorNegative, boolType());
            quotient = select(quotientNegative, unary("-", quotient, type), quotient, type);
            remainder = select(dividendNegative, unary("-", remainder, type), remainder, type);
        }
        quotient = saveTemporary("divide_quotient", quotient);
        remainder = saveTemporary("divide_remainder", remainder);
        add(assignRegister("rax", quotient));
        add(assignRegister("rdx", remainder));
        invalidateFlags();
    }

    void liftDivide(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() != 1) {
            return;
        }
        const bool isSigned = instruction.id == X86_INS_IDIV;
        const auto bits = operandBits(ops[0]);
        auto divisor = valueOf(ops[0]);
        if (bits == 64) {
            liftDivide64(std::move(divisor), isSigned);
            return;
        }
        ExpressionPtr dividend;
        if (bits == 8) {
            dividend = readRegister("ax");
        } else {
            const char* lowName = bits == 16 ? "ax" : bits == 32 ? "eax" : "rax";
            const char* highName = bits == 16 ? "dx" : bits == 32 ? "edx" : "rdx";
            auto low = zeroExtend(readRegister(lowName), bits, bits * 2);
            auto high = binary("<<", zeroExtend(readRegister(highName), bits, bits * 2), constant(bits, uintType(bits * 2)), uintType(bits * 2));
            dividend = binary("|", high, low, uintType(bits * 2));
        }
        const auto wideBits = bits == 8 ? 16 : bits * 2;
        auto wideDivisor = isSigned ? signExtend(divisor, bits, wideBits) : zeroExtend(divisor, bits, wideBits);
        if (isSigned) {
            dividend = cast(dividend, intType(wideBits));
            wideDivisor = cast(wideDivisor, intType(wideBits));
        }
        const auto wideType = isSigned ? intType(wideBits) : uintType(wideBits);
        auto quotient = saveTemporary("divide_quotient", coerce(binary("/", dividend, wideDivisor, wideType), uintType(bits)));
        auto remainder = saveTemporary("divide_remainder", coerce(binary("%", dividend, wideDivisor, wideType), uintType(bits)));
        if (bits == 8) {
            add(assignRegister("al", cast(quotient, uintType(8))));
            add(assignRegister("ah", cast(remainder, uintType(8))));
        } else {
            const char* lowName = bits == 16 ? "ax" : bits == 32 ? "eax" : "rax";
            const char* highName = bits == 16 ? "dx" : bits == 32 ? "edx" : "rdx";
            add(assignRegister(lowName, cast(quotient, uintType(bits))));
            add(assignRegister(highName, cast(remainder, uintType(bits))));
        }
        invalidateFlags();
    }

    void liftSseMove(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2) {
            return;
        }
        const auto id = instruction.id;
        if (id == X86_INS_MOVD || id == X86_INS_MOVQ) {
            const auto bits = id == X86_INS_MOVD ? 32 : 64;
            if (ops[0].kind == OperandKind::Register && registerInfo(ops[0].reg).vector) {
                writeVectorLane(ops[0], readVectorRaw(ops[1], bits), bits, 0, true);
            } else {
                writeOperand(ops[0], readVectorRaw(ops[1], bits));
            }
            return;
        }
        if (id == X86_INS_MOVSS || id == X86_INS_MOVSD || id == X86_INS_MOVNTSS || id == X86_INS_MOVNTSD) {
            const auto bits = id == X86_INS_MOVSS || id == X86_INS_MOVNTSS ? 32 : 64;
            if (ops[0].kind == OperandKind::Register && registerInfo(ops[0].reg).vector) {
                writeVectorLane(ops[0], readVectorRaw(ops[1], bits), bits, 0, ops[1].kind == OperandKind::Memory);
            } else {
                writeOperand(ops[0], readVectorRaw(ops[1], bits));
            }
            return;
        }
        if (id == X86_INS_MOVLPS || id == X86_INS_MOVLPD || id == X86_INS_MOVHPS || id == X86_INS_MOVHPD) {
            const auto lane = id == X86_INS_MOVHPS || id == X86_INS_MOVHPD ? 1 : 0;
            if (ops[0].kind == OperandKind::Register && registerInfo(ops[0].reg).vector) {
                writeVectorLane(ops[0], readVectorRaw(ops[1], 64), 64, lane, false);
            } else {
                writeOperand(ops[0], readVectorRaw(ops[1], 64, lane));
            }
            return;
        }
        if (id == X86_INS_MOVHLPS || id == X86_INS_MOVLHPS) {
            const auto sourceLane = id == X86_INS_MOVHLPS ? 1 : 0;
            const auto destinationLane = id == X86_INS_MOVHLPS ? 0 : 1;
            writeVectorLane(ops[0], readVectorRaw(ops[1], 64, sourceLane), 64, destinationLane, false);
            return;
        }
        if (id == X86_INS_MOVDDUP || id == X86_INS_MOVSHDUP || id == X86_INS_MOVSLDUP) {
            const auto bits = id == X86_INS_MOVDDUP ? 64 : 32;
            const auto lanes = 128 / bits;
            std::vector<ExpressionPtr> sources;
            sources.reserve(lanes);
            for (int lane = 0; lane < lanes; ++lane) {
                const auto sourceLane = id == X86_INS_MOVDDUP ? 0 : id == X86_INS_MOVSHDUP ? lane | 1 : lane & ~1;
                sources.push_back(readVectorRaw(ops[1], bits, sourceLane));
            }
            for (int lane = 0; lane < lanes; ++lane) {
                writeVectorLane(ops[0], sources[lane], bits, lane, false);
            }
            return;
        }
        const auto parts = ops[0].kind == OperandKind::Register && registerInfo(ops[0].reg).valid
            ? vectorPartCount(registerInfo(ops[0].reg)) : 2;
        for (int part = 0; part < parts; ++part) {
            writeVectorPart(ops[0], part, readVectorRaw(ops[1], 64, part));
        }
    }

    void liftAvxMove(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto id = instruction.id;
        if (ops.size() < 2) {
            return;
        }
        if (id == X86_INS_VMOVD || id == X86_INS_VMOVQ) {
            const auto bits = id == X86_INS_VMOVD ? 32 : 64;
            if (ops[0].kind == OperandKind::Register && registerInfo(ops[0].reg).vector) {
                writeVectorLane(ops[0], readVectorRaw(ops[1], bits), bits, 0, true);
                finishAvxVector(ops[0]);
            } else {
                writeOperand(ops[0], readVectorRaw(ops[1], bits));
            }
            return;
        }
        if (id == X86_INS_VMOVSS || id == X86_INS_VMOVSD) {
            const auto bits = id == X86_INS_VMOVSS ? 32 : 64;
            if (ops[0].kind == OperandKind::Memory) {
                writeOperand(ops[0], readVectorRaw(ops.back(), bits));
            } else if (ops[1].kind == OperandKind::Memory) {
                writeVectorLane(ops[0], readVectorRaw(ops[1], bits), bits, 0, true);
                finishAvxVector(ops[0]);
            } else if (ops.size() >= 3) {
                copyVectorLanes(ops[0], ops[1], bits, 1);
                writeVectorLane(ops[0], readVectorRaw(ops[2], bits), bits, 0, false);
                finishAvxVector(ops[0]);
            }
            return;
        }
        if (id == X86_INS_VMOVLPS || id == X86_INS_VMOVLPD || id == X86_INS_VMOVHPS || id == X86_INS_VMOVHPD) {
            const auto lane = id == X86_INS_VMOVHPS || id == X86_INS_VMOVHPD ? 1 : 0;
            if (ops[0].kind == OperandKind::Memory) {
                writeOperand(ops[0], readVectorRaw(ops.back(), 64, lane));
            } else if (ops.size() >= 3) {
                writeWholeVector(ops[0], ops[1], false);
                writeVectorLane(ops[0], readVectorRaw(ops[2], 64), 64, lane, false);
                finishAvxVector(ops[0]);
            }
            return;
        }
        if (id == X86_INS_VMOVHLPS || id == X86_INS_VMOVLHPS) {
            if (ops.size() >= 3) {
                const auto sourceLane = id == X86_INS_VMOVHLPS ? 1 : 0;
                const auto destinationLane = id == X86_INS_VMOVHLPS ? 0 : 1;
                writeWholeVector(ops[0], ops[1], false);
                writeVectorLane(ops[0], readVectorRaw(ops[2], 64, sourceLane), 64, destinationLane, false);
                finishAvxVector(ops[0]);
            }
            return;
        }
        if (id == X86_INS_VMOVDDUP || id == X86_INS_VMOVSHDUP || id == X86_INS_VMOVSLDUP) {
            const auto bits = id == X86_INS_VMOVDDUP ? 64 : 32;
            const auto lanes = vectorLaneCount(ops[0], bits);
            std::vector<ExpressionPtr> sources;
            sources.reserve(lanes);
            for (int lane = 0; lane < lanes; ++lane) {
                const auto sourceLane = id == X86_INS_VMOVDDUP ? lane & ~1 : id == X86_INS_VMOVSHDUP ? lane | 1 : lane & ~1;
                sources.push_back(readVectorRaw(ops[1], bits, sourceLane));
            }
            for (int lane = 0; lane < lanes; ++lane) {
                writeVectorLane(ops[0], sources[lane], bits, lane, false);
            }
            finishAvxVector(ops[0]);
            return;
        }
        if (id == X86_INS_VEXTRACTF128 || id == X86_INS_VEXTRACTI128) {
            if (ops.size() >= 3 && ops[2].kind == OperandKind::Immediate) {
                const auto firstPart = static_cast<int>(ops[2].immediate & 1) * 2;
                for (int part = 0; part < 2; ++part) {
                    writeVectorPart(ops[0], part, readVectorRaw(ops[1], 64, firstPart + part));
                }
                if (ops[0].kind == OperandKind::Register) {
                    finishAvxVector(ops[0]);
                }
            }
            return;
        }
        if (id == X86_INS_VINSERTF128 || id == X86_INS_VINSERTI128) {
            if (ops.size() >= 4 && ops[3].kind == OperandKind::Immediate) {
                const auto firstPart = static_cast<int>(ops[3].immediate & 1) * 2;
                writeWholeVector(ops[0], ops[1], false);
                for (int part = 0; part < 2; ++part) {
                    writeVectorPart(ops[0], firstPart + part, readVectorRaw(ops[2], 64, part));
                }
                finishAvxVector(ops[0]);
            }
            return;
        }
        if (ops[0].kind == OperandKind::Memory) {
            const auto parts = vectorPartCount(registerInfo(ops[1].reg));
            for (int part = 0; part < parts; ++part) {
                writeVectorPart(ops[0], part, readVectorRaw(ops[1], 64, part));
            }
        } else {
            writeWholeVector(ops[0], ops[1], true);
        }
    }

    void liftSseConversion(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2) {
            return;
        }
        const auto id = instruction.id;
        if (id == X86_INS_CVTSS2SI || id == X86_INS_CVTTSS2SI || id == X86_INS_CVTSD2SI || id == X86_INS_CVTTSD2SI) {
            const auto sourceBits = id == X86_INS_CVTSS2SI || id == X86_INS_CVTTSS2SI ? 32 : 64;
            auto source = readVectorFloat(ops[1], sourceBits);
            if (id == X86_INS_CVTSS2SI || id == X86_INS_CVTSD2SI) {
                source = roundToInteger(source);
            }
            writeOperand(ops[0], cast(source, intType(operandBits(ops[0]))));
            return;
        }
        if (id == X86_INS_CVTSI2SS || id == X86_INS_CVTSI2SD) {
            const auto destinationBits = id == X86_INS_CVTSI2SS ? 32 : 64;
            auto source = cast(coerce(valueOf(ops[1]), uintType(operandBits(ops[1]))), intType(operandBits(ops[1])));
            auto converted = floatToRaw(cast(source, floatType(destinationBits)), destinationBits);
            writeVectorLane(ops[0], converted, destinationBits, 0, false);
            return;
        }
        if (id == X86_INS_CVTSS2SD || id == X86_INS_CVTSD2SS) {
            const auto sourceBits = id == X86_INS_CVTSS2SD ? 32 : 64;
            const auto destinationBits = id == X86_INS_CVTSS2SD ? 64 : 32;
            auto converted = floatToRaw(cast(readVectorFloat(ops[1], sourceBits), floatType(destinationBits)), destinationBits);
            writeVectorLane(ops[0], converted, destinationBits, 0, false);
            return;
        }

        int sourceBits = 32;
        int destinationBits = 32;
        int destinationLanes = 4;
        ScalarKind sourceKind = ScalarKind::SignedInteger;
        ScalarKind destinationKind = ScalarKind::FloatingPoint;
        switch (id) {
        case X86_INS_CVTDQ2PS:
            break;
        case X86_INS_CVTPS2DQ:
        case X86_INS_CVTTPS2DQ:
            sourceKind = ScalarKind::FloatingPoint;
            destinationKind = ScalarKind::SignedInteger;
            break;
        case X86_INS_CVTDQ2PD:
            destinationBits = 64;
            destinationLanes = 2;
            break;
        case X86_INS_CVTPS2PD:
            sourceKind = ScalarKind::FloatingPoint;
            destinationKind = ScalarKind::FloatingPoint;
            destinationBits = 64;
            destinationLanes = 2;
            break;
        case X86_INS_CVTPD2DQ:
        case X86_INS_CVTTPD2DQ:
            sourceKind = ScalarKind::FloatingPoint;
            destinationKind = ScalarKind::SignedInteger;
            sourceBits = 64;
            destinationLanes = 2;
            break;
        case X86_INS_CVTPD2PS:
            sourceKind = destinationKind = ScalarKind::FloatingPoint;
            sourceBits = 64;
            destinationLanes = 2;
            break;
        default:
            return;
        }
        std::vector<ExpressionPtr> convertedLanes;
        convertedLanes.reserve(destinationLanes);
        for (int lane = 0; lane < destinationLanes; ++lane) {
            auto source = readVectorRaw(ops[1], sourceBits, lane);
            source = sourceKind == ScalarKind::FloatingPoint ? rawToFloat(source, sourceBits) : cast(source, intType(sourceBits));
            if (destinationKind == ScalarKind::SignedInteger && sourceKind == ScalarKind::FloatingPoint &&
                (id == X86_INS_CVTPS2DQ || id == X86_INS_CVTPD2DQ)) {
                source = roundToInteger(source);
            }
            auto converted = cast(source, destinationKind == ScalarKind::FloatingPoint ? floatType(destinationBits) : intType(destinationBits));
            convertedLanes.push_back(destinationKind == ScalarKind::FloatingPoint
                ? floatToRaw(converted, destinationBits) : cast(converted, uintType(destinationBits)));
        }
        for (int lane = 0; lane < destinationLanes; ++lane) {
            writeVectorLane(ops[0], convertedLanes[lane], destinationBits, lane, false);
        }
        for (int part = destinationLanes * destinationBits / 64; part < 2; ++part) {
            writeVectorPart(ops[0], part, constant(0, uintType(64)));
        }
    }

    void liftAvxConversion(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto id = instruction.id;
        if (ops.size() < 2) {
            return;
        }
        if (id == X86_INS_VCVTSS2SI || id == X86_INS_VCVTTSS2SI ||
            id == X86_INS_VCVTSD2SI || id == X86_INS_VCVTTSD2SI) {
            const auto sourceBits = id == X86_INS_VCVTSS2SI || id == X86_INS_VCVTTSS2SI ? 32 : 64;
            auto source = readVectorFloat(ops[1], sourceBits);
            if (id == X86_INS_VCVTSS2SI || id == X86_INS_VCVTSD2SI) {
                source = roundToInteger(source);
            }
            writeOperand(ops[0], cast(source, intType(operandBits(ops[0]))));
            return;
        }
        if (id == X86_INS_VCVTSI2SS || id == X86_INS_VCVTSI2SD ||
            id == X86_INS_VCVTSS2SD || id == X86_INS_VCVTSD2SS) {
            if (ops.size() < 3) {
                return;
            }
            const auto destinationBits = id == X86_INS_VCVTSI2SS || id == X86_INS_VCVTSD2SS ? 32 : 64;
            ExpressionPtr converted;
            if (id == X86_INS_VCVTSI2SS || id == X86_INS_VCVTSI2SD) {
                auto source = cast(coerce(valueOf(ops[2]), uintType(operandBits(ops[2]))), intType(operandBits(ops[2])));
                converted = floatToRaw(cast(source, floatType(destinationBits)), destinationBits);
            } else {
                const auto sourceBits = id == X86_INS_VCVTSS2SD ? 32 : 64;
                converted = floatToRaw(cast(readVectorFloat(ops[2], sourceBits), floatType(destinationBits)), destinationBits);
            }
            copyVectorLanes(ops[0], ops[1], destinationBits, 1);
            writeVectorLane(ops[0], converted, destinationBits, 0, false);
            finishAvxVector(ops[0]);
            return;
        }

        int sourceBits = 32;
        int destinationBits = 32;
        ScalarKind sourceKind = ScalarKind::SignedInteger;
        ScalarKind destinationKind = ScalarKind::FloatingPoint;
        switch (id) {
        case X86_INS_VCVTDQ2PS:
            break;
        case X86_INS_VCVTPS2DQ:
        case X86_INS_VCVTTPS2DQ:
            sourceKind = ScalarKind::FloatingPoint;
            destinationKind = ScalarKind::SignedInteger;
            break;
        case X86_INS_VCVTDQ2PD:
            destinationBits = 64;
            break;
        case X86_INS_VCVTPS2PD:
            sourceKind = ScalarKind::FloatingPoint;
            destinationKind = ScalarKind::FloatingPoint;
            destinationBits = 64;
            break;
        case X86_INS_VCVTPD2DQ:
        case X86_INS_VCVTTPD2DQ:
            sourceKind = ScalarKind::FloatingPoint;
            destinationKind = ScalarKind::SignedInteger;
            sourceBits = 64;
            break;
        case X86_INS_VCVTPD2PS:
            sourceKind = ScalarKind::FloatingPoint;
            destinationKind = ScalarKind::FloatingPoint;
            sourceBits = 64;
            break;
        default:
            return;
        }
        const auto lanes = vectorLaneCount(ops[0], destinationBits);
        std::vector<ExpressionPtr> convertedLanes;
        convertedLanes.reserve(lanes);
        for (int lane = 0; lane < lanes; ++lane) {
            auto source = readVectorRaw(ops[1], sourceBits, lane);
            source = sourceKind == ScalarKind::FloatingPoint ? rawToFloat(source, sourceBits) : cast(source, intType(sourceBits));
            if (destinationKind == ScalarKind::SignedInteger && sourceKind == ScalarKind::FloatingPoint &&
                (id == X86_INS_VCVTPS2DQ || id == X86_INS_VCVTPD2DQ)) {
                source = roundToInteger(source);
            }
            auto converted = cast(source, destinationKind == ScalarKind::FloatingPoint ? floatType(destinationBits) : intType(destinationBits));
            convertedLanes.push_back(destinationKind == ScalarKind::FloatingPoint
                ? floatToRaw(converted, destinationBits) : cast(converted, uintType(destinationBits)));
        }
        for (int lane = 0; lane < lanes; ++lane) {
            writeVectorLane(ops[0], convertedLanes[lane], destinationBits, lane, false);
        }
        for (int part = lanes * destinationBits / 64; part < vectorPartCount(registerInfo(ops[0].reg)); ++part) {
            writeVectorPart(ops[0], part, constant(0, uintType(64)));
        }
        finishAvxVector(ops[0]);
    }

    void liftSseArithmetic(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (ops.size() < 2) {
            return;
        }
        const auto id = instruction.id;
        const bool scalar = id == X86_INS_ADDSS || id == X86_INS_SUBSS || id == X86_INS_MULSS || id == X86_INS_DIVSS ||
            id == X86_INS_ADDSD || id == X86_INS_SUBSD || id == X86_INS_MULSD || id == X86_INS_DIVSD;
        const auto bits = id == X86_INS_ADDSS || id == X86_INS_SUBSS || id == X86_INS_MULSS || id == X86_INS_DIVSS ||
            id == X86_INS_ADDPS || id == X86_INS_SUBPS || id == X86_INS_MULPS || id == X86_INS_DIVPS ? 32 : 64;
        const char* op = id == X86_INS_ADDSS || id == X86_INS_ADDSD || id == X86_INS_ADDPS || id == X86_INS_ADDPD ? "+" :
            id == X86_INS_SUBSS || id == X86_INS_SUBSD || id == X86_INS_SUBPS || id == X86_INS_SUBPD ? "-" :
            id == X86_INS_MULSS || id == X86_INS_MULSD || id == X86_INS_MULPS || id == X86_INS_MULPD ? "*" : "/";
        if (scalar) {
            auto left = readVectorFloat(ops[0], bits);
            auto right = readVectorFloat(ops[1], bits);
            writeVectorLane(ops[0], floatToRaw(binary(op, left, right, floatType(bits)), bits), bits, 0, false);
            return;
        }
        const auto lanes = 128 / bits;
        for (int lane = 0; lane < lanes; ++lane) {
            auto left = readVectorFloat(ops[0], bits, lane);
            auto right = readVectorFloat(ops[1], bits, lane);
            auto value = floatToRaw(binary(op, left, right, floatType(bits)), bits);
            writeVectorLane(ops[0], value, bits, lane, false);
        }
    }

    void liftLaneImmediate(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto id = instruction.id;
        const bool avx = id == X86_INS_VPINSRB || id == X86_INS_VPINSRW || id == X86_INS_VPINSRD || id == X86_INS_VPINSRQ ||
            id == X86_INS_VPEXTRB || id == X86_INS_VPEXTRW || id == X86_INS_VPEXTRD || id == X86_INS_VPEXTRQ ||
            id == X86_INS_VINSERTPS || id == X86_INS_VEXTRACTPS || id == X86_INS_VPSHUFD ||
            id == X86_INS_VPSHUFHW || id == X86_INS_VPSHUFLW || id == X86_INS_VSHUFPS || id == X86_INS_VSHUFPD ||
            id == X86_INS_VPBLENDW || id == X86_INS_VPBLENDD || id == X86_INS_VBLENDPS || id == X86_INS_VBLENDPD ||
            id == X86_INS_VBLENDVPS || id == X86_INS_VBLENDVPD || id == X86_INS_VPBLENDVB;
        const bool insert = id == X86_INS_PINSRB || id == X86_INS_PINSRW || id == X86_INS_PINSRD || id == X86_INS_PINSRQ ||
            id == X86_INS_VPINSRB || id == X86_INS_VPINSRW || id == X86_INS_VPINSRD || id == X86_INS_VPINSRQ;
        const bool extract = id == X86_INS_PEXTRB || id == X86_INS_PEXTRW || id == X86_INS_PEXTRD || id == X86_INS_PEXTRQ ||
            id == X86_INS_VPEXTRB || id == X86_INS_VPEXTRW || id == X86_INS_VPEXTRD || id == X86_INS_VPEXTRQ;
        if (insert || extract) {
            const auto bits = id == X86_INS_PINSRB || id == X86_INS_PEXTRB || id == X86_INS_VPINSRB || id == X86_INS_VPEXTRB ? 8 :
                id == X86_INS_PINSRW || id == X86_INS_PEXTRW || id == X86_INS_VPINSRW || id == X86_INS_VPEXTRW ? 16 :
                id == X86_INS_PINSRD || id == X86_INS_PEXTRD || id == X86_INS_VPINSRD || id == X86_INS_VPEXTRD ? 32 : 64;
            const auto immediateIndex = avx && insert ? 3 : 2;
            if (ops.size() <= static_cast<size_t>(immediateIndex) || ops[immediateIndex].kind != OperandKind::Immediate) {
                return;
            }
            const auto lane = static_cast<int>(ops[immediateIndex].immediate) & (128 / bits - 1);
            if (extract) {
                writeOperand(ops[0], readVectorRaw(ops[1], bits, lane));
            } else {
                if (avx) {
                    writeWholeVector(ops[0], ops[1], false);
                }
                writeVectorLane(ops[0], readVectorRaw(ops[avx ? 2 : 1], bits), bits, lane, false);
                if (avx) {
                    finishAvxVector(ops[0]);
                }
            }
            return;
        }
        if (id == X86_INS_EXTRACTPS || id == X86_INS_VEXTRACTPS) {
            if (ops.size() >= 3 && ops[2].kind == OperandKind::Immediate) {
                writeOperand(ops[0], readVectorRaw(ops[1], 32, static_cast<int>(ops[2].immediate & 3)));
            }
            return;
        }
        if (id == X86_INS_INSERTPS || id == X86_INS_VINSERTPS) {
            const auto immediateIndex = avx ? 3 : 2;
            if (ops.size() <= static_cast<size_t>(immediateIndex) || ops[immediateIndex].kind != OperandKind::Immediate) {
                return;
            }
            const auto immediate = static_cast<uint64_t>(ops[immediateIndex].immediate);
            if (avx) {
                writeWholeVector(ops[0], ops[1], false);
            }
            const auto sourceLane = static_cast<int>((immediate >> 6) & 3);
            const auto destinationLane = static_cast<int>((immediate >> 4) & 3);
            writeVectorLane(ops[0], readVectorRaw(ops[avx ? 2 : 1], 32, sourceLane), 32, destinationLane, false);
            for (int lane = 0; lane < 4; ++lane) {
                if ((immediate & (uint64_t{1} << lane)) != 0) {
                    writeVectorLane(ops[0], constant(0, uintType(32)), 32, lane, false);
                }
            }
            if (avx) {
                finishAvxVector(ops[0]);
            }
            return;
        }
        if (id == X86_INS_PSHUFD || id == X86_INS_VPSHUFD || id == X86_INS_PSHUFHW || id == X86_INS_VPSHUFHW ||
            id == X86_INS_PSHUFLW || id == X86_INS_VPSHUFLW || id == X86_INS_SHUFPS || id == X86_INS_VSHUFPS ||
            id == X86_INS_SHUFPD || id == X86_INS_VSHUFPD) {
            const bool shuffle = id == X86_INS_SHUFPS || id == X86_INS_SHUFPD || id == X86_INS_VSHUFPS || id == X86_INS_VSHUFPD;
            const auto immediateIndex = avx && shuffle ? 3 : 2;
            if (ops.size() <= static_cast<size_t>(immediateIndex) || ops[immediateIndex].kind != OperandKind::Immediate) {
                return;
            }
            const auto immediate = static_cast<uint64_t>(ops[immediateIndex].immediate);
            const auto bits = id == X86_INS_SHUFPD || id == X86_INS_VSHUFPD ? 64 :
                id == X86_INS_PSHUFHW || id == X86_INS_VPSHUFHW || id == X86_INS_PSHUFLW || id == X86_INS_VPSHUFLW ? 16 : 32;
            const auto groupLanes = 128 / bits;
            const auto& left = shuffle && !avx ? ops[0] : ops[1];
            const auto& right = avx ? ops[2] : ops[1];
            for (int lane = 0; lane < vectorLaneCount(ops[0], bits); ++lane) {
                const auto groupBase = lane / groupLanes * groupLanes;
                const auto position = lane % groupLanes;
                auto sourceLane = lane;
                const Operand* source = &ops[1];
                if (id == X86_INS_PSHUFD || id == X86_INS_VPSHUFD) {
                    sourceLane = groupBase + static_cast<int>((immediate >> (2 * position)) & 3);
                } else if (id == X86_INS_PSHUFHW || id == X86_INS_VPSHUFHW || id == X86_INS_PSHUFLW || id == X86_INS_VPSHUFLW) {
                    const bool high = id == X86_INS_PSHUFHW || id == X86_INS_VPSHUFHW;
                    if ((position >= 4) == high) {
                        sourceLane = groupBase + (high ? 4 : 0) + static_cast<int>((immediate >> (2 * (position & 3))) & 3);
                    }
                } else if (id == X86_INS_SHUFPS || id == X86_INS_VSHUFPS) {
                    source = position < 2 ? &left : &right;
                    sourceLane = groupBase + static_cast<int>((immediate >> (2 * position)) & 3);
                } else {
                    source = position == 0 ? &left : &right;
                    sourceLane = groupBase + static_cast<int>((immediate >> position) & 1);
                }
                writeVectorLane(ops[0], saveTemporary("lane_value", readVectorRaw(*source, bits, sourceLane)), bits, lane, false);
            }
            if (avx) {
                finishAvxVector(ops[0]);
            }
            return;
        }

        const bool variable = id == X86_INS_BLENDVPS || id == X86_INS_BLENDVPD || id == X86_INS_PBLENDVB ||
            id == X86_INS_VBLENDVPS || id == X86_INS_VBLENDVPD || id == X86_INS_VPBLENDVB;
        const auto bits = id == X86_INS_PBLENDW || id == X86_INS_VPBLENDW ? 16 :
            id == X86_INS_PBLENDVB || id == X86_INS_VPBLENDVB ? 8 :
            id == X86_INS_BLENDPD || id == X86_INS_VBLENDPD || id == X86_INS_BLENDVPD || id == X86_INS_VBLENDVPD ? 64 : 32;
        const auto immediateIndex = variable ? -1 : avx ? 3 : 2;
        if (!variable && (ops.size() <= static_cast<size_t>(immediateIndex) || ops[immediateIndex].kind != OperandKind::Immediate)) {
            return;
        }
        const auto immediate = variable ? 0 : static_cast<uint64_t>(ops[immediateIndex].immediate);
        const auto& left = avx ? ops[1] : ops[0];
        const auto& right = avx ? ops[2] : ops[1];
        const auto maskOperand = variable ? (avx ? ops[3] : ops.size() >= 3 ? ops[2] : registerOperand("xmm0")) : Operand{};
        if (avx) {
            writeWholeVector(ops[0], left, false);
        }
        for (int lane = 0; lane < vectorLaneCount(ops[0], bits); ++lane) {
            auto leftValue = readVectorRaw(left, bits, lane);
            auto rightValue = readVectorRaw(right, bits, lane);
            auto selected = variable
                ? select(bitAt(readVectorRaw(maskOperand, bits, lane), bits - 1), rightValue, leftValue, uintType(bits))
                : ((immediate & (uint64_t{1} << (lane % (128 / bits)))) != 0 ? rightValue : leftValue);
            writeVectorLane(ops[0], saveTemporary("lane_value", selected), bits, lane, false);
        }
        if (avx) {
            finishAvxVector(ops[0]);
        }
    }

    void liftAvxArithmetic(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto id = instruction.id;
        if (ops.size() < 3) {
            return;
        }
        const bool scalar = id == X86_INS_VADDSS || id == X86_INS_VSUBSS || id == X86_INS_VMULSS || id == X86_INS_VDIVSS ||
            id == X86_INS_VADDSD || id == X86_INS_VSUBSD || id == X86_INS_VMULSD || id == X86_INS_VDIVSD;
        const auto bits = id == X86_INS_VADDSS || id == X86_INS_VSUBSS || id == X86_INS_VMULSS || id == X86_INS_VDIVSS ||
            id == X86_INS_VADDPS || id == X86_INS_VSUBPS || id == X86_INS_VMULPS || id == X86_INS_VDIVPS ? 32 : 64;
        const char* op = id == X86_INS_VADDSS || id == X86_INS_VADDSD || id == X86_INS_VADDPS || id == X86_INS_VADDPD ? "+" :
            id == X86_INS_VSUBSS || id == X86_INS_VSUBSD || id == X86_INS_VSUBPS || id == X86_INS_VSUBPD ? "-" :
            id == X86_INS_VMULSS || id == X86_INS_VMULSD || id == X86_INS_VMULPS || id == X86_INS_VMULPD ? "*" : "/";
        if (scalar) {
            copyVectorLanes(ops[0], ops[1], bits, 1);
            auto left = readVectorFloat(ops[1], bits);
            auto right = readVectorFloat(ops[2], bits);
            writeVectorLane(ops[0], floatToRaw(binary(op, left, right, floatType(bits)), bits), bits, 0, false);
        } else {
            for (int lane = 0; lane < vectorLaneCount(ops[0], bits); ++lane) {
                auto left = readVectorFloat(ops[1], bits, lane);
                auto right = readVectorFloat(ops[2], bits, lane);
                writeVectorLane(ops[0], floatToRaw(binary(op, left, right, floatType(bits)), bits), bits, lane, false);
            }
        }
        finishAvxVector(ops[0]);
    }

    void liftFpSpecial(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto id = instruction.id;
        if (ops.size() < 2) {
            return;
        }
        const bool avx = id == X86_INS_VMINSS || id == X86_INS_VMINSD || id == X86_INS_VMINPS || id == X86_INS_VMINPD ||
            id == X86_INS_VMAXSS || id == X86_INS_VMAXSD || id == X86_INS_VMAXPS || id == X86_INS_VMAXPD ||
            id == X86_INS_VSQRTSS || id == X86_INS_VSQRTSD || id == X86_INS_VSQRTPS || id == X86_INS_VSQRTPD;
        const bool scalar = id == X86_INS_MINSS || id == X86_INS_MINSD || id == X86_INS_MAXSS || id == X86_INS_MAXSD ||
            id == X86_INS_SQRTSS || id == X86_INS_SQRTSD || id == X86_INS_VMINSS || id == X86_INS_VMINSD ||
            id == X86_INS_VMAXSS || id == X86_INS_VMAXSD || id == X86_INS_VSQRTSS || id == X86_INS_VSQRTSD;
        const bool bits32 = id == X86_INS_MINSS || id == X86_INS_MAXSS || id == X86_INS_SQRTSS ||
            id == X86_INS_MINPS || id == X86_INS_MAXPS || id == X86_INS_SQRTPS ||
            id == X86_INS_VMINSS || id == X86_INS_VMAXSS || id == X86_INS_VSQRTSS ||
            id == X86_INS_VMINPS || id == X86_INS_VMAXPS || id == X86_INS_VSQRTPS;
        const auto bits = bits32 ? 32 : 64;
        const auto& leftOperand = avx ? ops[1] : ops[0];
        const auto& rightOperand = avx ? ops[2] : ops[1];
        const bool minimum = id == X86_INS_MINSS || id == X86_INS_MINSD || id == X86_INS_MINPS || id == X86_INS_MINPD ||
            id == X86_INS_VMINSS || id == X86_INS_VMINSD || id == X86_INS_VMINPS || id == X86_INS_VMINPD;
        const bool maximum = id == X86_INS_MAXSS || id == X86_INS_MAXSD || id == X86_INS_MAXPS || id == X86_INS_MAXPD ||
            id == X86_INS_VMAXSS || id == X86_INS_VMAXSD || id == X86_INS_VMAXPS || id == X86_INS_VMAXPD;
        const auto convertLane = [&](int lane) {
            if (!minimum && !maximum) {
                return floatToRaw(unary("global::System.Math.Sqrt", readVectorFloat(rightOperand, bits, lane), floatType(bits)), bits);
            }
            auto left = readVectorFloat(leftOperand, bits, lane);
            auto right = readVectorFloat(rightOperand, bits, lane);
            return floatToRaw(select(binary(minimum ? "<" : ">", left, right, boolType()), left, right, floatType(bits)), bits);
        };
        if (scalar && avx) {
            copyVectorLanes(ops[0], leftOperand, bits, 1);
        }
        const auto lanes = scalar ? 1 : vectorLaneCount(ops[0], bits);
        for (int lane = 0; lane < lanes; ++lane) {
            writeVectorLane(ops[0], convertLane(lane), bits, lane, false);
        }
        if (avx) {
            finishAvxVector(ops[0]);
        }
    }

    void liftAvxBitwise(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto id = instruction.id;
        if (ops.size() < 3) {
            return;
        }
        const bool isAnd = id == X86_INS_VPAND || id == X86_INS_VANDPS || id == X86_INS_VANDPD;
        const bool isAndNot = id == X86_INS_VPANDN || id == X86_INS_VANDNPS || id == X86_INS_VANDNPD;
        const bool isOr = id == X86_INS_VPOR || id == X86_INS_VORPS || id == X86_INS_VORPD;
        for (int part = 0; part < vectorPartCount(registerInfo(ops[0].reg)); ++part) {
            auto left = readVectorRaw(ops[1], 64, part);
            auto right = readVectorRaw(ops[2], 64, part);
            auto result = isAndNot ? binary("&", unary("~", left, left->type), right, left->type) :
                binary(isAnd ? "&" : isOr ? "|" : "^", left, right, left->type);
            writeVectorPart(ops[0], part, result);
        }
        finishAvxVector(ops[0]);
    }

    enum class PackedIntegerOperation {
        Add,
        Subtract,
        MultiplyLow,
        MultiplyHigh,
        MultiplyEven,
        Minimum,
        Maximum
    };

    void liftPackedInteger(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto id = instruction.id;
        PackedIntegerOperation operation = PackedIntegerOperation::Add;
        int bits = 0;
        bool avx = false;
        bool isSigned = false;
        bool saturating = false;
        switch (id) {
        case X86_INS_PADDB: case X86_INS_PADDSB: case X86_INS_PADDUSB:
            bits = 8; saturating = id != X86_INS_PADDB; isSigned = id == X86_INS_PADDSB; break;
        case X86_INS_PADDW: case X86_INS_PADDSW: case X86_INS_PADDUSW:
            bits = 16; saturating = id != X86_INS_PADDW; isSigned = id == X86_INS_PADDSW; break;
        case X86_INS_PADDD: bits = 32; break;
        case X86_INS_PADDQ: bits = 64; break;
        case X86_INS_PSUBB: case X86_INS_PSUBSB: case X86_INS_PSUBUSB:
            operation = PackedIntegerOperation::Subtract; bits = 8; saturating = id != X86_INS_PSUBB; isSigned = id == X86_INS_PSUBSB; break;
        case X86_INS_PSUBW: case X86_INS_PSUBSW: case X86_INS_PSUBUSW:
            operation = PackedIntegerOperation::Subtract; bits = 16; saturating = id != X86_INS_PSUBW; isSigned = id == X86_INS_PSUBSW; break;
        case X86_INS_PSUBD: operation = PackedIntegerOperation::Subtract; bits = 32; break;
        case X86_INS_PSUBQ: operation = PackedIntegerOperation::Subtract; bits = 64; break;
        case X86_INS_PMULLW: operation = PackedIntegerOperation::MultiplyLow; bits = 16; break;
        case X86_INS_PMULLD: operation = PackedIntegerOperation::MultiplyLow; bits = 32; break;
        case X86_INS_PMULHW: operation = PackedIntegerOperation::MultiplyHigh; bits = 16; isSigned = true; break;
        case X86_INS_PMULHUW: operation = PackedIntegerOperation::MultiplyHigh; bits = 16; break;
        case X86_INS_PMULDQ: operation = PackedIntegerOperation::MultiplyEven; bits = 32; isSigned = true; break;
        case X86_INS_PMULUDQ: operation = PackedIntegerOperation::MultiplyEven; bits = 32; break;
        case X86_INS_PMINSB: case X86_INS_PMINSW: case X86_INS_PMINSD:
        case X86_INS_PMINUB: case X86_INS_PMINUW: case X86_INS_PMINUD:
            operation = PackedIntegerOperation::Minimum;
            bits = id == X86_INS_PMINSB || id == X86_INS_PMINUB ? 8 : id == X86_INS_PMINSW || id == X86_INS_PMINUW ? 16 : 32;
            isSigned = id == X86_INS_PMINSB || id == X86_INS_PMINSW || id == X86_INS_PMINSD;
            break;
        case X86_INS_PMAXSB: case X86_INS_PMAXSW: case X86_INS_PMAXSD:
        case X86_INS_PMAXUB: case X86_INS_PMAXUW: case X86_INS_PMAXUD:
            operation = PackedIntegerOperation::Maximum;
            bits = id == X86_INS_PMAXSB || id == X86_INS_PMAXUB ? 8 : id == X86_INS_PMAXSW || id == X86_INS_PMAXUW ? 16 : 32;
            isSigned = id == X86_INS_PMAXSB || id == X86_INS_PMAXSW || id == X86_INS_PMAXSD;
            break;
        case X86_INS_VPADDB: case X86_INS_VPADDSB: case X86_INS_VPADDUSB:
            avx = true; bits = 8; saturating = id != X86_INS_VPADDB; isSigned = id == X86_INS_VPADDSB; break;
        case X86_INS_VPADDW: case X86_INS_VPADDSW: case X86_INS_VPADDUSW:
            avx = true; bits = 16; saturating = id != X86_INS_VPADDW; isSigned = id == X86_INS_VPADDSW; break;
        case X86_INS_VPADDD: avx = true; bits = 32; break;
        case X86_INS_VPADDQ: avx = true; bits = 64; break;
        case X86_INS_VPSUBB: case X86_INS_VPSUBSB: case X86_INS_VPSUBUSB:
            avx = true; operation = PackedIntegerOperation::Subtract; bits = 8; saturating = id != X86_INS_VPSUBB; isSigned = id == X86_INS_VPSUBSB; break;
        case X86_INS_VPSUBW: case X86_INS_VPSUBSW: case X86_INS_VPSUBUSW:
            avx = true; operation = PackedIntegerOperation::Subtract; bits = 16; saturating = id != X86_INS_VPSUBW; isSigned = id == X86_INS_VPSUBSW; break;
        case X86_INS_VPSUBD: avx = true; operation = PackedIntegerOperation::Subtract; bits = 32; break;
        case X86_INS_VPSUBQ: avx = true; operation = PackedIntegerOperation::Subtract; bits = 64; break;
        case X86_INS_VPMULLW: avx = true; operation = PackedIntegerOperation::MultiplyLow; bits = 16; break;
        case X86_INS_VPMULLD: avx = true; operation = PackedIntegerOperation::MultiplyLow; bits = 32; break;
        case X86_INS_VPMULHW: avx = true; operation = PackedIntegerOperation::MultiplyHigh; bits = 16; isSigned = true; break;
        case X86_INS_VPMULHUW: avx = true; operation = PackedIntegerOperation::MultiplyHigh; bits = 16; break;
        case X86_INS_VPMULDQ: avx = true; operation = PackedIntegerOperation::MultiplyEven; bits = 32; isSigned = true; break;
        case X86_INS_VPMULUDQ: avx = true; operation = PackedIntegerOperation::MultiplyEven; bits = 32; break;
        case X86_INS_VPMINSB: case X86_INS_VPMINSW: case X86_INS_VPMINSD:
        case X86_INS_VPMINUB: case X86_INS_VPMINUW: case X86_INS_VPMINUD:
            avx = true; operation = PackedIntegerOperation::Minimum;
            bits = id == X86_INS_VPMINSB || id == X86_INS_VPMINUB ? 8 : id == X86_INS_VPMINSW || id == X86_INS_VPMINUW ? 16 : 32;
            isSigned = id == X86_INS_VPMINSB || id == X86_INS_VPMINSW || id == X86_INS_VPMINSD;
            break;
        case X86_INS_VPMAXSB: case X86_INS_VPMAXSW: case X86_INS_VPMAXSD:
        case X86_INS_VPMAXUB: case X86_INS_VPMAXUW: case X86_INS_VPMAXUD:
            avx = true; operation = PackedIntegerOperation::Maximum;
            bits = id == X86_INS_VPMAXSB || id == X86_INS_VPMAXUB ? 8 : id == X86_INS_VPMAXSW || id == X86_INS_VPMAXUW ? 16 : 32;
            isSigned = id == X86_INS_VPMAXSB || id == X86_INS_VPMAXSW || id == X86_INS_VPMAXSD;
            break;
        default:
            return;
        }
        if (ops.size() < (avx ? 3U : 2U)) {
            return;
        }
        const auto& leftOperand = avx ? ops[1] : ops[0];
        const auto& rightOperand = avx ? ops[2] : ops[1];
        const auto outputBits = operation == PackedIntegerOperation::MultiplyEven ? 64 : bits;
        const auto lanes = vectorLaneCount(ops[0], outputBits);
        for (int lane = 0; lane < lanes; ++lane) {
            const auto sourceLane = operation == PackedIntegerOperation::MultiplyEven ? lane * 2 : lane;
            auto left = readVectorRaw(leftOperand, bits, sourceLane);
            auto right = readVectorRaw(rightOperand, bits, sourceLane);
            ExpressionPtr result;
            if (operation == PackedIntegerOperation::MultiplyEven || operation == PackedIntegerOperation::MultiplyHigh) {
                const auto wideBits = bits * 2;
                left = isSigned ? signExtend(left, bits, wideBits) : zeroExtend(left, bits, wideBits);
                right = isSigned ? signExtend(right, bits, wideBits) : zeroExtend(right, bits, wideBits);
                const auto wideType = isSigned ? intType(wideBits) : uintType(wideBits);
                if (isSigned) {
                    left = cast(left, wideType);
                    right = cast(right, wideType);
                }
                result = binary("*", left, right, wideType);
                if (operation == PackedIntegerOperation::MultiplyHigh) {
                    result = binary(">>", result, constant(bits, wideType), wideType);
                }
                result = coerce(result, uintType(outputBits));
            } else if (operation == PackedIntegerOperation::MultiplyLow) {
                result = cast(binary("*", left, right, uintType(bits)), uintType(bits));
            } else if (operation == PackedIntegerOperation::Minimum || operation == PackedIntegerOperation::Maximum) {
                const auto comparisonType = isSigned ? intType(bits) : uintType(bits);
                left = cast(left, comparisonType);
                right = cast(right, comparisonType);
                result = select(binary(operation == PackedIntegerOperation::Minimum ? "<" : ">", left, right, boolType()),
                    left, right, comparisonType);
            } else if (saturating) {
                const auto wideBits = bits * 2;
                const auto wideType = isSigned ? intType(wideBits) : uintType(wideBits);
                left = isSigned ? signExtend(left, bits, wideBits) : zeroExtend(left, bits, wideBits);
                right = isSigned ? signExtend(right, bits, wideBits) : zeroExtend(right, bits, wideBits);
                left = cast(left, wideType);
                right = cast(right, wideType);
                result = binary(operation == PackedIntegerOperation::Add ? "+" : "-", left, right, wideType);
                if (isSigned) {
                    const auto minimum = -(int64_t{1} << (bits - 1));
                    const auto maximum = (int64_t{1} << (bits - 1)) - 1;
                    result = select(binary("<", result, constant(static_cast<uint64_t>(minimum), wideType), boolType()),
                        constant(static_cast<uint64_t>(minimum), wideType), result, wideType);
                    result = select(binary(">", result, constant(maximum, wideType), boolType()),
                        constant(maximum, wideType), result, wideType);
                } else if (operation == PackedIntegerOperation::Subtract) {
                    result = select(binary("<", left, right, boolType()), constant(0, wideType), result, wideType);
                } else {
                    const auto maximum = (uint64_t{1} << bits) - 1;
                    result = select(binary(">", result, constant(maximum, wideType), boolType()),
                        constant(maximum, wideType), result, wideType);
                }
                result = coerce(result, uintType(bits));
            } else {
                result = binary(operation == PackedIntegerOperation::Add ? "+" : "-", left, right, uintType(bits));
            }
            writeVectorLane(ops[0], saveTemporary("packed_value", coerce(result, uintType(outputBits))), outputBits, lane, false);
        }
        if (avx) {
            finishAvxVector(ops[0]);
        }
    }

    void lift(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        const auto id = instruction.id;

        const auto conditionCode = conditionFor(id);
        if (conditionCode != Condition::Invalid) {
            switch (id) {
            case X86_INS_JO: case X86_INS_JNO: case X86_INS_JB: case X86_INS_JAE:
            case X86_INS_JE: case X86_INS_JNE: case X86_INS_JBE: case X86_INS_JA:
            case X86_INS_JS: case X86_INS_JNS: case X86_INS_JP: case X86_INS_JNP:
            case X86_INS_JL: case X86_INS_JGE: case X86_INS_JLE: case X86_INS_JG:
                addBranch(instruction, condition(conditionCode));
                return;
            default:
                break;
            }
            if (ops.size() == 1 &&
                (ops[0].kind == OperandKind::Register || ops[0].kind == OperandKind::Memory)) {
                writeOperand(ops[0], select(condition(conditionCode), constant(1, uintType(8)), constant(0, uintType(8)), uintType(8)));
                return;
            }
            if (ops.size() == 2 && ops[0].kind == OperandKind::Register) {
                const auto bits = operandBits(ops[0]);
                auto source = saveTemporary("cmov_source", valueOf(ops[1], uintType(bits)));
                auto destination = valueOf(ops[0], uintType(bits));
                writeOperand(ops[0], select(condition(conditionCode), source, destination, uintType(bits)));
                return;
            }
            unsupported(instruction);
            return;
        }

        switch (id) {
        case X86_INS_NOP:
        case X86_INS_ENDBR32:
        case X86_INS_ENDBR64:
        case X86_INS_PAUSE:
        case X86_INS_LFENCE:
        case X86_INS_MFENCE:
        case X86_INS_SFENCE:
            return;

        case X86_INS_MOV:
        case X86_INS_MOVABS:
        case X86_INS_MOVZX:
        case X86_INS_MOVSX:
        case X86_INS_MOVSXD:
        case X86_INS_MOVBE:
        case X86_INS_MOVNTI:
            liftMove(instruction);
            return;

        case X86_INS_MOVAPS:
        case X86_INS_MOVUPS:
        case X86_INS_MOVAPD:
        case X86_INS_MOVUPD:
        case X86_INS_MOVDQA:
        case X86_INS_MOVDQU:
        case X86_INS_MOVNTDQ:
        case X86_INS_MOVNTDQA:
        case X86_INS_MOVNTPS:
        case X86_INS_MOVNTPD:
        case X86_INS_MOVNTSS:
        case X86_INS_MOVNTSD:
        case X86_INS_LDDQU:
        case X86_INS_MOVD:
        case X86_INS_MOVQ:
        case X86_INS_MOVSS:
        case X86_INS_MOVSD:
        case X86_INS_MOVLPS:
        case X86_INS_MOVLPD:
        case X86_INS_MOVHPS:
        case X86_INS_MOVHPD:
        case X86_INS_MOVHLPS:
        case X86_INS_MOVLHPS:
        case X86_INS_MOVDDUP:
        case X86_INS_MOVSHDUP:
        case X86_INS_MOVSLDUP:
            liftSseMove(instruction);
            return;

        case X86_INS_VMOVAPS:
        case X86_INS_VMOVUPS:
        case X86_INS_VMOVAPD:
        case X86_INS_VMOVUPD:
        case X86_INS_VMOVDQA:
        case X86_INS_VMOVDQU:
        case X86_INS_VMOVNTDQ:
        case X86_INS_VMOVNTDQA:
        case X86_INS_VMOVNTPS:
        case X86_INS_VMOVNTPD:
        case X86_INS_VLDDQU:
        case X86_INS_VMOVD:
        case X86_INS_VMOVQ:
        case X86_INS_VMOVSS:
        case X86_INS_VMOVSD:
        case X86_INS_VMOVLPS:
        case X86_INS_VMOVLPD:
        case X86_INS_VMOVHPS:
        case X86_INS_VMOVHPD:
        case X86_INS_VMOVHLPS:
        case X86_INS_VMOVLHPS:
        case X86_INS_VMOVDDUP:
        case X86_INS_VMOVSHDUP:
        case X86_INS_VMOVSLDUP:
        case X86_INS_VEXTRACTF128:
        case X86_INS_VEXTRACTI128:
        case X86_INS_VINSERTF128:
        case X86_INS_VINSERTI128:
            liftAvxMove(instruction);
            return;

        case X86_INS_CVTSS2SI:
        case X86_INS_CVTTSS2SI:
        case X86_INS_CVTSD2SI:
        case X86_INS_CVTTSD2SI:
        case X86_INS_CVTSI2SS:
        case X86_INS_CVTSI2SD:
        case X86_INS_CVTSS2SD:
        case X86_INS_CVTSD2SS:
        case X86_INS_CVTDQ2PS:
        case X86_INS_CVTPS2DQ:
        case X86_INS_CVTTPS2DQ:
        case X86_INS_CVTDQ2PD:
        case X86_INS_CVTPS2PD:
        case X86_INS_CVTPD2DQ:
        case X86_INS_CVTTPD2DQ:
        case X86_INS_CVTPD2PS:
            liftSseConversion(instruction);
            return;

        case X86_INS_VCVTSS2SI:
        case X86_INS_VCVTTSS2SI:
        case X86_INS_VCVTSD2SI:
        case X86_INS_VCVTTSD2SI:
        case X86_INS_VCVTSI2SS:
        case X86_INS_VCVTSI2SD:
        case X86_INS_VCVTSS2SD:
        case X86_INS_VCVTSD2SS:
        case X86_INS_VCVTDQ2PS:
        case X86_INS_VCVTPS2DQ:
        case X86_INS_VCVTTPS2DQ:
        case X86_INS_VCVTDQ2PD:
        case X86_INS_VCVTPS2PD:
        case X86_INS_VCVTPD2DQ:
        case X86_INS_VCVTTPD2DQ:
        case X86_INS_VCVTPD2PS:
            liftAvxConversion(instruction);
            return;

        case X86_INS_ADDSS:
        case X86_INS_ADDSD:
        case X86_INS_ADDPS:
        case X86_INS_ADDPD:
        case X86_INS_SUBSS:
        case X86_INS_SUBSD:
        case X86_INS_SUBPS:
        case X86_INS_SUBPD:
        case X86_INS_MULSS:
        case X86_INS_MULSD:
        case X86_INS_MULPS:
        case X86_INS_MULPD:
        case X86_INS_DIVSS:
        case X86_INS_DIVSD:
        case X86_INS_DIVPS:
        case X86_INS_DIVPD:
            liftSseArithmetic(instruction);
            return;

        case X86_INS_VADDSS:
        case X86_INS_VADDSD:
        case X86_INS_VADDPS:
        case X86_INS_VADDPD:
        case X86_INS_VSUBSS:
        case X86_INS_VSUBSD:
        case X86_INS_VSUBPS:
        case X86_INS_VSUBPD:
        case X86_INS_VMULSS:
        case X86_INS_VMULSD:
        case X86_INS_VMULPS:
        case X86_INS_VMULPD:
        case X86_INS_VDIVSS:
        case X86_INS_VDIVSD:
        case X86_INS_VDIVPS:
        case X86_INS_VDIVPD:
            liftAvxArithmetic(instruction);
            return;

        case X86_INS_MINSS:
        case X86_INS_MINSD:
        case X86_INS_MINPS:
        case X86_INS_MINPD:
        case X86_INS_MAXSS:
        case X86_INS_MAXSD:
        case X86_INS_MAXPS:
        case X86_INS_MAXPD:
        case X86_INS_SQRTSS:
        case X86_INS_SQRTSD:
        case X86_INS_SQRTPS:
        case X86_INS_SQRTPD:
        case X86_INS_VMINSS:
        case X86_INS_VMINSD:
        case X86_INS_VMINPS:
        case X86_INS_VMINPD:
        case X86_INS_VMAXSS:
        case X86_INS_VMAXSD:
        case X86_INS_VMAXPS:
        case X86_INS_VMAXPD:
        case X86_INS_VSQRTSS:
        case X86_INS_VSQRTSD:
        case X86_INS_VSQRTPS:
        case X86_INS_VSQRTPD:
            liftFpSpecial(instruction);
            return;

        case X86_INS_PINSRB:
        case X86_INS_PINSRW:
        case X86_INS_PINSRD:
        case X86_INS_PINSRQ:
        case X86_INS_PEXTRB:
        case X86_INS_PEXTRW:
        case X86_INS_PEXTRD:
        case X86_INS_PEXTRQ:
        case X86_INS_INSERTPS:
        case X86_INS_EXTRACTPS:
        case X86_INS_PSHUFD:
        case X86_INS_PSHUFHW:
        case X86_INS_PSHUFLW:
        case X86_INS_SHUFPS:
        case X86_INS_SHUFPD:
        case X86_INS_BLENDPS:
        case X86_INS_BLENDPD:
        case X86_INS_PBLENDW:
        case X86_INS_BLENDVPS:
        case X86_INS_BLENDVPD:
        case X86_INS_PBLENDVB:
        case X86_INS_VPINSRB:
        case X86_INS_VPINSRW:
        case X86_INS_VPINSRD:
        case X86_INS_VPINSRQ:
        case X86_INS_VPEXTRB:
        case X86_INS_VPEXTRW:
        case X86_INS_VPEXTRD:
        case X86_INS_VPEXTRQ:
        case X86_INS_VINSERTPS:
        case X86_INS_VEXTRACTPS:
        case X86_INS_VPSHUFD:
        case X86_INS_VPSHUFHW:
        case X86_INS_VPSHUFLW:
        case X86_INS_VSHUFPS:
        case X86_INS_VSHUFPD:
        case X86_INS_VPBLENDW:
        case X86_INS_VPBLENDD:
        case X86_INS_VBLENDPS:
        case X86_INS_VBLENDPD:
        case X86_INS_VBLENDVPS:
        case X86_INS_VBLENDVPD:
        case X86_INS_VPBLENDVB:
            liftLaneImmediate(instruction);
            return;

        case X86_INS_PXOR:
        case X86_INS_PAND:
        case X86_INS_PANDN:
        case X86_INS_POR:
        case X86_INS_XORPS:
        case X86_INS_XORPD:
        case X86_INS_ANDPS:
        case X86_INS_ANDPD:
        case X86_INS_ANDNPS:
        case X86_INS_ANDNPD:
        case X86_INS_ORPS:
        case X86_INS_ORPD: {
            if (ops.size() < 2) return;
            const bool isAnd = id == X86_INS_PAND || id == X86_INS_ANDPS || id == X86_INS_ANDPD;
            const bool isAndNot = id == X86_INS_PANDN || id == X86_INS_ANDNPS || id == X86_INS_ANDNPD;
            const bool isOr = id == X86_INS_POR || id == X86_INS_ORPS || id == X86_INS_ORPD;
            for (int part = 0; part < 2; ++part) {
                auto left = readVectorRaw(ops[0], 64, part);
                auto right = readVectorRaw(ops[1], 64, part);
                auto result = isAndNot ? binary("&", unary("~", left, left->type), right, left->type) :
                    binary(isAnd ? "&" : isOr ? "|" : "^", left, right, left->type);
                writeVectorPart(ops[0], part, result);
            }
            return;
        }

        case X86_INS_VPXOR:
        case X86_INS_VPAND:
        case X86_INS_VPANDN:
        case X86_INS_VPOR:
        case X86_INS_VXORPS:
        case X86_INS_VXORPD:
        case X86_INS_VANDPS:
        case X86_INS_VANDPD:
        case X86_INS_VANDNPS:
        case X86_INS_VANDNPD:
        case X86_INS_VORPS:
        case X86_INS_VORPD:
            liftAvxBitwise(instruction);
            return;

        case X86_INS_PADDB: case X86_INS_PADDW: case X86_INS_PADDD: case X86_INS_PADDQ:
        case X86_INS_PADDSB: case X86_INS_PADDSW: case X86_INS_PADDUSB: case X86_INS_PADDUSW:
        case X86_INS_PSUBB: case X86_INS_PSUBW: case X86_INS_PSUBD: case X86_INS_PSUBQ:
        case X86_INS_PSUBSB: case X86_INS_PSUBSW: case X86_INS_PSUBUSB: case X86_INS_PSUBUSW:
        case X86_INS_PMULLW: case X86_INS_PMULLD: case X86_INS_PMULHW: case X86_INS_PMULHUW:
        case X86_INS_PMULDQ: case X86_INS_PMULUDQ:
        case X86_INS_PMINSB: case X86_INS_PMINSW: case X86_INS_PMINSD:
        case X86_INS_PMINUB: case X86_INS_PMINUW: case X86_INS_PMINUD:
        case X86_INS_PMAXSB: case X86_INS_PMAXSW: case X86_INS_PMAXSD:
        case X86_INS_PMAXUB: case X86_INS_PMAXUW: case X86_INS_PMAXUD:
        case X86_INS_VPADDB: case X86_INS_VPADDW: case X86_INS_VPADDD: case X86_INS_VPADDQ:
        case X86_INS_VPADDSB: case X86_INS_VPADDSW: case X86_INS_VPADDUSB: case X86_INS_VPADDUSW:
        case X86_INS_VPSUBB: case X86_INS_VPSUBW: case X86_INS_VPSUBD: case X86_INS_VPSUBQ:
        case X86_INS_VPSUBSB: case X86_INS_VPSUBSW: case X86_INS_VPSUBUSB: case X86_INS_VPSUBUSW:
        case X86_INS_VPMULLW: case X86_INS_VPMULLD: case X86_INS_VPMULHW: case X86_INS_VPMULHUW:
        case X86_INS_VPMULDQ: case X86_INS_VPMULUDQ:
        case X86_INS_VPMINSB: case X86_INS_VPMINSW: case X86_INS_VPMINSD:
        case X86_INS_VPMINUB: case X86_INS_VPMINUW: case X86_INS_VPMINUD:
        case X86_INS_VPMAXSB: case X86_INS_VPMAXSW: case X86_INS_VPMAXSD:
        case X86_INS_VPMAXUB: case X86_INS_VPMAXUW: case X86_INS_VPMAXUD:
            liftPackedInteger(instruction);
            return;

        case X86_INS_VZEROUPPER:
        case X86_INS_VZEROALL: {
            const auto firstPart = id == X86_INS_VZEROUPPER ? 2 : 0;
            for (int index = 0; index < (pointerBits_ == 64 ? 16 : 8); ++index) {
                const auto info = registerInfo("xmm" + std::to_string(index));
                for (int part = firstPart; part < 4; ++part) {
                    add(assignment(vectorPartRegister(info, part), constant(0, uintType(64))));
                }
            }
            return;
        }

        case X86_INS_LEA:
            if (ops.size() >= 2 && ops[1].kind == OperandKind::Memory) {
                add(assignRegister(ops[0].reg, addressOf(ops[1])));
            }
            return;

        case X86_INS_XCHG: {
            if (ops.size() < 2) return;
            auto left = saveTemporary("xchg_left", valueOf(ops[0]));
            auto right = saveTemporary("xchg_right", valueOf(ops[1]));
            writeOperand(ops[0], right);
            writeOperand(ops[1], left);
            return;
        }

        case X86_INS_BSWAP:
            if (!ops.empty()) writeOperand(ops[0], byteSwap(valueOf(ops[0]), operandBits(ops[0])));
            return;

        case X86_INS_ADD:
        case X86_INS_ADC:
        case X86_INS_SUB:
        case X86_INS_SBB:
        case X86_INS_AND:
        case X86_INS_OR:
        case X86_INS_XOR:
        case X86_INS_XADD:
            liftBinary(instruction);
            return;

        case X86_INS_SHL:
        case X86_INS_SAL:
        case X86_INS_SHR:
        case X86_INS_SAR:
        case X86_INS_ROL:
        case X86_INS_ROR:
            liftShift(instruction);
            return;

        case X86_INS_MUL:
        case X86_INS_IMUL:
            liftMultiply(instruction);
            return;

        case X86_INS_DIV:
        case X86_INS_IDIV:
            liftDivide(instruction);
            return;

        case X86_INS_INC:
        case X86_INS_DEC: {
            if (ops.empty()) return;
            auto oldValue = valueOf(ops[0]);
            auto one = constant(1, oldValue->type);
            auto result = binary(id == X86_INS_INC ? "+" : "-", oldValue, one, oldValue->type);
            if (id == X86_INS_INC) setAddFlags(oldValue, one, result, nullptr, true);
            else setSubtractFlags(oldValue, one, result, nullptr, true);
            writeOperand(ops[0], result);
            return;
        }

        case X86_INS_NEG: {
            if (ops.empty()) return;
            auto oldValue = valueOf(ops[0]);
            auto zero = constant(0, oldValue->type);
            auto result = unary("-", oldValue, oldValue->type);
            setSubtractFlags(zero, oldValue, result);
            writeOperand(ops[0], result);
            return;
        }

        case X86_INS_NOT:
            if (!ops.empty()) writeOperand(ops[0], unary("~", valueOf(ops[0]), valueOf(ops[0])->type));
            return;

        case X86_INS_CBW:
            add(assignRegister("ax", signExtend(readRegister("al"), 8, 16)));
            return;
        case X86_INS_CWDE:
            add(assignRegister("eax", signExtend(readRegister("ax"), 16, 32)));
            return;
        case X86_INS_CDQE:
            if (pointerBits_ == 64) add(assignRegister("rax", signExtend(readRegister("eax"), 32, 64)));
            return;
        case X86_INS_CWD: {
            auto sign = cast(binary(">>", cast(readRegister("ax"), intType(16)), constant(15, intType(16)), intType(16)), uintType(16));
            add(assignRegister("dx", sign));
            return;
        }
        case X86_INS_CDQ: {
            auto sign = cast(binary(">>", cast(readRegister("eax"), intType(32)), constant(31, intType(32)), intType(32)), uintType(32));
            add(assignRegister("edx", sign));
            return;
        }
        case X86_INS_CQO: {
            if (pointerBits_ == 64) {
                auto sign = cast(binary(">>", cast(readRegister("rax"), intType(64)), constant(63, intType(64)), intType(64)), uintType(64));
                add(assignRegister("rdx", sign));
            }
            return;
        }

        case X86_INS_CMP: {
            if (ops.size() < 2) return;
            auto left = valueOf(ops[0]);
            auto right = coerce(valueOf(ops[1]), left->type);
            auto result = binary("-", left, right, left->type);
            setSubtractFlags(left, right, result);
            return;
        }
        case X86_INS_TEST: {
            if (ops.size() < 2) return;
            auto left = valueOf(ops[0]);
            auto right = coerce(valueOf(ops[1]), left->type);
            setLogicalFlags(binary("&", left, right, left->type));
            return;
        }
        case X86_INS_COMISS:
        case X86_INS_UCOMISS:
        case X86_INS_COMISD:
        case X86_INS_UCOMISD: {
            if (ops.size() < 2) return;
            const auto bits = id == X86_INS_COMISS || id == X86_INS_UCOMISS ? 32 : 64;
            auto left = rawToFloat(saveTemporary("flags_float_left", readVectorRaw(ops[0], bits)), bits);
            auto right = rawToFloat(saveTemporary("flags_float_right", readVectorRaw(ops[1], bits)), bits);
            auto unordered = booleanOr(binary("!=", left, left, boolType()), binary("!=", right, right, boolType()));
            flags_.zero = booleanOr(unordered, binary("==", left, right, boolType()));
            flags_.carry = booleanOr(unordered, binary("<", left, right, boolType()));
            flags_.parity = unordered;
            flags_.overflow = booleanConstant(false);
            flags_.sign = booleanConstant(false);
            return;
        }

        case X86_INS_BT:
        case X86_INS_BTS:
        case X86_INS_BTR:
        case X86_INS_BTC: {
            if (ops.size() < 2) return;
            auto base = valueOf(ops[0]);
            const auto bits = base->type.bits;
            auto index = binary("&", coerce(valueOf(ops[1]), uintType(bits)), constant(bits - 1, uintType(bits)), uintType(bits));
            auto savedBase = saveTemporary(id == X86_INS_BT ? "flags_bit_base" : "bit_base", base);
            auto savedIndex = saveTemporary(id == X86_INS_BT ? "flags_bit_index" : "bit_index", index);
            flags_.carry = bitAt(savedBase, savedIndex);
            if (id != X86_INS_BT) {
                auto mask = binary("<<", constant(1, uintType(bits)), savedIndex, uintType(bits));
                auto result = id == X86_INS_BTS ? binary("|", savedBase, mask, uintType(bits)) :
                    id == X86_INS_BTR ? binary("&", savedBase, unary("~", mask, uintType(bits)), uintType(bits)) :
                    binary("^", savedBase, mask, uintType(bits));
                writeOperand(ops[0], result);
            }
            return;
        }

        case X86_INS_CMPXCHG: {
            if (ops.size() < 2) return;
            const auto bits = operandBits(ops[0]);
            const char* accumulator = bits == 8 ? "al" : bits == 16 ? "ax" : bits == 32 ? "eax" : "rax";
            auto oldDestination = saveTemporary("cmpxchg_destination", valueOf(ops[0]));
            auto oldAccumulator = saveTemporary("cmpxchg_accumulator", readRegister(accumulator));
            auto source = saveTemporary("cmpxchg_source", valueOf(ops[1], uintType(bits)));
            auto result = saveTemporary("cmpxchg_result", binary("-", oldAccumulator, oldDestination, uintType(bits)));
            setSubtractFlags(oldAccumulator, oldDestination, result);
            auto equal = isZero(result);
            writeOperand(ops[0], select(equal, source, oldDestination, uintType(bits)));
            add(assignRegister(accumulator, select(equal, oldAccumulator, oldDestination, uintType(bits))));
            return;
        }

        case X86_INS_CLC:
            flags_.carry = booleanConstant(false);
            return;
        case X86_INS_STC:
            flags_.carry = booleanConstant(true);
            return;
        case X86_INS_CMC:
            flags_.carry = flags_.carry ? booleanNot(flags_.carry) : unknown(boolType());
            return;

        case X86_INS_PUSH: {
            if (ops.empty()) {
                unsupported(instruction);
                return;
            }
            const auto stack = pointerBits_ == 64 ? "rsp" : "esp";
            const auto stackBits = ops[0].kind == OperandKind::Immediate ? pointerBits_ : operandBits(ops[0]);
            auto oldStack = readRegister(stack);
            auto newStack = binary("-", oldStack, constant(stackBits / 8, pointerType()), pointerType());
            auto value = valueOf(ops[0]);
            if (ops[0].kind == OperandKind::Immediate && operandBits(ops[0]) < stackBits) {
                value = signExtend(value, operandBits(ops[0]), stackBits);
            } else {
                value = coerce(value, uintType(stackBits));
            }
            Statement store;
            store.address = instruction.address;
            store.kind = Statement::Kind::Store;
            store.destination = newStack;
            store.value = value;
            add(std::move(store));
            add(assignRegister(stack, newStack));
            return;
        }
        case X86_INS_POP: {
            if (ops.empty()) {
                unsupported(instruction);
                return;
            }
            const auto stack = pointerBits_ == 64 ? "rsp" : "esp";
            const auto stackBits = operandBits(ops[0]);
            auto oldStack = saveTemporary("pop_stack", readRegister(stack));
            auto value = saveTemporary("pop_value", load(coerce(oldStack, pointerType()), uintType(stackBits)));
            add(assignRegister(stack, binary("+", oldStack, constant(stackBits / 8, pointerType()), pointerType())));
            writeOperand(ops[0], value);
            return;
        }
        case X86_INS_LEAVE: {
            const auto stack = pointerBits_ == 64 ? "rsp" : "esp";
            const auto frame = pointerBits_ == 64 ? "rbp" : "ebp";
            auto oldFrame = saveTemporary("leave_frame", readRegister(frame));
            add(assignRegister(stack, oldFrame));
            auto value = load(coerce(oldFrame, pointerType()), uintType(pointerBits_));
            add(assignRegister(frame, value));
            add(assignRegister(stack, binary("+", oldFrame, constant(pointerBits_ / 8, pointerType()), pointerType())));
            return;
        }
        case X86_INS_ENTER: {
            if (ops.size() < 2 || ops[1].kind != OperandKind::Immediate || ops[1].immediate != 0) {
                unsupported(instruction);
                return;
            }
            const auto stack = pointerBits_ == 64 ? "rsp" : "esp";
            const auto frame = pointerBits_ == 64 ? "rbp" : "ebp";
            auto oldStack = readRegister(stack);
            auto newStack = binary("-", oldStack, constant(pointerBits_ / 8, pointerType()), pointerType());
            Statement store;
            store.address = instruction.address;
            store.kind = Statement::Kind::Store;
            store.destination = newStack;
            store.value = readRegister(frame);
            add(std::move(store));
            add(assignRegister(stack, newStack));
            add(assignRegister(frame, readRegister(stack)));
            add(assignRegister(stack, binary("-", readRegister(stack), constant(static_cast<uint64_t>(ops[0].immediate), pointerType()), pointerType())));
            return;
        }

        case X86_INS_CALL:
            addCall(instruction);
            return;
        case X86_INS_JMP:
            addBranch(instruction);
            return;
        case X86_INS_JCXZ:
        case X86_INS_JECXZ:
        case X86_INS_JRCXZ: {
            const auto counter = id == X86_INS_JCXZ ? "cx" : id == X86_INS_JECXZ ? "ecx" : "rcx";
            addBranch(instruction, isZero(readRegister(counter)));
            return;
        }
        case X86_INS_LOOP:
        case X86_INS_LOOPE:
        case X86_INS_LOOPNE: {
            const auto counter = pointerBits_ == 64 ? "rcx" : "ecx";
            auto value = binary("-", readRegister(counter), constant(1, uintType(pointerBits_)), uintType(pointerBits_));
            add(assignRegister(counter, value));
            auto loopCondition = binary("!=", value, constant(0, uintType(pointerBits_)), boolType());
            if (id == X86_INS_LOOPE) loopCondition = booleanAnd(loopCondition, condition(Condition::E));
            if (id == X86_INS_LOOPNE) loopCondition = booleanAnd(loopCondition, condition(Condition::NE));
            addBranch(instruction, loopCondition);
            return;
        }
        case X86_INS_RET: {
            if (!ops.empty() && ops[0].kind == OperandKind::Immediate && ops[0].immediate != 0) {
                const auto stack = pointerBits_ == 64 ? "rsp" : "esp";
                add(assignRegister(stack, binary("+", readRegister(stack), constant(static_cast<uint64_t>(ops[0].immediate), pointerType()), pointerType())));
            }
            Statement statement;
            statement.address = instruction.address;
            statement.kind = Statement::Kind::Return;
            statement.value = readRegister(pointerBits_ == 64 ? "rax" : "eax");
            add(std::move(statement));
            return;
        }
        default:
            unsupported(instruction);
            return;
        }
    }
};

X86Lifter::X86Lifter(Architecture architecture, uint64_t address, std::string name)
    : impl_(std::make_unique<Impl>(architecture, address, std::move(name))) {}

X86Lifter::X86Lifter(const FunctionImage& image)
    : X86Lifter(image.architecture, image.address, image.name) {}

X86Lifter::~X86Lifter() = default;
X86Lifter::X86Lifter(X86Lifter&&) noexcept = default;
X86Lifter& X86Lifter::operator=(X86Lifter&&) noexcept = default;

RecoveredFunction X86Lifter::run(std::vector<NativeInstruction> instructions) {
    return impl_->run(std::move(instructions));
}

} // namespace il2cpprec
