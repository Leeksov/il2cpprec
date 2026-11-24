#include <il2cpprec/Recovery.hpp>
#include <il2cpprec/flow/ExceptionRegions.hpp>
#include <il2cpprec/flow/RecursiveDecoder.hpp>
#include <il2cpprec/flow/SSA.hpp>
#include <il2cpprec/lifters/Arm32Lifter.hpp>
#include <il2cpprec/lifters/Arm64Lifter.hpp>
#include <il2cpprec/lifters/X86Lifter.hpp>

#include <capstone/arm.h>
#include <capstone/arm64.h>
#include <capstone/x86.h>

#include <algorithm>
#include <cctype>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
namespace {

struct RegisterInfo {
    std::string canonical;
    uint16_t bits;
    bool highByte = false;
    bool floatingPoint = false;
    bool zero = false;
};

class Lifter {
public:
    explicit Lifter(const FunctionImage& image)
        : image_(image), pointerBits_(image.architecture == Architecture::Arm64 || image.architecture == Architecture::X64 ? 64 : 32) {
        output_.architecture = image.architecture;
        output_.address = image.address;
        output_.name = image.name;
    }

    RecoveredFunction run(std::vector<NativeInstruction> instructions) {
        instructions_ = std::move(instructions);
        collectBranchTargets();
        for (const auto& instruction : instructions_) {
            if (branchTargets_.contains(instruction.address) && !output_.blocks.empty() && !output_.blocks.back().statements.empty()) {
                output_.blocks.push_back({instruction.address, {}});
                terminated_ = false;
            }
            if (!terminated_) {
                lift(instruction);
            }
        }
        return std::move(output_);
    }

private:
    const FunctionImage& image_;
    int pointerBits_;
    RecoveredFunction output_;
    std::vector<NativeInstruction> instructions_;
    std::set<uint64_t> branchTargets_;
    ExpressionPtr flagsLeft_;
    ExpressionPtr flagsRight_;
    Arm64Lifter arm64Extended_;
    std::unordered_map<std::string, ScalarType> registerViews_;
    const NativeInstruction* currentInstruction_ = nullptr;
    bool terminated_ = false;

    ScalarType pointerType() const { return ScalarType::pointer(pointerBits_); }
    ScalarType uintType(int bits) const { return ScalarType::uintBits(static_cast<uint16_t>(bits)); }
    ScalarType intType(int bits) const { return ScalarType::intBits(static_cast<uint16_t>(bits)); }

    BasicBlock& currentBlock() {
        if (output_.blocks.empty()) {
            output_.blocks.push_back({image_.address, {}});
        }
        return output_.blocks.back();
    }

    void add(Statement statement) {
        statement.address = instructions_.empty() ? image_.address : statement.address;
        trackRegisterView(statement);
        if (statement.kind == Statement::Kind::Return || statement.kind == Statement::Kind::Branch) {
            terminated_ = true;
        }
        currentBlock().statements.push_back(std::move(statement));
    }

    RegisterInfo registerInfo(std::string name) const {
        if (image_.architecture == Architecture::Arm64) {
            if (name == "lr") return {"x30", 64};
            if (name == "fp") return {"x29", 64};
            if (name == "wsp") return {"sp", 32};
            if (name == "sp") return {"sp", 64};
            if (name == "wzr") return {"zr", 32, false, false, true};
            if (name == "xzr") return {"zr", 64, false, false, true};
            if (name.size() > 1 && std::isdigit(static_cast<unsigned char>(name[1]))) {
                const auto suffix = name.substr(1);
                switch (name[0]) {
                case 'w': return {'x' + suffix, 32};
                case 'x': return {name, 64};
                case 'b': return {'v' + suffix, 8, false, true};
                case 'h': return {'v' + suffix, 16, false, true};
                case 's': return {'v' + suffix, 32, false, true};
                case 'd': return {'v' + suffix, 64, false, true};
                case 'q':
                case 'v': return {'v' + suffix, 128};
                default: break;
                }
            }
            return {name, 64};
        }
        if (image_.architecture == Architecture::Arm32) {
            return {name, 32};
        }
        if (image_.architecture == Architecture::X86) {
            return {name, 32};
        }

        static const std::vector<std::pair<std::string, std::string>> aliases = {
            {"rax", "rax"}, {"rbx", "rbx"}, {"rcx", "rcx"}, {"rdx", "rdx"},
            {"rsi", "rsi"}, {"rdi", "rdi"}, {"rbp", "rbp"}, {"rsp", "rsp"}, {"rip", "rip"}
        };
        if (name == "ah" || name == "bh" || name == "ch" || name == "dh") {
            return {name == "ah" ? "rax" : name == "bh" ? "rbx" : name == "ch" ? "rcx" : "rdx", 8, true};
        }
        if (name.size() == 2 && name[1] == 'l' && (name[0] == 'a' || name[0] == 'b' || name[0] == 'c' || name[0] == 'd')) {
            return {name[0] == 'a' ? "rax" : name[0] == 'b' ? "rbx" : name[0] == 'c' ? "rcx" : "rdx", 8};
        }
        static const std::vector<std::pair<std::string, std::string>> wordAliases = {
            {"ax", "rax"}, {"bx", "rbx"}, {"cx", "rcx"}, {"dx", "rdx"},
            {"si", "rsi"}, {"di", "rdi"}, {"bp", "rbp"}, {"sp", "rsp"}
        };
        for (const auto& [word, full] : wordAliases) {
            if (name == word) return {full, 16};
        }
        for (const auto& [full, unused] : aliases) {
            (void)unused;
            if (name == full) return {full, 64};
            if (name == 'e' + full.substr(1)) return {full, 32};
        }
        if (name.size() >= 3 && name[0] == 'r' && std::isdigit(static_cast<unsigned char>(name[1]))) {
            const auto suffix = name.back();
            if (suffix == 'd') return {name.substr(0, name.size() - 1), 32};
            if (suffix == 'w') return {name.substr(0, name.size() - 1), 16};
            if (suffix == 'l') return {name.substr(0, name.size() - 1), 8};
            return {name, 64};
        }
        if (name == "eip") return {"rip", 32};
        if (name == "ip") return {"rip", 16};
        return {name, 64};
    }

    ScalarType registerType(const RegisterInfo& info) const {
        if (info.floatingPoint) return ScalarType::floatBits(info.bits);
        if (info.bits == 128) return ScalarType::vectorBits(128);
        return pointerType();
    }

    ScalarType operandType(const Operand& operand) const {
        if (operand.kind == OperandKind::Register) {
            const auto info = registerInfo(operand.reg);
            if (info.floatingPoint || info.zero || info.bits == 128) return registerType(info);
            return uintType(info.bits);
        }
        if (operand.kind == OperandKind::FloatingPoint) {
            return ScalarType::floatBits(operand.size ? operand.size * 8 : 64);
        }
        return operand.size ? uintType(operand.size * 8) : pointerType();
    }

    ExpressionPtr coerce(ExpressionPtr value, ScalarType type) {
        if (!value) return unknown(type);
        if (value->type.kind == type.kind && value->type.bits == type.bits) return value;
        return cast(std::move(value), type);
    }

    void trackRegisterView(const Statement& statement) {
        if (image_.architecture != Architecture::Arm64 || !currentInstruction_ ||
            statement.kind != Statement::Kind::Assign || !statement.destination ||
            statement.destination->kind != Expression::Kind::Register) {
            return;
        }
        for (const auto& operand : currentInstruction_->operands) {
            if (operand.kind != OperandKind::Register) continue;
            const auto info = registerInfo(operand.reg);
            if (info.canonical != statement.destination->name) continue;
            registerViews_[info.canonical] = info.floatingPoint || info.zero || info.bits == 128
                ? registerType(info)
                : info.bits < pointerBits_ ? uintType(info.bits) : pointerType();
        }
    }

    ExpressionPtr readRegister(const std::string& name) {
        const auto info = registerInfo(name);
        if (info.zero) return constant(0, uintType(info.bits));
        if (info.floatingPoint || info.bits == 128) return reg(info.canonical, registerType(info));

        auto value = reg(info.canonical, pointerType());
        if (image_.architecture == Architecture::Arm64) {
            const auto found = registerViews_.find(info.canonical);
            if (found != registerViews_.end()) value = coerce(std::move(value), found->second);
        }
        if (info.highByte) {
            value = binary(">>", value, constant(8, pointerType()), pointerType());
        }
        if (info.bits < pointerBits_ || info.highByte) {
            return coerce(std::move(value), uintType(info.bits));
        }
        return value;
    }

    Statement assignRegister(const std::string& name, ExpressionPtr value) {
        const auto info = registerInfo(name);
        Statement result;
        result.kind = Statement::Kind::Assign;
        result.destination = reg(info.canonical, registerType(info));
        if (info.highByte) {
            const auto mask = constant(0xFF00UL, pointerType());
            const auto preserved = binary("&", readRegister(info.canonical), unary("~", constant(mask->constant, pointerType()), pointerType()), pointerType());
            const auto shifted = binary("<<", cast(value, uintType(8)), constant(8, pointerType()), pointerType());
            result.value = binary("|", preserved, shifted, pointerType());
        } else if (info.floatingPoint || info.bits == 128) {
            result.value = coerce(std::move(value), registerType(info));
        } else if (info.bits < pointerBits_) {
            result.value = coerce(std::move(value), uintType(info.bits));
        } else {
            result.value = coerce(std::move(value), registerType(info));
        }
        return result;
    }

    ExpressionPtr addressOf(const Operand& operand) {
        ExpressionPtr address;
        if (!operand.memoryBase.empty()) {
            address = coerce(readRegister(operand.memoryBase), pointerType());
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
        return address ? address : constant(0, pointerType());
    }

    ExpressionPtr applyShift(ExpressionPtr value, const Shift& shift) {
        if (shift.value == 0) return value;
        const auto amount = constant(shift.value, pointerType());
        switch (shift.type) {
        case ARM64_SFT_LSL:
            return binary("<<", value, amount, value->type);
        case ARM64_SFT_LSR:
            return binary(">>", value, amount, value->type);
        case ARM64_SFT_ASR:
            return binary(">>", cast(value, intType(value->type.bits)), amount, value->type);
        case ARM64_SFT_ROR:
            return binary("|", binary(">>", value, amount, value->type), binary("<<", value, constant(value->type.bits - shift.value, pointerType()), value->type), value->type);
        default:
            return value;
        }
    }

    ExpressionPtr valueOf(const Operand& operand) {
        ExpressionPtr value;
        switch (operand.kind) {
        case OperandKind::Register:
            value = readRegister(operand.reg);
            break;
        case OperandKind::Immediate:
            value = constant(static_cast<uint64_t>(operand.immediate), operand.size ? uintType(operand.size * 8) : pointerType());
            break;
        case OperandKind::Memory:
            value = load(addressOf(operand), operand.size ? uintType(operand.size * 8) : pointerType());
            break;
        case OperandKind::FloatingPoint:
            value = constant(static_cast<uint64_t>(operand.floatingPoint), ScalarType::floatBits(operand.size ? operand.size * 8 : 64));
            break;
        }
        return applyShift(value, operand.shift);
    }

    ExpressionPtr conditionFromArm(uint32_t conditionCode) {
        if (!flagsLeft_ || !flagsRight_) return unknown(ScalarType::boolean());
        auto left = flagsLeft_;
        auto right = flagsRight_;
        switch (conditionCode) {
        case ARM64_CC_EQ: return binary("==", left, right, ScalarType::boolean());
        case ARM64_CC_NE: return binary("!=", left, right, ScalarType::boolean());
        case ARM64_CC_HS: return binary(">=", left, right, ScalarType::boolean());
        case ARM64_CC_LO: return binary("<", left, right, ScalarType::boolean());
        case ARM64_CC_MI: return binary("<", left, constant(0, left->type), ScalarType::boolean());
        case ARM64_CC_PL: return binary(">=", left, constant(0, left->type), ScalarType::boolean());
        case ARM64_CC_HI: return binary(">", left, right, ScalarType::boolean());
        case ARM64_CC_LS: return binary("<=", left, right, ScalarType::boolean());
        case ARM64_CC_GE: return binary(">=", cast(left, intType(left->type.bits)), cast(right, intType(right->type.bits)), ScalarType::boolean());
        case ARM64_CC_LT: return binary("<", cast(left, intType(left->type.bits)), cast(right, intType(right->type.bits)), ScalarType::boolean());
        case ARM64_CC_GT: return binary(">", cast(left, intType(left->type.bits)), cast(right, intType(right->type.bits)), ScalarType::boolean());
        case ARM64_CC_LE: return binary("<=", cast(left, intType(left->type.bits)), cast(right, intType(right->type.bits)), ScalarType::boolean());
        default: return unknown(ScalarType::boolean());
        }
    }

    ExpressionPtr conditionFromX86(uint32_t id) {
        if (!flagsLeft_ || !flagsRight_) return unknown(ScalarType::boolean());
        auto left = flagsLeft_;
        auto right = flagsRight_;
        auto signedLeft = cast(left, intType(left->type.bits));
        auto signedRight = cast(right, intType(right->type.bits));
        switch (id) {
        case X86_INS_JE: return binary("==", left, right, ScalarType::boolean());
        case X86_INS_JNE: return binary("!=", left, right, ScalarType::boolean());
        case X86_INS_JL: return binary("<", signedLeft, signedRight, ScalarType::boolean());
        case X86_INS_JLE: return binary("<=", signedLeft, signedRight, ScalarType::boolean());
        case X86_INS_JG: return binary(">", signedLeft, signedRight, ScalarType::boolean());
        case X86_INS_JGE: return binary(">=", signedLeft, signedRight, ScalarType::boolean());
        case X86_INS_JB: return binary("<", left, right, ScalarType::boolean());
        case X86_INS_JBE: return binary("<=", left, right, ScalarType::boolean());
        case X86_INS_JA: return binary(">", left, right, ScalarType::boolean());
        case X86_INS_JAE: return binary(">=", left, right, ScalarType::boolean());
        case X86_INS_JS: return binary("<", signedLeft, constant(0, signedLeft->type), ScalarType::boolean());
        case X86_INS_JNS: return binary(">=", signedLeft, constant(0, signedLeft->type), ScalarType::boolean());
        default: return unknown(ScalarType::boolean());
        }
    }

    ExpressionPtr directTarget(const Operand& operand) {
        return constant(static_cast<uint64_t>(operand.immediate), pointerType());
    }

    void addBranch(const NativeInstruction& instruction, ExpressionPtr condition = nullptr) {
        Statement statement;
        statement.address = instruction.address;
        statement.kind = condition ? Statement::Kind::ConditionalBranch : Statement::Kind::Branch;
        statement.condition = std::move(condition);
        const auto& target = instruction.operands.back();
        statement.target = target.kind == OperandKind::Immediate ? directTarget(target) : valueOf(target);
        add(std::move(statement));
    }

    void addCall(const NativeInstruction& instruction) {
        Statement statement;
        statement.address = instruction.address;
        statement.kind = Statement::Kind::Call;
        statement.destination = reg(image_.architecture == Architecture::Arm64 ? "x0" : image_.architecture == Architecture::Arm32 ? "r0" : "rax", pointerType());
        const auto& target = instruction.operands.back();
        statement.target = target.kind == OperandKind::Immediate ? directTarget(target) : valueOf(target);
        if (image_.architecture == Architecture::Arm64) {
            statement.arguments = {readRegister("x0"), readRegister("x1"), readRegister("x2"), readRegister("x3")};
        } else if (image_.architecture == Architecture::Arm32) {
            statement.arguments = {readRegister("r0"), readRegister("r1"), readRegister("r2"), readRegister("r3")};
        } else if (image_.architecture == Architecture::X64) {
            statement.arguments = {readRegister("rcx"), readRegister("rdx"), readRegister("r8"), readRegister("r9")};
        } else {
            statement.arguments = {readRegister("ecx"), readRegister("edx")};
        }
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
        if (image_.architecture == Architecture::Arm64) {
            return instruction.id == ARM64_INS_B || instruction.id == ARM64_INS_BR || instruction.id == ARM64_INS_CBZ || instruction.id == ARM64_INS_CBNZ || instruction.id == ARM64_INS_TBZ || instruction.id == ARM64_INS_TBNZ;
        }
        if (image_.architecture == Architecture::Arm32) {
            return instruction.id == ARM_INS_B || instruction.id == ARM_INS_BX || instruction.id == ARM_INS_CBZ || instruction.id == ARM_INS_CBNZ;
        }
        return instruction.id == X86_INS_JMP || (instruction.id >= X86_INS_JAE && instruction.id <= X86_INS_JNS) || instruction.id == X86_INS_JCXZ || instruction.id == X86_INS_JECXZ || instruction.id == X86_INS_JRCXZ;
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

    void lift(const NativeInstruction& instruction) {
        if (image_.architecture == Architecture::Arm64) {
            currentInstruction_ = &instruction;
            liftArm64(instruction);
            currentInstruction_ = nullptr;
        } else if (image_.architecture == Architecture::Arm32) {
            liftArm32(instruction);
        } else {
            liftX86(instruction);
        }
    }

    static bool isGenericMemoryInstruction(uint32_t id) {
        switch (id) {
        case ARM64_INS_LDR:
        case ARM64_INS_LDUR:
        case ARM64_INS_LDRB:
        case ARM64_INS_LDURB:
        case ARM64_INS_LDRH:
        case ARM64_INS_LDURH:
        case ARM64_INS_LDRSB:
        case ARM64_INS_LDURSB:
        case ARM64_INS_LDRSH:
        case ARM64_INS_LDURSH:
        case ARM64_INS_LDRSW:
        case ARM64_INS_LDURSW:
        case ARM64_INS_STR:
        case ARM64_INS_STUR:
        case ARM64_INS_STRB:
        case ARM64_INS_STURB:
        case ARM64_INS_STRH:
        case ARM64_INS_STURH:
        case ARM64_INS_LDP:
        case ARM64_INS_STP:
            return true;
        default:
            return false;
        }
    }

    static bool hasVectorMemoryRegister(const NativeInstruction& instruction) {
        return std::any_of(instruction.operands.begin(), instruction.operands.end(), [](const Operand& operand) {
            if (operand.kind != OperandKind::Register || operand.reg.size() < 2 ||
                !std::isdigit(static_cast<unsigned char>(operand.reg[1]))) {
                return false;
            }
            switch (operand.reg[0]) {
            case 'b':
            case 'h':
            case 's':
            case 'd':
            case 'q':
            case 'v':
                return true;
            default:
                return false;
            }
        });
    }

    static bool requiresExtendedArm64Semantics(uint32_t id) {
        switch (id) {
        case ARM64_INS_CMP:
        case ARM64_INS_CMN:
        case ARM64_INS_TST:
        case ARM64_INS_B:
        case ARM64_INS_CSEL:
        case ARM64_INS_CSINC:
        case ARM64_INS_CSINV:
        case ARM64_INS_CSNEG:
        case ARM64_INS_CSET:
        case ARM64_INS_CSETM:
        case ARM64_INS_FSQRT:
        case ARM64_INS_MOVI:
        case ARM64_INS_CINC:
        case ARM64_INS_CNEG:
        case ARM64_INS_SMULL:
        case ARM64_INS_SMULH:
        case ARM64_INS_UMULL:
        case ARM64_INS_UMULH:
        case ARM64_INS_FCVTZS:
        case ARM64_INS_FCVTZU:
        case ARM64_INS_FMAX:
        case ARM64_INS_FMIN:
        case ARM64_INS_FABS:
        case ARM64_INS_FNMUL:
        case ARM64_INS_FCSEL:
        case ARM64_INS_FCCMP:
        case ARM64_INS_CCMP:
        case ARM64_INS_DUP:
        case ARM64_INS_EXT:
        case ARM64_INS_LD1R:
            return true;
        default:
            return false;
        }
    }

    void liftExtendedArm64(const NativeInstruction& instruction) {
        auto& statements = currentBlock().statements;
        const size_t firstNewStatement = statements.size();
        const bool lifted = arm64Extended_.lift(instruction, statements);
        for (size_t i = firstNewStatement; i < statements.size(); ++i) {
            trackRegisterView(statements[i]);
            if (statements[i].kind == Statement::Kind::Return || statements[i].kind == Statement::Kind::Branch) {
                terminated_ = true;
            }
        }
        if (!lifted) unsupported(instruction);
    }

    void liftArm64(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        if (requiresExtendedArm64Semantics(instruction.id) ||
            (isGenericMemoryInstruction(instruction.id) && hasVectorMemoryRegister(instruction))) {
            liftExtendedArm64(instruction);
            return;
        }
        switch (instruction.id) {
        case ARM64_INS_NOP:
            return;
        case ARM64_INS_MOV:
        case ARM64_INS_MOVZ:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, valueOf(ops[1])));
            return;
        case ARM64_INS_MOVN:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, unary("~", valueOf(ops[1]), valueOf(ops[1])->type)));
            return;
        case ARM64_INS_MOVK: {
            if (ops.size() < 2) return;
            const auto shift = ops[0].shift.value;
            const auto mask = 0xFFFFUL << shift;
            const auto oldValue = binary("&", readRegister(ops[0].reg), unary("~", constant(mask, pointerType()), pointerType()), pointerType());
            const auto newValue = binary("<<", valueOf(ops[1]), constant(shift, pointerType()), pointerType());
            add(assignRegister(ops[0].reg, binary("|", oldValue, newValue, pointerType())));
            return;
        }
        case ARM64_INS_ADD:
        case ARM64_INS_SUB:
        case ARM64_INS_AND:
        case ARM64_INS_ORR:
        case ARM64_INS_EOR:
        case ARM64_INS_LSL:
        case ARM64_INS_LSR:
        case ARM64_INS_ASR:
        case ARM64_INS_MUL:
        case ARM64_INS_UDIV: {
            if (ops.size() < 3) return;
            std::string op;
            switch (instruction.id) {
            case ARM64_INS_ADD: op = "+"; break;
            case ARM64_INS_SUB: op = "-"; break;
            case ARM64_INS_AND: op = "&"; break;
            case ARM64_INS_ORR: op = "|"; break;
            case ARM64_INS_EOR: op = "^"; break;
            case ARM64_INS_LSL: op = "<<"; break;
            case ARM64_INS_LSR:
            case ARM64_INS_ASR: op = ">>"; break;
            case ARM64_INS_MUL: op = "*"; break;
            default: op = "/"; break;
            }
            auto left = valueOf(ops[1]);
            auto right = valueOf(ops[2]);
            if (instruction.id == ARM64_INS_ASR) left = cast(left, intType(left->type.bits));
            add(assignRegister(ops[0].reg, binary(op, left, right, left->type)));
            return;
        }
        case ARM64_INS_MADD:
            if (ops.size() >= 4) add(assignRegister(ops[0].reg, binary("+", binary("*", valueOf(ops[1]), valueOf(ops[2]), valueOf(ops[1])->type), valueOf(ops[3]), valueOf(ops[1])->type)));
            return;
        case ARM64_INS_MSUB:
            if (ops.size() >= 4) add(assignRegister(ops[0].reg, binary("-", valueOf(ops[3]), binary("*", valueOf(ops[1]), valueOf(ops[2]), valueOf(ops[1])->type), valueOf(ops[1])->type)));
            return;
        case ARM64_INS_NEG:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, unary("-", valueOf(ops[1]), valueOf(ops[1])->type)));
            return;
        case ARM64_INS_MVN:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, unary("~", valueOf(ops[1]), valueOf(ops[1])->type)));
            return;
        case ARM64_INS_ADR:
        case ARM64_INS_ADRP:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, directTarget(ops[1])));
            return;
        case ARM64_INS_SXTW:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, cast(valueOf(ops[1]), intType(32))));
            return;
        case ARM64_INS_UXTW:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, cast(valueOf(ops[1]), uintType(32))));
            return;
        case ARM64_INS_LDR:
        case ARM64_INS_LDUR:
        case ARM64_INS_LDRB:
        case ARM64_INS_LDURB:
        case ARM64_INS_LDRH:
        case ARM64_INS_LDURH:
        case ARM64_INS_LDRSB:
        case ARM64_INS_LDURSB:
        case ARM64_INS_LDRSH:
        case ARM64_INS_LDURSH:
        case ARM64_INS_LDRSW:
        case ARM64_INS_LDURSW: {
            if (ops.size() < 2) return;
            auto type = operandType(ops[0]);
            switch (instruction.id) {
            case ARM64_INS_LDRB:
            case ARM64_INS_LDURB: type = uintType(8); break;
            case ARM64_INS_LDRH:
            case ARM64_INS_LDURH: type = uintType(16); break;
            case ARM64_INS_LDRSB:
            case ARM64_INS_LDURSB: type = intType(8); break;
            case ARM64_INS_LDRSH:
            case ARM64_INS_LDURSH: type = intType(16); break;
            case ARM64_INS_LDRSW:
            case ARM64_INS_LDURSW: type = intType(32); break;
            default: break;
            }
            ExpressionPtr value = load(addressOf(ops[1]), type);
            const auto destinationBits = operandType(ops[0]).bits;
            if (type.kind == ScalarKind::SignedInteger && destinationBits > type.bits) {
                value = cast(value, intType(destinationBits));
            }
            add(assignRegister(ops[0].reg, value));
            return;
        }
        case ARM64_INS_STR:
        case ARM64_INS_STUR:
        case ARM64_INS_STRB:
        case ARM64_INS_STURB:
        case ARM64_INS_STRH:
        case ARM64_INS_STURH: {
            if (ops.size() < 2) return;
            auto type = operandType(ops[0]);
            switch (instruction.id) {
            case ARM64_INS_STRB:
            case ARM64_INS_STURB: type = uintType(8); break;
            case ARM64_INS_STRH:
            case ARM64_INS_STURH: type = uintType(16); break;
            default: break;
            }
            Statement statement;
            statement.address = instruction.address;
            statement.kind = Statement::Kind::Store;
            statement.destination = addressOf(ops[1]);
            statement.value = coerce(valueOf(ops[0]), type);
            add(std::move(statement));
            return;
        }
        case ARM64_INS_LDP: {
            if (ops.size() < 3) return;
            const auto firstType = operandType(ops[0]);
            const auto secondType = operandType(ops[1]);
            const auto base = addressOf(ops[2]);
            add(assignRegister(ops[0].reg, load(base, firstType)));
            const auto secondAddress = binary("+", base, constant(firstType.bits / 8, pointerType()), pointerType());
            add(assignRegister(ops[1].reg, load(secondAddress, secondType)));
            return;
        }
        case ARM64_INS_STP: {
            if (ops.size() < 3) return;
            uint64_t offset = 0;
            const auto base = addressOf(ops[2]);
            for (size_t i = 0; i < 2; ++i) {
                const auto type = operandType(ops[i]);
                Statement statement;
                statement.address = instruction.address;
                statement.kind = Statement::Kind::Store;
                statement.destination = binary("+", base, constant(offset, pointerType()), pointerType());
                statement.value = coerce(valueOf(ops[i]), type);
                add(std::move(statement));
                offset += type.bits / 8;
            }
            return;
        }
        case ARM64_INS_BL:
        case ARM64_INS_BLR:
            addCall(instruction);
            return;
        case ARM64_INS_B: {
            const bool unconditional = instruction.conditionCode == ARM64_CC_INVALID ||
                instruction.conditionCode == ARM64_CC_AL || instruction.conditionCode == ARM64_CC_NV;
            addBranch(instruction, unconditional ? nullptr : conditionFromArm(instruction.conditionCode));
            return;
        }
        case ARM64_INS_BR:
            if (!ops.empty() && (ops[0].reg == "x30" || ops[0].reg == "lr")) {
                Statement statement;
                statement.address = instruction.address;
                statement.kind = Statement::Kind::Return;
                statement.value = readRegister("x0");
                add(std::move(statement));
            } else {
                addBranch(instruction);
            }
            return;
        case ARM64_INS_CBZ:
        case ARM64_INS_CBNZ:
            if (ops.size() >= 2) addBranch(instruction, binary(instruction.id == ARM64_INS_CBZ ? "==" : "!=", valueOf(ops[0]), constant(0, valueOf(ops[0])->type), ScalarType::boolean()));
            return;
        case ARM64_INS_TBZ:
        case ARM64_INS_TBNZ:
            if (ops.size() >= 3) addBranch(instruction, binary(instruction.id == ARM64_INS_TBZ ? "==" : "!=", binary("&", valueOf(ops[0]), binary("<<", constant(1, valueOf(ops[0])->type), valueOf(ops[1]), valueOf(ops[0])->type), valueOf(ops[0])->type), constant(0, valueOf(ops[0])->type), ScalarType::boolean()));
            return;
        case ARM64_INS_CMP:
        case ARM64_INS_CMN:
            if (ops.size() >= 2) {
                flagsLeft_ = valueOf(ops[0]);
                flagsRight_ = valueOf(ops[1]);
            }
            return;
        case ARM64_INS_TST:
            if (ops.size() >= 2) {
                flagsLeft_ = binary("&", valueOf(ops[0]), valueOf(ops[1]), valueOf(ops[0])->type);
                flagsRight_ = constant(0, flagsLeft_->type);
            }
            return;
        case ARM64_INS_CSEL:
            if (ops.size() >= 3) add(assignRegister(ops[0].reg, select(conditionFromArm(instruction.conditionCode), valueOf(ops[1]), valueOf(ops[2]), valueOf(ops[1])->type)));
            return;
        case ARM64_INS_CSINC:
            if (ops.size() >= 3) add(assignRegister(ops[0].reg, select(conditionFromArm(instruction.conditionCode), valueOf(ops[1]), binary("+", valueOf(ops[2]), constant(1, valueOf(ops[2])->type), valueOf(ops[2])->type), valueOf(ops[1])->type)));
            return;
        case ARM64_INS_CSINV:
            if (ops.size() >= 3) add(assignRegister(ops[0].reg, select(conditionFromArm(instruction.conditionCode), valueOf(ops[1]), unary("~", valueOf(ops[2]), valueOf(ops[2])->type), valueOf(ops[1])->type)));
            return;
        case ARM64_INS_CSNEG:
            if (ops.size() >= 3) add(assignRegister(ops[0].reg, select(conditionFromArm(instruction.conditionCode), valueOf(ops[1]), unary("-", valueOf(ops[2]), valueOf(ops[2])->type), valueOf(ops[1])->type)));
            return;
        case ARM64_INS_CSET:
            if (!ops.empty()) add(assignRegister(ops[0].reg, select(conditionFromArm(instruction.conditionCode), constant(1, pointerType()), constant(0, pointerType()), pointerType())));
            return;
        case ARM64_INS_CSETM:
            if (!ops.empty()) add(assignRegister(ops[0].reg, select(conditionFromArm(instruction.conditionCode), unary("~", constant(0, pointerType()), pointerType()), constant(0, pointerType()), pointerType())));
            return;
        case ARM64_INS_RET: {
            Statement statement;
            statement.address = instruction.address;
            statement.kind = Statement::Kind::Return;
            statement.value = readRegister("x0");
            add(std::move(statement));
            return;
        }
        default:
            liftExtendedArm64(instruction);
            return;
        }
    }

    void liftArm32(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        switch (instruction.id) {
        case ARM_INS_MOV:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, valueOf(ops[1])));
            return;
        case ARM_INS_ADD:
        case ARM_INS_SUB:
        case ARM_INS_AND:
        case ARM_INS_ORR:
        case ARM_INS_EOR:
            if (ops.size() >= 3) {
                std::string op = instruction.id == ARM_INS_ADD ? "+" : instruction.id == ARM_INS_SUB ? "-" : instruction.id == ARM_INS_AND ? "&" : instruction.id == ARM_INS_ORR ? "|" : "^";
                add(assignRegister(ops[0].reg, binary(op, valueOf(ops[1]), valueOf(ops[2]), valueOf(ops[1])->type)));
            }
            return;
        case ARM_INS_LDR:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, valueOf(ops[1])));
            return;
        case ARM_INS_STR: {
            if (ops.size() < 2) return;
            Statement statement;
            statement.address = instruction.address;
            statement.kind = Statement::Kind::Store;
            statement.destination = addressOf(ops[1]);
            statement.value = valueOf(ops[0]);
            add(std::move(statement));
            return;
        }
        case ARM_INS_CMP:
            if (ops.size() >= 2) {
                flagsLeft_ = valueOf(ops[0]);
                flagsRight_ = valueOf(ops[1]);
            }
            return;
        case ARM_INS_B:
            addBranch(instruction, instruction.conditionCode == ARM_CC_AL ? nullptr : conditionFromArm(instruction.conditionCode));
            return;
        case ARM_INS_BX:
            if (!ops.empty() && ops[0].reg == "lr") {
                Statement statement;
                statement.address = instruction.address;
                statement.kind = Statement::Kind::Return;
                statement.value = readRegister("r0");
                add(std::move(statement));
            } else {
                addBranch(instruction);
            }
            return;
        case ARM_INS_BL:
        case ARM_INS_BLX:
            addCall(instruction);
            return;
        default:
            unsupported(instruction);
            return;
        }
    }

    void liftX86(const NativeInstruction& instruction) {
        const auto& ops = instruction.operands;
        switch (instruction.id) {
        case X86_INS_NOP:
        case X86_INS_ENDBR32:
        case X86_INS_ENDBR64:
        case X86_INS_CQO:
        case X86_INS_CDQ:
            return;
        case X86_INS_MOV:
        case X86_INS_MOVABS:
        case X86_INS_MOVQ:
        case X86_INS_MOVD:
        case X86_INS_MOVSS:
        case X86_INS_MOVSD:
        case X86_INS_MOVZX:
        case X86_INS_MOVSX:
            if (ops.size() >= 2) {
                auto value = valueOf(ops[1]);
                if (instruction.id == X86_INS_MOVSX) value = cast(value, intType(value->type.bits));
                if (ops[0].kind == OperandKind::Register) {
                    add(assignRegister(ops[0].reg, value));
                } else {
                    Statement statement;
                    statement.address = instruction.address;
                    statement.kind = Statement::Kind::Store;
                    statement.destination = addressOf(ops[0]);
                    statement.value = std::move(value);
                    add(std::move(statement));
                }
            }
            return;
        case X86_INS_LEA:
            if (ops.size() >= 2) add(assignRegister(ops[0].reg, addressOf(ops[1])));
            return;
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_AND:
        case X86_INS_OR:
        case X86_INS_XOR:
        case X86_INS_PXOR:
        case X86_INS_IMUL:
        case X86_INS_IDIV:
        case X86_INS_DIV:
        case X86_INS_SHL:
        case X86_INS_SHR:
        case X86_INS_SAR:
        case X86_INS_ROL:
        case X86_INS_ROR: {
            if (ops.empty()) return;
            if ((instruction.id == X86_INS_XOR || instruction.id == X86_INS_PXOR) && ops.size() >= 2 && ops[0].kind == OperandKind::Register && ops[1].kind == OperandKind::Register && ops[0].reg == ops[1].reg) {
                add(assignRegister(ops[0].reg, constant(0, pointerType())));
                flagsLeft_ = constant(0, pointerType());
                flagsRight_ = constant(0, pointerType());
                return;
            }
            if (ops.size() < 2) return;
            std::string op;
            switch (instruction.id) {
            case X86_INS_ADD: op = "+"; break;
            case X86_INS_SUB: op = "-"; break;
            case X86_INS_AND: op = "&"; break;
            case X86_INS_OR: op = "|"; break;
            case X86_INS_XOR:
            case X86_INS_PXOR: op = "^"; break;
            case X86_INS_IMUL: op = "*"; break;
            case X86_INS_IDIV:
            case X86_INS_DIV: op = "/"; break;
            case X86_INS_SHL: op = "<<"; break;
            case X86_INS_SHR:
            case X86_INS_SAR: op = ">>"; break;
            default: op = "rol";
            }
            ExpressionPtr value;
            if (instruction.id == X86_INS_ROL || instruction.id == X86_INS_ROR) {
                const auto bits = ops[0].size ? ops[0].size * 8 : pointerBits_;
                const auto source = valueOf(ops[0]);
                const auto amount = valueOf(ops[1]);
                const auto inverseAmount = constant(bits - ops[1].immediate, pointerType());
                const auto forward = instruction.id == X86_INS_ROL
                    ? binary("<<", source, amount, uintType(bits))
                    : binary(">>", source, amount, uintType(bits));
                const auto inverse = instruction.id == X86_INS_ROL
                    ? binary(">>", source, inverseAmount, uintType(bits))
                    : binary("<<", source, inverseAmount, uintType(bits));
                value = binary("|", forward, inverse, uintType(bits));
            } else {
                auto left = valueOf(ops[0]);
                auto right = valueOf(ops[1]);
                if (instruction.id == X86_INS_SAR) left = cast(left, intType(left->type.bits));
                value = binary(op, left, right, left->type);
            }
            if (ops[0].kind == OperandKind::Register) {
                add(assignRegister(ops[0].reg, value));
            } else {
                Statement statement;
                statement.address = instruction.address;
                statement.kind = Statement::Kind::Store;
                statement.destination = addressOf(ops[0]);
                statement.value = std::move(value);
                add(std::move(statement));
            }
            if (instruction.id == X86_INS_ADD || instruction.id == X86_INS_SUB) {
                flagsLeft_ = valueOf(ops[0]);
                flagsRight_ = valueOf(ops[1]);
            }
            return;
        }
        case X86_INS_INC:
        case X86_INS_DEC:
            if (!ops.empty()) add(assignRegister(ops[0].reg, binary(instruction.id == X86_INS_INC ? "+" : "-", valueOf(ops[0]), constant(1, valueOf(ops[0])->type), valueOf(ops[0])->type)));
            return;
        case X86_INS_NEG:
            if (!ops.empty()) add(assignRegister(ops[0].reg, unary("-", valueOf(ops[0]), valueOf(ops[0])->type)));
            return;
        case X86_INS_NOT:
            if (!ops.empty()) add(assignRegister(ops[0].reg, unary("~", valueOf(ops[0]), valueOf(ops[0])->type)));
            return;
        case X86_INS_PUSH: {
            if (ops.empty()) return;
            const auto stack = image_.architecture == Architecture::X64 ? "rsp" : "esp";
            add(assignRegister(stack, binary("-", readRegister(stack), constant(pointerBits_ / 8, pointerType()), pointerType())));
            Statement statement;
            statement.address = instruction.address;
            statement.kind = Statement::Kind::Store;
            statement.destination = readRegister(stack);
            statement.value = valueOf(ops[0]);
            add(std::move(statement));
            return;
        }
        case X86_INS_POP: {
            if (ops.empty()) return;
            const auto stack = image_.architecture == Architecture::X64 ? "rsp" : "esp";
            add(assignRegister(ops[0].reg, load(readRegister(stack), pointerType())));
            add(assignRegister(stack, binary("+", readRegister(stack), constant(pointerBits_ / 8, pointerType()), pointerType())));
            return;
        }
        case X86_INS_LEAVE: {
            const auto stack = image_.architecture == Architecture::X64 ? "rsp" : "esp";
            const auto frame = image_.architecture == Architecture::X64 ? "rbp" : "ebp";
            add(assignRegister(stack, readRegister(frame)));
            add(assignRegister(frame, load(readRegister(stack), pointerType())));
            add(assignRegister(stack, binary("+", readRegister(stack), constant(pointerBits_ / 8, pointerType()), pointerType())));
            return;
        }
        case X86_INS_CALL:
            addCall(instruction);
            return;
        case X86_INS_JMP:
            addBranch(instruction);
            return;
        case X86_INS_JE:
        case X86_INS_JNE:
        case X86_INS_JL:
        case X86_INS_JLE:
        case X86_INS_JG:
        case X86_INS_JGE:
        case X86_INS_JB:
        case X86_INS_JBE:
        case X86_INS_JA:
        case X86_INS_JAE:
        case X86_INS_JS:
        case X86_INS_JNS:
            addBranch(instruction, conditionFromX86(instruction.id));
            return;
        case X86_INS_CMP:
            if (ops.size() >= 2) {
                flagsLeft_ = valueOf(ops[0]);
                flagsRight_ = valueOf(ops[1]);
            }
            return;
        case X86_INS_TEST:
            if (ops.size() >= 2) {
                flagsLeft_ = binary("&", valueOf(ops[0]), valueOf(ops[1]), valueOf(ops[0])->type);
                flagsRight_ = constant(0, flagsLeft_->type);
            }
            return;
        case X86_INS_SETA:
        case X86_INS_SETAE:
        case X86_INS_SETB:
        case X86_INS_SETBE:
        case X86_INS_SETE:
        case X86_INS_SETG:
        case X86_INS_SETGE:
        case X86_INS_SETL:
        case X86_INS_SETLE:
        case X86_INS_SETNE:
        case X86_INS_SETS:
        case X86_INS_SETNS: {
            if (ops.empty()) return;
            const auto conditionId = instruction.id == X86_INS_SETA ? X86_INS_JA : instruction.id == X86_INS_SETAE ? X86_INS_JAE : instruction.id == X86_INS_SETB ? X86_INS_JB : instruction.id == X86_INS_SETBE ? X86_INS_JBE : instruction.id == X86_INS_SETE ? X86_INS_JE : instruction.id == X86_INS_SETG ? X86_INS_JG : instruction.id == X86_INS_SETGE ? X86_INS_JGE : instruction.id == X86_INS_SETL ? X86_INS_JL : instruction.id == X86_INS_SETLE ? X86_INS_JLE : instruction.id == X86_INS_SETNE ? X86_INS_JNE : instruction.id == X86_INS_SETS ? X86_INS_JS : X86_INS_JNS;
            add(assignRegister(ops[0].reg, select(conditionFromX86(conditionId), constant(1, uintType(8)), constant(0, uintType(8)), uintType(8))));
            return;
        }
        case X86_INS_CMOVA:
        case X86_INS_CMOVAE:
        case X86_INS_CMOVB:
        case X86_INS_CMOVBE:
        case X86_INS_CMOVE:
        case X86_INS_CMOVG:
        case X86_INS_CMOVGE:
        case X86_INS_CMOVL:
        case X86_INS_CMOVLE:
        case X86_INS_CMOVNE:
        case X86_INS_CMOVS:
        case X86_INS_CMOVNS: {
            if (ops.size() < 2) return;
            const auto conditionId = instruction.id == X86_INS_CMOVA ? X86_INS_JA : instruction.id == X86_INS_CMOVAE ? X86_INS_JAE : instruction.id == X86_INS_CMOVB ? X86_INS_JB : instruction.id == X86_INS_CMOVBE ? X86_INS_JBE : instruction.id == X86_INS_CMOVE ? X86_INS_JE : instruction.id == X86_INS_CMOVG ? X86_INS_JG : instruction.id == X86_INS_CMOVGE ? X86_INS_JGE : instruction.id == X86_INS_CMOVL ? X86_INS_JL : instruction.id == X86_INS_CMOVLE ? X86_INS_JLE : instruction.id == X86_INS_CMOVNE ? X86_INS_JNE : instruction.id == X86_INS_CMOVS ? X86_INS_JS : X86_INS_JNS;
            add(assignRegister(ops[0].reg, select(conditionFromX86(conditionId), valueOf(ops[1]), valueOf(ops[0]), valueOf(ops[0])->type)));
            return;
        }
        case X86_INS_RET: {
            Statement statement;
            statement.address = instruction.address;
            statement.kind = Statement::Kind::Return;
            statement.value = readRegister("rax");
            add(std::move(statement));
            return;
        }
        default:
            unsupported(instruction);
            return;
        }
    }
};

RecoveryDiagnosticKind recoveryDiagnosticKind(flow::DecodeDiagnosticKind kind) {
    switch (kind) {
    case flow::DecodeDiagnosticKind::InvalidImage:
        return RecoveryDiagnosticKind::InvalidImage;
    case flow::DecodeDiagnosticKind::OutsideExecutableSection:
        return RecoveryDiagnosticKind::OutsideExecutableSection;
    case flow::DecodeDiagnosticKind::DecodeFailed:
        return RecoveryDiagnosticKind::DecodeFailed;
    case flow::DecodeDiagnosticKind::UnresolvedTarget:
        return RecoveryDiagnosticKind::UnresolvedTarget;
    case flow::DecodeDiagnosticKind::IndirectTarget:
        return RecoveryDiagnosticKind::IndirectTarget;
    case flow::DecodeDiagnosticKind::OverlappingStart:
        return RecoveryDiagnosticKind::OverlappingStart;
    case flow::DecodeDiagnosticKind::InstructionBudgetExceeded:
        return RecoveryDiagnosticKind::InstructionBudgetExceeded;
    }
    return RecoveryDiagnosticKind::InvalidImage;
}

} // namespace

RecoveredFunction Recovery::recover(const FunctionImage& image) const {
    return recoverWithDiagnostics(image).function;
}

RecoveredFunction Recovery::recover(
    const FunctionImage& image,
    const std::vector<Section>& sections) const {
    return recoverWithDiagnostics(image, sections).function;
}

RecoveryOutcome Recovery::recoverWithDiagnostics(
    const FunctionImage& image,
    const std::vector<Section>& sections) const {
    if (image.code == nullptr && image.size != 0) {
        throw std::invalid_argument("Code pointer is null");
    }

    auto decoded = flow::RecursiveDecoder{}.decode(image, sections);
    RecoveryOutcome report;
    report.diagnostics.reserve(decoded.diagnostics.size());
    for (const auto& diagnostic : decoded.diagnostics) {
        report.diagnostics.push_back({recoveryDiagnosticKind(diagnostic.kind), diagnostic.address, diagnostic.target});
    }

    auto instructions = std::move(decoded.instructions);
    const auto nativeInstructions = instructions;
    if (image.architecture == Architecture::Arm32) {
        report.function = Arm32Lifter(image).run(std::move(instructions));
    } else if (image.architecture == Architecture::X86 || image.architecture == Architecture::X64) {
        report.function = X86Lifter(image).run(std::move(instructions));
    } else {
        report.function = Lifter(image).run(std::move(instructions));
    }
    report.exceptionAnalysis = flow::ExceptionRegions{}.analyze(report.function, nativeInstructions);
    report.function.exceptionRegions = report.exceptionAnalysis.regions;
    report.function = flow::SSA{}.transform(report.function);
    return report;
}

} // namespace il2cpprec
