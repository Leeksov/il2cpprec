#pragma once

#include <cstdint>
#include <vector>

#include <il2cpprec/IR.hpp>

namespace il2cpprec {

class Arm64Lifter {
public:
    bool lift(const NativeInstruction& instruction, std::vector<Statement>& statements);

    void setCompareOperands(ExpressionPtr left, ExpressionPtr right, bool floatingPoint = false);
    ExpressionPtr condition(uint32_t conditionCode) const;

    const ExpressionPtr& compareLeft() const { return flagsLeft_; }
    const ExpressionPtr& compareRight() const { return flagsRight_; }
    bool compareIsFloatingPoint() const { return floatingPointFlags_; }

private:
    struct RegisterInfo;
    enum class FlagsKind {
        None,
        Subtract,
        Add,
        Logical
    };

    std::vector<Statement>* statements_ = nullptr;
    uint64_t instructionAddress_ = 0;
    uint64_t instructionSize_ = 0;
    uint64_t previousInstructionAddress_ = 0;
    uint16_t previousInstructionSize_ = 0;
    bool hasPreviousInstruction_ = false;
    ExpressionPtr flagsLeft_;
    ExpressionPtr flagsRight_;
    ExpressionPtr flagsResult_;
    FlagsKind flagsKind_ = FlagsKind::None;
    bool floatingPointFlags_ = false;
    ExpressionPtr conditionalCondition_;
    uint8_t conditionalNzcv_ = 0;

    static ScalarType pointerType();
    static ScalarType uintType(uint16_t bits);
    static ScalarType intType(uint16_t bits);
    static ScalarType floatType(uint16_t bits);

    RegisterInfo registerInfo(const std::string& name) const;
    ExpressionPtr rawVector(const RegisterInfo& info) const;
    ExpressionPtr rawToFloat(ExpressionPtr value, uint16_t bits) const;
    ExpressionPtr floatToRaw(ExpressionPtr value, uint16_t bits) const;
    ExpressionPtr readRegister(const std::string& name) const;
    Statement assignRegister(const Operand& destination, ExpressionPtr value) const;
    bool addAssignment(const Operand& destination, ExpressionPtr value);
    bool addVectorAssignment(const Operand& destination, ExpressionPtr value);
    ExpressionPtr replicateLane(ExpressionPtr value, uint16_t bits, uint16_t laneCount) const;
    ExpressionPtr unsignedMultiplyHigh(ExpressionPtr left, ExpressionPtr right) const;

    ScalarType operandType(const Operand& operand, ScalarType fallback = {}) const;
    ExpressionPtr valueOf(const Operand& operand, ScalarType fallback = {}) const;
    ExpressionPtr addressOf(const Operand& operand) const;
    ExpressionPtr applyShift(ExpressionPtr value, const Shift& shift) const;

    void add(Statement statement);
    void addStore(ExpressionPtr address, ExpressionPtr value);
    void addUnsupported(const NativeInstruction& instruction);
    ExpressionPtr saveTemporary(const char* role, ExpressionPtr value);
    void addWriteback(const Operand& memory, const Operand& offset);
    void addInstructionWriteback(const NativeInstruction& instruction, size_t memoryIndex, size_t offsetIndex, ExpressionPtr savedAddress = nullptr);
    void addBranch(const NativeInstruction& instruction, ExpressionPtr condition = nullptr);
    void addCall(const NativeInstruction& instruction);

    ExpressionPtr integerCondition(uint32_t conditionCode) const;
    ExpressionPtr floatingCondition(uint32_t conditionCode) const;
    ExpressionPtr conditionFromNzcv(uint32_t conditionCode) const;
    bool conditionAvailable(uint32_t conditionCode) const;
    void invalidateFlags();
    void setAddCompare(ExpressionPtr left, ExpressionPtr right);
    void setLogicalCompare(ExpressionPtr result);
    void setConditionalCompare(ExpressionPtr left, ExpressionPtr right, uint32_t conditionCode, uint8_t nzcv, bool addition = false);

    bool liftMove(const NativeInstruction& instruction);
    bool liftArithmetic(const NativeInstruction& instruction);
    bool liftShift(const NativeInstruction& instruction);
    bool liftBitfield(const NativeInstruction& instruction);
    bool liftExtend(const NativeInstruction& instruction);
    bool liftFloatingPoint(const NativeInstruction& instruction);
    bool liftConditional(const NativeInstruction& instruction);
    bool liftLoadStore(const NativeInstruction& instruction);
    bool liftPair(const NativeInstruction& instruction);
    bool liftControlFlow(const NativeInstruction& instruction);
};

} // namespace il2cpprec
