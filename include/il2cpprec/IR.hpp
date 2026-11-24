#pragma once

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <il2cpprec/Disassembler.hpp>

namespace il2cpprec {

enum class ScalarKind {
    Unknown,
    Boolean,
    UnsignedInteger,
    SignedInteger,
    FloatingPoint,
    Pointer,
    Vector
};

struct ScalarType {
    ScalarKind kind = ScalarKind::Unknown;
    uint16_t bits = 0;

    static ScalarType unknown();
    static ScalarType boolean();
    static ScalarType uintBits(uint16_t bits);
    static ScalarType intBits(uint16_t bits);
    static ScalarType floatBits(uint16_t bits);
    static ScalarType pointer(uint16_t bits);
    static ScalarType vectorBits(uint16_t bits);
};

struct Expression;
using ExpressionPtr = std::shared_ptr<Expression>;

struct Expression {
    enum class Kind {
        Unknown,
        Constant,
        Register,
        Unary,
        Binary,
        Load,
        Cast,
        Select
    };

    Kind kind = Kind::Unknown;
    ScalarType type;
    uint64_t constant = 0;
    std::string name;
    std::string op;
    std::vector<ExpressionPtr> arguments;
};

ExpressionPtr constant(uint64_t value, ScalarType type);
ExpressionPtr reg(std::string name, ScalarType type);
ExpressionPtr unary(std::string op, ExpressionPtr value, ScalarType type);
ExpressionPtr binary(std::string op, ExpressionPtr left, ExpressionPtr right, ScalarType type);
ExpressionPtr load(ExpressionPtr address, ScalarType type);
ExpressionPtr cast(ExpressionPtr value, ScalarType type);
ExpressionPtr select(ExpressionPtr condition, ExpressionPtr ifTrue, ExpressionPtr ifFalse, ScalarType type);
ExpressionPtr unknown(ScalarType type);

struct Statement {
    enum class Kind {
        Assign,
        Store,
        Call,
        Branch,
        ConditionalBranch,
        Return
    };

    Kind kind = Kind::Assign;
    uint64_t address = 0;
    ExpressionPtr destination;
    ExpressionPtr value;
    ExpressionPtr condition;
    ExpressionPtr target;
    std::vector<ExpressionPtr> arguments;
};

struct BasicBlock {
    uint64_t address = 0;
    std::vector<Statement> statements;
};

enum class ExceptionRegionKind {
    Catch,
    Finally,
    Fault,
    Filter
};

struct ExceptionRegion {
    using Kind = ExceptionRegionKind;

    uint64_t tryBegin = 0;
    uint64_t tryEnd = 0;
    uint64_t handler = 0;
    uint64_t leaveTarget = 0;
    Kind kind = Kind::Catch;
};

struct CSharpDiagnostic {
    uint64_t address = 0;
    std::string message;
};

struct CSharpEmissionResult {
    std::string source;
    std::vector<CSharpDiagnostic> diagnostics;
    bool partial = false;
};

struct CSharpBodyOptions {
    bool voidReturn = false;
    bool declareNativeParameters = true;
    // Native argument registers initialized by the caller of emitCSharpBody.
    std::set<std::string> externalNativeRegisters;
    // Optional managed enum type for a verified integral native return.
    std::string managedReturnCast;
    // Optional managed reference type for a handler-dependent native pointer return.
    std::string managedReturnReferenceType;
};

struct CSharpBodyEmissionResult {
    struct SupportFragment {
        std::string key;
        std::string source;
    };
    std::string declarations;
    std::string body;
    std::string support;
    std::vector<SupportFragment> supportFragments;
    std::vector<CSharpDiagnostic> diagnostics;
    bool partial = false;
};

struct RecoveredFunction {
    Architecture architecture = Architecture::Arm64;
    uint64_t address = 0;
    std::string name;
    std::vector<BasicBlock> blocks;
    std::vector<ExceptionRegion> exceptionRegions;

    std::string toCSharp() const;
    CSharpEmissionResult emitCSharp() const;
    CSharpBodyEmissionResult emitCSharpBody(CSharpBodyOptions options = {}) const;
};

} // namespace il2cpprec
