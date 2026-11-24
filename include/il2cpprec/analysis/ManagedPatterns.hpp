#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <il2cpprec/IR.hpp>
#include <il2cpprec/Model.hpp>

namespace il2cpprec {

enum class ManagedOperationKind {
    StringLiteralReference,
    DirectMethodCall,
    FieldLoad,
    FieldStore,
    ObjectConstruction,
    ArrayAllocation,
    ArrayLength,
    ArrayElementLoad,
    ArrayElementStore,
    VirtualDispatch,
    Box,
    UnBox,
    IsInst,
    NullCheck,
    RuntimeClassInit
};

enum class ManagedPatternStatus {
    Resolved,
    Placeholder,
    Ambiguous,
    Unresolved
};

enum class ManagedPatternConfidence {
    None,
    Low,
    Medium,
    High
};

struct ManagedMethodReference {
    uint32_t token = 0;
    int definitionIndex = -1;
    uint64_t address = 0;
    std::string imageName;
    std::string declaringType;
    std::string name;
    bool isStatic = false;
};

struct ManagedFieldReference {
    std::string declaringType;
    std::string name;
    std::string type;
    int64_t offset = 0;
    bool isStatic = false;
};

struct ManagedGenericTarget {
    bool present = false;
    bool adjustor = false;
    int32_t genericMethodIndex = -1;
    int32_t classInstIndex = -1;
    int32_t methodInstIndex = -1;
    GenericMethodPointerModel mapping;
};

struct ManagedTargetProfile {
    std::unordered_map<uint64_t, uint32_t> genericAdjustorTargets;
    std::set<uint64_t> unresolvedVirtualCallStubs;
    std::unordered_map<uint64_t, uint32_t> genericTypeAddresses;
};

struct ManagedOperation {
    ManagedOperationKind kind = ManagedOperationKind::DirectMethodCall;
    ManagedPatternStatus status = ManagedPatternStatus::Unresolved;
    ManagedPatternConfidence confidence = ManagedPatternConfidence::None;
    uint64_t address = 0;
    size_t blockIndex = 0;
    size_t statementIndex = 0;

    ExpressionPtr destination;
    ExpressionPtr object;
    ExpressionPtr value;
    ExpressionPtr index;
    ExpressionPtr length;

    int64_t offset = 0;
    uint64_t targetAddress = 0;
    uint64_t allocationAddress = 0;
    uint64_t typeAddress = 0;
    uint32_t stringLiteralToken = 0;
    std::string stringLiteral;
    std::string typeName;
    std::string reason;

    ManagedMethodReference method;
    ManagedGenericTarget genericTarget;
    bool unresolvedStub = false;
    ManagedFieldReference field;
    std::vector<ManagedMethodReference> methodCandidates;
    std::vector<ManagedFieldReference> fieldCandidates;
    std::vector<uint32_t> stringLiteralTokens;

    std::vector<Statement> nativeStatements;
};

struct ManagedPatternOptions {
    const BinaryImage* binary = nullptr;
    ManagedTargetProfile profile;
    std::unordered_map<uint32_t, uint64_t> stringLiteralAddresses;
    std::unordered_map<uint64_t, std::string> runtimeTypeAddresses;
    std::set<uint64_t> objectAllocatorAddresses;
    std::set<uint64_t> arrayAllocatorAddresses;
    std::set<uint64_t> boxAddresses;
    std::set<uint64_t> unboxAddresses;
    std::set<uint64_t> isInstAddresses;
    std::set<uint64_t> nullCheckAddresses;
    std::set<uint64_t> runtimeClassInitAddresses;
    size_t arrayTypeArgument = 0;
    size_t arrayLengthArgument = 1;
    size_t boxTypeArgument = 0;
    size_t boxValueArgument = 1;
    size_t unboxTypeArgument = 1;
    size_t unboxValueArgument = 0;
    size_t isInstTypeArgument = 1;
    size_t isInstValueArgument = 0;
    size_t runtimeClassInitTypeArgument = 0;
    bool recognizeArrayLayout = true;
    bool recognizeNullBranches = true;
    std::optional<int64_t> arrayLengthOffset;
    std::optional<int64_t> arrayElementsOffset;
};

struct ManagedAnalysisResult {
    RecoveredFunction native;
    std::vector<ManagedOperation> operations;
};

class ManagedPatterns {
public:
    ManagedAnalysisResult analyze(
        const RecoveredFunction& function,
        const MetadataModel& metadata,
        const ManagedPatternOptions& options = {}) const;
};

} // namespace il2cpprec
