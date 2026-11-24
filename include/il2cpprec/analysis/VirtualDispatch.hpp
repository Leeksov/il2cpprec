#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <il2cpprec/analysis/ManagedPatterns.hpp>

namespace il2cpprec {

enum class VirtualDispatchKind {
    Virtual,
    Interface,
    GenericVirtual,
    GenericInterface
};

struct VirtualInvokeData {
    uint64_t methodPointer = 0;
    uint64_t methodInfo = 0;
};

struct VirtualInterfaceOffset {
    uint64_t interfaceType = 0;
    int32_t offset = 0;
};

struct VirtualDispatchOptions {
    const BinaryImage* binary = nullptr;
    // Borrow the immutable method-address index already built for this exact
    // MetadataModel. A mismatched source falls back to a local index.
    const ManagedMetadataIndex* metadataIndex = nullptr;
    ManagedTargetProfile profile;
    bool unity2017Layout = true;
    bool vtablePointer = false;
    std::optional<uint64_t> vtableOffset;
    std::optional<uint64_t> classVtablePointerOffset;
    std::optional<uint64_t> classInterfaceOffsetsPointerOffset;
    std::optional<uint64_t> classInterfaceOffsetsCountOffset;
    uint64_t objectKlassOffset = 0;
    uint32_t virtualInvokeDataSize = 0;
    uint32_t methodPointerOffset = 0;
    uint32_t methodInfoOffset = 0;
    uint32_t interfaceOffsetEntrySize = 0;
    uint32_t interfaceOffsetValueOffset = 0;

    std::set<uint64_t> virtualHelperAddresses;
    std::set<uint64_t> interfaceHelperAddresses;
    std::set<uint64_t> genericVirtualHelperAddresses;
    std::set<uint64_t> genericInterfaceHelperAddresses;
    std::set<uint64_t> genericMethodResolverAddresses;
    size_t virtualSlotArgument = 0;
    size_t virtualObjectArgument = 1;
    size_t interfaceSlotArgument = 0;
    size_t interfaceTypeArgument = 1;
    size_t interfaceObjectArgument = 2;

    std::unordered_map<uint64_t, VirtualInvokeData> invokeDataByAddress;
    std::unordered_map<uint64_t, std::vector<VirtualInterfaceOffset>> interfaceOffsetsByClass;
    std::unordered_map<uint64_t, uint64_t> methodInfoTargets;
    std::set<uint64_t> genericMethodInfo;
    std::set<uint32_t> genericVirtualSlots;
    std::set<uint32_t> genericInterfaceSlots;
};

struct VirtualDispatchOperation {
    VirtualDispatchKind kind = VirtualDispatchKind::Virtual;
    ManagedPatternStatus status = ManagedPatternStatus::Placeholder;
    ManagedPatternConfidence confidence = ManagedPatternConfidence::Low;
    uint64_t address = 0;
    size_t blockIndex = 0;
    size_t statementIndex = 0;

    ExpressionPtr object;
    ExpressionPtr methodPointerExpression;
    ExpressionPtr methodInfoExpression;
    ExpressionPtr slotExpression;
    std::optional<uint32_t> slot;
    int64_t vtableOffset = 0;
    int32_t interfaceOffset = 0;
    bool hasInterfaceOffset = false;
    bool methodInfoPassed = false;

    uint64_t klassAddress = 0;
    uint64_t vtableAddress = 0;
    uint64_t interfaceAddress = 0;
    uint64_t invokeDataAddress = 0;
    VirtualInvokeData invokeData;
    bool hasMethodPointer = false;
    bool hasMethodInfo = false;

    ManagedMethodReference method;
    ManagedGenericTarget genericTarget;
    std::vector<ManagedMethodReference> methodCandidates;
    std::string reason;
    std::vector<Statement> nativeStatements;
};

struct VirtualDispatchAnalysisResult {
    RecoveredFunction native;
    std::vector<VirtualDispatchOperation> operations;
};

class VirtualDispatch {
public:
    VirtualDispatchAnalysisResult analyze(
        const RecoveredFunction& function,
        const MetadataModel& metadata,
        const VirtualDispatchOptions& options = {}) const;
};

} // namespace il2cpprec
