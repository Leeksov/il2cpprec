#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <il2cpprec/Model.hpp>
#include <il2cpprec/analysis/ManagedPatterns.hpp>
#include <il2cpprec/analysis/VirtualDispatch.hpp>

namespace il2cpprec {

enum class MetadataUsageKind : uint8_t {
    Invalid = 0,
    TypeInfo = 1,
    Il2CppType = 2,
    MethodDef = 3,
    FieldInfo = 4,
    StringLiteral = 5,
    MethodRef = 6
};

enum class MetadataUsageStatus {
    Resolved,
    Ambiguous,
    Unresolved
};

struct MetadataUsageEncoded {
    MetadataUsageKind kind = MetadataUsageKind::Invalid;
    uint32_t index = 0;
};

struct MetadataUsageGenericMethodResolution {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    std::optional<uint32_t> methodDefinitionIndex;
    std::string diagnostic;
};

using MetadataUsageGenericMethodResolver =
    std::function<MetadataUsageGenericMethodResolution(uint32_t genericMethodIndex)>;

struct MetadataUsageSection {
    uint32_t offset = 0;
    uint32_t size = 0;
    uint32_t count = 0;
};

struct MetadataUsageHeaderInfo {
    int32_t rawVersion = 0;
    double version = 0;
    size_t typeIndexWidth = 4;
    size_t methodDefinitionIndexWidth = 4;
    MetadataUsageSection methods;
    MetadataUsageSection interfaceOffsets;
    MetadataUsageSection metadataUsageLists;
    MetadataUsageSection metadataUsagePairs;
    MetadataUsageSection fieldRefs;
    MetadataUsageSection unresolvedVirtualCallParameterTypes;
    MetadataUsageSection unresolvedVirtualCallParameterRanges;
    MetadataUsageSection methodSpecsOnGenericType;
    MetadataUsageSection genericMethodSpecsOnType;
    MetadataUsageSection methodSpecs;
    MetadataUsageSection genericMethodFunctionsDefinitions;
    MetadataUsageSection genericMethodFunctionsDefinitionsWithAdjustor;
    MetadataUsageSection invokerIndices;
    MetadataUsageSection rgctxRanges;
    MetadataUsageSection rgctxValues;
    MetadataUsageSection staticConstructorTypeIndices;
};

struct MetadataUsageTableView {
    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t listsOffset = 0;
    size_t listsSize = 0;
    size_t pairsOffset = 0;
    size_t pairsSize = 0;
    size_t fieldRefsOffset = 0;
    size_t fieldRefsSize = 0;
};

struct MetadataUsageList {
    uint32_t start = 0;
    uint32_t count = 0;
};

struct MetadataUsagePair {
    uint32_t destinationIndex = 0;
    uint32_t encodedSourceIndex = 0;
};

struct MetadataUsageField {
    uint32_t typeReferenceIndex = 0;
    int32_t typeDefinitionIndex = -1;
    uint32_t fieldIndex = 0;
    FieldModel field;
};

struct MetadataUsageEntry {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    MetadataUsageKind kind = MetadataUsageKind::Invalid;
    uint32_t sourceIndex = 0;
    uint32_t destinationIndex = 0;
    size_t pairIndex = 0;
    std::vector<uint32_t> listIndices;
    std::optional<uint32_t> genericMethodIndex;
    std::optional<TypeReferenceModel> type;
    std::optional<MethodModel> method;
    std::optional<MetadataUsageField> field;
    std::optional<std::string> stringLiteral;
};

struct MetadataUsageDiagnostic {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    std::string code;
    std::string message;
    std::optional<uint32_t> listIndex;
    std::optional<size_t> pairIndex;
    std::optional<uint32_t> destinationIndex;
};

struct MetadataUsageHeaderResult {
    bool ok = false;
    MetadataUsageHeaderInfo header;
    std::vector<MetadataUsageDiagnostic> diagnostics;
};

struct MetadataUsageSignature {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    uint32_t rangeIndex = 0;
    std::vector<TypeReferenceModel> parameterTypes;
    std::string diagnostic;
};

struct MetadataUsageSignatureResult {
    bool tablesValid = false;
    std::vector<MetadataUsageSignature> signatures;
    std::vector<MetadataUsageDiagnostic> diagnostics;
};

struct MetadataUsageRgctxResult {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    uint32_t token = 0;
    std::vector<RgctxValueModel> values;
    std::string diagnostic;
};

MetadataUsageHeaderResult readMetadataUsageHeader(const std::vector<uint8_t>& globalMetadata, double version);
MetadataUsageSignatureResult readUnresolvedSignatures(
    const std::vector<uint8_t>& globalMetadata,
    double version,
    const MetadataModel& metadata);
MetadataUsageRgctxResult resolveMetadataRgctx(const MetadataModel& metadata, uint32_t token);

struct MetadataUsageResult {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    bool tablesValid = false;
    std::vector<MetadataUsageList> lists;
    std::vector<MetadataUsagePair> pairs;
    std::vector<MetadataUsageEntry> entries;
    std::vector<MetadataUsageDiagnostic> diagnostics;
    size_t resolvedCount = 0;
    size_t ambiguousCount = 0;
    size_t unresolvedCount = 0;
    size_t referencedPairCount = 0;
    size_t unreferencedPairCount = 0;

    bool ok() const;
};

struct MetadataUsageLinkOptions {
    std::unordered_map<uint32_t, uint64_t> destinationAddresses;
    std::set<uint32_t> requiredDestinations;
    ManagedPatternOptions managed;
    VirtualDispatchOptions virtualDispatch;
};

struct MetadataUsageLinkResult {
    MetadataModel metadata;
    ManagedPatternOptions managed;
    VirtualDispatchOptions virtualDispatch;
    std::vector<MetadataUsageDiagnostic> diagnostics;
};

struct MetadataUsageManagedResult {
    ManagedAnalysisResult analysis;
    std::vector<MetadataUsageDiagnostic> diagnostics;
};

struct MetadataUsageVirtualResult {
    VirtualDispatchAnalysisResult analysis;
    std::vector<MetadataUsageDiagnostic> diagnostics;
};

class MetadataUsageResolver {
public:
    MetadataUsageResolver(const MetadataModel& metadata, MetadataUsageResult usages);

    const MetadataUsageResult& usages() const;
    const MetadataUsageEntry* findDestination(uint32_t destinationIndex) const;
    MetadataUsageLinkResult link(const MetadataUsageLinkOptions& options = {}) const;
    MetadataUsageManagedResult analyzeManaged(
        const RecoveredFunction& function,
        const MetadataUsageLinkOptions& options = {}) const;
    MetadataUsageVirtualResult analyzeVirtualDispatch(
        const RecoveredFunction& function,
        const MetadataUsageLinkOptions& options = {}) const;

private:
    const MetadataModel* metadata_;
    MetadataUsageResult usages_;
};

const char* toString(MetadataUsageKind kind);
const char* toString(MetadataUsageStatus status);

class MetadataUsageReader {
public:
    static constexpr uint32_t indexMask = 0x1fffffff;
    static constexpr uint32_t usageShift = 29;
    static constexpr size_t listStride = 8;
    static constexpr size_t pairStride = 8;
    static constexpr size_t fieldRefStride = 8;

    static MetadataUsageEncoded decode(uint32_t encodedSourceIndex);

    MetadataUsageResult read(
        const MetadataUsageTableView& tables,
        const MetadataModel* metadata = nullptr,
        const MetadataUsageGenericMethodResolver& genericMethods = {}) const;

    MetadataUsageResult readUnity2017(
        const std::vector<uint8_t>& globalMetadata,
        const MetadataModel* metadata = nullptr,
        const MetadataUsageGenericMethodResolver& genericMethods = {}) const;

    MetadataUsageResult readVersioned(
        const std::vector<uint8_t>& globalMetadata,
        double version,
        const MetadataModel* metadata = nullptr,
        const MetadataUsageGenericMethodResolver& genericMethods = {}) const;

    MetadataUsageResult initializeMethodMetadata(
        const MetadataUsageTableView& tables,
        uint32_t listIndex,
        const MetadataModel* metadata = nullptr,
        const MetadataUsageGenericMethodResolver& genericMethods = {}) const;

    MetadataUsageResult initializeMethodMetadataUnity2017(
        const std::vector<uint8_t>& globalMetadata,
        uint32_t listIndex,
        const MetadataModel* metadata = nullptr,
        const MetadataUsageGenericMethodResolver& genericMethods = {}) const;

    MetadataUsageResult initializeMethodMetadataVersioned(
        const std::vector<uint8_t>& globalMetadata,
        double version,
        uint32_t listIndex,
        const MetadataModel* metadata = nullptr,
        const MetadataUsageGenericMethodResolver& genericMethods = {}) const;
};

} // namespace il2cpprec
