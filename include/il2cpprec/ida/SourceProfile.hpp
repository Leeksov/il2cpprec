#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec::ida {

enum class CodeGenModulePresence {
    Absent,
    Present
};

enum class MethodMapping {
    GlobalMethodIndex,
    PerImageTokenRowId
};

enum class NativeProfileConfidence {
    Exact,
    High,
    Compatible,
    Override,
    Unsupported
};

struct NativeFieldLayout {
    std::size_t offset = 0;
    std::size_t size = 0;
    bool present = true;
};

struct NativeTableLayout {
    NativeFieldLayout count;
    NativeFieldLayout pointer;
};

struct MethodInfoSourceLayout {
    std::size_t size = 0;
    std::size_t alignment = 0;
    NativeFieldLayout methodPointer;
    NativeFieldLayout invokerMethod;
    NativeFieldLayout name;
    NativeFieldLayout declaringType;
    NativeFieldLayout returnType;
    NativeFieldLayout parameters;
    NativeFieldLayout rgctxData;
    NativeFieldLayout genericMethod;
    NativeFieldLayout customAttributeIndex;
    NativeFieldLayout token;
    NativeFieldLayout flags;
    NativeFieldLayout iflags;
    NativeFieldLayout slot;
    NativeFieldLayout parametersCount;
    NativeFieldLayout methodFlags;
};

struct CodeRegistrationSourceLayout {
    std::size_t size = 0;
    std::size_t alignment = 0;
    NativeTableLayout methodPointers;
    NativeTableLayout reversePInvokeWrappers;
    NativeTableLayout genericMethodPointers;
    NativeFieldLayout genericAdjustorThunks;
    NativeTableLayout invokerPointers;
    NativeTableLayout customAttributeGenerators;
    NativeTableLayout unresolvedVirtualCallPointers;
    NativeTableLayout interopData;
    NativeTableLayout windowsRuntimeFactoryTable;
    NativeTableLayout codeGenModules;
};

struct MetadataRegistrationSourceLayout {
    std::size_t size = 0;
    std::size_t alignment = 0;
    NativeTableLayout genericClasses;
    NativeTableLayout genericInsts;
    NativeTableLayout genericMethodTable;
    NativeTableLayout types;
    NativeTableLayout methodSpecs;
    NativeTableLayout fieldOffsets;
    NativeTableLayout typeDefinitionsSizes;
    NativeTableLayout metadataUsages;
};

struct CodeGenModuleSourceLayout {
    std::size_t size = 0;
    std::size_t alignment = 0;
    NativeFieldLayout moduleName;
    NativeFieldLayout methodPointerCount;
    NativeFieldLayout methodPointers;
    NativeFieldLayout adjustorThunkCount;
    NativeFieldLayout adjustorThunks;
    NativeFieldLayout invokerIndices;
    NativeTableLayout reversePInvokeWrapperIndices;
    NativeTableLayout rgctxRanges;
    NativeTableLayout rgctxs;
    NativeFieldLayout debuggerMetadata;
};

struct ManagedObjectSourceLayout {
    std::size_t size = 0;
    NativeFieldLayout klass;
    NativeFieldLayout monitor;
};

struct ManagedArraySourceLayout {
    std::size_t size = 0;
    NativeFieldLayout klass;
    NativeFieldLayout monitor;
    NativeFieldLayout bounds;
    NativeFieldLayout length;
    NativeFieldLayout data;
    std::size_t dataAlignment = 0;
};

struct ManagedStringSourceLayout {
    std::size_t size = 0;
    NativeFieldLayout klass;
    NativeFieldLayout monitor;
    NativeFieldLayout length;
    NativeFieldLayout chars;
};

struct GlobalMetadataSourceLayout {
    int rawVersion = 0;
    double version = 0;
    std::size_t headerSize = 0;
    std::size_t imagesOffset = 0;
    std::size_t assembliesOffset = 0;
    std::size_t typeDefinitionStride = 0;
    std::size_t methodDefinitionStride = 0;
    std::size_t parameterDefinitionStride = 0;
    std::size_t fieldDefinitionStride = 0;
    std::size_t imageDefinitionStride = 0;
    std::size_t assemblyDefinitionStride = 0;
};

struct SourceProfile;

struct SourceLayoutSelection {
    const SourceProfile* profile = nullptr;
    double metadataVersion = 0;
    std::size_t pointerSize = 0;
    bool supported = false;
    bool nativeRuntimeAvailable = false;
    std::string variant;
    NativeProfileConfidence confidence = NativeProfileConfidence::Unsupported;
    std::string provenance;
    MethodMapping methodMapping = MethodMapping::GlobalMethodIndex;
    CodeGenModulePresence codeGenModules = CodeGenModulePresence::Absent;
    GlobalMetadataSourceLayout globalMetadata;
    MethodInfoSourceLayout methodInfo;
    CodeRegistrationSourceLayout codeRegistration;
    MetadataRegistrationSourceLayout metadataRegistration;
    CodeGenModuleSourceLayout codeGenModule;
    ManagedObjectSourceLayout object;
    ManagedArraySourceLayout array;
    ManagedStringSourceLayout string;

    std::string layoutHash() const;
    std::string diagnostics() const;
};

struct SourceProfile {
    std::string id;
    std::string unityVersion;
    std::string metadataRange;
    std::string sourceSet;
    bool exact = false;
    double canonicalMetadataVersion = 0;
    NativeProfileConfidence confidence = NativeProfileConfidence::Compatible;
    std::string provenance;

    SourceLayoutSelection resolve(double metadataVersion, std::size_t pointerSize) const;
    SourceLayoutSelection resolve(double metadataVersion, const BinaryImage& binary) const;
    std::string profileHash() const;
    std::string diagnostics() const;
};

struct SourceDetectionOverrides {
    std::string profileId;
    std::optional<double> metadataVersion;
    std::optional<std::size_t> pointerSize;
    std::optional<GlobalMetadataSourceLayout> globalMetadata;
};

struct RegistrationProfileEvidence {
    std::optional<std::uint64_t> metadataRegistrationAddress;
    std::optional<std::uint64_t> codeRegistrationAddress;
    std::optional<bool> codeGenModulesPresent;
};

struct SourceDetectionInput {
    std::vector<std::uint8_t> rawMetadata;
    std::optional<double> metadataVersion;
    const BinaryImage* binary = nullptr;
    std::string unityVersion;
    RegistrationProfileEvidence registration;
    SourceDetectionOverrides overrides;
};

struct SourceDetectionResult {
    SourceLayoutSelection selection;
    std::vector<std::string> evidence;
    std::string error;

    bool supported() const noexcept {
        return error.empty() && selection.supported;
    }
};

class Il2CppNativeProfileRegistry {
public:
    static const std::vector<const SourceProfile*>& profiles();
    static const SourceProfile* find(std::string_view profileId) noexcept;
    static const SourceProfile* findMetadata(double metadataVersion) noexcept;
    static SourceDetectionResult detect(const SourceDetectionInput& input);
};

std::size_t sourcePointerSize(const BinaryImage& binary) noexcept;
std::vector<std::string> validateSourceLayout(const SourceLayoutSelection& selection);

const SourceProfile& unity2017_4_11f1Profile() noexcept;
const SourceProfile& metadata24BaseProfile() noexcept;
const SourceProfile* findSourceProfile(std::string_view unityVersion) noexcept;

} // namespace il2cpprec::ida
