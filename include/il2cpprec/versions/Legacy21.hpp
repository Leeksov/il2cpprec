#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace il2cpprec {

enum class Legacy21Variant {
    Unity535,
    Unity54,
    Unity54PerType = Unity54
};

enum class Legacy21FieldOffsetStorage {
    FlatInt32,
    PerTypePointers
};

enum class Legacy21TypeDefinitionSizeStorage {
    InlineRecords,
    PointerArray
};

enum class Legacy21VTableKind {
    MethodInfoPointers,
    VirtualInvokeData
};

enum class Legacy21ReversePInvokeName {
    DelegateWrappersFromNativeToManaged,
    ReversePInvokeWrapper
};

struct Legacy21FieldLayout {
    std::size_t offset = 0;
    std::size_t size = 0;
    bool present = true;
};

struct Legacy21TableLayout {
    Legacy21FieldLayout count;
    Legacy21FieldLayout pointer;
};

struct Legacy21VTableLayout {
    Legacy21VTableKind kind = Legacy21VTableKind::MethodInfoPointers;
    std::size_t elementSize = 0;
    Legacy21FieldLayout methodPointer;
    Legacy21FieldLayout methodInfo;
};

struct Legacy21ClassLayout {
    std::size_t size = 0;
    std::size_t alignment = 0;
    Legacy21FieldLayout vtable;
    Legacy21FieldLayout interfaceOffsets;
    Legacy21FieldLayout typeHierarchy;
    Legacy21FieldLayout cctorStarted;
    Legacy21FieldLayout cctorFinished;
    Legacy21FieldLayout cctorThread;
    Legacy21FieldLayout genericContainerIndex;
    Legacy21FieldLayout customAttributeIndex;
    Legacy21FieldLayout instanceSize;
    Legacy21FieldLayout actualSize;
    Legacy21FieldLayout elementSize;
    Legacy21FieldLayout nativeSize;
    Legacy21FieldLayout staticFieldsSize;
    Legacy21FieldLayout threadStaticFieldsSize;
    Legacy21FieldLayout threadStaticFieldsOffset;
    Legacy21FieldLayout flags;
    Legacy21FieldLayout token;
    Legacy21FieldLayout methodCount;
    Legacy21FieldLayout propertyCount;
    Legacy21FieldLayout fieldCount;
    Legacy21FieldLayout eventCount;
    Legacy21FieldLayout nestedTypeCount;
    Legacy21FieldLayout vtableCount;
    Legacy21FieldLayout interfacesCount;
    Legacy21FieldLayout interfaceOffsetsCount;
    Legacy21FieldLayout typeHierarchyDepth;
    Legacy21FieldLayout genericRecursionDepth;
    Legacy21FieldLayout rank;
    Legacy21FieldLayout minimumAlignment;
    Legacy21FieldLayout packingSize;
    Legacy21FieldLayout bitfield;
};

struct Legacy21MethodInfoLayout {
    std::size_t size = 0;
    std::size_t alignment = 0;
    Legacy21FieldLayout methodPointer;
    Legacy21FieldLayout invokerMethod;
    Legacy21FieldLayout name;
    Legacy21FieldLayout declaringType;
    Legacy21FieldLayout returnType;
    Legacy21FieldLayout parameters;
    Legacy21FieldLayout rgctxData;
    Legacy21FieldLayout genericMethod;
    Legacy21FieldLayout customAttributeIndex;
    Legacy21FieldLayout token;
    Legacy21FieldLayout flags;
    Legacy21FieldLayout iflags;
    Legacy21FieldLayout slot;
    Legacy21FieldLayout parametersCount;
    Legacy21FieldLayout methodFlags;
};

struct Legacy21CodeRegistrationLayout {
    std::size_t size = 0;
    std::size_t alignment = 0;
    Legacy21ReversePInvokeName reversePInvokeName =
        Legacy21ReversePInvokeName::DelegateWrappersFromNativeToManaged;
    Legacy21TableLayout methodPointers;
    Legacy21TableLayout reversePInvokeWrappers;
    Legacy21TableLayout delegateWrappersFromManagedToNative;
    Legacy21TableLayout marshalingFunctions;
    Legacy21TableLayout ccwMarshalingFunctions;
    Legacy21TableLayout genericMethodPointers;
    Legacy21TableLayout invokerPointers;
    Legacy21TableLayout customAttributeGenerators;
    Legacy21TableLayout guids;
};

struct Legacy21MetadataRegistrationLayout {
    std::size_t size = 0;
    std::size_t alignment = 0;
    Legacy21TableLayout genericClasses;
    Legacy21TableLayout genericInsts;
    Legacy21TableLayout genericMethodTable;
    Legacy21TableLayout types;
    Legacy21TableLayout methodSpecs;
    Legacy21TableLayout fieldOffsets;
    Legacy21TableLayout typeDefinitionsSizes;
    Legacy21TableLayout metadataUsages;
};

struct Legacy21Layout {
    Legacy21Variant variant = Legacy21Variant::Unity535;
    std::size_t pointerSize = 0;
    Legacy21FieldOffsetStorage fieldOffsetStorage = Legacy21FieldOffsetStorage::FlatInt32;
    Legacy21TypeDefinitionSizeStorage typeDefinitionSizeStorage =
        Legacy21TypeDefinitionSizeStorage::InlineRecords;
    std::size_t fieldOffsetElementSize = 0;
    std::size_t typeDefinitionSizeRecordSize = 16;
    std::size_t typeDefinitionSizeElementSize = 0;
    Legacy21VTableLayout vtable;
    Legacy21ClassLayout classLayout;
    Legacy21MethodInfoLayout methodInfo;
    Legacy21CodeRegistrationLayout codeRegistration;
    Legacy21MetadataRegistrationLayout metadataRegistration;
};

struct Legacy21DetectionEvidence {
    std::int32_t metadataVersion = 21;
    std::string unityVersion;
    std::optional<Legacy21FieldOffsetStorage> fieldOffsets;
    std::optional<Legacy21TypeDefinitionSizeStorage> typeDefinitionSizes;
    std::optional<Legacy21VTableKind> vtable;
    std::optional<bool> hasGenericRecursionDepth;
};

enum class Legacy21DetectionStatus {
    Confirmed,
    InsufficientEvidence,
    Ambiguous,
    ConflictingEvidence,
    Unsupported
};

enum class Legacy21DiagnosticSeverity {
    Info,
    Error
};

struct Legacy21Diagnostic {
    Legacy21DiagnosticSeverity severity = Legacy21DiagnosticSeverity::Error;
    std::string code;
    std::string message;
};

struct Legacy21DetectionResult {
    Legacy21DetectionStatus status = Legacy21DetectionStatus::InsufficientEvidence;
    std::optional<Legacy21Layout> layout;
    std::vector<Legacy21Diagnostic> diagnostics;

    bool ok() const noexcept;
    bool rejected() const noexcept { return !ok(); }
};

Legacy21Layout makeLegacy21Layout(Legacy21Variant variant, std::size_t pointerSize);
std::vector<Legacy21Diagnostic> validateLegacy21Layout(const Legacy21Layout& layout);

Legacy21DetectionResult detectLegacy21Layout(
    const Legacy21DetectionEvidence& evidence,
    std::size_t pointerSize);
Legacy21DetectionResult detectLegacy21Layout(
    std::string_view unityVersion,
    std::size_t pointerSize);

class Legacy21Detector {
public:
    explicit Legacy21Detector(std::size_t pointerSize = 8) : pointerSize_(pointerSize) {}

    Legacy21DetectionResult detect(const Legacy21DetectionEvidence& evidence) const;
    Legacy21DetectionResult detect(std::string_view unityVersion) const;
    std::size_t pointerSize() const noexcept { return pointerSize_; }

private:
    std::size_t pointerSize_;
};

const char* toString(Legacy21Variant value) noexcept;
const char* toString(Legacy21FieldOffsetStorage value) noexcept;
const char* toString(Legacy21TypeDefinitionSizeStorage value) noexcept;
const char* toString(Legacy21VTableKind value) noexcept;
const char* toString(Legacy21ReversePInvokeName value) noexcept;
const char* toString(Legacy21DetectionStatus value) noexcept;

} // namespace il2cpprec
