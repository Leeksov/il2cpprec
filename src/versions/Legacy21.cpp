#include <il2cpprec/versions/Legacy21.hpp>

#include <algorithm>
#include <cctype>
#include <iterator>
#include <stdexcept>
#include <utility>

namespace il2cpprec {
namespace {

Legacy21FieldLayout field(std::size_t offset, std::size_t size) {
    return {offset, size, true};
}

Legacy21FieldLayout absentField() {
    return {0, 0, false};
}

Legacy21TableLayout table(std::size_t pointerSize, std::size_t index, std::size_t countSize = 4) {
    const std::size_t offset = index * 2 * pointerSize;
    return {field(offset, countSize), field(offset + pointerSize, pointerSize)};
}

std::size_t alignUp(std::size_t value, std::size_t alignment) {
    return (value + alignment - 1) / alignment * alignment;
}

Legacy21ClassLayout makeClass(Legacy21Variant variant, std::size_t pointerSize) {
    Legacy21ClassLayout layout;
    layout.alignment = 8;
    layout.vtable = field(18 * pointerSize, pointerSize);
    layout.interfaceOffsets = field(19 * pointerSize, pointerSize);
    layout.typeHierarchy = field(22 * pointerSize, pointerSize);

    const std::size_t cctorStarted = 23 * pointerSize;
    layout.cctorStarted = field(cctorStarted, 4);
    layout.cctorFinished = field(cctorStarted + 4, 4);
    const std::size_t cctorThread = alignUp(cctorStarted + 8, 8);
    layout.cctorThread = field(cctorThread, 8);

    const std::size_t indices = cctorThread + 8;
    layout.genericContainerIndex = field(indices, 4);
    layout.customAttributeIndex = field(indices + 4, 4);
    const std::size_t sizes = indices + 8;
    layout.instanceSize = field(sizes, 4);
    layout.actualSize = field(sizes + 4, 4);
    layout.elementSize = field(sizes + 8, 4);
    layout.nativeSize = field(sizes + 12, 4);
    layout.staticFieldsSize = field(sizes + 16, 4);
    layout.threadStaticFieldsSize = field(sizes + 20, 4);
    layout.threadStaticFieldsOffset = field(sizes + 24, 4);
    layout.flags = field(sizes + 28, 4);
    layout.token = field(sizes + 32, 4);

    const std::size_t counts = sizes + 36;
    layout.methodCount = field(counts, 2);
    layout.propertyCount = field(counts + 2, 2);
    layout.fieldCount = field(counts + 4, 2);
    layout.eventCount = field(counts + 6, 2);
    layout.nestedTypeCount = field(counts + 8, 2);
    layout.vtableCount = field(counts + 10, 2);
    layout.interfacesCount = field(counts + 12, 2);
    layout.interfaceOffsetsCount = field(counts + 14, 2);

    const std::size_t bytes = counts + 16;
    layout.typeHierarchyDepth = field(bytes, 1);
    std::size_t rank = bytes + 1;
    if (variant == Legacy21Variant::Unity54) {
        layout.genericRecursionDepth = field(bytes + 1, 1);
        rank = bytes + 2;
    } else {
        layout.genericRecursionDepth = absentField();
    }
    layout.rank = field(rank, 1);
    layout.minimumAlignment = field(rank + 1, 1);
    layout.packingSize = field(rank + 2, 1);
    layout.bitfield = field(rank + 3, 1);
    layout.size = alignUp(rank + 4, 8);
    return layout;
}

Legacy21MethodInfoLayout makeMethodInfo(std::size_t pointerSize) {
    Legacy21MethodInfoLayout layout;
    layout.alignment = pointerSize;
    layout.methodPointer = field(0 * pointerSize, pointerSize);
    layout.invokerMethod = field(1 * pointerSize, pointerSize);
    layout.name = field(2 * pointerSize, pointerSize);
    layout.declaringType = field(3 * pointerSize, pointerSize);
    layout.returnType = field(4 * pointerSize, pointerSize);
    layout.parameters = field(5 * pointerSize, pointerSize);
    layout.rgctxData = field(6 * pointerSize, pointerSize);
    layout.genericMethod = field(7 * pointerSize, pointerSize);

    const std::size_t scalar = 8 * pointerSize;
    layout.customAttributeIndex = field(scalar, 4);
    layout.token = field(scalar + 4, 4);
    layout.flags = field(scalar + 8, 2);
    layout.iflags = field(scalar + 10, 2);
    layout.slot = field(scalar + 12, 2);
    layout.parametersCount = field(scalar + 14, 1);
    layout.methodFlags = field(scalar + 15, 1);
    layout.size = alignUp(scalar + 16, pointerSize);
    return layout;
}

Legacy21CodeRegistrationLayout makeCodeRegistration(
    Legacy21Variant variant,
    std::size_t pointerSize) {
    Legacy21CodeRegistrationLayout layout;
    layout.alignment = pointerSize;
    layout.reversePInvokeName = variant == Legacy21Variant::Unity535
        ? Legacy21ReversePInvokeName::DelegateWrappersFromNativeToManaged
        : Legacy21ReversePInvokeName::ReversePInvokeWrapper;
    layout.methodPointers = table(pointerSize, 0);
    layout.reversePInvokeWrappers = table(pointerSize, 1);
    layout.delegateWrappersFromManagedToNative = table(pointerSize, 2);
    layout.marshalingFunctions = table(pointerSize, 3);
    layout.ccwMarshalingFunctions = table(pointerSize, 4);
    layout.genericMethodPointers = table(pointerSize, 5);
    layout.invokerPointers = table(pointerSize, 6);
    layout.customAttributeGenerators = table(pointerSize, 7);
    layout.guids = table(pointerSize, 8);
    layout.size = 18 * pointerSize;
    return layout;
}

Legacy21MetadataRegistrationLayout makeMetadataRegistration(std::size_t pointerSize) {
    Legacy21MetadataRegistrationLayout layout;
    layout.alignment = pointerSize;
    layout.genericClasses = table(pointerSize, 0);
    layout.genericInsts = table(pointerSize, 1);
    layout.genericMethodTable = table(pointerSize, 2);
    layout.types = table(pointerSize, 3);
    layout.methodSpecs = table(pointerSize, 4);
    layout.fieldOffsets = table(pointerSize, 5);
    layout.typeDefinitionsSizes = table(pointerSize, 6);
    layout.metadataUsages = table(pointerSize, 7, pointerSize);
    layout.size = 16 * pointerSize;
    return layout;
}

void addDiagnostic(
    Legacy21DetectionResult& result,
    Legacy21DetectionStatus status,
    std::string code,
    std::string message) {
    result.status = status;
    result.layout.reset();
    result.diagnostics.push_back({Legacy21DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

struct ParsedUnityVersion {
    bool valid = false;
    bool supported = false;
    int major = 0;
    int minor = 0;
    int patch = 0;
    Legacy21Variant variant = Legacy21Variant::Unity535;
};

ParsedUnityVersion parseUnityVersion(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) text.remove_prefix(1);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) text.remove_suffix(1);
    if (text.starts_with("Unity ")) text.remove_prefix(6);

    ParsedUnityVersion parsed;
    int* components[] = {&parsed.major, &parsed.minor, &parsed.patch};
    for (std::size_t index = 0; index < 3; ++index) {
        if (text.empty() || std::isdigit(static_cast<unsigned char>(text.front())) == 0) return parsed;
        unsigned value = 0;
        while (!text.empty() && std::isdigit(static_cast<unsigned char>(text.front())) != 0) {
            value = value * 10 + static_cast<unsigned>(text.front() - '0');
            if (value > 1000000) return parsed;
            text.remove_prefix(1);
        }
        *components[index] = static_cast<int>(value);
        if (index != 2) {
            if (text.empty() || text.front() != '.') return parsed;
            text.remove_prefix(1);
        }
    }
    if (!text.empty()) {
        const char suffix = text.front();
        if (suffix != 'f' && suffix != 'p' && suffix != 'a' && suffix != 'b') return parsed;
        text.remove_prefix(1);
        if (text.empty() || !std::all_of(text.begin(), text.end(), [](char value) {
                return std::isdigit(static_cast<unsigned char>(value)) != 0;
            })) {
            return parsed;
        }
    }
    parsed.valid = true;
    if (parsed.major == 5 && parsed.minor == 3 && parsed.patch == 5) {
        parsed.supported = true;
        parsed.variant = Legacy21Variant::Unity535;
    } else if (parsed.major == 5 && parsed.minor == 4 && parsed.patch >= 4 && parsed.patch <= 6) {
        parsed.supported = true;
        parsed.variant = Legacy21Variant::Unity54;
    }
    return parsed;
}

bool valid(Legacy21FieldOffsetStorage value) {
    return value == Legacy21FieldOffsetStorage::FlatInt32 ||
        value == Legacy21FieldOffsetStorage::PerTypePointers;
}

bool valid(Legacy21TypeDefinitionSizeStorage value) {
    return value == Legacy21TypeDefinitionSizeStorage::InlineRecords ||
        value == Legacy21TypeDefinitionSizeStorage::PointerArray;
}

bool valid(Legacy21VTableKind value) {
    return value == Legacy21VTableKind::MethodInfoPointers ||
        value == Legacy21VTableKind::VirtualInvokeData;
}

bool valid(Legacy21ReversePInvokeName value) {
    return value == Legacy21ReversePInvokeName::DelegateWrappersFromNativeToManaged ||
        value == Legacy21ReversePInvokeName::ReversePInvokeWrapper;
}

bool hasEvidence(const Legacy21DetectionEvidence& evidence) {
    return evidence.fieldOffsets.has_value() || evidence.typeDefinitionSizes.has_value() ||
        evidence.vtable.has_value() || evidence.hasGenericRecursionDepth.has_value() ||
        evidence.reversePInvokeName.has_value();
}

bool matches(
    const Legacy21DetectionEvidence& evidence,
    Legacy21Variant variant,
    std::string& mismatch) {
    const auto expectedFields = variant == Legacy21Variant::Unity535
        ? Legacy21FieldOffsetStorage::FlatInt32
        : Legacy21FieldOffsetStorage::PerTypePointers;
    const auto expectedSizes = variant == Legacy21Variant::Unity535
        ? Legacy21TypeDefinitionSizeStorage::InlineRecords
        : Legacy21TypeDefinitionSizeStorage::PointerArray;
    const auto expectedVtable = variant == Legacy21Variant::Unity535
        ? Legacy21VTableKind::MethodInfoPointers
        : Legacy21VTableKind::VirtualInvokeData;
    const bool expectedGenericRecursionDepth = variant == Legacy21Variant::Unity54;
    if (evidence.fieldOffsets && *evidence.fieldOffsets != expectedFields) {
        mismatch = std::string("field offsets are ") + toString(*evidence.fieldOffsets) + ", expected " +
            toString(expectedFields);
        return false;
    }
    if (evidence.typeDefinitionSizes && *evidence.typeDefinitionSizes != expectedSizes) {
        mismatch = std::string("type definition sizes are ") + toString(*evidence.typeDefinitionSizes) +
            ", expected " + toString(expectedSizes);
        return false;
    }
    if (evidence.vtable && *evidence.vtable != expectedVtable) {
        mismatch = std::string("vtable is ") + toString(*evidence.vtable) + ", expected " + toString(expectedVtable);
        return false;
    }
    if (evidence.hasGenericRecursionDepth &&
        *evidence.hasGenericRecursionDepth != expectedGenericRecursionDepth) {
        mismatch = std::string("genericRecursionDepth presence is ") +
            (*evidence.hasGenericRecursionDepth ? "true" : "false") + ", expected " +
            (expectedGenericRecursionDepth ? "true" : "false");
        return false;
    }
    const auto expectedReversePInvoke = variant == Legacy21Variant::Unity535
        ? Legacy21ReversePInvokeName::DelegateWrappersFromNativeToManaged
        : Legacy21ReversePInvokeName::ReversePInvokeWrapper;
    if (evidence.reversePInvokeName && *evidence.reversePInvokeName != expectedReversePInvoke) {
        mismatch = std::string("reverse P/Invoke registration is ") + toString(*evidence.reversePInvokeName) +
            ", expected " + toString(expectedReversePInvoke);
        return false;
    }
    return true;
}

void confirm(
    Legacy21DetectionResult& result,
    Legacy21Variant variant,
    std::size_t pointerSize,
    std::string source) {
    result.status = Legacy21DetectionStatus::Confirmed;
    result.layout = makeLegacy21Layout(variant, pointerSize);
    result.diagnostics.push_back({
        Legacy21DiagnosticSeverity::Info,
        "confirmed-v21-layout",
        std::move(source) + ";variant=" + toString(variant) + ";pointer-size=" + std::to_string(pointerSize)
    });
}

void validationError(
    std::vector<Legacy21Diagnostic>& diagnostics,
    std::string code,
    std::string message) {
    diagnostics.push_back({Legacy21DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

void checkField(
    std::vector<Legacy21Diagnostic>& diagnostics,
    std::string_view owner,
    std::string_view name,
    const Legacy21FieldLayout& value,
    std::size_t size) {
    if (!value.present) return;
    if (value.offset > size || value.size > size - value.offset) {
        validationError(
            diagnostics,
            "field-outside-structure",
            std::string(owner) + "." + std::string(name) + " is outside the native structure");
    }
}

void checkTable(
    std::vector<Legacy21Diagnostic>& diagnostics,
    std::string_view owner,
    std::string_view name,
    const Legacy21TableLayout& value,
    std::size_t index,
    std::size_t pointerSize,
    std::size_t countSize,
    std::size_t structureSize) {
    checkField(diagnostics, owner, "count", value.count, structureSize);
    checkField(diagnostics, owner, "pointer", value.pointer, structureSize);
    const std::size_t offset = index * 2 * pointerSize;
    if (!value.count.present || !value.pointer.present || value.count.offset != offset ||
        value.count.size != countSize || value.pointer.offset != offset + pointerSize ||
        value.pointer.size != pointerSize) {
        validationError(
            diagnostics,
            "invalid-registration-table",
            std::string(owner) + "." + std::string(name) + " does not match its confirmed count/pointer pair");
    }
}

void expect(
    std::vector<Legacy21Diagnostic>& diagnostics,
    bool condition,
    std::string code,
    std::string message) {
    if (!condition) validationError(diagnostics, std::move(code), std::move(message));
}

bool sameField(const Legacy21FieldLayout& actual, const Legacy21FieldLayout& expected) {
    return actual.present == expected.present && actual.offset == expected.offset &&
        actual.size == expected.size;
}

} // namespace

Legacy21Layout makeLegacy21Layout(Legacy21Variant variant, std::size_t pointerSize) {
    if (variant != Legacy21Variant::Unity535 && variant != Legacy21Variant::Unity54) {
        throw std::invalid_argument("Unknown IL2CPP v21 layout variant");
    }
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP v21 native pointer size must be 4 or 8 bytes");
    }

    Legacy21Layout layout;
    layout.variant = variant;
    layout.pointerSize = pointerSize;
    if (variant == Legacy21Variant::Unity535) {
        layout.fieldOffsetStorage = Legacy21FieldOffsetStorage::FlatInt32;
        layout.typeDefinitionSizeStorage = Legacy21TypeDefinitionSizeStorage::InlineRecords;
        layout.fieldOffsetElementSize = 4;
        layout.typeDefinitionSizeElementSize = 16;
        layout.vtable = {
            Legacy21VTableKind::MethodInfoPointers,
            pointerSize,
            field(0, pointerSize),
            absentField()
        };
    } else {
        layout.fieldOffsetStorage = Legacy21FieldOffsetStorage::PerTypePointers;
        layout.typeDefinitionSizeStorage = Legacy21TypeDefinitionSizeStorage::PointerArray;
        layout.fieldOffsetElementSize = pointerSize;
        layout.typeDefinitionSizeElementSize = pointerSize;
        layout.vtable = {
            Legacy21VTableKind::VirtualInvokeData,
            2 * pointerSize,
            field(0, pointerSize),
            field(pointerSize, pointerSize)
        };
    }
    layout.classLayout = makeClass(variant, pointerSize);
    layout.methodInfo = makeMethodInfo(pointerSize);
    layout.codeRegistration = makeCodeRegistration(variant, pointerSize);
    layout.metadataRegistration = makeMetadataRegistration(pointerSize);
    return layout;
}

bool Legacy21DetectionResult::ok() const noexcept {
    return status == Legacy21DetectionStatus::Confirmed && layout.has_value();
}

Legacy21DetectionResult detectLegacy21Layout(
    const Legacy21DetectionEvidence& evidence,
    std::size_t pointerSize) {
    Legacy21DetectionResult result;
    if (pointerSize != 4 && pointerSize != 8) {
        addDiagnostic(
            result,
            Legacy21DetectionStatus::Unsupported,
            "unsupported-pointer-size",
            "IL2CPP v21 requires an explicit 32-bit or 64-bit ABI; pointer size " +
                std::to_string(pointerSize) + " is unsupported");
        return result;
    }
    if (evidence.metadataVersion != 21) {
        addDiagnostic(
            result,
            Legacy21DetectionStatus::Unsupported,
            "unsupported-metadata-version",
            "Legacy21 detector requires metadata version 21, got " + std::to_string(evidence.metadataVersion));
        return result;
    }
    if ((evidence.fieldOffsets && !valid(*evidence.fieldOffsets)) ||
        (evidence.typeDefinitionSizes && !valid(*evidence.typeDefinitionSizes)) ||
        (evidence.vtable && !valid(*evidence.vtable)) ||
        (evidence.reversePInvokeName && !valid(*evidence.reversePInvokeName))) {
        addDiagnostic(
            result,
            Legacy21DetectionStatus::ConflictingEvidence,
            "invalid-abi-evidence",
            "ABI evidence contains an unknown enumeration value");
        return result;
    }

    std::optional<Legacy21Variant> versionVariant;
    if (!evidence.unityVersion.empty()) {
        const auto parsed = parseUnityVersion(evidence.unityVersion);
        if (!parsed.valid) {
            addDiagnostic(
                result,
                Legacy21DetectionStatus::Unsupported,
                "invalid-unity-version",
                "Unity version must identify an exact patch release, for example 5.3.5f1 or 5.4.4f1: " +
                    evidence.unityVersion);
            return result;
        }
        if (!parsed.supported) {
            addDiagnostic(
                result,
                Legacy21DetectionStatus::Unsupported,
                "unsupported-unity-version",
                "No requested confirmed layout for Unity " + evidence.unityVersion +
                    "; supported v21 variants are 5.3.5 and 5.4.4-5.4.6");
            return result;
        }
        versionVariant = parsed.variant;
    }

    const bool completeNativeEvidence =
        evidence.fieldOffsets && evidence.typeDefinitionSizes && evidence.vtable;
    const bool oldNativeLayout = completeNativeEvidence &&
        *evidence.fieldOffsets == Legacy21FieldOffsetStorage::FlatInt32 &&
        *evidence.typeDefinitionSizes == Legacy21TypeDefinitionSizeStorage::InlineRecords &&
        *evidence.vtable == Legacy21VTableKind::MethodInfoPointers;
    const bool perTypeNativeLayout = completeNativeEvidence &&
        *evidence.fieldOffsets == Legacy21FieldOffsetStorage::PerTypePointers &&
        *evidence.typeDefinitionSizes == Legacy21TypeDefinitionSizeStorage::PointerArray &&
        *evidence.vtable == Legacy21VTableKind::VirtualInvokeData;

    std::optional<Legacy21Variant> structuralVariant;
    if (oldNativeLayout &&
        (!evidence.hasGenericRecursionDepth || !*evidence.hasGenericRecursionDepth)) {
        structuralVariant = Legacy21Variant::Unity535;
    } else if (perTypeNativeLayout && evidence.hasGenericRecursionDepth &&
               *evidence.hasGenericRecursionDepth) {
        structuralVariant = Legacy21Variant::Unity54;
    }

    if (versionVariant) {
        std::string mismatch;
        if (!matches(evidence, *versionVariant, mismatch)) {
            addDiagnostic(
                result,
                Legacy21DetectionStatus::ConflictingEvidence,
                "conflicting-v21-evidence",
                "Unity version selects " + std::string(toString(*versionVariant)) + " but " + mismatch);
            return result;
        }
        confirm(result, *versionVariant, pointerSize, "exact-unity-version");
        return result;
    }

    if (structuralVariant) {
        std::string mismatch;
        if (!matches(evidence, *structuralVariant, mismatch)) {
            addDiagnostic(
                result,
                Legacy21DetectionStatus::ConflictingEvidence,
                "conflicting-v21-evidence",
                "Native layout selects " + std::string(toString(*structuralVariant)) + " but " + mismatch);
            return result;
        }
        confirm(result, *structuralVariant, pointerSize, "complete-matching-abi-evidence");
        return result;
    }

    if (hasEvidence(evidence)) {
        const bool flatVirtualIntermediate = completeNativeEvidence &&
            *evidence.fieldOffsets == Legacy21FieldOffsetStorage::FlatInt32 &&
            *evidence.typeDefinitionSizes == Legacy21TypeDefinitionSizeStorage::InlineRecords &&
            *evidence.vtable == Legacy21VTableKind::VirtualInvokeData;
        const bool storageConflict =
            evidence.fieldOffsets && evidence.typeDefinitionSizes &&
            ((*evidence.fieldOffsets == Legacy21FieldOffsetStorage::FlatInt32) !=
             (*evidence.typeDefinitionSizes == Legacy21TypeDefinitionSizeStorage::InlineRecords));
        const bool perTypeWithOldVtable = evidence.vtable &&
            *evidence.vtable == Legacy21VTableKind::MethodInfoPointers &&
            ((evidence.fieldOffsets && *evidence.fieldOffsets == Legacy21FieldOffsetStorage::PerTypePointers) ||
             (evidence.typeDefinitionSizes &&
              *evidence.typeDefinitionSizes == Legacy21TypeDefinitionSizeStorage::PointerArray));
        const bool genericDepthConflict = evidence.hasGenericRecursionDepth &&
            *evidence.hasGenericRecursionDepth &&
            ((evidence.fieldOffsets && *evidence.fieldOffsets == Legacy21FieldOffsetStorage::FlatInt32) ||
             (evidence.typeDefinitionSizes &&
              *evidence.typeDefinitionSizes == Legacy21TypeDefinitionSizeStorage::InlineRecords) ||
             (evidence.vtable && *evidence.vtable == Legacy21VTableKind::MethodInfoPointers));
        if (storageConflict || perTypeWithOldVtable || genericDepthConflict) {
            addDiagnostic(
                result,
                Legacy21DetectionStatus::ConflictingEvidence,
                "conflicting-v21-evidence",
                "Field offsets, type definition sizes, vtable and class-field observations do not form a confirmed v21 ABI");
        } else if (flatVirtualIntermediate) {
            addDiagnostic(
                result,
                Legacy21DetectionStatus::Ambiguous,
                "unconfirmed-intermediate-v21-layout",
                "Flat offsets, inline sizes and VirtualInvokeData match intermediate 5.3.6-5.4.0 layouts, "
                "not either confirmed variant; an exact supported Unity version is required");
        } else if (perTypeNativeLayout && !evidence.hasGenericRecursionDepth) {
            addDiagnostic(
                result,
                Legacy21DetectionStatus::Ambiguous,
                "ambiguous-late-v21-class-layout",
                "Per-type offsets and VirtualInvokeData do not establish the Il2CppClass scalar layout; "
                "provide genericRecursionDepth presence or an exact 5.4.4-5.4.6 version");
        } else if (perTypeNativeLayout && evidence.hasGenericRecursionDepth &&
                   !*evidence.hasGenericRecursionDepth) {
            addDiagnostic(
                result,
                Legacy21DetectionStatus::Ambiguous,
                "unconfirmed-intermediate-v21-layout",
                "Per-type offsets and VirtualInvokeData without genericRecursionDepth match earlier v21 layouts, "
                "not the confirmed 5.4.4-5.4.6 variant");
        } else {
            addDiagnostic(
                result,
                Legacy21DetectionStatus::Ambiguous,
                "ambiguous-v21-abi",
                "Incomplete ABI evidence cannot select a confirmed layout; provide field offsets, type definition "
                "sizes, vtable kind and genericRecursionDepth presence, or an exact supported Unity version");
        }
        return result;
    }

    addDiagnostic(
        result,
        Legacy21DetectionStatus::InsufficientEvidence,
        "insufficient-v21-evidence",
        "Metadata version 21 alone does not select an ABI; no Unity version or native layout evidence was supplied");
    return result;
}

Legacy21DetectionResult detectLegacy21Layout(std::string_view unityVersion, std::size_t pointerSize) {
    Legacy21DetectionEvidence evidence;
    evidence.unityVersion = std::string(unityVersion);
    return detectLegacy21Layout(evidence, pointerSize);
}

Legacy21DetectionResult Legacy21Detector::detect(const Legacy21DetectionEvidence& evidence) const {
    return detectLegacy21Layout(evidence, pointerSize_);
}

Legacy21DetectionResult Legacy21Detector::detect(std::string_view unityVersion) const {
    return detectLegacy21Layout(unityVersion, pointerSize_);
}

std::vector<Legacy21Diagnostic> validateLegacy21Layout(const Legacy21Layout& layout) {
    std::vector<Legacy21Diagnostic> diagnostics;
    if (layout.pointerSize != 4 && layout.pointerSize != 8) {
        validationError(diagnostics, "unsupported-pointer-size", "Native pointer size must be 4 or 8 bytes");
        return diagnostics;
    }
    if (layout.variant != Legacy21Variant::Unity535 && layout.variant != Legacy21Variant::Unity54) {
        validationError(diagnostics, "unsupported-v21-variant", "Unknown IL2CPP v21 layout variant");
        return diagnostics;
    }

    const std::size_t pointerSize = layout.pointerSize;
    const bool old = layout.variant == Legacy21Variant::Unity535;
    const auto expected = makeLegacy21Layout(layout.variant, pointerSize);
    expect(
        diagnostics,
        layout.fieldOffsetStorage == (old ? Legacy21FieldOffsetStorage::FlatInt32
                                         : Legacy21FieldOffsetStorage::PerTypePointers),
        "invalid-field-offset-storage",
        "Field offset storage does not match the selected v21 variant");
    expect(
        diagnostics,
        layout.typeDefinitionSizeStorage == (old ? Legacy21TypeDefinitionSizeStorage::InlineRecords
                                                : Legacy21TypeDefinitionSizeStorage::PointerArray),
        "invalid-type-size-storage",
        "Type definition size storage does not match the selected v21 variant");
    expect(
        diagnostics,
        layout.fieldOffsetElementSize == (old ? 4 : pointerSize) &&
            layout.typeDefinitionSizeRecordSize == 16 &&
            layout.typeDefinitionSizeElementSize == (old ? 16 : pointerSize),
        "invalid-registration-element-size",
        "Field offset or type definition size element stride is incorrect");

    const auto expectedVtable = old ? Legacy21VTableKind::MethodInfoPointers : Legacy21VTableKind::VirtualInvokeData;
    expect(
        diagnostics,
        layout.vtable.kind == expectedVtable && layout.vtable.elementSize == (old ? pointerSize : 2 * pointerSize) &&
            sameField(layout.vtable.methodPointer, expected.vtable.methodPointer) &&
            sameField(layout.vtable.methodInfo, expected.vtable.methodInfo),
        "invalid-vtable-layout",
        "Vtable element layout does not match MethodInfo pointers or VirtualInvokeData for the selected variant");

    const auto& klass = layout.classLayout;
    const std::size_t classSize = pointerSize == 4 ? 184 : 272;
    const std::size_t cctorThread = pointerSize == 4 ? 104 : 192;
    const std::size_t sizes = pointerSize == 4 ? 120 : 208;
    const std::size_t counts = sizes + 36;
    const std::size_t bytes = counts + 16;
    expect(
        diagnostics,
        klass.size == classSize && klass.alignment == 8 && klass.vtable.offset == 18 * pointerSize &&
            klass.interfaceOffsets.offset == 19 * pointerSize && klass.typeHierarchy.offset == 22 * pointerSize &&
            klass.cctorStarted.offset == 23 * pointerSize && klass.cctorThread.offset == cctorThread &&
            klass.instanceSize.offset == sizes && klass.token.offset == sizes + 32 &&
            klass.methodCount.offset == counts && klass.interfaceOffsetsCount.offset == counts + 14 &&
            klass.typeHierarchyDepth.offset == bytes && klass.genericRecursionDepth.present == !old &&
            klass.rank.offset == bytes + (old ? 1 : 2) && klass.bitfield.offset == bytes + (old ? 4 : 5),
        "invalid-class-layout",
        "Il2CppClass size, alignment, scalar offsets or late-5.4 genericRecursionDepth are incorrect");

    const Legacy21FieldLayout classFields[] = {
        klass.vtable, klass.interfaceOffsets, klass.typeHierarchy, klass.cctorStarted, klass.cctorFinished,
        klass.cctorThread, klass.genericContainerIndex, klass.customAttributeIndex, klass.instanceSize,
        klass.actualSize, klass.elementSize, klass.nativeSize, klass.staticFieldsSize,
        klass.threadStaticFieldsSize, klass.threadStaticFieldsOffset, klass.flags, klass.token,
        klass.methodCount, klass.propertyCount, klass.fieldCount, klass.eventCount, klass.nestedTypeCount,
        klass.vtableCount, klass.interfacesCount, klass.interfaceOffsetsCount, klass.typeHierarchyDepth,
        klass.genericRecursionDepth, klass.rank, klass.minimumAlignment, klass.packingSize, klass.bitfield
    };
    const auto& expectedClass = expected.classLayout;
    const Legacy21FieldLayout expectedClassFields[] = {
        expectedClass.vtable, expectedClass.interfaceOffsets, expectedClass.typeHierarchy,
        expectedClass.cctorStarted, expectedClass.cctorFinished, expectedClass.cctorThread,
        expectedClass.genericContainerIndex, expectedClass.customAttributeIndex,
        expectedClass.instanceSize, expectedClass.actualSize, expectedClass.elementSize,
        expectedClass.nativeSize, expectedClass.staticFieldsSize, expectedClass.threadStaticFieldsSize,
        expectedClass.threadStaticFieldsOffset, expectedClass.flags, expectedClass.token,
        expectedClass.methodCount, expectedClass.propertyCount, expectedClass.fieldCount,
        expectedClass.eventCount, expectedClass.nestedTypeCount, expectedClass.vtableCount,
        expectedClass.interfacesCount, expectedClass.interfaceOffsetsCount,
        expectedClass.typeHierarchyDepth, expectedClass.genericRecursionDepth, expectedClass.rank,
        expectedClass.minimumAlignment, expectedClass.packingSize, expectedClass.bitfield
    };
    for (std::size_t index = 0; index < std::size(classFields); ++index) {
        checkField(diagnostics, "Il2CppClass", "field", classFields[index], klass.size);
        if (!sameField(classFields[index], expectedClassFields[index])) {
            validationError(diagnostics, "invalid-class-field", "Il2CppClass field differs from the selected v21 variant");
        }
    }

    const auto& method = layout.methodInfo;
    const std::size_t methodScalar = 8 * pointerSize;
    expect(
        diagnostics,
        method.size == (pointerSize == 4 ? 48 : 80) && method.alignment == pointerSize &&
            method.genericMethod.offset == 7 * pointerSize && method.customAttributeIndex.offset == methodScalar &&
            method.token.offset == methodScalar + 4 && method.flags.offset == methodScalar + 8 &&
            method.slot.offset == methodScalar + 12 && method.parametersCount.offset == methodScalar + 14 &&
            method.methodFlags.offset == methodScalar + 15,
        "invalid-method-info-layout",
        "MethodInfo pointer and scalar offsets do not match the confirmed v21 layout");
    const Legacy21FieldLayout methodFields[] = {
        method.methodPointer, method.invokerMethod, method.name, method.declaringType, method.returnType,
        method.parameters, method.rgctxData, method.genericMethod, method.customAttributeIndex, method.token,
        method.flags, method.iflags, method.slot, method.parametersCount, method.methodFlags
    };
    const auto& expectedMethod = expected.methodInfo;
    const Legacy21FieldLayout expectedMethodFields[] = {
        expectedMethod.methodPointer, expectedMethod.invokerMethod, expectedMethod.name,
        expectedMethod.declaringType, expectedMethod.returnType, expectedMethod.parameters,
        expectedMethod.rgctxData, expectedMethod.genericMethod, expectedMethod.customAttributeIndex,
        expectedMethod.token, expectedMethod.flags, expectedMethod.iflags, expectedMethod.slot,
        expectedMethod.parametersCount, expectedMethod.methodFlags
    };
    for (std::size_t index = 0; index < std::size(methodFields); ++index) {
        checkField(diagnostics, "MethodInfo", "field", methodFields[index], method.size);
        if (!sameField(methodFields[index], expectedMethodFields[index])) {
            validationError(diagnostics, "invalid-method-info-field", "MethodInfo field differs from the selected v21 variant");
        }
    }

    const auto& code = layout.codeRegistration;
    expect(
        diagnostics,
        code.size == 18 * pointerSize && code.alignment == pointerSize &&
            code.reversePInvokeName == (old ? Legacy21ReversePInvokeName::DelegateWrappersFromNativeToManaged
                                            : Legacy21ReversePInvokeName::ReversePInvokeWrapper),
        "invalid-code-registration-layout",
        "CodeRegistration size or reverse P/Invoke field semantics are incorrect");
    const std::pair<std::string_view, const Legacy21TableLayout*> codeTables[] = {
        {"methodPointers", &code.methodPointers},
        {"reversePInvokeWrappers", &code.reversePInvokeWrappers},
        {"delegateWrappersFromManagedToNative", &code.delegateWrappersFromManagedToNative},
        {"marshalingFunctions", &code.marshalingFunctions},
        {"ccwMarshalingFunctions", &code.ccwMarshalingFunctions},
        {"genericMethodPointers", &code.genericMethodPointers},
        {"invokerPointers", &code.invokerPointers},
        {"customAttributeGenerators", &code.customAttributeGenerators},
        {"guids", &code.guids}
    };
    for (std::size_t index = 0; index < std::size(codeTables); ++index) {
        checkTable(
            diagnostics, "CodeRegistration", codeTables[index].first, *codeTables[index].second,
            index, pointerSize, 4, code.size);
    }

    const auto& metadata = layout.metadataRegistration;
    expect(
        diagnostics,
        metadata.size == 16 * pointerSize && metadata.alignment == pointerSize,
        "invalid-metadata-registration-layout",
        "MetadataRegistration size or alignment is incorrect");
    const std::pair<std::string_view, const Legacy21TableLayout*> metadataTables[] = {
        {"genericClasses", &metadata.genericClasses},
        {"genericInsts", &metadata.genericInsts},
        {"genericMethodTable", &metadata.genericMethodTable},
        {"types", &metadata.types},
        {"methodSpecs", &metadata.methodSpecs},
        {"fieldOffsets", &metadata.fieldOffsets},
        {"typeDefinitionsSizes", &metadata.typeDefinitionsSizes},
        {"metadataUsages", &metadata.metadataUsages}
    };
    for (std::size_t index = 0; index < std::size(metadataTables); ++index) {
        checkTable(
            diagnostics, "MetadataRegistration", metadataTables[index].first, *metadataTables[index].second,
            index, pointerSize, index == 7 ? pointerSize : 4, metadata.size);
    }
    return diagnostics;
}

const char* toString(Legacy21Variant value) noexcept {
    switch (value) {
    case Legacy21Variant::Unity535: return "5.3.5";
    case Legacy21Variant::Unity54: return "5.4.4-5.4.6";
    }
    return "unknown";
}

const char* toString(Legacy21FieldOffsetStorage value) noexcept {
    switch (value) {
    case Legacy21FieldOffsetStorage::FlatInt32: return "flat-int32";
    case Legacy21FieldOffsetStorage::PerTypePointers: return "per-type-pointers";
    }
    return "unknown";
}

const char* toString(Legacy21TypeDefinitionSizeStorage value) noexcept {
    switch (value) {
    case Legacy21TypeDefinitionSizeStorage::InlineRecords: return "inline-records";
    case Legacy21TypeDefinitionSizeStorage::PointerArray: return "pointer-array";
    }
    return "unknown";
}

const char* toString(Legacy21VTableKind value) noexcept {
    switch (value) {
    case Legacy21VTableKind::MethodInfoPointers: return "method-info-pointers";
    case Legacy21VTableKind::VirtualInvokeData: return "virtual-invoke-data";
    }
    return "unknown";
}

const char* toString(Legacy21ReversePInvokeName value) noexcept {
    switch (value) {
    case Legacy21ReversePInvokeName::DelegateWrappersFromNativeToManaged:
        return "delegateWrappersFromNativeToManaged";
    case Legacy21ReversePInvokeName::ReversePInvokeWrapper:
        return "reversePInvokeWrapper";
    }
    return "unknown";
}

const char* toString(Legacy21DetectionStatus value) noexcept {
    switch (value) {
    case Legacy21DetectionStatus::Confirmed: return "confirmed";
    case Legacy21DetectionStatus::InsufficientEvidence: return "insufficient-evidence";
    case Legacy21DetectionStatus::Ambiguous: return "ambiguous";
    case Legacy21DetectionStatus::ConflictingEvidence: return "conflicting-evidence";
    case Legacy21DetectionStatus::Unsupported: return "unsupported";
    }
    return "unknown";
}

} // namespace il2cpprec
