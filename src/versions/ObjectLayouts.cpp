#include <il2cpprec/versions/ObjectLayouts.hpp>

#include <algorithm>
#include <cmath>

namespace il2cpprec::versions {
namespace {

enum class Family {
    Unknown,
    Legacy16,
    Legacy19,
    Unity56,
    V24_0,
    V24_1,
    V24_2,
    V27,
    V29_0,
    V29_1
};

bool near(double left, double right) {
    return std::abs(left - right) < 0.001;
}

bool integerVersion(double version, int expected) {
    return near(version, static_cast<double>(expected));
}

Family familyFor(double version) {
    if (integerVersion(version, 16) || integerVersion(version, 17) || integerVersion(version, 18)) return Family::Legacy16;
    if (integerVersion(version, 19) || integerVersion(version, 20) || integerVersion(version, 21) ||
        integerVersion(version, 22)) return Family::Legacy19;
    if (integerVersion(version, 23)) return Family::Unity56;
    if (near(version, 24.0)) return Family::V24_0;
    if (near(version, 24.1) || near(version, 24.15)) return Family::V24_1;
    if (near(version, 24.2) || near(version, 24.3) || near(version, 24.4) || near(version, 24.5)) return Family::V24_2;
    if (near(version, 27.0) || near(version, 27.1) || near(version, 27.2) || near(version, 27.3)) return Family::V27;
    if (near(version, 29.0)) return Family::V29_0;
    if (near(version, 29.1) || near(version, 29.2) || near(version, 29.3) || near(version, 31.0)) return Family::V29_1;
    return Family::Unknown;
}

NativeFieldLayout field(std::size_t offset, std::size_t size) {
    return {offset, size, true};
}

std::size_t alignUp(std::size_t value, std::size_t alignment) {
    const std::size_t remainder = value % alignment;
    return remainder == 0 ? value : value + alignment - remainder;
}

class ClassBuilder {
public:
    explicit ClassBuilder(std::size_t pointerSize) : pointerSize_(pointerSize), alignment_(pointerSize) {}

    NativeFieldLayout pointer() {
        return bytes(pointerSize_, pointerSize_);
    }

    NativeFieldLayout uint32() {
        return bytes(sizeof(std::uint32_t), sizeof(std::uint32_t));
    }

    NativeFieldLayout uint16() {
        return bytes(sizeof(std::uint16_t), sizeof(std::uint16_t));
    }

    NativeFieldLayout alignedUint64() {
        return bytes(sizeof(std::uint64_t), sizeof(std::uint64_t));
    }

    NativeFieldLayout il2cppType() {
        return bytes(pointerSize_ + sizeof(std::uint32_t), pointerSize_);
    }

    NativeFieldLayout bytes(std::size_t size, std::size_t alignment = 1) {
        cursor_ = alignUp(cursor_, alignment);
        alignment_ = std::max(alignment_, alignment);
        const NativeFieldLayout result = field(cursor_, size);
        cursor_ += size;
        return result;
    }

    void pointers(std::size_t count) {
        for (std::size_t i = 0; i < count; ++i) pointer();
    }

    void uint32s(std::size_t count) {
        for (std::size_t i = 0; i < count; ++i) uint32();
    }

    std::size_t finish() {
        return alignUp(cursor_, alignment_);
    }

    std::size_t alignment() const {
        return alignment_;
    }

private:
    std::size_t pointerSize_;
    std::size_t cursor_ = 0;
    std::size_t alignment_;
};

VtableLayout methodInfoVtable(std::size_t offset, std::size_t pointerSize) {
    VtableLayout result;
    result.form = VtableForm::MethodInfoPointerTable;
    result.offset = offset;
    result.entrySize = pointerSize;
    result.methodInfo = field(0, pointerSize);
    return result;
}

VtableLayout inlineVtable(std::size_t offset, std::size_t pointerSize, bool virtualMethodPointer) {
    VtableLayout result;
    result.form = VtableForm::InlineVirtualInvokeData;
    result.offset = offset;
    result.entrySize = (virtualMethodPointer ? 3 : 2) * pointerSize;
    result.methodPointer = field(0, pointerSize);
    result.methodInfo = field(pointerSize, pointerSize);
    if (virtualMethodPointer) result.virtualMethodPointer = field(2 * pointerSize, pointerSize);
    return result;
}

ClassLayout legacyClass(std::size_t pointerSize, bool token, bool unity56) {
    ClassBuilder builder(pointerSize);
    ClassLayout result;

    builder.pointers(6);
    result.elementClass = builder.pointer();
    builder.pointers(5);
    if (unity56) builder.pointer();
    builder.pointers(6);

    std::size_t oldVtableOffset = 0;
    if (!unity56) oldVtableOffset = builder.pointer().offset;

    result.interfaceOffsets = builder.pointer();
    result.staticFields = builder.pointer();
    builder.pointers(2);

    builder.uint32();
    result.cctorFinished = builder.uint32();
    builder.alignedUint64();
    builder.uint32s(2);

    result.instanceSize = builder.uint32();
    result.actualSize = builder.uint32();
    builder.uint32s(4);
    result.threadStaticFieldsOffset = builder.uint32();
    builder.uint32();
    if (token) builder.uint32();

    builder.bytes(5 * sizeof(std::uint16_t), sizeof(std::uint16_t));
    result.vtableCount = builder.uint16();
    builder.bytes(2 * sizeof(std::uint16_t), sizeof(std::uint16_t));
    builder.bytes(unity56 ? 7 : 6);

    result.size = builder.finish();
    result.alignment = builder.alignment();
    result.vtable = unity56
        ? inlineVtable(result.size, pointerSize, false)
        : methodInfoVtable(oldVtableOffset, pointerSize);
    return result;
}

ClassLayout modernClass(std::size_t pointerSize, Family family, bool virtualMethodPointer) {
    ClassBuilder builder(pointerSize);
    ClassLayout result;

    builder.pointers(4);
    builder.il2cppType();
    builder.il2cppType();
    result.elementClass = builder.pointer();
    builder.pointers(13);
    result.interfaceOffsets = builder.pointer();
    result.staticFields = builder.pointer();
    builder.pointers(2);

    const bool unityUserData = family != Family::V24_0 && family != Family::V24_1;
    const bool initializationException = family != Family::V24_0;
    const bool nativeCctorThread = family != Family::V24_0 && family != Family::V24_1;
    const bool metadataHandles = family == Family::V27 || family == Family::V29_0 || family == Family::V29_1;
    const bool stackSlotSize = family == Family::V29_1;
    const bool naturalAlignment = family == Family::V24_2 || family == Family::V27 || family == Family::V29_0;

    if (unityUserData) builder.pointer();
    if (initializationException) builder.uint32();
    builder.uint32();
    result.cctorFinished = builder.uint32();
    if (nativeCctorThread) {
        builder.pointer();
    } else {
        builder.alignedUint64();
    }

    if (metadataHandles) {
        builder.pointer();
    } else {
        builder.uint32();
    }
    if (family == Family::V24_0 || family == Family::V24_1) builder.uint32();

    result.instanceSize = builder.uint32();
    if (stackSlotSize) builder.uint32();
    result.actualSize = builder.uint32();
    builder.uint32s(4);
    result.threadStaticFieldsOffset = builder.uint32();
    builder.uint32s(2);

    builder.bytes(5 * sizeof(std::uint16_t), sizeof(std::uint16_t));
    result.vtableCount = builder.uint16();
    builder.bytes(2 * sizeof(std::uint16_t), sizeof(std::uint16_t));
    builder.bytes(naturalAlignment ? 8 : 7);

    result.size = builder.finish();
    result.alignment = builder.alignment();
    result.vtable = inlineVtable(result.size, pointerSize, virtualMethodPointer);
    return result;
}

void managedLayouts(ObjectLayoutSelection& result, bool pointerSizedArray) {
    const std::size_t pointerSize = result.pointerSize;
    result.object.size = 2 * pointerSize;
    result.object.klass = field(0, pointerSize);
    result.object.monitor = field(pointerSize, pointerSize);

    result.array.size = 4 * pointerSize;
    result.array.klass = result.object.klass;
    result.array.monitor = result.object.monitor;
    result.array.bounds = field(2 * pointerSize, pointerSize);
    result.array.length = field(3 * pointerSize, pointerSizedArray ? pointerSize : sizeof(std::uint32_t));
    result.array.data = field(4 * pointerSize, 0);
    result.array.dataAlignment = sizeof(std::uint64_t);
    result.array.boundsLength = field(0, result.array.length.size);
    result.array.boundsLowerBound = field(pointerSizedArray ? pointerSize : sizeof(std::uint32_t), sizeof(std::uint32_t));
    result.array.boundsSize = pointerSizedArray ? alignUp(pointerSize + sizeof(std::uint32_t), pointerSize) : 2 * sizeof(std::uint32_t);

    result.string.size = 2 * pointerSize + sizeof(std::uint32_t);
    result.string.klass = result.object.klass;
    result.string.monitor = result.object.monitor;
    result.string.length = field(2 * pointerSize, sizeof(std::uint32_t));
    result.string.chars = field(result.string.size, 0);
}

std::string variantFor(Family family) {
    switch (family) {
    case Family::Legacy16: return "unity-5.2-5.3-methodinfo-vtable";
    case Family::Legacy19: return "unity-5.3-5.5-methodinfo-vtable";
    case Family::Unity56: return "unity-5.6-inline-vtable";
    case Family::V24_0: return "metadata-24.0";
    case Family::V24_1: return "metadata-24.1";
    case Family::V24_2: return "metadata-24.2-24.5";
    case Family::V27: return "metadata-27.x-pointer-array";
    case Family::V29_0: return "metadata-29.0-pointer-array";
    case Family::V29_1: return "metadata-29.1+-31-pointer-array";
    default: return {};
    }
}

ObjectLayoutSelection resolve(double metadataVersion, std::size_t pointerSize, const ObjectLayoutOptions& options) {
    ObjectLayoutSelection result;
    result.metadataVersion = metadataVersion;
    result.pointerSize = pointerSize;
    if (pointerSize != 4 && pointerSize != 8) return result;

    const Family family = familyFor(metadataVersion);
    if (family == Family::Unknown) return result;
    if (options.virtualMethodPointer && (family == Family::Legacy16 || family == Family::Legacy19)) return result;

    result.supported = true;
    result.confidence = options.virtualMethodPointer ? LayoutConfidence::Provisional : LayoutConfidence::Exact;
    result.provisional = options.virtualMethodPointer;
    result.variant = variantFor(family);
    managedLayouts(result, family == Family::V27 || family == Family::V29_0 || family == Family::V29_1);

    switch (family) {
    case Family::Legacy16:
        result.klass = legacyClass(pointerSize, false, false);
        break;
    case Family::Legacy19:
        result.klass = legacyClass(pointerSize, true, false);
        break;
    case Family::Unity56:
        result.klass = legacyClass(pointerSize, true, true);
        break;
    default:
        result.klass = modernClass(pointerSize, family, options.virtualMethodPointer);
        break;
    }
    return result;
}

} // namespace

ObjectLayoutSelection ObjectLayouts::resolve(
    double metadataVersion,
    std::size_t pointerSize,
    const ObjectLayoutOptions& options) {
    return versions::resolve(metadataVersion, pointerSize, options);
}

ObjectLayoutSelection ObjectLayouts::resolve(
    double metadataVersion,
    std::size_t pointerSize,
    bool virtualMethodPointer) {
    return versions::resolve(metadataVersion, pointerSize, ObjectLayoutOptions{virtualMethodPointer});
}

ObjectLayoutSelection resolveObjectLayouts(
    double metadataVersion,
    std::size_t pointerSize,
    const ObjectLayoutOptions& options) {
    return versions::resolve(metadataVersion, pointerSize, options);
}

ObjectLayoutSelection resolveObjectLayouts(
    double metadataVersion,
    std::size_t pointerSize,
    bool virtualMethodPointer) {
    return versions::resolve(metadataVersion, pointerSize, ObjectLayoutOptions{virtualMethodPointer});
}

} // namespace il2cpprec::versions
