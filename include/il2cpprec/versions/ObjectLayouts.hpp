#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace il2cpprec::versions {

enum class LayoutConfidence : uint8_t {
    Unknown,
    Provisional,
    Exact
};

struct NativeFieldLayout {
    std::size_t offset = 0;
    std::size_t size = 0;
    bool present = false;
};

struct ManagedObjectLayout {
    std::size_t size = 0;
    NativeFieldLayout klass;
    NativeFieldLayout monitor;
};

struct ManagedArrayLayout {
    std::size_t size = 0;
    NativeFieldLayout klass;
    NativeFieldLayout monitor;
    NativeFieldLayout bounds;
    NativeFieldLayout length;
    NativeFieldLayout data;
    std::size_t dataAlignment = 0;
    std::size_t boundsSize = 0;
    NativeFieldLayout boundsLength;
    NativeFieldLayout boundsLowerBound;
};

struct ManagedStringLayout {
    std::size_t size = 0;
    NativeFieldLayout klass;
    NativeFieldLayout monitor;
    NativeFieldLayout length;
    NativeFieldLayout chars;
};

enum class VtableForm : uint8_t {
    Absent,
    MethodInfoPointerTable,
    InlineVirtualInvokeData
};

struct VtableLayout {
    VtableForm form = VtableForm::Absent;
    std::size_t offset = 0;
    std::size_t entrySize = 0;
    NativeFieldLayout methodPointer;
    NativeFieldLayout methodInfo;
    NativeFieldLayout virtualMethodPointer;
};

struct ClassLayout {
    std::size_t size = 0;
    std::size_t alignment = 0;
    NativeFieldLayout elementClass;
    NativeFieldLayout interfaceOffsets;
    NativeFieldLayout staticFields;
    NativeFieldLayout threadStaticFieldsOffset;
    NativeFieldLayout cctorFinished;
    NativeFieldLayout instanceSize;
    NativeFieldLayout actualSize;
    NativeFieldLayout vtableCount;
    VtableLayout vtable;
};

struct ObjectLayoutSelection {
    double metadataVersion = 0;
    std::size_t pointerSize = 0;
    bool supported = false;
    LayoutConfidence confidence = LayoutConfidence::Unknown;
    bool provisional = true;
    std::string variant;
    ManagedObjectLayout object;
    ManagedArrayLayout array;
    ManagedStringLayout string;
    ClassLayout klass;
};

struct ObjectLayoutOptions {
    bool virtualMethodPointer = false;
};

class ObjectLayouts {
public:
    static ObjectLayoutSelection resolve(
        double metadataVersion,
        std::size_t pointerSize,
        const ObjectLayoutOptions& options = {});
    static ObjectLayoutSelection resolve(
        double metadataVersion,
        std::size_t pointerSize,
        bool virtualMethodPointer);
};

ObjectLayoutSelection resolveObjectLayouts(
    double metadataVersion,
    std::size_t pointerSize,
    const ObjectLayoutOptions& options = {});
ObjectLayoutSelection resolveObjectLayouts(
    double metadataVersion,
    std::size_t pointerSize,
    bool virtualMethodPointer);

} // namespace il2cpprec::versions
