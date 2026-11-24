#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec::versions {

enum class Version29Subversion {
    V29_0,
    V29_1
};

struct Version29Layout {
    Version29Subversion subversion = Version29Subversion::V29_0;
    size_t pointerSize = 0;
    size_t codeRegistrationSize = 0;
    size_t unresolvedCallCountOffset = 0;
    size_t unresolvedVirtualCallPointersOffset = 0;
    std::optional<size_t> unresolvedInstanceCallPointersOffset;
    std::optional<size_t> unresolvedStaticCallPointersOffset;
    size_t codeGenModulesCountOffset = 0;
    size_t codeGenModulesOffset = 0;
    size_t genericClassTypeOffset = 0;
    size_t genericClassClassInstOffset = 0;
    size_t genericClassMethodInstOffset = 0;
    size_t genericClassCachedClassOffset = 0;
    size_t genericClassSize = 0;
    size_t genericMethodRowSize = 16;
};

struct Version29TypeBits {
    uint16_t attrs = 0;
    uint8_t type = 0;
    uint8_t numMods = 0;
    bool byRef = false;
    bool pinned = false;
    bool valueType = false;
};

struct Version29Type {
    uint64_t address = 0;
    uint64_t data = 0;
    uint32_t bits = 0;
    Version29TypeBits decoded;
};

struct Version29GenericClass {
    uint64_t address = 0;
    uint64_t typeAddress = 0;
    int32_t definitionIndex = -1;
    uint64_t classInstAddress = 0;
    uint64_t methodInstAddress = 0;
    uint64_t cachedClassAddress = 0;

    GenericClassModel toModel() const;
};

struct Version29CodeRegistration {
    Version29Subversion subversion = Version29Subversion::V29_0;
    uint64_t address = 0;
    uint64_t reversePInvokeWrapperCount = 0;
    uint64_t reversePInvokeWrappersAddress = 0;
    uint64_t genericMethodPointersCount = 0;
    uint64_t genericMethodPointersAddress = 0;
    uint64_t genericAdjustorThunksAddress = 0;
    uint64_t invokerPointersCount = 0;
    uint64_t invokerPointersAddress = 0;
    uint64_t unresolvedCallCount = 0;
    uint64_t unresolvedVirtualCallPointersAddress = 0;
    uint64_t unresolvedInstanceCallPointersAddress = 0;
    uint64_t unresolvedStaticCallPointersAddress = 0;
    uint64_t interopDataCount = 0;
    uint64_t interopDataAddress = 0;
    uint64_t windowsRuntimeFactoryCount = 0;
    uint64_t windowsRuntimeFactoryTableAddress = 0;
    uint64_t codeGenModulesCount = 0;
    uint64_t codeGenModulesAddress = 0;
};

class Version29 {
public:
    static bool supports(int32_t rawVersion);
    static Version29Subversion subversion(double version);
    static Version29Layout layout(Version29Subversion subversion, size_t pointerSize);
    static Version29Layout layout(double version, size_t pointerSize);

    static MetadataVersionModel detect(int32_t rawVersion);
    static MetadataVersionModel detect(
        const BinaryImage& binary,
        int32_t rawVersion,
        uint64_t codeRegistrationAddress,
        size_t pointerSize = 0);

    static Version29CodeRegistration readCodeRegistration(
        const BinaryImage& binary,
        uint64_t address,
        Version29Subversion subversion,
        size_t pointerSize = 0);
    static Version29CodeRegistration readCodeRegistration(
        const BinaryImage& binary,
        uint64_t address,
        double version,
        size_t pointerSize = 0);

    static Version29TypeBits decodeTypeBits(uint32_t bits);
    static Version29Type readType(
        const BinaryImage& binary,
        uint64_t address,
        size_t pointerSize = 0);

    static Version29GenericClass readGenericClass(
        const BinaryImage& binary,
        uint64_t address,
        size_t pointerSize = 0);
    static std::vector<Version29GenericClass> readGenericClasses(
        const BinaryImage& binary,
        uint64_t address,
        uint64_t count,
        size_t pointerSize = 0);

    static GenericMethodPointerModel readGenericMethodRow(
        const BinaryImage& binary,
        uint64_t address);
    static std::vector<GenericMethodPointerModel> readGenericMethodRows(
        const BinaryImage& binary,
        uint64_t address,
        uint64_t count);
};

} // namespace il2cpprec::versions

namespace il2cpprec {

using versions::Version29;
using versions::Version29CodeRegistration;
using versions::Version29GenericClass;
using versions::Version29Layout;
using versions::Version29Subversion;
using versions::Version29Type;
using versions::Version29TypeBits;

} // namespace il2cpprec
