#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec::versions {

struct Version27Layout {
    static constexpr size_t codeRegistrationSlotCount = 14;
    static constexpr size_t codeGenModuleSlotCount = 16;
    static constexpr size_t rgctxRangeSize = 12;
    static constexpr size_t rgctxDefinitionSize = 8;
    static constexpr size_t customAttributeTypeRangeSize = 12;

    size_t pointerSize = 0;
    size_t typeSize = 0;
    size_t codeRegistrationSize = 0;
    size_t codeGenModuleSize = 0;
    size_t genericClassTypeOffset = 0;
    size_t genericClassClassInstOffset = 0;
    size_t genericClassMethodInstOffset = 0;
    size_t genericClassCachedClassOffset = 0;
    size_t genericClassSize = 0;
    size_t methodPointerCountOffset = 0;
    size_t methodPointersOffset = 0;
    size_t invokerIndicesOffset = 0;
    size_t rgctxRangesCountOffset = 0;
    size_t rgctxRangesOffset = 0;
    size_t rgctxsCountOffset = 0;
    size_t rgctxsOffset = 0;
    size_t customAttributeCacheGeneratorOffset = 0;
    size_t metadataRegistrationOffset = 0;
    size_t codeRegistrationOffset = 0;
};

struct Version27TypeBits {
    uint16_t attrs = 0;
    uint8_t type = 0;
    uint8_t numMods = 0;
    bool byRef = false;
    bool pinned = false;
};

struct Version27Type {
    uint64_t address = 0;
    uint64_t data = 0;
    uint32_t bits = 0;
    Version27TypeBits decoded;
};

struct Version27GenericClass {
    uint64_t address = 0;
    uint64_t typeAddress = 0;
    int32_t definitionIndex = -1;
    uint64_t classInstAddress = 0;
    uint64_t methodInstAddress = 0;
    uint64_t cachedClassAddress = 0;

    GenericClassModel toModel() const;
};

struct Version27NativeTable {
    uint64_t count = 0;
    uint64_t address = 0;
};

struct Version27CodeRegistration {
    uint64_t address = 0;
    Version27NativeTable reversePInvokeWrappers;
    Version27NativeTable genericMethodPointers;
    Version27NativeTable invokerPointers;
    Version27NativeTable unresolvedVirtualCallPointers;
    Version27NativeTable interopData;
    Version27NativeTable windowsRuntimeFactoryTable;
    Version27NativeTable codeGenModules;
};

struct Version27CodeGenModule {
    uint64_t address = 0;
    std::string name;
    std::vector<uint64_t> methodPointers;
    std::vector<int32_t> invokerIndices;
    Version27NativeTable reversePInvokeWrapperIndices;
    std::vector<RgctxRangeModel> rgctxRanges;
    std::vector<RgctxValueModel> rgctxValues;
    uint64_t debuggerMetadata = 0;
    uint64_t customAttributeCacheGenerator = 0;
    uint64_t moduleInitializer = 0;
    uint64_t staticConstructorTypeIndicesAddress = 0;
    uint64_t metadataRegistrationAddress = 0;
    uint64_t codeRegistrationAddress = 0;
};

struct Version27CustomAttributeTypeRange {
    uint32_t token = 0;
    int32_t start = 0;
    int32_t count = 0;
};

struct Version27CustomAttributeGenerators {
    int32_t imageStart = 0;
    std::vector<uint64_t> addresses;
};

enum class Version27MethodPointerKind {
    Ordinary,
    Invoker
};

struct Version27Registration {
    Version27Layout layout;
    uint64_t codeRegistrationAddress = 0;
    Version27CodeRegistration codeRegistration;
    std::vector<uint64_t> genericMethodPointers;
    std::vector<uint64_t> invokerPointers;
    std::vector<Version27CodeGenModule> modules;

    const Version27CodeGenModule* findModule(std::string_view imageName) const noexcept;
    std::optional<uint64_t> methodPointer(std::string_view imageName, uint32_t methodDefToken) const noexcept;
    uint64_t select(
        std::string_view imageName,
        uint32_t methodDefToken,
        Version27MethodPointerKind kind = Version27MethodPointerKind::Ordinary) const noexcept;
};

class Version27Base {
public:
    static bool supports(int32_t rawVersion) noexcept;
    static bool supports(double metadataVersion) noexcept;
    static size_t pointerSize(const BinaryImage& binary);
    static Version27Layout layout(size_t pointerSize);
    static std::optional<size_t> methodPointerIndex(uint32_t token) noexcept;

    static Version27CodeRegistration readCodeRegistration(
        const BinaryImage& binary,
        uint64_t address,
        size_t pointerSize = 0);
    static Version27TypeBits decodeTypeBits(uint32_t bits) noexcept;
    static Version27Type readType(
        const BinaryImage& binary,
        uint64_t address,
        size_t pointerSize = 0);
    static Version27GenericClass readGenericClass(
        const BinaryImage& binary,
        uint64_t address,
        size_t pointerSize = 0);
    static std::vector<Version27GenericClass> readGenericClasses(
        const BinaryImage& binary,
        uint64_t address,
        uint64_t count,
        size_t pointerSize = 0);

    static std::vector<RgctxRangeModel> readRgctxRanges(
        const BinaryImage& binary,
        uint64_t address,
        uint64_t count,
        size_t pointerSize = 0);
    static std::vector<RgctxValueModel> readRgctxDefinitions(
        const BinaryImage& binary,
        uint64_t address,
        uint64_t count,
        size_t pointerSize = 0);
    static void validateRgctxRanges(
        const std::vector<RgctxRangeModel>& ranges,
        size_t definitionCount);

    static Version27CodeGenModule readCodeGenModule(
        const BinaryImage& binary,
        uint64_t address,
        size_t pointerSize = 0);
    static std::vector<Version27CodeGenModule> readCodeGenModules(
        const BinaryImage& binary,
        uint64_t address,
        uint64_t count,
        size_t pointerSize = 0);
    static Version27Registration read(
        const BinaryImage& binary,
        uint64_t codeRegistrationAddress,
        size_t pointerSize = 0);

    static std::vector<Version27CustomAttributeTypeRange> readCustomAttributeTypeRanges(
        const BinaryImage& binary,
        uint64_t address,
        uint64_t count,
        size_t pointerSize = 0);
    static void validateCustomAttributeTypeRanges(
        const std::vector<Version27CustomAttributeTypeRange>& ranges,
        size_t attributeTypeCount);
    static Version27CustomAttributeGenerators readCustomAttributeGenerators(
        const BinaryImage& binary,
        const Version27CodeGenModule& module,
        int32_t imageStart,
        uint32_t imageCount,
        size_t pointerSize = 0);
};

} // namespace il2cpprec::versions

namespace il2cpprec {

using versions::Version27Base;
using versions::Version27CodeGenModule;
using versions::Version27CodeRegistration;
using versions::Version27CustomAttributeGenerators;
using versions::Version27CustomAttributeTypeRange;
using versions::Version27GenericClass;
using versions::Version27Layout;
using versions::Version27MethodPointerKind;
using versions::Version27NativeTable;
using versions::Version27Registration;
using versions::Version27Type;
using versions::Version27TypeBits;

} // namespace il2cpprec
