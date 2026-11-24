#pragma once

#include <il2cpprec/Model.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace il2cpprec::versions {

struct Version24AssemblyDefinition {
    int32_t imageIndex = 0;
    uint32_t token = 0;
    int32_t referencedAssemblyStart = 0;
    int32_t referencedAssemblyCount = 0;
    uint32_t nameIndex = 0;
    uint32_t cultureIndex = 0;
    uint32_t publicKeyIndex = 0;
    uint32_t hashAlgorithm = 0;
    int32_t hashLength = 0;
    uint32_t flags = 0;
    int32_t major = 0;
    int32_t minor = 0;
    int32_t build = 0;
    int32_t revision = 0;
    uint8_t publicKeyToken[8]{};
};

struct Version24TypeDefinition {
    uint32_t nameIndex = 0;
    uint32_t namespaceIndex = 0;
    int32_t byvalTypeIndex = 0;
    int32_t byrefTypeIndex = 0;
    int32_t declaringTypeIndex = 0;
    int32_t parentIndex = 0;
    int32_t elementTypeIndex = 0;
    int32_t genericContainerIndex = 0;
    uint32_t flags = 0;
    int32_t fieldStart = 0;
    int32_t methodStart = 0;
    int32_t eventStart = 0;
    int32_t propertyStart = 0;
    int32_t nestedTypesStart = 0;
    int32_t interfacesStart = 0;
    int32_t vtableStart = 0;
    int32_t interfaceOffsetsStart = 0;
    uint16_t methodCount = 0;
    uint16_t propertyCount = 0;
    uint16_t fieldCount = 0;
    uint16_t eventCount = 0;
    uint16_t nestedTypeCount = 0;
    uint16_t vtableCount = 0;
    uint16_t interfacesCount = 0;
    uint16_t interfaceOffsetsCount = 0;
    uint32_t bitfield = 0;
    uint32_t token = 0;
};

static_assert(sizeof(Version24AssemblyDefinition) == 64);
static_assert(sizeof(Version24TypeDefinition) == 92);

struct Version24Layout {
    double version = 24.4;
    size_t pointerSize = 8;
    size_t assemblyDefinitionSize = 64;
    size_t typeDefinitionSize = 92;
    size_t codeRegistrationSize = 0;
    size_t codeGenModuleSize = 0;
    size_t genericMethodRowSize = 0;
    size_t tokenAdjustorThunkPairSize = 0;
    size_t genericMethodPointersCountOffset = 0;
    size_t genericMethodPointersOffset = 0;
    std::optional<size_t> genericAdjustorThunksOffset;
    size_t invokerPointersCountOffset = 0;
    size_t invokerPointersOffset = 0;
    size_t codeGenModulesCountOffset = 0;
    size_t codeGenModulesOffset = 0;
    size_t methodPointerCountOffset = 0;
    size_t methodPointersOffset = 0;
    std::optional<size_t> adjustorThunkCountOffset;
    std::optional<size_t> adjustorThunksOffset;
    size_t invokerIndicesOffset = 0;
};

struct Version24NativeTable {
    uint64_t count = 0;
    uint64_t address = 0;
};

struct Version24CodeRegistration {
    Version24NativeTable reversePInvokeWrappers;
    Version24NativeTable genericMethodPointers;
    uint64_t genericAdjustorThunks = 0;
    Version24NativeTable invokerPointers;
    Version24NativeTable customAttributeGenerators;
    Version24NativeTable unresolvedVirtualCallPointers;
    Version24NativeTable interopData;
    Version24NativeTable windowsRuntimeFactoryTable;
    Version24NativeTable codeGenModules;
};

struct Version24AdjustorCodeGenModule {
    std::string name;
    uint64_t address = 0;
    std::vector<uint64_t> methodPointers;
    std::unordered_map<uint32_t, uint64_t> adjustorThunks;
    std::vector<int32_t> invokerIndices;
};

struct Version24GenericMethodFunctionsDefinition {
    int32_t genericMethodIndex = -1;
    int32_t methodIndex = -1;
    int32_t invokerIndex = -1;
    int32_t adjustorThunkIndex = -1;
    uint64_t methodPointer = 0;
    uint64_t invokerPointer = 0;
    uint64_t adjustorThunk = 0;
};

enum class Version24MethodPointerKind {
    Ordinary,
    Adjustor,
    AdjustorThunk = Adjustor,
    Invoker
};

struct Version24Registration {
    Version24Layout layout;
    uint64_t codeRegistrationAddress = 0;
    uint64_t genericMethodTableAddress = 0;
    Version24CodeRegistration codeRegistration;
    std::vector<uint64_t> genericMethodPointers;
    std::vector<uint64_t> genericAdjustorThunks;
    std::vector<uint64_t> invokerPointers;
    std::unordered_map<std::string, Version24AdjustorCodeGenModule> modules;
    std::vector<Version24GenericMethodFunctionsDefinition> genericMethodTable;

    uint64_t select(
        std::string_view imageName,
        uint32_t methodToken,
        Version24MethodPointerKind kind = Version24MethodPointerKind::Ordinary) const noexcept;
    uint64_t select(
        const Version24GenericMethodFunctionsDefinition& method,
        Version24MethodPointerKind kind = Version24MethodPointerKind::Ordinary) const noexcept;
};

class Version24Adjustor {
public:
    explicit Version24Adjustor(double version, size_t pointerSize = 0);

    static bool supports(double version) noexcept;
    static size_t pointerSize(const BinaryImage& binary);
    static Version24Layout makeLayout(double version, size_t pointerSize);

    Version24Layout layout() const;

    Version24Registration read(
        const BinaryImage& binary,
        uint64_t codeRegistrationAddress,
        uint64_t genericMethodTableAddress = 0,
        uint64_t genericMethodTableCount = 0) const;

    static Version24AssemblyDefinition readAssemblyDefinition(const uint8_t* data, size_t size);
    static Version24TypeDefinition readTypeDefinition(const uint8_t* data, size_t size);

private:
    double version_;
    size_t pointerSize_;
};

} // namespace il2cpprec::versions

namespace il2cpprec {

using versions::Version24Adjustor;
using versions::Version24AdjustorCodeGenModule;
using versions::Version24AssemblyDefinition;
using versions::Version24CodeRegistration;
using versions::Version24GenericMethodFunctionsDefinition;
using versions::Version24Layout;
using versions::Version24MethodPointerKind;
using versions::Version24NativeTable;
using versions::Version24Registration;
using versions::Version24TypeDefinition;

} // namespace il2cpprec
