#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec::versions {

enum class Version107Variant {
    Unity65,
    Unity66
};

struct Version104Options {
    double version = 104.0;
    Version107Variant version107Variant = Version107Variant::Unity65;
    std::optional<std::size_t> typeIndexWidth;
};

struct Version104Layout {
    double version = 104.0;
    double registrationVersion = 104.0;
    std::size_t typeIndex = 4;
    bool typeIndexWidthKnown = false;
    std::size_t typeDefinitionIndex = 4;
    std::size_t genericContainerIndex = 4;
    std::size_t parameterIndex = 4;
    std::size_t eventIndex = 4;
    std::size_t interfaceIndex = 4;
    std::size_t nestedTypeIndex = 4;
    std::size_t nestedTypeTableIndex = 4;
    std::size_t propertyIndex = 4;
    std::size_t methodIndex = 4;
    std::size_t genericParameterIndex = 4;
    std::size_t fieldIndex = 4;
    std::size_t defaultValueDataIndex = 4;
    std::size_t typeDefinitionSize = 0;
    std::size_t methodDefinitionSize = 0;
    std::size_t parameterDefinitionSize = 0;
    std::size_t fieldDefinitionSize = 0;
    std::size_t genericParameterSize = 0;
    std::size_t genericContainerSize = 0;
    std::size_t fieldDefaultValueSize = 0;
    std::size_t parameterDefaultValueSize = 0;
    std::size_t eventDefinitionSize = 0;
    std::size_t propertyDefinitionSize = 0;
    std::size_t inlineArraySize = 0;
    std::size_t imageDefinitionSize = 0;
    std::size_t assemblyDefinitionSize = 68;
    bool compactGenericContainers = false;
    bool hasAlwaysInitMetadataUsages = false;
};

struct InlineArrayLengthModel {
    int32_t typeIndex = -1;
    int32_t length = 0;
};

struct EventDefinitionModel {
    uint32_t nameIndex = 0;
    int32_t typeIndex = -1;
    int32_t add = -1;
    int32_t remove = -1;
    int32_t raise = -1;
    uint32_t token = 0;
};

struct PropertyDefinitionModel {
    uint32_t nameIndex = 0;
    int32_t get = -1;
    int32_t set = -1;
    uint32_t attrs = 0;
    uint32_t token = 0;
};

struct InterfaceOffsetModel {
    int32_t typeIndex = -1;
    int32_t offset = 0;
};

struct Version104Metadata : MetadataModel {
    Version104Layout layout;
    std::vector<InlineArrayLengthModel> typeInlineArrays;
    std::vector<EventDefinitionModel> events;
    std::vector<PropertyDefinitionModel> properties;
    std::vector<int32_t> nestedTypes;
    std::vector<int32_t> interfaces;
    std::vector<InterfaceOffsetModel> interfaceOffsets;
};

struct Version104NativeTable {
    uint64_t count = 0;
    uint64_t address = 0;
    bool present = true;
};

struct Version104MetadataRegistration {
    std::size_t pointerSize = 0;
    std::size_t size = 0;
    Version104NativeTable genericClasses;
    Version104NativeTable genericInsts;
    Version104NativeTable genericMethodTable;
    Version104NativeTable types;
    Version104NativeTable methodSpecs;
    Version104NativeTable fieldOffsets;
    Version104NativeTable typeDefinitionsSizes;
    Version104NativeTable metadataUsages;
    Version104NativeTable alwaysInitMetadataUsages{0, 0, false};
};

struct Version104CodeRegistration {
    std::size_t pointerSize = 0;
    std::size_t size = 0;
    Version104NativeTable reversePInvokeWrappers;
    Version104NativeTable genericMethodPointers;
    uint64_t genericAdjustorThunks = 0;
    Version104NativeTable invokerPointers;
    Version104NativeTable unresolvedIndirectCallPointers;
    uint64_t unresolvedInstanceCallPointers = 0;
    uint64_t unresolvedStaticCallPointers = 0;
    Version104NativeTable interopData;
    Version104NativeTable windowsRuntimeFactoryTable;
    Version104NativeTable codeGenModules;
};

struct Version104NativeTables {
    Version104MetadataRegistration metadataRegistration;
    Version104CodeRegistration codeRegistration;
    std::vector<uint64_t> alwaysInitMetadataUsages;
};

class Version104 {
public:
    explicit Version104(Version104Options options = {});
    explicit Version104(double version);

    static bool supports(double version) noexcept;

    const Version104Options& options() const { return options_; }
    double registrationVersion() const noexcept;
    std::size_t metadataRegistrationSize(std::size_t pointerSize) const;
    std::size_t codeRegistrationSize(std::size_t pointerSize) const;

    Version104Layout layout(const MetadataSectionsModel& sections) const;
    Version104Metadata read(const std::vector<uint8_t>& data) const;
    Version104Metadata read(const uint8_t* data, std::size_t size) const;
    Version104Metadata readFile(const std::string& path) const;

    Version104MetadataRegistration readMetadataRegistration(
        const BinaryImage& binary,
        uint64_t address,
        std::size_t pointerSize = 0) const;
    Version104CodeRegistration readCodeRegistration(
        const BinaryImage& binary,
        uint64_t address,
        std::size_t pointerSize = 0) const;
    Version104NativeTables readNative(
        const BinaryImage& binary,
        MetadataModel& metadata,
        uint64_t metadataRegistrationAddress,
        uint64_t codeRegistrationAddress,
        std::size_t pointerSize = 0) const;

private:
    Version104Options options_;
};

using Version104Reader = Version104;

} // namespace il2cpprec::versions

namespace il2cpprec {
using Version104 = versions::Version104;
using Version104Options = versions::Version104Options;
using Version104Metadata = versions::Version104Metadata;
} // namespace il2cpprec
