#pragma once

#include <il2cpprec/Model.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace il2cpprec {

struct Version108IndexWidths {
    size_t type = 4;
    size_t typeDefinition = 4;
    size_t methodDefinition = 4;
    size_t genericInst = 4;
    size_t methodSpec = 4;
    size_t genericMethodPointer = 4;
    size_t invoker = 4;
    size_t adjustorThunk = 4;
};

struct Version108Header {
    static constexpr size_t sectionCount = 41;
    static constexpr size_t serializedSize = 8 + sectionCount * 12;

    int32_t version = 0;
    MetadataSectionsModel sections;
    Version108IndexWidths indices;

    size_t recordStride(const MetadataSectionModel& section) const;
    static size_t indexWidth(int32_t count);
};

struct Version108NativeTable {
    uint64_t count = 0;
    uint64_t address = 0;
};

struct Version108Layout {
    size_t pointerSize = 0;
    size_t codeRegistrationSize = 0;
    size_t metadataRegistrationSize = 0;
    size_t codeGenModuleSize = 0;
    size_t genericAdjustorThunksOffset = 0;
    size_t invokerPointersCountOffset = 0;
    size_t invokerPointersOffset = 0;
    size_t codeGenModulesCountOffset = 0;
    size_t codeGenModulesOffset = 0;
    size_t adjustorThunkCountOffset = 0;
    size_t adjustorThunksOffset = 0;
};

struct Version108CodeRegistration {
    Version108NativeTable reversePInvokeWrappers;
    Version108NativeTable genericMethodPointers;
    uint64_t genericAdjustorThunks = 0;
    Version108NativeTable invokerPointers;
    Version108NativeTable unresolvedVirtualCallPointers;
    uint64_t unresolvedInstanceCallPointers = 0;
    uint64_t unresolvedStaticCallPointers = 0;
    Version108NativeTable interopData;
    Version108NativeTable windowsRuntimeFactoryTable;
    Version108NativeTable codeGenModules;
};

struct Version108MetadataRegistration {
    Version108NativeTable genericClasses;
    Version108NativeTable genericInsts;
    Version108NativeTable types;
    Version108NativeTable fieldOffsets;
    Version108NativeTable typeDefinitionsSizes;
    Version108NativeTable metadataUsages;
    Version108NativeTable alwaysInitMetadataUsages;
};

enum class Version108MethodPointerKind {
    Ordinary,
    Adjustor,
    AdjustorThunk = Adjustor,
    Invoker
};

struct Version108CodeGenModule {
    std::string name;
    uint64_t address = 0;
    std::vector<uint64_t> methodPointers;
    std::vector<int32_t> invokerIndices;
    std::unordered_map<uint32_t, uint64_t> adjustorThunks;
    Version108NativeTable reversePInvokeWrapperIndices;
    uint64_t debuggerMetadata = 0;
    uint64_t moduleInitializer = 0;
    uint64_t metadataRegistration = 0;
    uint64_t codeRegistration = 0;
};

struct Version108Registration {
    Version108Layout layout;
    uint64_t codeRegistrationAddress = 0;
    uint64_t metadataRegistrationAddress = 0;
    Version108CodeRegistration codeRegistration;
    Version108MetadataRegistration metadataRegistration;
    std::vector<uint64_t> genericMethodPointers;
    std::vector<uint64_t> genericAdjustorThunks;
    std::vector<uint64_t> invokerPointers;
    std::unordered_map<std::string, Version108CodeGenModule> modules;
    std::vector<GenericMethodPointerModel> genericMethodTable;

    uint64_t select(
        std::string_view imageName,
        uint32_t methodToken,
        Version108MethodPointerKind kind = Version108MethodPointerKind::Ordinary) const noexcept;
    uint64_t select(
        const GenericMethodPointerModel& method,
        Version108MethodPointerKind kind = Version108MethodPointerKind::Ordinary) const noexcept;
};

class Version108 {
public:
    explicit Version108(size_t pointerSize = 0);

    static bool supports(double version) noexcept;
    static bool supports(int32_t rawVersion) noexcept;
    static size_t pointerSize(const BinaryImage& binary);
    static Version108Layout makeLayout(size_t pointerSize);

    Version108Layout layout() const;

    static Version108Header readHeader(const std::vector<uint8_t>& data);
    static Version108Header readHeader(const uint8_t* data, size_t size);

    MetadataModel read(const std::vector<uint8_t>& data) const;
    MetadataModel read(const uint8_t* data, size_t size) const;
    MetadataModel readFile(const std::string& path) const;

    Version108CodeRegistration readCodeRegistration(
        const BinaryImage& binary,
        uint64_t address) const;
    Version108MetadataRegistration readMetadataRegistration(
        const BinaryImage& binary,
        uint64_t address) const;

    Version108Registration readRegistration(
        const BinaryImage& binary,
        MetadataModel& metadata,
        uint64_t metadataRegistrationAddress,
        uint64_t codeRegistrationAddress) const;

    static void validateRgctxRanges(
        const std::vector<RgctxRangeModel>& ranges,
        size_t valueCount);

private:
    size_t pointerSize_;
};

} // namespace il2cpprec
