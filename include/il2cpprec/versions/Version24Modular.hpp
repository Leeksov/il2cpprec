#pragma once

#include <il2cpprec/Model.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace il2cpprec::versions {

enum class Version24ModularVariant {
    V24_2,
    V24_3
};

enum class Version24MetadataRegistrationPair : size_t {
    GenericClasses = 0,
    GenericInsts = 1,
    GenericMethodTable = 2,
    Types = 3,
    MethodSpecs = 4,
    FieldOffsets = 5,
    TypeDefinitionsSizes = 6,
    MetadataUsages = 7
};

struct Version24ModularLayout {
    static constexpr size_t noPair = static_cast<size_t>(-1);

    Version24ModularVariant variant = Version24ModularVariant::V24_2;
    size_t pointerSize = 0;
    size_t reversePInvokeWrappersPair = 0;
    size_t genericMethodPointersPair = 1;
    size_t invokerPointersPair = 2;
    size_t customAttributeGeneratorsPair = 3;
    size_t unresolvedVirtualCallPointersPair = 4;
    size_t interopDataPair = 5;
    size_t windowsRuntimeFactoryPair = noPair;
    size_t codeGenModulesPair = 6;
    size_t codeRegistrationSize = 0;
    size_t codeGenModuleSize = 0;

    static Version24ModularLayout make(Version24ModularVariant variant, size_t pointerSize);
    double version() const noexcept;
    bool hasWindowsRuntimeFactory() const noexcept;
};

struct Version24RegistrationPair {
    uint64_t count = 0;
    uint64_t address = 0;
};

struct Version24CodeGenModule {
    uint64_t address = 0;
    std::string name;
    std::vector<uint64_t> methodPointers;
    std::vector<int32_t> invokerIndices;
    Version24RegistrationPair reversePInvokeWrapperIndices;
    std::vector<RgctxRangeModel> rgctxRanges;
    std::vector<RgctxValueModel> rgctxValues;
    uint64_t debuggerMetadata = 0;
};

struct Version24ModularResult {
    bool detected = false;
    Version24ModularLayout layout;
    uint64_t codeRegistrationAddress = 0;
    uint64_t metadataRegistrationAddress = 0;
    std::array<Version24RegistrationPair, 8> codeRegistrationPairs{};
    std::array<Version24RegistrationPair, 8> metadataRegistrationPairs{};
    std::vector<uint64_t> genericMethodPointers;
    std::vector<uint64_t> invokerPointers;
    std::vector<Version24CodeGenModule> modules;
    std::vector<std::string> diagnostics;

    bool ok() const noexcept;
    const Version24CodeGenModule* findModule(std::string_view imageName) const noexcept;
    std::optional<uint64_t> methodPointer(std::string_view imageName, uint32_t methodDefToken) const;
};

std::optional<uint32_t> version24MethodDefRid(uint32_t token) noexcept;
std::optional<size_t> version24MethodDefIndex(uint32_t token) noexcept;

class Version24Modular {
public:
    static bool supports(double metadataVersion) noexcept;
    static std::optional<Version24ModularVariant> variantFor(double metadataVersion) noexcept;

    Version24ModularResult inspect(
        const BinaryImage& binary,
        uint64_t codeRegistrationAddress,
        std::optional<Version24ModularVariant> expected = std::nullopt,
        uint64_t metadataRegistrationAddress = 0) const;

    Version24ModularResult detect(
        const BinaryImage& binary,
        uint64_t codeRegistrationAddress = 0,
        std::optional<double> expectedVersion = std::nullopt,
        uint64_t metadataRegistrationAddress = 0) const;

    Version24ModularResult apply(
        const BinaryImage& binary,
        MetadataModel& metadata,
        uint64_t codeRegistrationAddress = 0,
        uint64_t metadataRegistrationAddress = 0) const;
};

} // namespace il2cpprec::versions
