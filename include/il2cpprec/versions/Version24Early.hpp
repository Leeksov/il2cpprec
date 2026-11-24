#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace il2cpprec::versions {

inline constexpr std::uint32_t metadata24Sanity = 0xFAB11BAFU;

enum class Version24EarlyKind : std::uint8_t {
    V24_0,
    V24_1
};

struct Version24EarlyField {
    std::string_view name;
    std::uint32_t offset;
    std::uint32_t size;
};

struct Version24EarlyTable {
    char code;
    std::string_view name;
    std::uint32_t headerOffset;
    std::uint32_t stride;
    std::span<const Version24EarlyField> fields;
};

struct Version24EarlyHeader {
    std::uint32_t size;
    std::uint32_t customAttributeRangesOffset;
};

struct Version24EarlyCodeRegistrationPair {
    std::uint32_t countOffset;
    std::uint32_t pointerOffset;
};

struct Version24EarlyCodeRegistration {
    std::size_t pointerSize = 0;
    std::size_t size = 0;
    Version24EarlyCodeRegistrationPair methodPointers{};
    Version24EarlyCodeRegistrationPair reversePInvokeWrappers{};
    Version24EarlyCodeRegistrationPair genericMethodPointers{};
    Version24EarlyCodeRegistrationPair invokerPointers{};
    Version24EarlyCodeRegistrationPair customAttributeGenerators{};
    Version24EarlyCodeRegistrationPair unresolvedVirtualCallPointers{};
    Version24EarlyCodeRegistrationPair interopData{};
    bool genericAdjustorThunks = false;
    bool windowsRuntimeFactoryTable = false;
    bool codeGenModules = false;
};

struct Version24EarlyProfile {
    Version24EarlyKind kind;
    double version;
    std::string_view name;
    Version24EarlyHeader header;
    std::span<const std::uint32_t> acceptedHeaderSizes;
    Version24EarlyTable typeDefinitions;
    Version24EarlyTable methods;
    Version24EarlyTable parameters;
    Version24EarlyTable fields;
    Version24EarlyTable images;
    Version24EarlyTable assemblies;
    Version24EarlyTable rgctxEntries;
    bool globalMethodIndex;
    std::uint32_t methodIndexOffset;
    std::uint32_t imageTokenOffset;
    bool imageTokenMustBeOne;
    bool imageCustomAttributes;
    std::uint32_t imageCustomAttributeStartOffset;
    std::uint32_t imageCustomAttributeCountOffset;
};

struct Version24EarlyValidation {
    const Version24EarlyProfile* profile = nullptr;
    std::vector<std::string> errors;

    bool ok() const noexcept { return profile != nullptr && errors.empty(); }
    explicit operator bool() const noexcept { return ok(); }
};

const Version24EarlyProfile& version24_0Profile() noexcept;
const Version24EarlyProfile& version24_1Profile() noexcept;
const Version24EarlyProfile& unity2017Profile() noexcept;
std::span<const Version24EarlyProfile* const> version24EarlyProfiles() noexcept;

const Version24EarlyProfile* findVersion24EarlyProfile(double version) noexcept;
const Version24EarlyProfile* detectVersion24EarlyProfile(std::span<const std::uint8_t> metadata) noexcept;

Version24EarlyCodeRegistration makeVersion24EarlyCodeRegistration(std::size_t pointerSize) noexcept;
std::vector<std::string> validateVersion24EarlyCodeRegistration(
    const Version24EarlyCodeRegistration& layout);
std::vector<std::string> validateVersion24EarlyProfile(const Version24EarlyProfile& profile);

Version24EarlyValidation validateVersion24EarlyMetadata(
    const Version24EarlyProfile& profile,
    std::span<const std::uint8_t> metadata);
Version24EarlyValidation validateVersion24EarlyMetadata(std::span<const std::uint8_t> metadata);

} // namespace il2cpprec::versions
