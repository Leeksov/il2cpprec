#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

struct Version110MethodRange {
    int32_t ordinaryStart = -1;
    uint32_t ordinaryCount = 0;
    int32_t generatedStart = -1;
    uint32_t generatedCount = 0;
};

struct Version110Header {
    static constexpr size_t sectionCount = 43;
    static constexpr size_t serializedSize = 8 + sectionCount * 12;

    int32_t version = 0;
    MetadataSectionsModel sections;
    size_t typeIndexWidth = 0;
    size_t typeDefinitionIndexWidth = 0;
    size_t methodDefinitionIndexWidth = 0;
};

class Version110 {
public:
    static constexpr uint32_t HasGeneratedMethods = 1U << 19;

    static bool supports(double version) noexcept;
    static bool supports(int32_t rawVersion) noexcept;
    static Version110Header readHeader(const std::vector<uint8_t>& data);
    static Version110Header readHeader(const uint8_t* data, size_t size);
    MetadataModel read(const std::vector<uint8_t>& data) const;
    MetadataModel read(const uint8_t* data, size_t size) const;
    MetadataModel readFile(const std::string& path) const;

    static bool hasGeneratedMethods(uint32_t bitfield) noexcept;
    static bool hasGeneratedMethods(const TypeModel& type) noexcept;

    static int32_t generatedMethodsStart(size_t methodDefinitionCount, size_t generatedMethodTokenCount);

    static void readGeneratedMethodTables(
        const uint8_t* data,
        size_t size,
        size_t methodDefinitionCount,
        MetadataModel& metadata);
    static void readGeneratedMethodTables(
        const std::vector<uint8_t>& data,
        size_t methodDefinitionCount,
        MetadataModel& metadata);

    static Version110MethodRange methodRange(
        const MetadataModel& metadata,
        int32_t typeDefinitionIndex,
        int32_t ordinaryMethodStart,
        uint32_t methodCount);
    static int32_t methodIndex(
        const MetadataModel& metadata,
        int32_t typeDefinitionIndex,
        int32_t ordinaryMethodStart,
        uint32_t methodCount,
        uint32_t methodIndexInType);

    static uint32_t methodToken(
        const MetadataModel& metadata,
        const ImageModel& image,
        int32_t typeDefinitionIndex,
        int32_t methodDefinitionIndex);
    static void reconstructMethodTokens(MetadataModel& metadata, size_t methodDefinitionCount);

    static std::optional<size_t> methodPointerIndex(uint32_t token, size_t methodPointerCount) noexcept;
    static std::optional<uint64_t> methodPointer(
        const MetadataModel& metadata,
        const std::string& imageName,
        uint32_t token);
};

} // namespace il2cpprec
