#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

struct Version38Header {
    static constexpr size_t sectionCount = 31;
    static constexpr size_t serializedSize = 8 + sectionCount * 12;

    int32_t version = 0;
    MetadataSectionsModel sections;
    size_t typeIndexWidth = 4;
    size_t typeDefinitionIndexWidth = 4;
    size_t genericContainerIndexWidth = 4;
    size_t parameterIndexWidth = 4;

    size_t recordStride(const MetadataSectionModel& section) const;
    static size_t indexWidth(int32_t count);
};

class Version38 {
public:
    Version38Header readHeader(const std::vector<uint8_t>& data) const;
    Version38Header readHeader(const uint8_t* data, size_t size) const;

    MetadataModel read(const std::vector<uint8_t>& data) const;
    MetadataModel read(const uint8_t* data, size_t size) const;
    MetadataModel readFile(const std::string& path) const;
};

} // namespace il2cpprec
