#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>
#include <il2cpprec/versions/Version108.hpp>
#include <il2cpprec/versions/Version110.hpp>

namespace il2cpprec {

struct Version111Header {
    static constexpr size_t sectionCount = 44;
    static constexpr size_t serializedSize = 8 + sectionCount * 12;

    int32_t version = 0;
    MetadataSectionsModel sections;
    Version108IndexWidths indices;

    size_t recordStride(const MetadataSectionModel& section) const;
    static size_t indexWidth(int32_t count);
};

class Version111 {
public:
    static bool supports(double version) noexcept;
    static bool supports(int32_t rawVersion) noexcept;

    static Version111Header readHeader(const std::vector<uint8_t>& data);
    static Version111Header readHeader(const uint8_t* data, size_t size);

    MetadataModel read(const std::vector<uint8_t>& data) const;
    MetadataModel read(const uint8_t* data, size_t size) const;
    MetadataModel readFile(const std::string& path) const;
};

} // namespace il2cpprec
