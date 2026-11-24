#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

class GlobalMetadata {
public:
    MetadataModel read(const std::vector<uint8_t>& data) const;
    MetadataModel read(const uint8_t* data, size_t size) const;
    MetadataModel readFile(const std::string& path) const;
};

} // namespace il2cpprec
