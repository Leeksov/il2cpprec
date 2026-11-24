#pragma once

#include <il2cpprec/Model.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace il2cpprec {

class MachOLoader {
public:
    static BinaryImage load(const std::string& path);
    static BinaryImage parse(std::shared_ptr<std::vector<uint8_t>> bytes);
    static BinaryImage parse(const std::vector<uint8_t>& bytes);
};

} // namespace il2cpprec
