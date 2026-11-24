#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

class ELFLoader {
public:
    BinaryImage load(const std::vector<uint8_t>& bytes) const;
    BinaryImage load(const uint8_t* bytes, size_t size) const;
};

} // namespace il2cpprec
