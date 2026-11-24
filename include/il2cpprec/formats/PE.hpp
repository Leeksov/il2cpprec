#pragma once

#include <memory>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

BinaryImage parsePE(std::shared_ptr<std::vector<uint8_t>> bytes);
BinaryImage loadPE(const std::string& path);

} // namespace il2cpprec
