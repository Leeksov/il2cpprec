#include <il2cpprec/formats/BinaryLoader.hpp>

#include <il2cpprec/formats/ELF.hpp>
#include <il2cpprec/formats/MachO.hpp>
#include <il2cpprec/formats/PE.hpp>

#include <fstream>
#include <limits>
#include <stdexcept>

namespace il2cpprec {
namespace {

std::shared_ptr<std::vector<uint8_t>> readBytes(const std::string& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open binary: " + path);
    const auto size = stream.tellg();
    if (size < 0 || static_cast<uint64_t>(size) > std::numeric_limits<size_t>::max() ||
        static_cast<uint64_t>(size) > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("Cannot determine binary file size: " + path);
    }
    auto bytes = std::make_shared<std::vector<uint8_t>>(static_cast<size_t>(size));
    stream.seekg(0, std::ios::beg);
    if (!stream) throw std::runtime_error("Cannot seek binary: " + path);
    if (!bytes->empty()) {
        stream.read(reinterpret_cast<char*>(bytes->data()), static_cast<std::streamsize>(bytes->size()));
    }
    if (!stream) throw std::runtime_error("Cannot read binary: " + path);
    return bytes;
}

uint32_t read32(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 4) return 0;
    return static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8) |
        (static_cast<uint32_t>(bytes[2]) << 16) |
        (static_cast<uint32_t>(bytes[3]) << 24);
}

} // namespace

BinaryImage loadBinary(const std::string& path) {
    const auto bytes = readBytes(path);
    const auto magic = read32(*bytes);
    if ((magic & 0xFFFFu) == 0x5A4Du) return parsePE(bytes);
    if (magic == 0x464C457Fu) return ELFLoader().load(*bytes);
    if (magic == 0xFEEDFACFu || magic == 0xFEEDFACEu ||
        magic == 0xCAFEBABEu || magic == 0xBEBAFECAu ||
        magic == 0xCAFEBABFu || magic == 0xBFBAFECAu) {
        return MachOLoader::parse(bytes);
    }
    throw std::runtime_error("Unsupported binary format: " + path);
}

} // namespace il2cpprec
