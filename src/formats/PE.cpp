#include <il2cpprec/formats/PE.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint16_t kDosSignature = 0x5a4d;
constexpr uint32_t kNtSignature = 0x00004550;
constexpr uint16_t kMachineX86 = 0x014c;
constexpr uint16_t kMachineArm = 0x01c0;
constexpr uint16_t kMachineThumb = 0x01c2;
constexpr uint16_t kMachineArmNt = 0x01c4;
constexpr uint16_t kMachineX64 = 0x8664;
constexpr uint16_t kMachineArm64 = 0xaa64;
constexpr uint16_t kPe32Magic = 0x010b;
constexpr uint16_t kPe32PlusMagic = 0x020b;
constexpr uint32_t kExecutableSection = 0x20000000;
constexpr size_t kFileHeaderSize = 20;
constexpr size_t kSectionHeaderSize = 40;

void requireRange(size_t offset, size_t size, size_t fileSize, const char* description) {
    if (offset > fileSize || size > fileSize - offset) {
        throw std::invalid_argument(std::string("PE ") + description + " is outside the file");
    }
}

uint16_t readU16(const std::vector<uint8_t>& bytes, size_t offset) {
    requireRange(offset, 2, bytes.size(), "field");
    return static_cast<uint16_t>(bytes[offset]) |
           (static_cast<uint16_t>(bytes[offset + 1]) << 8);
}

uint32_t readU32(const std::vector<uint8_t>& bytes, size_t offset) {
    requireRange(offset, 4, bytes.size(), "field");
    return static_cast<uint32_t>(bytes[offset]) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

uint64_t readU64(const std::vector<uint8_t>& bytes, size_t offset) {
    return static_cast<uint64_t>(readU32(bytes, offset)) |
           (static_cast<uint64_t>(readU32(bytes, offset + 4)) << 32);
}

size_t checkedTableSize(uint16_t count, size_t entrySize) {
    const auto result = static_cast<size_t>(count) * entrySize;
    if (count != 0 && result / count != entrySize) {
        throw std::invalid_argument("PE section table size overflows");
    }
    return result;
}

bool is32BitMachine(uint16_t machine) {
    return machine == kMachineX86 || machine == kMachineArm ||
           machine == kMachineThumb || machine == kMachineArmNt;
}

bool is64BitMachine(uint16_t machine) {
    return machine == kMachineX64 || machine == kMachineArm64;
}

Architecture architectureFor(uint16_t machine) {
    switch (machine) {
        case kMachineX86: return Architecture::X86;
        case kMachineArm:
        case kMachineThumb:
        case kMachineArmNt: return Architecture::Arm32;
        case kMachineX64: return Architecture::X64;
        case kMachineArm64: return Architecture::Arm64;
        default: throw std::invalid_argument("PE machine architecture is unsupported");
    }
}

} // namespace

BinaryImage parsePE(std::shared_ptr<std::vector<uint8_t>> bytes) {
    if (!bytes) {
        throw std::invalid_argument("PE input is null");
    }

    const auto& data = *bytes;
    requireRange(0, 64, data.size(), "DOS header");
    if (readU16(data, 0) != kDosSignature) {
        throw std::invalid_argument("PE input has an invalid DOS signature");
    }

    const auto ntOffsetValue = readU32(data, 0x3c);
    if (ntOffsetValue > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
        throw std::invalid_argument("PE NT header offset is negative");
    }
    const auto ntOffset = static_cast<size_t>(ntOffsetValue);
    requireRange(ntOffset, 4 + kFileHeaderSize, data.size(), "NT headers");
    if (readU32(data, ntOffset) != kNtSignature) {
        throw std::invalid_argument("PE input has an invalid NT signature");
    }

    const auto fileHeader = ntOffset + 4;
    const auto machine = readU16(data, fileHeader);
    const auto sectionCount = readU16(data, fileHeader + 2);
    const auto optionalHeaderSize = readU16(data, fileHeader + 16);
    if (sectionCount == 0) {
        throw std::invalid_argument("PE image has no sections");
    }
    const auto architecture = architectureFor(machine);
    const bool is64 = is64BitMachine(machine);
    if (!is64 && !is32BitMachine(machine)) {
        throw std::invalid_argument("PE machine architecture is unsupported");
    }

    const auto optionalHeader = fileHeader + kFileHeaderSize;
    requireRange(optionalHeader, optionalHeaderSize, data.size(), "optional header");
    if (optionalHeaderSize < 32) {
        throw std::invalid_argument("PE optional header is too small");
    }

    const auto optionalMagic = readU16(data, optionalHeader);
    const auto expectedMagic = is64 ? kPe32PlusMagic : kPe32Magic;
    if (optionalMagic != expectedMagic) {
        throw std::invalid_argument("PE optional header does not match its machine architecture");
    }

    BinaryImage image;
    image.format = BinaryFormat::PE;
    image.architecture = architecture;
    image.imageBase = is64
        ? readU64(data, optionalHeader + 24)
        : readU32(data, optionalHeader + 28);

    const auto sectionTable = optionalHeader + optionalHeaderSize;
    requireRange(sectionTable, checkedTableSize(sectionCount, kSectionHeaderSize), data.size(),
                 "section table");
    image.bytes = std::move(bytes);
    image.sections.reserve(sectionCount);

    for (uint16_t i = 0; i < sectionCount; ++i) {
        const auto header = sectionTable + static_cast<size_t>(i) * kSectionHeaderSize;
        Section section;
        for (size_t j = 0; j < 8 && data[header + j] != 0; ++j) {
            section.name.push_back(static_cast<char>(data[header + j]));
        }
        section.virtualSize = readU32(data, header + 8);
        section.virtualAddress = readU32(data, header + 12);
        section.fileSize = readU32(data, header + 16);
        section.fileOffset = readU32(data, header + 20);
        section.executable = (readU32(data, header + 36) & kExecutableSection) != 0;

        if (section.fileOffset > data.size() || section.fileSize > data.size() - section.fileOffset) {
            throw std::invalid_argument("PE section data is outside the file");
        }
        if (section.virtualAddress > std::numeric_limits<uint64_t>::max() - image.imageBase) {
            throw std::invalid_argument("PE section virtual address overflows");
        }
        const uint64_t sectionStart = image.imageBase + section.virtualAddress;
        const uint64_t virtualSize = section.virtualSize != 0 ? section.virtualSize : section.fileSize;
        if (virtualSize > std::numeric_limits<uint64_t>::max() - sectionStart) {
            throw std::invalid_argument("PE section virtual address range overflows");
        }
        if (!is64 && sectionStart + virtualSize > uint64_t{1} << 32) {
            throw std::invalid_argument("PE 32-bit section extends beyond the address space");
        }
        image.sections.push_back(std::move(section));
    }

    return image;
}

BinaryImage loadPE(const std::string& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        throw std::runtime_error("Cannot open PE file: " + path);
    }

    const auto end = stream.tellg();
    if (end < 0 || static_cast<uint64_t>(end) > std::numeric_limits<size_t>::max() ||
        static_cast<uint64_t>(end) > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("Cannot determine PE file size: " + path);
    }
    auto bytes = std::make_shared<std::vector<uint8_t>>(static_cast<size_t>(end));
    stream.seekg(0, std::ios::beg);
    if (!bytes->empty()) {
        stream.read(reinterpret_cast<char*>(bytes->data()), static_cast<std::streamsize>(bytes->size()));
    }
    if (!stream) {
        throw std::runtime_error("Cannot read PE file: " + path);
    }
    return parsePE(std::move(bytes));
}

} // namespace il2cpprec
