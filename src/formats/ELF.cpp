#include <il2cpprec/formats/ELF.hpp>

#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint8_t elfClass32 = 1;
constexpr uint8_t elfClass64 = 2;
constexpr uint8_t elfDataLittleEndian = 1;
constexpr uint32_t ptLoad = 1;
constexpr uint32_t pfExecute = 1;
constexpr uint16_t pnXnum = 0xffff;

void requireRange(uint64_t offset, uint64_t size, uint64_t total, const char* description) {
    if (offset > total || size > total - offset) {
        throw std::runtime_error(std::string("ELF ") + description + " is outside the file");
    }
}

class Reader {
public:
    explicit Reader(const std::vector<uint8_t>& bytes) : bytes_(bytes) {}

    template <typename T>
    T read(uint64_t offset, const char* description) const {
        static_assert(std::is_unsigned_v<T>);
        requireRange(offset, sizeof(T), bytes_.size(), description);
        T value = 0;
        for (size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<T>(bytes_[static_cast<size_t>(offset + i)]) << (i * 8);
        }
        return value;
    }

private:
    const std::vector<uint8_t>& bytes_;
};

Architecture architectureFor(uint16_t machine, bool is64) {
    switch (machine) {
        case 3:
            if (is64) break;
            return Architecture::X86;
        case 40:
            if (is64) break;
            return Architecture::Arm32;
        case 62:
            if (!is64) break;
            return Architecture::X64;
        case 183:
            if (!is64) break;
            return Architecture::Arm64;
        default:
            throw std::runtime_error("Unsupported ELF machine architecture: " + std::to_string(machine));
    }
    throw std::runtime_error("ELF class does not match its machine architecture");
}

BinaryImage parseELF(std::shared_ptr<std::vector<uint8_t>> bytes) {
    const auto& data = *bytes;
    const uint64_t fileSize = data.size();
    requireRange(0, 16, fileSize, "identification");
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        throw std::runtime_error("Invalid ELF identification magic");
    }
    if (data[4] != elfClass32 && data[4] != elfClass64) {
        throw std::runtime_error("Unsupported ELF class: " + std::to_string(data[4]));
    }
    if (data[5] != elfDataLittleEndian) {
        throw std::runtime_error("Only little-endian ELF files are supported");
    }
    if (data[6] != 1) {
        throw std::runtime_error("Unsupported ELF identification version");
    }

    const bool is64 = data[4] == elfClass64;
    const uint64_t expectedHeaderSize = is64 ? 64 : 52;
    const uint64_t expectedProgramHeaderSize = is64 ? 56 : 32;
    requireRange(0, expectedHeaderSize, fileSize, "header");

    Reader reader(data);
    if (reader.read<uint32_t>(20, "version") != 1) {
        throw std::runtime_error("Unsupported ELF header version");
    }

    const auto architecture = architectureFor(reader.read<uint16_t>(18, "machine"), is64);
    const uint64_t declaredHeaderSize = reader.read<uint16_t>(is64 ? 52 : 40, "header size");
    if (declaredHeaderSize < expectedHeaderSize) {
        throw std::runtime_error("ELF header is smaller than required");
    }
    requireRange(0, declaredHeaderSize, fileSize, "declared header");

    const uint64_t programHeaderOffset = is64
        ? reader.read<uint64_t>(32, "program header offset")
        : reader.read<uint32_t>(28, "program header offset");
    const uint64_t programHeaderEntrySize = reader.read<uint16_t>(is64 ? 54 : 42, "program header entry size");
    const uint64_t programHeaderCount = reader.read<uint16_t>(is64 ? 56 : 44, "program header count");
    if (programHeaderCount == pnXnum) {
        throw std::runtime_error("Extended ELF program header counts are not supported");
    }
    if (programHeaderCount != 0 && programHeaderEntrySize < expectedProgramHeaderSize) {
        throw std::runtime_error("ELF program header entries are smaller than required");
    }
    if (programHeaderCount != 0 && programHeaderEntrySize > std::numeric_limits<uint64_t>::max() / programHeaderCount) {
        throw std::runtime_error("ELF program header table size overflows");
    }
    requireRange(
        programHeaderOffset,
        programHeaderEntrySize * programHeaderCount,
        fileSize,
        "program header table");

    BinaryImage image;
    image.architecture = architecture;
    image.format = BinaryFormat::ELF;
    image.bytes = std::move(bytes);
    image.sections.reserve(static_cast<size_t>(programHeaderCount));

    bool foundLoadSegment = false;
    for (uint64_t i = 0; i < programHeaderCount; ++i) {
        const uint64_t offset = programHeaderOffset + i * programHeaderEntrySize;
        if (reader.read<uint32_t>(offset, "program header type") != ptLoad) {
            continue;
        }

        uint64_t fileOffset;
        uint64_t virtualAddress;
        uint64_t segmentFileSize;
        uint64_t segmentMemorySize;
        uint32_t flags;
        if (is64) {
            flags = reader.read<uint32_t>(offset + 4, "segment flags");
            fileOffset = reader.read<uint64_t>(offset + 8, "segment file offset");
            virtualAddress = reader.read<uint64_t>(offset + 16, "segment virtual address");
            segmentFileSize = reader.read<uint64_t>(offset + 32, "segment file size");
            segmentMemorySize = reader.read<uint64_t>(offset + 40, "segment memory size");
        } else {
            fileOffset = reader.read<uint32_t>(offset + 4, "segment file offset");
            virtualAddress = reader.read<uint32_t>(offset + 8, "segment virtual address");
            segmentFileSize = reader.read<uint32_t>(offset + 16, "segment file size");
            segmentMemorySize = reader.read<uint32_t>(offset + 20, "segment memory size");
            flags = reader.read<uint32_t>(offset + 24, "segment flags");
        }

        if (segmentFileSize > segmentMemorySize) {
            throw std::runtime_error("ELF loadable segment file size exceeds its memory size");
        }
        requireRange(fileOffset, segmentFileSize, fileSize, "loadable segment");
        if (virtualAddress > std::numeric_limits<uint64_t>::max() - segmentMemorySize) {
            throw std::runtime_error("ELF loadable segment virtual address range overflows");
        }
        if (!is64 && virtualAddress + segmentMemorySize > uint64_t{1} << 32) {
            throw std::runtime_error("ELF 32-bit loadable segment extends beyond the address space");
        }

        Section section;
        section.name = "LOAD" + std::to_string(i);
        section.virtualAddress = virtualAddress;
        section.virtualSize = segmentMemorySize;
        section.fileOffset = fileOffset;
        section.fileSize = segmentFileSize;
        section.executable = (flags & pfExecute) != 0;
        image.sections.push_back(std::move(section));

        if (!foundLoadSegment || virtualAddress < image.imageBase) {
            image.imageBase = virtualAddress;
        }
        foundLoadSegment = true;
    }

    if (!foundLoadSegment) {
        throw std::runtime_error("ELF contains no loadable segments");
    }
    return image;
}

} // namespace

BinaryImage ELFLoader::load(const std::vector<uint8_t>& bytes) const {
    return parseELF(std::make_shared<std::vector<uint8_t>>(bytes));
}

BinaryImage ELFLoader::load(const uint8_t* bytes, size_t size) const {
    if (bytes == nullptr && size != 0) {
        throw std::invalid_argument("ELF input buffer is null");
    }
    auto ownedBytes = std::make_shared<std::vector<uint8_t>>();
    if (size != 0) {
        ownedBytes->assign(bytes, bytes + size);
    }
    return parseELF(std::move(ownedBytes));
}

} // namespace il2cpprec
