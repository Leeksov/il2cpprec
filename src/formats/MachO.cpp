#include <il2cpprec/formats/MachO.hpp>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace il2cpprec {
namespace {

constexpr uint32_t kMachOMagic64 = 0xfeedfacf;
constexpr uint32_t kMachOMagic = 0xfeedface;
constexpr uint32_t kMachOSwappedMagic64 = 0xcffaedfe;
constexpr uint32_t kMachOSwappedMagic = 0xcefaedfe;
constexpr uint32_t kFatMagic = 0xcafebabe;
constexpr uint32_t kFatCigam = 0xbebafeca;
constexpr uint32_t kFatMagic64 = 0xcafebabf;
constexpr uint32_t kFatCigam64 = 0xbfbafeca;
constexpr uint32_t kCpuTypeArm = 0x0000000c;
constexpr uint32_t kCpuTypeArm64 = 0x0100000c;
constexpr uint32_t kCpuSubtypeArmV7 = 9;
constexpr uint32_t kLoadCommandSegment = 0x1;
constexpr uint32_t kLoadCommandSegment64 = 0x19;
constexpr uint32_t kVmProtectExecute = 0x4;
constexpr uint32_t kSectionType = 0x000000ff;
constexpr uint32_t kSectionTypeZeroFill = 0x1;
constexpr uint32_t kSectionTypeGbZeroFill = 0xc;
constexpr uint32_t kSectionTypeThreadLocalZeroFill = 0x12;
constexpr uint32_t kSectionAttrPureInstructions = 0x80000000;
constexpr uint32_t kSectionAttrSomeInstructions = 0x00000400;
constexpr size_t kMachOHeaderSize = 28;
constexpr size_t kMachOHeader64Size = 32;
constexpr size_t kLoadCommandHeaderSize = 8;
constexpr size_t kSegmentCommandSize = 56;
constexpr size_t kSegmentCommand64Size = 72;
constexpr size_t kSectionSize = 68;
constexpr size_t kSection64Size = 80;
constexpr size_t kFatHeaderSize = 8;
constexpr size_t kFatArchSize = 20;
constexpr size_t kFatArch64Size = 32;

void requireRange(const std::vector<uint8_t>& bytes, size_t offset, size_t size,
                  const std::string& description) {
    if (offset > bytes.size() || size > bytes.size() - offset) {
        throw std::runtime_error("Truncated Mach-O " + description);
    }
}

uint32_t readU32(const std::vector<uint8_t>& bytes, size_t offset, bool littleEndian = true) {
    requireRange(bytes, offset, 4, "field");
    if (littleEndian) {
        return static_cast<uint32_t>(bytes[offset]) |
               (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
               (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
               (static_cast<uint32_t>(bytes[offset + 3]) << 24);
    }
    return (static_cast<uint32_t>(bytes[offset]) << 24) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<uint32_t>(bytes[offset + 3]);
}

uint64_t readU64(const std::vector<uint8_t>& bytes, size_t offset, bool littleEndian = true) {
    if (littleEndian) {
        return static_cast<uint64_t>(readU32(bytes, offset)) |
               (static_cast<uint64_t>(readU32(bytes, offset + 4)) << 32);
    }
    return (static_cast<uint64_t>(readU32(bytes, offset, false)) << 32) |
           static_cast<uint64_t>(readU32(bytes, offset + 4, false));
}

std::string fixedName(const std::vector<uint8_t>& bytes, size_t offset) {
    requireRange(bytes, offset, 16, "name");
    size_t length = 0;
    while (length < 16 && bytes[offset + length] != 0) ++length;
    return std::string(reinterpret_cast<const char*>(bytes.data() + offset), length);
}

struct FatSlice {
    uint64_t offset = 0;
    uint64_t size = 0;
    uint32_t cpuType = 0;
    uint32_t cpuSubtype = 0;
};

FatSlice selectFatSlice(const std::vector<uint8_t>& data, uint32_t magic) {
    const bool is64 = magic == kFatMagic64 || magic == kFatCigam64;
    const bool littleEndian = magic == kFatMagic || magic == kFatMagic64;
    const size_t entrySize = is64 ? kFatArch64Size : kFatArchSize;
    requireRange(data, 0, kFatHeaderSize, "FAT header");

    const uint32_t architectureCount = readU32(data, 4, littleEndian);
    if (architectureCount > (data.size() - kFatHeaderSize) / entrySize) {
        throw std::runtime_error("Truncated Mach-O FAT architecture table");
    }

    int bestScore = 0;
    FatSlice bestSlice;
    for (uint32_t index = 0; index < architectureCount; ++index) {
        const size_t entry = kFatHeaderSize + static_cast<size_t>(index) * entrySize;
        const uint32_t cpuType = readU32(data, entry, littleEndian);
        const uint32_t cpuSubtype = readU32(data, entry + 4, littleEndian);
        int score = 0;
        if (cpuType == kCpuTypeArm64) score = 3;
        if (cpuType == kCpuTypeArm) score = (cpuSubtype & 0xff) == kCpuSubtypeArmV7 ? 2 : 1;
        if (score <= bestScore) continue;

        bestSlice.offset = is64
            ? readU64(data, entry + 8, littleEndian)
            : readU32(data, entry + 8, littleEndian);
        bestSlice.size = is64
            ? readU64(data, entry + 16, littleEndian)
            : readU32(data, entry + 12, littleEndian);
        bestSlice.cpuType = cpuType;
        bestSlice.cpuSubtype = cpuSubtype;
        bestScore = score;
    }

    if (bestScore == 0) {
        throw std::runtime_error("FAT Mach-O contains no ARM64 or ARM32 slice");
    }
    const size_t tableEnd = kFatHeaderSize + static_cast<size_t>(architectureCount) * entrySize;
    if (bestSlice.offset < tableEnd || bestSlice.size < kMachOHeaderSize ||
        bestSlice.offset > data.size() ||
        bestSlice.size > data.size() - static_cast<size_t>(bestSlice.offset)) {
        throw std::runtime_error("Selected Mach-O FAT slice has an invalid file range");
    }
    return bestSlice;
}

bool isZeroFill(uint32_t flags) {
    const uint32_t type = flags & kSectionType;
    return type == kSectionTypeZeroFill || type == kSectionTypeGbZeroFill ||
           type == kSectionTypeThreadLocalZeroFill;
}

BinaryImage parseThin(std::shared_ptr<std::vector<uint8_t>> bytes) {
    const auto& data = *bytes;
    requireRange(data, 0, 4, "header");
    const uint32_t magic = readU32(data, 0);
    if (magic == kMachOSwappedMagic64 || magic == kMachOSwappedMagic) {
        throw std::runtime_error("Big-endian Mach-O binaries are unsupported; expected little-endian");
    }
    if (magic != kMachOMagic64 && magic != kMachOMagic) {
        throw std::runtime_error("Invalid Mach-O magic; expected a thin little-endian image");
    }

    const bool is64 = magic == kMachOMagic64;
    const size_t headerSize = is64 ? kMachOHeader64Size : kMachOHeaderSize;
    requireRange(data, 0, headerSize, is64 ? "64-bit header" : "32-bit header");

    const uint32_t expectedCpuType = is64 ? kCpuTypeArm64 : kCpuTypeArm;
    if (readU32(data, 4) != expectedCpuType) {
        throw std::runtime_error(is64
            ? "Unsupported Mach-O CPU type; expected ARM64"
            : "Unsupported Mach-O CPU type; expected ARM32");
    }

    const uint32_t commandCount = readU32(data, 16);
    const uint32_t commandsSize = readU32(data, 20);
    if (commandsSize > data.size() - headerSize) {
        throw std::runtime_error("Mach-O load commands extend beyond the file");
    }

    size_t cursor = headerSize;
    const size_t commandsEnd = cursor + static_cast<size_t>(commandsSize);
    std::vector<Section> sections;
    uint64_t imageBase = 0;
    bool foundSegment = false;
    bool hasImageBase = false;

    for (uint32_t index = 0; index < commandCount; ++index) {
        if (cursor > commandsEnd || commandsEnd - cursor < kLoadCommandHeaderSize) {
            throw std::runtime_error("Truncated Mach-O load command " + std::to_string(index));
        }

        const uint32_t command = readU32(data, cursor);
        const uint32_t commandSize = readU32(data, cursor + 4);
        const size_t commandAlignment = is64 ? 8 : 4;
        if (commandSize < kLoadCommandHeaderSize || commandSize % commandAlignment != 0) {
            throw std::runtime_error("Invalid Mach-O load command size at index " + std::to_string(index));
        }
        if (commandSize > commandsEnd - cursor) {
            throw std::runtime_error("Mach-O load command extends beyond the command region");
        }

        const uint32_t expectedSegmentCommand = is64 ? kLoadCommandSegment64 : kLoadCommandSegment;
        if (command == expectedSegmentCommand) {
            foundSegment = true;
            const size_t segmentCommandSize = is64 ? kSegmentCommand64Size : kSegmentCommandSize;
            const size_t sectionSize = is64 ? kSection64Size : kSectionSize;
            if (commandSize < segmentCommandSize) {
                throw std::runtime_error("Truncated Mach-O segment command at index " + std::to_string(index));
            }

            const uint32_t sectionCount = readU32(data, cursor + (is64 ? 64 : 48));
            if (sectionCount > (commandSize - segmentCommandSize) / sectionSize) {
                throw std::runtime_error("Mach-O section table exceeds its segment command size");
            }

            const std::string segmentName = fixedName(data, cursor + 8);
            const uint64_t virtualAddress = is64
                ? readU64(data, cursor + 24)
                : readU32(data, cursor + 24);
            const uint64_t virtualSize = is64
                ? readU64(data, cursor + 32)
                : readU32(data, cursor + 28);
            const uint64_t fileOffset = is64
                ? readU64(data, cursor + 40)
                : readU32(data, cursor + 32);
            const uint64_t fileSize = is64
                ? readU64(data, cursor + 48)
                : readU32(data, cursor + 36);
            const uint32_t initialProtection = readU32(data, cursor + (is64 ? 60 : 44));
            const bool segmentExecutable = (initialProtection & kVmProtectExecute) != 0;

            if (virtualSize > std::numeric_limits<uint64_t>::max() - virtualAddress) {
                throw std::runtime_error("Mach-O segment virtual address range overflows");
            }
            if (fileSize > virtualSize) {
                throw std::runtime_error("Mach-O segment file size exceeds its virtual size");
            }
            if (fileOffset > data.size() || fileSize > data.size() - static_cast<size_t>(fileOffset)) {
                throw std::runtime_error("Mach-O segment file range extends beyond the file");
            }

            if (fileSize != 0 && (!hasImageBase || virtualAddress < imageBase)) {
                imageBase = virtualAddress;
                hasImageBase = true;
            }

            if (sectionCount == 0) {
                if (fileSize != 0) {
                    Section section;
                    section.name = segmentName;
                    section.virtualAddress = virtualAddress;
                    section.virtualSize = virtualSize;
                    section.fileOffset = fileOffset;
                    section.fileSize = fileSize;
                    section.executable = segmentExecutable;
                    sections.push_back(std::move(section));
                }
                cursor += commandSize;
                continue;
            }

            for (uint32_t sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
                const size_t sectionOffset = cursor + segmentCommandSize +
                    static_cast<size_t>(sectionIndex) * sectionSize;
                const std::string sectionName = fixedName(data, sectionOffset);
                const uint64_t address = is64
                    ? readU64(data, sectionOffset + 32)
                    : readU32(data, sectionOffset + 32);
                const uint64_t size = is64
                    ? readU64(data, sectionOffset + 40)
                    : readU32(data, sectionOffset + 36);
                const uint64_t rawOffset = readU32(data, sectionOffset + (is64 ? 48 : 40));
                const uint32_t flags = readU32(data, sectionOffset + (is64 ? 64 : 56));

                if (size > std::numeric_limits<uint64_t>::max() - address) {
                    throw std::runtime_error("Mach-O section virtual address range overflows");
                }
                if (address < virtualAddress || address - virtualAddress > virtualSize ||
                    size > virtualSize - (address - virtualAddress)) {
                    throw std::runtime_error("Mach-O section exceeds its segment virtual range");
                }

                Section section;
                section.name = segmentName.empty() ? sectionName : segmentName + "," + sectionName;
                section.virtualAddress = address;
                section.virtualSize = size;
                section.executable = segmentExecutable &&
                    (flags & (kSectionAttrPureInstructions | kSectionAttrSomeInstructions)) != 0;

                if (!isZeroFill(flags)) {
                    if (size != 0) {
                        if (rawOffset > data.size() || size > data.size() - static_cast<size_t>(rawOffset)) {
                            throw std::runtime_error("Mach-O section " + sectionName + " file range extends beyond the file");
                        }
                        if (rawOffset < fileOffset || rawOffset - fileOffset > fileSize ||
                            size > fileSize - (rawOffset - fileOffset)) {
                            throw std::runtime_error("Mach-O section exceeds its segment file range");
                        }
                    }
                    section.fileOffset = rawOffset;
                    section.fileSize = size;
                }
                sections.push_back(std::move(section));
            }
        }

        cursor += commandSize;
    }

    if (cursor != commandsEnd) {
        throw std::runtime_error("Mach-O load commands do not fill their declared region");
    }
    if (!foundSegment || !hasImageBase) {
        throw std::runtime_error("Mach-O contains no file-backed segment");
    }

    BinaryImage image;
    image.architecture = is64 ? Architecture::Arm64 : Architecture::Arm32;
    image.format = BinaryFormat::MachO;
    image.imageBase = imageBase;
    image.bytes = std::move(bytes);
    image.sections = std::move(sections);
    return image;
}

} // namespace

BinaryImage MachOLoader::load(const std::string& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open Mach-O file: " + path);

    const std::streamoff length = stream.tellg();
    if (length < 0) throw std::runtime_error("Cannot determine Mach-O file size: " + path);
    if (static_cast<uint64_t>(length) > std::numeric_limits<size_t>::max() ||
        static_cast<uint64_t>(length) > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("Mach-O file is too large: " + path);
    }

    auto bytes = std::make_shared<std::vector<uint8_t>>(static_cast<size_t>(length));
    stream.seekg(0, std::ios::beg);
    if (!stream) throw std::runtime_error("Cannot seek Mach-O file: " + path);
    if (length != 0) {
        stream.read(reinterpret_cast<char*>(bytes->data()), static_cast<std::streamsize>(length));
        if (!stream) throw std::runtime_error("Cannot read Mach-O file: " + path);
    }
    return parse(std::move(bytes));
}

BinaryImage MachOLoader::parse(const std::vector<uint8_t>& bytes) {
    return parse(std::make_shared<std::vector<uint8_t>>(bytes));
}

BinaryImage MachOLoader::parse(std::shared_ptr<std::vector<uint8_t>> bytes) {
    if (!bytes) throw std::invalid_argument("Mach-O input bytes are null");
    requireRange(*bytes, 0, 4, "header");

    const uint32_t magic = readU32(*bytes, 0);
    const bool isFat = magic == kFatMagic || magic == kFatCigam ||
                       magic == kFatMagic64 || magic == kFatCigam64;
    if (!isFat) return parseThin(std::move(bytes));

    const FatSlice slice = selectFatSlice(*bytes, magic);
    const auto sliceOffset = static_cast<size_t>(slice.offset);
    const uint32_t thinMagic = readU32(*bytes, sliceOffset);
    if (thinMagic != (slice.cpuType == kCpuTypeArm64 ? kMachOMagic64 : kMachOMagic) ||
        readU32(*bytes, sliceOffset + 4) != slice.cpuType ||
        (readU32(*bytes, sliceOffset + 8) & 0x00ffffffu) !=
            (slice.cpuSubtype & 0x00ffffffu)) {
        throw std::runtime_error("Selected Mach-O FAT slice does not match its architecture entry");
    }
    auto sliceBytes = std::make_shared<std::vector<uint8_t>>(
        bytes->begin() + static_cast<std::ptrdiff_t>(slice.offset),
        bytes->begin() + static_cast<std::ptrdiff_t>(slice.offset + slice.size));
    return parseThin(std::move(sliceBytes));
}

} // namespace il2cpprec
