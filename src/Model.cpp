#include <il2cpprec/Model.hpp>

#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>

namespace il2cpprec {
namespace {

uint64_t fileBackedSize(const Section& section) {
    if (section.virtualSize == 0) return section.fileSize;
    return std::min(section.fileSize, section.virtualSize);
}

std::optional<uint64_t> mapAddressDirect(const BinaryImage& image, uint64_t virtualAddress) {
    for (const auto& section : image.sections) {
        if (virtualAddress < section.virtualAddress) continue;
        const auto offset = virtualAddress - section.virtualAddress;
        if (offset >= fileBackedSize(section)) continue;
        if (section.fileOffset > std::numeric_limits<uint64_t>::max() - offset) {
            throw std::overflow_error("Binary image VA-to-file mapping overflows");
        }
        return section.fileOffset + offset;
    }
    return std::nullopt;
}

} // namespace

uint64_t BinaryImage::mapVATR(uint64_t virtualAddress) const {
    if (format == BinaryFormat::PE && imageBase != 0 && virtualAddress >= imageBase) {
        if (const auto offset = mapAddressDirect(*this, virtualAddress - imageBase)) return *offset;
    }
    if (const auto offset = mapAddressDirect(*this, virtualAddress)) return *offset;

    if (format != BinaryFormat::PE && imageBase != 0) {
        if (virtualAddress >= imageBase) {
            if (const auto offset = mapAddressDirect(*this, virtualAddress - imageBase)) return *offset;
        }
        if (virtualAddress <= std::numeric_limits<uint64_t>::max() - imageBase) {
            if (const auto offset = mapAddressDirect(*this, imageBase + virtualAddress)) return *offset;
        }
    }
    throw std::out_of_range("Virtual address is not backed by a file range");
}

uint64_t BinaryImage::mapRTVA(uint64_t fileOffset) const {
    for (const auto& section : sections) {
        if (fileOffset < section.fileOffset) continue;
        const auto offset = fileOffset - section.fileOffset;
        if (offset >= fileBackedSize(section)) continue;
        if (section.virtualAddress > std::numeric_limits<uint64_t>::max() - offset) {
            throw std::overflow_error("Binary image file-to-VA mapping overflows");
        }
        return section.virtualAddress + offset;
    }
    throw std::out_of_range("File offset is not backed by a virtual address range");
}

const uint8_t* BinaryImage::data(uint64_t fileOffset, size_t size) const {
    if (!bytes) throw std::invalid_argument("Binary image has no file data");
    if (fileOffset > bytes->size() || size > bytes->size() - static_cast<size_t>(fileOffset)) {
        throw std::out_of_range("Binary image read is outside the file");
    }
    return bytes->data() + static_cast<size_t>(fileOffset);
}

} // namespace il2cpprec
