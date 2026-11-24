#include <il2cpprec/formats/BinaryLoader.hpp>
#include <il2cpprec/formats/ELF.hpp>
#include <il2cpprec/formats/MachO.hpp>
#include <il2cpprec/formats/PE.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using il2cpprec::Architecture;
using il2cpprec::BinaryImage;
using il2cpprec::Section;

void check(bool condition) {
    if (!condition) throw std::runtime_error("format fixture check failed");
}

template <typename Function>
void expectThrow(Function&& function) {
    try {
        function();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("malformed format fixture was accepted");
}

void put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value) {
    bytes[offset] = static_cast<uint8_t>(value);
    bytes[offset + 1] = static_cast<uint8_t>(value >> 8);
}

void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}

void put64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    put32(bytes, offset, static_cast<uint32_t>(value));
    put32(bytes, offset + 4, static_cast<uint32_t>(value >> 32));
}

void put32BE(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) bytes[offset + i] = static_cast<uint8_t>(value >> ((3 - i) * 8));
}

void put64BE(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    put32BE(bytes, offset, static_cast<uint32_t>(value >> 32));
    put32BE(bytes, offset + 4, static_cast<uint32_t>(value));
}

void putName(std::vector<uint8_t>& bytes, size_t offset, const std::string& name) {
    std::copy(name.begin(), name.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
}

std::vector<uint8_t> makeMachO(bool is64, uint32_t subtype) {
    const size_t headerSize = is64 ? 32 : 28;
    const size_t segmentSize = is64 ? 72 : 56;
    const size_t sectionSize = is64 ? 80 : 68;
    const size_t commandSize = segmentSize + 3 * sectionSize;
    const uint64_t imageBase = is64 ? 0x100000000ULL : 0x2000ULL + static_cast<uint64_t>(subtype) * 0x10000;
    std::vector<uint8_t> bytes(0x208, 0);
    put32(bytes, 0, is64 ? 0xfeedfacf : 0xfeedface);
    put32(bytes, 4, is64 ? 0x0100000c : 0x0c);
    put32(bytes, 8, subtype);
    put32(bytes, 12, 2);
    put32(bytes, 16, 1);
    put32(bytes, 20, static_cast<uint32_t>(commandSize));
    const size_t segment = headerSize;
    put32(bytes, segment, is64 ? 0x19 : 0x1);
    put32(bytes, segment + 4, static_cast<uint32_t>(commandSize));
    putName(bytes, segment + 8, "__TEXT");
    if (is64) {
        put64(bytes, segment + 24, imageBase);
        put64(bytes, segment + 32, 0x1000);
        put64(bytes, segment + 40, 0);
        put64(bytes, segment + 48, 0x208);
    } else {
        put32(bytes, segment + 24, static_cast<uint32_t>(imageBase));
        put32(bytes, segment + 28, 0x1000);
        put32(bytes, segment + 32, 0);
        put32(bytes, segment + 36, 0x208);
    }
    put32(bytes, segment + (is64 ? 56 : 40), 5);
    put32(bytes, segment + (is64 ? 60 : 44), 5);
    put32(bytes, segment + (is64 ? 64 : 48), 3);

    const size_t section = segment + segmentSize;
    const char* names[] = {"__text", "__cstring", "__bss"};
    const uint64_t addresses[] = {imageBase + 0x200, imageBase + 0x204, imageBase + 0x300};
    const uint32_t sizes[] = {4, 4, 4};
    const uint32_t offsets[] = {0x200, 0x204, 0};
    const uint32_t flags[] = {0x80000400, 0x2, 0x1};
    for (size_t i = 0; i < 3; ++i) {
        const size_t at = section + i * sectionSize;
        putName(bytes, at, names[i]);
        putName(bytes, at + 16, "__TEXT");
        if (is64) {
            put64(bytes, at + 32, addresses[i]);
            put64(bytes, at + 40, sizes[i]);
        } else {
            put32(bytes, at + 32, static_cast<uint32_t>(addresses[i]));
            put32(bytes, at + 36, sizes[i]);
        }
        put32(bytes, at + (is64 ? 48 : 40), offsets[i]);
        put32(bytes, at + (is64 ? 64 : 56), flags[i]);
    }
    return bytes;
}

void putFatArch(std::vector<uint8_t>& bytes, size_t offset, bool fat64, bool little,
                uint32_t cpu, uint32_t subtype, uint64_t sliceOffset, uint64_t sliceSize) {
    const auto word32 = [&](size_t at, uint32_t value) {
        if (little) put32(bytes, at, value); else put32BE(bytes, at, value);
    };
    const auto word64 = [&](size_t at, uint64_t value) {
        if (little) put64(bytes, at, value); else put64BE(bytes, at, value);
    };
    word32(offset, cpu);
    word32(offset + 4, subtype);
    if (fat64) {
        word64(offset + 8, sliceOffset);
        word64(offset + 16, sliceSize);
        word32(offset + 24, 0);
    } else {
        word32(offset + 8, static_cast<uint32_t>(sliceOffset));
        word32(offset + 12, static_cast<uint32_t>(sliceSize));
        word32(offset + 16, 0);
    }
}

std::vector<uint8_t> makeFat(bool fat64, bool little, bool include64) {
    const size_t entrySize = fat64 ? 32 : 20;
    const size_t count = include64 ? 4 : 3;
    std::vector<uint8_t> bytes(0x1000, 0);
    const uint32_t magic = fat64 ? 0xcafebabf : 0xcafebabe;
    if (little) put32(bytes, 0, magic); else put32BE(bytes, 0, magic);
    if (little) put32(bytes, 4, static_cast<uint32_t>(count)); else put32BE(bytes, 4, static_cast<uint32_t>(count));
    size_t entry = 8;
    putFatArch(bytes, entry, fat64, little, 7, 0, 0x100, 4);
    entry += entrySize;
    const auto armv6 = makeMachO(false, 6);
    putFatArch(bytes, entry, fat64, little, 0x0c, 6, 0x400, armv6.size());
    std::copy(armv6.begin(), armv6.end(), bytes.begin() + 0x400);
    entry += entrySize;
    const auto armv7 = makeMachO(false, 9);
    putFatArch(bytes, entry, fat64, little, 0x0c, 9, 0x800, armv7.size());
    std::copy(armv7.begin(), armv7.end(), bytes.begin() + 0x800);
    if (include64) {
        entry += entrySize;
        const auto arm64 = makeMachO(true, 0);
        putFatArch(bytes, entry, fat64, little, 0x0100000c, 0, 0xc00, arm64.size());
        std::copy(arm64.begin(), arm64.end(), bytes.begin() + 0xc00);
    }
    return bytes;
}

std::vector<uint8_t> makePE(uint16_t machine) {
    const bool is64 = machine == 0x8664 || machine == 0xaa64;
    std::vector<uint8_t> bytes(0x208, 0);
    put16(bytes, 0, 0x5a4d);
    put32(bytes, 0x3c, 0x80);
    put32(bytes, 0x80, 0x4550);
    put16(bytes, 0x84, machine);
    put16(bytes, 0x86, 2);
    put16(bytes, 0x94, 32);
    put16(bytes, 0x98, is64 ? 0x020b : 0x010b);
    if (is64) put64(bytes, 0xb0, 0x140000000); else put32(bytes, 0xb4, 0x400000);
    const size_t section = 0xb8;
    putName(bytes, section, ".text");
    put32(bytes, section + 8, 4);
    put32(bytes, section + 12, 0x1000);
    put32(bytes, section + 16, 4);
    put32(bytes, section + 20, 0x200);
    put32(bytes, section + 36, 0x20000000);
    putName(bytes, section + 40, ".data");
    put32(bytes, section + 48, 4);
    put32(bytes, section + 52, 0x2000);
    put32(bytes, section + 56, 4);
    put32(bytes, section + 60, 0x204);
    return bytes;
}

std::vector<uint8_t> makeELF(bool is64, uint16_t machine) {
    const uint64_t imageBase = is64 ? 0x100000000ULL : 0x10000;
    std::vector<uint8_t> bytes(0x208, 0);
    bytes[0] = 0x7f;
    bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
    bytes[4] = is64 ? 2 : 1;
    bytes[5] = 1;
    bytes[6] = 1;
    put16(bytes, 16, 2);
    put16(bytes, 18, machine);
    put32(bytes, 20, 1);
    if (is64) {
        put64(bytes, 32, 64);
        put16(bytes, 52, 64); put16(bytes, 54, 56); put16(bytes, 56, 2);
        for (size_t i = 0; i < 2; ++i) {
            const size_t at = 64 + i * 56;
            put32(bytes, at, 1);
            put32(bytes, at + 4, i == 0 ? 5 : 6);
            put64(bytes, at + 8, 0x200 + i * 4);
            put64(bytes, at + 16, imageBase + i * 0x1000);
            put64(bytes, at + 32, 4);
            put64(bytes, at + 40, i == 0 ? 4 : 8);
        }
    } else {
        put32(bytes, 28, 52);
        put16(bytes, 40, 52); put16(bytes, 42, 32); put16(bytes, 44, 2);
        for (size_t i = 0; i < 2; ++i) {
            const size_t at = 52 + i * 32;
            put32(bytes, at, 1);
            put32(bytes, at + 4, 0x200 + i * 4);
            put32(bytes, at + 8, static_cast<uint32_t>(imageBase + i * 0x1000));
            put32(bytes, at + 16, 4);
            put32(bytes, at + 20, i == 0 ? 4 : 8);
            put32(bytes, at + 24, i == 0 ? 5 : 6);
        }
    }
    return bytes;
}

const Section& section(const BinaryImage& image, const std::string& name) {
    const auto found = std::find_if(image.sections.begin(), image.sections.end(), [&](const Section& candidate) {
        return candidate.name == name;
    });
    if (found == image.sections.end()) throw std::runtime_error("missing fixture section " + name);
    return *found;
}

void testMachO() {
    for (bool is64 : {false, true}) {
        const auto image = il2cpprec::MachOLoader::parse(makeMachO(is64, is64 ? 0 : 9));
        check(image.architecture == (is64 ? Architecture::Arm64 : Architecture::Arm32));
        check(image.sections.size() == 3);
        check(section(image, "__TEXT,__text").executable);
        check(!section(image, "__TEXT,__cstring").executable);
        check(section(image, "__TEXT,__bss").fileSize == 0);
        check(image.mapVATR(image.imageBase + 0x200) == 0x200);
        check(image.mapVATR(0x200) == 0x200);
        expectThrow([&] { static_cast<void>(image.mapVATR(image.imageBase + 0x300)); });
    }
    for (bool fat64 : {false, true}) for (bool little : {false, true}) {
        const auto arm64 = il2cpprec::MachOLoader::parse(makeFat(fat64, little, true));
        check(arm64.architecture == Architecture::Arm64 && arm64.bytes->size() == 0x208);
        const auto armv7 = il2cpprec::MachOLoader::parse(makeFat(fat64, little, false));
        check(armv7.architecture == Architecture::Arm32 && armv7.imageBase == 0x92000);
    }
    auto malformed = makeMachO(true, 0);
    put32(malformed, 32 + 72 + 48, 0xfffffff0);
    expectThrow([&] { static_cast<void>(il2cpprec::MachOLoader::parse(malformed)); });
    malformed = makeMachO(true, 0);
    put64(malformed, 32 + 72 + 40, 0x2000);
    expectThrow([&] { static_cast<void>(il2cpprec::MachOLoader::parse(malformed)); });
    malformed = makeFat(false, false, true);
    put32BE(malformed, 8 + 3 * 20 + 8, 0xfffffff0);
    expectThrow([&] { static_cast<void>(il2cpprec::MachOLoader::parse(malformed)); });
    malformed = makeMachO(false, 9);
    malformed.pop_back();
    expectThrow([&] { static_cast<void>(il2cpprec::MachOLoader::parse(malformed)); });
}

void testPE() {
    for (uint16_t machine : {uint16_t{0x014c}, uint16_t{0x8664}, uint16_t{0x01c0}, uint16_t{0x01c4}, uint16_t{0xaa64}}) {
        const auto image = il2cpprec::parsePE(std::make_shared<std::vector<uint8_t>>(makePE(machine)));
        const bool is64 = machine == 0x8664 || machine == 0xaa64;
        const Architecture expected = machine == 0x014c ? Architecture::X86
            : machine == 0x8664 ? Architecture::X64
            : is64 ? Architecture::Arm64 : Architecture::Arm32;
        check(image.architecture == expected);
        check(image.sections.size() == 2 && image.sections[0].executable && !image.sections[1].executable);
        check(image.mapVATR(0x1000) == 0x200);
        check(image.mapVATR(image.imageBase + 0x1000) == 0x200);
        check(image.mapRTVA(0x200) == 0x1000);
    }
    auto malformed = makePE(0x01c4);
    put32(malformed, 0xb8 + 16, 16);
    expectThrow([&] { static_cast<void>(il2cpprec::parsePE(std::make_shared<std::vector<uint8_t>>(malformed))); });
    malformed = makePE(0xaa64);
    put16(malformed, 0x98, 0x010b);
    expectThrow([&] { static_cast<void>(il2cpprec::parsePE(std::make_shared<std::vector<uint8_t>>(malformed))); });
    auto padded = makePE(0x01c4);
    put32(padded, 0xb8 + 16, 8);
    const auto image = il2cpprec::parsePE(std::make_shared<std::vector<uint8_t>>(padded));
    check(image.mapVATR(0x1003) == 0x203);
    expectThrow([&] { static_cast<void>(image.mapVATR(0x1004)); });
}

void testELF() {
    il2cpprec::ELFLoader loader;
    for (bool is64 : {false, true}) {
        for (uint16_t machine : (is64 ? std::vector<uint16_t>{62, 183} : std::vector<uint16_t>{3, 40})) {
            const auto image = loader.load(makeELF(is64, machine));
            const Architecture expected = machine == 3 ? Architecture::X86
                : machine == 40 ? Architecture::Arm32
                : machine == 62 ? Architecture::X64 : Architecture::Arm64;
            check(image.architecture == expected);
            check(image.sections.size() == 2 && image.sections[0].executable && !image.sections[1].executable);
            check(image.mapVATR(image.imageBase) == 0x200);
            check(image.mapVATR(0) == 0x200);
            check(image.mapRTVA(0x204) == image.imageBase + 0x1000);
            expectThrow([&] { static_cast<void>(image.mapVATR(image.imageBase + 4)); });
        }
    }
    auto malformed = makeELF(true, 183);
    put64(malformed, 64 + 32, 8);
    expectThrow([&] { static_cast<void>(loader.load(malformed)); });
    malformed = makeELF(false, 40);
    put32(malformed, 52 + 4, 0xfffffff0);
    expectThrow([&] { static_cast<void>(loader.load(malformed)); });
    malformed = makeELF(true, 183);
    put64(malformed, 64 + 16, std::numeric_limits<uint64_t>::max() - 1);
    expectThrow([&] { static_cast<void>(loader.load(malformed)); });
}

void testMappingFailures() {
    BinaryImage image;
    Section section;
    section.virtualAddress = 0x1000;
    section.virtualSize = 4;
    section.fileOffset = std::numeric_limits<uint64_t>::max() - 1;
    section.fileSize = 4;
    image.sections = {section};
    expectThrow([&] { static_cast<void>(image.mapVATR(0x1002)); });
    section.virtualAddress = std::numeric_limits<uint64_t>::max() - 1;
    section.fileOffset = 0;
    image.sections = {section};
    expectThrow([&] { static_cast<void>(image.mapRTVA(2)); });
    image.sections.clear();
    expectThrow([&] { static_cast<void>(image.mapVATR(1)); });
    expectThrow([&] { static_cast<void>(image.mapRTVA(1)); });
}

} // namespace

int main() {
    testMachO();
    std::cout << "[PASS] synthetic Mach-O FAT ARMv7/ARM64 and malformed fixtures\n";
    testPE();
    std::cout << "[PASS] synthetic PE x86/x64/ARM/ARMNT/ARM64 fixtures\n";
    testELF();
    std::cout << "[PASS] synthetic ELF x86/x64/ARM32/ARM64 fixtures\n";
    testMappingFailures();
    std::cout << "[PASS] mapping overflow and bounds fixtures\n";
}
