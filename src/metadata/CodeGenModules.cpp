#include <il2cpprec/metadata/CodeGenModules.hpp>

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint32_t maxCodeGenModuleCount = 1000000;
constexpr uint32_t maxMethodPointerCount = 1000000;
constexpr uint32_t maxLegacyMethodPointerCount = 100000000;
constexpr size_t maxModuleNameLength = 1024;
constexpr size_t noField = std::numeric_limits<size_t>::max();

size_t pointerSize(const BinaryImage& binary) {
    return binary.architecture == Architecture::X86 || binary.architecture == Architecture::Arm32 ? 4 : 8;
}

uint32_t read32(const std::vector<uint8_t>& bytes, size_t offset) {
    uint32_t value = 0;
    for (size_t i = 0; i < 4; ++i) {
        value |= static_cast<uint32_t>(bytes[offset + i]) << (i * 8);
    }
    return value;
}

uint64_t read64(const std::vector<uint8_t>& bytes, size_t offset) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(bytes[offset + i]) << (i * 8);
    }
    return value;
}

uint64_t readPointer(const std::vector<uint8_t>& bytes, size_t offset, size_t size) {
    return size == sizeof(uint64_t) ? read64(bytes, offset) : read32(bytes, offset);
}

bool readCount(const std::vector<uint8_t>& bytes, size_t offset, size_t pointerBytes, uint32_t& count) {
    count = read32(bytes, offset);
    return pointerBytes == sizeof(uint32_t) || read32(bytes, offset + sizeof(uint32_t)) == 0;
}

uint64_t normalizePointer(uint64_t value) {
    return value & 0x0000FFFFFFFFFFFFULL;
}

bool addOverflows(uint64_t left, uint64_t right) {
    return left > std::numeric_limits<uint64_t>::max() - right;
}

bool usesRelativeSections(const BinaryImage& binary) {
    if (binary.format == BinaryFormat::PE) return true;
    if (binary.imageBase == 0) return false;
    return std::any_of(binary.sections.begin(), binary.sections.end(), [&](const Section& section) {
        return section.fileSize != 0 && section.virtualAddress < binary.imageBase;
    });
}

bool mapRVA(const BinaryImage& binary, uint64_t rva, size_t size, bool executable, size_t& offset) {
    for (const auto& section : binary.sections) {
        if (executable && !section.executable) continue;
        if (rva < section.virtualAddress) continue;
        const auto sectionOffset = rva - section.virtualAddress;
        if (sectionOffset >= section.fileSize || size > section.fileSize - sectionOffset) continue;
        if (addOverflows(section.fileOffset, sectionOffset)) continue;
        const auto rawOffset = section.fileOffset + sectionOffset;
        if (rawOffset > std::numeric_limits<size_t>::max()) continue;
        offset = static_cast<size_t>(rawOffset);
        if (offset <= binary.bytes->size() && size <= binary.bytes->size() - offset) return true;
    }
    return false;
}

bool mapPointer(const BinaryImage& binary, uint64_t pointer, size_t size, size_t& offset,
                bool executable = false) {
    pointer = normalizePointer(pointer);
    if (binary.architecture == Architecture::Arm32) pointer &= ~uint64_t{1};
    if (usesRelativeSections(binary)) {
        if (pointer >= binary.imageBase && mapRVA(binary, pointer - binary.imageBase, size, executable, offset)) {
            return true;
        }
        return mapRVA(binary, pointer, size, executable, offset);
    }
    if (mapRVA(binary, pointer, size, executable, offset)) return true;
    if (pointer >= binary.imageBase && mapRVA(binary, pointer - binary.imageBase, size, executable, offset)) {
        return true;
    }
    if (binary.format == BinaryFormat::MachO) return false;
    return !addOverflows(binary.imageBase, pointer) &&
           mapRVA(binary, binary.imageBase + pointer, size, executable, offset);
}

bool fileOffsetToPointer(const BinaryImage& binary, size_t offset, uint64_t& pointer) {
    if (!binary.bytes || offset >= binary.bytes->size()) return false;
    for (const auto& section : binary.sections) {
        if (offset < section.fileOffset) continue;
        const auto sectionOffset = static_cast<uint64_t>(offset) - section.fileOffset;
        if (sectionOffset >= section.fileSize || addOverflows(section.virtualAddress, sectionOffset)) continue;
        const auto rva = section.virtualAddress + sectionOffset;
        if (usesRelativeSections(binary)) {
            if (addOverflows(binary.imageBase, rva)) return false;
            pointer = normalizePointer(binary.imageBase + rva);
        } else {
            pointer = normalizePointer(rva);
        }
        return true;
    }
    return false;
}

bool arraySize(uint64_t count, size_t elementSize, size_t& size) {
    if (elementSize != 0 && count > std::numeric_limits<size_t>::max() / elementSize) return false;
    size = static_cast<size_t>(count) * elementSize;
    return true;
}

bool validModuleName(const std::string& name) {
    if (name.size() < 5 || name.size() > maxModuleNameLength || name.compare(name.size() - 4, 4, ".dll") != 0) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return c >= 0x20 && c <= 0x7e && c != '/' && c != '\\';
    });
}

bool readModuleName(const BinaryImage& binary, uint64_t pointer, std::string& name) {
    size_t offset = 0;
    if (pointer == 0 || !mapPointer(binary, pointer, 1, offset)) return false;
    const auto remaining = binary.bytes->size() - offset;
    const auto limit = std::min(remaining, maxModuleNameLength + 1);
    size_t length = 0;
    while (length < limit && (*binary.bytes)[offset + length] != 0) ++length;
    if (length == 0 || length > maxModuleNameLength || length == remaining) return false;
    name.assign(reinterpret_cast<const char*>(binary.bytes->data() + offset), length);
    return validModuleName(name);
}

struct CodeGenModuleLayout {
    const char* name;
    size_t totalSlots;
    size_t adjustorSlot;
    size_t invokerSlot;
    size_t reverseSlot;
    size_t rgctxRangesSlot;
    size_t rgctxsSlot;
    size_t rgctxEntrySize;
    size_t metadataRegistrationSlot;
    size_t codeRegistrationSlot;
};

const CodeGenModuleLayout module24{"24.2-24.4", 11, noField, 3, 4, 6, 8, 8, noField, noField};
const CodeGenModuleLayout module24_5{"24.5", 13, 3, 5, 6, 8, 10, 8, noField, noField};
const CodeGenModuleLayout module27{"27.0", 16, noField, 3, 4, 6, 8, 8, 14, 15};
const CodeGenModuleLayout module27_1{"27.1-27.2", 18, 3, 5, 6, 8, 10, 8, 16, 17};
const CodeGenModuleLayout module27_2{"27.2", 18, 3, 5, 6, 8, 10, 16, 16, 17};
const CodeGenModuleLayout module29{"29-107", 17, 3, 5, 6, 8, 10, 16, 15, 16};
const CodeGenModuleLayout module108{"108+", 11, 3, noField, 5, noField, noField, 0, 9, 10};

enum class LayoutVersion {
    V24_2,
    V24_3,
    V24_5,
    V27_0,
    V27_1,
    V27_2,
    V29_0,
    V29_1,
    V33,
    V35,
    V108
};

struct CodeRegistrationLayout {
    const char* name;
    LayoutVersion version;
    size_t modulesSlot;
    size_t totalSlots;
    const CodeGenModuleLayout* module;
    std::initializer_list<size_t> countTableSlots;
    size_t globalMethodsSlot;
};

const CodeRegistrationLayout registrationLayouts[] = {
    {"24.2", LayoutVersion::V24_2, 20, 22, &module24, {0, 2, 4, 6, 8, 10, 12, 14, 16, 18}, 0},
    {"24.3-24.4", LayoutVersion::V24_3, 22, 24, &module24, {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20}, 0},
    {"24.5", LayoutVersion::V24_5, 23, 25, &module24_5, {0, 2, 4, 6, 8, 10, 13, 15, 17, 19, 21}, 0},
    {"27.0", LayoutVersion::V27_0, 12, 14, &module27, {0, 2, 4, 6, 8, 10}, noField},
    {"27.1", LayoutVersion::V27_1, 13, 15, &module27_1, {0, 2, 5, 7, 9, 11}, noField},
    {"27.2", LayoutVersion::V27_2, 13, 15, &module27_2, {0, 2, 5, 7, 9, 11}, noField},
    {"29.0", LayoutVersion::V29_0, 13, 15, &module29, {0, 2, 5, 7, 9, 11}, noField},
    {"29.1-31", LayoutVersion::V29_1, 15, 17, &module29, {0, 2, 5, 7, 11, 13}, noField},
    {"33-34", LayoutVersion::V33, 12, 14, &module29, {0, 2, 5, 8, 10}, noField},
    {"35-107", LayoutVersion::V35, 15, 17, &module29, {0, 2, 5, 7, 11, 13}, noField},
    {"108+", LayoutVersion::V108, 15, 17, &module108, {0, 2, 5, 7, 11, 13}, noField}
};

bool versionMatches(LayoutVersion layout, double version) {
    if (version == 0) return true;
    switch (layout) {
        case LayoutVersion::V24_2: return version == 24.2;
        case LayoutVersion::V24_3: return version == 24.3 || version == 24.4;
        case LayoutVersion::V24_5: return version == 24.5;
        case LayoutVersion::V27_0: return version == 27.0;
        case LayoutVersion::V27_1: return version == 27.1;
        case LayoutVersion::V27_2: return version == 27.2;
        case LayoutVersion::V29_0: return version == 29.0;
        case LayoutVersion::V29_1: return version == 29.1 || version == 31.0;
        case LayoutVersion::V33: return version >= 33.0 && version < 35.0;
        case LayoutVersion::V35: return version >= 35.0 && version < 108.0;
        case LayoutVersion::V108: return version >= 108.0;
    }
    return false;
}

std::vector<const CodeRegistrationLayout*> layoutsForVersion(double version) {
    std::vector<const CodeRegistrationLayout*> result;
    for (const auto& layout : registrationLayouts) {
        if (versionMatches(layout.version, version)) result.push_back(&layout);
    }
    return result;
}

struct ModuleRecord {
    std::string name;
    uint32_t methodCount = 0;
    size_t methodPointersOffset = 0;
    size_t moduleOffset = 0;
    uint64_t metadataRegistration = 0;
    uint64_t codeRegistration = 0;
};

struct Candidate {
    std::vector<ModuleRecord> modules;
    uint64_t metadataRegistration = 0;
    uint64_t codeRegistration = 0;
    size_t registrationOffset = 0;
    bool backPointersConfirmed = false;
};

bool readTablePair(const BinaryImage& binary, size_t offset, uint32_t maximum, uint32_t& count,
                   size_t& tableOffset) {
    const auto pointerBytes = pointerSize(binary);
    if (offset > binary.bytes->size() || 2 * pointerBytes > binary.bytes->size() - offset) return false;
    if (!readCount(*binary.bytes, offset, pointerBytes, count) || count > maximum) return false;
    const auto table = readPointer(*binary.bytes, offset + pointerBytes, pointerBytes);
    if (count == 0) return true;
    size_t tableSize = 0;
    return table != 0 && arraySize(count, pointerBytes, tableSize) &&
           mapPointer(binary, table, tableSize, tableOffset);
}

bool validExecutableMethodTable(const BinaryImage& binary, size_t offset, uint32_t count) {
    const auto pointerBytes = pointerSize(binary);
    bool any = false;
    for (uint32_t i = 0; i < count; ++i) {
        const auto pointer = readPointer(*binary.bytes, offset + static_cast<size_t>(i) * pointerBytes, pointerBytes);
        if (normalizePointer(pointer) == 0) continue;
        size_t methodOffset = 0;
        if (!mapPointer(binary, pointer, 1, methodOffset, true)) return false;
        any = true;
    }
    return any;
}

bool validateByteTable(const BinaryImage& binary, uint64_t pointer, uint32_t count, size_t elementSize) {
    if (count == 0) return true;
    size_t size = 0;
    size_t offset = 0;
    return pointer != 0 && arraySize(count, elementSize, size) && mapPointer(binary, pointer, size, offset);
}

bool validateModulePair(const BinaryImage& binary, size_t moduleOffset, size_t slot,
                        size_t elementSize, uint32_t maximum) {
    const auto pointerBytes = pointerSize(binary);
    const auto offset = moduleOffset + slot * pointerBytes;
    uint32_t count = 0;
    if (!readCount(*binary.bytes, offset, pointerBytes, count) || count > maximum) return false;
    const auto table = readPointer(*binary.bytes, offset + pointerBytes, pointerBytes);
    return validateByteTable(binary, table, count, elementSize);
}

bool parseModuleAtOffset(const BinaryImage& binary, size_t offset, const CodeGenModuleLayout& layout,
                         ModuleRecord& module) {
    const auto pointerBytes = pointerSize(binary);
    if (offset > binary.bytes->size() || layout.totalSlots * pointerBytes > binary.bytes->size() - offset) {
        return false;
    }
    if (!readModuleName(binary, readPointer(*binary.bytes, offset, pointerBytes), module.name)) return false;
    if (!readCount(*binary.bytes, offset + pointerBytes, pointerBytes, module.methodCount) ||
        module.methodCount > maxMethodPointerCount) {
        return false;
    }
    const auto methodPointers = readPointer(*binary.bytes, offset + 2 * pointerBytes, pointerBytes);
    if (module.methodCount != 0) {
        size_t tableSize = 0;
        if (methodPointers == 0 || !arraySize(module.methodCount, pointerBytes, tableSize) ||
            !mapPointer(binary, methodPointers, tableSize, module.methodPointersOffset)) {
            return false;
        }
    }
    if (layout.adjustorSlot != noField &&
        !validateModulePair(binary, offset, layout.adjustorSlot, pointerBytes, maxMethodPointerCount)) {
        return false;
    }
    if (layout.invokerSlot != noField) {
        const auto indices = readPointer(*binary.bytes, offset + layout.invokerSlot * pointerBytes, pointerBytes);
        if (!validateByteTable(binary, indices, module.methodCount, sizeof(uint32_t))) return false;
    }
    if (!validateModulePair(binary, offset, layout.reverseSlot, sizeof(uint32_t), maxMethodPointerCount)) {
        return false;
    }
    if (layout.rgctxRangesSlot != noField &&
        !validateModulePair(binary, offset, layout.rgctxRangesSlot, 12, maxMethodPointerCount)) {
        return false;
    }
    if (layout.rgctxsSlot != noField &&
        !validateModulePair(binary, offset, layout.rgctxsSlot, layout.rgctxEntrySize, maxMethodPointerCount)) {
        return false;
    }

    module.moduleOffset = offset;
    if (layout.metadataRegistrationSlot != noField) {
        module.metadataRegistration = normalizePointer(readPointer(
            *binary.bytes, offset + layout.metadataRegistrationSlot * pointerBytes, pointerBytes));
        module.codeRegistration = normalizePointer(readPointer(
            *binary.bytes, offset + layout.codeRegistrationSlot * pointerBytes, pointerBytes));
    }
    return true;
}

bool parseModule(const BinaryImage& binary, uint64_t pointer, const CodeGenModuleLayout& layout,
                 ModuleRecord& module) {
    if (pointer == 0) return false;
    size_t offset = 0;
    if (!mapPointer(binary, pointer, layout.totalSlots * pointerSize(binary), offset)) return false;
    return parseModuleAtOffset(binary, offset, layout, module);
}

bool commonRegistrationPointer(const BinaryImage& binary, const std::vector<ModuleRecord>& modules,
                               bool metadataRegistration, uint64_t& pointer) {
    if (modules.empty()) return false;
    const auto& first = modules.front();
    pointer = metadataRegistration ? first.metadataRegistration : first.codeRegistration;
    if (pointer == 0) return false;
    for (const auto& module : modules) {
        const auto current = metadataRegistration ? module.metadataRegistration : module.codeRegistration;
        if (current != pointer) return false;
    }
    size_t offset = 0;
    return mapPointer(binary, pointer, 1, offset);
}

bool allRegistrationPointersZero(const std::vector<ModuleRecord>& modules, bool metadataRegistration) {
    return std::all_of(modules.begin(), modules.end(), [&](const ModuleRecord& module) {
        return (metadataRegistration ? module.metadataRegistration : module.codeRegistration) == 0;
    });
}

int legacyRegistrationScore(const BinaryImage& binary, size_t offset, uint32_t expectedCount) {
    const auto pointerBytes = pointerSize(binary);
    uint32_t methodCount = 0;
    size_t methodTable = 0;
    if (!readTablePair(binary, offset, maxLegacyMethodPointerCount, methodCount, methodTable) ||
        methodCount == 0 || (expectedCount != 0 && methodCount != expectedCount)) {
        return 0;
    }
    int populatedPairs = 0;
    for (size_t pair = 1; pair < 7; ++pair) {
        uint32_t count = 0;
        size_t table = 0;
        if (!readTablePair(binary, offset + pair * 2 * pointerBytes, maxLegacyMethodPointerCount, count, table)) {
            return 0;
        }
        if (count != 0) ++populatedPairs;
    }
    if (populatedPairs < 2 || !validExecutableMethodTable(binary, methodTable, methodCount)) return 0;
    return populatedPairs;
}

bool validateRegistration(const BinaryImage& binary, size_t offset, const CodeRegistrationLayout& layout) {
    const auto pointerBytes = pointerSize(binary);
    if (offset > binary.bytes->size() || layout.totalSlots * pointerBytes > binary.bytes->size() - offset) {
        return false;
    }
    size_t populated = 0;
    for (const auto slot : layout.countTableSlots) {
        uint32_t count = 0;
        size_t table = 0;
        if (!readTablePair(binary, offset + slot * pointerBytes, maxLegacyMethodPointerCount, count, table)) {
            return false;
        }
        if (count != 0) ++populated;
        if (slot == layout.globalMethodsSlot && (count == 0 || !validExecutableMethodTable(binary, table, count))) {
            return false;
        }
    }
    return populated >= 2;
}

bool identifyRegistrations(const BinaryImage& binary, const CodeRegistrationLayout& layout,
                           Candidate& candidate) {
    if (!fileOffsetToPointer(binary, candidate.registrationOffset, candidate.codeRegistration)) return false;
    if (layout.module->codeRegistrationSlot == noField) return true;
    if (allRegistrationPointersZero(candidate.modules, false)) return true;

    uint64_t moduleCodeRegistration = 0;
    if (!commonRegistrationPointer(binary, candidate.modules, false, moduleCodeRegistration) ||
        moduleCodeRegistration != candidate.codeRegistration) {
        return false;
    }
    candidate.backPointersConfirmed = true;
    if (!allRegistrationPointersZero(candidate.modules, true)) {
        if (!commonRegistrationPointer(binary, candidate.modules, true, candidate.metadataRegistration)) return false;
    }
    return true;
}

bool parseCandidate(const BinaryImage& binary, size_t registrationOffset,
                    const CodeRegistrationLayout& layout, Candidate& candidate) {
    if (!validateRegistration(binary, registrationOffset, layout)) return false;
    const auto& bytes = *binary.bytes;
    const auto pointerBytes = pointerSize(binary);
    const auto countOffset = registrationOffset + layout.modulesSlot * pointerBytes;
    uint32_t moduleCount = 0;
    size_t tableOffset = 0;
    if (!readTablePair(binary, countOffset, maxCodeGenModuleCount, moduleCount, tableOffset) || moduleCount == 0) {
        return false;
    }

    candidate.registrationOffset = registrationOffset;
    candidate.modules.reserve(moduleCount);
    uint64_t totalMethodCount = 0;
    for (uint32_t i = 0; i < moduleCount; ++i) {
        const auto modulePointer = readPointer(bytes, tableOffset + static_cast<size_t>(i) * pointerBytes, pointerBytes);
        ModuleRecord module;
        if (!parseModule(binary, modulePointer, *layout.module, module)) return false;
        totalMethodCount += module.methodCount;
        if (totalMethodCount > bytes.size() / pointerBytes) return false;
        candidate.modules.push_back(std::move(module));
    }
    std::sort(candidate.modules.begin(), candidate.modules.end(), [](const ModuleRecord& left, const ModuleRecord& right) {
        return left.name < right.name;
    });
    if (std::adjacent_find(candidate.modules.begin(), candidate.modules.end(), [](const ModuleRecord& left, const ModuleRecord& right) {
            return left.name == right.name;
        }) != candidate.modules.end()) {
        return false;
    }
    return identifyRegistrations(binary, layout, candidate);
}

bool betterCandidate(const Candidate& candidate, const Candidate& current) {
    if (candidate.backPointersConfirmed != current.backPointersConfirmed) return candidate.backPointersConfirmed;
    if (candidate.modules.size() != current.modules.size()) return candidate.modules.size() > current.modules.size();
    if ((candidate.metadataRegistration != 0) != (current.metadataRegistration != 0)) {
        return candidate.metadataRegistration != 0;
    }
    return candidate.registrationOffset < current.registrationOffset;
}

void commitCandidate(const BinaryImage& binary, const Candidate& candidate, MetadataModel& metadata) {
    const auto pointerBytes = pointerSize(binary);
    for (const auto& module : candidate.modules) {
        auto destination = metadata.methodPointersByImage.try_emplace(module.name).first;
        if (!destination->second.empty()) continue;
        std::vector<uint64_t> methodPointers;
        methodPointers.reserve(module.methodCount);
        for (uint32_t i = 0; i < module.methodCount; ++i) {
            methodPointers.push_back(normalizePointer(readPointer(
                *binary.bytes, module.methodPointersOffset + static_cast<size_t>(i) * pointerBytes, pointerBytes)));
        }
        destination->second = std::move(methodPointers);
    }
    if (candidate.metadataRegistration != 0) metadata.metadataRegistrationAddress = candidate.metadataRegistration;
    if (candidate.codeRegistration != 0) metadata.codeRegistrationAddress = candidate.codeRegistration;
}

bool discoverFallback(const BinaryImage& binary, MetadataModel& metadata,
                      const std::vector<const CodeRegistrationLayout*>& layouts) {
    const auto& bytes = *binary.bytes;
    std::unordered_map<uint64_t, size_t> nameAddresses;
    size_t stringStart = 0;
    for (size_t offset = 0; offset < bytes.size(); ++offset) {
        const auto c = bytes[offset];
        if (c != 0 && c >= 0x20 && c <= 0x7e) continue;
        if (c == 0 && offset > stringStart) {
            std::string name(reinterpret_cast<const char*>(bytes.data() + stringStart), offset - stringStart);
            if (validModuleName(name)) {
                uint64_t address = 0;
                if (fileOffsetToPointer(binary, stringStart, address)) nameAddresses.try_emplace(address, stringStart);
            }
        }
        stringStart = offset + 1;
    }
    if (nameAddresses.empty()) return false;

    const auto pointerBytes = pointerSize(binary);
    std::vector<ModuleRecord> modules;
    for (size_t offset = 0; offset <= bytes.size() - pointerBytes; offset += pointerBytes) {
        const auto nameAddress = normalizePointer(readPointer(bytes, offset, pointerBytes));
        if (nameAddresses.find(nameAddress) == nameAddresses.end()) continue;
        for (const auto* registration : layouts) {
            ModuleRecord module;
            if (parseModuleAtOffset(binary, offset, *registration->module, module)) {
                modules.push_back(std::move(module));
                break;
            }
        }
    }
    if (modules.empty()) return false;
    std::sort(modules.begin(), modules.end(), [](const ModuleRecord& left, const ModuleRecord& right) {
        if (left.name != right.name) return left.name < right.name;
        return left.moduleOffset < right.moduleOffset;
    });
    modules.erase(std::unique(modules.begin(), modules.end(), [](const ModuleRecord& left, const ModuleRecord& right) {
        return left.name == right.name;
    }), modules.end());

    Candidate candidate;
    candidate.modules = std::move(modules);
    commonRegistrationPointer(binary, candidate.modules, true, candidate.metadataRegistration);
    commonRegistrationPointer(binary, candidate.modules, false, candidate.codeRegistration);
    commitCandidate(binary, candidate, metadata);
    return true;
}

uint32_t expectedLegacyMethodCount(const MetadataModel& metadata) {
    uint64_t count = 0;
    for (const auto& type : metadata.types) {
        for (const auto& method : type.methods) {
            if (method.methodIndex < 0) continue;
            count = std::max(count, static_cast<uint64_t>(method.methodIndex) + 1);
        }
    }
    return count <= maxLegacyMethodPointerCount ? static_cast<uint32_t>(count) : 0;
}

void emitDiagnostic(const CodeGenModulesValidation& validation, const std::string& message) {
    if (validation.diagnostic) validation.diagnostic(message);
}

std::string hexAddress(uint64_t address) {
    std::ostringstream stream;
    stream << "0x" << std::hex << address;
    return stream.str();
}

bool checkExternalRange(const CodeGenModulesValidation& validation, const char* label,
                        uint64_t address, size_t size, bool executable) {
    const auto bounds = validation.bounds(address);
    if (!bounds) {
        emitDiagnostic(validation, std::string(label) + " " + hexAddress(address) + " has no external bounds");
        return false;
    }
    if (bounds->end < bounds->start || address < bounds->start || address > bounds->end ||
        size > bounds->end - address) {
        emitDiagnostic(validation, std::string(label) + " " + hexAddress(address) + " with size " +
                       std::to_string(size) + " exceeds external bounds [" + hexAddress(bounds->start) +
                       ", " + hexAddress(bounds->end) + ")");
        return false;
    }
    if (executable && !bounds->executable) {
        emitDiagnostic(validation, std::string(label) + " " + hexAddress(address) +
                       " is outside executable external bounds");
        return false;
    }
    return true;
}

void validateLegacyRegistration(const BinaryImage& binary, const CodeGenModulesValidation& validation,
                                size_t registrationOffset, size_t tableOffset, uint32_t methodCount) {
    uint64_t codeRegistration = 0;
    uint64_t methodPointers = 0;
    fileOffsetToPointer(binary, registrationOffset, codeRegistration);
    fileOffsetToPointer(binary, tableOffset, methodPointers);
    emitDiagnostic(validation, "legacy CodeRegistration " + hexAddress(codeRegistration) +
                   ", methodPointers " + hexAddress(methodPointers) + ", count " + std::to_string(methodCount));
    if (!validation.bounds) return;
    const auto pointerBytes = pointerSize(binary);
    bool valid = checkExternalRange(validation, "legacy CodeRegistration", codeRegistration,
                                    14 * pointerBytes, false);
    size_t tableSize = 0;
    if (!arraySize(methodCount, pointerBytes, tableSize)) {
        emitDiagnostic(validation, "legacy methodPointers size overflows the host size type");
        return;
    }
    valid = checkExternalRange(validation, "legacy methodPointers", methodPointers, tableSize, false) && valid;
    const uint32_t samples[] = {0, methodCount / 2, methodCount - 1};
    for (const auto index : samples) {
        const auto method = readPointer(*binary.bytes, tableOffset + static_cast<size_t>(index) * pointerBytes,
                                        pointerBytes);
        if (normalizePointer(method) == 0) continue;
        valid = checkExternalRange(validation, "legacy method pointer", normalizePointer(method), 1, true) && valid;
    }
    if (valid) emitDiagnostic(validation, "legacy registration external bounds validation succeeded");
}

bool discoverLegacyGlobal(const BinaryImage& binary, MetadataModel& metadata,
                          const CodeGenModulesValidation& validation) {
    const auto expectedCount = expectedLegacyMethodCount(metadata);
    const auto pointerBytes = pointerSize(binary);
    std::optional<size_t> bestOffset;
    size_t bestTableOffset = 0;
    int bestScore = 0;
    for (size_t offset = 0; offset <= binary.bytes->size() - 2 * pointerBytes; offset += pointerBytes) {
        uint32_t count = 0;
        size_t tableOffset = 0;
        if (!readTablePair(binary, offset, maxLegacyMethodPointerCount, count, tableOffset) ||
            count == 0 || (expectedCount != 0 && count != expectedCount)) {
            continue;
        }
        const auto score = legacyRegistrationScore(binary, offset, expectedCount);
        if (score > bestScore) {
            bestOffset = offset;
            bestTableOffset = tableOffset;
            bestScore = score;
        }
    }
    if (!bestOffset) return false;
    uint64_t codeRegistration = 0;
    if (fileOffsetToPointer(binary, *bestOffset, codeRegistration)) metadata.codeRegistrationAddress = codeRegistration;
    const uint32_t methodCount = read32(*binary.bytes, *bestOffset);
    validateLegacyRegistration(binary, validation, *bestOffset, bestTableOffset, methodCount);
    if (expectedCount == 0) return true;

    struct Binding {
        const MethodModel* method = nullptr;
    };
    std::vector<Binding> bindings;
    for (const auto& type : metadata.types) {
        for (const auto& method : type.methods) {
            if (method.methodIndex >= 0 && static_cast<uint32_t>(method.methodIndex) < expectedCount &&
                !method.imageName.empty()) {
                bindings.push_back(Binding{&method});
            }
        }
    }
    std::sort(bindings.begin(), bindings.end(), [](const Binding& left, const Binding& right) {
        if (left.method->imageName != right.method->imageName) return left.method->imageName < right.method->imageName;
        if (left.method->methodIndex != right.method->methodIndex) return left.method->methodIndex < right.method->methodIndex;
        return left.method->definitionIndex < right.method->definitionIndex;
    });
    for (const auto& binding : bindings) {
        const auto& method = *binding.method;
        const auto index = static_cast<size_t>(method.methodIndex);
        auto destination = metadata.methodPointersByImage.try_emplace(method.imageName).first;
        if (destination->second.size() <= index) destination->second.resize(index + 1, 0);
        if (destination->second[index] == 0) {
            destination->second[index] = normalizePointer(
                readPointer(*binary.bytes, bestTableOffset + index * pointerBytes, pointerBytes));
        }
    }
    return true;
}

// Metadata 24.0/24.1 predates the CodeGenModule back pointers. Its metadata
// registration consists of eight count/table pairs; the field-offset and
// type-definition-size tables have the same number of entries.
bool validEarlyMetadataRegistration(const BinaryImage& binary, size_t offset,
                                    const MetadataModel& metadata) {
    constexpr size_t pairCount = 8;
    constexpr size_t pointerBytes = 8;
    const auto& bytes = *binary.bytes;
    if (offset > bytes.size() || pairCount * 2 * pointerBytes > bytes.size() - offset) return false;
    uint32_t counts[pairCount]{};
    size_t tables[pairCount]{};
    constexpr size_t elementSizes[pairCount] = {8, 8, 12, 8, 12, 8, 4, 8};
    for (size_t pair = 0; pair < pairCount; ++pair) {
        const auto pairOffset = offset + pair * 2 * pointerBytes;
        if (!readCount(bytes, pairOffset, pointerBytes, counts[pair]) ||
            counts[pair] > maxLegacyMethodPointerCount || counts[pair] == 0) return false;
        const auto pointer = readPointer(bytes, pairOffset + pointerBytes, pointerBytes);
        size_t tableSize = 0;
        if (!arraySize(counts[pair], elementSizes[pair], tableSize) ||
            !mapPointer(binary, pointer, tableSize, tables[pair])) return false;
    }
    if (counts[5] != counts[6] || counts[3] < counts[5]) return false;
    if (!metadata.types.empty() && counts[5] != metadata.types.size()) return false;

    // Check several independent type entries. A mapped pointer table alone
    // can be a coincidental match in a large native image.
    const uint32_t samples[] = {0, 1, counts[3] / 4, counts[3] / 2,
                                counts[3] * 3 / 4, counts[3] - 1};
    for (const auto index : samples) {
        const auto typePointer = read64(bytes, tables[3] + static_cast<size_t>(index) * pointerBytes);
        size_t typeOffset = 0;
        if (typePointer == 0 || !mapPointer(binary, typePointer, 16, typeOffset)) return false;
        const auto code = bytes[typeOffset + 10];
        if (code == 0 || (code > 0x21 && code != 0x40 && code != 0x41 &&
                          code != 0x45 && code != 0x55 && code != 0xff)) return false;
        if ((code == 0x11 || code == 0x12 || code == 0x55) &&
            !metadata.types.empty() && read32(bytes, typeOffset) >= metadata.types.size()) return false;
    }
    return true;
}

void discoverEarlyMetadataRegistration(const BinaryImage& binary, MetadataModel& metadata) {
    if (binary.format != BinaryFormat::MachO || binary.architecture != Architecture::Arm64 ||
        metadata.version < 24.0 || metadata.version >= 24.2 ||
        metadata.metadataRegistrationAddress != 0) return;
    constexpr size_t registrationSize = 8 * 2 * sizeof(uint64_t);
    const auto& bytes = *binary.bytes;
    if (bytes.size() < registrationSize) return;
    uint64_t discovered = 0;
    for (size_t offset = 0; offset <= bytes.size() - registrationSize; offset += sizeof(uint64_t)) {
        // These two neighboring counts are equal in this registration layout.
        if (read32(bytes, offset + 5 * 16) != read32(bytes, offset + 6 * 16)) continue;
        if (!validEarlyMetadataRegistration(binary, offset, metadata)) continue;
        uint64_t address = 0;
        if (!fileOffsetToPointer(binary, offset, address)) continue;
        if (discovered != 0 && address != discovered) return;
        discovered = address;
    }
    metadata.metadataRegistrationAddress = discovered;
}

} // namespace

void discoverCodeGenModules(const BinaryImage& binary, MetadataModel& metadata) {
    discoverCodeGenModules(binary, metadata, CodeGenModulesValidation{});
}

void discoverCodeGenModules(const BinaryImage& binary, MetadataModel& metadata,
                            const CodeGenModulesValidation& validation) {
    if (!binary.bytes || binary.bytes->empty()) return;
    const auto pointerBytes = pointerSize(binary);
    if (binary.bytes->size() < 2 * pointerBytes) return;
    const auto layouts = layoutsForVersion(metadata.version);
    if (layouts.empty()) {
        if (metadata.version == 0 || metadata.version < 24.2) discoverLegacyGlobal(binary, metadata, validation);
        discoverEarlyMetadataRegistration(binary, metadata);
        return;
    }

    std::optional<Candidate> best;
    for (size_t offset = 0; offset <= binary.bytes->size() - 2 * pointerBytes; offset += pointerBytes) {
        for (const auto* layout : layouts) {
            const auto displacement = layout->modulesSlot * pointerBytes;
            if (offset < displacement || layout->totalSlots * pointerBytes > binary.bytes->size() - offset + displacement) {
                continue;
            }
            Candidate candidate;
            const auto registrationOffset = offset - displacement;
            if (!parseCandidate(binary, registrationOffset, *layout, candidate)) continue;
            if (!best || betterCandidate(candidate, *best)) best = std::move(candidate);
        }
    }
    if (best) {
        commitCandidate(binary, *best, metadata);
        return;
    }
    if (discoverFallback(binary, metadata, layouts)) return;
    if (metadata.version == 0) discoverLegacyGlobal(binary, metadata, validation);
}

} // namespace il2cpprec
