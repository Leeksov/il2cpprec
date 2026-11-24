#include <il2cpprec/versions/Version24Modular.hpp>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <unordered_set>
#include <utility>

namespace il2cpprec::versions {
namespace {

constexpr uint32_t methodDefTable = 0x06000000;
constexpr uint32_t methodDefRidMask = 0x00ffffff;
constexpr size_t maxModuleNameLength = 4096;
constexpr size_t codeGenModuleSlots = 11;

uint64_t normalizePointer(uint64_t value) {
    return value & 0x0000ffffffffffffULL;
}

bool addOverflows(uint64_t left, uint64_t right) {
    return left > std::numeric_limits<uint64_t>::max() - right;
}

bool tableSize(uint64_t count, size_t stride, size_t& size) {
    if (stride == 0 || count > std::numeric_limits<size_t>::max()) return false;
    const auto nativeCount = static_cast<size_t>(count);
    if (nativeCount > std::numeric_limits<size_t>::max() / stride) return false;
    size = nativeCount * stride;
    return true;
}

size_t pointerSize(const BinaryImage& binary) {
    switch (binary.architecture) {
    case Architecture::X86:
    case Architecture::Arm32:
        return 4;
    case Architecture::X64:
    case Architecture::Arm64:
        return 8;
    }
    return 0;
}

uint32_t read32(const std::vector<uint8_t>& bytes, size_t offset) {
    return static_cast<uint32_t>(bytes[offset]) |
        (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
        (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
        (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

uint64_t read64(const std::vector<uint8_t>& bytes, size_t offset) {
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= static_cast<uint64_t>(bytes[offset + index]) << (index * 8);
    }
    return value;
}

uint64_t readPointer(const std::vector<uint8_t>& bytes, size_t offset, size_t size) {
    return size == 4 ? read32(bytes, offset) : read64(bytes, offset);
}

bool usesRelativeSections(const BinaryImage& binary) {
    if (binary.format == BinaryFormat::PE) return true;
    if (binary.imageBase == 0) return false;
    return std::any_of(binary.sections.begin(), binary.sections.end(), [&](const Section& section) {
        return section.fileSize != 0 && section.virtualAddress < binary.imageBase;
    });
}

bool mapRVA(const BinaryImage& binary, uint64_t rva, size_t size, bool executable, size_t& offset) {
    if (!binary.bytes) return false;
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
        if (pointer >= binary.imageBase &&
            mapRVA(binary, pointer - binary.imageBase, size, executable, offset)) {
            return true;
        }
        return mapRVA(binary, pointer, size, executable, offset);
    }
    if (mapRVA(binary, pointer, size, executable, offset)) return true;
    if (pointer >= binary.imageBase &&
        mapRVA(binary, pointer - binary.imageBase, size, executable, offset)) {
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

class Reader {
public:
    Reader(const BinaryImage& binary, size_t pointerSize, std::string& error)
        : binary_(binary), pointerSize_(pointerSize), error_(error) {}

    size_t pointerSize() const { return pointerSize_; }

    bool map(uint64_t address, size_t size, size_t& offset, bool executable = false) const {
        return mapPointer(binary_, address, size, offset, executable);
    }

    bool count(uint64_t address, uint64_t& value, const char* field) {
        size_t offset = 0;
        if (!map(address, pointerSize_, offset)) return fail(std::string(field) + " count is not file-backed");
        value = readPointer(*binary_.bytes, offset, pointerSize_);
        if (value > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
            return fail(std::string(field) + " count is negative or unreasonably large");
        }
        return true;
    }

    bool pair(uint64_t owner, size_t index, size_t elementSize, Version24RegistrationPair& pair,
              const char* field) {
        if (index > std::numeric_limits<uint64_t>::max() / (2 * pointerSize_)) {
            return fail("registration pair index overflows");
        }
        const auto address = owner + index * 2 * pointerSize_;
        if (!count(address, pair.count, field)) return false;
        size_t offset = 0;
        if (!map(address + pointerSize_, pointerSize_, offset)) {
            return fail(std::string(field) + " pointer is not file-backed");
        }
        pair.address = normalizePointer(readPointer(*binary_.bytes, offset, pointerSize_));
        if (pair.count == 0) {
            if (pair.address != 0) return fail(std::string(field) + " has a null count but a non-null table");
            return true;
        }
        if (pair.address == 0) return fail(std::string(field) + " has a non-null count but a null table");
        size_t size = 0;
        if (!tableSize(pair.count, elementSize, size)) return fail(std::string(field) + " table size overflows");
        size_t tableOffset = 0;
        if (!map(pair.address, size, tableOffset)) return fail(std::string(field) + " table is not file-backed");
        return true;
    }

    bool pointer(uint64_t address, uint64_t& value) const {
        size_t offset = 0;
        if (!map(address, pointerSize_, offset)) return false;
        value = normalizePointer(readPointer(*binary_.bytes, offset, pointerSize_));
        return true;
    }

    bool functionTable(const Version24RegistrationPair& pair, bool allowNull,
                       std::vector<uint64_t>& values, const char* field) {
        values.clear();
        if (pair.count == 0) return true;
        size_t size = 0;
        size_t offset = 0;
        if (!tableSize(pair.count, pointerSize_, size) || !map(pair.address, size, offset)) {
            return fail(std::string(field) + " pointer table is not file-backed");
        }
        values.reserve(static_cast<size_t>(pair.count));
        for (size_t index = 0; index < static_cast<size_t>(pair.count); ++index) {
            auto value = normalizePointer(readPointer(*binary_.bytes, offset + index * pointerSize_, pointerSize_));
            if (binary_.architecture == Architecture::Arm32) value &= ~uint64_t{1};
            if (value == 0) {
                if (!allowNull) return fail(std::string(field) + " contains a null function pointer");
            } else {
                size_t functionOffset = 0;
                if (!map(value, 1, functionOffset, true)) {
                    return fail(std::string(field) + " contains a non-executable or unmapped function pointer");
                }
            }
            values.push_back(value);
        }
        return true;
    }

    bool readModuleName(uint64_t address, std::string& name) {
        if (address == 0) return fail("CodeGenModule has a null moduleName");
        size_t offset = 0;
        if (!map(address, 1, offset)) return fail("CodeGenModule moduleName is not file-backed");
        const auto remaining = binary_.bytes->size() - offset;
        const auto limit = std::min(remaining, maxModuleNameLength + 1);
        size_t length = 0;
        while (length < limit && (*binary_.bytes)[offset + length] != 0) ++length;
        if (length == 0 || length > maxModuleNameLength || length == remaining) {
            return fail("CodeGenModule moduleName is empty, unterminated, or too long");
        }
        name.assign(reinterpret_cast<const char*>(binary_.bytes->data() + offset), length);
        if (name.size() < 5 || name.compare(name.size() - 4, 4, ".dll") != 0 ||
            !std::all_of(name.begin(), name.end(), [](unsigned char c) {
                return c >= 0x20 && c <= 0x7e && c != '/' && c != '\\';
            })) {
            return fail("CodeGenModule moduleName is not a plain .dll file name");
        }
        return true;
    }

    bool fail(const std::string& message) {
        if (error_.empty()) error_ = message;
        return false;
    }

private:
    const BinaryImage& binary_;
    size_t pointerSize_;
    std::string& error_;
};

bool readMetadataRegistration(Reader& reader, uint64_t address,
                              std::array<Version24RegistrationPair, 8>& pairs) {
    constexpr size_t strides[] = {0, 0, 12, 0, 12, 0, 0};
    constexpr const char* names[] = {
        "MetadataRegistration.genericClasses",
        "MetadataRegistration.genericInsts",
        "MetadataRegistration.genericMethodTable",
        "MetadataRegistration.types",
        "MetadataRegistration.methodSpecs",
        "MetadataRegistration.fieldOffsets",
        "MetadataRegistration.typeDefinitionsSizes"
    };
    size_t offset = 0;
    if (!reader.map(address, 16 * reader.pointerSize(), offset)) {
        return reader.fail("MetadataRegistration is truncated or not file-backed");
    }
    for (size_t index = 0; index < 7; ++index) {
        const auto stride = strides[index] == 0 ? reader.pointerSize() : strides[index];
        if (!reader.pair(address, index, stride, pairs[index], names[index])) return false;
    }
    if (!reader.pair(address, 7, reader.pointerSize(), pairs[7], "MetadataRegistration.metadataUsages")) {
        return false;
    }
    return true;
}

const std::vector<uint8_t>& bytesOf(const BinaryImage& binary) {
    return *binary.bytes;
}

bool parseModule(Reader& reader, const BinaryImage& binary, uint64_t address, uint64_t invokerCount,
                 Version24CodeGenModule& module) {
    const auto p = reader.pointerSize();
    const auto& bytes = bytesOf(binary);
    size_t base = 0;
    if (address == 0 || !reader.map(address, codeGenModuleSlots * p, base)) {
        return reader.fail("CodeGenModule is null, truncated, or not file-backed");
    }
    module.address = normalizePointer(address);
    const auto slot = [&](size_t index) {
        return normalizePointer(readPointer(bytes, base + index * p, p));
    };
    if (!reader.readModuleName(slot(0), module.name)) return false;

    uint64_t methodCount = 0;
    if (!reader.count(address + p, methodCount, "CodeGenModule.methodPointerCount")) return false;
    const auto methodPointers = slot(2);
    if (methodCount == 0) {
        if (methodPointers != 0) return reader.fail("CodeGenModule has methods pointer with zero method count");
    } else {
        if (methodPointers == 0) return reader.fail("CodeGenModule has null methodPointers");
        size_t tableBytes = 0;
        size_t tableOffset = 0;
        if (!tableSize(methodCount, p, tableBytes) || !reader.map(methodPointers, tableBytes, tableOffset)) {
            return reader.fail("CodeGenModule methodPointers table is not file-backed");
        }
        module.methodPointers.reserve(static_cast<size_t>(methodCount));
        for (size_t index = 0; index < static_cast<size_t>(methodCount); ++index) {
            auto method = normalizePointer(readPointer(bytes, tableOffset + index * p, p));
            if (binary.architecture == Architecture::Arm32) method &= ~uint64_t{1};
            if (method != 0) {
                size_t methodOffset = 0;
                if (!reader.map(method, 1, methodOffset, true)) {
                    return reader.fail("CodeGenModule contains an unmapped or non-executable method pointer");
                }
            }
            module.methodPointers.push_back(method);
        }
    }

    const auto invokerIndices = slot(3);
    if (methodCount == 0) {
        if (invokerIndices != 0) return reader.fail("CodeGenModule has invokerIndices with zero method count");
    } else {
        if (invokerIndices == 0) return reader.fail("CodeGenModule has null invokerIndices");
        size_t tableBytes = 0;
        size_t tableOffset = 0;
        if (!tableSize(methodCount, sizeof(int32_t), tableBytes) ||
            !reader.map(invokerIndices, tableBytes, tableOffset)) {
            return reader.fail("CodeGenModule invokerIndices table is not file-backed");
        }
        module.invokerIndices.reserve(static_cast<size_t>(methodCount));
        for (size_t index = 0; index < static_cast<size_t>(methodCount); ++index) {
            const auto invoker = static_cast<int32_t>(read32(bytes, tableOffset + index * sizeof(int32_t)));
            if (invoker < -1 || (invoker >= 0 && static_cast<uint64_t>(invoker) >= invokerCount)) {
                return reader.fail("CodeGenModule invoker index is outside CodeRegistration.invokerPointers");
            }
            module.invokerIndices.push_back(invoker);
        }
    }

    Version24RegistrationPair reverse;
    if (!reader.pair(address + 4 * p, 0, 8, reverse, "CodeGenModule.reversePInvokeWrapperIndices")) {
        return false;
    }
    module.reversePInvokeWrapperIndices = reverse;

    Version24RegistrationPair ranges;
    Version24RegistrationPair values;
    if (!reader.pair(address + 6 * p, 0, 12, ranges, "CodeGenModule.rgctxRanges") ||
        !reader.pair(address + 8 * p, 0, 8, values, "CodeGenModule.rgctxs")) {
        return false;
    }
    if (ranges.count != 0) {
        size_t offset = 0;
        if (!reader.map(ranges.address, static_cast<size_t>(ranges.count) * 12, offset)) {
            return reader.fail("CodeGenModule RGCTX ranges are not file-backed");
        }
        std::unordered_set<uint32_t> tokens;
        module.rgctxRanges.reserve(static_cast<size_t>(ranges.count));
        for (size_t index = 0; index < static_cast<size_t>(ranges.count); ++index) {
            const auto entry = offset + index * 12;
            RgctxRangeModel range;
            range.token = read32(bytes, entry);
            range.start = static_cast<int32_t>(read32(bytes, entry + 4));
            range.count = static_cast<int32_t>(read32(bytes, entry + 8));
            if (range.start < 0 || range.count < 0 ||
                static_cast<uint64_t>(range.start) + static_cast<uint64_t>(range.count) > values.count) {
                return reader.fail("CodeGenModule RGCTX range is negative or outside rgctxs");
            }
            if (!tokens.insert(range.token).second) return reader.fail("CodeGenModule has duplicate RGCTX tokens");
            module.rgctxRanges.push_back(range);
        }
    }
    if (values.count != 0) {
        size_t offset = 0;
        if (!reader.map(values.address, static_cast<size_t>(values.count) * 8, offset)) {
            return reader.fail("CodeGenModule RGCTX values are not file-backed");
        }
        module.rgctxValues.reserve(static_cast<size_t>(values.count));
        for (size_t index = 0; index < static_cast<size_t>(values.count); ++index) {
            const auto entry = offset + index * 8;
            module.rgctxValues.push_back({read32(bytes, entry), read32(bytes, entry + 4)});
        }
    }

    module.debuggerMetadata = slot(10);
    if (module.debuggerMetadata != 0) {
        size_t offset = 0;
        if (!reader.map(module.debuggerMetadata, 1, offset)) {
            return reader.fail("CodeGenModule debuggerMetadata is not file-backed");
        }
    }
    return true;
}

bool parseRegistration(const BinaryImage& binary, uint64_t codeRegistrationAddress,
                       uint64_t metadataRegistrationAddress, const Version24ModularLayout& layout,
                       Version24ModularResult& result, std::string& error) {
    result = Version24ModularResult{};
    result.layout = layout;
    if (!binary.bytes || binary.bytes->empty()) {
        error = "binary image has no data";
        return false;
    }
    if (layout.pointerSize != pointerSize(binary) || (layout.pointerSize != 4 && layout.pointerSize != 8)) {
        error = "binary architecture and layout pointer size differ";
        return false;
    }
    Reader reader(binary, layout.pointerSize, error);
    size_t registrationOffset = 0;
    if (codeRegistrationAddress == 0 ||
        !reader.map(codeRegistrationAddress, layout.codeRegistrationSize, registrationOffset)) {
        error = "CodeRegistration is null, truncated, or not file-backed";
        return false;
    }
    if (!fileOffsetToPointer(binary, registrationOffset, result.codeRegistrationAddress)) {
        error = "CodeRegistration file offset cannot be converted to a virtual address";
        return false;
    }

    constexpr const char* pairNames[] = {
        "CodeRegistration.reversePInvokeWrappers",
        "CodeRegistration.genericMethodPointers",
        "CodeRegistration.invokerPointers",
        "CodeRegistration.customAttributeGenerators",
        "CodeRegistration.unresolvedVirtualCallPointers",
        "CodeRegistration.interopData",
        "CodeRegistration.windowsRuntimeFactoryTable",
        "CodeRegistration.codeGenModules"
    };
    for (size_t index = 0; index <= layout.interopDataPair; ++index) {
        if (!reader.pair(codeRegistrationAddress, index, layout.pointerSize,
                         result.codeRegistrationPairs[index], pairNames[index])) {
            return false;
        }
    }
    if (layout.hasWindowsRuntimeFactory() &&
        !reader.pair(codeRegistrationAddress, layout.windowsRuntimeFactoryPair, 2 * layout.pointerSize,
                     result.codeRegistrationPairs[layout.windowsRuntimeFactoryPair],
                     pairNames[layout.windowsRuntimeFactoryPair])) {
        return false;
    }
    if (!reader.pair(codeRegistrationAddress, layout.codeGenModulesPair, layout.pointerSize,
                     result.codeRegistrationPairs[layout.codeGenModulesPair],
                     "CodeRegistration.codeGenModules")) {
        return false;
    }
    const auto& modulesPair = result.codeRegistrationPairs[layout.codeGenModulesPair];
    if (modulesPair.count == 0) {
        error = "CodeRegistration.codeGenModules is empty";
        return false;
    }

    if (!reader.functionTable(result.codeRegistrationPairs[layout.genericMethodPointersPair], false,
                              result.genericMethodPointers, pairNames[layout.genericMethodPointersPair]) ||
        !reader.functionTable(result.codeRegistrationPairs[layout.invokerPointersPair], false,
                              result.invokerPointers, pairNames[layout.invokerPointersPair])) {
        return false;
    }

    if (metadataRegistrationAddress != 0) {
        if (!readMetadataRegistration(reader, metadataRegistrationAddress, result.metadataRegistrationPairs)) {
            return false;
        }
        size_t metadataOffset = 0;
        if (!reader.map(metadataRegistrationAddress, 1, metadataOffset) ||
            !fileOffsetToPointer(binary, metadataOffset, result.metadataRegistrationAddress)) {
            error = "MetadataRegistration address cannot be canonicalized";
            return false;
        }
    }

    size_t modulesOffset = 0;
    size_t modulesBytes = 0;
    if (!tableSize(modulesPair.count, layout.pointerSize, modulesBytes) ||
        !reader.map(modulesPair.address, modulesBytes, modulesOffset)) {
        error = "CodeGenModules pointer table is not file-backed";
        return false;
    }
    const auto& bytes = *binary.bytes;
    std::unordered_set<std::string> names;
    std::unordered_set<uint64_t> addresses;
    bool anyMethod = false;
    result.modules.reserve(static_cast<size_t>(modulesPair.count));
    for (size_t index = 0; index < static_cast<size_t>(modulesPair.count); ++index) {
        const auto moduleAddress = normalizePointer(
            readPointer(bytes, modulesOffset + index * layout.pointerSize, layout.pointerSize));
        Version24CodeGenModule module;
        if (!parseModule(reader, binary, moduleAddress, result.invokerPointers.size(), module)) return false;
        if (!names.insert(module.name).second) {
            error = "CodeGenModules contains duplicate module names";
            return false;
        }
        if (!addresses.insert(module.address).second) {
            error = "CodeGenModules contains duplicate module addresses";
            return false;
        }
        anyMethod = anyMethod || !module.methodPointers.empty();
        result.modules.push_back(std::move(module));
    }
    if (!anyMethod) {
        error = "CodeGenModules contains no method pointers";
        return false;
    }
    result.detected = true;
    return true;
}

std::string variantName(Version24ModularVariant variant) {
    return variant == Version24ModularVariant::V24_2 ? "24.2" : "24.3";
}

} // namespace

Version24ModularLayout Version24ModularLayout::make(Version24ModularVariant selected, size_t nativePointerSize) {
    Version24ModularLayout layout;
    layout.variant = selected;
    layout.pointerSize = nativePointerSize;
    if (selected == Version24ModularVariant::V24_3) {
        layout.windowsRuntimeFactoryPair = 6;
        layout.codeGenModulesPair = 7;
    }
    layout.codeRegistrationSize = (layout.codeGenModulesPair + 1) * 2 * nativePointerSize;
    layout.codeGenModuleSize = codeGenModuleSlots * nativePointerSize;
    return layout;
}

double Version24ModularLayout::version() const noexcept {
    return variant == Version24ModularVariant::V24_2 ? 24.2 : 24.3;
}

bool Version24ModularLayout::hasWindowsRuntimeFactory() const noexcept {
    return windowsRuntimeFactoryPair != noPair;
}

bool Version24ModularResult::ok() const noexcept {
    return detected;
}

const Version24CodeGenModule* Version24ModularResult::findModule(std::string_view imageName) const noexcept {
    for (const auto& module : modules) {
        if (module.name == imageName) return &module;
    }
    return nullptr;
}

std::optional<uint64_t> Version24ModularResult::methodPointer(
    std::string_view imageName, uint32_t methodDefToken) const {
    const auto* module = findModule(imageName);
    const auto index = version24MethodDefIndex(methodDefToken);
    if (!module || !index || *index >= module->methodPointers.size()) return std::nullopt;
    return module->methodPointers[*index];
}

std::optional<uint32_t> version24MethodDefRid(uint32_t token) noexcept {
    if ((token & ~methodDefRidMask) != methodDefTable) return std::nullopt;
    const auto rid = token & methodDefRidMask;
    if (rid == 0) return std::nullopt;
    return rid;
}

std::optional<size_t> version24MethodDefIndex(uint32_t token) noexcept {
    const auto rid = version24MethodDefRid(token);
    if (!rid) return std::nullopt;
    return static_cast<size_t>(*rid - 1);
}

bool Version24Modular::supports(double metadataVersion) noexcept {
    return variantFor(metadataVersion).has_value();
}

std::optional<Version24ModularVariant> Version24Modular::variantFor(double metadataVersion) noexcept {
    if (std::abs(metadataVersion - 24.2) < 0.001) return Version24ModularVariant::V24_2;
    if (std::abs(metadataVersion - 24.3) < 0.001) return Version24ModularVariant::V24_3;
    return std::nullopt;
}

Version24ModularResult Version24Modular::inspect(
    const BinaryImage& binary,
    uint64_t codeRegistrationAddress,
    std::optional<Version24ModularVariant> expected,
    uint64_t metadataRegistrationAddress) const {
    const auto p = pointerSize(binary);
    Version24ModularResult result;
    result.layout.pointerSize = p;
    result.codeRegistrationAddress = codeRegistrationAddress;
    result.metadataRegistrationAddress = metadataRegistrationAddress;
    if (p == 0) {
        result.diagnostics.push_back("unsupported binary architecture for metadata 24 modular layouts");
        return result;
    }

    const Version24ModularVariant variants[] = {
        Version24ModularVariant::V24_2,
        Version24ModularVariant::V24_3
    };
    std::optional<Version24ModularResult> match;
    std::vector<std::string> errors;
    for (const auto variant : variants) {
        if (expected && variant != *expected) continue;
        Version24ModularResult candidate;
        std::string error;
        if (parseRegistration(binary, codeRegistrationAddress, metadataRegistrationAddress,
                              Version24ModularLayout::make(variant, p), candidate, error)) {
            if (match) {
                result.diagnostics.push_back("ambiguous CodeRegistration: both 24.2 and 24.3 layouts match");
                return result;
            }
            match = std::move(candidate);
        } else {
            errors.push_back("metadata " + variantName(variant) + ": " + error);
        }
    }
    if (match) return std::move(*match);
    result.diagnostics.insert(result.diagnostics.end(), errors.begin(), errors.end());
    return result;
}

Version24ModularResult Version24Modular::detect(
    const BinaryImage& binary,
    uint64_t codeRegistrationAddress,
    std::optional<double> expectedVersion,
    uint64_t metadataRegistrationAddress) const {
    std::optional<Version24ModularVariant> expected;
    if (expectedVersion) {
        expected = variantFor(*expectedVersion);
        if (!expected) {
            Version24ModularResult result;
            result.diagnostics.push_back("metadata version is not exactly 24.2 or 24.3");
            return result;
        }
    }
    if (codeRegistrationAddress != 0) {
        return inspect(binary, codeRegistrationAddress, expected, metadataRegistrationAddress);
    }

    Version24ModularResult failure;
    if (!binary.bytes || binary.bytes->empty()) {
        failure.diagnostics.push_back("binary image has no data");
        return failure;
    }
    const auto p = pointerSize(binary);
    if (p == 0) {
        failure.diagnostics.push_back("unsupported binary architecture for metadata 24 modular layouts");
        return failure;
    }
    if (binary.bytes->size() < p) {
        failure.diagnostics.push_back("binary image is smaller than a native pointer");
        return failure;
    }
    std::optional<Version24ModularResult> match;
    for (size_t offset = 0; offset <= binary.bytes->size() - p; offset += p) {
        uint64_t address = 0;
        if (!fileOffsetToPointer(binary, offset, address)) continue;
        auto candidate = inspect(binary, address, expected, metadataRegistrationAddress);
        if (!candidate.detected) continue;
        if (match) {
            failure.diagnostics.push_back("strict detection found more than one valid CodeRegistration");
            return failure;
        }
        match = std::move(candidate);
    }
    if (match) return std::move(*match);
    failure.diagnostics.push_back("no strictly valid 24.2/24.3 CodeRegistration was found");
    return failure;
}

Version24ModularResult Version24Modular::apply(
    const BinaryImage& binary,
    MetadataModel& metadata,
    uint64_t codeRegistrationAddress,
    uint64_t metadataRegistrationAddress) const {
    if (codeRegistrationAddress == 0) codeRegistrationAddress = metadata.codeRegistrationAddress;
    if (metadataRegistrationAddress == 0) metadataRegistrationAddress = metadata.metadataRegistrationAddress;
    const auto expected = metadata.version == 0
        ? std::optional<double>{}
        : std::optional<double>{metadata.version};
    auto result = detect(binary, codeRegistrationAddress, expected, metadataRegistrationAddress);
    if (!result.detected) return result;

    MetadataModel updated = metadata;
    updated.version = result.layout.version();
    updated.versionInfo.rawVersion = 24;
    updated.versionInfo.preciseVersion = result.layout.version();
    updated.versionInfo.registrationVersion = result.layout.version();
    updated.versionInfo.confidence = MetadataVersionConfidence::Registration;
    updated.codeRegistrationAddress = result.codeRegistrationAddress;
    if (result.metadataRegistrationAddress != 0) {
        updated.metadataRegistrationAddress = result.metadataRegistrationAddress;
        updated.metadataUsagesCount = result.metadataRegistrationPairs[
            static_cast<size_t>(Version24MetadataRegistrationPair::MetadataUsages)].count;
    }
    updated.genericMethodPointers = result.genericMethodPointers;
    updated.invokerPointers = result.invokerPointers;
    updated.invokerIndices.clear();
    updated.rgctxRanges.clear();
    updated.rgctxValues.clear();

    for (const auto& module : result.modules) {
        updated.methodPointersByImage.insert_or_assign(module.name, module.methodPointers);
        const auto invokerStart = updated.invokerIndices.size();
        const auto rgctxStart = updated.rgctxRanges.size();
        updated.invokerIndices.insert(updated.invokerIndices.end(),
                                      module.invokerIndices.begin(), module.invokerIndices.end());
        for (auto range : module.rgctxRanges) {
            if (range.start >= 0) range.start += static_cast<int32_t>(updated.rgctxValues.size());
            updated.rgctxRanges.push_back(range);
        }
        updated.rgctxValues.insert(updated.rgctxValues.end(), module.rgctxValues.begin(), module.rgctxValues.end());
        for (auto& image : updated.images) {
            if (image.name != module.name) continue;
            image.invokerIndicesStart = static_cast<int32_t>(invokerStart);
            image.rgctxRangesStart = static_cast<int32_t>(rgctxStart);
            image.rgctxRangesCount = static_cast<int32_t>(module.rgctxRanges.size());
            break;
        }
    }
    metadata = std::move(updated);
    return result;
}

} // namespace il2cpprec::versions
