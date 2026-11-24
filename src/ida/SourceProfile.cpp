#include <il2cpprec/ida/SourceProfile.hpp>

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <initializer_list>
#include <limits>
#include <sstream>
#include <utility>

namespace il2cpprec::ida {
namespace {

NativeFieldLayout field(std::size_t offset, std::size_t size) {
    return {offset, size, true};
}

NativeFieldLayout absentField() {
    return {0, 0, false};
}

NativeTableLayout table(std::size_t pointerSize, std::size_t index) {
    return {
        field(index * pointerSize, sizeof(std::uint32_t)),
        field((index + 1) * pointerSize, pointerSize)
    };
}

NativeTableLayout absentTable() {
    return {absentField(), absentField()};
}

std::size_t alignUp(std::size_t value, std::size_t alignment) {
    return (value + alignment - 1) / alignment * alignment;
}

MethodInfoSourceLayout makeMethodInfo(std::size_t pointerSize, bool hasCustomAttributeIndex) {
    MethodInfoSourceLayout layout;
    layout.alignment = pointerSize;
    layout.methodPointer = field(0 * pointerSize, pointerSize);
    layout.invokerMethod = field(1 * pointerSize, pointerSize);
    layout.name = field(2 * pointerSize, pointerSize);
    layout.declaringType = field(3 * pointerSize, pointerSize);
    layout.returnType = field(4 * pointerSize, pointerSize);
    layout.parameters = field(5 * pointerSize, pointerSize);
    layout.rgctxData = field(6 * pointerSize, pointerSize);
    layout.genericMethod = field(7 * pointerSize, pointerSize);
    layout.customAttributeIndex = absentField();

    std::size_t cursor = 8 * pointerSize;
    if (hasCustomAttributeIndex) {
        layout.customAttributeIndex = field(cursor, sizeof(std::uint32_t));
        cursor += sizeof(std::uint32_t);
    }
    layout.token = field(cursor, sizeof(std::uint32_t));
    cursor += sizeof(std::uint32_t);
    layout.flags = field(cursor, sizeof(std::uint16_t));
    cursor += sizeof(std::uint16_t);
    layout.iflags = field(cursor, sizeof(std::uint16_t));
    cursor += sizeof(std::uint16_t);
    layout.slot = field(cursor, sizeof(std::uint16_t));
    cursor += sizeof(std::uint16_t);
    layout.parametersCount = field(cursor, sizeof(std::uint8_t));
    cursor += sizeof(std::uint8_t);
    layout.methodFlags = field(cursor, sizeof(std::uint8_t));
    cursor += sizeof(std::uint8_t);
    layout.size = alignUp(cursor, pointerSize);
    return layout;
}

CodeRegistrationSourceLayout makeLegacyCodeRegistration(std::size_t pointerSize, bool hasWindowsRuntimeFactory) {
    CodeRegistrationSourceLayout layout;
    layout.alignment = pointerSize;
    layout.methodPointers = table(pointerSize, 0);
    layout.reversePInvokeWrappers = table(pointerSize, 2);
    layout.genericMethodPointers = table(pointerSize, 4);
    layout.genericAdjustorThunks = absentField();
    layout.invokerPointers = table(pointerSize, 6);
    layout.customAttributeGenerators = table(pointerSize, 8);
    layout.unresolvedVirtualCallPointers = table(pointerSize, 10);
    layout.interopData = table(pointerSize, 12);
    layout.windowsRuntimeFactoryTable = absentTable();
    layout.codeGenModules = absentTable();
    std::size_t slots = 14;
    if (hasWindowsRuntimeFactory) {
        layout.windowsRuntimeFactoryTable = table(pointerSize, 14);
        slots = 16;
    }
    layout.size = slots * pointerSize;
    return layout;
}

CodeRegistrationSourceLayout makeModularCodeRegistration(std::size_t pointerSize) {
    CodeRegistrationSourceLayout layout;
    layout.alignment = pointerSize;
    layout.methodPointers = absentTable();
    layout.reversePInvokeWrappers = table(pointerSize, 0);
    layout.genericMethodPointers = table(pointerSize, 2);
    layout.genericAdjustorThunks = field(4 * pointerSize, pointerSize);
    layout.invokerPointers = table(pointerSize, 5);
    layout.customAttributeGenerators = table(pointerSize, 7);
    layout.unresolvedVirtualCallPointers = table(pointerSize, 9);
    layout.interopData = table(pointerSize, 11);
    layout.windowsRuntimeFactoryTable = table(pointerSize, 13);
    layout.codeGenModules = table(pointerSize, 15);
    layout.size = 17 * pointerSize;
    return layout;
}

MetadataRegistrationSourceLayout makeMetadataRegistration(std::size_t pointerSize) {
    MetadataRegistrationSourceLayout layout;
    layout.alignment = pointerSize;
    layout.genericClasses = table(pointerSize, 0);
    layout.genericInsts = table(pointerSize, 2);
    layout.genericMethodTable = table(pointerSize, 4);
    layout.types = table(pointerSize, 6);
    layout.methodSpecs = table(pointerSize, 8);
    layout.fieldOffsets = table(pointerSize, 10);
    layout.typeDefinitionsSizes = table(pointerSize, 12);
    layout.metadataUsages = table(pointerSize, 14);
    layout.metadataUsages.count.size = pointerSize;
    layout.size = 16 * pointerSize;
    return layout;
}

CodeGenModuleSourceLayout makeCodeGenModule(std::size_t pointerSize) {
    CodeGenModuleSourceLayout layout;
    layout.alignment = pointerSize;
    layout.moduleName = field(0 * pointerSize, pointerSize);
    layout.methodPointerCount = field(1 * pointerSize, sizeof(std::uint32_t));
    layout.methodPointers = field(2 * pointerSize, pointerSize);
    layout.adjustorThunkCount = field(3 * pointerSize, sizeof(std::uint32_t));
    layout.adjustorThunks = field(4 * pointerSize, pointerSize);
    layout.invokerIndices = field(5 * pointerSize, pointerSize);
    layout.reversePInvokeWrapperIndices = table(pointerSize, 6);
    layout.rgctxRanges = table(pointerSize, 8);
    layout.rgctxs = table(pointerSize, 10);
    layout.debuggerMetadata = field(12 * pointerSize, pointerSize);
    layout.size = 13 * pointerSize;
    return layout;
}

ManagedObjectSourceLayout makeObject(std::size_t pointerSize) {
    return {2 * pointerSize, field(0, pointerSize), field(pointerSize, pointerSize)};
}

ManagedArraySourceLayout makeArray(std::size_t pointerSize) {
    ManagedArraySourceLayout layout;
    layout.size = 4 * pointerSize;
    layout.klass = field(0, pointerSize);
    layout.monitor = field(pointerSize, pointerSize);
    layout.bounds = field(2 * pointerSize, pointerSize);
    layout.length = field(3 * pointerSize, sizeof(std::uint32_t));
    layout.data = field(4 * pointerSize, 0);
    layout.dataAlignment = 8;
    return layout;
}

ManagedStringSourceLayout makeString(std::size_t pointerSize) {
    ManagedStringSourceLayout layout;
    layout.size = 2 * pointerSize + sizeof(std::uint32_t);
    layout.klass = field(0, pointerSize);
    layout.monitor = field(pointerSize, pointerSize);
    layout.length = field(2 * pointerSize, sizeof(std::uint32_t));
    layout.chars = field(layout.size, 0);
    return layout;
}

bool versionIs(double value, double expected) {
    return std::abs(value - expected) < 0.001;
}

std::string versionText(double version) {
    std::ostringstream output;
    output << std::fixed << std::setprecision(1) << version;
    return output.str();
}

class Fnv1a64 {
public:
    void add(std::string_view value) {
        for (const unsigned char byte : value) addByte(byte);
    }

    void add(std::uint64_t value) {
        for (unsigned shift = 0; shift != 64; shift += 8) {
            addByte(static_cast<unsigned char>((value >> shift) & 0xff));
        }
    }

    std::string str() const {
        std::ostringstream output;
        output << "fnv1a64:" << std::hex << std::setfill('0') << std::setw(16) << value_;
        return output.str();
    }

private:
    void addByte(unsigned char byte) {
        value_ ^= byte;
        value_ *= 1099511628211ULL;
    }

    std::uint64_t value_ = 14695981039346656037ULL;
};

void hashField(Fnv1a64& hash, std::string_view name, const NativeFieldLayout& field) {
    hash.add(name);
    hash.add(field.offset);
    hash.add(field.size);
    hash.add(field.present);
}

void hashTable(Fnv1a64& hash, std::string_view name, const NativeTableLayout& table) {
    hash.add(name);
    hashField(hash, "count", table.count);
    hashField(hash, "pointer", table.pointer);
}

void checkField(
    std::vector<std::string>& errors,
    std::string_view owner,
    std::string_view name,
    const NativeFieldLayout& field,
    std::size_t structSize) {
    if (!field.present) return;
    if (field.offset > structSize || field.size > structSize - field.offset) {
        errors.push_back(std::string(owner) + "." + std::string(name) + " is outside the native structure");
    }
}

void checkTable(
    std::vector<std::string>& errors,
    std::string_view owner,
    std::string_view name,
    const NativeTableLayout& table,
    std::size_t structSize) {
    if (table.count.present != table.pointer.present) {
        errors.push_back(std::string(owner) + "." + std::string(name) + " has an incomplete count/pointer pair");
        return;
    }
    checkField(errors, owner, "count", table.count, structSize);
    checkField(errors, owner, "pointer", table.pointer, structSize);
    if (table.count.present && table.pointer.offset < table.count.offset + table.count.size) {
        errors.push_back(std::string(owner) + "." + std::string(name) + " count overlaps its pointer");
    }
}

void checkFields(
    std::vector<std::string>& errors,
    std::string_view owner,
    std::size_t structSize,
    std::initializer_list<std::pair<std::string_view, const NativeFieldLayout*>> fields) {
    for (const auto& [name, field] : fields) checkField(errors, owner, name, *field, structSize);
}

void checkTables(
    std::vector<std::string>& errors,
    std::string_view owner,
    std::size_t structSize,
    std::initializer_list<std::pair<std::string_view, const NativeTableLayout*>> tables) {
    for (const auto& [name, table] : tables) checkTable(errors, owner, name, *table, structSize);
}

GlobalMetadataSourceLayout makeGlobalMetadata(double version) {
    GlobalMetadataSourceLayout layout;
    layout.version = version;
    layout.rawVersion = static_cast<int>(version);
    if (versionIs(version, 24.1) || versionIs(version, 24.2) || versionIs(version, 24.3) ||
        versionIs(version, 24.4) || versionIs(version, 24.5) || versionIs(version, 27.1) ||
        versionIs(version, 27.2) || versionIs(version, 29.1) || versionIs(version, 31.1)) {
        layout.rawVersion = static_cast<int>(version);
    }
    if (version < 16.0 || version > 31.1) return {};

    if (version <= 20.0) layout.typeDefinitionStride = 112;
    else if (version <= 22.0) layout.typeDefinitionStride = 120;
    else if (version <= 24.1) layout.typeDefinitionStride = 104;
    else if (versionIs(version, 24.2)) layout.typeDefinitionStride = 92;
    else if (versionIs(version, 24.3)) layout.typeDefinitionStride = 88;
    else if (versionIs(version, 24.4)) layout.typeDefinitionStride = 96;
    else if (versionIs(version, 24.5)) layout.typeDefinitionStride = 92;
    else layout.typeDefinitionStride = 88;

    if (version <= 24.1) layout.methodDefinitionStride = 56;
    else if (version >= 31.0) layout.methodDefinitionStride = 36;
    else layout.methodDefinitionStride = 32;
    layout.parameterDefinitionStride = version <= 24.0 ? 16 : 12;
    layout.fieldDefinitionStride = version < 19.0 ? 12 : (version <= 24.0 ? 16 : 12);
    layout.imageDefinitionStride = 20;
    if (version >= 19.0) layout.imageDefinitionStride += 4;
    if (version >= 24.0) layout.imageDefinitionStride += 8;
    if (version >= 24.1) layout.imageDefinitionStride += 8;
    layout.assemblyDefinitionStride = version < 20.0 ? 60 : 68;
    if (version >= 24.4) layout.assemblyDefinitionStride = 64;

    if (version < 19.0) layout.headerSize = 192;
    else if (version < 20.0) layout.headerSize = 216;
    else if (version < 21.0) layout.headerSize = 224;
    else if (version < 22.0) layout.headerSize = 240;
    else if (version < 23.0) layout.headerSize = 256;
    else if (versionIs(version, 24.0)) layout.headerSize = 240;
    else if (versionIs(version, 24.1)) layout.headerSize = 272;
    else if (versionIs(version, 24.2)) layout.headerSize = 264;
    else if (version < 23.0) layout.headerSize = 264;
    else if (version < 28.0) layout.headerSize = 256;
    else if (version < 29.0) layout.headerSize = 240;
    else layout.headerSize = 256;
    if (version >= 23.0 && version < 24.0) layout.headerSize = 264;
    layout.imagesOffset = version <= 24.1 ? 176 : 168;
    layout.assembliesOffset = layout.imagesOffset + 8;
    return layout;
}

std::optional<std::uint32_t> read32(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset > data.size() || data.size() - offset < 4) return std::nullopt;
    return static_cast<std::uint32_t>(data[offset]) |
        (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::optional<std::uint64_t> readPointer(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t pointerSize) {
    const auto low = read32(data, offset);
    if (!low) return std::nullopt;
    if (pointerSize == 4) return *low;
    const auto high = read32(data, offset + 4);
    if (!high) return std::nullopt;
    return static_cast<std::uint64_t>(*low) | (static_cast<std::uint64_t>(*high) << 32);
}

std::optional<std::vector<std::uint8_t>> binaryBytes(const BinaryImage& binary, std::uint64_t address, std::size_t size) {
    if (!binary.bytes || size == 0) return std::nullopt;
    const auto map = [&](std::uint64_t rva) -> std::optional<std::vector<std::uint8_t>> {
        const auto offset = binary.mapVATR(rva);
        if (offset > binary.bytes->size() || size > binary.bytes->size() - static_cast<std::size_t>(offset)) {
            return std::nullopt;
        }
        const auto begin = binary.bytes->begin() + static_cast<std::size_t>(offset);
        return std::vector<std::uint8_t>(begin, begin + static_cast<std::size_t>(size));
    };
    if (address >= binary.imageBase) {
        if (auto result = map(address - binary.imageBase)) return result;
    }
    return map(address);
}

bool validCountAndPointer(
    const std::vector<std::uint8_t>& data,
    const NativeTableLayout& table,
    std::size_t pointerSize) {
    if (!table.count.present) return true;
    const auto count = read32(data, table.count.offset);
    const auto pointer = readPointer(data, table.pointer.offset, pointerSize);
    if (!count || !pointer || *count > 100000000) return false;
    return *count == 0 || *pointer != 0;
}

bool metadataRegistrationValid(const BinaryImage& binary, const SourceLayoutSelection& selection, std::uint64_t address) {
    const auto data = binaryBytes(binary, address, selection.metadataRegistration.size);
    if (!data) return false;
    const auto& layout = selection.metadataRegistration;
    return validCountAndPointer(*data, layout.types, selection.pointerSize) &&
        validCountAndPointer(*data, layout.fieldOffsets, selection.pointerSize);
}

bool codeRegistrationValid(const BinaryImage& binary, const SourceLayoutSelection& selection, std::uint64_t address) {
    const auto data = binaryBytes(binary, address, selection.codeRegistration.size);
    if (!data) return false;
    const auto& layout = selection.codeRegistration;
    const NativeTableLayout* tables[] = {
        &layout.methodPointers, &layout.reversePInvokeWrappers, &layout.genericMethodPointers,
        &layout.invokerPointers, &layout.customAttributeGenerators, &layout.unresolvedVirtualCallPointers,
        &layout.interopData, &layout.windowsRuntimeFactoryTable, &layout.codeGenModules
    };
    for (const auto* table : tables) {
        if (!validCountAndPointer(*data, *table, selection.pointerSize)) return false;
    }
    if (layout.codeGenModules.count.present) {
        const auto count = read32(*data, layout.codeGenModules.count.offset);
        const auto pointer = readPointer(*data, layout.codeGenModules.pointer.offset, selection.pointerSize);
        if (!count || !pointer || (*count != 0 && *pointer == 0)) return false;
    }
    return true;
}

std::optional<bool> observedCodeGenModules(const BinaryImage& binary, const SourceLayoutSelection& selection, std::uint64_t address) {
    if (!selection.codeRegistration.codeGenModules.count.present) return std::nullopt;
    const auto data = binaryBytes(binary, address, selection.codeRegistration.size);
    if (!data) return std::nullopt;
    const auto count = read32(*data, selection.codeRegistration.codeGenModules.count.offset);
    const auto pointer = readPointer(*data, selection.codeRegistration.codeGenModules.pointer.offset, selection.pointerSize);
    if (!count || !pointer) return std::nullopt;
    return *count != 0 && *pointer != 0;
}

std::string confidenceText(NativeProfileConfidence confidence) {
    switch (confidence) {
    case NativeProfileConfidence::Exact: return "exact";
    case NativeProfileConfidence::High: return "high";
    case NativeProfileConfidence::Compatible: return "compatible";
    case NativeProfileConfidence::Override: return "override";
    case NativeProfileConfidence::Unsupported: return "unsupported";
    }
    return "unsupported";
}

} // namespace

std::size_t sourcePointerSize(const BinaryImage& binary) noexcept {
    switch (binary.architecture) {
    case Architecture::Arm32:
    case Architecture::X86:
        return 4;
    case Architecture::Arm64:
    case Architecture::X64:
        return 8;
    }
    return 0;
}

SourceLayoutSelection SourceProfile::resolve(double version, std::size_t pointerSize) const {
    SourceLayoutSelection selection;
    selection.profile = this;
    selection.metadataVersion = version == 0 ? canonicalMetadataVersion : version;
    selection.pointerSize = pointerSize;
    selection.confidence = confidence;
    selection.provenance = provenance;
    if (pointerSize != 4 && pointerSize != 8) return selection;

    const bool base24 = id == "il2cpp-24-base";
    const bool base27 = id == "il2cpp-27";
    const bool versionMatches = canonicalMetadataVersion != 0 &&
        (versionIs(selection.metadataVersion, canonicalMetadataVersion) ||
         (base27 && selection.metadataVersion >= 27.0 && selection.metadataVersion <= 27.2));
    const bool familyMatches = base24 && selection.metadataVersion >= 24.0 && selection.metadataVersion <= 24.5;
    if ((!versionMatches && !familyMatches) || selection.metadataVersion == 0) return selection;

    selection.globalMetadata = makeGlobalMetadata(selection.metadataVersion);
    if (selection.globalMetadata.typeDefinitionStride == 0) return selection;
    selection.variant = versionText(selection.metadataVersion);
    selection.methodMapping = selection.metadataVersion >= 24.5
        ? MethodMapping::PerImageTokenRowId
        : MethodMapping::GlobalMethodIndex;
    selection.nativeRuntimeAvailable = selection.metadataVersion >= 24.0 && selection.metadataVersion <= 24.5;
    if (selection.nativeRuntimeAvailable) {
        const bool customAttributeIndex = exact || versionIs(selection.metadataVersion, 24.0) ||
            versionIs(selection.metadataVersion, 24.1) || versionIs(selection.metadataVersion, 24.2);
        selection.methodInfo = makeMethodInfo(pointerSize, customAttributeIndex);
        selection.metadataRegistration = makeMetadataRegistration(pointerSize);
        if (selection.metadataVersion <= 24.3) {
            selection.codeRegistration = makeLegacyCodeRegistration(pointerSize, false);
        } else if (versionIs(selection.metadataVersion, 24.4)) {
            selection.codeRegistration = makeLegacyCodeRegistration(pointerSize, true);
        } else {
            selection.codeRegistration = makeModularCodeRegistration(pointerSize);
            selection.codeGenModule = makeCodeGenModule(pointerSize);
            selection.codeGenModules = CodeGenModulePresence::Present;
        }
    }
    selection.object = makeObject(pointerSize);
    selection.array = makeArray(pointerSize);
    selection.string = makeString(pointerSize);
    if (exact) selection.variant = "2017.4.11f1-metadata-24.0";
    selection.supported = true;
    return selection;
}

SourceLayoutSelection SourceProfile::resolve(double metadataVersion, const BinaryImage& binary) const {
    return resolve(metadataVersion, sourcePointerSize(binary));
}

std::string SourceProfile::profileHash() const {
    Fnv1a64 hash;
    hash.add(id);
    hash.add(unityVersion);
    hash.add(metadataRange);
    hash.add(sourceSet);
    hash.add(exact);
    hash.add(versionText(canonicalMetadataVersion));
    hash.add(static_cast<std::uint64_t>(confidence));
    hash.add(provenance);
    if (canonicalMetadataVersion != 0) {
        const auto global = makeGlobalMetadata(canonicalMetadataVersion);
        hash.add(global.headerSize);
        hash.add(global.imagesOffset);
        hash.add(global.assembliesOffset);
        hash.add(global.typeDefinitionStride);
        hash.add(global.methodDefinitionStride);
        hash.add(global.parameterDefinitionStride);
        hash.add(global.fieldDefinitionStride);
        hash.add(global.imageDefinitionStride);
        hash.add(global.assemblyDefinitionStride);
    }
    return hash.str();
}

std::string SourceProfile::diagnostics() const {
    return "profile=" + id + ";profile-version=" + unityVersion + ";metadata=" + metadataRange +
        ";source-set=" + sourceSet + ";profile-hash=" + profileHash();
}

std::string SourceLayoutSelection::layoutHash() const {
    Fnv1a64 hash;
    if (profile) hash.add(profile->profileHash());
    hash.add(variant);
    hash.add(versionText(metadataVersion));
    hash.add(pointerSize);
    hash.add(supported);
    hash.add(nativeRuntimeAvailable);
    hash.add(static_cast<std::uint64_t>(methodMapping));
    hash.add(static_cast<std::uint64_t>(codeGenModules));
    hash.add(globalMetadata.rawVersion);
    hash.add(globalMetadata.headerSize);
    hash.add(globalMetadata.imagesOffset);
    hash.add(globalMetadata.assembliesOffset);
    hash.add(globalMetadata.typeDefinitionStride);
    hash.add(globalMetadata.methodDefinitionStride);
    hash.add(globalMetadata.parameterDefinitionStride);
    hash.add(globalMetadata.fieldDefinitionStride);
    hash.add(globalMetadata.imageDefinitionStride);
    hash.add(globalMetadata.assemblyDefinitionStride);

    const auto& method = methodInfo;
    hash.add(method.size);
    hash.add(method.alignment);
    hashField(hash, "methodPointer", method.methodPointer);
    hashField(hash, "invokerMethod", method.invokerMethod);
    hashField(hash, "name", method.name);
    hashField(hash, "declaringType", method.declaringType);
    hashField(hash, "returnType", method.returnType);
    hashField(hash, "parameters", method.parameters);
    hashField(hash, "rgctxData", method.rgctxData);
    hashField(hash, "genericMethod", method.genericMethod);
    hashField(hash, "customAttributeIndex", method.customAttributeIndex);
    hashField(hash, "token", method.token);
    hashField(hash, "flags", method.flags);
    hashField(hash, "iflags", method.iflags);
    hashField(hash, "slot", method.slot);
    hashField(hash, "parametersCount", method.parametersCount);
    hashField(hash, "methodFlags", method.methodFlags);

    const auto& code = codeRegistration;
    hash.add(code.size);
    hash.add(code.alignment);
    hashTable(hash, "methodPointers", code.methodPointers);
    hashTable(hash, "reversePInvokeWrappers", code.reversePInvokeWrappers);
    hashTable(hash, "genericMethodPointers", code.genericMethodPointers);
    hashField(hash, "genericAdjustorThunks", code.genericAdjustorThunks);
    hashTable(hash, "invokerPointers", code.invokerPointers);
    hashTable(hash, "customAttributeGenerators", code.customAttributeGenerators);
    hashTable(hash, "unresolvedVirtualCallPointers", code.unresolvedVirtualCallPointers);
    hashTable(hash, "interopData", code.interopData);
    hashTable(hash, "windowsRuntimeFactoryTable", code.windowsRuntimeFactoryTable);
    hashTable(hash, "codeGenModules", code.codeGenModules);

    const auto& metadata = metadataRegistration;
    hash.add(metadata.size);
    hash.add(metadata.alignment);
    hashTable(hash, "genericClasses", metadata.genericClasses);
    hashTable(hash, "genericInsts", metadata.genericInsts);
    hashTable(hash, "genericMethodTable", metadata.genericMethodTable);
    hashTable(hash, "types", metadata.types);
    hashTable(hash, "methodSpecs", metadata.methodSpecs);
    hashTable(hash, "fieldOffsets", metadata.fieldOffsets);
    hashTable(hash, "typeDefinitionsSizes", metadata.typeDefinitionsSizes);
    hashTable(hash, "metadataUsages", metadata.metadataUsages);

    const auto& module = codeGenModule;
    hash.add(module.size);
    hash.add(module.alignment);
    hashField(hash, "moduleName", module.moduleName);
    hashField(hash, "methodPointerCount", module.methodPointerCount);
    hashField(hash, "methodPointers", module.methodPointers);
    hashField(hash, "adjustorThunkCount", module.adjustorThunkCount);
    hashField(hash, "adjustorThunks", module.adjustorThunks);
    hashField(hash, "invokerIndices", module.invokerIndices);
    hashTable(hash, "reversePInvokeWrapperIndices", module.reversePInvokeWrapperIndices);
    hashTable(hash, "rgctxRanges", module.rgctxRanges);
    hashTable(hash, "rgctxs", module.rgctxs);
    hashField(hash, "debuggerMetadata", module.debuggerMetadata);

    hash.add(object.size);
    hashField(hash, "object.klass", object.klass);
    hashField(hash, "object.monitor", object.monitor);
    hash.add(array.size);
    hashField(hash, "array.klass", array.klass);
    hashField(hash, "array.monitor", array.monitor);
    hashField(hash, "array.bounds", array.bounds);
    hashField(hash, "array.length", array.length);
    hashField(hash, "array.data", array.data);
    hash.add(array.dataAlignment);
    hash.add(string.size);
    hashField(hash, "string.klass", string.klass);
    hashField(hash, "string.monitor", string.monitor);
    hashField(hash, "string.length", string.length);
    hashField(hash, "string.chars", string.chars);
    return hash.str();
}

std::string SourceLayoutSelection::diagnostics() const {
    std::string result = profile ? profile->diagnostics() : "profile=<missing>";
    result += ";metadata-selected=" + versionText(metadataVersion) + ";layout-variant=" + variant +
        ";pointer-size=" + std::to_string(pointerSize) + ";method-mapping=" +
        (methodMapping == MethodMapping::PerImageTokenRowId ? "per-image-token-row" : "global-method-index") +
        ";codegen-modules=" + std::string(codeGenModules == CodeGenModulePresence::Present ? "present" : "absent") +
        ";confidence=" + confidenceText(confidence) + ";provenance=" + provenance +
        ";native-runtime=" + (nativeRuntimeAvailable ? "available" : "unavailable") +
        ";type-stride=" + std::to_string(globalMetadata.typeDefinitionStride) +
        ";layout-hash=" + layoutHash() + ";supported=" + (supported ? "true" : "false");
    if (supported) {
        const auto errors = validateSourceLayout(*this);
        result += errors.empty() ? ";validation=ok" : ";validation=" + errors.front();
    }
    return result;
}

std::vector<std::string> validateSourceLayout(const SourceLayoutSelection& selection) {
    std::vector<std::string> errors;
    if (!selection.profile) errors.push_back("source profile is missing");
    if (selection.pointerSize != 4 && selection.pointerSize != 8) {
        errors.push_back("native pointer size must be 4 or 8 bytes");
    }
    if (!selection.supported) {
        errors.push_back("source profile and metadata version combination is unsupported");
        return errors;
    }

    if (selection.globalMetadata.typeDefinitionStride == 0 || selection.globalMetadata.headerSize == 0) {
        errors.push_back("global metadata layout is unavailable");
    }
    if (selection.nativeRuntimeAvailable) {
    const auto& method = selection.methodInfo;
    checkFields(errors, "MethodInfo", method.size, {
        {"methodPointer", &method.methodPointer}, {"invokerMethod", &method.invokerMethod},
        {"name", &method.name}, {"declaringType", &method.declaringType},
        {"returnType", &method.returnType}, {"parameters", &method.parameters},
        {"rgctxData", &method.rgctxData}, {"genericMethod", &method.genericMethod},
        {"customAttributeIndex", &method.customAttributeIndex}, {"token", &method.token},
        {"flags", &method.flags}, {"iflags", &method.iflags}, {"slot", &method.slot},
        {"parametersCount", &method.parametersCount}, {"methodFlags", &method.methodFlags}
    });

    const auto& code = selection.codeRegistration;
    checkTables(errors, "CodeRegistration", code.size, {
        {"methodPointers", &code.methodPointers},
        {"reversePInvokeWrappers", &code.reversePInvokeWrappers},
        {"genericMethodPointers", &code.genericMethodPointers},
        {"invokerPointers", &code.invokerPointers},
        {"customAttributeGenerators", &code.customAttributeGenerators},
        {"unresolvedVirtualCallPointers", &code.unresolvedVirtualCallPointers},
        {"interopData", &code.interopData},
        {"windowsRuntimeFactoryTable", &code.windowsRuntimeFactoryTable},
        {"codeGenModules", &code.codeGenModules}
    });
    checkField(errors, "CodeRegistration", "genericAdjustorThunks", code.genericAdjustorThunks, code.size);

    const auto& metadata = selection.metadataRegistration;
    checkTables(errors, "MetadataRegistration", metadata.size, {
        {"genericClasses", &metadata.genericClasses}, {"genericInsts", &metadata.genericInsts},
        {"genericMethodTable", &metadata.genericMethodTable}, {"types", &metadata.types},
        {"methodSpecs", &metadata.methodSpecs}, {"fieldOffsets", &metadata.fieldOffsets},
        {"typeDefinitionsSizes", &metadata.typeDefinitionsSizes}, {"metadataUsages", &metadata.metadataUsages}
    });
    if (!metadata.types.count.present || !metadata.fieldOffsets.count.present) {
        errors.push_back("MetadataRegistration requires types and fieldOffsets tables");
    }
    if (metadata.types.count.offset != 6 * selection.pointerSize ||
        metadata.types.pointer.offset != 7 * selection.pointerSize) {
        errors.push_back("MetadataRegistration.types does not match registration pair index 3");
    }
    if (metadata.fieldOffsets.count.offset != 10 * selection.pointerSize ||
        metadata.fieldOffsets.pointer.offset != 11 * selection.pointerSize) {
        errors.push_back("MetadataRegistration.fieldOffsets does not match registration pair index 5");
    }

    if (selection.codeGenModules == CodeGenModulePresence::Present) {
        if (!code.codeGenModules.count.present) {
            errors.push_back("CodeGenModule presence is declared without CodeRegistration.codeGenModules");
        }
        const auto& module = selection.codeGenModule;
        checkFields(errors, "CodeGenModule", module.size, {
            {"moduleName", &module.moduleName}, {"methodPointerCount", &module.methodPointerCount},
            {"methodPointers", &module.methodPointers}, {"adjustorThunkCount", &module.adjustorThunkCount},
            {"adjustorThunks", &module.adjustorThunks}, {"invokerIndices", &module.invokerIndices},
            {"debuggerMetadata", &module.debuggerMetadata}
        });
        checkTables(errors, "CodeGenModule", module.size, {
            {"reversePInvokeWrapperIndices", &module.reversePInvokeWrapperIndices},
            {"rgctxRanges", &module.rgctxRanges}, {"rgctxs", &module.rgctxs}
        });
        if (selection.methodMapping != MethodMapping::PerImageTokenRowId) {
            errors.push_back("CodeGenModule profile does not select per-image token mapping");
        }
    } else if (selection.methodMapping == MethodMapping::PerImageTokenRowId) {
        errors.push_back("Per-image token mapping requires CodeGenModule tables");
    }

    checkFields(errors, "Il2CppObject", selection.object.size, {
        {"klass", &selection.object.klass}, {"monitor", &selection.object.monitor}
    });
    checkFields(errors, "Il2CppArray", selection.array.size, {
        {"klass", &selection.array.klass}, {"monitor", &selection.array.monitor},
        {"bounds", &selection.array.bounds}, {"length", &selection.array.length}, {"data", &selection.array.data}
    });
    checkFields(errors, "Il2CppString", selection.string.size, {
        {"klass", &selection.string.klass}, {"monitor", &selection.string.monitor},
        {"length", &selection.string.length}, {"chars", &selection.string.chars}
    });
    if (selection.object.klass.offset != 0 || selection.object.monitor.offset != selection.pointerSize ||
        selection.object.size != 2 * selection.pointerSize) {
        errors.push_back("Il2CppObject header does not match the two-pointer native layout");
    }
    if (selection.array.bounds.offset != 2 * selection.pointerSize ||
        selection.array.length.offset != 3 * selection.pointerSize ||
        selection.array.data.offset != 4 * selection.pointerSize || selection.array.dataAlignment != 8) {
        errors.push_back("Il2CppArray header does not match the aligned native vector layout");
    }
    if (selection.string.length.offset != 2 * selection.pointerSize ||
        selection.string.chars.offset != 2 * selection.pointerSize + sizeof(std::uint32_t)) {
        errors.push_back("Il2CppString header does not match the native length/chars layout");
    }
    return errors;
}

const SourceProfile& unity2017_4_11f1Profile() noexcept {
    static const SourceProfile profile{
        "unity-2017.4.11f1",
        "2017.4.11f1",
        "24.1",
        "libil2cpp/Unity_2017.4/2017.4.11f1",
        true
    };
    return profile;
}

const SourceProfile& metadata24BaseProfile() noexcept {
    static const SourceProfile profile{
        "il2cpp-24-base",
        "24.x",
        "24.0-24.5",
        "libil2cpp metadata 24 native layout family",
        false
    };
    return profile;
}

const SourceProfile* findSourceProfile(std::string_view unityVersion) noexcept {
    if (unityVersion == "2017.4.11f1" || unityVersion == "unity-2017.4.11f1") {
        return &unity2017_4_11f1Profile();
    }
    if (unityVersion == "24" || unityVersion == "24.x" || unityVersion == "il2cpp-24-base") {
        return &metadata24BaseProfile();
    }
    return nullptr;
}

} // namespace il2cpprec::ida
