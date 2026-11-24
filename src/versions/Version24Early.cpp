#include <il2cpprec/versions/Version24Early.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <limits>
#include <utility>

namespace il2cpprec::versions {
namespace {

using Field = Version24EarlyField;

constexpr Field type24_0Fields[] = {
    {"nameIndex", 0, 4}, {"namespaceIndex", 4, 4}, {"customAttributeIndex", 8, 4},
    {"byvalTypeIndex", 12, 4}, {"byrefTypeIndex", 16, 4}, {"declaringTypeIndex", 20, 4},
    {"parentIndex", 24, 4}, {"elementTypeIndex", 28, 4}, {"rgctxStartIndex", 32, 4},
    {"rgctxCount", 36, 4}, {"genericContainerIndex", 40, 4}, {"flags", 44, 4},
    {"fieldStart", 48, 4}, {"methodStart", 52, 4}, {"eventStart", 56, 4},
    {"propertyStart", 60, 4}, {"nestedTypesStart", 64, 4}, {"interfacesStart", 68, 4},
    {"vtableStart", 72, 4}, {"interfaceOffsetsStart", 76, 4}, {"methodCount", 80, 2},
    {"propertyCount", 82, 2}, {"fieldCount", 84, 2}, {"eventCount", 86, 2},
    {"nestedTypeCount", 88, 2}, {"vtableCount", 90, 2}, {"interfacesCount", 92, 2},
    {"interfaceOffsetsCount", 94, 2}, {"bitfield", 96, 4}, {"token", 100, 4}
};

constexpr Field type24_1Fields[] = {
    {"nameIndex", 0, 4}, {"namespaceIndex", 4, 4}, {"byvalTypeIndex", 8, 4},
    {"byrefTypeIndex", 12, 4}, {"declaringTypeIndex", 16, 4}, {"parentIndex", 20, 4},
    {"elementTypeIndex", 24, 4}, {"rgctxStartIndex", 28, 4}, {"rgctxCount", 32, 4},
    {"genericContainerIndex", 36, 4}, {"flags", 40, 4}, {"fieldStart", 44, 4},
    {"methodStart", 48, 4}, {"eventStart", 52, 4}, {"propertyStart", 56, 4},
    {"nestedTypesStart", 60, 4}, {"interfacesStart", 64, 4}, {"vtableStart", 68, 4},
    {"interfaceOffsetsStart", 72, 4}, {"methodCount", 76, 2}, {"propertyCount", 78, 2},
    {"fieldCount", 80, 2}, {"eventCount", 82, 2}, {"nestedTypeCount", 84, 2},
    {"vtableCount", 86, 2}, {"interfacesCount", 88, 2}, {"interfaceOffsetsCount", 90, 2},
    {"bitfield", 92, 4}, {"token", 96, 4}
};

constexpr Field method24_0Fields[] = {
    {"nameIndex", 0, 4}, {"declaringType", 4, 4}, {"returnType", 8, 4},
    {"parameterStart", 12, 4}, {"customAttributeIndex", 16, 4},
    {"genericContainerIndex", 20, 4}, {"methodIndex", 24, 4}, {"invokerIndex", 28, 4},
    {"delegateWrapperIndex", 32, 4}, {"rgctxStartIndex", 36, 4}, {"rgctxCount", 40, 4},
    {"token", 44, 4}, {"flags", 48, 2}, {"iflags", 50, 2}, {"slot", 52, 2},
    {"parameterCount", 54, 2}
};

constexpr Field method24_1Fields[] = {
    {"nameIndex", 0, 4}, {"declaringType", 4, 4}, {"returnType", 8, 4},
    {"parameterStart", 12, 4}, {"genericContainerIndex", 16, 4}, {"methodIndex", 20, 4},
    {"invokerIndex", 24, 4}, {"delegateWrapperIndex", 28, 4}, {"rgctxStartIndex", 32, 4},
    {"rgctxCount", 36, 4}, {"token", 40, 4}, {"flags", 44, 2}, {"iflags", 46, 2},
    {"slot", 48, 2}, {"parameterCount", 50, 2}
};

constexpr Field parameter24_0Fields[] = {
    {"nameIndex", 0, 4}, {"token", 4, 4}, {"customAttributeIndex", 8, 4}, {"typeIndex", 12, 4}
};

constexpr Field parameter24_1Fields[] = {
    {"nameIndex", 0, 4}, {"token", 4, 4}, {"typeIndex", 8, 4}
};

constexpr Field field24_0Fields[] = {
    {"nameIndex", 0, 4}, {"typeIndex", 4, 4}, {"customAttributeIndex", 8, 4}, {"token", 12, 4}
};

constexpr Field field24_1Fields[] = {
    {"nameIndex", 0, 4}, {"typeIndex", 4, 4}, {"token", 8, 4}
};

constexpr Field image24_0Fields[] = {
    {"nameIndex", 0, 4}, {"assemblyIndex", 4, 4}, {"typeStart", 8, 4},
    {"typeCount", 12, 4}, {"exportedTypeStart", 16, 4}, {"exportedTypeCount", 20, 4},
    {"entryPointIndex", 24, 4}, {"token", 28, 4}
};

constexpr Field image24_1Fields[] = {
    {"nameIndex", 0, 4}, {"assemblyIndex", 4, 4}, {"typeStart", 8, 4},
    {"typeCount", 12, 4}, {"exportedTypeStart", 16, 4}, {"exportedTypeCount", 20, 4},
    {"entryPointIndex", 24, 4}, {"token", 28, 4}, {"customAttributeStart", 32, 4},
    {"customAttributeCount", 36, 4}
};

constexpr Field assembly24_0Fields[] = {
    {"imageIndex", 0, 4}, {"customAttributeIndex", 4, 4}, {"referencedAssemblyStart", 8, 4},
    {"referencedAssemblyCount", 12, 4}, {"nameIndex", 16, 4}, {"cultureIndex", 20, 4},
    {"hashValueIndex", 24, 4}, {"publicKeyIndex", 28, 4}, {"hashAlgorithm", 32, 4},
    {"hashLength", 36, 4}, {"flags", 40, 4}, {"major", 44, 4}, {"minor", 48, 4},
    {"build", 52, 4}, {"revision", 56, 4}, {"publicKeyToken", 60, 8}
};

constexpr Field assembly24_1Fields[] = {
    {"imageIndex", 0, 4}, {"token", 4, 4}, {"referencedAssemblyStart", 8, 4},
    {"referencedAssemblyCount", 12, 4}, {"nameIndex", 16, 4}, {"cultureIndex", 20, 4},
    {"hashValueIndex", 24, 4}, {"publicKeyIndex", 28, 4}, {"hashAlgorithm", 32, 4},
    {"hashLength", 36, 4}, {"flags", 40, 4}, {"major", 44, 4}, {"minor", 48, 4},
    {"build", 52, 4}, {"revision", 56, 4}, {"publicKeyToken", 60, 8}
};

constexpr Field rgctxFields[] = {
    {"type", 0, 4}, {"data", 4, 4}
};

constexpr std::uint32_t header24_0Sizes[] = {240, 272};
constexpr std::uint32_t header24_1Sizes[] = {272};

const Field* findField(const Version24EarlyTable& table, std::string_view name) {
    const auto it = std::find_if(table.fields.begin(), table.fields.end(), [name](const Field& field) {
        return field.name == name;
    });
    return it == table.fields.end() ? nullptr : &*it;
}

std::uint32_t load32(const std::uint8_t* data) {
    return static_cast<std::uint32_t>(data[0]) |
        (static_cast<std::uint32_t>(data[1]) << 8) |
        (static_cast<std::uint32_t>(data[2]) << 16) |
        (static_cast<std::uint32_t>(data[3]) << 24);
}

bool read32(std::span<const std::uint8_t> data, std::size_t offset, std::uint32_t& value) {
    if (offset > data.size() || data.size() - offset < 4) return false;
    value = load32(data.data() + offset);
    return true;
}

bool readSigned32(std::span<const std::uint8_t> data, std::size_t offset, std::int32_t& value) {
    std::uint32_t bits = 0;
    if (!read32(data, offset, bits)) return false;
    value = std::bit_cast<std::int32_t>(bits);
    return true;
}

struct TableView {
    std::uint32_t offset = 0;
    std::int32_t byteSize = 0;
    bool valid = false;

    std::size_t count(std::uint32_t stride) const {
        return valid ? static_cast<std::size_t>(byteSize) / stride : 0;
    }
};

TableView tableView(std::span<const std::uint8_t> data, const Version24EarlyTable& table) {
    TableView view;
    if (!read32(data, table.headerOffset, view.offset) ||
        !readSigned32(data, table.headerOffset + 4, view.byteSize)) {
        return view;
    }
    if (view.byteSize < 0) return view;
    const auto size = static_cast<std::size_t>(view.byteSize);
    view.valid = size % table.stride == 0 && view.offset <= data.size() && size <= data.size() - view.offset;
    return view;
}

void validateTable(
    std::span<const std::uint8_t> data,
    const Version24EarlyTable& table,
    TableView& view,
    std::vector<std::string>& errors) {
    const std::string owner = std::string(1, table.code) + " (" + std::string(table.name) + ")";
    if (view.byteSize < 0) {
        errors.push_back(owner + " has a negative byte size");
        return;
    }
    const auto size = static_cast<std::size_t>(view.byteSize);
    if (size % table.stride != 0) {
        errors.push_back(owner + " byte size is not divisible by official stride " + std::to_string(table.stride));
    }
    if (view.offset > data.size() || size > data.size() - view.offset) {
        errors.push_back(owner + " is outside the metadata file");
    }
}

void validateFields(
    const Version24EarlyTable& table,
    std::vector<std::string>& errors) {
    if (table.fields.empty()) {
        errors.push_back(std::string(table.name) + " has no field descriptors");
        return;
    }
    std::uint32_t cursor = 0;
    for (const auto& field : table.fields) {
        if (field.size == 0 || field.offset != cursor) {
            errors.push_back(
                std::string(table.name) + "." + std::string(field.name) +
                " is not contiguous in the official packed layout");
        }
        if (field.offset > std::numeric_limits<std::uint32_t>::max() - field.size) {
            errors.push_back(std::string(table.name) + "." + std::string(field.name) + " overflows");
        } else {
            cursor = field.offset + field.size;
        }
    }
    if (cursor != table.stride) {
        errors.push_back(
            std::string(table.name) + " fields end at " + std::to_string(cursor) +
            " instead of official stride " + std::to_string(table.stride));
    }
}

bool samePair(
    const Version24EarlyCodeRegistrationPair& actual,
    const Version24EarlyCodeRegistrationPair& expected) {
    return actual.countOffset == expected.countOffset && actual.pointerOffset == expected.pointerOffset;
}

bool plausible(std::span<const std::uint8_t> data, const Version24EarlyProfile& profile) {
    const std::array<const Version24EarlyTable*, 7> tables = {
        &profile.typeDefinitions, &profile.methods, &profile.parameters, &profile.fields,
        &profile.images, &profile.assemblies, &profile.rgctxEntries
    };
    for (const auto* table : tables) {
        if (!tableView(data, *table).valid) return false;
    }
    Version24EarlyTable attributes{'C', "custom attribute ranges",
        profile.header.customAttributeRangesOffset, profile.customAttributeRangeStride, {}};
    if (!tableView(data, attributes).valid) return false;
    if (profile.imageTokenMustBeOne) {
        const auto images = tableView(data, profile.images);
        for (std::size_t index = 0; index < images.count(profile.images.stride); ++index) {
            std::uint32_t token = 0;
            if (!read32(data, images.offset + index * profile.images.stride + profile.imageTokenOffset, token) ||
                token != 1) {
                return false;
            }
        }
    }
    return true;
}

void validateRgctxOwner(
    std::span<const std::uint8_t> data,
    const Version24EarlyTable& table,
    const TableView& view,
    std::size_t rgctxCount,
    std::vector<std::string>& errors) {
    const auto* startField = findField(table, "rgctxStartIndex");
    const auto* countField = findField(table, "rgctxCount");
    if (!startField || !countField || !view.valid) return;
    for (std::size_t index = 0; index < view.count(table.stride); ++index) {
        const std::size_t base = view.offset + index * table.stride;
        std::int32_t start = 0;
        std::int32_t count = 0;
        if (!readSigned32(data, base + startField->offset, start) ||
            !readSigned32(data, base + countField->offset, count)) {
            continue;
        }
        const auto row = std::to_string(index);
        if (start < -1) errors.push_back(std::string(table.name) + "[" + row + "] has invalid RGCTX start");
        if (count < 0) errors.push_back(std::string(table.name) + "[" + row + "] has negative RGCTX count");
        if (start == -1 && count != 0) {
            errors.push_back(std::string(table.name) + "[" + row + "] has RGCTX entries without a start");
        }
        if (start >= 0 && count >= 0 &&
            static_cast<std::uint64_t>(static_cast<std::uint32_t>(start)) +
                static_cast<std::uint32_t>(count) > rgctxCount) {
            errors.push_back(std::string(table.name) + "[" + row + "] RGCTX range is outside the entry table");
        }
    }
}

} // namespace

const Version24EarlyProfile& version24_0Profile() noexcept {
    static const Version24EarlyProfile profile{
        Version24EarlyKind::V24_0, 24.0, "IL2CPP 24.0", {272, 224}, header24_0Sizes,
        {'T', "type definitions", 160, 104, type24_0Fields},
        {'M', "methods", 48, 56, method24_0Fields},
        {'P', "parameters", 88, 16, parameter24_0Fields},
        {'F', "fields", 96, 16, field24_0Fields},
        {'I', "images", 176, 32, image24_0Fields},
        {'A', "assemblies", 184, 68, assembly24_0Fields},
        {'R', "RGCTX entries", 168, 8, rgctxFields},
        8, true, 24, 28, true, false, 0, 0
    };
    return profile;
}

const Version24EarlyProfile& version24_1Profile() noexcept {
    static const Version24EarlyProfile profile{
        Version24EarlyKind::V24_1, 24.1, "IL2CPP 24.1", {272, 224}, header24_1Sizes,
        {'T', "type definitions", 160, 100, type24_1Fields},
        {'M', "methods", 48, 52, method24_1Fields},
        {'P', "parameters", 88, 12, parameter24_1Fields},
        {'F', "fields", 96, 12, field24_1Fields},
        {'I', "images", 176, 40, image24_1Fields},
        {'A', "assemblies", 184, 68, assembly24_1Fields},
        {'R', "RGCTX entries", 168, 8, rgctxFields},
        12, true, 20, 28, false, true, 32, 36
    };
    return profile;
}

const Version24EarlyProfile& unity2017Profile() noexcept {
    return version24_0Profile();
}

std::span<const Version24EarlyProfile* const> version24EarlyProfiles() noexcept {
    static const std::array<const Version24EarlyProfile*, 2> profiles = {
        &version24_0Profile(), &version24_1Profile()
    };
    return profiles;
}

const Version24EarlyProfile* findVersion24EarlyProfile(double version) noexcept {
    if (std::abs(version - 24.0) < 0.001) return &version24_0Profile();
    if (std::abs(version - 24.1) < 0.001) return &version24_1Profile();
    return nullptr;
}

const Version24EarlyProfile* detectVersion24EarlyProfile(std::span<const std::uint8_t> metadata) noexcept {
    std::uint32_t sanity = 0;
    std::uint32_t rawVersion = 0;
    std::uint32_t declaredHeaderSize = 0;
    if (!read32(metadata, 0, sanity) || !read32(metadata, 4, rawVersion) ||
        !read32(metadata, 8, declaredHeaderSize) || sanity != metadata24Sanity || rawVersion != 24 ||
        (declaredHeaderSize != 240 && declaredHeaderSize != 272) || metadata.size() < declaredHeaderSize) {
        return nullptr;
    }

    const bool matches24_0 = plausible(metadata, version24_0Profile());
    const bool matches24_1 = declaredHeaderSize == 272 && plausible(metadata, version24_1Profile());
    if (matches24_0 == matches24_1) return nullptr;
    if (matches24_0) return &version24_0Profile();
    if (matches24_1) return &version24_1Profile();
    return nullptr;
}

Version24EarlyCodeRegistration makeVersion24EarlyCodeRegistration(std::size_t pointerSize) noexcept {
    Version24EarlyCodeRegistration layout;
    layout.pointerSize = pointerSize;
    if (pointerSize != 4 && pointerSize != 8) return layout;
    const auto pair = [pointerSize](std::size_t index) {
        const auto offset = static_cast<std::uint32_t>(index * 2 * pointerSize);
        return Version24EarlyCodeRegistrationPair{
            offset, offset + static_cast<std::uint32_t>(pointerSize)
        };
    };
    layout.size = 14 * pointerSize;
    layout.methodPointers = pair(0);
    layout.reversePInvokeWrappers = pair(1);
    layout.genericMethodPointers = pair(2);
    layout.invokerPointers = pair(3);
    layout.customAttributeGenerators = pair(4);
    layout.unresolvedVirtualCallPointers = pair(5);
    layout.interopData = pair(6);
    return layout;
}

std::vector<std::string> validateVersion24EarlyCodeRegistration(
    const Version24EarlyCodeRegistration& layout) {
    std::vector<std::string> errors;
    if (layout.pointerSize != 4 && layout.pointerSize != 8) {
        errors.push_back("CodeRegistration pointer size must be 4 or 8");
        return errors;
    }
    const auto expected = makeVersion24EarlyCodeRegistration(layout.pointerSize);
    if (layout.size != expected.size) errors.push_back("CodeRegistration must contain exactly 14 pointer-sized slots");
    if (!samePair(layout.methodPointers, expected.methodPointers) ||
        !samePair(layout.reversePInvokeWrappers, expected.reversePInvokeWrappers) ||
        !samePair(layout.genericMethodPointers, expected.genericMethodPointers) ||
        !samePair(layout.invokerPointers, expected.invokerPointers) ||
        !samePair(layout.customAttributeGenerators, expected.customAttributeGenerators) ||
        !samePair(layout.unresolvedVirtualCallPointers, expected.unresolvedVirtualCallPointers) ||
        !samePair(layout.interopData, expected.interopData)) {
        errors.push_back("CodeRegistration count/pointer pairs do not match the official seven-pair layout");
    }
    if (layout.genericAdjustorThunks) errors.push_back("CodeRegistration 24.0/24.1 has no genericAdjustorThunks");
    if (layout.windowsRuntimeFactoryTable) errors.push_back("CodeRegistration 24.0/24.1 has no Windows Runtime factory table");
    if (layout.codeGenModules) errors.push_back("CodeRegistration 24.0/24.1 has no codeGenModules table");
    return errors;
}

Version24EarlyMethodInfo makeVersion24EarlyMethodInfo(
    Version24EarlyKind kind, std::size_t pointerSize) noexcept {
    Version24EarlyMethodInfo layout;
    layout.pointerSize = pointerSize;
    if ((kind != Version24EarlyKind::V24_0 && kind != Version24EarlyKind::V24_1) ||
        (pointerSize != 4 && pointerSize != 8)) return layout;
    // Eight pointer fields precede the version-dependent metadata fields.
    layout.methodPointerOffset = 0;
    layout.invokerOffset = static_cast<std::uint32_t>(pointerSize);
    layout.declaringTypeOffset = static_cast<std::uint32_t>(3 * pointerSize);
    layout.rgctxOrDefinitionOffset = static_cast<std::uint32_t>(6 * pointerSize);
    layout.genericMethodOrContainerOffset = static_cast<std::uint32_t>(7 * pointerSize);
    layout.hasCustomAttributeIndex = kind == Version24EarlyKind::V24_0;
    layout.customAttributeIndexOffset = static_cast<std::uint32_t>(8 * pointerSize);
    layout.tokenOffset = layout.customAttributeIndexOffset + (layout.hasCustomAttributeIndex ? 4 : 0);
    layout.flagsOffset = layout.tokenOffset + 4;
    layout.parameterCountOffset = layout.flagsOffset + 6;
    layout.bitfieldOffset = layout.parameterCountOffset + 1;
    layout.size = (static_cast<std::size_t>(layout.bitfieldOffset) + 1 + pointerSize - 1) & ~(pointerSize - 1);
    return layout;
}

std::vector<std::string> validateVersion24EarlyMethodInfo(
    Version24EarlyKind kind, const Version24EarlyMethodInfo& layout) {
    if ((kind != Version24EarlyKind::V24_0 && kind != Version24EarlyKind::V24_1) ||
        (layout.pointerSize != 4 && layout.pointerSize != 8)) {
        return {"MethodInfo requires a known early-24 version and 4- or 8-byte pointers"};
    }
    const auto expected = makeVersion24EarlyMethodInfo(kind, layout.pointerSize);
    if (layout.size != expected.size || layout.methodPointerOffset != expected.methodPointerOffset ||
        layout.invokerOffset != expected.invokerOffset ||
        layout.declaringTypeOffset != expected.declaringTypeOffset ||
        layout.rgctxOrDefinitionOffset != expected.rgctxOrDefinitionOffset ||
        layout.genericMethodOrContainerOffset != expected.genericMethodOrContainerOffset ||
        layout.hasCustomAttributeIndex != expected.hasCustomAttributeIndex ||
        layout.customAttributeIndexOffset != expected.customAttributeIndexOffset ||
        layout.tokenOffset != expected.tokenOffset || layout.flagsOffset != expected.flagsOffset ||
        layout.parameterCountOffset != expected.parameterCountOffset ||
        layout.bitfieldOffset != expected.bitfieldOffset) {
        return {"MethodInfo does not match the official early-24 runtime layout"};
    }
    return {};
}

std::vector<std::string> validateVersion24EarlyProfile(const Version24EarlyProfile& profile) {
    std::vector<std::string> errors;
    const bool is24_0 = profile.kind == Version24EarlyKind::V24_0;
    const bool is24_1 = profile.kind == Version24EarlyKind::V24_1;
    if (!is24_0 && !is24_1) {
        errors.push_back("unknown early metadata 24 profile");
        return errors;
    }
    const auto& expected = is24_0 ? version24_0Profile() : version24_1Profile();
    const std::array<std::pair<const Version24EarlyTable*, const Version24EarlyTable*>, 7> tables = {{
        {&profile.typeDefinitions, &expected.typeDefinitions}, {&profile.methods, &expected.methods},
        {&profile.parameters, &expected.parameters}, {&profile.fields, &expected.fields},
        {&profile.images, &expected.images}, {&profile.assemblies, &expected.assemblies},
        {&profile.rgctxEntries, &expected.rgctxEntries}
    }};
    for (const auto& [actual, official] : tables) {
        if (actual->code != official->code || actual->name != official->name ||
            actual->headerOffset != official->headerOffset || actual->stride != official->stride) {
            errors.push_back(std::string(official->name) + " does not match the official " + std::string(expected.name) + " descriptor");
        }
        if (actual->fields.size() != official->fields.size()) {
            errors.push_back(std::string(official->name) + " has a different field count from the official descriptor");
        } else {
            for (std::size_t index = 0; index < official->fields.size(); ++index) {
                const auto& field = actual->fields[index];
                const auto& canonical = official->fields[index];
                if (field.name != canonical.name || field.offset != canonical.offset ||
                    field.size != canonical.size) {
                    errors.push_back(std::string(official->name) + " has a noncanonical field descriptor");
                    break;
                }
            }
        }
        validateFields(*actual, errors);
    }
    if (profile.header.size != 272 || profile.header.customAttributeRangesOffset != 224) {
        errors.push_back("metadata 24.0/24.1 canonical header must be 272 bytes with custom attributes at 224");
    }
    if (profile.customAttributeRangeStride != expected.customAttributeRangeStride) {
        errors.push_back("custom attribute range stride does not match the official profile");
    }
    const auto hasHeaderSize = [&profile](std::uint32_t size) {
        return std::find(profile.acceptedHeaderSizes.begin(), profile.acceptedHeaderSizes.end(), size) !=
            profile.acceptedHeaderSizes.end();
    };
    if (profile.acceptedHeaderSizes.size() != (is24_0 ? 2U : 1U) || !hasHeaderSize(272) ||
        (is24_0 && !hasHeaderSize(240)) || (is24_1 && hasHeaderSize(240))) {
        errors.push_back("accepted metadata headers must be 240/272 for 24.0 and 272 for 24.1");
    }
    if (std::abs(profile.version - expected.version) >= 0.001) errors.push_back("profile numeric version is inconsistent");
    if (!profile.globalMethodIndex) errors.push_back("metadata 24.0/24.1 methods require global methodIndex mapping");
    if (profile.methodIndexOffset != expected.methodIndexOffset ||
        !findField(profile.methods, "methodIndex") ||
        findField(profile.methods, "methodIndex")->offset != profile.methodIndexOffset) {
        errors.push_back("global methodIndex offset does not match the official method descriptor");
    }
    if (profile.imageTokenOffset != 28 || !findField(profile.images, "token") ||
        findField(profile.images, "token")->offset != 28) {
        errors.push_back("image token must be at offset 28");
    }
    if (profile.imageTokenMustBeOne != is24_0) errors.push_back("only metadata 24.0 requires image token 1");
    if (profile.imageCustomAttributes != is24_1 ||
        profile.imageCustomAttributeStartOffset != expected.imageCustomAttributeStartOffset ||
        profile.imageCustomAttributeCountOffset != expected.imageCustomAttributeCountOffset) {
        errors.push_back("image custom-attribute fields do not match the official profile");
    }
    if (is24_1 && (!findField(profile.images, "customAttributeStart") ||
                   !findField(profile.images, "customAttributeCount"))) {
        errors.push_back("metadata 24.1 image custom-attribute fields are missing");
    }
    for (const auto pointerSize : {4U, 8U}) {
        auto codeErrors = validateVersion24EarlyCodeRegistration(makeVersion24EarlyCodeRegistration(pointerSize));
        auto methodErrors = validateVersion24EarlyMethodInfo(
            profile.kind, makeVersion24EarlyMethodInfo(profile.kind, pointerSize));
        errors.insert(errors.end(), codeErrors.begin(), codeErrors.end());
        errors.insert(errors.end(), methodErrors.begin(), methodErrors.end());
    }
    return errors;
}

Version24EarlyValidation validateVersion24EarlyMetadata(
    const Version24EarlyProfile& profile,
    std::span<const std::uint8_t> metadata) {
    Version24EarlyValidation result{&profile, validateVersion24EarlyProfile(profile)};
    if (!result.errors.empty()) return result;

    std::uint32_t sanity = 0;
    std::uint32_t rawVersion = 0;
    std::uint32_t declaredHeaderSize = 0;
    if (!read32(metadata, 0, sanity) || !read32(metadata, 4, rawVersion) ||
        !read32(metadata, 8, declaredHeaderSize)) {
        result.errors.push_back("metadata is smaller than the mandatory header prefix");
        return result;
    }
    if (sanity != metadata24Sanity) result.errors.push_back("incorrect metadata sanity value");
    if (rawVersion != 24) result.errors.push_back("metadata raw version must be 24");
    if (std::find(profile.acceptedHeaderSizes.begin(), profile.acceptedHeaderSizes.end(), declaredHeaderSize) ==
        profile.acceptedHeaderSizes.end()) {
        result.errors.push_back(std::string(profile.name) + " does not accept declared header size " +
            std::to_string(declaredHeaderSize));
    }
    if (metadata.size() < declaredHeaderSize) {
        result.errors.push_back("metadata is smaller than its declared header");
        return result;
    }

    const std::array<const Version24EarlyTable*, 7> tables = {
        &profile.typeDefinitions, &profile.methods, &profile.parameters, &profile.fields,
        &profile.images, &profile.assemblies, &profile.rgctxEntries
    };
    std::array<TableView, 7> views;
    for (std::size_t index = 0; index < tables.size(); ++index) {
        views[index] = tableView(metadata, *tables[index]);
        validateTable(metadata, *tables[index], views[index], result.errors);
    }
    auto& types = views[0];
    auto& methods = views[1];
    auto& images = views[4];
    auto& rgctx = views[6];

    Version24EarlyTable attributeRanges{
        'C', "custom attribute ranges", profile.header.customAttributeRangesOffset,
        profile.customAttributeRangeStride, {}
    };
    TableView attributes = tableView(metadata, attributeRanges);
    validateTable(metadata, attributeRanges, attributes, result.errors);
    const std::size_t attributeCount = attributes.count(attributeRanges.stride);

    if (images.valid) {
        for (std::size_t index = 0; index < images.count(profile.images.stride); ++index) {
            const std::size_t base = images.offset + index * profile.images.stride;
            std::uint32_t token = 0;
            if (read32(metadata, base + profile.imageTokenOffset, token) && profile.imageTokenMustBeOne && token != 1) {
                result.errors.push_back("images[" + std::to_string(index) + "] token must be 1 in metadata 24.0");
            }
            if (!profile.imageCustomAttributes) continue;

            std::int32_t start = 0;
            std::uint32_t count = 0;
            if (!readSigned32(metadata, base + profile.imageCustomAttributeStartOffset, start) ||
                !read32(metadata, base + profile.imageCustomAttributeCountOffset, count)) {
                continue;
            }
            if (start < -1) {
                result.errors.push_back("images[" + std::to_string(index) + "] has invalid custom-attribute start");
            }
            if (start == -1 && count != 0) {
                result.errors.push_back("images[" + std::to_string(index) + "] has custom attributes without a start");
            }
            if (start >= 0 && static_cast<std::uint64_t>(static_cast<std::uint32_t>(start)) + count > attributeCount) {
                result.errors.push_back("images[" + std::to_string(index) + "] custom-attribute range is outside the table");
            }
        }
    }

    if (rgctx.valid) {
        for (std::size_t index = 0; index < rgctx.count(profile.rgctxEntries.stride); ++index) {
            std::uint32_t kind = 0;
            if (read32(metadata, rgctx.offset + index * profile.rgctxEntries.stride, kind) && kind > 4) {
                result.errors.push_back("RGCTX entries[" + std::to_string(index) + "] has invalid data kind");
            }
        }
    }
    const std::size_t rgctxCount = rgctx.count(profile.rgctxEntries.stride);
    validateRgctxOwner(metadata, profile.typeDefinitions, types, rgctxCount, result.errors);
    validateRgctxOwner(metadata, profile.methods, methods, rgctxCount, result.errors);

    if (methods.valid) {
        for (std::size_t index = 0; index < methods.count(profile.methods.stride); ++index) {
            std::int32_t methodIndex = 0;
            if (readSigned32(
                    metadata,
                    methods.offset + index * profile.methods.stride + profile.methodIndexOffset,
                    methodIndex) && methodIndex < -1) {
                result.errors.push_back("methods[" + std::to_string(index) + "] has invalid global methodIndex");
            }
        }
    }
    return result;
}

Version24EarlyValidation validateVersion24EarlyMetadata(std::span<const std::uint8_t> metadata) {
    const auto* profile = detectVersion24EarlyProfile(metadata);
    if (!profile) {
        return {nullptr, {"metadata does not match an official IL2CPP 24.0/24.1 layout"}};
    }
    return validateVersion24EarlyMetadata(*profile, metadata);
}

} // namespace il2cpprec::versions
