#include <il2cpprec/versions/Version104.hpp>

#include <il2cpprec/metadata/MetadataRegistration.hpp>

#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace il2cpprec::versions {
namespace {

constexpr uint32_t metadataMagic = 0xFAB11BAF;
constexpr std::size_t sectionHeaderSize = 12;
constexpr std::size_t sectionCount = 32;
constexpr std::size_t metadataHeaderSize = 8 + sectionCount * sectionHeaderSize;

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 104-107 metadata: " + message);
}

[[noreturn]] void invalidNative(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 104-107 native registration: " + message);
}

bool versionIs(double value, double expected) {
    return std::abs(value - expected) < 0.0001;
}

class Reader {
public:
    Reader(const uint8_t* data, std::size_t size) : data_(data), size_(size) {
        if (data == nullptr && size != 0) invalid("null data with nonzero size");
    }

    std::size_t size() const { return size_; }

    void require(std::size_t offset, std::size_t amount) const {
        if (offset > size_ || amount > size_ - offset) invalid("read past end of file");
    }

    uint8_t u8(std::size_t offset) const {
        require(offset, 1);
        return data_[offset];
    }

    uint16_t u16(std::size_t offset) const {
        require(offset, 2);
        return static_cast<uint16_t>(data_[offset]) |
            static_cast<uint16_t>(static_cast<uint16_t>(data_[offset + 1]) << 8);
    }

    uint32_t u32(std::size_t offset) const {
        require(offset, 4);
        return static_cast<uint32_t>(data_[offset]) |
            (static_cast<uint32_t>(data_[offset + 1]) << 8) |
            (static_cast<uint32_t>(data_[offset + 2]) << 16) |
            (static_cast<uint32_t>(data_[offset + 3]) << 24);
    }

    int32_t i32(std::size_t offset) const {
        return std::bit_cast<int32_t>(u32(offset));
    }

    int16_t i16(std::size_t offset) const {
        return std::bit_cast<int16_t>(u16(offset));
    }

    int32_t index(std::size_t offset, std::size_t width) const {
        switch (width) {
        case 1: {
            const uint8_t value = u8(offset);
            return value == std::numeric_limits<uint8_t>::max() ? -1 : value;
        }
        case 2: {
            const uint16_t value = u16(offset);
            return value == std::numeric_limits<uint16_t>::max() ? -1 : value;
        }
        case 4:
            return i32(offset);
        default:
            invalid("index width is not 1, 2, or 4 bytes");
        }
    }

    const uint8_t* bytes(std::size_t offset, std::size_t amount) const {
        require(offset, amount);
        return data_ + offset;
    }

private:
    const uint8_t* data_;
    std::size_t size_;
};

MetadataSectionModel readSection(const Reader& reader, std::size_t offset) {
    MetadataSectionModel section;
    section.offset = reader.i32(offset);
    section.sectionSize = reader.i32(offset + 4);
    section.count = reader.i32(offset + 8);
    if (section.offset < 0 || section.sectionSize < 0 || section.count < 0) {
        invalid("section has a negative offset, size, or count");
    }
    const auto start = static_cast<std::size_t>(section.offset);
    const auto size = static_cast<std::size_t>(section.sectionSize);
    if (start > reader.size() || size > reader.size() - start) invalid("section is outside the file");
    return section;
}

void validateBlob(const Reader& reader, const MetadataSectionModel& section, const char* name) {
    if (section.sectionSize != section.count) {
        invalid(std::string(name) + " byte count does not match its section size");
    }
    reader.require(static_cast<std::size_t>(section.offset), static_cast<std::size_t>(section.sectionSize));
}

std::size_t validateTable(
    const Reader& reader,
    const MetadataSectionModel& section,
    std::size_t stride,
    const char* name) {
    const auto count = static_cast<std::size_t>(section.count);
    if (count > std::numeric_limits<std::size_t>::max() / stride ||
        count * stride != static_cast<std::size_t>(section.sectionSize)) {
        invalid(std::string(name) + " size does not match count and element width");
    }
    reader.require(static_cast<std::size_t>(section.offset), static_cast<std::size_t>(section.sectionSize));
    return count;
}

std::size_t indexWidth(int32_t count) {
    if (count < 0) invalid("negative element count used for index width");
    // The all-ones value is reserved for -1, so it cannot name an element.
    if (count < std::numeric_limits<uint8_t>::max()) return 1;
    if (count < std::numeric_limits<uint16_t>::max()) return 2;
    return 4;
}

std::optional<std::string> readString(
    const Reader& reader,
    const MetadataSectionModel& strings,
    uint32_t index) {
    if (index == std::numeric_limits<uint32_t>::max()) return std::nullopt;
    const auto stringSize = static_cast<size_t>(strings.sectionSize);
    if (index >= stringSize) return std::nullopt;
    const std::size_t start = static_cast<std::size_t>(strings.offset) + index;
    const std::size_t remaining = stringSize - index;
    const auto* bytes = reinterpret_cast<const char*>(reader.bytes(start, remaining));
    const void* terminator = std::memchr(bytes, 0, remaining);
    if (terminator == nullptr) return std::nullopt;
    return std::string(bytes, static_cast<std::size_t>(static_cast<const char*>(terminator) - bytes));
}

std::string typeReference(int32_t index) {
    return index < 0 ? std::string{} : "type[" + std::to_string(index) + "]";
}

std::string qualifiedName(const TypeModel& type) {
    if (type.nameSpace.empty()) return type.name;
    if (type.name.empty()) return type.nameSpace;
    return type.nameSpace + "." + type.name;
}

struct TypeDefinition {
    uint32_t nameIndex = 0;
    uint32_t namespaceIndex = 0;
    int32_t declaringTypeIndex = -1;
    int32_t parentIndex = -1;
    int32_t genericContainerIndex = -1;
    uint32_t flags = 0;
    int32_t fieldStart = -1;
    int32_t methodStart = -1;
    int32_t eventStart = -1;
    int32_t propertyStart = -1;
    int32_t nestedTypeStart = -1;
    int32_t interfacesStart = -1;
    int32_t interfaceOffsetsStart = -1;
    uint16_t methodCount = 0;
    uint16_t propertyCount = 0;
    uint16_t fieldCount = 0;
    uint16_t eventCount = 0;
    uint16_t nestedTypeCount = 0;
    uint16_t interfacesCount = 0;
    uint16_t interfaceOffsetsCount = 0;
    uint32_t bitfield = 0;
    uint32_t token = 0;
};

struct MethodDefinition {
    uint32_t nameIndex = 0;
    int32_t declaringType = -1;
    int32_t returnType = -1;
    uint32_t returnParameterToken = 0;
    int32_t parameterStart = -1;
    int32_t genericContainerIndex = -1;
    uint32_t token = 0;
    uint16_t flags = 0;
    uint16_t iflags = 0;
    uint16_t slot = 0;
    uint16_t parameterCount = 0;
};

struct ParameterDefinition {
    uint32_t nameIndex = 0;
    uint32_t token = 0;
    int32_t typeIndex = -1;
};

struct FieldDefinition {
    uint32_t nameIndex = 0;
    int32_t typeIndex = -1;
    uint32_t token = 0;
};

std::size_t inferredPointerSize(const BinaryImage& binary, std::size_t requested) {
    if (requested != 0) {
        if (requested != 4 && requested != 8) {
            throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
        }
        return requested;
    }
    switch (binary.architecture) {
    case Architecture::Arm32:
    case Architecture::X86:
        return 4;
    case Architecture::Arm64:
    case Architecture::X64:
        return 8;
    }
    throw std::invalid_argument("Unsupported IL2CPP binary architecture");
}

uint64_t checkedAdd(uint64_t value, uint64_t amount) {
    if (amount > std::numeric_limits<uint64_t>::max() - value) invalidNative("address overflow");
    return value + amount;
}

class NativeReader {
public:
    NativeReader(const BinaryImage& binary, std::size_t pointerSize)
        : binary_(binary), pointerSize_(pointerSize) {
        if (pointerSize != 4 && pointerSize != 8) {
            throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
        }
        if (!binary.bytes) invalidNative("binary image has no data");
    }

    uint32_t u32(uint64_t address) const {
        const auto* data = bytes(address, 4);
        return static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << 8) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 24);
    }

    uint64_t native(uint64_t address) const {
        if (pointerSize_ == 4) return u32(address);
        const auto* data = bytes(address, 8);
        uint64_t value = 0;
        for (std::size_t index = 0; index != 8; ++index) {
            value |= static_cast<uint64_t>(data[index]) << (index * 8);
        }
        return value;
    }

    Version104NativeTable table(uint64_t base, std::size_t slot, bool signedCount, const char* name) const {
        const uint64_t address = checkedAdd(base, slot * pointerSize_);
        Version104NativeTable result;
        result.count = native(address);
        result.address = native(checkedAdd(address, pointerSize_));
        if (signedCount && result.count > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
            invalidNative(std::string(name) + " count is negative or exceeds int32");
        }
        validateTable(result, pointerSize_, name);
        return result;
    }

    void validateTable(const Version104NativeTable& table, std::size_t stride, const char* name) const {
        if (!table.present) return;
        if (table.count != 0 && table.address == 0) {
            invalidNative(std::string(name) + " has a nonzero count and null address");
        }
        const std::size_t size = checkedNativeProduct(table.count, stride);
        if (size != 0) require(table.address, size);
    }

    std::vector<uint64_t> pointerTable(uint64_t address, uint64_t count) const {
        const std::size_t size = checkedNativeProduct(count, pointerSize_);
        if (size != 0) require(address, size);
        if (count > std::numeric_limits<std::size_t>::max()) invalidNative("pointer table is too large");
        std::vector<uint64_t> result;
        result.reserve(static_cast<std::size_t>(count));
        for (std::size_t index = 0; index < static_cast<std::size_t>(count); ++index) {
            result.push_back(native(checkedAdd(address, index * pointerSize_)));
        }
        return result;
    }

    void require(uint64_t address, std::size_t size) const {
        bytes(address, size);
    }

private:
    static std::size_t checkedNativeProduct(uint64_t count, std::size_t stride) {
        if (stride != 0 && count > std::numeric_limits<std::size_t>::max() / stride) {
            invalidNative("native table size overflow");
        }
        return static_cast<std::size_t>(count) * stride;
    }

    const uint8_t* bytes(uint64_t address, std::size_t size) const {
        uint64_t fileOffset = 0;
        try {
            fileOffset = binary_.mapVATR(address);
        } catch (const std::out_of_range&) {
            if (address >= binary_.imageBase) {
                try {
                    fileOffset = binary_.mapVATR(address - binary_.imageBase);
                } catch (const std::out_of_range&) {
                    invalidNative("read is outside the binary image");
                }
            } else {
                invalidNative("read is outside the binary image");
            }
        }
        if (fileOffset > binary_.bytes->size() || size > binary_.bytes->size() - static_cast<std::size_t>(fileOffset)) {
            invalidNative("read is outside the binary image");
        }
        return binary_.bytes->data() + static_cast<std::size_t>(fileOffset);
    }

    const BinaryImage& binary_;
    std::size_t pointerSize_;
};

} // namespace

Version104::Version104(Version104Options options) : options_(options) {
    if (!supports(options_.version)) {
        throw std::invalid_argument("Version104 supports metadata versions 104, 105, 106, 106.1, and 107");
    }
    if (options_.typeIndexWidth && options_.typeIndexWidth != 1 && options_.typeIndexWidth != 2 &&
        options_.typeIndexWidth != 4) {
        throw std::invalid_argument("IL2CPP type index width must be 1, 2, or 4 bytes");
    }
}

Version104::Version104(double version)
    : Version104(Version104Options{version, Version107Variant::Unity65, std::nullopt}) {}

bool Version104::supports(double version) noexcept {
    return versionIs(version, 104.0) || versionIs(version, 105.0) || versionIs(version, 106.0) ||
        versionIs(version, 106.1) || versionIs(version, 107.0);
}

double Version104::registrationVersion() const noexcept {
    if (versionIs(options_.version, 106.1)) return 106.1;
    if (versionIs(options_.version, 107.0) && options_.version107Variant == Version107Variant::Unity66) {
        return 106.1;
    }
    if (versionIs(options_.version, 107.0)) return 106.0;
    return options_.version;
}

std::size_t Version104::metadataRegistrationSize(std::size_t pointerSize) const {
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
    return (registrationVersion() >= 106.1 ? 18 : 16) * pointerSize;
}

std::size_t Version104::codeRegistrationSize(std::size_t pointerSize) const {
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
    return 17 * pointerSize;
}

Version104Layout Version104::layout(const MetadataSectionsModel& sections) const {
    Version104Layout result;
    result.version = options_.version;
    result.registrationVersion = registrationVersion();
    result.typeDefinitionIndex = indexWidth(sections.typeDefinitions.count);
    result.genericContainerIndex = indexWidth(sections.genericContainers.count);
    result.parameterIndex = indexWidth(sections.parameters.count);

    if (options_.typeIndexWidth) {
        result.typeIndex = *options_.typeIndexWidth;
        result.typeIndexWidthKnown = true;
    } else if (sections.interfaceOffsets.count != 0) {
        if (sections.interfaceOffsets.sectionSize < 0 ||
            sections.interfaceOffsets.sectionSize % sections.interfaceOffsets.count != 0) {
            invalid("interfaceOffsets table has an unaligned element width");
        }
        const int32_t stride = sections.interfaceOffsets.sectionSize / sections.interfaceOffsets.count;
        if (stride != 5 && stride != 6 && stride != 8) {
            invalid("interfaceOffsets element width does not contain a valid type index");
        }
        result.typeIndex = static_cast<std::size_t>(stride - 4);
        result.typeIndexWidthKnown = true;
    } else {
        const bool hasTypeIndices = sections.typeDefinitions.count != 0 || sections.methods.count != 0 ||
            sections.parameters.count != 0 || sections.fields.count != 0 || sections.events.count != 0 ||
            sections.fieldDefaultValues.count != 0 || sections.parameterDefaultValues.count != 0 ||
            sections.interfaces.count != 0 || sections.genericParameterConstraints.count != 0 ||
            sections.typeInlineArrays.count != 0 || sections.unresolvedIndirectCallParameterTypes.count != 0 ||
            sections.fieldRefs.count != 0;
        if (hasTypeIndices) {
            invalid("type index width requires a non-empty interfaceOffsets table or an explicit width");
        }
        // No record can consume a TypeIndex. Keep a nonzero internal stride for
        // empty-table validation while recording that the width was not inferred.
    }

    const bool v105 = versionIs(options_.version, 105.0);
    const bool v106 = versionIs(options_.version, 106.0) || versionIs(options_.version, 106.1);
    const bool v107 = versionIs(options_.version, 107.0);
    result.eventIndex = indexWidth(sections.events.count);
    result.interfaceIndex = indexWidth(sections.interfaceOffsets.count);
    result.nestedTypeIndex = indexWidth(sections.nestedTypes.count);
    result.propertyIndex = indexWidth(sections.properties.count);
    result.methodIndex = (v105 || v106 || v107) ? indexWidth(sections.methods.count) : 4;
    result.genericParameterIndex = (v106 || v107) ? indexWidth(sections.genericParameters.count) : 4;
    result.fieldIndex = (v106 || v107) ? indexWidth(sections.fields.count) : 4;
    result.defaultValueDataIndex = (v106 || v107) ? indexWidth(sections.defaultValueData.count) : 4;
    result.compactGenericContainers = v106 || v107;
    result.hasAlwaysInitMetadataUsages = registrationVersion() >= 106.1;

    // The flat nestedTypes array has its own on-disk width. Its elements do
    // not necessarily use the width of a TypeDefinitionIndex in a record.
    if (sections.nestedTypes.count != 0) {
        if (sections.nestedTypes.sectionSize % sections.nestedTypes.count != 0) {
            invalid("nested types table has an unaligned element width");
        }
        result.nestedTypeTableIndex = static_cast<std::size_t>(
            sections.nestedTypes.sectionSize / sections.nestedTypes.count);
        if (result.nestedTypeTableIndex != 1 && result.nestedTypeTableIndex != 2 &&
            result.nestedTypeTableIndex != 4) {
            invalid("nested types table has an unsupported element width");
        }
    }

    result.typeDefinitionSize = 40 + 3 * result.typeIndex + result.genericContainerIndex + result.fieldIndex +
        result.methodIndex + result.eventIndex + result.propertyIndex + result.nestedTypeIndex +
        2 * result.interfaceIndex;
    result.methodDefinitionSize = 20 + result.typeDefinitionIndex + result.typeIndex + result.parameterIndex +
        result.genericContainerIndex;
    result.parameterDefinitionSize = 8 + result.typeIndex;
    result.fieldDefinitionSize = 8 + result.typeIndex;
    result.genericParameterSize = 12 + result.genericContainerIndex;
    result.genericContainerSize = ((v106 || v107) ? 7 : 12) + result.genericParameterIndex;
    if (result.compactGenericContainers && sections.genericContainers.count != 0) {
        if (sections.genericContainers.sectionSize % sections.genericContainers.count != 0) {
            invalid("generic containers have an unaligned element width");
        }
        const auto recordedSize = static_cast<std::size_t>(
            sections.genericContainers.sectionSize / sections.genericContainers.count);
        // Unity may pad the compact 7-byte prefix before its final index.
        if (recordedSize < result.genericContainerSize ||
            recordedSize - result.genericContainerSize > 4) {
            invalid("generic container element width is outside the compact layout");
        }
        result.genericContainerSize = recordedSize;
    }
    result.fieldDefaultValueSize = result.fieldIndex + result.typeIndex + result.defaultValueDataIndex;
    result.parameterDefaultValueSize = result.parameterIndex + result.typeIndex + result.defaultValueDataIndex;
    result.eventDefinitionSize = 8 + result.typeIndex + 3 * result.methodIndex;
    result.propertyDefinitionSize = 12 + 2 * result.methodIndex;
    result.inlineArraySize = 4 + result.typeIndex;
    result.imageDefinitionSize = 28 + 2 * result.typeDefinitionIndex + result.methodIndex;
    return result;
}

Version104Metadata Version104::read(const std::vector<uint8_t>& data) const {
    return read(data.data(), data.size());
}

Version104Metadata Version104::read(const uint8_t* data, std::size_t size) const {
    Reader reader(data, size);
    reader.require(0, metadataHeaderSize);
    if (reader.u32(0) != metadataMagic) invalid("incorrect sanity value");
    const int32_t rawVersion = reader.i32(4);
    if (rawVersion != static_cast<int32_t>(options_.version)) {
        invalid("header version does not match the selected 104-107 layout");
    }

    Version104Metadata model;
    model.version = options_.version;
    model.versionInfo.rawVersion = rawVersion;
    model.versionInfo.preciseVersion = options_.version;
    model.versionInfo.registrationVersion = registrationVersion();
    model.versionInfo.confidence = MetadataVersionConfidence::Explicit;

    const std::array<MetadataSectionModel MetadataSectionsModel::*, sectionCount> members{
        &MetadataSectionsModel::stringLiterals,
        &MetadataSectionsModel::stringLiteralData,
        &MetadataSectionsModel::strings,
        &MetadataSectionsModel::events,
        &MetadataSectionsModel::properties,
        &MetadataSectionsModel::methods,
        &MetadataSectionsModel::parameterDefaultValues,
        &MetadataSectionsModel::fieldDefaultValues,
        &MetadataSectionsModel::defaultValueData,
        &MetadataSectionsModel::fieldMarshaledSizes,
        &MetadataSectionsModel::parameters,
        &MetadataSectionsModel::fields,
        &MetadataSectionsModel::genericParameters,
        &MetadataSectionsModel::genericParameterConstraints,
        &MetadataSectionsModel::genericContainers,
        &MetadataSectionsModel::nestedTypes,
        &MetadataSectionsModel::interfaces,
        &MetadataSectionsModel::vtableMethods,
        &MetadataSectionsModel::interfaceOffsets,
        &MetadataSectionsModel::typeDefinitions,
        &MetadataSectionsModel::typeInlineArrays,
        &MetadataSectionsModel::images,
        &MetadataSectionsModel::assemblies,
        &MetadataSectionsModel::fieldRefs,
        &MetadataSectionsModel::referencedAssemblies,
        &MetadataSectionsModel::attributeData,
        &MetadataSectionsModel::attributeDataRanges,
        &MetadataSectionsModel::unresolvedIndirectCallParameterTypes,
        &MetadataSectionsModel::unresolvedIndirectCallParameterRanges,
        &MetadataSectionsModel::windowsRuntimeTypeNames,
        &MetadataSectionsModel::windowsRuntimeStrings,
        &MetadataSectionsModel::exportedTypeDefinitions,
    };
    for (std::size_t index = 0; index < members.size(); ++index) {
        model.sections.*(members[index]) = readSection(reader, 8 + index * sectionHeaderSize);
    }
    const auto& sections = model.sections;
    model.layout = layout(sections);
    const auto& widths = model.layout;

    validateBlob(reader, sections.strings, "strings");
    validateBlob(reader, sections.stringLiteralData, "string literal data");
    validateBlob(reader, sections.defaultValueData, "default value data");
    validateTable(reader, sections.stringLiterals, 4, "string literals");
    const std::size_t typeCount = validateTable(
        reader, sections.typeDefinitions, widths.typeDefinitionSize, "type definitions");
    const std::size_t methodCount = validateTable(reader, sections.methods, widths.methodDefinitionSize, "methods");
    const std::size_t parameterCount = validateTable(
        reader, sections.parameters, widths.parameterDefinitionSize, "parameters");
    const std::size_t fieldCount = validateTable(reader, sections.fields, widths.fieldDefinitionSize, "fields");
    validateTable(reader, sections.genericParameters, widths.genericParameterSize, "generic parameters");
    validateTable(reader, sections.genericContainers, widths.genericContainerSize, "generic containers");
    validateTable(reader, sections.fieldDefaultValues, widths.fieldDefaultValueSize, "field default values");
    validateTable(
        reader, sections.parameterDefaultValues, widths.parameterDefaultValueSize, "parameter default values");
    validateTable(reader, sections.events, widths.eventDefinitionSize, "events");
    validateTable(reader, sections.properties, widths.propertyDefinitionSize, "properties");
    validateTable(reader, sections.nestedTypes, widths.nestedTypeTableIndex, "nested types");
    validateTable(reader, sections.interfaces, widths.typeIndex, "interfaces");
    validateTable(reader, sections.interfaceOffsets, widths.typeIndex + 4, "interface offsets");
    validateTable(reader, sections.typeInlineArrays, widths.inlineArraySize, "type inline arrays");
    validateTable(reader, sections.images, widths.imageDefinitionSize, "images");
    validateTable(reader, sections.assemblies, widths.assemblyDefinitionSize, "assemblies");
    validateTable(reader, sections.genericParameterConstraints, widths.typeIndex, "generic parameter constraints");
    validateTable(reader, sections.vtableMethods, 4, "vtable methods");
    const std::size_t unresolvedTypeCount = validateTable(
        reader, sections.unresolvedIndirectCallParameterTypes, widths.typeIndex,
        "unresolved indirect call parameter types");
    const std::size_t unresolvedRangeCount = validateTable(
        reader, sections.unresolvedIndirectCallParameterRanges, 8,
        "unresolved indirect call parameter ranges");

    std::vector<int32_t> unresolvedTypes;
    unresolvedTypes.reserve(unresolvedTypeCount);
    for (std::size_t index = 0; index < unresolvedTypeCount; ++index) {
        unresolvedTypes.push_back(reader.index(
            static_cast<std::size_t>(sections.unresolvedIndirectCallParameterTypes.offset) +
                index * widths.typeIndex,
            widths.typeIndex));
    }
    model.unresolvedSignatures.reserve(unresolvedRangeCount);
    for (std::size_t index = 0; index < unresolvedRangeCount; ++index) {
        const std::size_t cursor =
            static_cast<std::size_t>(sections.unresolvedIndirectCallParameterRanges.offset) + index * 8;
        UnresolvedSignatureModel signature;
        signature.start = reader.i32(cursor);
        signature.count = reader.i32(cursor + 4);
        if (signature.start < 0 || signature.count < 0 ||
            static_cast<std::size_t>(signature.start) > unresolvedTypes.size() ||
            static_cast<std::size_t>(signature.count) >
                unresolvedTypes.size() - static_cast<std::size_t>(signature.start)) {
            invalid("unresolved signature range is outside the type index table");
        }
        const auto begin = unresolvedTypes.begin() + signature.start;
        signature.parameterTypeIndices.assign(begin, begin + signature.count);
        model.unresolvedSignatures.push_back(std::move(signature));
    }

    std::vector<TypeDefinition> types;
    types.reserve(typeCount);
    for (std::size_t index = 0; index < typeCount; ++index) {
        std::size_t cursor = static_cast<std::size_t>(sections.typeDefinitions.offset) + index * widths.typeDefinitionSize;
        TypeDefinition definition;
        definition.nameIndex = reader.u32(cursor);
        definition.namespaceIndex = reader.u32(cursor + 4);
        cursor += 8;
        cursor += widths.typeIndex;
        definition.declaringTypeIndex = reader.index(cursor, widths.typeIndex);
        cursor += widths.typeIndex;
        definition.parentIndex = reader.index(cursor, widths.typeIndex);
        cursor += widths.typeIndex;
        definition.genericContainerIndex = reader.index(cursor, widths.genericContainerIndex);
        cursor += widths.genericContainerIndex;
        definition.flags = reader.u32(cursor);
        cursor += 4;
        definition.fieldStart = reader.index(cursor, widths.fieldIndex);
        cursor += widths.fieldIndex;
        definition.methodStart = reader.index(cursor, widths.methodIndex);
        cursor += widths.methodIndex;
        definition.eventStart = reader.index(cursor, widths.eventIndex);
        cursor += widths.eventIndex;
        definition.propertyStart = reader.index(cursor, widths.propertyIndex);
        cursor += widths.propertyIndex;
        definition.nestedTypeStart = reader.index(cursor, widths.nestedTypeIndex);
        cursor += widths.nestedTypeIndex;
        definition.interfacesStart = reader.index(cursor, widths.interfaceIndex);
        cursor += widths.interfaceIndex + 4;
        definition.interfaceOffsetsStart = reader.index(cursor, widths.interfaceIndex);
        cursor += widths.interfaceIndex;
        definition.methodCount = reader.u16(cursor);
        definition.propertyCount = reader.u16(cursor + 2);
        definition.fieldCount = reader.u16(cursor + 4);
        definition.eventCount = reader.u16(cursor + 6);
        definition.nestedTypeCount = reader.u16(cursor + 8);
        definition.interfacesCount = reader.u16(cursor + 12);
        definition.interfaceOffsetsCount = reader.u16(cursor + 14);
        cursor += 16;
        definition.bitfield = reader.u32(cursor);
        definition.token = reader.u32(cursor + 4);
        types.push_back(definition);
    }

    std::vector<MethodDefinition> methods;
    methods.reserve(methodCount);
    for (std::size_t index = 0; index < methodCount; ++index) {
        std::size_t cursor = static_cast<std::size_t>(sections.methods.offset) + index * widths.methodDefinitionSize;
        MethodDefinition definition;
        definition.nameIndex = reader.u32(cursor);
        cursor += 4;
        definition.declaringType = reader.index(cursor, widths.typeDefinitionIndex);
        cursor += widths.typeDefinitionIndex;
        definition.returnType = reader.index(cursor, widths.typeIndex);
        cursor += widths.typeIndex;
        definition.returnParameterToken = reader.u32(cursor);
        cursor += 4;
        definition.parameterStart = reader.index(cursor, widths.parameterIndex);
        cursor += widths.parameterIndex;
        definition.genericContainerIndex = reader.index(cursor, widths.genericContainerIndex);
        cursor += widths.genericContainerIndex;
        definition.token = reader.u32(cursor);
        definition.flags = reader.u16(cursor + 4);
        definition.iflags = reader.u16(cursor + 6);
        definition.slot = reader.u16(cursor + 8);
        definition.parameterCount = reader.u16(cursor + 10);
        methods.push_back(definition);
    }

    std::vector<ParameterDefinition> parameters;
    parameters.reserve(parameterCount);
    for (std::size_t index = 0; index < parameterCount; ++index) {
        const std::size_t cursor = static_cast<std::size_t>(sections.parameters.offset) + index * widths.parameterDefinitionSize;
        parameters.push_back({
            reader.u32(cursor), reader.u32(cursor + 4), reader.index(cursor + 8, widths.typeIndex)});
    }

    std::vector<FieldDefinition> fields;
    fields.reserve(fieldCount);
    for (std::size_t index = 0; index < fieldCount; ++index) {
        const std::size_t cursor = static_cast<std::size_t>(sections.fields.offset) + index * widths.fieldDefinitionSize;
        FieldDefinition definition;
        definition.nameIndex = reader.u32(cursor);
        definition.typeIndex = reader.index(cursor + 4, widths.typeIndex);
        definition.token = reader.u32(cursor + 4 + widths.typeIndex);
        fields.push_back(definition);
    }

    model.genericParameters.reserve(static_cast<std::size_t>(sections.genericParameters.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.genericParameters.count); ++index) {
        std::size_t cursor = static_cast<std::size_t>(sections.genericParameters.offset) + index * widths.genericParameterSize;
        GenericParameterModel parameter;
        parameter.ownerIndex = reader.index(cursor, widths.genericContainerIndex);
        cursor += widths.genericContainerIndex;
        parameter.name = readString(reader, sections.strings, reader.u32(cursor)).value_or("");
        parameter.constraintsStart = reader.i16(cursor + 4);
        parameter.constraintsCount = reader.i16(cursor + 6);
        parameter.num = reader.u16(cursor + 8);
        parameter.flags = reader.u16(cursor + 10);
        model.genericParameters.push_back(parameter);
    }

    model.genericContainers.reserve(static_cast<std::size_t>(sections.genericContainers.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.genericContainers.count); ++index) {
        std::size_t cursor = static_cast<std::size_t>(sections.genericContainers.offset) + index * widths.genericContainerSize;
        GenericContainerModel container;
        container.ownerIndex = reader.i32(cursor);
        cursor += 4;
        if (widths.compactGenericContainers) {
            container.typeArgumentCount = reader.u16(cursor);
            container.isMethod = reader.u8(cursor + 2);
            cursor += 3 + widths.genericContainerSize - (7 + widths.genericParameterIndex);
        } else {
            container.typeArgumentCount = reader.i32(cursor);
            container.isMethod = reader.i32(cursor + 4);
            cursor += 8;
        }
        container.genericParameterStart = reader.index(cursor, widths.genericParameterIndex);
        model.genericContainers.push_back(container);
    }

    model.fieldDefaultValues.reserve(static_cast<std::size_t>(sections.fieldDefaultValues.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.fieldDefaultValues.count); ++index) {
        std::size_t cursor = static_cast<std::size_t>(sections.fieldDefaultValues.offset) + index * widths.fieldDefaultValueSize;
        FieldDefaultValueModel value;
        value.fieldIndex = reader.index(cursor, widths.fieldIndex);
        cursor += widths.fieldIndex;
        value.typeIndex = reader.index(cursor, widths.typeIndex);
        cursor += widths.typeIndex;
        value.dataIndex = reader.index(cursor, widths.defaultValueDataIndex);
        model.fieldDefaultValues.push_back(value);
    }

    model.parameterDefaultValues.reserve(static_cast<std::size_t>(sections.parameterDefaultValues.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.parameterDefaultValues.count); ++index) {
        std::size_t cursor = static_cast<std::size_t>(sections.parameterDefaultValues.offset) + index * widths.parameterDefaultValueSize;
        ParameterDefaultValueModel value;
        value.parameterIndex = reader.index(cursor, widths.parameterIndex);
        cursor += widths.parameterIndex;
        value.typeIndex = reader.index(cursor, widths.typeIndex);
        cursor += widths.typeIndex;
        value.dataIndex = reader.index(cursor, widths.defaultValueDataIndex);
        model.parameterDefaultValues.push_back(value);
    }

    model.events.reserve(static_cast<std::size_t>(sections.events.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.events.count); ++index) {
        std::size_t cursor = static_cast<std::size_t>(sections.events.offset) + index * widths.eventDefinitionSize;
        EventDefinitionModel event;
        event.nameIndex = reader.u32(cursor);
        cursor += 4;
        event.typeIndex = reader.index(cursor, widths.typeIndex);
        cursor += widths.typeIndex;
        event.add = reader.index(cursor, widths.methodIndex);
        cursor += widths.methodIndex;
        event.remove = reader.index(cursor, widths.methodIndex);
        cursor += widths.methodIndex;
        event.raise = reader.index(cursor, widths.methodIndex);
        cursor += widths.methodIndex;
        event.token = reader.u32(cursor);
        model.events.push_back(event);
    }

    model.properties.reserve(static_cast<std::size_t>(sections.properties.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.properties.count); ++index) {
        std::size_t cursor = static_cast<std::size_t>(sections.properties.offset) + index * widths.propertyDefinitionSize;
        PropertyDefinitionModel property;
        property.nameIndex = reader.u32(cursor);
        cursor += 4;
        property.get = reader.index(cursor, widths.methodIndex);
        cursor += widths.methodIndex;
        property.set = reader.index(cursor, widths.methodIndex);
        cursor += widths.methodIndex;
        property.attrs = reader.u32(cursor);
        property.token = reader.u32(cursor + 4);
        model.properties.push_back(property);
    }

    model.nestedTypes.reserve(static_cast<std::size_t>(sections.nestedTypes.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.nestedTypes.count); ++index) {
        const int32_t nested = reader.index(
            static_cast<std::size_t>(sections.nestedTypes.offset) + index * widths.nestedTypeTableIndex,
            widths.nestedTypeTableIndex);
        if (nested < 0 || static_cast<std::size_t>(nested) >= typeCount) invalid("nested type index is out of range");
        model.nestedTypes.push_back(nested);
    }

    model.interfaces.reserve(static_cast<std::size_t>(sections.interfaces.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.interfaces.count); ++index) {
        model.interfaces.push_back(reader.index(
            static_cast<std::size_t>(sections.interfaces.offset) + index * widths.typeIndex, widths.typeIndex));
    }

    model.interfaceOffsets.reserve(static_cast<std::size_t>(sections.interfaceOffsets.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.interfaceOffsets.count); ++index) {
        const std::size_t cursor = static_cast<std::size_t>(sections.interfaceOffsets.offset) + index * (widths.typeIndex + 4);
        model.interfaceOffsets.push_back({reader.index(cursor, widths.typeIndex), reader.i32(cursor + widths.typeIndex)});
    }

    model.typeInlineArrays.reserve(static_cast<std::size_t>(sections.typeInlineArrays.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.typeInlineArrays.count); ++index) {
        const std::size_t cursor = static_cast<std::size_t>(sections.typeInlineArrays.offset) + index * widths.inlineArraySize;
        const auto typeIndex = reader.index(cursor, widths.typeIndex);
        const auto length = reader.i32(cursor + widths.typeIndex);
        if (typeIndex < 0 || length < 0) invalid("type inline array has an invalid type or length");
        model.typeInlineArrays.push_back({typeIndex, length});
    }

    // Keep the common metadata view populated as well as the version-specific
    // records, since callers may hold this result through MetadataModel&.
    model.MetadataModel::events.reserve(model.events.size());
    for (const auto& event : model.events) {
        model.MetadataModel::events.push_back({
            readString(reader, sections.strings, event.nameIndex).value_or(""),
            event.typeIndex, event.add, event.remove, event.raise, event.token});
    }
    model.MetadataModel::properties.reserve(model.properties.size());
    for (const auto& property : model.properties) {
        model.MetadataModel::properties.push_back({
            readString(reader, sections.strings, property.nameIndex).value_or(""),
            property.get, property.set, property.attrs, property.token});
    }
    model.MetadataModel::nestedTypes = model.nestedTypes;

    model.images.reserve(static_cast<std::size_t>(sections.images.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.images.count); ++index) {
        std::size_t cursor = static_cast<std::size_t>(sections.images.offset) + index * widths.imageDefinitionSize;
        ImageModel image;
        const uint32_t nameIndex = reader.u32(cursor);
        image.name = readString(reader, sections.strings, nameIndex).value_or("");
        image.assemblyIndex = reader.i32(cursor + 4);
        cursor += 8;
        image.typeStart = reader.index(cursor, widths.typeDefinitionIndex);
        cursor += widths.typeDefinitionIndex;
        image.typeCount = reader.u32(cursor);
        cursor += 4;
        image.exportedTypeStart = reader.index(cursor, widths.typeDefinitionIndex);
        cursor += widths.typeDefinitionIndex;
        image.exportedTypeCount = reader.u32(cursor);
        cursor += 4;
        image.entryPointIndex = reader.index(cursor, widths.methodIndex);
        cursor += widths.methodIndex;
        image.token = reader.u32(cursor);
        image.customAttributeStart = reader.i32(cursor + 4);
        image.customAttributeCount = reader.u32(cursor + 8);
        if (image.typeCount != 0) {
            if (image.typeStart < 0 || static_cast<uint64_t>(static_cast<uint32_t>(image.typeStart)) + image.typeCount > typeCount) {
                invalid("image type range is outside the type definition table");
            }
        }
        model.images.push_back(std::move(image));
    }

    model.assemblies.reserve(static_cast<std::size_t>(sections.assemblies.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.assemblies.count); ++index) {
        const std::size_t cursor = static_cast<std::size_t>(sections.assemblies.offset) + index * widths.assemblyDefinitionSize;
        AssemblyModel assembly;
        assembly.imageIndex = reader.i32(cursor);
        assembly.token = reader.u32(cursor + 4);
        assembly.moduleToken = reader.u32(cursor + 8);
        assembly.referencedAssemblyStart = reader.i32(cursor + 12);
        assembly.referencedAssemblyCount = reader.i32(cursor + 16);
        model.assemblies.push_back(assembly);
    }

    if (sections.defaultValueData.sectionSize != 0) {
        const auto* begin = reader.bytes(
            static_cast<std::size_t>(sections.defaultValueData.offset),
            static_cast<std::size_t>(sections.defaultValueData.sectionSize));
        model.defaultValueData.assign(begin, begin + sections.defaultValueData.sectionSize);
    }

    std::unordered_map<int32_t, int32_t> fieldDefaults;
    for (std::size_t index = 0; index < model.fieldDefaultValues.size(); ++index) {
        const auto& value = model.fieldDefaultValues[index];
        const bool dummy = index + 1 == model.fieldDefaultValues.size() &&
            (value.fieldIndex == -1 || value.fieldIndex == std::numeric_limits<int32_t>::max());
        if (!dummy) {
            if (value.fieldIndex < 0 || static_cast<std::size_t>(value.fieldIndex) >= fieldCount) {
                invalid("field default value references an invalid field");
            }
            fieldDefaults.insert_or_assign(value.fieldIndex, static_cast<int32_t>(index));
        }
        if (value.dataIndex >= 0 && static_cast<std::size_t>(value.dataIndex) > model.defaultValueData.size()) {
            invalid("field default value data index is outside the data blob");
        }
    }
    std::unordered_map<int32_t, int32_t> parameterDefaults;
    for (std::size_t index = 0; index < model.parameterDefaultValues.size(); ++index) {
        const auto& value = model.parameterDefaultValues[index];
        if (value.parameterIndex < 0 || static_cast<std::size_t>(value.parameterIndex) >= parameterCount) {
            invalid("parameter default value references an invalid parameter");
        }
        if (value.dataIndex >= 0 && static_cast<std::size_t>(value.dataIndex) > model.defaultValueData.size()) {
            invalid("parameter default value data index is outside the data blob");
        }
        parameterDefaults.insert_or_assign(value.parameterIndex, static_cast<int32_t>(index));
    }

    model.types.reserve(typeCount);
    std::vector<std::string> typeImages(typeCount);
    for (const auto& image : model.images) {
        model.methodPointersByImage.try_emplace(image.name);
        if (image.typeCount == 0) continue;
        const std::size_t begin = static_cast<std::size_t>(image.typeStart);
        for (std::size_t index = 0; index < image.typeCount; ++index) {
            if (typeImages[begin + index].empty()) typeImages[begin + index] = image.name;
        }
    }

    std::vector<std::string> declaringNames;
    declaringNames.reserve(typeCount);
    for (std::size_t index = 0; index < typeCount; ++index) {
        const auto& definition = types[index];
        TypeModel type;
        type.name = readString(reader, sections.strings, definition.nameIndex).value_or("");
        type.nameSpace = readString(reader, sections.strings, definition.namespaceIndex).value_or("");
        type.baseType = typeReference(definition.parentIndex);
        type.imageName = typeImages[index];
        type.declaringTypeIndex = definition.declaringTypeIndex;
        type.genericContainerIndex = definition.genericContainerIndex;
        type.flags = definition.flags;
        type.bitfield = definition.bitfield;
        type.token = definition.token;
        type.eventStart = definition.eventStart;
        type.eventCount = definition.eventCount;
        type.propertyStart = definition.propertyStart;
        type.propertyCount = definition.propertyCount;
        type.nestedTypeStart = definition.nestedTypeStart;
        type.nestedTypeCount = definition.nestedTypeCount;
        declaringNames.push_back(qualifiedName(type));
        model.types.push_back(std::move(type));
    }

    for (std::size_t typeIndex = 0; typeIndex < typeCount; ++typeIndex) {
        const auto& definition = types[typeIndex];
        auto& outputType = model.types[typeIndex];
        const auto validRange = [](int32_t start, uint16_t count, std::size_t total) {
            return count == 0 ||
                (start >= 0 && static_cast<std::size_t>(start) <= total &&
                 count <= total - static_cast<std::size_t>(start));
        };
        if (!validRange(definition.eventStart, definition.eventCount, model.events.size()) ||
            !validRange(definition.propertyStart, definition.propertyCount, model.properties.size()) ||
            !validRange(definition.nestedTypeStart, definition.nestedTypeCount, model.nestedTypes.size()) ||
            !validRange(definition.interfacesStart, definition.interfacesCount, model.interfaces.size()) ||
            !validRange(definition.interfaceOffsetsStart, definition.interfaceOffsetsCount,
                        model.interfaceOffsets.size())) {
            invalid("type event, property, nested, or interface range is outside its table");
        }
        if (definition.fieldCount != 0 &&
            (definition.fieldStart < 0 ||
             static_cast<uint64_t>(static_cast<uint32_t>(definition.fieldStart)) + definition.fieldCount > fieldCount)) {
            invalid("type field range is outside the field table");
        }
        if (definition.methodCount != 0 &&
            (definition.methodStart < 0 ||
             static_cast<uint64_t>(static_cast<uint32_t>(definition.methodStart)) + definition.methodCount > methodCount)) {
            invalid("type method range is outside the method table");
        }
        for (uint32_t index = 0; index < definition.fieldCount; ++index) {
            const int32_t fieldIndex = definition.fieldStart + static_cast<int32_t>(index);
            const auto& fieldDefinition = fields[static_cast<std::size_t>(fieldIndex)];
            FieldModel field;
            field.name = readString(reader, sections.strings, fieldDefinition.nameIndex).value_or("");
            field.type = typeReference(fieldDefinition.typeIndex);
            field.token = fieldDefinition.token;
            if (const auto value = fieldDefaults.find(fieldIndex); value != fieldDefaults.end()) {
                field.defaultValueIndex = value->second;
            }
            outputType.fields.push_back(std::move(field));
        }
        for (uint32_t index = 0; index < definition.methodCount; ++index) {
            const int32_t methodIndex = definition.methodStart + static_cast<int32_t>(index);
            const auto& methodDefinition = methods[static_cast<std::size_t>(methodIndex)];
            MethodModel method;
            method.token = methodDefinition.token;
            method.definitionIndex = methodIndex;
            method.imageName = typeImages[typeIndex];
            method.declaringType = declaringNames[typeIndex];
            if (methodDefinition.declaringType >= 0 &&
                static_cast<std::size_t>(methodDefinition.declaringType) < declaringNames.size()) {
                method.declaringType = declaringNames[static_cast<std::size_t>(methodDefinition.declaringType)];
            }
            method.name = readString(reader, sections.strings, methodDefinition.nameIndex).value_or("");
            method.returnType = typeReference(methodDefinition.returnType);
            method.isStatic = (methodDefinition.flags & 0x0010) != 0;
            method.flags = methodDefinition.flags;
            method.iflags = methodDefinition.iflags;
            method.slot = methodDefinition.slot;
            method.genericContainerIndex = methodDefinition.genericContainerIndex;
            method.returnParameterToken = methodDefinition.returnParameterToken;
            if (methodDefinition.parameterCount != 0 &&
                (methodDefinition.parameterStart < 0 ||
                 static_cast<uint64_t>(static_cast<uint32_t>(methodDefinition.parameterStart)) +
                     methodDefinition.parameterCount > parameterCount)) {
                invalid("method parameter range is outside the parameter table");
            }
            for (uint32_t parameterIndex = 0; parameterIndex < methodDefinition.parameterCount; ++parameterIndex) {
                const int32_t indexInTable = methodDefinition.parameterStart + static_cast<int32_t>(parameterIndex);
                const auto& parameterDefinition = parameters[static_cast<std::size_t>(indexInTable)];
                ParameterModel parameter;
                parameter.name = readString(reader, sections.strings, parameterDefinition.nameIndex).value_or("");
                parameter.type = typeReference(parameterDefinition.typeIndex);
                if (const auto value = parameterDefaults.find(indexInTable); value != parameterDefaults.end()) {
                    parameter.defaultValueIndex = value->second;
                }
                method.parameters.push_back(std::move(parameter));
            }
            outputType.methods.push_back(std::move(method));
        }
    }

    std::vector<int32_t> literalIndices;
    literalIndices.reserve(static_cast<std::size_t>(sections.stringLiterals.count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(sections.stringLiterals.count); ++index) {
        literalIndices.push_back(reader.i32(static_cast<std::size_t>(sections.stringLiterals.offset) + index * 4));
    }
    for (std::size_t index = 0; index < literalIndices.size(); ++index) {
        const int32_t dataIndex = literalIndices[index];
        if (dataIndex < 0) continue;
        const std::size_t start = static_cast<std::size_t>(dataIndex);
        const std::size_t dataSize = static_cast<std::size_t>(sections.stringLiteralData.sectionSize);
        if (start > dataSize) invalid("string literal data index is outside the data blob");
        std::size_t end = dataSize;
        for (std::size_t next = index + 1; next < literalIndices.size(); ++next) {
            if (literalIndices[next] >= 0) {
                end = static_cast<std::size_t>(literalIndices[next]);
                break;
            }
        }
        if (end < start || end > dataSize) invalid("string literal data ranges are not ordered");
        const auto* bytes = reader.bytes(static_cast<std::size_t>(sections.stringLiteralData.offset) + start, end - start);
        model.stringLiterals.emplace(
            static_cast<uint32_t>(index), std::string(reinterpret_cast<const char*>(bytes), end - start));
    }

    return model;
}

Version104Metadata Version104::readFile(const std::string& path) const {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open global metadata file: " + path);
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("Cannot determine global metadata file size: " + path);
    const auto fileSize = static_cast<uint64_t>(end);
    if (fileSize > std::numeric_limits<std::size_t>::max() ||
        fileSize > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("Global metadata file is too large: " + path);
    }
    std::vector<uint8_t> data(static_cast<std::size_t>(fileSize));
    stream.seekg(0, std::ios::beg);
    if (!data.empty()) {
        stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!stream) throw std::runtime_error("Cannot read global metadata file: " + path);
    }
    return read(data);
}

Version104MetadataRegistration Version104::readMetadataRegistration(
    const BinaryImage& binary,
    uint64_t address,
    std::size_t pointerSize) const {
    pointerSize = inferredPointerSize(binary, pointerSize);
    NativeReader reader(binary, pointerSize);
    reader.require(address, metadataRegistrationSize(pointerSize));
    Version104MetadataRegistration result;
    result.pointerSize = pointerSize;
    result.size = metadataRegistrationSize(pointerSize);
    result.genericClasses = reader.table(address, 0, true, "genericClasses");
    result.genericInsts = reader.table(address, 2, true, "genericInsts");
    result.genericMethodTable = reader.table(address, 4, true, "genericMethodTable");
    reader.validateTable(result.genericMethodTable, 12, "genericMethodTable");
    result.types = reader.table(address, 6, true, "types");
    result.methodSpecs = reader.table(address, 8, true, "methodSpecs");
    reader.validateTable(result.methodSpecs, 12, "methodSpecs");
    result.fieldOffsets = reader.table(address, 10, true, "fieldOffsets");
    result.typeDefinitionsSizes = reader.table(address, 12, true, "typeDefinitionsSizes");
    result.metadataUsages = reader.table(address, 14, false, "metadataUsages");
    if (registrationVersion() >= 106.1) {
        result.alwaysInitMetadataUsages = reader.table(address, 16, false, "alwaysInitMetadataUsages");
    }
    return result;
}

Version104CodeRegistration Version104::readCodeRegistration(
    const BinaryImage& binary,
    uint64_t address,
    std::size_t pointerSize) const {
    pointerSize = inferredPointerSize(binary, pointerSize);
    NativeReader reader(binary, pointerSize);
    reader.require(address, codeRegistrationSize(pointerSize));
    Version104CodeRegistration result;
    result.pointerSize = pointerSize;
    result.size = codeRegistrationSize(pointerSize);
    result.reversePInvokeWrappers = reader.table(address, 0, true, "reversePInvokeWrappers");
    result.genericMethodPointers = reader.table(address, 2, true, "genericMethodPointers");
    result.genericAdjustorThunks = reader.native(checkedAdd(address, 4 * pointerSize));
    result.invokerPointers = reader.table(address, 5, true, "invokerPointers");
    result.unresolvedIndirectCallPointers = reader.table(address, 7, true, "unresolvedIndirectCallPointers");
    result.unresolvedInstanceCallPointers = reader.native(checkedAdd(address, 9 * pointerSize));
    result.unresolvedStaticCallPointers = reader.native(checkedAdd(address, 10 * pointerSize));
    result.interopData = reader.table(address, 11, true, "interopData");
    result.windowsRuntimeFactoryTable = reader.table(address, 13, true, "windowsRuntimeFactoryTable");
    result.codeGenModules = reader.table(address, 15, true, "codeGenModules");
    return result;
}

Version104NativeTables Version104::readNative(
    const BinaryImage& binary,
    MetadataModel& metadata,
    uint64_t metadataRegistrationAddress,
    uint64_t codeRegistrationAddress,
    std::size_t pointerSize) const {
    pointerSize = inferredPointerSize(binary, pointerSize);
    Version104NativeTables result;
    result.metadataRegistration = readMetadataRegistration(binary, metadataRegistrationAddress, pointerSize);
    result.codeRegistration = readCodeRegistration(binary, codeRegistrationAddress, pointerSize);

    MetadataRegistrationInfo registration;
    registration.metadataRegistrationAddress = metadataRegistrationAddress;
    registration.codeRegistrationAddress = codeRegistrationAddress;
    registration.typesAddress = result.metadataRegistration.types.address;
    registration.typesCount = result.metadataRegistration.types.count;
    registration.fieldOffsetsAddress = result.metadataRegistration.fieldOffsets.address;
    registration.fieldOffsetsCount = result.metadataRegistration.fieldOffsets.count;
    registration.genericClassesAddress = result.metadataRegistration.genericClasses.address;
    registration.genericClassesCount = result.metadataRegistration.genericClasses.count;
    registration.genericInstsAddress = result.metadataRegistration.genericInsts.address;
    registration.genericInstsCount = result.metadataRegistration.genericInsts.count;
    registration.genericMethodTableAddress = result.metadataRegistration.genericMethodTable.address;
    registration.genericMethodTableCount = result.metadataRegistration.genericMethodTable.count;
    registration.methodSpecsAddress = result.metadataRegistration.methodSpecs.address;
    registration.methodSpecsCount = result.metadataRegistration.methodSpecs.count;
    registration.genericMethodPointersAddress = result.codeRegistration.genericMethodPointers.address;
    registration.genericMethodPointersCount = result.codeRegistration.genericMethodPointers.count;
    registration.invokerPointersAddress = result.codeRegistration.invokerPointers.address;
    registration.invokerPointersCount = result.codeRegistration.invokerPointers.count;
    registration.unresolvedVirtualCallPointersAddress = result.codeRegistration.unresolvedIndirectCallPointers.address;
    registration.unresolvedVirtualCallPointersCount = result.codeRegistration.unresolvedIndirectCallPointers.count;
    registration.genericMethodTableEntrySize = 12;
    registration.registrationVersion = registrationVersion();
    registration.versionConfidence = MetadataVersionConfidence::Registration;
    registration.metadataUsagesCount = result.metadataRegistration.metadataUsages.count;
    MetadataRegistrationReader(pointerSize).read(binary, metadata, registration);

    NativeReader reader(binary, pointerSize);
    metadata.unresolvedVirtualCallPointers = reader.pointerTable(
        result.codeRegistration.unresolvedIndirectCallPointers.address,
        result.codeRegistration.unresolvedIndirectCallPointers.count);
    if (result.metadataRegistration.alwaysInitMetadataUsages.present) {
        result.alwaysInitMetadataUsages = reader.pointerTable(
            result.metadataRegistration.alwaysInitMetadataUsages.address,
            result.metadataRegistration.alwaysInitMetadataUsages.count);
    }
    metadata.versionInfo.registrationVersion = registrationVersion();
    if (metadata.versionInfo.confidence == MetadataVersionConfidence::Unknown) {
        metadata.versionInfo.confidence = MetadataVersionConfidence::Registration;
    }
    return result;
}

} // namespace il2cpprec::versions
