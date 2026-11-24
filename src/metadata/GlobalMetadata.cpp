#include <il2cpprec/metadata/GlobalMetadata.hpp>

#include <algorithm>
#include <bit>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint32_t sanityValue = 0xFAB11BAF;
constexpr size_t stringLiteralSize = 8;

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid global metadata: " + message);
}

struct Header {
    int rawVersion = 0;
    double version = 0;
    size_t headerSize = 0;
    uint32_t stringLiteralOffset = 0;
    int32_t stringLiteralSize = 0;
    uint32_t stringLiteralDataOffset = 0;
    int32_t stringLiteralDataSize = 0;
    uint32_t stringOffset = 0;
    int32_t stringSize = 0;
    uint32_t methodsOffset = 0;
    int32_t methodsSize = 0;
    uint32_t parameterDefaultValuesOffset = 0;
    int32_t parameterDefaultValuesSize = 0;
    uint32_t fieldDefaultValuesOffset = 0;
    int32_t fieldDefaultValuesSize = 0;
    uint32_t defaultValueDataOffset = 0;
    int32_t defaultValueDataSize = 0;
    uint32_t parametersOffset = 0;
    int32_t parametersSize = 0;
    uint32_t fieldsOffset = 0;
    int32_t fieldsSize = 0;
    uint32_t genericParametersOffset = 0;
    int32_t genericParametersSize = 0;
    uint32_t genericContainersOffset = 0;
    int32_t genericContainersSize = 0;
    uint32_t typeDefinitionsOffset = 0;
    int32_t typeDefinitionsSize = 0;
    uint32_t rgctxEntriesOffset = 0;
    int32_t rgctxEntriesSize = 0;
    uint32_t imagesOffset = 0;
    int32_t imagesSize = 0;
    uint32_t assembliesOffset = 0;
    int32_t assembliesSize = 0;
    uint32_t metadataUsageListsOffset = 0;
    int32_t metadataUsageListsSize = 0;
    uint32_t metadataUsagePairsOffset = 0;
    int32_t metadataUsagePairsSize = 0;
    uint32_t unresolvedTypesOffset = 0;
    int32_t unresolvedTypesSize = 0;
    uint32_t unresolvedRangesOffset = 0;
    int32_t unresolvedRangesSize = 0;
};

struct ImageDefinition {
    uint32_t nameIndex = 0;
    int32_t assemblyIndex = -1;
    int32_t typeStart = 0;
    uint32_t typeCount = 0;
    int32_t exportedTypeStart = -1;
    uint32_t exportedTypeCount = 0;
    int32_t entryPointIndex = -1;
    uint32_t token = 0;
    int32_t customAttributeStart = -1;
    uint32_t customAttributeCount = 0;
};

struct TypeDefinition {
    uint32_t nameIndex = 0;
    uint32_t namespaceIndex = 0;
    int32_t declaringTypeIndex = -1;
    int32_t parentIndex = -1;
    int32_t genericContainerIndex = -1;
    uint32_t flags = 0;
    int32_t fieldStart = -1;
    int32_t methodStart = -1;
    uint16_t methodCount = 0;
    uint16_t fieldCount = 0;
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
    int32_t methodIndex = -1;
    uint32_t token = 0;
    uint16_t flags = 0;
    uint16_t iflags = 0;
    uint16_t slot = 0;
    uint16_t parameterCount = 0;
};

struct ParameterDefinition {
    uint32_t nameIndex = 0;
    int32_t typeIndex = -1;
};

struct FieldDefinition {
    uint32_t nameIndex = 0;
    int32_t typeIndex = -1;
    uint32_t token = 0;
};

class Reader {
public:
    Reader(const uint8_t* data, size_t size)
        : data_(data), size_(size) {
        if (data == nullptr && size != 0) invalid("null data with nonzero size");
    }

    size_t size() const { return size_; }

    uint16_t u16(size_t offset) const {
        require(offset, 2);
        return static_cast<uint16_t>(data_[offset]) |
            static_cast<uint16_t>(static_cast<uint16_t>(data_[offset + 1]) << 8);
    }

    uint32_t u32(size_t offset) const {
        require(offset, 4);
        return static_cast<uint32_t>(data_[offset]) |
            (static_cast<uint32_t>(data_[offset + 1]) << 8) |
            (static_cast<uint32_t>(data_[offset + 2]) << 16) |
            (static_cast<uint32_t>(data_[offset + 3]) << 24);
    }

    int32_t i32(size_t offset) const {
        return std::bit_cast<int32_t>(u32(offset));
    }

    void require(size_t offset, size_t amount) const {
        if (offset > size_ || amount > size_ - offset) invalid("read past end of file");
    }

    const uint8_t* bytes(size_t offset, size_t amount) const {
        require(offset, amount);
        return data_ + offset;
    }

private:
    const uint8_t* data_;
    size_t size_;
};

bool hasTable(const Reader& reader, uint32_t offset, int32_t byteSize, size_t stride) {
    if (byteSize < 0) return false;
    const auto size = static_cast<size_t>(byteSize);
    if (size % stride != 0) return false;
    return offset <= reader.size() && size <= reader.size() - offset;
}

size_t tableCount(const Reader& reader, uint32_t offset, int32_t byteSize, size_t stride, const char* name) {
    if (byteSize < 0) invalid(std::string(name) + " table has negative size");
    if (!hasTable(reader, offset, byteSize, stride)) {
        invalid(std::string(name) + " table is misaligned or outside the file");
    }
    return static_cast<size_t>(byteSize) / stride;
}

size_t selectStride(
    const Reader& reader,
    uint32_t offset,
    int32_t byteSize,
    size_t official,
    size_t compatible,
    const char* name) {
    if (byteSize < 0) invalid(std::string(name) + " table has negative size");
    if (offset > reader.size() || static_cast<size_t>(byteSize) > reader.size() - offset) {
        invalid(std::string(name) + " table is misaligned or outside the file");
    }
    const auto size = static_cast<size_t>(byteSize);
    if (size % official == 0) return official;
    if (compatible != 0 && size % compatible == 0) return compatible;
    invalid(std::string(name) + " table is misaligned or outside the file");
}

template<typename T, typename Parse>
std::vector<T> readTable(
    const Reader& reader,
    uint32_t offset,
    int32_t byteSize,
    size_t stride,
    const char* name,
    Parse parse) {
    const size_t count = tableCount(reader, offset, byteSize, stride, name);
    std::vector<T> result;
    result.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        result.push_back(parse(offset + index * stride));
    }
    return result;
}

// Field inclusion mirrors VersionAttribute ranges in AndnixSH/Il2CppDumper MetadataClass.cs.
size_t typeDefinitionStride(double version) {
    size_t size = 8;
    if (version <= 24.0) size += 4;
    size += 4;
    if (version <= 24.5) size += 4;
    size += 12;
    if (version <= 24.1) size += 8;
    size += 4;
    if (version <= 22.0) size += 8;
    if (version >= 21.0 && version <= 22.0) size += 8;
    size += 4 + 32 + 16 + 4;
    if (version >= 19.0) size += 4;
    return size;
}

size_t methodDefinitionStride(double version) {
    size_t size = 12;
    if (version >= 31.0) size += 4;
    size += 4;
    if (version <= 24.0) size += 4;
    size += 4;
    if (version <= 24.1) size += 20;
    return size + 12;
}

size_t parameterDefinitionStride(double version) {
    return version <= 24.0 ? 16 : 12;
}

size_t fieldDefinitionStride(double version) {
    if (version < 19.0) return 12;
    return version <= 24.0 ? 16 : 12;
}

size_t imageDefinitionStride(double version) {
    size_t size = 16;
    if (version >= 24.0) size += 8;
    size += 4;
    if (version >= 19.0) size += 4;
    if (version >= 24.1) size += 8;
    return size;
}

size_t assemblyDefinitionStride(double version) {
    size_t size = 4;
    if (version >= 24.1) size += 4;
    if (version <= 24.0) size += 4;
    if (version >= 20.0) size += 8;
    size += 48;
    if (version <= 24.3) size += 4;
    return size;
}

std::pair<size_t, size_t> imageHeaderOffsets(double version) {
    size_t cursor = 168;
    if (version <= 24.1) cursor += 8;
    const size_t images = cursor;
    cursor += 8;
    const size_t assemblies = cursor;
    cursor += 8;
    if (version >= 19.0 && version <= 24.5) cursor += 16;
    if (version >= 19.0) cursor += 8;
    if (version >= 20.0) cursor += 8;
    if (version >= 21.0 && version <= 27.2) cursor += 16;
    if (version >= 29.0) cursor += 16;
    if (version >= 22.0) cursor += 16;
    if (version >= 23.0) cursor += 8;
    if (version >= 27.0) cursor += 8;
    if (version >= 24.0) cursor += 8;
    return {images, assemblies};
}

std::pair<size_t, size_t> unresolvedHeaderOffsets(double version) {
    size_t cursor = 168;
    if (version <= 24.1) cursor += 8;
    cursor += 16;
    if (version >= 19.0 && version <= 24.5) cursor += 16;
    if (version >= 19.0) cursor += 8;
    if (version >= 20.0) cursor += 8;
    if (version >= 21.0 && version <= 27.2) cursor += 16;
    if (version >= 29.0) cursor += 16;
    return {cursor, cursor + 8};
}

size_t metadataHeaderSize(double version) {
    size_t cursor = 168;
    if (version <= 24.1) cursor += 8;
    cursor += 16;
    if (version >= 19.0 && version <= 24.5) cursor += 16;
    if (version >= 19.0) cursor += 8;
    if (version >= 20.0) cursor += 8;
    if (version >= 21.0 && version <= 27.2) cursor += 16;
    if (version >= 29.0) cursor += 16;
    if (version >= 22.0) cursor += 16;
    if (version >= 23.0) cursor += 8;
    if (version >= 27.0) cursor += 8;
    if (version >= 24.0) cursor += 8;
    return cursor;
}

Header makeHeader(int rawVersion, double version) {
    Header header;
    header.rawVersion = rawVersion;
    header.version = version;
    header.headerSize = metadataHeaderSize(version);
    const auto [images, assemblies] = imageHeaderOffsets(version);
    header.imagesOffset = static_cast<uint32_t>(images);
    header.assembliesOffset = static_cast<uint32_t>(assemblies);
    if (version <= 24.1) header.rgctxEntriesOffset = 168;
    if (version >= 19.0 && version <= 24.5) {
        header.metadataUsageListsOffset = static_cast<uint32_t>(assemblies + 8);
        header.metadataUsagePairsOffset = static_cast<uint32_t>(assemblies + 16);
    }
    if (version >= 22.0) {
        const auto [types, ranges] = unresolvedHeaderOffsets(version);
        header.unresolvedTypesOffset = static_cast<uint32_t>(types);
        header.unresolvedRangesOffset = static_cast<uint32_t>(ranges);
    }
    return header;
}

Header readHeader(const Reader& reader) {
    reader.require(0, 8);
    if (reader.u32(0) != sanityValue) invalid("incorrect sanity value");
    const int32_t version = reader.i32(4);
    if (version < 16 || version > 31) {
        throw std::runtime_error("Unsupported global metadata version: " + std::to_string(version));
    }

    double preciseVersion = static_cast<double>(version);
    if (version == 24) {
        const uint32_t declaredSize = reader.u32(8);
        if (declaredSize == 264) {
            preciseVersion = 24.2;
        } else if (declaredSize != 240 && declaredSize != 272) {
            throw std::runtime_error("Unsupported metadata 24 header layout");
        }
    }

    Header header = makeHeader(version, preciseVersion);
    const size_t requiredSize = version == 24 && preciseVersion == 24.0 && reader.u32(8) == 240
        ? 240
        : header.headerSize;
    if (reader.size() < requiredSize && version != 24) {
        throw std::runtime_error(
            "Unsupported global metadata version " + std::to_string(version) + " header layout");
    }
    reader.require(0, requiredSize);
    header.stringLiteralOffset = reader.u32(8);
    header.stringLiteralSize = reader.i32(12);
    header.stringLiteralDataOffset = reader.u32(16);
    header.stringLiteralDataSize = reader.i32(20);
    header.stringOffset = reader.u32(24);
    header.stringSize = reader.i32(28);
    header.methodsOffset = reader.u32(48);
    header.methodsSize = reader.i32(52);
    header.parameterDefaultValuesOffset = reader.u32(56);
    header.parameterDefaultValuesSize = reader.i32(60);
    header.fieldDefaultValuesOffset = reader.u32(64);
    header.fieldDefaultValuesSize = reader.i32(68);
    header.defaultValueDataOffset = reader.u32(72);
    header.defaultValueDataSize = reader.i32(76);
    header.parametersOffset = reader.u32(88);
    header.parametersSize = reader.i32(92);
    header.fieldsOffset = reader.u32(96);
    header.fieldsSize = reader.i32(100);
    header.genericParametersOffset = reader.u32(104);
    header.genericParametersSize = reader.i32(108);
    header.genericContainersOffset = reader.u32(120);
    header.genericContainersSize = reader.i32(124);
    header.typeDefinitionsOffset = reader.u32(160);
    header.typeDefinitionsSize = reader.i32(164);
    const size_t imagesField = header.imagesOffset;
    const size_t assembliesField = header.assembliesOffset;
    const size_t usageListsField = header.metadataUsageListsOffset;
    const size_t usagePairsField = header.metadataUsagePairsOffset;
    const size_t unresolvedTypesField = header.unresolvedTypesOffset;
    const size_t unresolvedRangesField = header.unresolvedRangesOffset;
    if (header.rgctxEntriesOffset != 0) {
        const size_t rgctxField = header.rgctxEntriesOffset;
        header.rgctxEntriesOffset = reader.u32(rgctxField);
        header.rgctxEntriesSize = reader.i32(rgctxField + 4);
    }
    header.imagesOffset = reader.u32(imagesField);
    header.imagesSize = reader.i32(imagesField + 4);
    header.assembliesOffset = reader.u32(assembliesField);
    header.assembliesSize = reader.i32(assembliesField + 4);
    if (usageListsField != 0) {
        header.metadataUsageListsOffset = reader.u32(usageListsField);
        header.metadataUsageListsSize = reader.i32(usageListsField + 4);
        header.metadataUsagePairsOffset = reader.u32(usagePairsField);
        header.metadataUsagePairsSize = reader.i32(usagePairsField + 4);
    }
    if (unresolvedTypesField != 0) {
        header.unresolvedTypesOffset = reader.u32(unresolvedTypesField);
        header.unresolvedTypesSize = reader.i32(unresolvedTypesField + 4);
        header.unresolvedRangesOffset = reader.u32(unresolvedRangesField);
        header.unresolvedRangesSize = reader.i32(unresolvedRangesField + 4);
    }
    return header;
}

ImageDefinition parseImage(const Reader& reader, size_t base, double version) {
    ImageDefinition image;
    size_t cursor = base;
    image.nameIndex = reader.u32(cursor);
    image.assemblyIndex = reader.i32(cursor + 4);
    cursor += 8;
    image.typeStart = reader.i32(cursor);
    image.typeCount = reader.u32(cursor + 4);
    cursor += 8;
    if (version >= 24.0) {
        image.exportedTypeStart = reader.i32(cursor);
        image.exportedTypeCount = reader.u32(cursor + 4);
        cursor += 8;
    }
    image.entryPointIndex = reader.i32(cursor);
    cursor += 4;
    if (version >= 19.0) {
        image.token = reader.u32(cursor);
        cursor += 4;
    }
    if (version >= 24.1) {
        image.customAttributeStart = reader.i32(cursor);
        image.customAttributeCount = reader.u32(cursor + 4);
    }
    return image;
}

TypeDefinition parseType(const Reader& reader, size_t base, double version, size_t stride) {
    TypeDefinition type;
    size_t cursor = base;
    type.nameIndex = reader.u32(cursor);
    type.namespaceIndex = reader.u32(cursor + 4);
    cursor += 8;
    const bool compatible96 = stride == 96 && version > 24.0;
    if (version <= 24.0 || compatible96 || stride == 120) cursor += 4;
    cursor += 4;
    if (version <= 24.5) cursor += 4;
    type.declaringTypeIndex = reader.i32(cursor);
    cursor += 4;
    type.parentIndex = reader.i32(cursor);
    cursor += 8;
    if (version <= 24.1) cursor += 8;
    type.genericContainerIndex = reader.i32(cursor);
    cursor += 4;
    if (version <= 22.0 || stride == 120) cursor += 8;
    if ((version >= 21.0 && version <= 22.0) || stride == 120) cursor += 8;
    type.flags = reader.u32(cursor);
    cursor += 4;
    type.fieldStart = reader.i32(cursor);
    type.methodStart = reader.i32(cursor + 4);
    cursor += 32;
    type.methodCount = reader.u16(cursor);
    type.fieldCount = reader.u16(cursor + 4);
    type.bitfield = reader.u32(cursor + 16);
    if (version >= 19.0) type.token = reader.u32(cursor + 20);
    return type;
}

MethodDefinition parseMethod(const Reader& reader, size_t base, double version, size_t stride) {
    MethodDefinition method;
    size_t cursor = base;
    method.nameIndex = reader.u32(cursor);
    method.declaringType = reader.i32(cursor + 4);
    method.returnType = reader.i32(cursor + 8);
    cursor += 12;
    if (version >= 31.0) {
        method.returnParameterToken = reader.u32(cursor);
        cursor += 4;
    }
    method.parameterStart = reader.i32(cursor);
    cursor += 4;
    if (version <= 24.0 || stride == 56) cursor += 4;
    method.genericContainerIndex = reader.i32(cursor);
    cursor += 4;
    if (version <= 24.1) {
        method.methodIndex = reader.i32(cursor);
        cursor += 20;
    }
    method.token = reader.u32(cursor);
    method.flags = reader.u16(cursor + 4);
    method.iflags = reader.u16(cursor + 6);
    method.slot = reader.u16(cursor + 8);
    method.parameterCount = reader.u16(cursor + 10);
    return method;
}

ParameterDefinition parseParameter(const Reader& reader, size_t base, double version, size_t stride) {
    ParameterDefinition parameter;
    parameter.nameIndex = reader.u32(base);
    if (version <= 24.0 || stride == 16) {
        parameter.typeIndex = reader.i32(base + 12);
    } else {
        parameter.typeIndex = reader.i32(base + 8);
    }
    return parameter;
}

FieldDefinition parseField(const Reader& reader, size_t base, double version, size_t stride) {
    FieldDefinition field;
    field.nameIndex = reader.u32(base);
    field.typeIndex = reader.i32(base + 4);
    if (version >= 19.0) {
        field.token = (version <= 24.0 || stride == 16) ? reader.u32(base + 12) : reader.u32(base + 8);
    }
    return field;
}

AssemblyModel parseAssembly(const Reader& reader, size_t base, double version, size_t stride) {
    AssemblyModel assembly;
    size_t cursor = base;
    assembly.imageIndex = reader.i32(cursor);
    cursor += 4;
    if (version >= 24.1) {
        assembly.token = reader.u32(cursor);
        cursor += 4;
    }
    if (version <= 24.0) cursor += 4;
    if (stride == 72 && version >= 24.1) cursor += 4;
    if (version >= 20.0) {
        assembly.referencedAssemblyStart = reader.i32(cursor);
        assembly.referencedAssemblyCount = reader.i32(cursor + 4);
        cursor += 8;
    }
    if (version >= 38.0) {
        cursor += 48;
        if (version <= 24.3) cursor += 4;
        assembly.moduleToken = reader.u32(cursor);
    }
    return assembly;
}

void validateBlob(const Reader& reader, uint32_t offset, int32_t size, const char* name) {
    if (size < 0) invalid(std::string(name) + " has negative size");
    if (offset > reader.size() || static_cast<size_t>(size) > reader.size() - offset) {
        invalid(std::string(name) + " is outside the file");
    }
}

std::optional<std::string> readString(const Reader& reader, const Header& header, uint32_t index) {
    if (index == std::numeric_limits<uint32_t>::max()) return std::nullopt;
    const auto stringBytes = static_cast<size_t>(header.stringSize);
    if (index >= stringBytes) return std::nullopt;
    const size_t start = static_cast<size_t>(header.stringOffset) + index;
    const size_t remaining = stringBytes - index;
    const auto* bytes = reinterpret_cast<const char*>(reader.bytes(start, remaining));
    const void* terminator = std::memchr(bytes, 0, remaining);
    if (terminator == nullptr) return std::nullopt;
    const auto length = static_cast<const char*>(terminator) - bytes;
    return std::string(bytes, static_cast<size_t>(length));
}

std::string typeReference(int32_t index) {
    if (index < 0) return {};
    return "type[" + std::to_string(index) + "]";
}

std::string qualifiedName(const TypeModel& type) {
    if (type.nameSpace.empty()) return type.name;
    if (type.name.empty()) return type.nameSpace;
    return type.nameSpace + "." + type.name;
}

bool validImage(const ImageDefinition& image, size_t typeCount, const Reader& reader, const Header& header) {
    if (image.typeStart < 0) return false;
    if (static_cast<uint64_t>(static_cast<uint32_t>(image.typeStart)) + image.typeCount > typeCount) return false;
    return readString(reader, header, image.nameIndex).has_value();
}

void refineVersion24(const Reader& reader, Header& header) {
    if (header.rawVersion != 24 || header.version != 24.0) return;
    const auto matchesOnly = [](int32_t size, size_t before, size_t after) {
        return size > 0 && static_cast<size_t>(size) % before != 0 && static_cast<size_t>(size) % after == 0;
    };
    if (matchesOnly(header.imagesSize, 32, 40) ||
        matchesOnly(header.typeDefinitionsSize, 104, 100) ||
        matchesOnly(header.methodsSize, 56, 52) ||
        matchesOnly(header.parametersSize, 16, 12) ||
        matchesOnly(header.fieldsSize, 16, 12)) {
        header.version = 24.1;
        return;
    }
    if (header.imagesSize <= 0 || header.imagesOffset > reader.size() ||
        static_cast<size_t>(header.imagesSize) > reader.size() - header.imagesOffset) {
        return;
    }
    const size_t count = static_cast<size_t>(header.imagesSize) / 32;
    for (size_t index = 0; index < count; ++index) {
        if (reader.u32(header.imagesOffset + index * 32 + 28) != 1) {
            header.version = 24.1;
            return;
        }
    }
}

} // namespace

MetadataModel GlobalMetadata::read(const std::vector<uint8_t>& data) const {
    return read(data.data(), data.size());
}

MetadataModel GlobalMetadata::read(const uint8_t* data, size_t size) const {
    Reader reader(data, size);
    Header header = readHeader(reader);
    validateBlob(reader, header.stringOffset, header.stringSize, "string table");
    validateBlob(reader, header.stringLiteralDataOffset, header.stringLiteralDataSize, "string literal data");
    validateBlob(reader, header.defaultValueDataOffset, header.defaultValueDataSize, "default value data");
    refineVersion24(reader, header);

    if (header.version == 24.2 && header.typeDefinitionsSize >= 0 &&
        header.typeDefinitionsSize % 92 != 0 && header.typeDefinitionsSize % 88 == 0) {
        header.version = 24.5;
    }

    size_t compatibleTypeStride = 0;
    if (header.version == 24.0 || header.version == 24.1) compatibleTypeStride = 120;
    if (header.version == 24.2 || header.version == 24.4) compatibleTypeStride = 96;
    const size_t typeStride = selectStride(
        reader,
        header.typeDefinitionsOffset,
        header.typeDefinitionsSize,
        typeDefinitionStride(header.version),
        compatibleTypeStride,
        "type definitions");
    auto types = readTable<TypeDefinition>(
        reader,
        header.typeDefinitionsOffset,
        header.typeDefinitionsSize,
        typeStride,
        "type definitions",
        [&](size_t base) { return parseType(reader, base, header.version, typeStride); });

    const size_t imageStride = imageDefinitionStride(header.version);
    auto images = readTable<ImageDefinition>(
        reader,
        header.imagesOffset,
        header.imagesSize,
        imageStride,
        "images",
        [&](size_t base) { return parseImage(reader, base, header.version); });
    for (const auto& image : images) {
        if (!validImage(image, types.size(), reader, header)) invalid("images contain invalid names or type ranges");
    }

    if (header.version == 24.2 && header.assembliesSize >= 0 &&
        static_cast<size_t>(header.assembliesSize) / 68 < images.size()) {
        header.version = 24.4;
    }
    size_t assemblyStride = assemblyDefinitionStride(header.version);
    if (header.version == 24.1 && header.assembliesSize >= 0 && header.assembliesSize % 64 == 0 &&
        static_cast<size_t>(header.assembliesSize) / 64 == images.size()) {
        assemblyStride = 64;
    }
    assemblyStride = selectStride(
        reader,
        header.assembliesOffset,
        header.assembliesSize,
        assemblyStride,
        header.rawVersion == 24 && header.version <= 24.1 ? 72 : 0,
        "assemblies");
    auto assemblies = readTable<AssemblyModel>(
        reader,
        header.assembliesOffset,
        header.assembliesSize,
        assemblyStride,
        "assemblies",
        [&](size_t base) { return parseAssembly(reader, base, header.version, assemblyStride); });

    const size_t officialMethodStride = methodDefinitionStride(header.version);
    const size_t methodStride = selectStride(
        reader,
        header.methodsOffset,
        header.methodsSize,
        officialMethodStride,
        header.version == 24.1 ? 56 : 0,
        "methods");
    auto methods = readTable<MethodDefinition>(
        reader,
        header.methodsOffset,
        header.methodsSize,
        methodStride,
        "methods",
        [&](size_t base) { return parseMethod(reader, base, header.version, methodStride); });

    const size_t parameterCompatibleStride = header.rawVersion == 24 && header.version > 24.0 ? 16 : 0;
    const size_t parameterStride = selectStride(
        reader,
        header.parametersOffset,
        header.parametersSize,
        parameterDefinitionStride(header.version),
        parameterCompatibleStride,
        "parameters");
    auto parameters = readTable<ParameterDefinition>(
        reader,
        header.parametersOffset,
        header.parametersSize,
        parameterStride,
        "parameters",
        [&](size_t base) { return parseParameter(reader, base, header.version, parameterStride); });

    const size_t fieldStride = selectStride(
        reader,
        header.fieldsOffset,
        header.fieldsSize,
        fieldDefinitionStride(header.version),
        parameterCompatibleStride,
        "fields");
    auto fields = readTable<FieldDefinition>(
        reader,
        header.fieldsOffset,
        header.fieldsSize,
        fieldStride,
        "fields",
        [&](size_t base) { return parseField(reader, base, header.version, fieldStride); });

    std::vector<int32_t> unresolvedTypes;
    std::vector<UnresolvedSignatureModel> unresolvedSignatures;
    if (header.version >= 22.0) {
        unresolvedTypes = readTable<int32_t>(
            reader,
            header.unresolvedTypesOffset,
            header.unresolvedTypesSize,
            4,
            "unresolved signature types",
            [&](size_t base) { return reader.i32(base); });
        unresolvedSignatures = readTable<UnresolvedSignatureModel>(
            reader,
            header.unresolvedRangesOffset,
            header.unresolvedRangesSize,
            8,
            "unresolved signature ranges",
            [&](size_t base) {
                return UnresolvedSignatureModel{reader.i32(base), reader.i32(base + 4), {}};
            });
        for (auto& signature : unresolvedSignatures) {
            if (signature.start < 0 || signature.count < 0 ||
                static_cast<size_t>(signature.start) > unresolvedTypes.size() ||
                static_cast<size_t>(signature.count) > unresolvedTypes.size() - static_cast<size_t>(signature.start)) {
                invalid("unresolved signature range is outside the type table");
            }
            const auto begin = unresolvedTypes.begin() + signature.start;
            signature.parameterTypeIndices.assign(begin, begin + signature.count);
        }
    }

    auto genericParameters = readTable<GenericParameterModel>(
        reader,
        header.genericParametersOffset,
        header.genericParametersSize,
        16,
        "generic parameters",
        [&](size_t base) {
            GenericParameterModel parameter;
            parameter.ownerIndex = reader.i32(base);
            parameter.name = readString(reader, header, reader.u32(base + 4)).value_or("");
            parameter.constraintsStart = std::bit_cast<int16_t>(reader.u16(base + 8));
            parameter.constraintsCount = std::bit_cast<int16_t>(reader.u16(base + 10));
            parameter.num = reader.u16(base + 12);
            parameter.flags = reader.u16(base + 14);
            return parameter;
        });
    auto genericContainers = readTable<GenericContainerModel>(
        reader,
        header.genericContainersOffset,
        header.genericContainersSize,
        16,
        "generic containers",
        [&](size_t base) {
            return GenericContainerModel{
                reader.i32(base), reader.i32(base + 4), reader.i32(base + 8), reader.i32(base + 12)};
        });
    auto fieldDefaultValues = readTable<FieldDefaultValueModel>(
        reader,
        header.fieldDefaultValuesOffset,
        header.fieldDefaultValuesSize,
        12,
        "field default values",
        [&](size_t base) {
            return FieldDefaultValueModel{reader.i32(base), reader.i32(base + 4), reader.i32(base + 8)};
        });
    auto parameterDefaultValues = readTable<ParameterDefaultValueModel>(
        reader,
        header.parameterDefaultValuesOffset,
        header.parameterDefaultValuesSize,
        12,
        "parameter default values",
        [&](size_t base) {
            return ParameterDefaultValueModel{reader.i32(base), reader.i32(base + 4), reader.i32(base + 8)};
        });

    auto literals = readTable<uint64_t>(
        reader,
        header.stringLiteralOffset,
        header.stringLiteralSize,
        stringLiteralSize,
        "string literals",
        [&](size_t base) {
            return static_cast<uint64_t>(reader.u32(base)) |
                (static_cast<uint64_t>(reader.u32(base + 4)) << 32);
        });

    std::vector<MetadataUsageListModel> usageLists;
    std::vector<MetadataUsageModel> usagePairs;
    if (header.version >= 19.0 && header.version <= 24.5) {
        usageLists = readTable<MetadataUsageListModel>(
            reader,
            header.metadataUsageListsOffset,
            header.metadataUsageListsSize,
            8,
            "metadata usage lists",
            [&](size_t base) {
                return MetadataUsageListModel{reader.u32(base), reader.u32(base + 4)};
            });
        usagePairs = readTable<MetadataUsageModel>(
            reader,
            header.metadataUsagePairsOffset,
            header.metadataUsagePairsSize,
            8,
            "metadata usage pairs",
            [&](size_t base) {
                MetadataUsageModel usage;
                usage.destinationIndex = reader.u32(base);
                usage.encodedSourceIndex = reader.u32(base + 4);
                usage.kind = usage.encodedSourceIndex >> 29;
                usage.decodedIndex = header.version >= 27.0
                    ? (usage.encodedSourceIndex & 0x1FFFFFFEU) >> 1
                    : usage.encodedSourceIndex & 0x1FFFFFFFU;
                return usage;
            });
        for (const auto& list : usageLists) {
            if (list.start > usagePairs.size() || list.count > usagePairs.size() - list.start) {
                invalid("metadata usage list range is outside the pairs table");
            }
        }
    }

    MetadataModel model;
    model.version = header.version;
    model.versionInfo.rawVersion = header.rawVersion;
    model.versionInfo.preciseVersion = header.version;
    model.versionInfo.confidence = header.rawVersion == 24 && header.version != 24.0
        ? MetadataVersionConfidence::InferredLayout
        : MetadataVersionConfidence::RawHeader;
    model.assemblies = std::move(assemblies);
    model.unresolvedSignatures = std::move(unresolvedSignatures);
    model.sections.stringLiterals = {
        static_cast<int32_t>(header.stringLiteralOffset), header.stringLiteralSize, static_cast<int32_t>(literals.size())};
    model.sections.stringLiteralData = {
        static_cast<int32_t>(header.stringLiteralDataOffset), header.stringLiteralDataSize, header.stringLiteralDataSize};
    model.sections.strings = {
        static_cast<int32_t>(header.stringOffset), header.stringSize, header.stringSize};
    model.sections.methods = {
        static_cast<int32_t>(header.methodsOffset), header.methodsSize, static_cast<int32_t>(methods.size())};
    model.sections.parameterDefaultValues = {
        static_cast<int32_t>(header.parameterDefaultValuesOffset), header.parameterDefaultValuesSize,
        static_cast<int32_t>(model.parameterDefaultValues.size())};
    model.sections.fieldDefaultValues = {
        static_cast<int32_t>(header.fieldDefaultValuesOffset), header.fieldDefaultValuesSize,
        static_cast<int32_t>(model.fieldDefaultValues.size())};
    model.sections.defaultValueData = {
        static_cast<int32_t>(header.defaultValueDataOffset), header.defaultValueDataSize, header.defaultValueDataSize};
    model.sections.parameters = {
        static_cast<int32_t>(header.parametersOffset), header.parametersSize, static_cast<int32_t>(parameters.size())};
    model.sections.fields = {
        static_cast<int32_t>(header.fieldsOffset), header.fieldsSize, static_cast<int32_t>(fields.size())};
    model.sections.genericParameters = {
        static_cast<int32_t>(header.genericParametersOffset), header.genericParametersSize,
        static_cast<int32_t>(model.genericParameters.size())};
    model.sections.genericContainers = {
        static_cast<int32_t>(header.genericContainersOffset), header.genericContainersSize,
        static_cast<int32_t>(model.genericContainers.size())};
    model.sections.typeDefinitions = {
        static_cast<int32_t>(header.typeDefinitionsOffset), header.typeDefinitionsSize, static_cast<int32_t>(types.size())};
    model.sections.images = {
        static_cast<int32_t>(header.imagesOffset), header.imagesSize, static_cast<int32_t>(images.size())};
    model.sections.assemblies = {
        static_cast<int32_t>(header.assembliesOffset), header.assembliesSize, static_cast<int32_t>(model.assemblies.size())};
    model.metadataUsageLists = std::move(usageLists);
    model.metadataUsagePairs = std::move(usagePairs);
    model.genericParameters = std::move(genericParameters);
    model.genericContainers = std::move(genericContainers);
    model.fieldDefaultValues = std::move(fieldDefaultValues);
    model.parameterDefaultValues = std::move(parameterDefaultValues);
    if (header.defaultValueDataSize > 0) {
        model.defaultValueData.assign(
            data + header.defaultValueDataOffset,
            data + header.defaultValueDataOffset + header.defaultValueDataSize);
    }
    std::unordered_map<int32_t, int32_t> fieldDefaults;
    for (size_t index = 0; index < model.fieldDefaultValues.size(); ++index) {
        const auto& value = model.fieldDefaultValues[index];
        if (value.fieldIndex < 0 || static_cast<size_t>(value.fieldIndex) >= fields.size()) {
            invalid("field default value references an invalid field");
        }
        if (value.dataIndex >= 0 && static_cast<size_t>(value.dataIndex) > static_cast<size_t>(header.defaultValueDataSize)) {
            invalid("field default value data index is outside the data blob");
        }
        fieldDefaults.insert_or_assign(value.fieldIndex, static_cast<int32_t>(index));
    }
    std::unordered_map<int32_t, int32_t> parameterDefaults;
    for (size_t index = 0; index < model.parameterDefaultValues.size(); ++index) {
        const auto& value = model.parameterDefaultValues[index];
        if (value.parameterIndex < 0 || static_cast<size_t>(value.parameterIndex) >= parameters.size()) {
            invalid("parameter default value references an invalid parameter");
        }
        if (value.dataIndex >= 0 && static_cast<size_t>(value.dataIndex) > static_cast<size_t>(header.defaultValueDataSize)) {
            invalid("parameter default value data index is outside the data blob");
        }
        parameterDefaults.insert_or_assign(value.parameterIndex, static_cast<int32_t>(index));
    }
    model.types.reserve(types.size());
    std::vector<std::string> typeImages(types.size());
    for (const auto& image : images) {
        const auto imageName = readString(reader, header, image.nameIndex).value_or("");
        ImageModel imageModel;
        imageModel.name = imageName;
        imageModel.assemblyIndex = image.assemblyIndex;
        imageModel.typeStart = image.typeStart;
        imageModel.typeCount = image.typeCount;
        imageModel.exportedTypeStart = image.exportedTypeStart;
        imageModel.exportedTypeCount = image.exportedTypeCount;
        imageModel.entryPointIndex = image.entryPointIndex;
        imageModel.token = image.token;
        imageModel.customAttributeStart = image.customAttributeStart;
        imageModel.customAttributeCount = image.customAttributeCount;
        model.images.push_back(std::move(imageModel));
        model.methodPointersByImage.try_emplace(imageName);
        const size_t begin = static_cast<size_t>(image.typeStart);
        const size_t count = std::min<size_t>(image.typeCount, types.size() - begin);
        for (size_t index = 0; index < count; ++index) {
            if (typeImages[begin + index].empty()) typeImages[begin + index] = imageName;
        }
    }

    std::vector<std::string> declaringNames;
    declaringNames.reserve(types.size());
    for (size_t typeIndex = 0; typeIndex < types.size(); ++typeIndex) {
        const auto& definition = types[typeIndex];
        TypeModel type;
        type.name = readString(reader, header, definition.nameIndex).value_or("");
        type.nameSpace = readString(reader, header, definition.namespaceIndex).value_or("");
        type.baseType = typeReference(definition.parentIndex);
        type.imageName = typeImages[typeIndex];
        type.declaringTypeIndex = definition.declaringTypeIndex;
        type.genericContainerIndex = definition.genericContainerIndex;
        type.flags = definition.flags;
        type.bitfield = definition.bitfield;
        type.token = definition.token;
        declaringNames.push_back(qualifiedName(type));
        model.types.push_back(std::move(type));
    }

    for (size_t typeIndex = 0; typeIndex < types.size(); ++typeIndex) {
        const auto& definition = types[typeIndex];
        auto& outputType = model.types[typeIndex];
        for (uint32_t index = 0; index < definition.fieldCount; ++index) {
            const int64_t fieldIndex = static_cast<int64_t>(definition.fieldStart) + index;
            if (fieldIndex < 0 || static_cast<uint64_t>(fieldIndex) >= fields.size()) break;
            const auto& fieldDefinition = fields[static_cast<size_t>(fieldIndex)];
            FieldModel field;
            field.name = readString(reader, header, fieldDefinition.nameIndex).value_or("");
            field.type = typeReference(fieldDefinition.typeIndex);
            field.token = fieldDefinition.token;
            if (const auto defaultValue = fieldDefaults.find(static_cast<int32_t>(fieldIndex));
                defaultValue != fieldDefaults.end()) {
                field.defaultValueIndex = defaultValue->second;
            }
            outputType.fields.push_back(std::move(field));
        }

        for (uint32_t index = 0; index < definition.methodCount; ++index) {
            const int64_t methodIndex = static_cast<int64_t>(definition.methodStart) + index;
            if (methodIndex < 0 || static_cast<uint64_t>(methodIndex) >= methods.size()) break;
            const auto& methodDefinition = methods[static_cast<size_t>(methodIndex)];
            MethodModel method;
            method.token = methodDefinition.token;
            method.definitionIndex = static_cast<int>(methodIndex);
            method.methodIndex = methodDefinition.methodIndex;
            method.imageName = typeImages[typeIndex];
            method.declaringType = declaringNames[typeIndex];
            if (methodDefinition.declaringType >= 0 &&
                static_cast<size_t>(methodDefinition.declaringType) < declaringNames.size()) {
                method.declaringType = declaringNames[static_cast<size_t>(methodDefinition.declaringType)];
            }
            method.name = readString(reader, header, methodDefinition.nameIndex).value_or("");
            method.returnType = typeReference(methodDefinition.returnType);
            method.isStatic = (methodDefinition.flags & 0x0010) != 0;
            method.flags = methodDefinition.flags;
            method.iflags = methodDefinition.iflags;
            method.slot = methodDefinition.slot;
            method.genericContainerIndex = methodDefinition.genericContainerIndex;
            method.returnParameterToken = methodDefinition.returnParameterToken;

            for (uint32_t parameterIndex = 0; parameterIndex < methodDefinition.parameterCount; ++parameterIndex) {
                const int64_t indexInTable = static_cast<int64_t>(methodDefinition.parameterStart) + parameterIndex;
                if (indexInTable < 0 || static_cast<uint64_t>(indexInTable) >= parameters.size()) break;
                const auto& parameterDefinition = parameters[static_cast<size_t>(indexInTable)];
                ParameterModel parameter;
                parameter.name = readString(reader, header, parameterDefinition.nameIndex).value_or("");
                parameter.type = typeReference(parameterDefinition.typeIndex);
                if (const auto defaultValue = parameterDefaults.find(static_cast<int32_t>(indexInTable));
                    defaultValue != parameterDefaults.end()) {
                    parameter.defaultValueIndex = defaultValue->second;
                }
                method.parameters.push_back(std::move(parameter));
            }
            outputType.methods.push_back(std::move(method));
        }
    }

    for (size_t index = 0; index < literals.size(); ++index) {
        const uint32_t length = static_cast<uint32_t>(literals[index]);
        const int32_t dataIndex = static_cast<int32_t>(literals[index] >> 32);
        if (dataIndex < 0) continue;
        const size_t start = static_cast<size_t>(dataIndex);
        const size_t dataSize = static_cast<size_t>(header.stringLiteralDataSize);
        if (start > dataSize || length > dataSize - start) continue;
        if (length == 0) {
            model.stringLiterals.emplace(static_cast<uint32_t>(index), std::string{});
        } else {
            const size_t offset = static_cast<size_t>(header.stringLiteralDataOffset) + start;
            model.stringLiterals.emplace(
                static_cast<uint32_t>(index),
                std::string(reinterpret_cast<const char*>(data + offset), length));
        }
    }

    return model;
}

MetadataModel GlobalMetadata::readFile(const std::string& path) const {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open global metadata file: " + path);
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("Cannot determine global metadata file size: " + path);
    const auto fileSize = static_cast<uint64_t>(end);
    if (fileSize > std::numeric_limits<size_t>::max() ||
        fileSize > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("Global metadata file is too large: " + path);
    }
    std::vector<uint8_t> data(static_cast<size_t>(fileSize));
    stream.seekg(0, std::ios::beg);
    if (!data.empty()) {
        stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!stream) throw std::runtime_error("Cannot read global metadata file: " + path);
    }
    return read(data);
}

} // namespace il2cpprec
