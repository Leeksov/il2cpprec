#include <il2cpprec/versions/Version33.hpp>

#include <array>
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
constexpr size_t legacyHeaderSize = 256;

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid global metadata: " + message);
}

struct Blob {
    uint32_t offset = 0;
    int32_t size = 0;
};

struct Header {
    int32_t version = 0;
    Blob stringLiterals;
    Blob stringLiteralData;
    Blob strings;
    Blob methods;
    Blob parameterDefaultValues;
    Blob fieldDefaultValues;
    Blob defaultValueData;
    Blob parameters;
    Blob fields;
    Blob genericParameters;
    Blob genericContainers;
    Blob typeDefinitions;
    Blob images;
    Blob assemblies;
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

Blob readBlob(const Reader& reader, size_t headerOffset, const char* name) {
    Blob blob{reader.u32(headerOffset), reader.i32(headerOffset + 4)};
    if (blob.size < 0) invalid(std::string(name) + " has negative size");
    if (blob.offset > reader.size() || static_cast<size_t>(blob.size) > reader.size() - blob.offset) {
        invalid(std::string(name) + " is outside the file");
    }
    return blob;
}

Header readHeader(const Reader& reader) {
    reader.require(0, 8);
    if (reader.u32(0) != sanityValue) invalid("incorrect sanity value");

    Header header;
    header.version = reader.i32(4);
    if (header.version != 33 && header.version != 35) {
        throw std::runtime_error("Unsupported global metadata version: " + std::to_string(header.version));
    }
    reader.require(0, legacyHeaderSize);

    constexpr std::array<const char*, 31> names{
        "string literals", "string literal data", "string table", "events", "properties",
        "methods", "parameter default values", "field default values", "default value data",
        "field marshaled sizes", "parameters", "fields", "generic parameters",
        "generic parameter constraints", "generic containers", "nested types", "interfaces",
        "vtable methods", "interface offsets", "type definitions", "images", "assemblies",
        "field references", "referenced assemblies", "attribute data", "attribute data ranges",
        "unresolved virtual call parameter types", "unresolved virtual call parameter ranges",
        "Windows Runtime type names", "Windows Runtime strings", "exported type definitions"
    };
    std::array<Blob, names.size()> blobs{};
    for (size_t index = 0; index < blobs.size(); ++index) {
        blobs[index] = readBlob(reader, 8 + index * 8, names[index]);
    }

    header.stringLiterals = blobs[0];
    header.stringLiteralData = blobs[1];
    header.strings = blobs[2];
    header.methods = blobs[5];
    header.parameterDefaultValues = blobs[6];
    header.fieldDefaultValues = blobs[7];
    header.defaultValueData = blobs[8];
    header.parameters = blobs[10];
    header.fields = blobs[11];
    header.genericParameters = blobs[12];
    header.genericContainers = blobs[14];
    header.typeDefinitions = blobs[19];
    header.images = blobs[20];
    header.assemblies = blobs[21];
    return header;
}

template<typename T, typename Parse>
std::vector<T> readTable(
    const Reader& reader,
    const Blob& blob,
    size_t stride,
    const char* name,
    Parse parse) {
    const auto byteSize = static_cast<size_t>(blob.size);
    reader.require(blob.offset, byteSize);
    if (byteSize % stride != 0) {
        invalid(std::string(name) + " table is misaligned");
    }

    const size_t count = byteSize / stride;
    std::vector<T> result;
    result.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        result.push_back(parse(static_cast<size_t>(blob.offset) + index * stride));
    }
    return result;
}

std::optional<std::string> readString(const Reader& reader, const Header& header, uint32_t index) {
    if (index == std::numeric_limits<uint32_t>::max()) return std::nullopt;
    const auto stringSize = static_cast<size_t>(header.strings.size);
    if (index >= stringSize) invalid("string index is outside the string table");

    const size_t start = static_cast<size_t>(header.strings.offset) + index;
    const size_t remaining = stringSize - index;
    const auto* bytes = reinterpret_cast<const char*>(reader.bytes(start, remaining));
    const void* terminator = std::memchr(bytes, 0, remaining);
    if (terminator == nullptr) invalid("unterminated string in string table");
    const auto length = static_cast<const char*>(terminator) - bytes;
    return std::string(bytes, static_cast<size_t>(length));
}

std::string typeReference(int32_t index) {
    if (index < 0) return {};
    return "type[" + std::to_string(index) + "]";
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

struct ImageDefinition {
    uint32_t nameIndex = 0;
    ImageModel model;
};

struct StringLiteral {
    uint32_t length = 0;
    int32_t dataIndex = -1;
};

TypeDefinition parseType(const Reader& reader, size_t base, int32_t version) {
    TypeDefinition type;
    type.nameIndex = reader.u32(base);
    type.namespaceIndex = reader.u32(base + 4);
    type.declaringTypeIndex = reader.i32(base + 12);
    type.parentIndex = reader.i32(base + 16);

    size_t cursor = base + 20;
    if (version == 33) cursor += 4;
    type.genericContainerIndex = reader.i32(cursor);
    type.flags = reader.u32(cursor + 4);
    type.fieldStart = reader.i32(cursor + 8);
    type.methodStart = reader.i32(cursor + 12);
    cursor += 40;
    type.methodCount = reader.u16(cursor);
    type.fieldCount = reader.u16(cursor + 4);
    type.bitfield = reader.u32(cursor + 16);
    type.token = reader.u32(cursor + 20);
    return type;
}

MethodDefinition parseMethod(const Reader& reader, size_t base) {
    MethodDefinition method;
    method.nameIndex = reader.u32(base);
    method.declaringType = reader.i32(base + 4);
    method.returnType = reader.i32(base + 8);
    method.returnParameterToken = reader.u32(base + 12);
    method.parameterStart = reader.i32(base + 16);
    method.genericContainerIndex = reader.i32(base + 20);
    method.token = reader.u32(base + 24);
    method.flags = reader.u16(base + 28);
    method.iflags = reader.u16(base + 30);
    method.slot = reader.u16(base + 32);
    method.parameterCount = reader.u16(base + 34);
    return method;
}

std::pair<size_t, size_t> recordRange(
    int32_t start,
    uint32_t count,
    size_t available,
    const char* description) {
    if (count == 0) return {0, 0};
    if (start < 0) invalid(std::string(description) + " has a negative start");
    const auto begin = static_cast<size_t>(start);
    if (begin > available || count > available - begin) {
        invalid(std::string(description) + " is outside its table");
    }
    return {begin, count};
}

MetadataSectionModel sectionModel(const Blob& blob, size_t stride = 0) {
    MetadataSectionModel section;
    section.offset = std::bit_cast<int32_t>(blob.offset);
    section.sectionSize = blob.size;
    if (stride != 0) section.count = blob.size / static_cast<int32_t>(stride);
    return section;
}

} // namespace

MetadataModel Version33::read(const std::vector<uint8_t>& data) const {
    return read(data.data(), data.size());
}

MetadataModel Version33::read(const uint8_t* data, size_t size) const {
    Reader reader(data, size);
    const Header header = readHeader(reader);
    const size_t typeStride = header.version == 33 ? 88 : 84;
    const size_t literalStride = header.version == 33 ? 8 : 4;

    auto types = readTable<TypeDefinition>(
        reader, header.typeDefinitions, typeStride, "type definitions",
        [&](size_t base) { return parseType(reader, base, header.version); });
    auto methods = readTable<MethodDefinition>(
        reader, header.methods, 36, "methods",
        [&](size_t base) { return parseMethod(reader, base); });
    auto parameters = readTable<ParameterDefinition>(
        reader, header.parameters, 12, "parameters",
        [&](size_t base) {
            return ParameterDefinition{reader.u32(base), reader.i32(base + 8)};
        });
    auto fields = readTable<FieldDefinition>(
        reader, header.fields, 12, "fields",
        [&](size_t base) {
            return FieldDefinition{reader.u32(base), reader.i32(base + 4), reader.u32(base + 8)};
        });
    auto images = readTable<ImageDefinition>(
        reader, header.images, 40, "images",
        [&](size_t base) {
            ImageDefinition image;
            image.nameIndex = reader.u32(base);
            image.model.assemblyIndex = reader.i32(base + 4);
            image.model.typeStart = reader.i32(base + 8);
            image.model.typeCount = reader.u32(base + 12);
            image.model.exportedTypeStart = reader.i32(base + 16);
            image.model.exportedTypeCount = reader.u32(base + 20);
            image.model.entryPointIndex = reader.i32(base + 24);
            image.model.token = reader.u32(base + 28);
            image.model.customAttributeStart = reader.i32(base + 32);
            image.model.customAttributeCount = reader.u32(base + 36);
            return image;
        });
    auto assemblies = readTable<AssemblyModel>(
        reader, header.assemblies, 64, "assemblies",
        [&](size_t base) {
            AssemblyModel assembly;
            assembly.imageIndex = reader.i32(base);
            assembly.token = reader.u32(base + 4);
            assembly.referencedAssemblyStart = reader.i32(base + 8);
            assembly.referencedAssemblyCount = reader.i32(base + 12);
            return assembly;
        });
    auto genericParameters = readTable<GenericParameterModel>(
        reader, header.genericParameters, 16, "generic parameters",
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
        reader, header.genericContainers, 16, "generic containers",
        [&](size_t base) {
            return GenericContainerModel{
                reader.i32(base), reader.i32(base + 4), reader.i32(base + 8), reader.i32(base + 12)};
        });
    auto fieldDefaultValues = readTable<FieldDefaultValueModel>(
        reader, header.fieldDefaultValues, 12, "field default values",
        [&](size_t base) {
            return FieldDefaultValueModel{reader.i32(base), reader.i32(base + 4), reader.i32(base + 8)};
        });
    auto parameterDefaultValues = readTable<ParameterDefaultValueModel>(
        reader, header.parameterDefaultValues, 12, "parameter default values",
        [&](size_t base) {
            return ParameterDefaultValueModel{reader.i32(base), reader.i32(base + 4), reader.i32(base + 8)};
        });
    auto literals = readTable<StringLiteral>(
        reader, header.stringLiterals, literalStride, "string literals",
        [&](size_t base) {
            if (header.version == 35) return StringLiteral{0, reader.i32(base)};
            return StringLiteral{reader.u32(base), reader.i32(base + 4)};
        });

    const auto literalDataSize = static_cast<size_t>(header.stringLiteralData.size);
    for (const auto& literal : literals) {
        if (literal.dataIndex < 0) invalid("string literal has a negative data index");
        if (static_cast<size_t>(literal.dataIndex) > literalDataSize) {
            invalid("string literal data index is outside the literal data blob");
        }
    }

    MetadataModel model;
    model.version = static_cast<double>(header.version);
    model.versionInfo.rawVersion = header.version;
    model.versionInfo.preciseVersion = model.version;
    model.versionInfo.confidence = MetadataVersionConfidence::RawHeader;
    model.sections.stringLiterals = sectionModel(header.stringLiterals, literalStride);
    model.sections.stringLiteralData = sectionModel(header.stringLiteralData);
    model.sections.strings = sectionModel(header.strings);
    model.sections.methods = sectionModel(header.methods, 36);
    model.sections.parameterDefaultValues = sectionModel(header.parameterDefaultValues, 12);
    model.sections.fieldDefaultValues = sectionModel(header.fieldDefaultValues, 12);
    model.sections.defaultValueData = sectionModel(header.defaultValueData);
    model.sections.parameters = sectionModel(header.parameters, 12);
    model.sections.fields = sectionModel(header.fields, 12);
    model.sections.genericParameters = sectionModel(header.genericParameters, 16);
    model.sections.genericContainers = sectionModel(header.genericContainers, 16);
    model.sections.typeDefinitions = sectionModel(header.typeDefinitions, typeStride);
    model.sections.images = sectionModel(header.images, 40);
    model.sections.assemblies = sectionModel(header.assemblies, 64);
    model.genericParameters = std::move(genericParameters);
    model.genericContainers = std::move(genericContainers);
    model.fieldDefaultValues = std::move(fieldDefaultValues);
    model.parameterDefaultValues = std::move(parameterDefaultValues);

    if (header.defaultValueData.size != 0) {
        const auto* defaultData = reader.bytes(
            header.defaultValueData.offset, static_cast<size_t>(header.defaultValueData.size));
        model.defaultValueData.assign(defaultData, defaultData + header.defaultValueData.size);
    }

    std::unordered_map<int32_t, int32_t> fieldDefaults;
    for (size_t index = 0; index < model.fieldDefaultValues.size(); ++index) {
        const auto& value = model.fieldDefaultValues[index];
        if (value.fieldIndex < 0 || static_cast<size_t>(value.fieldIndex) >= fields.size()) {
            invalid("field default value references an invalid field");
        }
        if (value.dataIndex >= 0 && static_cast<size_t>(value.dataIndex) > model.defaultValueData.size()) {
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
        if (value.dataIndex >= 0 && static_cast<size_t>(value.dataIndex) > model.defaultValueData.size()) {
            invalid("parameter default value data index is outside the data blob");
        }
        parameterDefaults.insert_or_assign(value.parameterIndex, static_cast<int32_t>(index));
    }

    model.images.reserve(images.size());
    model.assemblies = std::move(assemblies);
    model.types.reserve(types.size());
    std::vector<std::string> typeImages(types.size());
    for (const auto& image : images) {
        ImageModel output = image.model;
        output.name = readString(reader, header, image.nameIndex).value_or("");
        const auto [begin, count] = recordRange(
            image.model.typeStart, image.model.typeCount, types.size(), "image type range");
        model.methodPointersByImage.try_emplace(output.name);
        for (size_t index = 0; index < count; ++index) {
            if (typeImages[begin + index].empty()) typeImages[begin + index] = output.name;
        }
        model.images.push_back(std::move(output));
    }

    std::vector<std::string> declaringNames;
    declaringNames.reserve(types.size());
    for (const auto& definition : types) {
        TypeModel type;
        type.name = readString(reader, header, definition.nameIndex).value_or("");
        type.nameSpace = readString(reader, header, definition.namespaceIndex).value_or("");
        type.baseType = typeReference(definition.parentIndex);
        type.declaringTypeIndex = definition.declaringTypeIndex;
        type.genericContainerIndex = definition.genericContainerIndex;
        type.flags = definition.flags;
        type.bitfield = definition.bitfield;
        type.token = definition.token;
        declaringNames.push_back(type.nameSpace.empty() ? type.name : type.nameSpace + "." + type.name);
        model.types.push_back(std::move(type));
    }

    for (size_t typeIndex = 0; typeIndex < types.size(); ++typeIndex) {
        const auto& definition = types[typeIndex];
        auto& outputType = model.types[typeIndex];
        outputType.imageName = typeImages[typeIndex];
        const auto [fieldBegin, fieldCount] = recordRange(
            definition.fieldStart, definition.fieldCount, fields.size(), "type field range");
        for (size_t offset = 0; offset < fieldCount; ++offset) {
            const size_t fieldIndex = fieldBegin + offset;
            const auto& fieldDefinition = fields[fieldIndex];
            FieldModel field;
            field.name = readString(reader, header, fieldDefinition.nameIndex).value_or("");
            field.type = typeReference(fieldDefinition.typeIndex);
            field.token = fieldDefinition.token;
            if (const auto value = fieldDefaults.find(static_cast<int32_t>(fieldIndex));
                value != fieldDefaults.end()) {
                field.defaultValueIndex = value->second;
            }
            outputType.fields.push_back(std::move(field));
        }

        const auto [methodBegin, methodCount] = recordRange(
            definition.methodStart, definition.methodCount, methods.size(), "type method range");
        for (size_t offset = 0; offset < methodCount; ++offset) {
            const size_t methodIndex = methodBegin + offset;
            if (methodIndex > static_cast<size_t>(std::numeric_limits<int>::max())) {
                invalid("method definition index does not fit MethodModel.definitionIndex");
            }
            const auto& methodDefinition = methods[methodIndex];
            MethodModel method;
            method.token = methodDefinition.token;
            method.definitionIndex = static_cast<int>(methodIndex);
            method.imageName = typeImages[typeIndex];
            method.declaringType = declaringNames[typeIndex];
            if (methodDefinition.declaringType >= 0) {
                if (static_cast<size_t>(methodDefinition.declaringType) >= declaringNames.size()) {
                    invalid("method declaring type index is outside the type table");
                }
                method.declaringType = declaringNames[static_cast<size_t>(methodDefinition.declaringType)];
            }
            method.name = readString(reader, header, methodDefinition.nameIndex).value_or("");
            method.returnType = typeReference(methodDefinition.returnType);
            method.returnParameterToken = methodDefinition.returnParameterToken;
            method.isStatic = (methodDefinition.flags & 0x0010) != 0;
            method.flags = methodDefinition.flags;
            method.iflags = methodDefinition.iflags;
            method.slot = methodDefinition.slot;
            method.genericContainerIndex = methodDefinition.genericContainerIndex;

            const auto [parameterBegin, parameterCount] = recordRange(
                methodDefinition.parameterStart,
                methodDefinition.parameterCount,
                parameters.size(),
                "method parameter range");
            for (size_t parameterOffset = 0; parameterOffset < parameterCount; ++parameterOffset) {
                const size_t parameterIndex = parameterBegin + parameterOffset;
                const auto& parameterDefinition = parameters[parameterIndex];
                ParameterModel parameter;
                parameter.name = readString(reader, header, parameterDefinition.nameIndex).value_or("");
                parameter.type = typeReference(parameterDefinition.typeIndex);
                if (const auto value = parameterDefaults.find(static_cast<int32_t>(parameterIndex));
                    value != parameterDefaults.end()) {
                    parameter.defaultValueIndex = value->second;
                }
                method.parameters.push_back(std::move(parameter));
            }
            outputType.methods.push_back(std::move(method));
        }
    }

    for (size_t index = 0; index < literals.size(); ++index) {
        const auto& literal = literals[index];
        const size_t start = static_cast<size_t>(literal.dataIndex);
        size_t length = literal.length;
        if (header.version == 35) {
            const size_t end = index + 1 < literals.size()
                ? static_cast<size_t>(literals[index + 1].dataIndex)
                : literalDataSize;
            if (end < start) invalid("string literal data indices are not monotonically increasing");
            length = end - start;
        }
        if (length > literalDataSize - start) invalid("string literal payload is outside the literal data blob");

        if (length == 0) {
            model.stringLiterals.emplace(static_cast<uint32_t>(index), std::string{});
        } else {
            const size_t offset = static_cast<size_t>(header.stringLiteralData.offset) + start;
            const auto* bytes = reader.bytes(offset, length);
            model.stringLiterals.emplace(
                static_cast<uint32_t>(index),
                std::string(reinterpret_cast<const char*>(bytes), length));
        }
    }

    return model;
}

MetadataModel Version33::readFile(const std::string& path) const {
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
