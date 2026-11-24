#include <il2cpprec/versions/Version110.hpp>

#include <bit>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint32_t methodTokenType = 0x06000000U;
constexpr uint32_t tokenRowIdMask = 0x00FFFFFFU;
constexpr size_t generatedMethodTypeInfoSize = 12;
constexpr size_t generatedMethodTokenSize = 4;
using SectionMember = MetadataSectionModel MetadataSectionsModel::*;
constexpr std::array<SectionMember, Version110Header::sectionCount> sectionOrder = {
    &MetadataSectionsModel::stringLiterals, &MetadataSectionsModel::stringLiteralData,
    &MetadataSectionsModel::strings, &MetadataSectionsModel::events,
    &MetadataSectionsModel::properties, &MetadataSectionsModel::methods,
    &MetadataSectionsModel::parameterDefaultValues, &MetadataSectionsModel::fieldDefaultValues,
    &MetadataSectionsModel::defaultValueData, &MetadataSectionsModel::fieldMarshaledSizes,
    &MetadataSectionsModel::parameters, &MetadataSectionsModel::fields,
    &MetadataSectionsModel::genericParameters, &MetadataSectionsModel::genericParameterConstraints,
    &MetadataSectionsModel::genericContainers, &MetadataSectionsModel::nestedTypes,
    &MetadataSectionsModel::interfaces, &MetadataSectionsModel::vtableMethods,
    &MetadataSectionsModel::interfaceOffsets, &MetadataSectionsModel::typeDefinitions,
    &MetadataSectionsModel::typeInlineArrays, &MetadataSectionsModel::images,
    &MetadataSectionsModel::assemblies, &MetadataSectionsModel::fieldRefs,
    &MetadataSectionsModel::referencedAssemblies, &MetadataSectionsModel::attributeData,
    &MetadataSectionsModel::attributeDataRanges,
    &MetadataSectionsModel::unresolvedIndirectCallParameterTypes,
    &MetadataSectionsModel::unresolvedIndirectCallParameterRanges,
    &MetadataSectionsModel::windowsRuntimeTypeNames,
    &MetadataSectionsModel::windowsRuntimeStrings,
    &MetadataSectionsModel::exportedTypeDefinitions,
    &MetadataSectionsModel::methodSpecsOnGenericType,
    &MetadataSectionsModel::genericMethodSpecsOnType, &MetadataSectionsModel::methodSpecs,
    &MetadataSectionsModel::genericMethodFunctionsDefinitions,
    &MetadataSectionsModel::genericMethodFunctionsDefinitionsWithAdjustor,
    &MetadataSectionsModel::invokerIndices, &MetadataSectionsModel::rgctxRanges,
    &MetadataSectionsModel::rgctxValues, &MetadataSectionsModel::staticConstructorTypeIndices,
    &MetadataSectionsModel::generatedMethodTypeInfos, &MetadataSectionsModel::generatedMethodTokens
};

struct GeneratedView {
    const std::vector<TypeModel>& types;
    const std::vector<GeneratedMethodTypeInfoModel>& typeInfos;
    const std::vector<GeneratedMethodTokenModel>& tokens;
    int32_t generatedMethodsStart;
};

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 110 generated methods: " + message);
}

GeneratedView view(const MetadataModel& metadata) {
    return {
        metadata.types,
        metadata.generatedMethodTypeInfos,
        metadata.generatedMethodTokens,
        metadata.generatedMethodsStart
    };
}

size_t totalMethodDefinitions(const GeneratedView& generated) {
    if (generated.generatedMethodsStart < 0) invalid("generatedMethodsStart is negative");
    const auto start = static_cast<uint64_t>(static_cast<uint32_t>(generated.generatedMethodsStart));
    const uint64_t total = start + generated.tokens.size();
    if (total > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
        invalid("method definition count exceeds the signed index range");
    }
    return static_cast<size_t>(total);
}

bool validMethodToken(uint32_t token) {
    return (token & ~tokenRowIdMask) == methodTokenType && (token & tokenRowIdMask) != 0;
}

void validateToken(uint32_t token) {
    if (!validMethodToken(token)) invalid("generated method has an invalid MethodDef token");
}

void validateTypeInfo(const GeneratedView& generated, const GeneratedMethodTypeInfoModel& info, size_t total) {
    if (info.typeIndex < 0) invalid("generated method type index is negative");
    if (info.generatedMethodCount < 0) invalid("generated method range has a negative count");

    // An empty range may use the usual invalid-index sentinel. It must never
    // be treated as a method definition or indexed into the token table.
    if (info.generatedMethodCount == 0 && info.generatedMethodStart == -1) return;
    if (info.generatedMethodStart < 0) invalid("generated method range has a negative start");

    const uint64_t start = static_cast<uint32_t>(info.generatedMethodStart);
    const uint64_t count = static_cast<uint32_t>(info.generatedMethodCount);
    const uint64_t end = start + count;
    if (end > total) invalid("generated method range exceeds the method definition table");
    if (count != 0 && start < static_cast<uint32_t>(generated.generatedMethodsStart)) {
        invalid("generated method range overlaps ordinary method definitions");
    }
}

const GeneratedMethodTypeInfoModel* findTypeInfo(const GeneratedView& generated, int32_t typeDefinitionIndex) {
    if (typeDefinitionIndex < 0 || static_cast<size_t>(typeDefinitionIndex) >= generated.types.size()) {
        invalid("type definition index is outside the type table");
    }

    const GeneratedMethodTypeInfoModel* result = nullptr;
    const size_t total = totalMethodDefinitions(generated);
    for (const auto& info : generated.typeInfos) {
        if (info.typeIndex != typeDefinitionIndex) continue;
        validateTypeInfo(generated, info, total);
        if (result != nullptr) invalid("type has duplicate generatedMethodTypeInfo entries");
        result = &info;
    }
    return result;
}

void validateTables(const GeneratedView& generated, size_t expectedTotal, bool validateTypes) {
    if (totalMethodDefinitions(generated) != expectedTotal) {
        invalid("generatedMethodsStart is inconsistent with the method and token table counts");
    }

    std::unordered_set<int32_t> typeIndices;
    for (const auto& info : generated.typeInfos) {
        validateTypeInfo(generated, info, expectedTotal);
        if (!typeIndices.insert(info.typeIndex).second) {
            invalid("type has duplicate generatedMethodTypeInfo entries");
        }
        if (validateTypes) {
            if (static_cast<size_t>(info.typeIndex) >= generated.types.size()) {
                invalid("generatedMethodTypeInfo references a type outside the type table");
            }
            const auto& type = generated.types[static_cast<size_t>(info.typeIndex)];
            if (info.generatedMethodCount > 0 && !Version110::hasGeneratedMethods(type)) {
                invalid("generatedMethodTypeInfo contradicts HasGeneratedMethods");
            }
        }
    }
    for (const auto& entry : generated.tokens) validateToken(entry.token);
}

struct TableLocation {
    size_t offset = 0;
    size_t count = 0;
};

TableLocation tableLocation(
    const MetadataSectionModel& section,
    size_t stride,
    const uint8_t* data,
    size_t size,
    const char* name) {
    if (data == nullptr && size != 0) invalid("null metadata data with nonzero size");
    if (section.offset < 0 || section.sectionSize < 0 || section.count < 0) {
        invalid(std::string(name) + " section has a negative offset, size, or count");
    }

    const auto count = static_cast<size_t>(section.count);
    if (count > std::numeric_limits<size_t>::max() / stride) {
        invalid(std::string(name) + " section size overflows");
    }
    const size_t expectedSize = count * stride;
    if (static_cast<size_t>(section.sectionSize) != expectedSize) {
        invalid(std::string(name) + " section size does not match its count and record size");
    }

    const auto offset = static_cast<size_t>(section.offset);
    if (offset > size || expectedSize > size - offset) {
        invalid(std::string(name) + " section is outside the metadata file");
    }
    return {offset, count};
}

uint32_t readU32(const uint8_t* data, size_t offset) {
    return static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset + 1]) << 8) |
        (static_cast<uint32_t>(data[offset + 2]) << 16) |
        (static_cast<uint32_t>(data[offset + 3]) << 24);
}

int32_t readI32(const uint8_t* data, size_t offset) {
    return std::bit_cast<int32_t>(readU32(data, offset));
}

uint32_t ordinaryMethodToken(const ImageModel& image, int32_t methodDefinitionIndex) {
    if (methodDefinitionIndex < 0) invalid("ordinary method definition index is negative");
    if (image.methodStart < 0) invalid("image has a negative ordinary method start");
    const int64_t rowId = static_cast<int64_t>(methodDefinitionIndex) - image.methodStart + 1;
    if (rowId <= 0 || rowId > tokenRowIdMask) invalid("ordinary MethodDef token row id is outside the 24-bit range");
    return methodTokenType | static_cast<uint32_t>(rowId);
}

size_t recordStride(const MetadataSectionModel& section, size_t expected, const char* name) {
    if (section.count == 0) {
        if (section.sectionSize != 0) invalid(std::string(name) + " has bytes but zero records");
        return 0;
    }
    if (section.sectionSize % section.count != 0 ||
        static_cast<size_t>(section.sectionSize / section.count) != expected) {
        invalid(std::string(name) + " has an unexpected record stride");
    }
    return expected;
}

size_t indexWidth(int32_t count) {
    if (count < 0) invalid("negative table count used for index width");
    if (count <= 255) return 1;
    if (count <= 65535) return 2;
    return 4;
}

int32_t readIndex(const uint8_t* data, size_t offset, size_t width) {
    if (width == 1) return data[offset] == 0xff ? -1 : data[offset];
    if (width == 2) {
        const uint16_t value = static_cast<uint16_t>(data[offset]) |
            static_cast<uint16_t>(static_cast<uint16_t>(data[offset + 1]) << 8);
        return value == 0xffff ? -1 : value;
    }
    if (width == 4) return readI32(data, offset);
    invalid("unsupported index width");
}

uint16_t readU16(const uint8_t* data, size_t offset) {
    return static_cast<uint16_t>(data[offset]) |
        static_cast<uint16_t>(static_cast<uint16_t>(data[offset + 1]) << 8);
}

std::string metadataString(const uint8_t* data, const MetadataSectionModel& section, uint32_t index) {
    if (index >= static_cast<uint32_t>(section.sectionSize)) invalid("string index is outside string table");
    const size_t start = static_cast<size_t>(section.offset) + index;
    const size_t remaining = static_cast<size_t>(section.sectionSize) - index;
    const auto* begin = reinterpret_cast<const char*>(data + start);
    const void* end = std::memchr(begin, 0, remaining);
    if (end == nullptr) invalid("unterminated metadata string");
    return std::string(begin, static_cast<const char*>(end));
}

void checkedRange(int32_t start, uint64_t count, size_t available, const char* name) {
    if (count == 0 && start == -1) return;
    if (start < 0 || static_cast<uint64_t>(start) > available ||
        count > available - static_cast<size_t>(start)) {
        invalid(std::string(name) + " is outside its table");
    }
}

std::string typeName(int32_t index) {
    return index < 0 ? std::string{} : "type[" + std::to_string(index) + "]";
}

} // namespace

bool Version110::supports(double version) noexcept { return version == 110.0; }
bool Version110::supports(int32_t rawVersion) noexcept { return rawVersion == 110; }

Version110Header Version110::readHeader(const std::vector<uint8_t>& data) {
    return readHeader(data.data(), data.size());
}

Version110Header Version110::readHeader(const uint8_t* data, size_t size) {
    if (data == nullptr || size < Version110Header::serializedSize) invalid("truncated metadata header");
    if (readU32(data, 0) != 0xFAB11BAFU) invalid("incorrect metadata sanity value");
    if (!supports(readI32(data, 4))) invalid("unsupported metadata version");

    Version110Header header;
    header.version = 110;
    for (size_t i = 0; i < sectionOrder.size(); ++i) {
        const size_t offset = 8 + i * 12;
        auto& section = header.sections.*sectionOrder[i];
        section = {readI32(data, offset), readI32(data, offset + 4), readI32(data, offset + 8)};
        if (section.offset < 0 || section.sectionSize < 0 || section.count < 0) {
            invalid("negative metadata section field");
        }
        const size_t start = static_cast<size_t>(section.offset);
        if (start > size || static_cast<size_t>(section.sectionSize) > size - start) {
            invalid("metadata section is outside the file");
        }
    }
    header.typeDefinitionIndexWidth = indexWidth(header.sections.typeDefinitions.count);
    header.methodDefinitionIndexWidth = indexWidth(header.sections.methods.count);
    const size_t offsetStride = recordStride(header.sections.interfaceOffsets,
        header.sections.interfaceOffsets.count == 0 ? 0 :
            static_cast<size_t>(header.sections.interfaceOffsets.sectionSize /
                header.sections.interfaceOffsets.count), "interface offsets");
    if (offsetStride != 0) {
        if (offsetStride <= 4) invalid("interface offset record is too short");
        header.typeIndexWidth = offsetStride - 4;
        if (header.typeIndexWidth != 1 && header.typeIndexWidth != 2 && header.typeIndexWidth != 4) {
            invalid("unsupported TypeIndex width");
        }
    }
    return header;
}

MetadataModel Version110::read(const std::vector<uint8_t>& data) const {
    return read(data.data(), data.size());
}

MetadataModel Version110::read(const uint8_t* data, size_t size) const {
    const Version110Header header = readHeader(data, size);
    const auto& s = header.sections;
    const size_t typeWidth = header.typeIndexWidth;
    const size_t typeDefWidth = header.typeDefinitionIndexWidth;
    const size_t methodWidth = header.methodDefinitionIndexWidth;
    const size_t parameterWidth = indexWidth(s.parameters.count);
    const size_t genericWidth = indexWidth(s.genericContainers.count);
    const size_t fieldWidth = indexWidth(s.fields.count);
    if ((s.methods.count != 0 || s.typeDefinitions.count != 0 || s.parameters.count != 0 ||
         s.fields.count != 0) && typeWidth == 0) {
        invalid("cannot determine TypeIndex width");
    }
    recordStride(s.methods, 16 + typeDefWidth + typeWidth + parameterWidth + genericWidth, "methods");
    recordStride(s.parameters, 8 + typeWidth, "parameters");
    recordStride(s.fields, 4 + typeWidth, "fields");
    recordStride(s.typeDefinitions, 36 + 3 * typeWidth + genericWidth + fieldWidth +
        methodWidth + 5 * typeDefWidth, "type definitions");
    recordStride(s.images, 56 + 3 * typeDefWidth + 2 * methodWidth, "images");
    recordStride(s.generatedMethodTypeInfos, generatedMethodTypeInfoSize, "generated method type info");
    recordStride(s.generatedMethodTokens, generatedMethodTokenSize, "generated method tokens");

    MetadataModel metadata;
    metadata.version = 110;
    metadata.versionInfo.rawVersion = 110;
    metadata.versionInfo.preciseVersion = 110;
    metadata.versionInfo.registrationVersion = 110;
    metadata.versionInfo.confidence = MetadataVersionConfidence::RawHeader;
    metadata.versionInfo.provenance = "global-metadata header";
    metadata.sections = s;

    struct MethodDefinition {
        uint32_t name = 0;
        int32_t declaringType = -1;
        int32_t returnType = -1;
        uint32_t returnParameterToken = 0;
        int32_t parameterStart = -1;
        int32_t genericContainer = -1;
        uint16_t flags = 0;
        uint16_t iflags = 0;
        uint16_t slot = 0;
        uint16_t parameterCount = 0;
    };
    std::vector<MethodDefinition> methods;
    methods.reserve(static_cast<size_t>(s.methods.count));
    const size_t methodStride = s.methods.count == 0 ? 0 :
        static_cast<size_t>(s.methods.sectionSize / s.methods.count);
    for (int32_t i = 0; i < s.methods.count; ++i) {
        size_t p = static_cast<size_t>(s.methods.offset) + static_cast<size_t>(i) * methodStride;
        MethodDefinition method;
        method.name = readU32(data, p); p += 4;
        method.declaringType = readIndex(data, p, typeDefWidth); p += typeDefWidth;
        method.returnType = readIndex(data, p, typeWidth); p += typeWidth;
        method.returnParameterToken = readU32(data, p); p += 4;
        method.parameterStart = readIndex(data, p, parameterWidth); p += parameterWidth;
        method.genericContainer = readIndex(data, p, genericWidth); p += genericWidth;
        method.flags = readU16(data, p); p += 2;
        method.iflags = readU16(data, p); p += 2;
        method.slot = readU16(data, p); p += 2;
        method.parameterCount = readU16(data, p);
        if (method.returnType < 0) invalid("method has invalid return TypeIndex");
        checkedRange(method.parameterStart, method.parameterCount,
            static_cast<size_t>(s.parameters.count), "method parameter range");
        methods.push_back(method);
    }

    struct TypeDefinition {
        uint32_t name = 0;
        uint32_t nameSpace = 0;
        int32_t declaringType = -1;
        int32_t parent = -1;
        int32_t fieldStart = -1;
        int32_t methodStart = -1;
        uint16_t methodCount = 0;
        uint16_t fieldCount = 0;
        uint32_t flags = 0;
        uint32_t bitfield = 0;
    };
    std::vector<TypeDefinition> definitions;
    definitions.reserve(static_cast<size_t>(s.typeDefinitions.count));
    const size_t typeStride = s.typeDefinitions.count == 0 ? 0 :
        static_cast<size_t>(s.typeDefinitions.sectionSize / s.typeDefinitions.count);
    for (int32_t i = 0; i < s.typeDefinitions.count; ++i) {
        size_t p = static_cast<size_t>(s.typeDefinitions.offset) + static_cast<size_t>(i) * typeStride;
        TypeDefinition definition;
        definition.name = readU32(data, p); p += 4;
        definition.nameSpace = readU32(data, p); p += 4;
        p += typeWidth;
        definition.declaringType = readIndex(data, p, typeWidth); p += typeWidth;
        definition.parent = readIndex(data, p, typeWidth); p += typeWidth;
        p += genericWidth;
        definition.flags = readU32(data, p); p += 4;
        definition.fieldStart = readIndex(data, p, fieldWidth); p += fieldWidth;
        definition.methodStart = readIndex(data, p, methodWidth); p += methodWidth;
        p += 4 * typeDefWidth + 4 + typeDefWidth;
        definition.methodCount = readU16(data, p); p += 4;
        definition.fieldCount = readU16(data, p); p += 12;
        definition.bitfield = readU32(data, p);
        checkedRange(definition.fieldStart, definition.fieldCount,
            static_cast<size_t>(s.fields.count), "type field range");
        definitions.push_back(definition);
        TypeModel type;
        type.name = metadataString(data, s.strings, definition.name);
        type.nameSpace = metadataString(data, s.strings, definition.nameSpace);
        type.baseType = typeName(definition.parent);
        type.declaringTypeIndex = definition.declaringType;
        type.flags = definition.flags;
        type.bitfield = definition.bitfield;
        metadata.types.push_back(std::move(type));
    }

    const size_t imageStride = s.images.count == 0 ? 0 :
        static_cast<size_t>(s.images.sectionSize / s.images.count);
    for (int32_t i = 0; i < s.images.count; ++i) {
        size_t p = static_cast<size_t>(s.images.offset) + static_cast<size_t>(i) * imageStride;
        ImageModel image;
        image.name = metadataString(data, s.strings, readU32(data, p)); p += 4;
        image.assemblyIndex = readI32(data, p); p += 4;
        image.typeStart = readIndex(data, p, typeDefWidth); p += typeDefWidth;
        image.typeCount = readU32(data, p); p += 4;
        image.exportedTypeStart = readIndex(data, p, typeDefWidth); p += typeDefWidth;
        image.exportedTypeCount = readU32(data, p); p += 4;
        image.entryPointIndex = readIndex(data, p, methodWidth); p += methodWidth;
        image.token = readU32(data, p); p += 4;
        image.customAttributeStart = readI32(data, p); p += 4;
        image.customAttributeCount = readU32(data, p); p += 4;
        image.invokerIndicesStart = readI32(data, p); p += 4;
        image.rgctxRangesStart = readI32(data, p); p += 4;
        image.rgctxRangesCount = readI32(data, p); p += 4;
        image.staticConstructorStart = readIndex(data, p, typeDefWidth); p += typeDefWidth;
        image.staticConstructorCount = readI32(data, p); p += 4;
        image.fieldStart = readI32(data, p); p += 4;
        image.propertyStart = readI32(data, p); p += 4;
        image.eventStart = readI32(data, p); p += 4;
        image.methodStart = readIndex(data, p, methodWidth);
        checkedRange(image.typeStart, image.typeCount, metadata.types.size(), "image type range");
        metadata.images.push_back(std::move(image));
    }

    readGeneratedMethodTables(data, size, methods.size(), metadata);
    for (size_t typeIndex = 0; typeIndex < definitions.size(); ++typeIndex) {
        const auto& definition = definitions[typeIndex];
        auto& output = metadata.types[typeIndex];
        const auto range = methodRange(metadata, static_cast<int32_t>(typeIndex),
            definition.methodStart, definition.methodCount);
        for (uint32_t offset = 0; offset < definition.methodCount; ++offset) {
            const int32_t index = methodIndex(metadata, static_cast<int32_t>(typeIndex),
                range.ordinaryStart, definition.methodCount, offset);
            if (index < 0 || static_cast<size_t>(index) >= methods.size()) {
                invalid("type method index is outside method table");
            }
            const auto& source = methods[static_cast<size_t>(index)];
            if (source.declaringType != static_cast<int32_t>(typeIndex)) {
                invalid("method declaring type does not match its range");
            }
            MethodModel method;
            method.definitionIndex = index;
            method.name = metadataString(data, s.strings, source.name);
            method.declaringType = output.nameSpace.empty() ? output.name :
                output.nameSpace + "." + output.name;
            method.returnType = typeName(source.returnType);
            method.returnParameterToken = source.returnParameterToken;
            method.isStatic = (source.flags & 0x10U) != 0;
            method.flags = source.flags;
            method.iflags = source.iflags;
            method.slot = source.slot;
            method.genericContainerIndex = source.genericContainer;
            const size_t parameterStride = 8 + typeWidth;
            for (uint16_t parameter = 0; parameter < source.parameterCount; ++parameter) {
                const size_t parameterOffset = static_cast<size_t>(s.parameters.offset) +
                    (static_cast<size_t>(source.parameterStart) + parameter) * parameterStride;
                ParameterModel item;
                item.name = metadataString(data, s.strings, readU32(data, parameterOffset));
                const int32_t type = readIndex(data, parameterOffset + 8, typeWidth);
                if (type < 0) invalid("parameter has invalid TypeIndex");
                item.type = typeName(type);
                method.parameters.push_back(std::move(item));
            }
            output.methods.push_back(std::move(method));
        }
        const size_t fieldStride = 4 + typeWidth;
        for (uint16_t field = 0; field < definition.fieldCount; ++field) {
            const size_t fieldIndex = static_cast<size_t>(definition.fieldStart) + field;
            const size_t fieldOffset = static_cast<size_t>(s.fields.offset) + fieldIndex * fieldStride;
            FieldModel item;
            item.name = metadataString(data, s.strings, readU32(data, fieldOffset));
            const int32_t type = readIndex(data, fieldOffset + 4, typeWidth);
            if (type < 0) invalid("field has invalid TypeIndex");
            item.type = typeName(type);
            output.fields.push_back(std::move(item));
        }
    }
    for (const auto& image : metadata.images) {
        for (uint32_t offset = 0; offset < image.typeCount; ++offset) {
            const size_t typeIndex = static_cast<size_t>(image.typeStart) + offset;
            auto& type = metadata.types[typeIndex];
            type.imageName = image.name;
            const uint64_t typeRow = static_cast<uint64_t>(offset) + 1;
            if (typeRow > tokenRowIdMask) invalid("type token row id exceeds 24 bits");
            type.token = 0x02000000U | static_cast<uint32_t>(typeRow);
            for (auto& method : type.methods) method.imageName = image.name;
            if (!type.fields.empty()) {
                if (image.fieldStart < 0 || definitions[typeIndex].fieldStart < image.fieldStart) {
                    invalid("field has no valid image-relative token row");
                }
                for (size_t field = 0; field < type.fields.size(); ++field) {
                    const uint64_t row = static_cast<uint64_t>(definitions[typeIndex].fieldStart -
                        image.fieldStart) + field + 1;
                    if (row > tokenRowIdMask) invalid("field token row id exceeds 24 bits");
                    type.fields[field].token = 0x04000000U | static_cast<uint32_t>(row);
                }
            }
        }
    }
    reconstructMethodTokens(metadata, methods.size());
    return metadata;
}

MetadataModel Version110::readFile(const std::string& path) const {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open global metadata file: " + path);
    const auto end = stream.tellg();
    if (end < 0 || static_cast<uint64_t>(end) > std::numeric_limits<size_t>::max() ||
        static_cast<uint64_t>(end) > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        invalid("metadata file size is invalid");
    }
    std::vector<uint8_t> data(static_cast<size_t>(end));
    stream.seekg(0);
    if (!data.empty()) stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!stream) invalid("could not read metadata file");
    return read(data);
}

bool Version110::hasGeneratedMethods(uint32_t bitfield) noexcept {
    return (bitfield & HasGeneratedMethods) != 0;
}

bool Version110::hasGeneratedMethods(const TypeModel& type) noexcept {
    return hasGeneratedMethods(type.bitfield);
}

int32_t Version110::generatedMethodsStart(size_t methodDefinitionCount, size_t generatedMethodTokenCount) {
    if (methodDefinitionCount > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
        invalid("method definition count exceeds the signed index range");
    }
    if (generatedMethodTokenCount > methodDefinitionCount) {
        invalid("generated token count exceeds the method definition count");
    }
    return static_cast<int32_t>(methodDefinitionCount - generatedMethodTokenCount);
}

void Version110::readGeneratedMethodTables(
    const uint8_t* data,
    size_t size,
    size_t methodDefinitionCount,
    MetadataModel& metadata) {
    const auto infoLocation = tableLocation(
        metadata.sections.generatedMethodTypeInfos,
        generatedMethodTypeInfoSize,
        data,
        size,
        "generatedMethodTypeInfos");
    const auto tokenLocation = tableLocation(
        metadata.sections.generatedMethodTokens,
        generatedMethodTokenSize,
        data,
        size,
        "generatedMethodTokens");

    const int32_t start = generatedMethodsStart(methodDefinitionCount, tokenLocation.count);
    std::vector<GeneratedMethodTypeInfoModel> typeInfos;
    typeInfos.reserve(infoLocation.count);
    for (size_t index = 0; index < infoLocation.count; ++index) {
        const size_t offset = infoLocation.offset + index * generatedMethodTypeInfoSize;
        typeInfos.push_back({
            readI32(data, offset),
            readI32(data, offset + 4),
            readI32(data, offset + 8)
        });
    }

    std::vector<GeneratedMethodTokenModel> tokens;
    tokens.reserve(tokenLocation.count);
    for (size_t index = 0; index < tokenLocation.count; ++index) {
        tokens.push_back({readU32(data, tokenLocation.offset + index * generatedMethodTokenSize)});
    }

    validateTables(GeneratedView{metadata.types, typeInfos, tokens, start}, methodDefinitionCount, false);
    metadata.generatedMethodTypeInfos = std::move(typeInfos);
    metadata.generatedMethodTokens = std::move(tokens);
    metadata.generatedMethodsStart = start;
}

void Version110::readGeneratedMethodTables(
    const std::vector<uint8_t>& data,
    size_t methodDefinitionCount,
    MetadataModel& metadata) {
    readGeneratedMethodTables(data.data(), data.size(), methodDefinitionCount, metadata);
}

Version110MethodRange Version110::methodRange(
    const MetadataModel& metadata,
    int32_t typeDefinitionIndex,
    int32_t ordinaryMethodStart,
    uint32_t methodCount) {
    const auto generated = view(metadata);
    if (typeDefinitionIndex < 0 || static_cast<size_t>(typeDefinitionIndex) >= generated.types.size()) {
        invalid("type definition index is outside the type table");
    }
    const auto& type = generated.types[static_cast<size_t>(typeDefinitionIndex)];
    const bool hasGenerated = hasGeneratedMethods(type);
    const auto* info = findTypeInfo(generated, typeDefinitionIndex);

    if (!hasGenerated && info != nullptr && info->generatedMethodCount > 0) {
        invalid("generatedMethodTypeInfo contradicts HasGeneratedMethods");
    }
    if (hasGenerated && info == nullptr && methodCount != 0) {
        invalid("HasGeneratedMethods is set without generatedMethodTypeInfo");
    }

    const uint32_t generatedCount = hasGenerated && info != nullptr
        ? static_cast<uint32_t>(info->generatedMethodCount)
        : 0;
    if (generatedCount > methodCount) invalid("generated method count exceeds the type method count");
    const uint32_t ordinaryCount = methodCount - generatedCount;
    const size_t generatedMethodsBegin = static_cast<size_t>(generated.generatedMethodsStart);

    if (ordinaryCount != 0) {
        if (ordinaryMethodStart < 0) invalid("ordinary method range has a negative start");
        const uint64_t end = static_cast<uint64_t>(static_cast<uint32_t>(ordinaryMethodStart)) + ordinaryCount;
        if (end > generatedMethodsBegin) invalid("ordinary method range overlaps generated method definitions");
    }

    Version110MethodRange result;
    result.ordinaryStart = ordinaryMethodStart;
    result.ordinaryCount = ordinaryCount;
    if (generatedCount != 0) result.generatedStart = info->generatedMethodStart;
    result.generatedCount = generatedCount;
    return result;
}

int32_t Version110::methodIndex(
    const MetadataModel& metadata,
    int32_t typeDefinitionIndex,
    int32_t ordinaryMethodStart,
    uint32_t methodCount,
    uint32_t methodIndexInType) {
    if (methodIndexInType >= methodCount) invalid("method index in type is outside the type method range");
    const auto range = methodRange(metadata, typeDefinitionIndex, ordinaryMethodStart, methodCount);
    const bool ordinary = methodIndexInType < range.ordinaryCount;
    const int64_t index = ordinary
        ? static_cast<int64_t>(range.ordinaryStart) + methodIndexInType
        : static_cast<int64_t>(range.generatedStart) + (methodIndexInType - range.ordinaryCount);
    if (index < 0 || index > std::numeric_limits<int32_t>::max()) {
        invalid("method definition index exceeds the signed index range");
    }
    return static_cast<int32_t>(index);
}

uint32_t Version110::methodToken(
    const MetadataModel& metadata,
    const ImageModel& image,
    int32_t typeDefinitionIndex,
    int32_t methodDefinitionIndex) {
    const auto generated = view(metadata);
    if (methodDefinitionIndex < 0) invalid("method definition index is negative");
    if (typeDefinitionIndex < 0 || static_cast<size_t>(typeDefinitionIndex) >= generated.types.size()) {
        invalid("type definition index is outside the type table");
    }
    const auto& type = generated.types[static_cast<size_t>(typeDefinitionIndex)];
    const auto* info = findTypeInfo(generated, typeDefinitionIndex);
    const bool hasGenerated = hasGeneratedMethods(type);

    if (!hasGenerated && info != nullptr && info->generatedMethodCount > 0) {
        invalid("generatedMethodTypeInfo contradicts HasGeneratedMethods");
    }
    if (hasGenerated && info == nullptr) invalid("HasGeneratedMethods is set without generatedMethodTypeInfo");

    if (hasGenerated && info != nullptr) {
        const int64_t generatedEnd = static_cast<int64_t>(info->generatedMethodStart) + info->generatedMethodCount;
        if (methodDefinitionIndex >= info->generatedMethodStart && methodDefinitionIndex < generatedEnd) {
            const int64_t tokenIndex = static_cast<int64_t>(methodDefinitionIndex) - generated.generatedMethodsStart;
            if (tokenIndex < 0 || static_cast<uint64_t>(tokenIndex) >= generated.tokens.size()) {
                invalid("generated method token index is outside the token table");
            }
            const uint32_t token = generated.tokens[static_cast<size_t>(tokenIndex)].token;
            validateToken(token);
            return token;
        }
    }

    if (methodDefinitionIndex >= generated.generatedMethodsStart) {
        invalid("generated method definition has no owning generated method range");
    }
    return ordinaryMethodToken(image, methodDefinitionIndex);
}

void Version110::reconstructMethodTokens(MetadataModel& metadata, size_t methodDefinitionCount) {
    const int32_t expectedStart = generatedMethodsStart(methodDefinitionCount, metadata.generatedMethodTokens.size());
    if (metadata.generatedMethodsStart != expectedStart) {
        invalid("generatedMethodsStart is inconsistent with the method and token table counts");
    }
    validateTables(view(metadata), methodDefinitionCount, true);

    std::vector<bool> visitedTypes(metadata.types.size(), false);
    std::vector<bool> visitedDefinitions(methodDefinitionCount, false);
    std::vector<std::pair<MethodModel*, uint32_t>> reconstructed;
    reconstructed.reserve(methodDefinitionCount);

    for (const auto& image : metadata.images) {
        if (image.typeCount != 0 && image.typeStart < 0) invalid("image has a negative type start");
        if (image.typeStart < 0 || static_cast<size_t>(image.typeStart) > metadata.types.size() ||
            image.typeCount > metadata.types.size() - static_cast<size_t>(image.typeStart)) {
            invalid("image type range is outside the type table");
        }

        std::unordered_set<uint32_t> imageTokens;
        for (uint32_t typeOffset = 0; typeOffset < image.typeCount; ++typeOffset) {
            const int64_t typeIndex64 = static_cast<int64_t>(image.typeStart) + typeOffset;
            if (typeIndex64 > std::numeric_limits<int32_t>::max()) invalid("type index exceeds the signed index range");
            const auto typeIndex = static_cast<int32_t>(typeIndex64);
            auto& type = metadata.types[static_cast<size_t>(typeIndex)];
            if (visitedTypes[static_cast<size_t>(typeIndex)]) invalid("type belongs to multiple image ranges");
            visitedTypes[static_cast<size_t>(typeIndex)] = true;

            if (type.methods.size() > std::numeric_limits<uint32_t>::max()) {
                invalid("type method count exceeds the unsigned 32-bit range");
            }
            const auto methodCount = static_cast<uint32_t>(type.methods.size());
            const auto* info = findTypeInfo(view(metadata), typeIndex);
            const uint32_t generatedCount = hasGeneratedMethods(type) && info != nullptr
                ? static_cast<uint32_t>(info->generatedMethodCount)
                : 0;
            if (generatedCount > methodCount) invalid("generated method count exceeds the type method count");
            const uint32_t ordinaryCount = methodCount - generatedCount;

            int32_t ordinaryStart = -1;
            if (ordinaryCount != 0) {
                ordinaryStart = type.methods.front().definitionIndex;
                if (ordinaryStart < 0) invalid("ordinary method has no definition index");
            }
            const auto range = methodRange(metadata, typeIndex, ordinaryStart, methodCount);

            for (uint32_t methodOffset = 0; methodOffset < methodCount; ++methodOffset) {
                auto& method = type.methods[methodOffset];
                const int32_t definitionIndex = methodIndex(
                    metadata,
                    typeIndex,
                    range.ordinaryStart,
                    methodCount,
                    methodOffset);
                if (method.definitionIndex != definitionIndex) {
                    invalid("method definition index does not match its ordinary/generated range");
                }
                if (static_cast<size_t>(definitionIndex) >= methodDefinitionCount) {
                    invalid("method definition index is outside the method definition table");
                }
                if (visitedDefinitions[static_cast<size_t>(definitionIndex)]) {
                    invalid("method definition is referenced by multiple type methods");
                }

                const uint32_t token = methodToken(metadata, image, typeIndex, definitionIndex);
                if (!imageTokens.insert(token).second) invalid("duplicate MethodDef token in image");
                visitedDefinitions[static_cast<size_t>(definitionIndex)] = true;
                reconstructed.emplace_back(&method, token);
            }
        }
    }

    for (size_t typeIndex = 0; typeIndex < metadata.types.size(); ++typeIndex) {
        if (!visitedTypes[typeIndex] && !metadata.types[typeIndex].methods.empty()) {
            invalid("type with methods is not covered by an image type range");
        }
    }
    for (size_t definitionIndex = 0; definitionIndex < visitedDefinitions.size(); ++definitionIndex) {
        if (!visitedDefinitions[definitionIndex]) invalid("method definition is not covered by a type method range");
    }

    for (const auto& [method, token] : reconstructed) method->token = token;
}

std::optional<size_t> Version110::methodPointerIndex(uint32_t token, size_t methodPointerCount) noexcept {
    if (!validMethodToken(token)) return std::nullopt;
    const size_t index = static_cast<size_t>((token & tokenRowIdMask) - 1);
    if (index >= methodPointerCount) return std::nullopt;
    return index;
}

std::optional<uint64_t> Version110::methodPointer(
    const MetadataModel& metadata,
    const std::string& imageName,
    uint32_t token) {
    // A generated MethodDef token is metadata identity, not proof that its RID
    // addresses a slot in the image's native method pointer table. Require an
    // unambiguous ordinary definition in this image before using that table.
    if (!validMethodToken(token) || metadata.generatedMethodsStart < 0) return std::nullopt;
    const MethodModel* ordinaryMethod = nullptr;
    const ImageModel* owningImage = nullptr;
    for (const auto& candidate : metadata.images) {
        if (candidate.name != imageName) continue;
        if (owningImage != nullptr || candidate.typeStart < 0 ||
            static_cast<size_t>(candidate.typeStart) > metadata.types.size() ||
            candidate.typeCount > metadata.types.size() - static_cast<size_t>(candidate.typeStart)) {
            return std::nullopt;
        }
        owningImage = &candidate;
        for (size_t typeOffset = 0; typeOffset < candidate.typeCount; ++typeOffset) {
            const auto& type = metadata.types[static_cast<size_t>(candidate.typeStart) + typeOffset];
            for (const auto& method : type.methods) {
                if (method.token != token) continue;
                if (ordinaryMethod != nullptr || method.definitionIndex < 0 ||
                    method.definitionIndex >= metadata.generatedMethodsStart) {
                    return std::nullopt;
                }
                ordinaryMethod = &method;
            }
        }
    }
    if (owningImage == nullptr || ordinaryMethod == nullptr || owningImage->methodStart < 0) {
        return std::nullopt;
    }
    const int64_t rowId = static_cast<int64_t>(ordinaryMethod->definitionIndex) -
        owningImage->methodStart + 1;
    if (rowId <= 0 || rowId > tokenRowIdMask ||
        token != (methodTokenType | static_cast<uint32_t>(rowId))) {
        return std::nullopt;
    }
    const auto image = metadata.methodPointersByImage.find(imageName);
    if (image == metadata.methodPointersByImage.end()) return std::nullopt;
    const auto index = methodPointerIndex(token, image->second.size());
    if (!index) return std::nullopt;
    const uint64_t pointer = image->second[*index];
    if (pointer == 0) return std::nullopt;
    return pointer;
}

} // namespace il2cpprec
