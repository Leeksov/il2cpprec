#include <il2cpprec/versions/Version111.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
namespace {

using Member = MetadataSectionModel MetadataSectionsModel::*;
constexpr std::array<Member, Version111Header::sectionCount> sectionOrder = {
    &MetadataSectionsModel::stringLiterals, &MetadataSectionsModel::stringLiteralData,
    &MetadataSectionsModel::strings, &MetadataSectionsModel::events,
    &MetadataSectionsModel::properties, &MetadataSectionsModel::methodSignatures,
    &MetadataSectionsModel::methods, &MetadataSectionsModel::parameterDefaultValues,
    &MetadataSectionsModel::fieldDefaultValues, &MetadataSectionsModel::defaultValueData,
    &MetadataSectionsModel::fieldMarshaledSizes, &MetadataSectionsModel::parameters,
    &MetadataSectionsModel::fields, &MetadataSectionsModel::genericParameters,
    &MetadataSectionsModel::genericParameterConstraints, &MetadataSectionsModel::genericContainers,
    &MetadataSectionsModel::nestedTypes, &MetadataSectionsModel::interfaces,
    &MetadataSectionsModel::vtableMethods, &MetadataSectionsModel::interfaceOffsets,
    &MetadataSectionsModel::typeDefinitions, &MetadataSectionsModel::typeInlineArrays,
    &MetadataSectionsModel::images, &MetadataSectionsModel::assemblies,
    &MetadataSectionsModel::fieldRefs, &MetadataSectionsModel::referencedAssemblies,
    &MetadataSectionsModel::attributeData, &MetadataSectionsModel::attributeDataRanges,
    &MetadataSectionsModel::unresolvedIndirectCallParameterTypes,
    &MetadataSectionsModel::unresolvedIndirectCallParameterRanges,
    &MetadataSectionsModel::windowsRuntimeTypeNames, &MetadataSectionsModel::windowsRuntimeStrings,
    &MetadataSectionsModel::exportedTypeDefinitions,
    &MetadataSectionsModel::methodSpecsOnGenericType,
    &MetadataSectionsModel::genericMethodSpecsOnType, &MetadataSectionsModel::methodSpecs,
    &MetadataSectionsModel::genericMethodFunctionsDefinitions,
    &MetadataSectionsModel::genericMethodFunctionsDefinitionsWithAdjustor,
    &MetadataSectionsModel::invokerIndices, &MetadataSectionsModel::rgctxRanges,
    &MetadataSectionsModel::rgctxValues, &MetadataSectionsModel::staticConstructorTypeIndices,
    &MetadataSectionsModel::generatedMethodTypeInfos, &MetadataSectionsModel::generatedMethodTokens
};

[[noreturn]] void invalid(const std::string& reason) {
    throw std::runtime_error("Invalid IL2CPP 111 metadata: " + reason);
}

class Reader {
public:
    Reader(const uint8_t* data, size_t size) : data_(data), size_(size) {
        if (data == nullptr && size != 0) invalid("null data with nonzero size");
    }
    void require(size_t offset, size_t amount) const {
        if (offset > size_ || amount > size_ - offset) invalid("read outside metadata file");
    }
    uint8_t u8(size_t offset) const { require(offset, 1); return data_[offset]; }
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
    int32_t i32(size_t offset) const { return std::bit_cast<int32_t>(u32(offset)); }
    int32_t index(size_t offset, size_t width) const {
        if (width == 1) return u8(offset) == 0xff ? -1 : u8(offset);
        if (width == 2) return u16(offset) == 0xffff ? -1 : u16(offset);
        if (width == 4) return i32(offset);
        invalid("unsupported index width");
    }
    std::string string(const MetadataSectionModel& section, uint32_t index) const {
        if (index >= static_cast<uint32_t>(section.sectionSize)) invalid("string index outside table");
        const size_t start = static_cast<size_t>(section.offset) + index;
        const size_t remaining = static_cast<size_t>(section.sectionSize) - index;
        require(start, remaining);
        const char* begin = reinterpret_cast<const char*>(data_ + start);
        const void* end = std::memchr(begin, 0, remaining);
        if (end == nullptr) invalid("unterminated metadata string");
        return std::string(begin, static_cast<const char*>(end));
    }
private:
    const uint8_t* data_;
    size_t size_;
};

size_t stride(const MetadataSectionModel& section) {
    if (section.count == 0) {
        if (section.sectionSize != 0) invalid("nonempty table with zero records");
        return 0;
    }
    if (section.sectionSize % section.count != 0) invalid("table size is not divisible by count");
    return static_cast<size_t>(section.sectionSize / section.count);
}

void table(const MetadataSectionModel& section, size_t expected, const char* name) {
    const size_t actual = stride(section);
    if (actual != 0 && actual != expected) invalid(std::string(name) + " has an unexpected stride");
}

void range(int32_t start, uint64_t count, size_t available, const char* name) {
    if (count == 0 && start == -1) return;
    if (start < 0 || static_cast<uint64_t>(start) > available ||
        count > available - static_cast<size_t>(start)) {
        invalid(std::string(name) + " exceeds its table");
    }
}

struct MethodDefinition {
    uint32_t name;
    int32_t declaringType;
    int32_t parameterStart;
    int32_t genericContainer;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    int32_t signatureOffset;
};

struct TypeDefinition {
    uint32_t name;
    uint32_t nameSpace;
    int32_t declaringType;
    int32_t parent;
    int32_t fieldStart;
    int32_t methodStart;
    uint16_t methodCount;
    uint16_t fieldCount;
    uint32_t flags;
    uint32_t bitfield;
};

std::string typeName(int32_t index) {
    return index < 0 ? std::string{} : "type[" + std::to_string(index) + "]";
}

} // namespace

size_t Version111Header::recordStride(const MetadataSectionModel& section) const {
    return stride(section);
}

size_t Version111Header::indexWidth(int32_t count) {
    if (count < 0) invalid("negative index table count");
    if (count <= 255) return 1;
    if (count <= 65535) return 2;
    return 4;
}

bool Version111::supports(double version) noexcept { return version == 111.0; }
bool Version111::supports(int32_t rawVersion) noexcept { return rawVersion == 111; }

Version111Header Version111::readHeader(const std::vector<uint8_t>& data) {
    return readHeader(data.data(), data.size());
}

Version111Header Version111::readHeader(const uint8_t* data, size_t size) {
    const Reader reader(data, size);
    reader.require(0, Version111Header::serializedSize);
    if (reader.u32(0) != 0xFAB11BAFU) invalid("incorrect sanity value");
    if (!supports(reader.i32(4))) invalid("unsupported version");
    Version111Header header;
    header.version = 111;
    for (size_t i = 0; i < sectionOrder.size(); ++i) {
        const size_t offset = 8 + i * 12;
        auto& section = header.sections.*sectionOrder[i];
        section = {reader.i32(offset), reader.i32(offset + 4), reader.i32(offset + 8)};
        if (section.offset < 0 || section.sectionSize < 0 || section.count < 0) {
            invalid("negative section field");
        }
        reader.require(static_cast<size_t>(section.offset), static_cast<size_t>(section.sectionSize));
    }
    const auto& sections = header.sections;
    header.indices.methodDefinition = Version111Header::indexWidth(sections.methods.count);
    header.indices.typeDefinition = Version111Header::indexWidth(sections.typeDefinitions.count);
    header.indices.type = 0;
    const size_t interfaceStride = stride(sections.interfaceOffsets);
    if (interfaceStride != 0) {
        if (interfaceStride <= 4) invalid("interface offset record is too short");
        header.indices.type = interfaceStride - 4;
        if (header.indices.type != 1 && header.indices.type != 2 && header.indices.type != 4) {
            invalid("unsupported TypeIndex width");
        }
    }
    return header;
}

MetadataModel Version111::read(const std::vector<uint8_t>& data) const {
    return read(data.data(), data.size());
}

MetadataModel Version111::read(const uint8_t* data, size_t size) const {
    const Reader reader(data, size);
    const auto header = readHeader(data, size);
    const auto& s = header.sections;
    MetadataModel metadata;
    metadata.version = 111;
    metadata.versionInfo = {111, 111, 111, MetadataVersionConfidence::RawHeader, "global-metadata header"};
    metadata.sections = s;
    const size_t typeWidth = header.indices.type;
    const size_t typeDefWidth = header.indices.typeDefinition;
    const size_t methodWidth = header.indices.methodDefinition;
    const size_t parameterWidth = Version111Header::indexWidth(s.parameters.count);
    const size_t genericWidth = Version111Header::indexWidth(s.genericContainers.count);
    if (s.methods.count != 0 && typeWidth == 0) invalid("cannot determine TypeIndex width");

    table(s.parameters, 4, "parameters");
    table(s.methods, 14 + typeDefWidth + parameterWidth + genericWidth, "methods");
    table(s.typeDefinitions, 36 + 3 * typeWidth + genericWidth +
        Version111Header::indexWidth(s.fields.count) + methodWidth + 5 * typeDefWidth, "type definitions");
    table(s.generatedMethodTypeInfos, 12, "generated method type info");
    table(s.generatedMethodTokens, 4, "generated method tokens");

    std::vector<MethodDefinition> methods;
    methods.reserve(static_cast<size_t>(s.methods.count));
    const size_t methodStride = stride(s.methods);
    for (int32_t i = 0; i < s.methods.count; ++i) {
        size_t p = static_cast<size_t>(s.methods.offset) + static_cast<size_t>(i) * methodStride;
        MethodDefinition m{};
        m.name = reader.u32(p); p += 4;
        m.declaringType = reader.index(p, typeDefWidth); p += typeDefWidth;
        m.parameterStart = reader.index(p, parameterWidth); p += parameterWidth;
        m.genericContainer = reader.index(p, genericWidth); p += genericWidth;
        m.flags = reader.u16(p); p += 2;
        m.iflags = reader.u16(p); p += 2;
        m.slot = reader.u16(p); p += 2;
        m.signatureOffset = reader.i32(p);
        methods.push_back(m);
    }

    const size_t signaturesSize = static_cast<size_t>(s.methodSignatures.sectionSize);
    std::unordered_map<int32_t, size_t> signatures;
    std::vector<std::pair<size_t, size_t>> signatureRanges;
    for (const auto& method : methods) {
        if (method.signatureOffset < 0 ||
            static_cast<size_t>(method.signatureOffset) >= signaturesSize) {
            invalid("method signature offset is outside the signature blob");
        }
        if (signatures.contains(method.signatureOffset)) continue;
        size_t p = static_cast<size_t>(method.signatureOffset);
        const size_t begin = static_cast<size_t>(s.methodSignatures.offset);
        if (typeWidth > signaturesSize - p) invalid("truncated signature return TypeIndex");
        MethodSignatureModel sig;
        sig.signatureOffset = method.signatureOffset;
        sig.returnTypeIndex = reader.index(begin + p, typeWidth);
        if (sig.returnTypeIndex < 0) invalid("invalid signature return TypeIndex");
        p += typeWidth;
        if (p >= signaturesSize) invalid("truncated signature parameter count");
        const uint8_t count = reader.u8(begin + p++);
        if (count > (signaturesSize - p) / typeWidth) invalid("truncated signature parameters");
        sig.parameterTypeIndices.reserve(count);
        for (uint16_t j = 0; j < count; ++j, p += typeWidth) {
            const int32_t type = reader.index(begin + p, typeWidth);
            if (type < 0) invalid("invalid signature parameter TypeIndex");
            sig.parameterTypeIndices.push_back(type);
        }
        signatures.emplace(sig.signatureOffset, metadata.methodSignatures.size());
        signatureRanges.emplace_back(static_cast<size_t>(sig.signatureOffset), p);
        metadata.methodSignatures.push_back(std::move(sig));
    }
    std::sort(signatureRanges.begin(), signatureRanges.end());
    for (size_t i = 1; i < signatureRanges.size(); ++i) {
        if (signatureRanges[i - 1].second > signatureRanges[i].first) {
            invalid("method signatures overlap");
        }
    }

    std::vector<TypeDefinition> definitions;
    definitions.reserve(static_cast<size_t>(s.typeDefinitions.count));
    const size_t typeStride = stride(s.typeDefinitions);
    const size_t fieldWidth = Version111Header::indexWidth(s.fields.count);
    for (int32_t i = 0; i < s.typeDefinitions.count; ++i) {
        size_t p = static_cast<size_t>(s.typeDefinitions.offset) + static_cast<size_t>(i) * typeStride;
        TypeDefinition t{};
        t.name = reader.u32(p); p += 4;
        t.nameSpace = reader.u32(p); p += 4;
        p += typeWidth; // byval TypeIndex
        t.declaringType = reader.index(p, typeWidth); p += typeWidth;
        t.parent = reader.index(p, typeWidth); p += typeWidth;
        p += genericWidth;
        t.flags = reader.u32(p); p += 4;
        t.fieldStart = reader.index(p, fieldWidth); p += fieldWidth;
        t.methodStart = reader.index(p, methodWidth); p += methodWidth;
        p += 4 * typeDefWidth;
        p += 4; // element type index
        p += typeDefWidth;
        t.methodCount = reader.u16(p); p += 4;
        t.fieldCount = reader.u16(p); p += 12;
        t.bitfield = reader.u32(p);
        definitions.push_back(t);
        TypeModel type;
        type.name = reader.string(s.strings, t.name);
        type.nameSpace = reader.string(s.strings, t.nameSpace);
        type.baseType = typeName(t.parent);
        type.declaringTypeIndex = t.declaringType;
        type.flags = t.flags;
        type.bitfield = t.bitfield;
        metadata.types.push_back(std::move(type));
    }

    // v110 adds three 32-bit field/property/event starts and a compact method start.
    table(s.images, 56 + 3 * typeDefWidth + 2 * methodWidth, "images");
    const size_t actualImageStride = stride(s.images);
    for (int32_t i = 0; i < s.images.count; ++i) {
        size_t p = static_cast<size_t>(s.images.offset) + static_cast<size_t>(i) * actualImageStride;
        ImageModel image;
        image.name = reader.string(s.strings, reader.u32(p)); p += 4;
        image.assemblyIndex = reader.i32(p); p += 4;
        image.typeStart = reader.index(p, typeDefWidth); p += typeDefWidth;
        image.typeCount = reader.u32(p); p += 4;
        image.exportedTypeStart = reader.index(p, typeDefWidth); p += typeDefWidth;
        image.exportedTypeCount = reader.u32(p); p += 4;
        image.entryPointIndex = reader.index(p, methodWidth); p += methodWidth;
        image.token = reader.u32(p); p += 4;
        image.customAttributeStart = reader.i32(p); p += 4;
        image.customAttributeCount = reader.u32(p); p += 4;
        image.invokerIndicesStart = reader.i32(p); p += 4;
        image.rgctxRangesStart = reader.i32(p); p += 4;
        image.rgctxRangesCount = reader.i32(p); p += 4;
        image.staticConstructorStart = reader.index(p, typeDefWidth); p += typeDefWidth;
        image.staticConstructorCount = reader.i32(p); p += 4;
        image.fieldStart = reader.i32(p); p += 4;
        image.propertyStart = reader.i32(p); p += 4;
        image.eventStart = reader.i32(p); p += 4;
        image.methodStart = reader.index(p, methodWidth);
        range(image.typeStart, image.typeCount, metadata.types.size(), "image type");
        metadata.images.push_back(std::move(image));
    }

    Version110::readGeneratedMethodTables(data, size, methods.size(), metadata);
    for (size_t typeIndex = 0; typeIndex < definitions.size(); ++typeIndex) {
        const auto& definition = definitions[typeIndex];
        auto& output = metadata.types[typeIndex];
        const auto typeIndex32 = static_cast<int32_t>(typeIndex);
        const auto methodRange = Version110::methodRange(
            metadata, typeIndex32, definition.methodStart, definition.methodCount);
        for (uint32_t j = 0; j < definition.methodCount; ++j) {
            const int32_t methodIndex = Version110::methodIndex(
                metadata, typeIndex32, methodRange.ordinaryStart, definition.methodCount, j);
            if (methodIndex < 0 || static_cast<size_t>(methodIndex) >= methods.size()) {
                invalid("type method index outside method table");
            }
            const auto& source = methods[static_cast<size_t>(methodIndex)];
            if (source.declaringType != typeIndex32) invalid("method declaring type mismatch");
            const auto& signature = metadata.methodSignatures[signatures.at(source.signatureOffset)];
            range(source.parameterStart, signature.parameterTypeIndices.size(),
                  static_cast<size_t>(s.parameters.count), "method parameter");
            MethodModel method;
            method.definitionIndex = methodIndex;
            method.name = reader.string(s.strings, source.name);
            method.declaringType = output.nameSpace.empty() ? output.name : output.nameSpace + "." + output.name;
            method.returnType = typeName(signature.returnTypeIndex);
            method.signatureOffset = source.signatureOffset;
            method.isStatic = (source.flags & 0x10) != 0;
            method.flags = source.flags;
            method.iflags = source.iflags;
            method.slot = source.slot;
            method.genericContainerIndex = source.genericContainer;
            for (size_t k = 0; k < signature.parameterTypeIndices.size(); ++k) {
                const size_t parameter = static_cast<size_t>(source.parameterStart) + k;
                ParameterModel item;
                item.name = reader.string(s.strings,
                    reader.u32(static_cast<size_t>(s.parameters.offset) + parameter * 4));
                item.type = typeName(signature.parameterTypeIndices[k]);
                method.parameters.push_back(std::move(item));
            }
            output.methods.push_back(std::move(method));
        }
    }
    for (const auto& image : metadata.images) {
        for (uint32_t i = 0; i < image.typeCount; ++i) {
            auto& type = metadata.types[static_cast<size_t>(image.typeStart) + i];
            type.imageName = image.name;
            for (auto& method : type.methods) method.imageName = image.name;
        }
    }
    Version110::reconstructMethodTokens(metadata, methods.size());
    return metadata;
}

MetadataModel Version111::readFile(const std::string& path) const {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open global metadata file: " + path);
    const auto end = stream.tellg();
    if (end < 0 || static_cast<uint64_t>(end) > std::numeric_limits<size_t>::max() ||
        static_cast<uint64_t>(end) > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        invalid("file size is invalid");
    }
    std::vector<uint8_t> data(static_cast<size_t>(end));
    stream.seekg(0);
    if (!data.empty()) stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!stream) invalid("could not read metadata file");
    return read(data);
}

} // namespace il2cpprec
