#include <il2cpprec/versions/Version38.hpp>

#include <algorithm>
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

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid global metadata 38/39: " + message);
}

using SectionMember = MetadataSectionModel MetadataSectionsModel::*;

constexpr std::array<SectionMember, Version38Header::sectionCount> sectionOrder = {
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

constexpr std::array<const char*, Version38Header::sectionCount> sectionNames = {
    "string literals",
    "string literal data",
    "strings",
    "events",
    "properties",
    "methods",
    "parameter default values",
    "field default values",
    "default value data",
    "field marshaled sizes",
    "parameters",
    "fields",
    "generic parameters",
    "generic parameter constraints",
    "generic containers",
    "nested types",
    "interfaces",
    "vtable methods",
    "interface offsets",
    "type definitions",
    "images",
    "assemblies",
    "field refs",
    "referenced assemblies",
    "attribute data",
    "attribute data ranges",
    "unresolved indirect call parameter types",
    "unresolved indirect call parameter ranges",
    "Windows Runtime type names",
    "Windows Runtime strings",
    "exported type definitions",
};

class Reader {
public:
    Reader(const uint8_t* data, size_t size) : data_(data), size_(size) {
        if (data == nullptr && size != 0) invalid("null data with nonzero size");
    }

    size_t size() const { return size_; }

    uint8_t u8(size_t offset) const {
        require(offset, 1);
        return data_[offset];
    }

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

    int32_t index(size_t offset, size_t width) const {
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
            if (const int32_t value = i32(offset); value >= -1) return value;
            invalid("index has an invalid negative value");
        default:
            invalid("unsupported index width " + std::to_string(width));
        }
    }

    const uint8_t* bytes(size_t offset, size_t amount) const {
        require(offset, amount);
        return data_ + offset;
    }

    void require(size_t offset, size_t amount) const {
        if (offset > size_ || amount > size_ - offset) invalid("read past end of file");
    }

private:
    const uint8_t* data_;
    size_t size_;
};

class RecordReader {
public:
    RecordReader(const Reader& reader, size_t base, size_t stride)
        : reader_(reader), cursor_(base), end_(base + stride) {
        if (base > reader.size() || stride > reader.size() - base) {
            invalid("record is outside the file");
        }
    }

    uint8_t u8() {
        require(1);
        return reader_.u8(cursor_++);
    }

    uint16_t u16() {
        require(2);
        const uint16_t value = reader_.u16(cursor_);
        cursor_ += 2;
        return value;
    }

    uint32_t u32() {
        require(4);
        const uint32_t value = reader_.u32(cursor_);
        cursor_ += 4;
        return value;
    }

    int32_t i32() {
        return std::bit_cast<int32_t>(u32());
    }

    int16_t i16() {
        return std::bit_cast<int16_t>(u16());
    }

    int32_t index(size_t width) {
        require(width);
        const int32_t value = reader_.index(cursor_, width);
        cursor_ += width;
        return value;
    }

    void skip(size_t amount) {
        require(amount);
        cursor_ += amount;
    }

private:
    void require(size_t amount) const {
        if (cursor_ > end_ || amount > end_ - cursor_) invalid("field exceeds its record stride");
    }

    const Reader& reader_;
    size_t cursor_;
    size_t end_;
};

size_t checkedCount(const MetadataSectionModel& section, const char* name) {
    if (section.count < 0) invalid(std::string(name) + " has a negative count");
    return static_cast<size_t>(section.count);
}

size_t strideOf(const MetadataSectionModel& section, const char* name) {
    const size_t count = checkedCount(section, name);
    if (section.sectionSize < 0) invalid(std::string(name) + " has a negative size");
    const size_t size = static_cast<size_t>(section.sectionSize);
    if (count == 0) {
        if (size != 0) invalid(std::string(name) + " is empty but has a nonzero size");
        return 0;
    }
    if (size == 0 || size % count != 0) {
        invalid(std::string(name) + " size is not divisible by its count");
    }
    return size / count;
}

void validateSection(
    const Reader& reader,
    const MetadataSectionModel& section,
    const char* name) {
    strideOf(section, name);
    if (section.offset < 0) invalid(std::string(name) + " has a negative offset");
    const size_t offset = static_cast<size_t>(section.offset);
    const size_t size = static_cast<size_t>(section.sectionSize);
    if (offset > reader.size() || size > reader.size() - offset) {
        invalid(std::string(name) + " is outside the file");
    }
    if (size != 0 && offset < Version38Header::serializedSize) {
        invalid(std::string(name) + " overlaps the header");
    }
}

void validateBlob(const MetadataSectionModel& section, const char* name) {
    if (section.count != section.sectionSize) {
        invalid(std::string(name) + " byte count differs from its section size");
    }
}

void validateTable(
    const MetadataSectionModel& section,
    size_t expectedStride,
    const char* name) {
    if (section.count != 0 && strideOf(section, name) != expectedStride) {
        invalid(
            std::string(name) + " has record stride " + std::to_string(strideOf(section, name)) +
            ", expected " + std::to_string(expectedStride));
    }
}

size_t validateIndexTable(const MetadataSectionModel& section, const char* name) {
    const size_t stride = strideOf(section, name);
    if (section.count != 0 && stride != 1 && stride != 2 && stride != 4) {
        invalid(std::string(name) + " has an invalid index width");
    }
    return stride;
}

size_t typeIndexWidthFromSections(const Version38Header& header) {
    const auto& sections = header.sections;
    const bool hasWidthEvidence =
        sections.interfaceOffsets.count != 0 || sections.events.count != 0 ||
        sections.methods.count != 0 || sections.parameterDefaultValues.count != 0 ||
        sections.fieldDefaultValues.count != 0 || sections.fieldMarshaledSizes.count != 0 ||
        sections.parameters.count != 0 || sections.fields.count != 0 ||
        sections.typeDefinitions.count != 0 || sections.fieldRefs.count != 0;
    if (!hasWidthEvidence) return 4;
    const auto matches = [&](const MetadataSectionModel& section, size_t expected) {
        return section.count == 0 || strideOf(section, "type-index-dependent section") == expected;
    };
    size_t selected = 0;
    for (const size_t width : {size_t{1}, size_t{2}, size_t{4}}) {
        if (!matches(sections.interfaceOffsets, 4 + width) ||
            !matches(sections.events, 20 + width) ||
            !matches(sections.methods,
                20 + header.typeDefinitionIndexWidth + width +
                    header.parameterIndexWidth + header.genericContainerIndexWidth) ||
            !matches(sections.parameterDefaultValues, header.parameterIndexWidth + width + 4) ||
            !matches(sections.fieldDefaultValues, 8 + width) ||
            !matches(sections.fieldMarshaledSizes, 8 + width) ||
            !matches(sections.parameters, 8 + width) ||
            !matches(sections.fields, 8 + width) ||
            !matches(sections.typeDefinitions, 68 + 3 * width + header.genericContainerIndexWidth) ||
            !matches(sections.fieldRefs, 4 + width)) {
            continue;
        }
        if (selected != 0) invalid("ambiguous type index width");
        selected = width;
    }
    if (selected != 0) return selected;
    invalid("inconsistent type index widths across sections");
}

void validateLayouts(const Version38Header& header) {
    const auto& sections = header.sections;
    validateTable(sections.stringLiterals, 4, "string literals");
    validateBlob(sections.stringLiteralData, "string literal data");
    validateBlob(sections.strings, "strings");
    validateTable(sections.events, 20 + header.typeIndexWidth, "events");
    validateTable(sections.properties, 20, "properties");
    validateTable(
        sections.methods,
        20 + header.typeDefinitionIndexWidth + header.typeIndexWidth +
            header.parameterIndexWidth + header.genericContainerIndexWidth,
        "methods");
    validateTable(
        sections.parameterDefaultValues,
        header.parameterIndexWidth + header.typeIndexWidth + 4,
        "parameter default values");
    validateTable(sections.fieldDefaultValues, 8 + header.typeIndexWidth, "field default values");
    validateBlob(sections.defaultValueData, "default value data");
    validateTable(sections.fieldMarshaledSizes, 8 + header.typeIndexWidth, "field marshaled sizes");
    validateTable(sections.parameters, 8 + header.typeIndexWidth, "parameters");
    validateTable(sections.fields, 8 + header.typeIndexWidth, "fields");
    validateTable(
        sections.genericParameters,
        12 + header.genericContainerIndexWidth,
        "generic parameters");
    validateIndexTable(sections.genericParameterConstraints, "generic parameter constraints");
    validateTable(sections.genericContainers, 16, "generic containers");
    validateIndexTable(sections.nestedTypes, "nested types");
    validateIndexTable(sections.interfaces, "interfaces");
    validateTable(sections.vtableMethods, 4, "vtable methods");
    validateTable(sections.interfaceOffsets, 4 + header.typeIndexWidth, "interface offsets");
    validateTable(
        sections.typeDefinitions,
        68 + 3 * header.typeIndexWidth + header.genericContainerIndexWidth,
        "type definitions");
    validateTable(sections.images, 32 + 2 * header.typeDefinitionIndexWidth, "images");
    validateTable(sections.assemblies, 72, "assemblies");
    validateTable(sections.fieldRefs, 4 + header.typeIndexWidth, "field refs");
    validateTable(sections.referencedAssemblies, 4, "referenced assemblies");
    validateBlob(sections.attributeData, "attribute data");
    validateTable(sections.attributeDataRanges, 8, "attribute data ranges");
    validateIndexTable(
        sections.unresolvedIndirectCallParameterTypes,
        "unresolved indirect call parameter types");
    validateTable(sections.unresolvedIndirectCallParameterRanges, 8, "unresolved indirect call parameter ranges");
    validateTable(sections.windowsRuntimeTypeNames, 8, "Windows Runtime type names");
    validateBlob(sections.windowsRuntimeStrings, "Windows Runtime strings");
    validateIndexTable(sections.exportedTypeDefinitions, "exported type definitions");
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

template<typename T, typename Parse>
std::vector<T> readTable(
    const MetadataSectionModel& section,
    const char* name,
    Parse parse) {
    const size_t count = checkedCount(section, name);
    const size_t stride = strideOf(section, name);
    std::vector<T> result;
    result.reserve(count);
    const size_t base = static_cast<size_t>(section.offset);
    for (size_t index = 0; index < count; ++index) {
        result.push_back(parse(base + index * stride, stride));
    }
    return result;
}

std::vector<int32_t> readIndices(
    const Reader& reader,
    const MetadataSectionModel& section,
    const char* name) {
    return readTable<int32_t>(section, name, [&](size_t base, size_t stride) {
        return reader.index(base, stride);
    });
}

std::optional<std::string> readString(
    const Reader& reader,
    const MetadataSectionModel& strings,
    uint32_t index) {
    if (index == std::numeric_limits<uint32_t>::max()) return std::nullopt;
    const size_t stringSize = static_cast<size_t>(strings.sectionSize);
    if (index >= stringSize) invalid("string index is outside the strings section");
    const size_t start = static_cast<size_t>(strings.offset) + index;
    const size_t remaining = stringSize - index;
    const auto* bytes = reinterpret_cast<const char*>(reader.bytes(start, remaining));
    const void* terminator = std::memchr(bytes, 0, remaining);
    if (terminator == nullptr) invalid("unterminated string in the strings section");
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

void validateRange(int32_t start, uint64_t count, size_t size, const char* name) {
    if (count == 0 && start == -1) return;
    if (start < 0 || static_cast<uint64_t>(static_cast<uint32_t>(start)) > size ||
        count > size - static_cast<size_t>(static_cast<uint32_t>(start))) {
        invalid(std::string(name) + " range is outside its table");
    }
}

TypeDefinition parseType(
    const Reader& reader,
    size_t base,
    size_t stride,
    const Version38Header& header) {
    RecordReader record(reader, base, stride);
    TypeDefinition type;
    type.nameIndex = record.u32();
    type.namespaceIndex = record.u32();
    record.index(header.typeIndexWidth);
    type.declaringTypeIndex = record.index(header.typeIndexWidth);
    type.parentIndex = record.index(header.typeIndexWidth);
    type.genericContainerIndex = record.index(header.genericContainerIndexWidth);
    type.flags = record.u32();
    type.fieldStart = record.i32();
    type.methodStart = record.i32();
    record.skip(6 * 4);
    const uint16_t methodCount = record.u16();
    record.u16();
    const uint16_t fieldCount = record.u16();
    record.skip(5 * 2);
    type.methodCount = methodCount;
    type.fieldCount = fieldCount;
    type.bitfield = record.u32();
    type.token = record.u32();
    return type;
}

MethodDefinition parseMethod(
    const Reader& reader,
    size_t base,
    size_t stride,
    const Version38Header& header) {
    RecordReader record(reader, base, stride);
    MethodDefinition method;
    method.nameIndex = record.u32();
    method.declaringType = record.index(header.typeDefinitionIndexWidth);
    method.returnType = record.index(header.typeIndexWidth);
    method.returnParameterToken = record.u32();
    method.parameterStart = record.index(header.parameterIndexWidth);
    method.genericContainerIndex = record.index(header.genericContainerIndexWidth);
    method.token = record.u32();
    method.flags = record.u16();
    method.iflags = record.u16();
    method.slot = record.u16();
    method.parameterCount = record.u16();
    return method;
}

ParameterDefinition parseParameter(
    const Reader& reader,
    size_t base,
    size_t stride,
    const Version38Header& header) {
    RecordReader record(reader, base, stride);
    ParameterDefinition parameter;
    parameter.nameIndex = record.u32();
    record.u32();
    parameter.typeIndex = record.index(header.typeIndexWidth);
    return parameter;
}

FieldDefinition parseField(
    const Reader& reader,
    size_t base,
    size_t stride,
    const Version38Header& header) {
    RecordReader record(reader, base, stride);
    FieldDefinition field;
    field.nameIndex = record.u32();
    field.typeIndex = record.index(header.typeIndexWidth);
    field.token = record.u32();
    return field;
}

ImageModel parseImage(
    const Reader& reader,
    size_t base,
    size_t stride,
    const Version38Header& header) {
    RecordReader record(reader, base, stride);
    ImageModel image;
    const uint32_t nameIndex = record.u32();
    image.assemblyIndex = record.i32();
    image.typeStart = record.index(header.typeDefinitionIndexWidth);
    image.typeCount = record.u32();
    image.exportedTypeStart = record.index(header.typeDefinitionIndexWidth);
    image.exportedTypeCount = record.u32();
    image.entryPointIndex = record.i32();
    image.token = record.u32();
    image.customAttributeStart = record.i32();
    image.customAttributeCount = record.u32();
    image.name = readString(reader, header.sections.strings, nameIndex).value_or("");
    return image;
}

AssemblyModel parseAssembly(const Reader& reader, size_t base, size_t stride) {
    RecordReader record(reader, base, stride);
    AssemblyModel assembly;
    assembly.imageIndex = record.i32();
    assembly.token = record.u32();
    record.u32();
    assembly.referencedAssemblyStart = record.i32();
    assembly.referencedAssemblyCount = record.i32();
    record.skip(48);
    assembly.moduleToken = record.u32();
    return assembly;
}

} // namespace

size_t Version38Header::recordStride(const MetadataSectionModel& section) const {
    return strideOf(section, "section");
}

size_t Version38Header::indexWidth(int32_t count) {
    if (count < 0) invalid("negative section count");
    if (count < std::numeric_limits<uint8_t>::max()) return 1;
    if (count < std::numeric_limits<uint16_t>::max()) return 2;
    return 4;
}

Version38Header Version38::readHeader(const std::vector<uint8_t>& data) const {
    return readHeader(data.data(), data.size());
}

Version38Header Version38::readHeader(const uint8_t* data, size_t size) const {
    const Reader reader(data, size);
    reader.require(0, Version38Header::serializedSize);
    if (reader.u32(0) != sanityValue) invalid("incorrect sanity value");
    const int32_t version = reader.i32(4);
    if (version != 38 && version != 39) {
        throw std::runtime_error("Unsupported global metadata version for Version38: " + std::to_string(version));
    }

    Version38Header header;
    header.version = version;
    size_t cursor = 8;
    for (size_t index = 0; index < sectionOrder.size(); ++index) {
        MetadataSectionModel section{reader.i32(cursor), reader.i32(cursor + 4), reader.i32(cursor + 8)};
        header.sections.*(sectionOrder[index]) = section;
        validateSection(reader, section, sectionNames[index]);
        cursor += 12;
    }

    header.typeDefinitionIndexWidth = Version38Header::indexWidth(header.sections.typeDefinitions.count);
    header.genericContainerIndexWidth = Version38Header::indexWidth(header.sections.genericContainers.count);
    header.parameterIndexWidth = version >= 39
        ? Version38Header::indexWidth(header.sections.parameters.count)
        : 4;

    header.typeIndexWidth = typeIndexWidthFromSections(header);

    validateLayouts(header);
    return header;
}

MetadataModel Version38::read(const std::vector<uint8_t>& data) const {
    return read(data.data(), data.size());
}

MetadataModel Version38::read(const uint8_t* data, size_t size) const {
    const Version38Header header = readHeader(data, size);
    const Reader reader(data, size);
    const auto& sections = header.sections;

    auto types = readTable<TypeDefinition>(sections.typeDefinitions, "type definitions",
        [&](size_t base, size_t stride) { return parseType(reader, base, stride, header); });
    auto methods = readTable<MethodDefinition>(sections.methods, "methods",
        [&](size_t base, size_t stride) { return parseMethod(reader, base, stride, header); });
    auto parameters = readTable<ParameterDefinition>(sections.parameters, "parameters",
        [&](size_t base, size_t stride) { return parseParameter(reader, base, stride, header); });
    auto fields = readTable<FieldDefinition>(sections.fields, "fields",
        [&](size_t base, size_t stride) { return parseField(reader, base, stride, header); });
    auto images = readTable<ImageModel>(sections.images, "images",
        [&](size_t base, size_t stride) { return parseImage(reader, base, stride, header); });
    auto assemblies = readTable<AssemblyModel>(sections.assemblies, "assemblies",
        [&](size_t base, size_t stride) { return parseAssembly(reader, base, stride); });

    MetadataModel model;
    model.version = header.version;
    model.versionInfo = {
        header.version,
        static_cast<double>(header.version),
        0,
        MetadataVersionConfidence::RawHeader,
        "global metadata header",
    };
    model.sections = sections;
    model.images = images;
    model.assemblies = std::move(assemblies);

    model.genericParameters = readTable<GenericParameterModel>(sections.genericParameters, "generic parameters",
        [&](size_t base, size_t stride) {
            RecordReader record(reader, base, stride);
            GenericParameterModel parameter;
            parameter.ownerIndex = record.index(header.genericContainerIndexWidth);
            parameter.name = readString(reader, sections.strings, record.u32()).value_or("");
            parameter.constraintsStart = record.i16();
            parameter.constraintsCount = record.i16();
            parameter.num = record.u16();
            parameter.flags = record.u16();
            return parameter;
        });
    model.genericContainers = readTable<GenericContainerModel>(sections.genericContainers, "generic containers",
        [&](size_t base, size_t stride) {
            RecordReader record(reader, base, stride);
            GenericContainerModel container;
            container.ownerIndex = record.i32();
            container.typeArgumentCount = record.i32();
            container.isMethod = record.i32();
            container.genericParameterStart = record.i32();
            return container;
        });
    for (const auto& parameter : model.genericParameters) {
        if (parameter.ownerIndex < 0 ||
            static_cast<size_t>(parameter.ownerIndex) >= model.genericContainers.size()) {
            invalid("generic parameter references an invalid container");
        }
        if (parameter.constraintsCount < 0) invalid("generic parameter has a negative constraint count");
        validateRange(
            parameter.constraintsStart,
            static_cast<uint16_t>(parameter.constraintsCount),
            static_cast<size_t>(sections.genericParameterConstraints.count),
            "generic parameter constraint");
    }
    for (const auto& container : model.genericContainers) {
        if (container.typeArgumentCount < 0) invalid("generic container has a negative argument count");
        validateRange(
            container.genericParameterStart,
            static_cast<uint32_t>(container.typeArgumentCount),
            model.genericParameters.size(),
            "generic container parameter");
        if (container.isMethod != 0 && container.isMethod != 1) {
            invalid("generic container has an invalid method flag");
        }
        const size_t ownerCount = container.isMethod ? methods.size() : types.size();
        if (container.ownerIndex < 0 || static_cast<size_t>(container.ownerIndex) >= ownerCount) {
            invalid("generic container references an invalid owner");
        }
    }
    model.fieldDefaultValues = readTable<FieldDefaultValueModel>(sections.fieldDefaultValues, "field default values",
        [&](size_t base, size_t stride) {
            RecordReader record(reader, base, stride);
            FieldDefaultValueModel value;
            value.fieldIndex = record.i32();
            value.typeIndex = record.index(header.typeIndexWidth);
            value.dataIndex = record.i32();
            return value;
        });
    model.parameterDefaultValues = readTable<ParameterDefaultValueModel>(sections.parameterDefaultValues, "parameter default values",
        [&](size_t base, size_t stride) {
            RecordReader record(reader, base, stride);
            ParameterDefaultValueModel value;
            value.parameterIndex = record.index(header.parameterIndexWidth);
            value.typeIndex = record.index(header.typeIndexWidth);
            value.dataIndex = record.i32();
            return value;
        });

    if (sections.defaultValueData.sectionSize > 0) {
        const size_t offset = static_cast<size_t>(sections.defaultValueData.offset);
        const size_t byteSize = static_cast<size_t>(sections.defaultValueData.sectionSize);
        const uint8_t* bytes = reader.bytes(offset, byteSize);
        model.defaultValueData.assign(bytes, bytes + byteSize);
    }

    std::unordered_map<int32_t, int32_t> fieldDefaults;
    for (size_t index = 0; index < model.fieldDefaultValues.size(); ++index) {
        const auto& value = model.fieldDefaultValues[index];
        if (value.fieldIndex < 0 || static_cast<size_t>(value.fieldIndex) >= fields.size()) {
            invalid("field default value references an invalid field");
        }
        if (value.dataIndex < 0 || static_cast<size_t>(value.dataIndex) > model.defaultValueData.size()) {
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
        if (value.dataIndex < 0 || static_cast<size_t>(value.dataIndex) > model.defaultValueData.size()) {
            invalid("parameter default value data index is outside the data blob");
        }
        parameterDefaults.insert_or_assign(value.parameterIndex, static_cast<int32_t>(index));
    }

    model.types.reserve(types.size());
    std::vector<std::string> typeImages(types.size());
    for (const auto& image : images) {
        validateRange(image.typeStart, image.typeCount, types.size(), "image type");
        validateRange(
            image.exportedTypeStart, image.exportedTypeCount,
            static_cast<size_t>(sections.exportedTypeDefinitions.count), "image exported type");
        model.methodPointersByImage.try_emplace(image.name);
        if (image.typeStart < 0) continue;
        const size_t begin = static_cast<size_t>(image.typeStart);
        for (size_t index = 0; index < image.typeCount; ++index) {
            if (typeImages[begin + index].empty()) typeImages[begin + index] = image.name;
        }
    }

    std::vector<std::string> declaringNames;
    declaringNames.reserve(types.size());
    for (size_t typeIndex = 0; typeIndex < types.size(); ++typeIndex) {
        const auto& definition = types[typeIndex];
        TypeModel type;
        type.name = readString(reader, sections.strings, definition.nameIndex).value_or("");
        type.nameSpace = readString(reader, sections.strings, definition.namespaceIndex).value_or("");
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
        validateRange(definition.fieldStart, definition.fieldCount, fields.size(), "type field");
        validateRange(definition.methodStart, definition.methodCount, methods.size(), "type method");
        for (uint32_t index = 0; index < definition.fieldCount; ++index) {
            const size_t fieldIndex = static_cast<size_t>(definition.fieldStart) + index;
            const auto& fieldDefinition = fields[fieldIndex];
            FieldModel field;
            field.name = readString(reader, sections.strings, fieldDefinition.nameIndex).value_or("");
            field.type = typeReference(fieldDefinition.typeIndex);
            field.token = fieldDefinition.token;
            if (const auto defaultValue = fieldDefaults.find(static_cast<int32_t>(fieldIndex));
                defaultValue != fieldDefaults.end()) {
                field.defaultValueIndex = defaultValue->second;
            }
            outputType.fields.push_back(std::move(field));
        }

        for (uint32_t index = 0; index < definition.methodCount; ++index) {
            const size_t methodIndex = static_cast<size_t>(definition.methodStart) + index;
            const auto& methodDefinition = methods[methodIndex];
            validateRange(
                methodDefinition.parameterStart,
                methodDefinition.parameterCount,
                parameters.size(),
                "method parameter");
            MethodModel method;
            method.token = methodDefinition.token;
            method.definitionIndex = static_cast<int>(methodIndex);
            method.imageName = typeImages[typeIndex];
            method.declaringType = declaringNames[typeIndex];
            if (methodDefinition.declaringType >= 0 &&
                static_cast<size_t>(methodDefinition.declaringType) < declaringNames.size()) {
                method.declaringType = declaringNames[static_cast<size_t>(methodDefinition.declaringType)];
            }
            method.name = readString(reader, sections.strings, methodDefinition.nameIndex).value_or("");
            method.returnType = typeReference(methodDefinition.returnType);
            method.isStatic = (methodDefinition.flags & 0x0010) != 0;
            method.flags = methodDefinition.flags;
            method.iflags = methodDefinition.iflags;
            method.slot = methodDefinition.slot;
            method.genericContainerIndex = methodDefinition.genericContainerIndex;
            method.returnParameterToken = methodDefinition.returnParameterToken;

            for (uint32_t parameterIndex = 0; parameterIndex < methodDefinition.parameterCount; ++parameterIndex) {
                const size_t indexInTable = static_cast<size_t>(methodDefinition.parameterStart) + parameterIndex;
                const auto& parameterDefinition = parameters[indexInTable];
                ParameterModel parameter;
                parameter.name = readString(reader, sections.strings, parameterDefinition.nameIndex).value_or("");
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

    const auto literalOffsets = readTable<int32_t>(sections.stringLiterals, "string literals",
        [&](size_t base, size_t stride) {
            RecordReader record(reader, base, stride);
            return record.i32();
        });
    const size_t literalDataSize = static_cast<size_t>(sections.stringLiteralData.sectionSize);
    for (size_t index = 0; index < literalOffsets.size(); ++index) {
        if (literalOffsets[index] < 0 || static_cast<size_t>(literalOffsets[index]) > literalDataSize) {
            invalid("string literal data index is outside the data blob");
        }
        if (index != 0 && literalOffsets[index] < literalOffsets[index - 1]) {
            invalid("string literal data indices are not monotonic");
        }
        const size_t start = static_cast<size_t>(literalOffsets[index]);
        const size_t end = index + 1 == literalOffsets.size()
            ? literalDataSize
            : static_cast<size_t>(literalOffsets[index + 1]);
        const size_t length = end - start;
        const size_t offset = static_cast<size_t>(sections.stringLiteralData.offset) + start;
        const char* bytes = reinterpret_cast<const char*>(reader.bytes(offset, length));
        model.stringLiterals.emplace(static_cast<uint32_t>(index), std::string(bytes, length));
    }

    const auto unresolvedTypes = readIndices(
        reader,
        sections.unresolvedIndirectCallParameterTypes,
        "unresolved indirect call parameter types");
    const auto unresolvedRanges = readTable<UnresolvedSignatureModel>(
        sections.unresolvedIndirectCallParameterRanges,
        "unresolved indirect call parameter ranges",
        [&](size_t base, size_t stride) {
            RecordReader record(reader, base, stride);
            UnresolvedSignatureModel signature;
            signature.start = record.i32();
            signature.count = record.i32();
            return signature;
        });
    model.unresolvedSignatures.reserve(unresolvedRanges.size());
    for (auto signature : unresolvedRanges) {
        if (signature.count < 0) invalid("unresolved signature has a negative parameter count");
        validateRange(
            signature.start,
            static_cast<uint32_t>(signature.count),
            unresolvedTypes.size(),
            "unresolved signature parameter");
        if (signature.start >= 0) {
            const size_t begin = static_cast<size_t>(signature.start);
            signature.parameterTypeIndices.assign(
                unresolvedTypes.begin() + static_cast<std::ptrdiff_t>(begin),
                unresolvedTypes.begin() + static_cast<std::ptrdiff_t>(begin + signature.count));
        }
        model.unresolvedSignatures.push_back(std::move(signature));
    }

    return model;
}

MetadataModel Version38::readFile(const std::string& path) const {
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
