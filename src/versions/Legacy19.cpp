#include <il2cpprec/versions/Legacy19.hpp>

#include <algorithm>
#include <bit>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint32_t metadataSanity = 0xFAB11BAF;
constexpr size_t legacyHeaderSize = 192;
constexpr size_t legacyUsageHeaderSize = 208;

class Error final : public std::runtime_error {
public:
    Error(std::string code, const std::string& message, uint64_t offset, bool hasOffset = true)
        : std::runtime_error(message), code(std::move(code)), offset(offset), hasOffset(hasOffset) {}

    std::string code;
    uint64_t offset = 0;
    bool hasOffset = false;
};

[[noreturn]] void fail(std::string code, const std::string& message) {
    throw Error(std::move(code), message, 0, false);
}

[[noreturn]] void failAt(std::string code, const std::string& message, uint64_t offset) {
    throw Error(std::move(code), message, offset);
}

void addError(Legacy19ReadResult& result, const Error& error) {
    result.diagnostics.push_back({
        Legacy19DiagnosticSeverity::Error,
        error.code,
        error.what(),
        error.offset,
        error.hasOffset
    });
}

size_t checkedSize(uint64_t count, size_t stride, const char* name) {
    if (count > std::numeric_limits<size_t>::max() ||
        static_cast<size_t>(count) > std::numeric_limits<size_t>::max() / stride) {
        fail("table-size-overflow", std::string(name) + " table size overflows size_t");
    }
    return static_cast<size_t>(count) * stride;
}

uint64_t checkedAdd(uint64_t value, uint64_t amount) {
    if (amount > std::numeric_limits<uint64_t>::max() - value) {
        fail("address-overflow", "Virtual address calculation overflows uint64_t");
    }
    return value + amount;
}

class MetadataReader {
public:
    MetadataReader(const uint8_t* data, size_t size) : data_(data), size_(size) {
        if (data == nullptr && size != 0) fail("null-input", "Global metadata pointer is null but size is nonzero");
    }

    size_t size() const noexcept { return size_; }

    void require(size_t offset, size_t amount) const {
        if (offset > size_ || amount > size_ - offset) {
            failAt("global-read-out-of-bounds", "Global metadata read is outside the input", offset);
        }
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

    int32_t i32(size_t offset) const { return std::bit_cast<int32_t>(u32(offset)); }

    const uint8_t* bytes(size_t offset, size_t amount) const {
        require(offset, amount);
        return data_ + offset;
    }

private:
    const uint8_t* data_;
    size_t size_;
};

struct Table {
    uint32_t offset = 0;
    int32_t size = 0;
};

struct Header {
    int32_t version = 0;
    bool usages = false;
    size_t size = legacyHeaderSize;
    Table stringLiterals;
    Table stringLiteralData;
    Table strings;
    Table events;
    Table properties;
    Table methods;
    Table parameterDefaultValues;
    Table fieldDefaultValues;
    Table defaultValueData;
    Table fieldMarshaledSizes;
    Table parameters;
    Table fields;
    Table genericParameters;
    Table genericParameterConstraints;
    Table genericContainers;
    Table nestedTypes;
    Table interfaces;
    Table vtableMethods;
    Table interfaceOffsets;
    Table typeDefinitions;
    Table rgctxEntries;
    Table images;
    Table assemblies;
    Table metadataUsageLists;
    Table metadataUsagePairs;
    Table fieldRefs;
    Table referencedAssemblies;
};

Table readTableHeader(const MetadataReader& reader, size_t offset) {
    return {reader.u32(offset), reader.i32(offset + 4)};
}

size_t tableCount(
    const MetadataReader& reader,
    const Table& table,
    size_t stride,
    const char* name) {
    if (table.size < 0) {
        failAt("negative-table-size", std::string(name) + " table has a negative byte size", 0);
    }
    const auto byteSize = static_cast<size_t>(table.size);
    if (byteSize % stride != 0) {
        failAt(
            "misaligned-table-size",
            std::string(name) + " byte size is not divisible by its stride " + std::to_string(stride),
            table.offset);
    }
    if (table.offset > reader.size() || byteSize > reader.size() - table.offset) {
        failAt("global-table-out-of-bounds", std::string(name) + " table is outside global metadata", table.offset);
    }
    return byteSize / stride;
}

Header readHeader(const MetadataReader& reader, Legacy19Profile& profile) {
    reader.require(0, 8);
    if (reader.u32(0) != metadataSanity) failAt("invalid-sanity", "Global metadata sanity value is invalid", 0);
    profile = describeLegacy19Profile(reader.i32(4));
    if (!profile.supported) {
        failAt(
            "unsupported-version",
            "Legacy19 supports only global metadata versions 19 and 20; got " + std::to_string(reader.i32(4)),
            4);
    }

    Header header;
    header.version = profile.version;
    header.usages = true;
    header.size = profile.headerSize;
    reader.require(0, header.size);
    header.stringLiterals = readTableHeader(reader, 8);
    if (header.stringLiterals.offset != header.size) {
        failAt(
            "invalid-header-size",
            "Metadata " + std::to_string(header.version) + " string literal table must start at " +
                std::to_string(header.size),
            8);
    }

    header.stringLiteralData = readTableHeader(reader, 16);
    header.strings = readTableHeader(reader, 24);
    header.events = readTableHeader(reader, 32);
    header.properties = readTableHeader(reader, 40);
    header.methods = readTableHeader(reader, 48);
    header.parameterDefaultValues = readTableHeader(reader, 56);
    header.fieldDefaultValues = readTableHeader(reader, 64);
    header.defaultValueData = readTableHeader(reader, 72);
    header.fieldMarshaledSizes = readTableHeader(reader, 80);
    header.parameters = readTableHeader(reader, 88);
    header.fields = readTableHeader(reader, 96);
    header.genericParameters = readTableHeader(reader, 104);
    header.genericParameterConstraints = readTableHeader(reader, 112);
    header.genericContainers = readTableHeader(reader, 120);
    header.nestedTypes = readTableHeader(reader, 128);
    header.interfaces = readTableHeader(reader, 136);
    header.vtableMethods = readTableHeader(reader, 144);
    header.interfaceOffsets = readTableHeader(reader, 152);
    header.typeDefinitions = readTableHeader(reader, 160);
    header.rgctxEntries = readTableHeader(reader, 168);
    header.images = readTableHeader(reader, 176);
    header.assemblies = readTableHeader(reader, 184);
    header.metadataUsageLists = readTableHeader(reader, 192);
    header.metadataUsagePairs = readTableHeader(reader, 200);
    header.fieldRefs = readTableHeader(reader, 208);
    if (profile.referencedAssemblies) header.referencedAssemblies = readTableHeader(reader, 216);
    return header;
}

struct ImageDefinition {
    uint32_t nameIndex = 0;
    int32_t assemblyIndex = -1;
    int32_t typeStart = 0;
    uint32_t typeCount = 0;
    int32_t entryPointIndex = -1;
    uint32_t token = 0;
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
    int32_t parameterStart = -1;
    int32_t genericContainerIndex = -1;
    int32_t methodIndex = -1;
    int32_t invokerIndex = -1;
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

struct Counts {
    size_t literals = 0;
    size_t events = 0;
    size_t properties = 0;
    size_t methods = 0;
    size_t parameterDefaults = 0;
    size_t fieldDefaults = 0;
    size_t marshaledSizes = 0;
    size_t parameters = 0;
    size_t fields = 0;
    size_t genericParameters = 0;
    size_t constraints = 0;
    size_t containers = 0;
    size_t nestedTypes = 0;
    size_t interfaces = 0;
    size_t vtable = 0;
    size_t interfaceOffsets = 0;
    size_t types = 0;
    size_t rgctx = 0;
    size_t images = 0;
    size_t assemblies = 0;
    size_t usageLists = 0;
    size_t usagePairs = 0;
    size_t fieldRefs = 0;
    size_t referencedAssemblies = 0;
};

Counts validateTables(const MetadataReader& reader, const Header& header) {
    Counts counts;
    counts.literals = tableCount(reader, header.stringLiterals, 8, "string literals");
    tableCount(reader, header.stringLiteralData, 1, "string literal data");
    tableCount(reader, header.strings, 1, "strings");
    counts.events = tableCount(reader, header.events, 28, "events");
    counts.properties = tableCount(reader, header.properties, 24, "properties");
    counts.methods = tableCount(reader, header.methods, 56, "methods");
    counts.parameterDefaults = tableCount(reader, header.parameterDefaultValues, 12, "parameter default values");
    counts.fieldDefaults = tableCount(reader, header.fieldDefaultValues, 12, "field default values");
    tableCount(reader, header.defaultValueData, 1, "default value data");
    counts.marshaledSizes = tableCount(reader, header.fieldMarshaledSizes, 12, "field marshaled sizes");
    counts.parameters = tableCount(reader, header.parameters, 16, "parameters");
    counts.fields = tableCount(reader, header.fields, 16, "fields");
    counts.genericParameters = tableCount(reader, header.genericParameters, 16, "generic parameters");
    counts.constraints = tableCount(reader, header.genericParameterConstraints, 4, "generic parameter constraints");
    counts.containers = tableCount(reader, header.genericContainers, 16, "generic containers");
    counts.nestedTypes = tableCount(reader, header.nestedTypes, 4, "nested types");
    counts.interfaces = tableCount(reader, header.interfaces, 4, "interfaces");
    counts.vtable = tableCount(reader, header.vtableMethods, 4, "vtable methods");
    counts.interfaceOffsets = tableCount(reader, header.interfaceOffsets, 8, "interface offsets");
    counts.types = tableCount(reader, header.typeDefinitions, 112, "type definitions");
    counts.rgctx = tableCount(reader, header.rgctxEntries, 8, "RGCTX entries");
    counts.images = tableCount(reader, header.images, 24, "images");
    counts.assemblies = tableCount(reader, header.assemblies, header.version == 20 ? 68 : 60, "assemblies");
    counts.usageLists = tableCount(reader, header.metadataUsageLists, 8, "metadata usage lists");
    counts.usagePairs = tableCount(reader, header.metadataUsagePairs, 8, "metadata usage pairs");
    counts.fieldRefs = tableCount(reader, header.fieldRefs, 8, "field references");
    if (header.version == 20) {
        counts.referencedAssemblies = tableCount(reader, header.referencedAssemblies, 4, "referenced assemblies");
    }
    return counts;
}

std::string metadataString(const MetadataReader& reader, const Header& header, uint32_t index) {
    if (index >= static_cast<uint32_t>(header.strings.size)) {
        failAt("string-index-out-of-bounds", "Metadata string index is outside the string table", index);
    }
    const size_t start = static_cast<size_t>(header.strings.offset) + index;
    const size_t remaining = static_cast<size_t>(header.strings.size) - index;
    const auto* bytes = reinterpret_cast<const char*>(reader.bytes(start, remaining));
    const void* terminator = std::memchr(bytes, 0, remaining);
    if (terminator == nullptr) {
        failAt("unterminated-string", "Metadata string has no NUL terminator inside the string table", start);
    }
    return std::string(bytes, static_cast<const char*>(terminator) - bytes);
}

std::string typeReference(int32_t index) {
    return index < 0 ? std::string{} : "type[" + std::to_string(index) + "]";
}

std::string qualifiedName(const TypeModel& type) {
    if (type.nameSpace.empty()) return type.name;
    if (type.name.empty()) return type.nameSpace;
    return type.nameSpace + "." + type.name;
}

template<typename T>
bool validOptionalIndex(int32_t index, const std::vector<T>& table) {
    return index == -1 || (index >= 0 && static_cast<size_t>(index) < table.size());
}

bool validRange(int32_t start, uint64_t count, size_t tableSize) {
    if (start == -1 && count == 0) return true;
    return start >= 0 && static_cast<uint64_t>(static_cast<uint32_t>(start)) + count <= tableSize;
}

MetadataModel readGlobal(const uint8_t* data, size_t size, Legacy19ReadResult& result) {
    MetadataReader reader(data, size);
    Header header = readHeader(reader, result.profile);
    const Counts counts = validateTables(reader, header);

    std::vector<ImageDefinition> images;
    images.reserve(counts.images);
    for (size_t index = 0; index < counts.images; ++index) {
        const size_t base = header.images.offset + index * 24;
        images.push_back({
            reader.u32(base),
            reader.i32(base + 4),
            reader.i32(base + 8),
            reader.u32(base + 12),
            reader.i32(base + 16),
            reader.u32(base + 20)
        });
    }

    std::vector<TypeDefinition> types;
    types.reserve(counts.types);
    for (size_t index = 0; index < counts.types; ++index) {
        const size_t base = header.typeDefinitions.offset + index * 112;
        types.push_back({
            reader.u32(base),
            reader.u32(base + 4),
            reader.i32(base + 20),
            reader.i32(base + 24),
            reader.i32(base + 40),
            reader.u32(base + 52),
            reader.i32(base + 56),
            reader.i32(base + 60),
            reader.u16(base + 88),
            reader.u16(base + 92),
            reader.u32(base + 104),
            reader.u32(base + 108)
        });
    }

    std::vector<MethodDefinition> methods;
    methods.reserve(counts.methods);
    for (size_t index = 0; index < counts.methods; ++index) {
        const size_t base = header.methods.offset + index * 56;
        methods.push_back({
            reader.u32(base),
            reader.i32(base + 4),
            reader.i32(base + 8),
            reader.i32(base + 12),
            reader.i32(base + 20),
            reader.i32(base + 24),
            reader.i32(base + 28),
            reader.u32(base + 44),
            reader.u16(base + 48),
            reader.u16(base + 50),
            reader.u16(base + 52),
            reader.u16(base + 54)
        });
    }

    std::vector<ParameterDefinition> parameters;
    parameters.reserve(counts.parameters);
    for (size_t index = 0; index < counts.parameters; ++index) {
        const size_t base = header.parameters.offset + index * 16;
        parameters.push_back({reader.u32(base), reader.i32(base + 12)});
    }

    std::vector<FieldDefinition> fields;
    fields.reserve(counts.fields);
    for (size_t index = 0; index < counts.fields; ++index) {
        const size_t base = header.fields.offset + index * 16;
        fields.push_back({reader.u32(base), reader.i32(base + 4), reader.u32(base + 12)});
    }

    const size_t assemblyStride = header.version == 20 ? 68 : 60;
    for (size_t index = 0; index < counts.assemblies; ++index) {
        const size_t base = header.assemblies.offset + index * assemblyStride;
        const int32_t imageIndex = reader.i32(base);
        if (imageIndex < 0 || static_cast<size_t>(imageIndex) >= images.size()) {
            failAt("assembly-image-out-of-bounds", "Assembly references an invalid image", base);
        }
        if (header.version == 20) {
            const int32_t start = reader.i32(base + 8);
            const int32_t count = reader.i32(base + 12);
            if (count < 0 || !validRange(start, static_cast<uint32_t>(count), counts.referencedAssemblies)) {
                failAt("assembly-reference-range-out-of-bounds", "Assembly referenced-assembly range is invalid", base + 8);
            }
        }
    }
    for (size_t index = 0; index < counts.referencedAssemblies; ++index) {
        const int32_t assembly = reader.i32(header.referencedAssemblies.offset + index * 4);
        if (assembly < 0 || static_cast<size_t>(assembly) >= counts.assemblies) {
            failAt(
                "referenced-assembly-out-of-bounds",
                "Referenced assembly index is outside the assembly table",
                header.referencedAssemblies.offset + index * 4);
        }
    }
    for (const auto& image : images) {
        metadataString(reader, header, image.nameIndex);
        if (image.assemblyIndex < 0 || static_cast<size_t>(image.assemblyIndex) >= counts.assemblies) {
            fail("image-assembly-out-of-bounds", "Image assemblyIndex is outside the assembly table");
        }
        if (!validRange(image.typeStart, image.typeCount, types.size())) {
            failAt("image-type-range-out-of-bounds", "Image type range is outside the type definition table", image.typeStart);
        }
    }
    for (const auto& type : types) {
        metadataString(reader, header, type.nameIndex);
        metadataString(reader, header, type.namespaceIndex);
        if (!validOptionalIndex(type.declaringTypeIndex, types)) {
            fail("declaring-type-out-of-bounds", "Type declaringTypeIndex is outside the type definition table");
        }
        if (!validRange(type.fieldStart, type.fieldCount, fields.size()) ||
            !validRange(type.methodStart, type.methodCount, methods.size())) {
            fail("type-member-range-out-of-bounds", "Type field or method range is outside its definition table");
        }
    }
    for (const auto& method : methods) {
        metadataString(reader, header, method.nameIndex);
        if (method.declaringType < 0 || static_cast<size_t>(method.declaringType) >= types.size()) {
            fail("method-declaring-type-out-of-bounds", "Method declaringType is outside the type definition table");
        }
        if (!validRange(method.parameterStart, method.parameterCount, parameters.size())) {
            fail("method-parameter-range-out-of-bounds", "Method parameter range is outside the parameter table");
        }
        if (method.methodIndex < -1 || method.invokerIndex < -1) {
            fail("invalid-method-native-index", "Method methodIndex and invokerIndex must be -1 or nonnegative");
        }
    }
    for (const auto& parameter : parameters) metadataString(reader, header, parameter.nameIndex);
    for (const auto& field : fields) metadataString(reader, header, field.nameIndex);

    for (size_t index = 0; index < counts.nestedTypes; ++index) {
        const int32_t nested = reader.i32(header.nestedTypes.offset + index * 4);
        if (nested < 0 || static_cast<size_t>(nested) >= types.size()) {
            failAt("nested-type-out-of-bounds", "Nested type index is outside the type definition table", header.nestedTypes.offset + index * 4);
        }
    }

    MetadataModel model;
    model.version = header.version;
    model.genericParameters.reserve(counts.genericParameters);
    for (size_t index = 0; index < counts.genericParameters; ++index) {
        const size_t base = header.genericParameters.offset + index * 16;
        GenericParameterModel parameter;
        parameter.ownerIndex = reader.i32(base);
        parameter.name = metadataString(reader, header, reader.u32(base + 4));
        parameter.constraintsStart = std::bit_cast<int16_t>(reader.u16(base + 8));
        parameter.constraintsCount = std::bit_cast<int16_t>(reader.u16(base + 10));
        parameter.num = reader.u16(base + 12);
        parameter.flags = reader.u16(base + 14);
        if (parameter.ownerIndex < 0 || static_cast<size_t>(parameter.ownerIndex) >= counts.containers) {
            failAt("generic-parameter-owner-out-of-bounds", "Generic parameter owner is outside generic containers", base);
        }
        if (parameter.constraintsStart < 0 || parameter.constraintsCount < 0 ||
            !validRange(parameter.constraintsStart, static_cast<uint16_t>(parameter.constraintsCount), counts.constraints)) {
            failAt("generic-constraint-range-out-of-bounds", "Generic parameter constraint range is invalid", base + 8);
        }
        model.genericParameters.push_back(std::move(parameter));
    }

    model.genericContainers.reserve(counts.containers);
    for (size_t index = 0; index < counts.containers; ++index) {
        const size_t base = header.genericContainers.offset + index * 16;
        GenericContainerModel container{
            reader.i32(base), reader.i32(base + 4), reader.i32(base + 8), reader.i32(base + 12)};
        const size_t ownerCount = container.isMethod != 0 ? methods.size() : types.size();
        if (container.ownerIndex < 0 || static_cast<size_t>(container.ownerIndex) >= ownerCount ||
            container.typeArgumentCount < 0 || container.genericParameterStart < 0 ||
            !validRange(container.genericParameterStart, static_cast<uint32_t>(container.typeArgumentCount), model.genericParameters.size())) {
            failAt("invalid-generic-container", "Generic container owner or generic parameter range is invalid", base);
        }
        model.genericContainers.push_back(container);
    }
    for (const auto& type : types) {
        if (!validOptionalIndex(type.genericContainerIndex, model.genericContainers)) {
            fail("type-generic-container-out-of-bounds", "Type genericContainerIndex is invalid");
        }
    }
    for (const auto& method : methods) {
        if (!validOptionalIndex(method.genericContainerIndex, model.genericContainers)) {
            fail("method-generic-container-out-of-bounds", "Method genericContainerIndex is invalid");
        }
    }

    model.fieldDefaultValues.reserve(counts.fieldDefaults);
    std::unordered_map<int32_t, int32_t> fieldDefaults;
    for (size_t index = 0; index < counts.fieldDefaults; ++index) {
        const size_t base = header.fieldDefaultValues.offset + index * 12;
        FieldDefaultValueModel value{reader.i32(base), reader.i32(base + 4), reader.i32(base + 8)};
        if (value.fieldIndex < 0 || static_cast<size_t>(value.fieldIndex) >= fields.size() ||
            value.dataIndex < -1 || (value.dataIndex >= 0 && value.dataIndex > header.defaultValueData.size)) {
            failAt("invalid-field-default-value", "Field default value field or data index is invalid", base);
        }
        if (!fieldDefaults.emplace(value.fieldIndex, static_cast<int32_t>(index)).second) {
            failAt("duplicate-field-default-value", "Field has more than one default value", base);
        }
        model.fieldDefaultValues.push_back(value);
    }

    model.parameterDefaultValues.reserve(counts.parameterDefaults);
    std::unordered_map<int32_t, int32_t> parameterDefaults;
    for (size_t index = 0; index < counts.parameterDefaults; ++index) {
        const size_t base = header.parameterDefaultValues.offset + index * 12;
        ParameterDefaultValueModel value{reader.i32(base), reader.i32(base + 4), reader.i32(base + 8)};
        if (value.parameterIndex < 0 || static_cast<size_t>(value.parameterIndex) >= parameters.size() ||
            value.dataIndex < -1 || (value.dataIndex >= 0 && value.dataIndex > header.defaultValueData.size)) {
            failAt("invalid-parameter-default-value", "Parameter default value parameter or data index is invalid", base);
        }
        if (!parameterDefaults.emplace(value.parameterIndex, static_cast<int32_t>(index)).second) {
            failAt("duplicate-parameter-default-value", "Parameter has more than one default value", base);
        }
        model.parameterDefaultValues.push_back(value);
    }
    if (header.defaultValueData.size > 0) {
        model.defaultValueData.assign(
            data + header.defaultValueData.offset,
            data + header.defaultValueData.offset + header.defaultValueData.size);
    }

    model.versionInfo.rawVersion = header.version;
    model.versionInfo.preciseVersion = header.version;
    model.versionInfo.confidence = MetadataVersionConfidence::RawHeader;
    model.images.reserve(images.size());
    for (const auto& definition : images) {
        ImageModel image;
        image.name = metadataString(reader, header, definition.nameIndex);
        image.assemblyIndex = definition.assemblyIndex;
        image.typeStart = definition.typeStart;
        image.typeCount = definition.typeCount;
        image.entryPointIndex = definition.entryPointIndex;
        image.token = definition.token;
        model.images.push_back(std::move(image));
    }
    model.assemblies.reserve(counts.assemblies);
    for (size_t index = 0; index < counts.assemblies; ++index) {
        const size_t base = header.assemblies.offset + index * assemblyStride;
        AssemblyModel assembly;
        assembly.imageIndex = reader.i32(base);
        if (header.version == 20) {
            assembly.referencedAssemblyStart = reader.i32(base + 8);
            assembly.referencedAssemblyCount = reader.i32(base + 12);
        }
        model.assemblies.push_back(assembly);
    }

    model.types.reserve(types.size());
    std::vector<std::string> typeImages(types.size());
    std::vector<std::string> declaringNames;
    declaringNames.reserve(types.size());
    for (const auto& image : model.images) {
        model.methodPointersByImage.try_emplace(image.name);
        const size_t begin = static_cast<size_t>(image.typeStart);
        for (size_t index = 0; index < image.typeCount; ++index) {
            if (typeImages[begin + index].empty()) typeImages[begin + index] = image.name;
        }
    }
    for (const auto& definition : types) {
        TypeModel type;
        type.name = metadataString(reader, header, definition.nameIndex);
        type.nameSpace = metadataString(reader, header, definition.namespaceIndex);
        type.baseType = typeReference(definition.parentIndex);
        type.declaringTypeIndex = definition.declaringTypeIndex;
        type.genericContainerIndex = definition.genericContainerIndex;
        type.flags = definition.flags;
        type.bitfield = definition.bitfield;
        type.token = definition.token;
        declaringNames.push_back(qualifiedName(type));
        model.types.push_back(std::move(type));
    }
    for (size_t typeIndex = 0; typeIndex < types.size(); ++typeIndex) {
        model.types[typeIndex].imageName = typeImages[typeIndex];
    }

    model.invokerIndices.resize(methods.size(), -1);
    for (size_t typeIndex = 0; typeIndex < types.size(); ++typeIndex) {
        const auto& definition = types[typeIndex];
        auto& outputType = model.types[typeIndex];
        outputType.fields.reserve(definition.fieldCount);
        for (uint32_t localIndex = 0; localIndex < definition.fieldCount; ++localIndex) {
            const int32_t fieldIndex = definition.fieldStart + static_cast<int32_t>(localIndex);
            const auto& fieldDefinition = fields[static_cast<size_t>(fieldIndex)];
            FieldModel field;
            field.name = metadataString(reader, header, fieldDefinition.nameIndex);
            field.type = typeReference(fieldDefinition.typeIndex);
            field.token = fieldDefinition.token;
            if (const auto value = fieldDefaults.find(fieldIndex); value != fieldDefaults.end()) {
                field.defaultValueIndex = value->second;
            }
            outputType.fields.push_back(std::move(field));
        }
        outputType.methods.reserve(definition.methodCount);
        for (uint32_t localIndex = 0; localIndex < definition.methodCount; ++localIndex) {
            const int32_t methodIndex = definition.methodStart + static_cast<int32_t>(localIndex);
            const auto& methodDefinition = methods[static_cast<size_t>(methodIndex)];
            MethodModel method;
            method.token = methodDefinition.token;
            method.definitionIndex = methodIndex;
            method.methodIndex = methodDefinition.methodIndex;
            method.imageName = typeImages[typeIndex];
            method.declaringType = declaringNames[static_cast<size_t>(methodDefinition.declaringType)];
            method.name = metadataString(reader, header, methodDefinition.nameIndex);
            method.returnType = typeReference(methodDefinition.returnType);
            method.isStatic = (methodDefinition.flags & 0x0010) != 0;
            method.flags = methodDefinition.flags;
            method.iflags = methodDefinition.iflags;
            method.slot = methodDefinition.slot;
            method.genericContainerIndex = methodDefinition.genericContainerIndex;
            model.invokerIndices[static_cast<size_t>(methodIndex)] = methodDefinition.invokerIndex;
            method.parameters.reserve(methodDefinition.parameterCount);
            for (uint32_t localParameter = 0; localParameter < methodDefinition.parameterCount; ++localParameter) {
                const int32_t parameterIndex = methodDefinition.parameterStart + static_cast<int32_t>(localParameter);
                const auto& parameterDefinition = parameters[static_cast<size_t>(parameterIndex)];
                ParameterModel parameter;
                parameter.name = metadataString(reader, header, parameterDefinition.nameIndex);
                parameter.type = typeReference(parameterDefinition.typeIndex);
                if (const auto value = parameterDefaults.find(parameterIndex); value != parameterDefaults.end()) {
                    parameter.defaultValueIndex = value->second;
                }
                method.parameters.push_back(std::move(parameter));
            }
            outputType.methods.push_back(std::move(method));
        }
    }

    for (size_t index = 0; index < counts.literals; ++index) {
        const size_t base = header.stringLiterals.offset + index * 8;
        const uint32_t length = reader.u32(base);
        const int32_t dataIndex = reader.i32(base + 4);
        if (dataIndex < 0 || dataIndex > header.stringLiteralData.size ||
            length > static_cast<uint32_t>(header.stringLiteralData.size - dataIndex)) {
            failAt("string-literal-out-of-bounds", "String literal range is outside literal data", base);
        }
        model.stringLiterals.emplace(
            static_cast<uint32_t>(index),
            std::string(
                reinterpret_cast<const char*>(data + header.stringLiteralData.offset + dataIndex),
                length));
    }

    if (header.usages) {
        model.metadataUsageLists.reserve(counts.usageLists);
        for (size_t index = 0; index < counts.usageLists; ++index) {
            const size_t base = header.metadataUsageLists.offset + index * 8;
            MetadataUsageListModel list{reader.u32(base), reader.u32(base + 4)};
            if (list.start > counts.usagePairs || list.count > counts.usagePairs - list.start) {
                failAt("metadata-usage-list-out-of-bounds", "MetadataUsage list range is outside the pairs table", base);
            }
            model.metadataUsageLists.push_back(list);
        }
        model.metadataUsagePairs.reserve(counts.usagePairs);
        uint64_t maximumDestination = 0;
        for (size_t index = 0; index < counts.usagePairs; ++index) {
            const size_t base = header.metadataUsagePairs.offset + index * 8;
            MetadataUsageModel usage;
            usage.destinationIndex = reader.u32(base);
            usage.encodedSourceIndex = reader.u32(base + 4);
            usage.kind = usage.encodedSourceIndex >> 29;
            usage.decodedIndex = usage.encodedSourceIndex & 0x1FFFFFFFU;
            if (usage.kind < 1 || usage.kind > 6) {
                failAt("invalid-metadata-usage-kind", "MetadataUsage encoded kind must be in range 1..6", base + 4);
            }
            if ((usage.kind == 3 && usage.decodedIndex >= methods.size()) ||
                (usage.kind == 4 && usage.decodedIndex >= counts.fieldRefs) ||
                (usage.kind == 5 && usage.decodedIndex >= counts.literals)) {
                failAt("metadata-usage-source-out-of-bounds", "MetadataUsage source index is outside its metadata table", base + 4);
            }
            maximumDestination = std::max(maximumDestination, static_cast<uint64_t>(usage.destinationIndex) + 1);
            model.metadataUsagePairs.push_back(usage);
        }
        model.metadataUsagesCount = maximumDestination;
    }
    return model;
}

size_t inferredPointerSize(const BinaryImage& binary, size_t requested) {
    if (requested != 0) return requested;
    switch (binary.architecture) {
    case Architecture::Arm32:
    case Architecture::X86:
        return 4;
    case Architecture::Arm64:
    case Architecture::X64:
        return 8;
    }
    fail("unsupported-architecture", "Cannot infer IL2CPP pointer size from binary architecture");
}

class ImageReader {
public:
    ImageReader(const BinaryImage& binary, size_t pointerSize) : binary_(binary), pointerSize_(pointerSize) {
        if (pointerSize != 4 && pointerSize != 8) fail("invalid-pointer-size", "IL2CPP pointer size must be 4 or 8");
        if (!binary.bytes) fail("binary-without-data", "Binary image has no data");
    }

    size_t pointerSize() const noexcept { return pointerSize_; }

    void require(uint64_t address, size_t amount) const { bytes(address, amount); }

    uint8_t u8(uint64_t address) const { return *bytes(address, 1); }

    uint16_t u16(uint64_t address) const {
        const auto* data = bytes(address, 2);
        return static_cast<uint16_t>(data[0]) |
            static_cast<uint16_t>(static_cast<uint16_t>(data[1]) << 8);
    }

    uint32_t u32(uint64_t address) const {
        const auto* data = bytes(address, 4);
        return static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << 8) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 24);
    }

    int32_t i32(uint64_t address) const { return std::bit_cast<int32_t>(u32(address)); }

    uint64_t u64(uint64_t address) const {
        const auto* data = bytes(address, 8);
        uint64_t value = 0;
        for (size_t index = 0; index < 8; ++index) value |= static_cast<uint64_t>(data[index]) << (index * 8);
        return value;
    }

    uint64_t pointer(uint64_t address) const { return pointerSize_ == 4 ? u32(address) : u64(address); }

    int64_t signedPointer(uint64_t address) const {
        return pointerSize_ == 4 ? static_cast<int64_t>(std::bit_cast<int32_t>(u32(address)))
                                 : std::bit_cast<int64_t>(u64(address));
    }

    uint64_t count(uint64_t address, const char* name) const {
        const int64_t value = signedPointer(address);
        if (value < 0) failAt("negative-native-table-count", std::string(name) + " count is negative", address);
        return static_cast<uint64_t>(value);
    }

    std::vector<uint64_t> pointerTable(uint64_t address, uint64_t count, const char* name) const {
        const size_t byteSize = checkedSize(count, pointerSize_, name);
        if (byteSize != 0) require(address, byteSize);
        std::vector<uint64_t> result;
        result.reserve(static_cast<size_t>(count));
        for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
            result.push_back(pointer(checkedAdd(address, index * pointerSize_)));
        }
        return result;
    }

private:
    const uint8_t* bytes(uint64_t address, size_t amount) const {
        uint64_t fileOffset = 0;
        try {
            if (address >= binary_.imageBase) {
                try {
                    fileOffset = binary_.mapVATR(address - binary_.imageBase);
                } catch (const std::out_of_range&) {
                    fileOffset = binary_.mapVATR(address);
                }
            } else {
                fileOffset = binary_.mapVATR(address);
            }
        } catch (const std::exception&) {
            failAt("unmapped-native-address", "Native address is not backed by a binary file range", address);
        }
        const auto& data = *binary_.bytes;
        if (fileOffset > data.size() || amount > data.size() - static_cast<size_t>(fileOffset)) {
            failAt("native-read-out-of-bounds", "Native read is outside the binary image", address);
        }
        return data.data() + static_cast<size_t>(fileOffset);
    }

    const BinaryImage& binary_;
    size_t pointerSize_;
};

class TypeTableReader {
public:
    TypeTableReader(
        const ImageReader& reader,
        uint64_t address,
        uint64_t count,
        const std::vector<TypeModel>& definitions)
        : reader_(reader), definitions_(definitions), addresses_(reader.pointerTable(address, count, "types")) {
        if (count > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
            fail("too-many-type-references", "Type reference count exceeds int32 indices");
        }
        references_.resize(addresses_.size());
        states_.resize(addresses_.size());
        for (size_t index = 0; index < addresses_.size(); ++index) {
            if (addresses_[index] != 0) indices_.try_emplace(addresses_[index], index);
        }
    }

    std::vector<TypeReferenceModel> read() {
        for (size_t index = 0; index < addresses_.size(); ++index) {
            if (addresses_[index] == 0) {
                states_[index] = State::Complete;
                continue;
            }
            const auto existing = indices_.find(addresses_[index]);
            if (existing != indices_.end() && existing->second != index) {
                readFixed(existing->second, addresses_[index]);
                references_[index] = references_[existing->second];
                states_[index] = State::Complete;
            } else {
                readFixed(index, addresses_[index]);
            }
        }
        return std::move(references_);
    }

private:
    enum class State { Unread, Reading, Complete };

    int32_t readPointer(uint64_t address) {
        if (address == 0) return -1;
        auto [position, inserted] = indices_.try_emplace(address, references_.size());
        if (inserted) {
            if (references_.size() >= static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
                fail("too-many-nested-type-references", "Nested type reference count exceeds int32 indices");
            }
            references_.emplace_back();
            states_.push_back(State::Unread);
        }
        readFixed(position->second, address);
        return static_cast<int32_t>(position->second);
    }

    void readFixed(size_t index, uint64_t address) {
        if (states_[index] != State::Unread) return;
        states_[index] = State::Reading;
        TypeReferenceModel reference;
        readType(address, reference);
        references_[index] = std::move(reference);
        states_[index] = State::Complete;
    }

    void setDefinition(TypeReferenceModel& reference, int32_t definitionIndex) const {
        if (definitionIndex < 0 || static_cast<size_t>(definitionIndex) >= definitions_.size()) {
            fail("type-definition-index-out-of-bounds", "Il2CppType class index is outside type definitions");
        }
        reference.definitionIndex = definitionIndex;
        reference.name = qualifiedName(definitions_[static_cast<size_t>(definitionIndex)]);
    }

    void readType(uint64_t address, TypeReferenceModel& reference) {
        const size_t pointerSize = reader_.pointerSize();
        reader_.require(address, pointerSize + 4);
        reference.attrs = reader_.u16(checkedAdd(address, pointerSize));
        reference.code = reader_.u8(checkedAdd(address, pointerSize + 2));
        reference.byRef = (reader_.u8(checkedAdd(address, pointerSize + 3)) & 0x40) != 0;
        switch (reference.code) {
        case 0x01: reference.name = "void"; break;
        case 0x02: reference.name = "bool"; break;
        case 0x03: reference.name = "char"; break;
        case 0x04: reference.name = "sbyte"; break;
        case 0x05: reference.name = "byte"; break;
        case 0x06: reference.name = "short"; break;
        case 0x07: reference.name = "ushort"; break;
        case 0x08: reference.name = "int"; break;
        case 0x09: reference.name = "uint"; break;
        case 0x0a: reference.name = "long"; break;
        case 0x0b: reference.name = "ulong"; break;
        case 0x0c: reference.name = "float"; break;
        case 0x0d: reference.name = "double"; break;
        case 0x0e: reference.name = "string"; break;
        case 0x18: reference.name = "IntPtr"; break;
        case 0x19: reference.name = "UIntPtr"; break;
        case 0x1c: reference.name = "object"; break;
        case 0x11:
        case 0x12:
        case 0x55:
            setDefinition(reference, reader_.i32(address));
            break;
        case 0x0f:
        case 0x10:
        case 0x1d:
        case 0x1f:
        case 0x20:
        case 0x41:
        case 0x45:
            reference.elementTypeIndex = readPointer(reader_.pointer(address));
            if (reference.code == 0x10) reference.byRef = true;
            if (reference.code == 0x1d) reference.rank = 1;
            break;
        case 0x14: {
            const uint64_t array = reader_.pointer(address);
            if (array != 0) {
                reference.elementTypeIndex = readPointer(reader_.pointer(array));
                reference.rank = reader_.u8(checkedAdd(array, pointerSize));
            }
            break;
        }
        case 0x15: {
            const uint64_t genericClass = reader_.pointer(address);
            if (genericClass == 0) break;
            setDefinition(reference, reader_.i32(genericClass));
            const uint64_t genericInst = reader_.pointer(checkedAdd(genericClass, pointerSize));
            if (genericInst == 0) break;
            const uint64_t count = reader_.count(genericInst, "generic instantiation");
            const uint64_t arguments = reader_.pointer(checkedAdd(genericInst, pointerSize));
            const auto argumentPointers = reader_.pointerTable(arguments, count, "generic arguments");
            for (const uint64_t argument : argumentPointers) {
                reference.genericArgumentIndices.push_back(readPointer(argument));
            }
            break;
        }
        case 0x13: reference.name = "!" + std::to_string(reader_.i32(address)); break;
        case 0x1e: reference.name = "!!" + std::to_string(reader_.i32(address)); break;
        default: break;
        }
    }

    const ImageReader& reader_;
    const std::vector<TypeModel>& definitions_;
    std::vector<uint64_t> addresses_;
    std::vector<TypeReferenceModel> references_;
    std::vector<State> states_;
    std::unordered_map<uint64_t, size_t> indices_;
};

size_t typeReferenceIndex(const std::string& type) {
    if (type.size() < 7 || !type.starts_with("type[") || type.back() != ']') {
        return std::numeric_limits<size_t>::max();
    }
    size_t result = 0;
    for (size_t index = 5; index + 1 < type.size(); ++index) {
        const char c = type[index];
        if (c < '0' || c > '9') return std::numeric_limits<size_t>::max();
        const size_t digit = static_cast<size_t>(c - '0');
        if (result > (std::numeric_limits<size_t>::max() - digit) / 10) return std::numeric_limits<size_t>::max();
        result = result * 10 + digit;
    }
    return result;
}

void applyTypeReferences(MetadataModel& metadata) {
    const auto resolve = [&](const std::string& type) {
        const size_t index = typeReferenceIndex(type);
        if (index >= metadata.typeReferences.size()) return type;
        const auto& name = metadata.typeReferences[index].name;
        return name.empty() ? type : name;
    };
    for (auto& type : metadata.types) {
        type.baseType = resolve(type.baseType);
        for (auto& field : type.fields) {
            const size_t referenceIndex = typeReferenceIndex(field.type);
            if (referenceIndex < metadata.typeReferences.size()) {
                field.flags = metadata.typeReferences[referenceIndex].attrs;
                field.isStatic = (field.flags & 0x0010) != 0;
            }
            field.type = resolve(field.type);
        }
        for (auto& method : type.methods) {
            method.returnType = resolve(method.returnType);
            for (auto& parameter : method.parameters) parameter.type = resolve(parameter.type);
        }
    }
}

struct NativePair {
    uint64_t count = 0;
    uint64_t address = 0;
};

NativePair readPair(const ImageReader& reader, uint64_t base, size_t index, const char* name) {
    const size_t pairSize = reader.pointerSize() * 2;
    const uint64_t address = checkedAdd(base, index * pairSize);
    return {reader.count(address, name), reader.pointer(checkedAdd(address, reader.pointerSize()))};
}

size_t methodDefinitionCount(const MetadataModel& metadata) {
    size_t count = 0;
    for (const auto& type : metadata.types) {
        if (type.methods.size() > std::numeric_limits<size_t>::max() - count) {
            fail("method-count-overflow", "Method definition count overflows size_t");
        }
        count += type.methods.size();
    }
    return count;
}

MetadataModel readNative(
    const BinaryImage& binary,
    const MetadataModel& input,
    uint64_t metadataRegistrationAddress,
    uint64_t codeRegistrationAddress,
    size_t pointerSize,
    Legacy19ReadResult& result) {
    if (input.version != 16.0 && input.version != 18.0) {
        fail("unsupported-model-version", "Legacy19 native registration requires a metadata 16 or 18 model");
    }
    result.profile = describeLegacy19Profile(static_cast<int32_t>(input.version));
    ImageReader reader(binary, pointerSize);
    const size_t metadataBytes = checkedSize(result.profile.metadataRegistrationPairs, pointerSize * 2, "metadata registration");
    reader.require(metadataRegistrationAddress, metadataBytes);

    const auto genericClasses = readPair(reader, metadataRegistrationAddress, 0, "generic classes");
    const auto genericInsts = readPair(reader, metadataRegistrationAddress, 1, "generic instantiations");
    const auto genericMethodTable = readPair(reader, metadataRegistrationAddress, 2, "generic method table");
    const auto types = readPair(reader, metadataRegistrationAddress, 3, "types");
    const auto methodSpecs = readPair(reader, metadataRegistrationAddress, 4, "method specs");
    NativePair methodReferences;
    if (result.profile.methodReferencesPair >= 0) {
        methodReferences = readPair(
            reader,
            metadataRegistrationAddress,
            static_cast<size_t>(result.profile.methodReferencesPair),
            "method references");
    }
    const auto fieldOffsets = readPair(reader, metadataRegistrationAddress, result.profile.fieldOffsetsPair, "field offsets");
    readPair(reader, metadataRegistrationAddress, result.profile.fieldOffsetsPair + 1, "type definition sizes");

    NativePair methodPointers;
    NativePair genericMethodPointers;
    NativePair invokerPointers;
    if (codeRegistrationAddress != 0) {
        reader.require(
            codeRegistrationAddress,
            checkedSize(result.profile.codeRegistrationPairs, pointerSize * 2, "code registration"));
        methodPointers = readPair(reader, codeRegistrationAddress, 0, "method pointers");
        readPair(reader, codeRegistrationAddress, 1, "delegate wrappers from native to managed");
        readPair(reader, codeRegistrationAddress, 2, "delegate wrappers from managed to native");
        readPair(reader, codeRegistrationAddress, 3, "marshaling functions");
        genericMethodPointers = readPair(reader, codeRegistrationAddress, 4, "generic method pointers");
        invokerPointers = readPair(reader, codeRegistrationAddress, 5, "invoker pointers");
        readPair(reader, codeRegistrationAddress, 6, "custom attribute generators");
    }

    MetadataModel metadata = input;
    metadata.metadataRegistrationAddress = metadataRegistrationAddress;
    metadata.codeRegistrationAddress = codeRegistrationAddress;
    result.registration.methodReferencesAddress = methodReferences.address;
    result.registration.methodReferencesCount = methodReferences.count;
    result.registration.methodReferences = reader.pointerTable(
        methodReferences.address,
        methodReferences.count,
        "method references");

    const auto methodPointerValues = reader.pointerTable(methodPointers.address, methodPointers.count, "method pointers");
    if (!methodPointerValues.empty()) {
        for (auto& [name, pointers] : metadata.methodPointersByImage) pointers = methodPointerValues;
    }
    for (auto& type : metadata.types) {
        for (auto& method : type.methods) {
            if (method.methodIndex < 0) continue;
            if (static_cast<size_t>(method.methodIndex) >= methodPointerValues.size()) {
                fail("global-method-index-out-of-bounds", "MethodDefinition.methodIndex is outside the global method pointer table");
            }
            method.address = methodPointerValues[static_cast<size_t>(method.methodIndex)];
        }
    }

    metadata.typeReferences = TypeTableReader(reader, types.address, types.count, metadata.types).read();
    applyTypeReferences(metadata);

    const size_t flatOffsetBytes = checkedSize(fieldOffsets.count, 4, "field offsets");
    if (flatOffsetBytes != 0) reader.require(fieldOffsets.address, flatOffsetBytes);
    size_t flatIndex = 0;
    for (auto& type : metadata.types) {
        for (auto& field : type.fields) {
            if (flatIndex >= fieldOffsets.count) fail("field-offsets-out-of-bounds", "Legacy flat fieldOffsets table is shorter than the field definitions");
            field.offset = reader.i32(checkedAdd(fieldOffsets.address, flatIndex * 4));
            if (field.token != 0) metadata.fieldOffsetsByToken.insert_or_assign(field.token, field.offset);
            ++flatIndex;
        }
    }

    metadata.genericInsts.clear();
    const auto instPointers = reader.pointerTable(genericInsts.address, genericInsts.count, "generic instantiations");
    metadata.genericInsts.reserve(instPointers.size());
    for (const uint64_t address : instPointers) {
        GenericInstModel inst;
        inst.address = address;
        if (address != 0) {
            reader.require(address, pointerSize * 2);
            const uint64_t count = reader.count(address, "generic instantiation");
            const uint64_t arguments = reader.pointer(checkedAdd(address, pointerSize));
            inst.typeAddresses = reader.pointerTable(arguments, count, "generic instantiation arguments");
        }
        metadata.genericInsts.push_back(std::move(inst));
    }

    metadata.genericClasses.clear();
    const auto classPointers = reader.pointerTable(genericClasses.address, genericClasses.count, "generic classes");
    metadata.genericClasses.reserve(classPointers.size());
    for (const uint64_t address : classPointers) {
        GenericClassModel genericClass;
        genericClass.address = address;
        if (address != 0) {
            reader.require(address, pointerSize * 4);
            const int64_t definition = reader.signedPointer(address);
            if (definition < 0 || static_cast<uint64_t>(definition) >= metadata.types.size()) {
                failAt("generic-class-definition-out-of-bounds", "Generic class definition index is invalid", address);
            }
            genericClass.definitionIndex = static_cast<int32_t>(definition);
            genericClass.classInstAddress = reader.pointer(checkedAdd(address, pointerSize));
            genericClass.methodInstAddress = reader.pointer(checkedAdd(address, pointerSize * 2));
            genericClass.cachedClassAddress = reader.pointer(checkedAdd(address, pointerSize * 3));
        }
        metadata.genericClasses.push_back(genericClass);
    }

    const size_t definitions = methodDefinitionCount(metadata);
    const size_t specsBytes = checkedSize(methodSpecs.count, 12, "method specs");
    if (specsBytes != 0) reader.require(methodSpecs.address, specsBytes);
    metadata.methodSpecs.clear();
    metadata.methodSpecs.reserve(static_cast<size_t>(methodSpecs.count));
    for (size_t index = 0; index < static_cast<size_t>(methodSpecs.count); ++index) {
        const uint64_t address = checkedAdd(methodSpecs.address, index * 12);
        GenericMethodSpecModel spec;
        spec.methodDefinitionIndex = reader.i32(address);
        spec.classInstIndex = reader.i32(checkedAdd(address, 4));
        spec.methodInstIndex = reader.i32(checkedAdd(address, 8));
        if (spec.methodDefinitionIndex < 0 || static_cast<size_t>(spec.methodDefinitionIndex) >= definitions) {
            failAt("method-spec-definition-out-of-bounds", "Generic method spec definition index is invalid", address);
        }
        const auto instAddress = [&](int32_t instIndex) {
            if (instIndex == -1) return uint64_t{0};
            if (instIndex < 0 || static_cast<size_t>(instIndex) >= metadata.genericInsts.size()) {
                fail("method-spec-inst-out-of-bounds", "Generic method spec instantiation index is invalid");
            }
            return metadata.genericInsts[static_cast<size_t>(instIndex)].address;
        };
        spec.classInstAddress = instAddress(spec.classInstIndex);
        spec.methodInstAddress = instAddress(spec.methodInstIndex);
        metadata.methodSpecs.push_back(spec);
    }

    metadata.genericMethodPointers = reader.pointerTable(
        genericMethodPointers.address,
        genericMethodPointers.count,
        "generic method pointers");
    metadata.invokerPointers = reader.pointerTable(invokerPointers.address, invokerPointers.count, "invoker pointers");
    const size_t genericBytes = checkedSize(genericMethodTable.count, 12, "generic method table");
    if (genericBytes != 0) reader.require(genericMethodTable.address, genericBytes);
    metadata.genericMethodTable.clear();
    metadata.genericMethodTable.reserve(static_cast<size_t>(genericMethodTable.count));
    for (size_t index = 0; index < static_cast<size_t>(genericMethodTable.count); ++index) {
        const uint64_t address = checkedAdd(genericMethodTable.address, index * 12);
        GenericMethodPointerModel mapping;
        mapping.genericMethodIndex = reader.i32(address);
        mapping.methodIndex = reader.i32(checkedAdd(address, 4));
        mapping.invokerIndex = reader.i32(checkedAdd(address, 8));
        if (mapping.genericMethodIndex < 0 || static_cast<size_t>(mapping.genericMethodIndex) >= metadata.methodSpecs.size()) {
            failAt("generic-method-index-out-of-bounds", "Generic method table spec index is invalid", address);
        }
        const auto pointerAt = [](const std::vector<uint64_t>& pointers, int32_t pointerIndex) {
            if (pointerIndex == -1) return uint64_t{0};
            if (pointerIndex < 0 || static_cast<size_t>(pointerIndex) >= pointers.size()) {
                fail("native-pointer-index-out-of-bounds", "Generic method pointer or invoker index is invalid");
            }
            return pointers[static_cast<size_t>(pointerIndex)];
        };
        mapping.methodPointer = pointerAt(metadata.genericMethodPointers, mapping.methodIndex);
        mapping.invokerPointer = pointerAt(metadata.invokerPointers, mapping.invokerIndex);
        const auto& spec = metadata.methodSpecs[static_cast<size_t>(mapping.genericMethodIndex)];
        mapping.classInstAddress = spec.classInstAddress;
        mapping.methodInstAddress = spec.methodInstAddress;
        metadata.genericMethodTable.push_back(mapping);
    }
    return metadata;
}

Legacy19ReadResult failureResult(Legacy19ReadResult result, const Error& error) {
    addError(result, error);
    return result;
}

} // namespace

bool Legacy19ReadResult::ok() const noexcept {
    return std::none_of(diagnostics.begin(), diagnostics.end(), [](const Legacy19Diagnostic& diagnostic) {
        return diagnostic.severity == Legacy19DiagnosticSeverity::Error;
    });
}

std::string Legacy19ReadResult::diagnosticText() const {
    std::ostringstream stream;
    for (const auto& diagnostic : diagnostics) {
        stream << '[' << toString(diagnostic.severity) << "] " << diagnostic.code << ": " << diagnostic.message;
        if (diagnostic.hasOffset) stream << " (offset 0x" << std::hex << diagnostic.offset << std::dec << ')';
        stream << '\n';
    }
    return stream.str();
}

Legacy19Profile describeLegacy19Profile(int32_t metadataVersion) noexcept {
    Legacy19Profile profile;
    profile.version = metadataVersion;
    profile.supported = metadataVersion == 16 || metadataVersion == 18;
    if (!profile.supported) return profile;
    profile.headerSize = legacyHeaderSize;
    profile.metadataUsageHeaderSize = metadataVersion == 18 ? legacyUsageHeaderSize : 0;
    profile.typeDefinitionStride = 108;
    profile.methodDefinitionStride = 56;
    profile.parameterDefinitionStride = 16;
    profile.fieldDefinitionStride = 12;
    profile.imageDefinitionStride = 20;
    profile.assemblyDefinitionStride = 60;
    profile.metadataRegistrationPairs = metadataVersion == 16 ? 8 : 7;
    profile.codeRegistrationPairs = 7;
    profile.fieldOffsetsPair = metadataVersion == 16 ? 6 : 5;
    profile.methodReferencesPair = metadataVersion == 16 ? 5 : -1;
    profile.metadataUsage18 = metadataVersion == 18;
    return profile;
}

std::string describeLegacy19Profile(const Legacy19Profile& profile) {
    if (!profile.supported) return "metadata " + std::to_string(profile.version) + ": unsupported (expected 16 or 18)";
    std::ostringstream stream;
    stream << "metadata " << profile.version << ": header=" << profile.headerSize
           << ", type=" << profile.typeDefinitionStride << ", method=" << profile.methodDefinitionStride
           << ", parameter=" << profile.parameterDefinitionStride << ", field=" << profile.fieldDefinitionStride
           << ", image=" << profile.imageDefinitionStride << ", assembly=" << profile.assemblyDefinitionStride
           << ", metadataPairs=" << profile.metadataRegistrationPairs
           << ", codePairs=" << profile.codeRegistrationPairs
           << ", fieldOffsetsPair=" << profile.fieldOffsetsPair;
    if (profile.methodReferencesPair >= 0) stream << ", methodReferencesPair=" << profile.methodReferencesPair;
    if (profile.metadataUsage18) stream << ", optionalMetadataUsageHeader=" << profile.metadataUsageHeaderSize;
    return stream.str();
}

const char* toString(Legacy19DiagnosticSeverity severity) noexcept {
    switch (severity) {
    case Legacy19DiagnosticSeverity::Info: return "info";
    case Legacy19DiagnosticSeverity::Warning: return "warning";
    case Legacy19DiagnosticSeverity::Error: return "error";
    }
    return "error";
}

Legacy19Reader::Legacy19Reader(size_t pointerSize) : pointerSize_(pointerSize) {
    if (pointerSize != 0 && pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 0, 4, or 8");
    }
}

Legacy19Profile Legacy19Reader::describe(int32_t metadataVersion) const noexcept {
    return describeLegacy19Profile(metadataVersion);
}

Legacy19ReadResult Legacy19Reader::read(const std::vector<uint8_t>& globalMetadata) const {
    return read(globalMetadata.data(), globalMetadata.size());
}

Legacy19ReadResult Legacy19Reader::read(const uint8_t* globalMetadata, size_t size) const {
    Legacy19ReadResult result;
    try {
        result.metadata = readGlobal(globalMetadata, size, result);
    } catch (const Error& error) {
        return failureResult(std::move(result), error);
    }
    return result;
}

Legacy19ReadResult Legacy19Reader::read(
    const BinaryImage& binary,
    const MetadataModel& metadata,
    uint64_t metadataRegistrationAddress,
    uint64_t codeRegistrationAddress) const {
    Legacy19ReadResult result;
    try {
        result.metadata = readNative(
            binary,
            metadata,
            metadataRegistrationAddress,
            codeRegistrationAddress,
            inferredPointerSize(binary, pointerSize_),
            result);
    } catch (const Error& error) {
        return failureResult(std::move(result), error);
    }
    return result;
}

Legacy19ReadResult Legacy19Reader::read(
    const std::vector<uint8_t>& globalMetadata,
    const BinaryImage& binary,
    uint64_t metadataRegistrationAddress,
    uint64_t codeRegistrationAddress) const {
    Legacy19ReadResult result = read(globalMetadata);
    if (!result.ok()) return result;
    Legacy19ReadResult native = read(binary, result.metadata, metadataRegistrationAddress, codeRegistrationAddress);
    native.profile = result.profile;
    return native;
}

} // namespace il2cpprec
