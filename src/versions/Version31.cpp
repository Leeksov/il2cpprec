#include <il2cpprec/versions/Version31.hpp>

#include <bit>
#include <cstring>
#include <limits>
#include <unordered_set>
#include <utility>

namespace il2cpprec::versions {
namespace {

constexpr uint32_t metadataSanity = 0xFAB11BAF;
constexpr int32_t metadataVersion = 31;
constexpr size_t methodsHeaderOffset = 48;
constexpr size_t assembliesHeaderOffset = 176;
constexpr size_t attributeDataHeaderOffset = 200;
constexpr size_t attributeDataRangesHeaderOffset = 208;
constexpr size_t maxValueNesting = 64;

constexpr uint8_t typeBoolean = 0x02;
constexpr uint8_t typeChar = 0x03;
constexpr uint8_t typeI1 = 0x04;
constexpr uint8_t typeU1 = 0x05;
constexpr uint8_t typeI2 = 0x06;
constexpr uint8_t typeU2 = 0x07;
constexpr uint8_t typeI4 = 0x08;
constexpr uint8_t typeU4 = 0x09;
constexpr uint8_t typeI8 = 0x0a;
constexpr uint8_t typeU8 = 0x0b;
constexpr uint8_t typeR4 = 0x0c;
constexpr uint8_t typeR8 = 0x0d;
constexpr uint8_t typeString = 0x0e;
constexpr uint8_t typeObject = 0x1c;
constexpr uint8_t typeSzArray = 0x1d;
constexpr uint8_t typeEnum = 0x55;
constexpr uint8_t typeTypeIndex = 0xff;

class BoundedReader {
public:
    BoundedReader() = default;

    BoundedReader(const uint8_t* data, size_t size)
        : data_(data), size_(size) {
    }

    size_t position() const { return position_; }
    size_t remaining() const { return size_ - position_; }

    bool readU8(uint8_t& value) {
        if (!require(1)) return false;
        value = data_[position_++];
        return true;
    }

    bool readU16(uint16_t& value) {
        if (!require(2)) return false;
        value = static_cast<uint16_t>(data_[position_]) |
            static_cast<uint16_t>(static_cast<uint16_t>(data_[position_ + 1]) << 8);
        position_ += 2;
        return true;
    }

    bool readU32(uint32_t& value) {
        if (!require(4)) return false;
        value = static_cast<uint32_t>(data_[position_]) |
            (static_cast<uint32_t>(data_[position_ + 1]) << 8) |
            (static_cast<uint32_t>(data_[position_ + 2]) << 16) |
            (static_cast<uint32_t>(data_[position_ + 3]) << 24);
        position_ += 4;
        return true;
    }

    bool readU64(uint64_t& value) {
        if (!require(8)) return false;
        value = 0;
        for (size_t index = 0; index < 8; ++index) {
            value |= static_cast<uint64_t>(data_[position_ + index]) << (index * 8);
        }
        position_ += 8;
        return true;
    }

    bool readI8(int8_t& value) {
        uint8_t raw = 0;
        if (!readU8(raw)) return false;
        value = std::bit_cast<int8_t>(raw);
        return true;
    }

    bool readI16(int16_t& value) {
        uint16_t raw = 0;
        if (!readU16(raw)) return false;
        value = std::bit_cast<int16_t>(raw);
        return true;
    }

    bool readI32(int32_t& value) {
        uint32_t raw = 0;
        if (!readU32(raw)) return false;
        value = std::bit_cast<int32_t>(raw);
        return true;
    }

    bool readI64(int64_t& value) {
        uint64_t raw = 0;
        if (!readU64(raw)) return false;
        value = std::bit_cast<int64_t>(raw);
        return true;
    }

    bool readCompressedUInt(uint32_t& value) {
        uint8_t first = 0;
        if (!readU8(first)) return false;
        if (first < 128) {
            value = first;
            return true;
        }
        if (first == 240) return readU32(value);
        if (first == 255) {
            value = std::numeric_limits<uint32_t>::max();
            return true;
        }
        if (first == 254) {
            value = std::numeric_limits<uint32_t>::max() - 1;
            return true;
        }
        if ((first & 192) == 192) {
            uint8_t second = 0;
            uint8_t third = 0;
            uint8_t fourth = 0;
            if (!readU8(second) || !readU8(third) || !readU8(fourth)) return false;
            value = (static_cast<uint32_t>(first & 63) << 24) |
                (static_cast<uint32_t>(second) << 16) |
                (static_cast<uint32_t>(third) << 8) |
                fourth;
            return true;
        }
        uint8_t second = 0;
        if (!readU8(second)) return false;
        value = (static_cast<uint32_t>(first & 127) << 8) | second;
        return true;
    }

    bool readCompressedInt(int32_t& value) {
        uint32_t encoded = 0;
        if (!readCompressedUInt(encoded)) return false;
        if (encoded == std::numeric_limits<uint32_t>::max()) {
            value = std::numeric_limits<int32_t>::min();
            return true;
        }
        const bool negative = (encoded & 1) != 0;
        const uint32_t magnitude = encoded >> 1;
        value = negative
            ? -1 - static_cast<int32_t>(magnitude)
            : static_cast<int32_t>(magnitude);
        return true;
    }

    bool readString(size_t length, std::string& value) {
        if (!require(length)) return false;
        if (length == 0) {
            value.clear();
        } else {
            value.assign(reinterpret_cast<const char*>(data_ + position_), length);
        }
        position_ += length;
        return true;
    }

private:
    bool require(size_t amount) const {
        return position_ <= size_ && amount <= size_ - position_;
    }

    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t position_ = 0;
};

uint32_t loadU32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
        (static_cast<uint32_t>(data[1]) << 8) |
        (static_cast<uint32_t>(data[2]) << 16) |
        (static_cast<uint32_t>(data[3]) << 24);
}

int32_t loadI32(const uint8_t* data) {
    return std::bit_cast<int32_t>(loadU32(data));
}

uint16_t loadU16(const uint8_t* data) {
    return static_cast<uint16_t>(data[0]) |
        static_cast<uint16_t>(static_cast<uint16_t>(data[1]) << 8);
}

uint64_t loadU64(const uint8_t* data) {
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= static_cast<uint64_t>(data[index]) << (index * 8);
    }
    return value;
}

bool sectionReader(
    const uint8_t* data,
    size_t size,
    Version31Section section,
    BoundedReader& output) {
    if (section.size < 0 || (data == nullptr && size != 0)) return false;
    const auto offset = static_cast<size_t>(section.offset);
    const auto byteSize = static_cast<size_t>(section.size);
    if (offset > size || byteSize > size - offset) return false;
    output = BoundedReader(data == nullptr ? nullptr : data + offset, byteSize);
    return true;
}

bool tableCount(
    const uint8_t* data,
    size_t size,
    Version31Section section,
    size_t stride,
    size_t& count) {
    BoundedReader reader;
    if (!sectionReader(data, size, section, reader)) return false;
    const auto byteSize = static_cast<size_t>(section.size);
    if (byteSize % stride != 0) return false;
    count = byteSize / stride;
    return true;
}

Version31Section readHeaderSection(const uint8_t* data, size_t offset) {
    return Version31Section{loadU32(data + offset), loadI32(data + offset + 4)};
}

bool resolveEnumUnderlyingType(
    int32_t enumTypeIndex,
    const Version31EnumUnderlyingTypeResolver& resolver,
    uint8_t& underlyingType) {
    underlyingType = typeI4;
    if (resolver) {
        const auto resolved = resolver(enumTypeIndex);
        if (!resolved) return false;
        underlyingType = *resolved;
    }
    switch (underlyingType) {
        case typeI1:
        case typeU1:
        case typeI2:
        case typeU2:
        case typeI4:
        case typeU4:
        case typeI8:
        case typeU8:
            return true;
        default:
            return false;
    }
}

bool readValueOfType(
    BoundedReader& reader,
    uint8_t type,
    const Version31EnumUnderlyingTypeResolver& resolver,
    Version31AttributeValue& output,
    size_t depth);

bool readScalar(
    BoundedReader& reader,
    uint8_t type,
    Version31AttributeValue& output) {
    switch (type) {
        case typeBoolean: {
            uint8_t value = 0;
            if (!reader.readU8(value)) return false;
            output.kind = Version31AttributeValueKind::Boolean;
            output.value = value != 0;
            return true;
        }
        case typeChar: {
            uint16_t value = 0;
            if (!reader.readU16(value)) return false;
            output.kind = Version31AttributeValueKind::Char;
            output.value = value;
            return true;
        }
        case typeI1: {
            int8_t value = 0;
            if (!reader.readI8(value)) return false;
            output.kind = Version31AttributeValueKind::Int8;
            output.value = value;
            return true;
        }
        case typeU1: {
            uint8_t value = 0;
            if (!reader.readU8(value)) return false;
            output.kind = Version31AttributeValueKind::UInt8;
            output.value = value;
            return true;
        }
        case typeI2: {
            int16_t value = 0;
            if (!reader.readI16(value)) return false;
            output.kind = Version31AttributeValueKind::Int16;
            output.value = value;
            return true;
        }
        case typeU2: {
            uint16_t value = 0;
            if (!reader.readU16(value)) return false;
            output.kind = Version31AttributeValueKind::UInt16;
            output.value = value;
            return true;
        }
        case typeI4: {
            int32_t value = 0;
            if (!reader.readCompressedInt(value)) return false;
            output.kind = Version31AttributeValueKind::Int32;
            output.value = value;
            return true;
        }
        case typeU4: {
            uint32_t value = 0;
            if (!reader.readCompressedUInt(value)) return false;
            output.kind = Version31AttributeValueKind::UInt32;
            output.value = value;
            return true;
        }
        case typeI8: {
            int64_t value = 0;
            if (!reader.readI64(value)) return false;
            output.kind = Version31AttributeValueKind::Int64;
            output.value = value;
            return true;
        }
        case typeU8: {
            uint64_t value = 0;
            if (!reader.readU64(value)) return false;
            output.kind = Version31AttributeValueKind::UInt64;
            output.value = value;
            return true;
        }
        case typeR4: {
            uint32_t raw = 0;
            if (!reader.readU32(raw)) return false;
            output.kind = Version31AttributeValueKind::Float;
            output.value = std::bit_cast<float>(raw);
            return true;
        }
        case typeR8: {
            uint64_t raw = 0;
            if (!reader.readU64(raw)) return false;
            output.kind = Version31AttributeValueKind::Double;
            output.value = std::bit_cast<double>(raw);
            return true;
        }
        default:
            return false;
    }
}

bool readArray(
    BoundedReader& reader,
    const Version31EnumUnderlyingTypeResolver& resolver,
    Version31AttributeValue& output,
    size_t depth) {
    int32_t length = 0;
    if (!reader.readCompressedInt(length)) return false;
    output.kind = Version31AttributeValueKind::Array;
    if (length == -1) {
        output.isNull = true;
        output.value = Version31AttributeValue::Array{};
        return true;
    }
    if (length < 0) return false;

    uint8_t elementType = 0;
    if (!reader.readU8(elementType)) return false;
    output.elementType = elementType;
    uint8_t storedElementType = elementType;
    if (elementType == typeEnum) {
        if (!reader.readCompressedInt(output.enumTypeIndex) || output.enumTypeIndex < 0 ||
            !resolveEnumUnderlyingType(output.enumTypeIndex, resolver, storedElementType)) {
            return false;
        }
    }
    output.underlyingType = storedElementType;

    uint8_t prefixed = 0;
    if (!reader.readU8(prefixed)) return false;
    output.elementsAreTypePrefixed = prefixed != 0;
    if (output.elementsAreTypePrefixed && elementType != typeObject) return false;
    if (static_cast<size_t>(length) > reader.remaining()) return false;

    Version31AttributeValue::Array elements;
    elements.reserve(static_cast<size_t>(length));
    for (int32_t index = 0; index < length; ++index) {
        uint8_t actualType = storedElementType;
        if (output.elementsAreTypePrefixed && !reader.readU8(actualType)) return false;
        Version31AttributeValue element;
        if (!readValueOfType(reader, actualType, resolver, element, depth + 1)) return false;
        if (!output.elementsAreTypePrefixed && elementType == typeEnum) {
            element.kind = Version31AttributeValueKind::Enum;
            element.type = typeEnum;
            element.underlyingType = storedElementType;
            element.enumTypeIndex = output.enumTypeIndex;
        }
        elements.push_back(std::move(element));
    }
    output.value = std::move(elements);
    return true;
}

bool readValueOfType(
    BoundedReader& reader,
    uint8_t type,
    const Version31EnumUnderlyingTypeResolver& resolver,
    Version31AttributeValue& output,
    size_t depth) {
    if (depth > maxValueNesting) return false;
    output = Version31AttributeValue{};
    output.type = type;
    if (type == typeString) {
        int32_t length = 0;
        if (!reader.readCompressedInt(length) || length < -1) return false;
        output.kind = Version31AttributeValueKind::String;
        if (length == -1) {
            output.isNull = true;
            return true;
        }
        std::string value;
        if (!reader.readString(static_cast<size_t>(length), value)) return false;
        output.value = std::move(value);
        return true;
    }
    if (type == typeTypeIndex) {
        int32_t typeIndex = 0;
        if (!reader.readCompressedInt(typeIndex) || typeIndex < -1) return false;
        output.kind = Version31AttributeValueKind::TypeOf;
        output.typeIndex = typeIndex;
        output.isNull = typeIndex == -1;
        return true;
    }
    if (type == typeSzArray) return readArray(reader, resolver, output, depth);
    if (type == typeEnum) {
        if (!reader.readCompressedInt(output.enumTypeIndex) || output.enumTypeIndex < 0) return false;
        uint8_t underlyingType = 0;
        if (!resolveEnumUnderlyingType(output.enumTypeIndex, resolver, underlyingType)) return false;
        output.underlyingType = underlyingType;
        if (!readScalar(reader, underlyingType, output)) return false;
        output.kind = Version31AttributeValueKind::Enum;
        output.type = typeEnum;
        return true;
    }
    return readScalar(reader, type, output);
}

bool readValue(
    BoundedReader& reader,
    const Version31EnumUnderlyingTypeResolver& resolver,
    Version31AttributeValue& output,
    size_t depth = 0) {
    uint8_t type = 0;
    return reader.readU8(type) && readValueOfType(reader, type, resolver, output, depth);
}

bool readNamedMembers(
    BoundedReader& reader,
    uint32_t count,
    Version31AttributeNamedMember::Kind kind,
    const Version31EnumUnderlyingTypeResolver& resolver,
    std::vector<Version31AttributeNamedMember>& output) {
    if (count > reader.remaining()) return false;
    output.reserve(count);
    for (uint32_t index = 0; index < count; ++index) {
        Version31AttributeNamedMember member;
        member.kind = kind;
        if (!readValue(reader, resolver, member.value)) return false;
        int32_t encodedIndex = 0;
        if (!reader.readCompressedInt(encodedIndex)) return false;
        if (encodedIndex < 0) {
            member.memberIndex = -(encodedIndex + 1);
            uint32_t declaringTypeIndex = 0;
            if (!reader.readCompressedUInt(declaringTypeIndex) ||
                declaringTypeIndex > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
                return false;
            }
            member.declaringTypeIndex = declaringTypeIndex;
        } else {
            member.memberIndex = encodedIndex;
        }
        output.push_back(std::move(member));
    }
    return true;
}

bool readAttribute(
    BoundedReader& reader,
    const Version31EnumUnderlyingTypeResolver& resolver,
    Version31Attribute& output) {
    uint32_t constructorCount = 0;
    uint32_t fieldCount = 0;
    uint32_t propertyCount = 0;
    if (!reader.readCompressedUInt(constructorCount) ||
        !reader.readCompressedUInt(fieldCount) ||
        !reader.readCompressedUInt(propertyCount)) {
        return false;
    }
    if (constructorCount > reader.remaining()) return false;
    output.constructorArguments.reserve(constructorCount);
    for (uint32_t index = 0; index < constructorCount; ++index) {
        Version31AttributeValue value;
        if (!readValue(reader, resolver, value)) return false;
        output.constructorArguments.push_back(std::move(value));
    }
    return readNamedMembers(reader, fieldCount, Version31AttributeNamedMember::Kind::Field, resolver, output.fields) &&
        readNamedMembers(reader, propertyCount, Version31AttributeNamedMember::Kind::Property, resolver, output.properties);
}

bool readAttributeBlob(
    BoundedReader& reader,
    const Version31EnumUnderlyingTypeResolver& resolver,
    std::vector<Version31Attribute>& output) {
    if (reader.remaining() == 0) return true;
    uint32_t attributeCount = 0;
    if (!reader.readCompressedUInt(attributeCount) || attributeCount > reader.remaining() / 4) return false;

    std::vector<uint32_t> constructorIndices;
    constructorIndices.reserve(attributeCount);
    for (uint32_t index = 0; index < attributeCount; ++index) {
        uint32_t constructorIndex = 0;
        if (!reader.readU32(constructorIndex)) return false;
        constructorIndices.push_back(constructorIndex);
    }
    if (attributeCount > reader.remaining() / 3) return false;

    output.reserve(attributeCount);
    for (const uint32_t constructorIndex : constructorIndices) {
        Version31Attribute attribute;
        attribute.constructorIndex = constructorIndex;
        if (!readAttribute(reader, resolver, attribute)) return false;
        output.push_back(std::move(attribute));
    }
    return reader.remaining() == 0;
}

} // namespace

Version31::Version31(const uint8_t* data, size_t size)
    : data_(data), size_(size) {
}

Version31::Version31(const std::vector<uint8_t>& data)
    : Version31(data.data(), data.size()) {
}

bool Version31::supports(int32_t rawVersion) noexcept {
    return rawVersion == metadataVersion;
}

void Version31::setEnumUnderlyingTypeResolver(Version31EnumUnderlyingTypeResolver resolver) {
    enumUnderlyingTypeResolver_ = std::move(resolver);
}

bool Version31::validHeader() const {
    return data_ != nullptr && size_ >= headerSize && loadU32(data_) == metadataSanity &&
        loadI32(data_ + 4) == metadataVersion;
}

Version31Section Version31::methodsSection() const {
    return validHeader() ? readHeaderSection(data_, methodsHeaderOffset) : Version31Section{};
}

Version31Section Version31::assembliesSection() const {
    return validHeader() ? readHeaderSection(data_, assembliesHeaderOffset) : Version31Section{};
}

Version31Section Version31::attributeDataSection() const {
    return validHeader() ? readHeaderSection(data_, attributeDataHeaderOffset) : Version31Section{};
}

Version31Section Version31::attributeDataRangesSection() const {
    return validHeader() ? readHeaderSection(data_, attributeDataRangesHeaderOffset) : Version31Section{};
}

std::optional<Version31Metadata> Version31::read() const {
    if (!validHeader()) return std::nullopt;
    Version31Metadata result;
    if (!readMethods(result.methods) || !readAssemblies(result.assemblies) || !readAttributes(result.attributes)) {
        return std::nullopt;
    }
    return result;
}

bool Version31::readMethods(std::vector<Version31MethodDefinition>& output) const {
    return validHeader() && readMethods(data_, size_, methodsSection(), output);
}

bool Version31::readAssemblies(std::vector<Version31AssemblyDefinition>& output) const {
    return validHeader() && readAssemblies(data_, size_, assembliesSection(), output);
}

bool Version31::readAttributes(std::vector<Version31AttributeBlob>& output) const {
    return validHeader() && readAttributes(
        data_, size_, attributeDataSection(), attributeDataRangesSection(), output, enumUnderlyingTypeResolver_);
}

bool Version31::readMethods(
    const uint8_t* data,
    size_t size,
    Version31Section section,
    std::vector<Version31MethodDefinition>& output) {
    size_t count = 0;
    if (!tableCount(data, size, section, methodDefinitionStride, count)) return false;
    std::vector<Version31MethodDefinition> result;
    result.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        const uint8_t* record = data + section.offset + index * methodDefinitionStride;
        Version31MethodDefinition method;
        method.nameIndex = loadU32(record);
        method.declaringTypeIndex = loadI32(record + 4);
        method.returnTypeIndex = loadI32(record + 8);
        method.returnParameterToken = loadU32(record + returnParameterTokenOffset);
        method.parameterStart = loadI32(record + 16);
        method.genericContainerIndex = loadI32(record + 20);
        method.token = loadU32(record + 24);
        method.flags = loadU16(record + 28);
        method.iflags = loadU16(record + 30);
        method.slot = loadU16(record + 32);
        method.parameterCount = loadU16(record + 34);
        result.push_back(method);
    }
    output = std::move(result);
    return true;
}

bool Version31::readAssemblies(
    const uint8_t* data,
    size_t size,
    Version31Section section,
    std::vector<Version31AssemblyDefinition>& output) {
    size_t count = 0;
    if (!tableCount(data, size, section, assemblyDefinitionStride, count)) return false;
    std::vector<Version31AssemblyDefinition> result;
    result.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        const uint8_t* record = data + section.offset + index * assemblyDefinitionStride;
        Version31AssemblyDefinition assembly;
        assembly.imageIndex = loadI32(record);
        assembly.token = loadU32(record + 4);
        assembly.referencedAssemblyStart = loadI32(record + 8);
        assembly.referencedAssemblyCount = loadI32(record + 12);
        const uint8_t* name = record + 16;
        assembly.name.nameIndex = loadI32(name);
        assembly.name.cultureIndex = loadI32(name + 4);
        assembly.name.publicKeyIndex = loadI32(name + 8);
        assembly.name.hashAlgorithm = loadU32(name + 12);
        assembly.name.hashLength = loadI32(name + 16);
        assembly.name.flags = loadU32(name + 20);
        assembly.name.majorVersion = loadI32(name + 24);
        assembly.name.minorVersion = loadI32(name + 28);
        assembly.name.buildNumber = loadI32(name + 32);
        assembly.name.revisionNumber = loadI32(name + 36);
        assembly.name.publicKeyToken = loadU64(name + 40);
        result.push_back(assembly);
    }
    output = std::move(result);
    return true;
}

bool Version31::readAttributes(
    const uint8_t* data,
    size_t size,
    Version31Section attributeData,
    Version31Section ranges,
    std::vector<Version31AttributeBlob>& output,
    const Version31EnumUnderlyingTypeResolver& enumUnderlyingTypeResolver) {
    BoundedReader dataReader;
    BoundedReader rangeReader;
    if (!sectionReader(data, size, attributeData, dataReader) ||
        !sectionReader(data, size, ranges, rangeReader)) {
        return false;
    }
    const size_t rangeBytes = static_cast<size_t>(ranges.size);
    if (rangeBytes % attributeDataRangeStride != 0) return false;
    const size_t rangeCount = rangeBytes / attributeDataRangeStride;
    if (rangeCount == 0) return attributeData.size == 0;

    struct Range {
        uint32_t token;
        uint32_t start;
    };
    std::vector<Range> entries;
    entries.reserve(rangeCount);
    uint32_t previousStart = 0;
    for (size_t index = 0; index < rangeCount; ++index) {
        uint32_t token = 0;
        uint32_t start = 0;
        if (!rangeReader.readU32(token) || !rangeReader.readU32(start)) return false;
        if ((index == 0 && start != 0) || start < previousStart ||
            start > static_cast<uint32_t>(attributeData.size)) {
            return false;
        }
        previousStart = start;
        entries.push_back(Range{token, start});
    }
    if (entries.back().start != static_cast<uint32_t>(attributeData.size)) return false;

    std::vector<Version31AttributeBlob> result;
    result.reserve(rangeCount - 1);
    std::unordered_set<uint32_t> seenTokens;
    for (size_t index = 0; index + 1 < entries.size(); ++index) {
        if (!seenTokens.insert(entries[index].token).second) continue;
        const size_t start = entries[index].start;
        const size_t end = entries[index + 1].start;
        BoundedReader blobReader(
            data == nullptr ? nullptr : data + attributeData.offset + start,
            end - start);
        Version31AttributeBlob blob;
        blob.token = entries[index].token;
        blob.startOffset = entries[index].start;
        blob.endOffset = entries[index + 1].start;
        if (!readAttributeBlob(blobReader, enumUnderlyingTypeResolver, blob.attributes)) return false;
        result.push_back(std::move(blob));
    }
    output = std::move(result);
    return true;
}

} // namespace il2cpprec::versions
