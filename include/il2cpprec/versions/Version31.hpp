#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace il2cpprec::versions {

struct Version31Section {
    uint32_t offset = 0;
    int32_t size = 0;
};

struct Version31MethodDefinition {
    uint32_t nameIndex = 0;
    int32_t declaringTypeIndex = -1;
    int32_t returnTypeIndex = -1;
    uint32_t returnParameterToken = 0;
    int32_t parameterStart = -1;
    int32_t genericContainerIndex = -1;
    uint32_t token = 0;
    uint16_t flags = 0;
    uint16_t iflags = 0;
    uint16_t slot = 0;
    uint16_t parameterCount = 0;
};

struct Version31AssemblyNameDefinition {
    int32_t nameIndex = -1;
    int32_t cultureIndex = -1;
    int32_t publicKeyIndex = -1;
    uint32_t hashAlgorithm = 0;
    int32_t hashLength = 0;
    uint32_t flags = 0;
    int32_t majorVersion = 0;
    int32_t minorVersion = 0;
    int32_t buildNumber = 0;
    int32_t revisionNumber = 0;
    uint64_t publicKeyToken = 0;
};

struct Version31AssemblyDefinition {
    int32_t imageIndex = -1;
    uint32_t token = 0;
    int32_t referencedAssemblyStart = -1;
    int32_t referencedAssemblyCount = 0;
    Version31AssemblyNameDefinition name;
};

enum class Version31AttributeValueKind {
    Boolean,
    Char,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    String,
    Enum,
    Array,
    TypeOf
};

struct Version31AttributeValue {
    using Array = std::vector<Version31AttributeValue>;
    using Storage = std::variant<
        std::monostate,
        bool,
        uint16_t,
        int8_t,
        uint8_t,
        int16_t,
        int32_t,
        uint32_t,
        int64_t,
        uint64_t,
        float,
        double,
        std::string,
        Array>;

    Version31AttributeValueKind kind = Version31AttributeValueKind::Int32;
    uint8_t type = 0;
    uint8_t underlyingType = 0;
    uint8_t elementType = 0;
    bool isNull = false;
    bool elementsAreTypePrefixed = false;
    int32_t typeIndex = -1;
    int32_t enumTypeIndex = -1;
    Storage value;
};

struct Version31AttributeNamedMember {
    enum class Kind {
        Field,
        Property
    };

    Kind kind = Kind::Field;
    int32_t memberIndex = -1;
    std::optional<uint32_t> declaringTypeIndex;
    Version31AttributeValue value;
};

struct Version31Attribute {
    uint32_t constructorIndex = 0;
    std::vector<Version31AttributeValue> constructorArguments;
    std::vector<Version31AttributeNamedMember> fields;
    std::vector<Version31AttributeNamedMember> properties;
};

struct Version31AttributeBlob {
    uint32_t token = 0;
    uint32_t startOffset = 0;
    uint32_t endOffset = 0;
    std::vector<Version31Attribute> attributes;
};

struct Version31Metadata {
    std::vector<Version31MethodDefinition> methods;
    std::vector<Version31AssemblyDefinition> assemblies;
    std::vector<Version31AttributeBlob> attributes;
};

using Version31EnumUnderlyingTypeResolver = std::function<std::optional<uint8_t>(int32_t)>;

class Version31 {
public:
    static constexpr size_t headerSize = 256;
    static constexpr size_t methodDefinitionStride = 36;
    static constexpr size_t returnParameterTokenOffset = 12;
    static constexpr size_t assemblyDefinitionStride = 64;
    static constexpr size_t attributeDataRangeStride = 8;

    Version31(const uint8_t* data, size_t size);
    explicit Version31(const std::vector<uint8_t>& data);

    static bool supports(int32_t rawVersion) noexcept;

    void setEnumUnderlyingTypeResolver(Version31EnumUnderlyingTypeResolver resolver);

    bool validHeader() const;
    Version31Section methodsSection() const;
    Version31Section assembliesSection() const;
    Version31Section attributeDataSection() const;
    Version31Section attributeDataRangesSection() const;

    std::optional<Version31Metadata> read() const;
    bool readMethods(std::vector<Version31MethodDefinition>& output) const;
    bool readAssemblies(std::vector<Version31AssemblyDefinition>& output) const;
    bool readAttributes(std::vector<Version31AttributeBlob>& output) const;

    static bool readMethods(
        const uint8_t* data,
        size_t size,
        Version31Section section,
        std::vector<Version31MethodDefinition>& output);
    static bool readAssemblies(
        const uint8_t* data,
        size_t size,
        Version31Section section,
        std::vector<Version31AssemblyDefinition>& output);
    static bool readAttributes(
        const uint8_t* data,
        size_t size,
        Version31Section attributeData,
        Version31Section ranges,
        std::vector<Version31AttributeBlob>& output,
        const Version31EnumUnderlyingTypeResolver& enumUnderlyingTypeResolver = {});

private:
    const uint8_t* data_;
    size_t size_;
    Version31EnumUnderlyingTypeResolver enumUnderlyingTypeResolver_;
};

using Version31Reader = Version31;

} // namespace il2cpprec::versions

namespace il2cpprec {

using versions::Version31;
using versions::Version31AssemblyDefinition;
using versions::Version31AssemblyNameDefinition;
using versions::Version31Attribute;
using versions::Version31AttributeBlob;
using versions::Version31AttributeNamedMember;
using versions::Version31AttributeValue;
using versions::Version31AttributeValueKind;
using versions::Version31EnumUnderlyingTypeResolver;
using versions::Version31Metadata;
using versions::Version31MethodDefinition;
using versions::Version31Reader;
using versions::Version31Section;

} // namespace il2cpprec
