#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

enum class CustomAttributeValueKind : uint8_t {
    Boolean = 0x02,
    Char = 0x03,
    I1 = 0x04,
    U1 = 0x05,
    I2 = 0x06,
    U2 = 0x07,
    I4 = 0x08,
    U4 = 0x09,
    I8 = 0x0a,
    U8 = 0x0b,
    R4 = 0x0c,
    R8 = 0x0d,
    String = 0x0e,
    Enum = 0x55,
    Type = 0xff
};

using CustomAttributeScalar = std::variant<
    std::monostate,
    bool,
    char16_t,
    int8_t,
    uint8_t,
    int16_t,
    uint16_t,
    int32_t,
    uint32_t,
    int64_t,
    uint64_t,
    float,
    double,
    std::string>;

struct CustomAttributeValue {
    CustomAttributeValueKind kind = CustomAttributeValueKind::I4;
    CustomAttributeScalar value;
    std::optional<CustomAttributeValueKind> enumUnderlyingKind;
    std::optional<uint32_t> typeIndex;
    std::string typeName;

    bool isNull() const noexcept;
};

enum class CustomAttributeNamedKind : uint8_t {
    Field,
    Property
};

struct CustomAttributeNamedArgument {
    CustomAttributeNamedKind kind = CustomAttributeNamedKind::Field;
    std::string name;
    int32_t memberIndex = -1;
    int32_t ownerTypeDefinitionIndex = -1;
    std::optional<uint32_t> ownerTypeReferenceIndex;
    CustomAttributeValue value;
    bool resolved = false;
};

struct EvaluatedCustomAttribute {
    uint32_t constructorIndex = 0;
    MethodModel constructor;
    int32_t attributeTypeDefinitionIndex = -1;
    std::string attributeTypeName;
    std::vector<CustomAttributeValue> constructorArguments;
    std::vector<CustomAttributeNamedArgument> namedArguments;
    size_t blobOffset = 0;
    size_t blobEnd = 0;
};

enum class CustomAttributeDiagnosticSeverity : uint8_t {
    Warning,
    Error
};

struct CustomAttributeDiagnostic {
    CustomAttributeDiagnosticSeverity severity = CustomAttributeDiagnosticSeverity::Error;
    std::string code;
    std::string message;
    std::optional<uint32_t> token;
    std::optional<size_t> imageIndex;
    std::optional<size_t> attributeIndex;
    std::optional<size_t> offset;
};

struct CustomAttributeEvaluationResult {
    std::vector<EvaluatedCustomAttribute> attributes;
    std::vector<CustomAttributeDiagnostic> diagnostics;
    bool complete = true;

    bool ok() const noexcept;
};

struct CustomAttributeDataRange {
    uint32_t token = 0;
    uint32_t startOffset = 0;
};

struct CustomAttributeTypeRange {
    uint32_t token = 0;
    int32_t start = 0;
    int32_t count = 0;
};

struct CustomAttributeProperty {
    int32_t typeDefinitionIndex = -1;
    std::string name;
    std::string type;
};

struct AttributeEvaluationInput {
    double version = 0;
    const MetadataModel* metadata = nullptr;
    std::span<const uint8_t> attributeData;
    std::span<const CustomAttributeDataRange> attributeDataRanges;
    std::span<const CustomAttributeTypeRange> attributeTypeRanges;
    std::span<const int32_t> attributeTypeIndices;
    std::span<const CustomAttributeProperty> properties;
};

struct AttributeEvaluatorOptions {
    size_t maxAttributes = 4096;
    size_t maxConstructorArguments = 1024;
    size_t maxNamedArguments = 4096;
    size_t maxTotalArguments = 16384;
    size_t maxStringLength = 16 * 1024 * 1024;
    size_t maxBlobSize = 64 * 1024 * 1024;
    size_t maxImageRanges = 1024 * 1024;
    size_t maxDiagnostics = 128;
};

class AttributeEvaluator {
public:
    explicit AttributeEvaluator(AttributeEvaluatorOptions options = {});

    static bool supports(double version) noexcept;

    CustomAttributeEvaluationResult evaluate(
        const AttributeEvaluationInput& input,
        uint32_t token,
        size_t imageIndex) const;

    CustomAttributeEvaluationResult evaluateBlob(
        const AttributeEvaluationInput& input,
        std::span<const uint8_t> blob) const;

    CustomAttributeEvaluationResult evaluateBlob(
        double version,
        const MetadataModel& metadata,
        std::span<const uint8_t> blob,
        std::span<const CustomAttributeProperty> properties = {}) const;

private:
    AttributeEvaluatorOptions options_;
};

} // namespace il2cpprec
