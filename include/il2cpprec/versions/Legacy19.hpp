#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

struct Legacy19Profile {
    int32_t version = 0;
    bool supported = false;
    size_t headerSize = 0;
    size_t typeDefinitionStride = 0;
    size_t methodDefinitionStride = 0;
    size_t parameterDefinitionStride = 0;
    size_t fieldDefinitionStride = 0;
    size_t eventDefinitionStride = 0;
    size_t propertyDefinitionStride = 0;
    size_t imageDefinitionStride = 0;
    size_t assemblyDefinitionStride = 0;
    size_t metadataRegistrationPairs = 0;
    size_t codeRegistrationPairs = 0;
    size_t fieldOffsetsPair = 0;
    size_t genericMethodPointersPair = 0;
    size_t invokerPointersPair = 0;
    size_t methodIndexOffset = 0;
    size_t invokerIndexOffset = 0;
    size_t methodTokenOffset = 0;
    size_t typeTokenOffset = 0;
    size_t fieldTokenOffset = 0;
    size_t imageTokenOffset = 0;
    bool referencedAssemblies = false;
};

struct Legacy19FieldLayout {
    size_t offset = 0;
    size_t size = 0;
};

struct Legacy19MethodInfoLayout {
    size_t size = 0;
    size_t alignment = 0;
    Legacy19FieldLayout methodPointer;
    Legacy19FieldLayout invokerMethod;
    Legacy19FieldLayout name;
    Legacy19FieldLayout declaringType;
    Legacy19FieldLayout returnType;
    Legacy19FieldLayout parameters;
    Legacy19FieldLayout rgctxData;
    Legacy19FieldLayout genericMethod;
    Legacy19FieldLayout customAttributeIndex;
    Legacy19FieldLayout token;
    Legacy19FieldLayout flags;
    Legacy19FieldLayout iflags;
    Legacy19FieldLayout slot;
    Legacy19FieldLayout parametersCount;
    Legacy19FieldLayout methodFlags;
};

struct Legacy19MethodInfo {
    uint64_t methodPointer = 0;
    uint64_t invokerMethod = 0;
    uint64_t name = 0;
    uint64_t declaringType = 0;
    uint64_t returnType = 0;
    uint64_t parameters = 0;
    uint64_t rgctxData = 0;
    uint64_t genericMethod = 0;
    int32_t customAttributeIndex = -1;
    uint32_t token = 0;
    uint16_t flags = 0;
    uint16_t iflags = 0;
    uint16_t slot = 0;
    uint8_t parametersCount = 0;
    uint8_t methodFlags = 0;
};

enum class Legacy19DiagnosticSeverity {
    Info,
    Warning,
    Error
};

struct Legacy19Diagnostic {
    Legacy19DiagnosticSeverity severity = Legacy19DiagnosticSeverity::Error;
    std::string code;
    std::string message;
    uint64_t offset = 0;
    bool hasOffset = false;
};

struct Legacy19NativeRegistration {
    uint64_t metadataUsagesAddress = 0;
    uint64_t metadataUsagesCount = 0;
    std::vector<uint64_t> metadataUsages;
};

struct Legacy19ReadResult {
    MetadataModel metadata;
    Legacy19Profile profile;
    Legacy19MethodInfoLayout methodInfo;
    Legacy19NativeRegistration registration;
    std::vector<Legacy19Diagnostic> diagnostics;

    bool ok() const noexcept;
    std::string diagnosticText() const;
};

Legacy19Profile describeLegacy19Profile(int32_t metadataVersion) noexcept;
std::string describeLegacy19Profile(const Legacy19Profile& profile);
Legacy19MethodInfoLayout makeLegacy19MethodInfoLayout(size_t pointerSize);
const char* toString(Legacy19DiagnosticSeverity severity) noexcept;

class Legacy19Reader {
public:
    explicit Legacy19Reader(size_t pointerSize = 0);

    static bool supports(double metadataVersion) noexcept;
    Legacy19Profile describe(int32_t metadataVersion) const noexcept;

    Legacy19ReadResult read(const std::vector<uint8_t>& globalMetadata) const;
    Legacy19ReadResult read(const uint8_t* globalMetadata, size_t size) const;

    Legacy19ReadResult read(
        const BinaryImage& binary,
        const MetadataModel& metadata,
        uint64_t metadataRegistrationAddress,
        uint64_t codeRegistrationAddress = 0) const;

    Legacy19ReadResult read(
        const std::vector<uint8_t>& globalMetadata,
        const BinaryImage& binary,
        uint64_t metadataRegistrationAddress,
        uint64_t codeRegistrationAddress = 0) const;

    Legacy19MethodInfo readMethodInfo(const BinaryImage& binary, uint64_t address) const;

private:
    size_t pointerSize_;
};

} // namespace il2cpprec
