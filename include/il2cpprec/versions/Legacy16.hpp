#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

struct Legacy16Profile {
    int32_t version = 0;
    bool supported = false;
    size_t headerSize = 0;
    size_t metadataUsageHeaderSize = 0;
    size_t typeDefinitionStride = 0;
    size_t methodDefinitionStride = 0;
    size_t parameterDefinitionStride = 0;
    size_t fieldDefinitionStride = 0;
    size_t imageDefinitionStride = 0;
    size_t assemblyDefinitionStride = 0;
    size_t metadataRegistrationPairs = 0;
    size_t codeRegistrationPairs = 0;
    size_t fieldOffsetsPair = 0;
    int32_t methodReferencesPair = -1;
    bool metadataUsage18 = false;
};

enum class Legacy16DiagnosticSeverity {
    Info,
    Warning,
    Error
};

struct Legacy16Diagnostic {
    Legacy16DiagnosticSeverity severity = Legacy16DiagnosticSeverity::Error;
    std::string code;
    std::string message;
    uint64_t offset = 0;
    bool hasOffset = false;
};

struct Legacy16NativeRegistration {
    uint64_t methodReferencesAddress = 0;
    uint64_t methodReferencesCount = 0;
    std::vector<uint64_t> methodReferences;
};

struct Legacy16ReadResult {
    MetadataModel metadata;
    Legacy16Profile profile;
    Legacy16NativeRegistration registration;
    std::vector<Legacy16Diagnostic> diagnostics;

    bool ok() const noexcept;
    std::string diagnosticText() const;
};

Legacy16Profile describeLegacy16Profile(int32_t metadataVersion) noexcept;
std::string describeLegacy16Profile(const Legacy16Profile& profile);
const char* toString(Legacy16DiagnosticSeverity severity) noexcept;

class Legacy16Reader {
public:
    explicit Legacy16Reader(size_t pointerSize = 0);

    Legacy16Profile describe(int32_t metadataVersion) const noexcept;

    Legacy16ReadResult read(const std::vector<uint8_t>& globalMetadata) const;
    Legacy16ReadResult read(const uint8_t* globalMetadata, size_t size) const;

    Legacy16ReadResult read(
        const BinaryImage& binary,
        const MetadataModel& metadata,
        uint64_t metadataRegistrationAddress,
        uint64_t codeRegistrationAddress = 0) const;

    Legacy16ReadResult read(
        const std::vector<uint8_t>& globalMetadata,
        const BinaryImage& binary,
        uint64_t metadataRegistrationAddress,
        uint64_t codeRegistrationAddress = 0) const;

private:
    size_t pointerSize_;
};

} // namespace il2cpprec
