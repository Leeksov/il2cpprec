#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

enum class ProtectedMetadataTableId : size_t {
    StringLiteralData = 0,
    StringLiterals,
    Methods,
    Properties,
    Assemblies,
    Fields,
    Strings,
    Images,
    Types,
    Parameters,
    Count
};

enum class ProtectedMetadataCipher {
    Raw,
    XorSizePlus35ByIndex,
    XorNegativeSizeMinus35ByIndex
};

struct ProtectedMetadataTableProfile {
    size_t sourceHeaderOffset = 0;
    int64_t sourceAdjustment = 0;
    size_t sizeHeaderOffset = 0;
    size_t stride = 0;
    ProtectedMetadataCipher cipher = ProtectedMetadataCipher::Raw;
};

struct ProtectedMetadataTypeLayout {
    size_t nameIndexOffset = 0;
    size_t namespaceIndexOffset = 4;
    size_t parentIndexOffset = 8;
    size_t fieldStartOffset = 12;
    size_t methodStartOffset = 16;
    size_t fieldCountOffset = 20;
    size_t methodCountOffset = 22;
};

struct ProtectedMetadataProfile {
    static constexpr size_t tableCount = static_cast<size_t>(ProtectedMetadataTableId::Count);

    std::string name;
    size_t headerSize = 0x150;
    uint8_t headerKeyBase = 0xb5;
    std::array<ProtectedMetadataTableProfile, tableCount> tables{};
    std::optional<ProtectedMetadataTypeLayout> typeLayout;

    static ProtectedMetadataProfile researched();
};

enum class ProtectedMetadataDiagnosticSeverity {
    Info,
    Error
};

struct ProtectedMetadataDiagnostic {
    ProtectedMetadataDiagnosticSeverity severity = ProtectedMetadataDiagnosticSeverity::Error;
    std::string code;
    std::string message;
    std::optional<ProtectedMetadataTableId> table;
    std::optional<uint64_t> offset;
    std::optional<uint64_t> size;
};

struct ProtectedMetadataTable {
    ProtectedMetadataTableId id = ProtectedMetadataTableId::StringLiteralData;
    uint64_t sourceOffset = 0;
    size_t stride = 0;
    size_t count = 0;
    ProtectedMetadataCipher cipher = ProtectedMetadataCipher::Raw;
    std::vector<uint8_t> bytes;
};

struct ProtectedMetadataTypeRecord {
    uint32_t nameIndex = 0;
    uint32_t namespaceIndex = 0;
    int32_t parentIndex = 0;
    int32_t fieldStart = 0;
    int32_t methodStart = 0;
    uint16_t fieldCount = 0;
    uint16_t methodCount = 0;
};

struct ProtectedMetadataImageModel {
    std::string name;
    int32_t typeStart = 0;
    uint32_t typeCount = 0;
};

struct ProtectedMetadataModelResult {
    MetadataModel metadata;
    std::vector<ProtectedMetadataImageModel> images;
    std::vector<uint32_t> fieldTokens;
    std::vector<ProtectedMetadataDiagnostic> diagnostics;

    bool ok() const;
};

using ProtectedMetadataTypeResolver = std::function<std::optional<std::string>(int32_t typeIndex)>;

struct ProtectedMetadataResult {
    std::string profileName;
    std::vector<uint8_t> header;
    std::vector<ProtectedMetadataTable> tables;
    std::vector<ProtectedMetadataTypeRecord> types;
    std::optional<ProtectedMetadataTypeLayout> confirmedTypeLayout;
    std::vector<ProtectedMetadataDiagnostic> diagnostics;

    bool ok() const;
    const ProtectedMetadataTable* findTable(ProtectedMetadataTableId id) const;
    ProtectedMetadataModelResult toMetadataModel(const ProtectedMetadataTypeResolver& typeResolver = {}) const;
};

const char* toString(ProtectedMetadataTableId id);

class ProtectedMetadata {
public:
    static ProtectedMetadata researched();

    explicit ProtectedMetadata(ProtectedMetadataProfile profile = ProtectedMetadataProfile::researched());

    ProtectedMetadataResult decode(const std::vector<uint8_t>& data) const;
    ProtectedMetadataResult decode(const uint8_t* data, size_t size) const;

    const ProtectedMetadataProfile& profile() const;

private:
    ProtectedMetadataProfile profile_;
};

} // namespace il2cpprec
