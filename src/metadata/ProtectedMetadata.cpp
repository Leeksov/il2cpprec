#include <il2cpprec/metadata/ProtectedMetadata.hpp>

#include <bit>
#include <cstring>
#include <limits>
#include <sstream>
#include <string_view>
#include <utility>

namespace il2cpprec {
namespace {

constexpr size_t tableIndex(ProtectedMetadataTableId id) {
    return static_cast<size_t>(id);
}

std::string hex(uint64_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << value;
    return output.str();
}

template<typename Result>
void diagnostic(
    Result& result,
    std::string code,
    std::string message,
    std::optional<ProtectedMetadataTableId> table = std::nullopt,
    std::optional<uint64_t> offset = std::nullopt,
    std::optional<uint64_t> size = std::nullopt) {
    result.diagnostics.push_back({
        ProtectedMetadataDiagnosticSeverity::Error,
        std::move(code),
        std::move(message),
        table,
        offset,
        size
    });
}

uint32_t readU32(const uint8_t* data, size_t offset) {
    return static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset + 1]) << 8) |
        (static_cast<uint32_t>(data[offset + 2]) << 16) |
        (static_cast<uint32_t>(data[offset + 3]) << 24);
}

uint16_t readU16(const uint8_t* data, size_t offset) {
    return static_cast<uint16_t>(data[offset]) |
        static_cast<uint16_t>(static_cast<uint16_t>(data[offset + 1]) << 8);
}

bool headerFieldFits(const ProtectedMetadataProfile& profile, size_t offset) {
    return offset <= profile.headerSize && 4 <= profile.headerSize - offset;
}

bool adjustedSource(uint32_t base, int64_t adjustment, uint64_t& source) {
    if (adjustment >= 0) {
        const auto amount = static_cast<uint64_t>(adjustment);
        if (amount > std::numeric_limits<uint64_t>::max() - base) return false;
        source = static_cast<uint64_t>(base) + amount;
        return true;
    }

    const auto magnitude = static_cast<uint64_t>(-(adjustment + 1)) + 1;
    if (magnitude > base) return false;
    source = static_cast<uint64_t>(base) - magnitude;
    return true;
}

uint8_t tableKey(ProtectedMetadataCipher cipher, uint32_t size, size_t index) {
    const auto position = static_cast<uint64_t>(index);
    if (cipher == ProtectedMetadataCipher::XorSizePlus35ByIndex) {
        const uint64_t counter = static_cast<uint64_t>(size) + 35;
        return static_cast<uint8_t>((counter ^ position) & 0xff);
    }

    const uint64_t counter = uint64_t{0} - static_cast<uint64_t>(size) - 35;
    return static_cast<uint8_t>((counter ^ position) & 0xff);
}

bool typeFieldFits(size_t offset, size_t width, size_t stride) {
    return offset <= stride && width <= stride - offset;
}

bool validateTypeLayout(
    const ProtectedMetadataTypeLayout& layout,
    size_t stride,
    ProtectedMetadataResult& result) {
    struct Field {
        const char* name;
        size_t offset;
        size_t width;
    };

    const Field fields[] = {
        {"nameIndex", layout.nameIndexOffset, 4},
        {"namespaceIndex", layout.namespaceIndexOffset, 4},
        {"parentIndex", layout.parentIndexOffset, 4},
        {"fieldStart", layout.fieldStartOffset, 4},
        {"methodStart", layout.methodStartOffset, 4},
        {"fieldCount", layout.fieldCountOffset, 2},
        {"methodCount", layout.methodCountOffset, 2}
    };

    bool valid = true;
    for (const auto& field : fields) {
        if (typeFieldFits(field.offset, field.width, stride)) continue;
        diagnostic(
            result,
            "invalid-type-layout",
            std::string("Type field ") + field.name + " at " + hex(field.offset) +
                " does not fit the configured stride " + std::to_string(stride),
            ProtectedMetadataTableId::Types,
            field.offset,
            field.width);
        valid = false;
    }
    return valid;
}

} // namespace

ProtectedMetadataProfile ProtectedMetadataProfile::researched() {
    ProtectedMetadataProfile profile;
    profile.name = "researched-header-0x150";

    auto& stringLiteralData = profile.tables[tableIndex(ProtectedMetadataTableId::StringLiteralData)];
    stringLiteralData = {168, 28, 112, 0, ProtectedMetadataCipher::XorSizePlus35ByIndex};

    auto& literals = profile.tables[tableIndex(ProtectedMetadataTableId::StringLiterals)];
    literals = {32, 52, 216, 8, ProtectedMetadataCipher::XorNegativeSizeMinus35ByIndex};

    auto& methods = profile.tables[tableIndex(ProtectedMetadataTableId::Methods)];
    methods = {232, -24, 80, 0, ProtectedMetadataCipher::XorSizePlus35ByIndex};

    auto& properties = profile.tables[tableIndex(ProtectedMetadataTableId::Properties)];
    properties = {172, -52, 212, 0, ProtectedMetadataCipher::XorSizePlus35ByIndex};

    auto& assemblies = profile.tables[tableIndex(ProtectedMetadataTableId::Assemblies)];
    assemblies = {196, -36, 12, 0, ProtectedMetadataCipher::XorNegativeSizeMinus35ByIndex};

    auto& fields = profile.tables[tableIndex(ProtectedMetadataTableId::Fields)];
    fields = {292, -48, 176, 16, ProtectedMetadataCipher::XorSizePlus35ByIndex};

    auto& strings = profile.tables[tableIndex(ProtectedMetadataTableId::Strings)];
    strings = {52, -20, 136, 0, ProtectedMetadataCipher::XorNegativeSizeMinus35ByIndex};

    auto& images = profile.tables[tableIndex(ProtectedMetadataTableId::Images)];
    images = {248, -40, 160, 40, ProtectedMetadataCipher::Raw};

    auto& types = profile.tables[tableIndex(ProtectedMetadataTableId::Types)];
    types = {284, 40, 284, 88, ProtectedMetadataCipher::Raw};

    auto& parameters = profile.tables[tableIndex(ProtectedMetadataTableId::Parameters)];
    parameters = {312, 60, 312, 16, ProtectedMetadataCipher::Raw};

    return profile;
}

const char* toString(ProtectedMetadataTableId id) {
    switch (id) {
    case ProtectedMetadataTableId::StringLiteralData: return "stringLiteralData";
    case ProtectedMetadataTableId::StringLiterals: return "stringLiterals";
    case ProtectedMetadataTableId::Methods: return "methods";
    case ProtectedMetadataTableId::Properties: return "properties";
    case ProtectedMetadataTableId::Assemblies: return "assemblies";
    case ProtectedMetadataTableId::Fields: return "fields";
    case ProtectedMetadataTableId::Strings: return "strings";
    case ProtectedMetadataTableId::Images: return "images";
    case ProtectedMetadataTableId::Types: return "types";
    case ProtectedMetadataTableId::Parameters: return "parameters";
    case ProtectedMetadataTableId::Count: break;
    }
    return "unknown";
}

bool ProtectedMetadataResult::ok() const {
    for (const auto& entry : diagnostics) {
        if (entry.severity == ProtectedMetadataDiagnosticSeverity::Error) return false;
    }
    return true;
}

const ProtectedMetadataTable* ProtectedMetadataResult::findTable(ProtectedMetadataTableId id) const {
    for (const auto& table : tables) {
        if (table.id == id) return &table;
    }
    return nullptr;
}

bool ProtectedMetadataModelResult::ok() const {
    for (const auto& entry : diagnostics) {
        if (entry.severity == ProtectedMetadataDiagnosticSeverity::Error) return false;
    }
    return true;
}

ProtectedMetadataModelResult ProtectedMetadataResult::toMetadataModel(
    const ProtectedMetadataTypeResolver& typeResolver) const {
    ProtectedMetadataModelResult result;
    result.diagnostics = diagnostics;
    if (!ok()) {
        diagnostic(result, "decode-failed", "Cannot build MetadataModel from a decode result containing errors");
        return result;
    }
    if (!confirmedTypeLayout.has_value()) {
        diagnostic(
            result,
            "type-layout-not-confirmed",
            "Cannot build MetadataModel without a configured and validated 88-byte type layout",
            ProtectedMetadataTableId::Types);
        return result;
    }
    if (header.size() < 8) {
        diagnostic(result, "truncated-header", "Decoded header does not contain a version field", std::nullopt, 0, 8);
        return result;
    }

    bool tablesValid = true;
    auto requireTable = [&](ProtectedMetadataTableId id, size_t stride) -> const ProtectedMetadataTable* {
        const auto* table = findTable(id);
        if (table == nullptr) {
            diagnostic(result, "missing-table", std::string("Missing decoded ") + toString(id) + " table", id);
            tablesValid = false;
            return nullptr;
        }
        if (stride != 0 && table->bytes.size() % stride != 0) {
            diagnostic(
                result,
                "misaligned-table-size",
                std::string("Decoded ") + toString(id) + " size " + std::to_string(table->bytes.size()) +
                    " is not divisible by required stride " + std::to_string(stride),
                id,
                table->sourceOffset,
                table->bytes.size());
            tablesValid = false;
            return nullptr;
        }
        return table;
    };

    const auto* stringTable = requireTable(ProtectedMetadataTableId::Strings, 0);
    const auto* literalData = requireTable(ProtectedMetadataTableId::StringLiteralData, 0);
    const auto* literals = requireTable(ProtectedMetadataTableId::StringLiterals, 8);
    const auto* methods = requireTable(ProtectedMetadataTableId::Methods, 36);
    const auto* fields = requireTable(ProtectedMetadataTableId::Fields, 16);
    const auto* images = requireTable(ProtectedMetadataTableId::Images, 40);
    requireTable(ProtectedMetadataTableId::Assemblies, 0);
    const auto* typeTable = requireTable(ProtectedMetadataTableId::Types, 88);
    const auto* parameters = requireTable(ProtectedMetadataTableId::Parameters, 16);
    if (typeTable != nullptr && typeTable->stride != 88) {
        diagnostic(
            result,
            "unsupported-type-stride",
            "MetadataModel conversion requires confirmed type stride 88, got " + std::to_string(typeTable->stride),
            ProtectedMetadataTableId::Types,
            typeTable->sourceOffset,
            typeTable->bytes.size());
        tablesValid = false;
    }
    if (!tablesValid) return result;

    const int32_t version = std::bit_cast<int32_t>(readU32(header.data(), 4));
    if (version < 0) {
        diagnostic(result, "invalid-metadata-version", "Metadata version is negative: " + std::to_string(version), std::nullopt, 4, 4);
        return result;
    }
    result.metadata.version = static_cast<double>(version);

    auto readString = [&](uint32_t index, ProtectedMetadataTableId owner, std::string_view role, size_t record)
        -> std::optional<std::string> {
        if (index >= stringTable->bytes.size()) {
            diagnostic(
                result,
                "string-index-out-of-range",
                std::string(role) + " " + std::to_string(record) + " references string offset " +
                    std::to_string(index) + ", but the string table contains " +
                    std::to_string(stringTable->bytes.size()) + " bytes",
                owner,
                index);
            return std::nullopt;
        }
        const auto* begin = reinterpret_cast<const char*>(stringTable->bytes.data() + index);
        const size_t remaining = stringTable->bytes.size() - index;
        const void* end = std::memchr(begin, 0, remaining);
        if (end == nullptr) {
            diagnostic(
                result,
                "unterminated-string",
                std::string(role) + " " + std::to_string(record) + " references an unterminated string at offset " +
                    std::to_string(index),
                owner,
                index,
                remaining);
            return std::nullopt;
        }
        return std::string(begin, static_cast<const char*>(end) - begin);
    };

    auto readRequiredString = [&](uint32_t index, ProtectedMetadataTableId owner, std::string_view role, size_t record)
        -> std::optional<std::string> {
        auto value = readString(index, owner, role, record);
        if (value.has_value() && value->empty()) {
            diagnostic(
                result,
                "empty-required-string",
                std::string(role) + " " + std::to_string(record) + " has an empty required name",
                owner,
                index);
            return std::nullopt;
        }
        return value;
    };

    bool missingResolverReported = false;
    auto resolveType = [&](int32_t index, ProtectedMetadataTableId owner, std::string_view role, size_t record)
        -> std::optional<std::string> {
        if (index < 0) {
            diagnostic(
                result,
                "invalid-type-reference",
                std::string(role) + " " + std::to_string(record) + " has negative Il2CppType index " +
                    std::to_string(index),
                owner,
                record);
            return std::nullopt;
        }
        if (!typeResolver) {
            if (!missingResolverReported) {
                diagnostic(
                    result,
                    "missing-type-reference-table",
                    std::string("Cannot resolve ") + std::string(role) + " " + std::to_string(record) +
                        ": the custom Il2CppType table is absent and no type resolver was supplied",
                    owner,
                    record);
                missingResolverReported = true;
            }
            return std::nullopt;
        }

        std::optional<std::string> value;
        try {
            value = typeResolver(index);
        } catch (...) {
            diagnostic(
                result,
                "type-resolver-failed",
                std::string("Type resolver threw while resolving ") + std::string(role) + " " + std::to_string(record) +
                    " (Il2CppType index " + std::to_string(index) + ")",
                owner,
                record);
            return std::nullopt;
        }
        if (!value.has_value() || value->empty()) {
            diagnostic(
                result,
                "unresolved-type-reference",
                std::string("Type resolver could not resolve ") + std::string(role) + " " + std::to_string(record) +
                    " (Il2CppType index " + std::to_string(index) + ")",
                owner,
                record);
            return std::nullopt;
        }
        return value;
    };

    auto recordRange = [&](int32_t start, uint32_t count, size_t available, ProtectedMetadataTableId owner,
                           std::string_view role, size_t record) -> std::optional<std::pair<size_t, size_t>> {
        if (count == 0) return std::pair<size_t, size_t>{0, 0};
        if (start < 0) {
            diagnostic(
                result,
                "negative-record-range",
                std::string(role) + " " + std::to_string(record) + " has negative start " + std::to_string(start) +
                    " with nonzero count " + std::to_string(count),
                owner,
                record);
            return std::nullopt;
        }
        const uint64_t begin = static_cast<uint32_t>(start);
        const uint64_t end = begin + count;
        if (end > available) {
            diagnostic(
                result,
                "record-range-out-of-bounds",
                std::string(role) + " " + std::to_string(record) + " range [" + std::to_string(begin) + ", " +
                    std::to_string(end) + ") exceeds " + std::to_string(available) + " records",
                owner,
                begin,
                count);
            return std::nullopt;
        }
        return std::pair<size_t, size_t>{static_cast<size_t>(begin), static_cast<size_t>(count)};
    };

    const size_t literalCount = literals->bytes.size() / 8;
    for (size_t index = 0; index < literalCount; ++index) {
        const uint8_t* bytes = literals->bytes.data() + index * 8;
        const uint32_t length = readU32(bytes, 0);
        const int32_t dataIndex = std::bit_cast<int32_t>(readU32(bytes, 4));
        if (dataIndex < 0) {
            diagnostic(
                result,
                "negative-string-literal-offset",
                "String literal " + std::to_string(index) + " has negative data offset " + std::to_string(dataIndex),
                ProtectedMetadataTableId::StringLiterals,
                index * 8,
                8);
            continue;
        }
        const auto begin = static_cast<size_t>(dataIndex);
        if (begin > literalData->bytes.size() || length > literalData->bytes.size() - begin) {
            diagnostic(
                result,
                "string-literal-out-of-range",
                "String literal " + std::to_string(index) + " data range [" + std::to_string(begin) + ", " +
                    std::to_string(static_cast<uint64_t>(begin) + length) + ") exceeds literal data size " +
                    std::to_string(literalData->bytes.size()),
                ProtectedMetadataTableId::StringLiteralData,
                begin,
                length);
            continue;
        }
        if (length == 0) {
            result.metadata.stringLiterals.emplace(static_cast<uint32_t>(index), std::string{});
        } else {
            result.metadata.stringLiterals.emplace(
                static_cast<uint32_t>(index),
                std::string(reinterpret_cast<const char*>(literalData->bytes.data() + begin), length));
        }
    }

    const size_t typeCount = typeTable->bytes.size() / 88;
    if (types.size() != typeCount) {
        diagnostic(
            result,
            "type-record-count-mismatch",
            "Confirmed type records count " + std::to_string(types.size()) +
                " does not match the 88-byte type table count " + std::to_string(typeCount),
            ProtectedMetadataTableId::Types);
        return result;
    }

    std::vector<std::string> typeImages(typeCount);
    const size_t imageCount = images->bytes.size() / 40;
    result.images.reserve(imageCount);
    for (size_t index = 0; index < imageCount; ++index) {
        const uint8_t* bytes = images->bytes.data() + index * 40;
        const uint32_t nameIndex = readU32(bytes, 0);
        const int32_t typeStart = std::bit_cast<int32_t>(readU32(bytes, 8));
        const uint32_t imageTypeCount = readU32(bytes, 12);
        auto name = readRequiredString(nameIndex, ProtectedMetadataTableId::Images, "image", index);
        if (!name.has_value()) continue;

        ProtectedMetadataImageModel image;
        image.name = *name;
        image.typeStart = typeStart;
        image.typeCount = imageTypeCount;
        result.images.push_back(image);

        auto range = recordRange(
            typeStart,
            imageTypeCount,
            typeCount,
            ProtectedMetadataTableId::Images,
            "image type",
            index);
        if (!range.has_value()) continue;
        result.metadata.methodPointersByImage.try_emplace(*name);
        const auto [begin, count] = *range;
        for (size_t offset = 0; offset < count; ++offset) {
            const size_t typeIndex = begin + offset;
            if (!typeImages[typeIndex].empty()) {
                diagnostic(
                    result,
                    "duplicate-type-image",
                    "Type " + std::to_string(typeIndex) + " is assigned to both image " + typeImages[typeIndex] +
                        " and image " + *name,
                    ProtectedMetadataTableId::Images,
                    index * 40,
                    40);
                continue;
            }
            typeImages[typeIndex] = *name;
        }
    }

    result.metadata.types.reserve(typeCount);
    std::vector<std::string> declaringNames;
    declaringNames.reserve(typeCount);
    for (size_t index = 0; index < typeCount; ++index) {
        const auto& definition = types[index];
        TypeModel type;
        auto name = readRequiredString(definition.nameIndex, ProtectedMetadataTableId::Types, "type", index);
        if (name.has_value()) type.name = *name;
        if (definition.namespaceIndex != std::numeric_limits<uint32_t>::max()) {
            auto nameSpace = readString(definition.namespaceIndex, ProtectedMetadataTableId::Types, "type namespace", index);
            if (nameSpace.has_value()) type.nameSpace = *nameSpace;
        }
        if (definition.parentIndex >= 0) {
            auto parent = resolveType(definition.parentIndex, ProtectedMetadataTableId::Types, "base type", index);
            if (parent.has_value()) type.baseType = *parent;
        }
        declaringNames.push_back(type.nameSpace.empty() ? type.name : type.nameSpace + "." + type.name);
        result.metadata.types.push_back(std::move(type));
    }

    const size_t fieldCount = fields->bytes.size() / 16;
    result.fieldTokens.resize(fieldCount);
    for (size_t index = 0; index < fieldCount; ++index) {
        result.fieldTokens[index] = readU32(fields->bytes.data() + index * 16, 12);
    }

    const size_t methodCount = methods->bytes.size() / 36;
    const size_t parameterCount = parameters->bytes.size() / 16;
    for (size_t typeIndex = 0; typeIndex < typeCount; ++typeIndex) {
        const auto& definition = types[typeIndex];
        auto& outputType = result.metadata.types[typeIndex];

        auto fieldRange = recordRange(
            definition.fieldStart,
            definition.fieldCount,
            fieldCount,
            ProtectedMetadataTableId::Fields,
            "type field",
            typeIndex);
        if (fieldRange.has_value()) {
            const auto [begin, count] = *fieldRange;
            for (size_t offset = 0; offset < count; ++offset) {
                const size_t fieldIndex = begin + offset;
                const uint8_t* bytes = fields->bytes.data() + fieldIndex * 16;
                FieldModel field;
                field.token = readU32(bytes, 12);
                auto name = readRequiredString(readU32(bytes, 0), ProtectedMetadataTableId::Fields, "field", fieldIndex);
                if (name.has_value()) field.name = *name;
                auto fieldType = resolveType(
                    std::bit_cast<int32_t>(readU32(bytes, 4)),
                    ProtectedMetadataTableId::Fields,
                    "field type",
                    fieldIndex);
                if (fieldType.has_value()) field.type = *fieldType;
                outputType.fields.push_back(std::move(field));
            }
        }

        auto methodRange = recordRange(
            definition.methodStart,
            definition.methodCount,
            methodCount,
            ProtectedMetadataTableId::Methods,
            "type method",
            typeIndex);
        if (!methodRange.has_value()) continue;
        const auto [methodBegin, typeMethodCount] = *methodRange;
        for (size_t offset = 0; offset < typeMethodCount; ++offset) {
            const size_t methodIndex = methodBegin + offset;
            const uint8_t* bytes = methods->bytes.data() + methodIndex * 36;
            MethodModel method;
            method.token = readU32(bytes, 24);
            method.isStatic = (readU16(bytes, 28) & 0x0010) != 0;
            if (methodIndex > static_cast<size_t>(std::numeric_limits<int>::max())) {
                diagnostic(
                    result,
                    "method-index-overflow",
                    "Method index " + std::to_string(methodIndex) + " does not fit MethodModel.definitionIndex",
                    ProtectedMetadataTableId::Methods,
                    methodIndex);
                continue;
            }
            method.definitionIndex = static_cast<int>(methodIndex);
            method.imageName = typeImages[typeIndex];
            if (method.imageName.empty()) {
                diagnostic(
                    result,
                    "method-image-unavailable",
                    "Method " + std::to_string(methodIndex) + " has no imageName because type " +
                        std::to_string(typeIndex) + " is outside all image type ranges",
                    ProtectedMetadataTableId::Methods,
                    methodIndex * 36,
                    36);
            }
            method.declaringType = declaringNames[typeIndex];
            const int32_t declaringType = std::bit_cast<int32_t>(readU32(bytes, 4));
            if (declaringType >= 0) {
                if (static_cast<size_t>(declaringType) >= declaringNames.size()) {
                    diagnostic(
                        result,
                        "declaring-type-out-of-range",
                        "Method " + std::to_string(methodIndex) + " declaring type index " +
                            std::to_string(declaringType) + " exceeds type count " + std::to_string(typeCount),
                        ProtectedMetadataTableId::Methods,
                        methodIndex * 36 + 4,
                        4);
                } else {
                    method.declaringType = declaringNames[static_cast<size_t>(declaringType)];
                }
            }
            auto name = readRequiredString(readU32(bytes, 0), ProtectedMetadataTableId::Methods, "method", methodIndex);
            if (name.has_value()) method.name = *name;
            auto returnType = resolveType(
                std::bit_cast<int32_t>(readU32(bytes, 8)),
                ProtectedMetadataTableId::Methods,
                "method return type",
                methodIndex);
            if (returnType.has_value()) method.returnType = *returnType;

            const int32_t parameterStart = std::bit_cast<int32_t>(readU32(bytes, 12));
            const uint16_t methodParameterCount = readU16(bytes, 34);
            auto parameterRange = recordRange(
                parameterStart,
                methodParameterCount,
                parameterCount,
                ProtectedMetadataTableId::Parameters,
                "method parameter",
                methodIndex);
            if (parameterRange.has_value()) {
                const auto [parameterBegin, count] = *parameterRange;
                for (size_t parameterOffset = 0; parameterOffset < count; ++parameterOffset) {
                    const size_t parameterIndex = parameterBegin + parameterOffset;
                    const uint8_t* parameterBytes = parameters->bytes.data() + parameterIndex * 16;
                    ParameterModel parameter;
                    auto parameterName = readString(
                        readU32(parameterBytes, 0),
                        ProtectedMetadataTableId::Parameters,
                        "parameter",
                        parameterIndex);
                    if (parameterName.has_value()) parameter.name = *parameterName;
                    auto parameterType = resolveType(
                        std::bit_cast<int32_t>(readU32(parameterBytes, 12)),
                        ProtectedMetadataTableId::Parameters,
                        "parameter type",
                        parameterIndex);
                    if (parameterType.has_value()) parameter.type = *parameterType;
                    method.parameters.push_back(std::move(parameter));
                }
            }
            outputType.methods.push_back(std::move(method));
        }
    }

    if (!result.ok()) {
        result.metadata = MetadataModel{};
        result.images.clear();
        result.fieldTokens.clear();
    }
    return result;
}

ProtectedMetadata ProtectedMetadata::researched() {
    return ProtectedMetadata(ProtectedMetadataProfile::researched());
}

ProtectedMetadata::ProtectedMetadata(ProtectedMetadataProfile profile)
    : profile_(std::move(profile)) {
}

ProtectedMetadataResult ProtectedMetadata::decode(const std::vector<uint8_t>& data) const {
    return decode(data.data(), data.size());
}

ProtectedMetadataResult ProtectedMetadata::decode(const uint8_t* data, size_t size) const {
    ProtectedMetadataResult result;
    result.profileName = profile_.name;

    if (data == nullptr && size != 0) {
        diagnostic(result, "null-input", "Protected metadata input is null but its size is nonzero", std::nullopt, 0, size);
        return result;
    }
    if (profile_.headerSize == 0) {
        diagnostic(result, "invalid-profile", "Protected metadata header size must not be zero");
        return result;
    }
    if (size < profile_.headerSize) {
        diagnostic(
            result,
            "truncated-header",
            "Protected metadata header requires " + std::to_string(profile_.headerSize) +
                " bytes, but the file contains " + std::to_string(size),
            std::nullopt,
            0,
            profile_.headerSize);
        return result;
    }

    result.header.resize(profile_.headerSize);
    for (size_t index = 0; index < profile_.headerSize; ++index) {
        const uint8_t key = static_cast<uint8_t>((static_cast<uint64_t>(profile_.headerKeyBase) + index) & 0xff);
        result.header[index] = static_cast<uint8_t>(data[index] ^ key);
    }

    for (size_t index = 0; index < ProtectedMetadataProfile::tableCount; ++index) {
        const auto id = static_cast<ProtectedMetadataTableId>(index);
        const auto& tableProfile = profile_.tables[index];
        const char* name = toString(id);

        if (!headerFieldFits(profile_, tableProfile.sourceHeaderOffset)) {
            diagnostic(
                result,
                "invalid-source-header-offset",
                std::string(name) + " source header field lies outside the decoded header",
                id,
                tableProfile.sourceHeaderOffset,
                4);
            continue;
        }
        if (!headerFieldFits(profile_, tableProfile.sizeHeaderOffset)) {
            diagnostic(
                result,
                "invalid-size-header-offset",
                std::string(name) + " size header field lies outside the decoded header",
                id,
                tableProfile.sizeHeaderOffset,
                4);
            continue;
        }

        const uint32_t encodedSource = readU32(result.header.data(), tableProfile.sourceHeaderOffset);
        const int32_t signedSize = std::bit_cast<int32_t>(readU32(result.header.data(), tableProfile.sizeHeaderOffset));

        uint64_t source = 0;
        if (!adjustedSource(encodedSource, tableProfile.sourceAdjustment, source)) {
            diagnostic(
                result,
                "source-offset-overflow",
                std::string(name) + " source calculation overflows or becomes negative: H[" +
                    std::to_string(tableProfile.sourceHeaderOffset) + "] " +
                    (tableProfile.sourceAdjustment < 0 ? "- " : "+ ") +
                    std::to_string(tableProfile.sourceAdjustment < 0
                        ? static_cast<uint64_t>(-(tableProfile.sourceAdjustment + 1)) + 1
                        : static_cast<uint64_t>(tableProfile.sourceAdjustment)),
                id,
                encodedSource,
                std::nullopt);
            continue;
        }
        if (signedSize < 0) {
            diagnostic(
                result,
                "negative-table-size",
                std::string(name) + " has negative byte size " + std::to_string(signedSize),
                id,
                source,
                static_cast<uint32_t>(signedSize));
            continue;
        }

        const auto byteSize = static_cast<uint32_t>(signedSize);
        if (static_cast<uint64_t>(byteSize) > std::numeric_limits<uint64_t>::max() - source) {
            diagnostic(
                result,
                "table-out-of-range",
                std::string(name) + " range end overflows 64-bit offset arithmetic; no bytes were read",
                id,
                source,
                byteSize);
            continue;
        }
        const uint64_t end = source + byteSize;
        if (source > size || static_cast<uint64_t>(byteSize) > static_cast<uint64_t>(size) - source) {
            diagnostic(
                result,
                "table-out-of-range",
                std::string(name) + " range [" + hex(source) + ", " + hex(end) +
                    ") exceeds file size " + hex(size) + "; no bytes were read",
                id,
                source,
                byteSize);
            continue;
        }
        if (tableProfile.stride != 0 && byteSize % tableProfile.stride != 0) {
            diagnostic(
                result,
                "misaligned-table-size",
                std::string(name) + " byte size " + std::to_string(byteSize) +
                    " is not divisible by stride " + std::to_string(tableProfile.stride),
                id,
                source,
                byteSize);
            continue;
        }

        ProtectedMetadataTable table;
        table.id = id;
        table.sourceOffset = source;
        table.stride = tableProfile.stride;
        table.count = tableProfile.stride == 0 ? 0 : byteSize / tableProfile.stride;
        table.cipher = tableProfile.cipher;
        const auto sourceOffset = static_cast<size_t>(source);
        table.bytes.assign(data + sourceOffset, data + sourceOffset + byteSize);

        if (tableProfile.cipher != ProtectedMetadataCipher::Raw) {
            for (size_t byteIndex = 0; byteIndex < table.bytes.size(); ++byteIndex) {
                table.bytes[byteIndex] = static_cast<uint8_t>(
                    table.bytes[byteIndex] ^ tableKey(tableProfile.cipher, byteSize, byteIndex));
            }
        }
        result.tables.push_back(std::move(table));
    }

    const auto* typeTable = result.findTable(ProtectedMetadataTableId::Types);
    if (typeTable != nullptr && profile_.typeLayout.has_value()) {
        const auto& layout = *profile_.typeLayout;
        if (typeTable->stride != 88) {
            diagnostic(
                result,
                "unconfirmed-type-layout",
                "Type layout requires the researched 88-byte stride, got " + std::to_string(typeTable->stride),
                ProtectedMetadataTableId::Types,
                typeTable->sourceOffset,
                typeTable->bytes.size());
        } else if (validateTypeLayout(layout, typeTable->stride, result)) {
            result.types.reserve(typeTable->count);
            for (size_t index = 0; index < typeTable->count; ++index) {
                const size_t base = index * typeTable->stride;
                const uint8_t* bytes = typeTable->bytes.data() + base;
                ProtectedMetadataTypeRecord type;
                type.nameIndex = readU32(bytes, layout.nameIndexOffset);
                type.namespaceIndex = readU32(bytes, layout.namespaceIndexOffset);
                type.parentIndex = std::bit_cast<int32_t>(readU32(bytes, layout.parentIndexOffset));
                type.fieldStart = std::bit_cast<int32_t>(readU32(bytes, layout.fieldStartOffset));
                type.methodStart = std::bit_cast<int32_t>(readU32(bytes, layout.methodStartOffset));
                type.fieldCount = readU16(bytes, layout.fieldCountOffset);
                type.methodCount = readU16(bytes, layout.methodCountOffset);
                result.types.push_back(type);
            }
            result.confirmedTypeLayout = layout;
        }
    }

    return result;
}

const ProtectedMetadataProfile& ProtectedMetadata::profile() const {
    return profile_;
}

} // namespace il2cpprec
