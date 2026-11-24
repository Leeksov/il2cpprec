#include <il2cpprec/metadata/AttributeEvaluator.hpp>

#include <algorithm>
#include <bit>
#include <charconv>
#include <limits>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint32_t compressedIndexMask = 0x1fffffffU;
constexpr uint8_t metadataUsageMethodDef = 3;
constexpr uint32_t staticFieldFlag = 0x0010;

struct MethodLocation {
    size_t typeIndex = 0;
    size_t methodIndex = 0;
};

struct TypeResolution {
    const TypeReferenceModel* reference = nullptr;
    int32_t definitionIndex = -1;
    std::string name;
};

std::string qualifiedName(const TypeModel& type) {
    if (type.nameSpace.empty()) return type.name;
    if (type.name.empty()) return type.nameSpace;
    return type.nameSpace + "." + type.name;
}

std::optional<uint32_t> parseTypeReferenceIndex(std::string_view text) {
    if (text.size() <= 6 || !text.starts_with("type[") || text.back() != ']') return std::nullopt;
    uint32_t value = 0;
    const auto begin = text.data() + 5;
    const auto end = text.data() + text.size() - 1;
    const auto parsed = std::from_chars(begin, end, value);
    if (parsed.ec != std::errc{} || parsed.ptr != end) return std::nullopt;
    return value;
}

std::optional<CustomAttributeValueKind> integralKind(uint8_t code) {
    switch (static_cast<CustomAttributeValueKind>(code)) {
    case CustomAttributeValueKind::I1: return CustomAttributeValueKind::I1;
    case CustomAttributeValueKind::U1: return CustomAttributeValueKind::U1;
    case CustomAttributeValueKind::I2: return CustomAttributeValueKind::I2;
    case CustomAttributeValueKind::U2: return CustomAttributeValueKind::U2;
    case CustomAttributeValueKind::I4: return CustomAttributeValueKind::I4;
    case CustomAttributeValueKind::U4: return CustomAttributeValueKind::U4;
    case CustomAttributeValueKind::I8: return CustomAttributeValueKind::I8;
    case CustomAttributeValueKind::U8: return CustomAttributeValueKind::U8;
    default: return std::nullopt;
    }
}

std::optional<CustomAttributeValueKind> integralKindFromName(std::string_view name) {
    if (name.starts_with("global::")) name.remove_prefix(8);
    if (name == "sbyte" || name == "System.SByte") return CustomAttributeValueKind::I1;
    if (name == "byte" || name == "System.Byte") return CustomAttributeValueKind::U1;
    if (name == "short" || name == "System.Int16") return CustomAttributeValueKind::I2;
    if (name == "ushort" || name == "System.UInt16") return CustomAttributeValueKind::U2;
    if (name == "int" || name == "System.Int32") return CustomAttributeValueKind::I4;
    if (name == "uint" || name == "System.UInt32") return CustomAttributeValueKind::U4;
    if (name == "long" || name == "System.Int64") return CustomAttributeValueKind::I8;
    if (name == "ulong" || name == "System.UInt64") return CustomAttributeValueKind::U8;
    return std::nullopt;
}

class BlobReader {
public:
    explicit BlobReader(std::span<const uint8_t> data) : data_(data) {}

    size_t position() const noexcept { return position_; }
    size_t remaining() const noexcept { return data_.size() - position_; }
    bool has(size_t amount) const noexcept { return amount <= remaining(); }

    uint8_t byte() noexcept { return data_[position_++]; }

    uint16_t u16() noexcept {
        const uint16_t value = static_cast<uint16_t>(data_[position_]) |
            static_cast<uint16_t>(static_cast<uint16_t>(data_[position_ + 1]) << 8);
        position_ += 2;
        return value;
    }

    uint32_t u32() noexcept {
        const uint32_t value = static_cast<uint32_t>(data_[position_]) |
            (static_cast<uint32_t>(data_[position_ + 1]) << 8) |
            (static_cast<uint32_t>(data_[position_ + 2]) << 16) |
            (static_cast<uint32_t>(data_[position_ + 3]) << 24);
        position_ += 4;
        return value;
    }

    uint64_t u64() noexcept {
        const uint64_t low = u32();
        return low | (static_cast<uint64_t>(u32()) << 32);
    }

    std::span<const uint8_t> bytes(size_t amount) noexcept {
        const auto result = data_.subspan(position_, amount);
        position_ += amount;
        return result;
    }

private:
    std::span<const uint8_t> data_;
    size_t position_ = 0;
};

class EvaluationSession {
public:
    EvaluationSession(
        const AttributeEvaluationInput& input,
        const AttributeEvaluatorOptions& options,
        CustomAttributeEvaluationResult& result)
        : input_(input), options_(options), result_(result), metadata_(input.metadata) {
        if (metadata_ != nullptr && input.version == 0) version_ = metadata_->version;
        else version_ = input.version;

        if (metadata_ == nullptr) return;
        for (size_t typeIndex = 0; typeIndex < metadata_->types.size(); ++typeIndex) {
            const auto& methods = metadata_->types[typeIndex].methods;
            for (size_t methodIndex = 0; methodIndex < methods.size(); ++methodIndex) {
                const int32_t definitionIndex = methods[methodIndex].definitionIndex;
                if (definitionIndex < 0) continue;
                const auto [position, inserted] = methods_.try_emplace(
                    definitionIndex, MethodLocation{typeIndex, methodIndex});
                if (!inserted) {
                    ambiguousMethods_.insert(definitionIndex);
                    ambiguousMethods_.insert(position->first);
                }
            }
        }
        for (const auto& property : input.properties) {
            properties_[property.typeDefinitionIndex].push_back(&property);
        }
    }

    CustomAttributeEvaluationResult evaluate(uint32_t token, size_t imageIndex) {
        token_ = token;
        imageIndex_ = imageIndex;
        if (!validateCommon()) return std::move(result_);
        if (imageIndex >= metadata_->images.size()) {
            fail("image-index-out-of-range", "Image index " + std::to_string(imageIndex) +
                " exceeds image count " + std::to_string(metadata_->images.size()));
            return std::move(result_);
        }

        const auto& image = metadata_->images[imageIndex];
        if (image.customAttributeCount == 0) return std::move(result_);
        if (image.customAttributeStart < 0) {
            fail("negative-image-attribute-range", "Image has a negative custom attribute range start");
            return std::move(result_);
        }
        if (image.customAttributeCount > options_.maxImageRanges) {
            fail("image-range-limit", "Image custom attribute range count exceeds the configured limit");
            return std::move(result_);
        }

        const size_t start = static_cast<size_t>(image.customAttributeStart);
        const size_t count = static_cast<size_t>(image.customAttributeCount);
        const size_t rangeCount = version_ >= 29.0
            ? input_.attributeDataRanges.size()
            : input_.attributeTypeRanges.size();
        if (start > rangeCount || count > rangeCount - start) {
            fail("image-range-out-of-bounds", "Image custom attribute range lies outside its metadata table");
            return std::move(result_);
        }

        if (version_ >= 29.0) return evaluateModern(start, count, token);
        return evaluateLegacy(start, count, token);
    }

    CustomAttributeEvaluationResult evaluateBlob(std::span<const uint8_t> blob) {
        if (!validateCommon()) return std::move(result_);
        if (version_ < 29.0) {
            fail("blob-format-unavailable", "Custom attribute data blobs require metadata version 29 or newer");
            return std::move(result_);
        }
        if (blob.size() > options_.maxBlobSize) {
            fail("blob-size-limit", "Custom attribute blob exceeds the configured size limit");
            return std::move(result_);
        }

        BlobReader reader(blob);
        uint32_t attributeCount = 0;
        if (!compressedUInt(reader, attributeCount, "attribute count")) return std::move(result_);
        if (attributeCount > options_.maxAttributes) {
            fail("attribute-limit", "Custom attribute count exceeds the configured limit", reader.position());
            return std::move(result_);
        }
        if (attributeCount > reader.remaining() / 4) {
            fail("truncated-constructor-table", "Constructor index table is truncated", reader.position());
            return std::move(result_);
        }

        std::vector<uint32_t> constructorIndices;
        constructorIndices.reserve(attributeCount);
        for (uint32_t index = 0; index < attributeCount; ++index) constructorIndices.push_back(reader.u32());

        result_.attributes.reserve(attributeCount);
        for (uint32_t index = 0; index < attributeCount; ++index) {
            currentAttribute_ = index;
            if (!readAttribute(reader, constructorIndices[index])) return std::move(result_);
        }
        currentAttribute_.reset();
        if (reader.remaining() != 0) {
            fail("trailing-attribute-data", "Custom attribute blob contains " +
                std::to_string(reader.remaining()) + " trailing bytes", reader.position());
        }
        return std::move(result_);
    }

private:
    bool validateCommon() {
        if (metadata_ == nullptr) {
            fail("metadata-unavailable", "Custom attribute evaluation requires MetadataModel");
            return false;
        }
        if (!AttributeEvaluator::supports(version_)) {
            fail("unsupported-metadata-version", "Custom attribute evaluator does not support metadata version " +
                std::to_string(version_));
            return false;
        }
        return true;
    }

    void diagnostic(
        CustomAttributeDiagnosticSeverity severity,
        std::string code,
        std::string message,
        std::optional<size_t> offset) {
        result_.complete = false;
        if (result_.diagnostics.size() >= options_.maxDiagnostics) return;
        CustomAttributeDiagnostic entry;
        entry.severity = severity;
        entry.code = std::move(code);
        entry.message = std::move(message);
        entry.token = token_;
        entry.imageIndex = imageIndex_;
        entry.attributeIndex = currentAttribute_;
        entry.offset = offset;
        result_.diagnostics.push_back(std::move(entry));
    }

    void fail(std::string code, std::string message, std::optional<size_t> offset = std::nullopt) {
        diagnostic(CustomAttributeDiagnosticSeverity::Error, std::move(code), std::move(message), offset);
    }

    void unsupported(std::string code, std::string message, std::optional<size_t> offset = std::nullopt) {
        diagnostic(CustomAttributeDiagnosticSeverity::Warning, std::move(code), std::move(message), offset);
    }

    bool require(BlobReader& reader, size_t amount, std::string_view what) {
        if (reader.has(amount)) return true;
        fail("truncated-blob", "Custom attribute blob ends while reading " + std::string(what), reader.position());
        return false;
    }

    bool compressedUInt(BlobReader& reader, uint32_t& value, std::string_view what) {
        if (!require(reader, 1, what)) return false;
        const uint8_t first = reader.byte();
        if (first < 128) {
            value = first;
            return true;
        }
        if (first == 240) {
            if (!require(reader, 4, what)) return false;
            value = reader.u32();
            return true;
        }
        if (first == 255) {
            value = std::numeric_limits<uint32_t>::max();
            return true;
        }
        if (first == 254) {
            value = std::numeric_limits<uint32_t>::max() - 1;
            return true;
        }
        if ((first & 0xc0) == 0xc0) {
            if (!require(reader, 3, what)) return false;
            value = (static_cast<uint32_t>(first & 0x3f) << 24) |
                (static_cast<uint32_t>(reader.byte()) << 16) |
                (static_cast<uint32_t>(reader.byte()) << 8) |
                reader.byte();
            return true;
        }
        if (!require(reader, 1, what)) return false;
        value = (static_cast<uint32_t>(first & 0x7f) << 8) | reader.byte();
        return true;
    }

    bool compressedInt(BlobReader& reader, int32_t& value, std::string_view what) {
        uint32_t encoded = 0;
        if (!compressedUInt(reader, encoded, what)) return false;
        if (encoded == std::numeric_limits<uint32_t>::max()) {
            value = std::numeric_limits<int32_t>::min();
            return true;
        }
        const uint32_t magnitude = encoded >> 1;
        if ((encoded & 1) != 0) value = -static_cast<int32_t>(magnitude + 1);
        else value = static_cast<int32_t>(magnitude);
        return true;
    }

    bool resolveType(uint32_t typeIndex, TypeResolution& resolution, size_t offset) {
        if (typeIndex >= metadata_->typeReferences.size()) {
            fail("type-reference-out-of-range", "Il2CppType index " + std::to_string(typeIndex) +
                " exceeds type reference count " + std::to_string(metadata_->typeReferences.size()), offset);
            return false;
        }
        const auto& reference = metadata_->typeReferences[typeIndex];
        if (reference.code == 0) {
            fail("null-type-reference", "Il2CppType index " + std::to_string(typeIndex) +
                " is a null type reference", offset);
            return false;
        }
        resolution.reference = &reference;
        resolution.definitionIndex = reference.definitionIndex;
        if (reference.definitionIndex >= 0 &&
            static_cast<size_t>(reference.definitionIndex) < metadata_->types.size()) {
            resolution.name = qualifiedName(metadata_->types[static_cast<size_t>(reference.definitionIndex)]);
        }
        if (resolution.name.empty()) resolution.name = reference.name;
        if (resolution.name.empty()) resolution.name = "type[" + std::to_string(typeIndex) + "]";
        return true;
    }

    const MethodLocation* resolveConstructor(
        uint32_t encoded,
        uint32_t& definitionIndex,
        size_t offset) {
        if (version_ >= 104.0) {
            uint32_t usageKind = encoded >> 29;
            if (version_ > 106.1 && usageKind > 1) ++usageKind;
            if (usageKind != metadataUsageMethodDef) {
                fail("invalid-constructor-usage", "Constructor index is not a MethodDef metadata usage", offset);
                return nullptr;
            }
            const uint32_t decoded = (encoded & compressedIndexMask) >> 1;
            if (decoded > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
                fail("constructor-index-overflow", "Constructor MethodDef index exceeds the supported index range", offset);
                return nullptr;
            }
            definitionIndex = decoded;
        } else {
            if (encoded > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
                fail("constructor-index-overflow", "Constructor MethodDef index exceeds the supported index range", offset);
                return nullptr;
            }
            definitionIndex = encoded;
        }

        const int32_t signedIndex = static_cast<int32_t>(definitionIndex);
        if (ambiguousMethods_.contains(signedIndex)) {
            fail("ambiguous-constructor", "Constructor MethodDef index " + std::to_string(definitionIndex) +
                " has duplicate MethodModel records", offset);
            return nullptr;
        }
        const auto found = methods_.find(signedIndex);
        if (found == methods_.end()) {
            fail("constructor-not-found", "Constructor MethodDef index " + std::to_string(definitionIndex) +
                " was not found in MetadataModel", offset);
            return nullptr;
        }
        const auto& location = found->second;
        const auto& method = metadata_->types[location.typeIndex].methods[location.methodIndex];
        if (method.name != ".ctor") {
            fail("constructor-not-constructor", "Attribute MethodDef index " + std::to_string(definitionIndex) +
                " does not name a constructor", offset);
            return nullptr;
        }
        return &location;
    }

    std::optional<CustomAttributeValueKind> underlyingFromReference(int32_t typeIndex) const {
        if (typeIndex < 0 || static_cast<size_t>(typeIndex) >= metadata_->typeReferences.size()) return std::nullopt;
        return integralKind(metadata_->typeReferences[static_cast<size_t>(typeIndex)].code);
    }

    std::optional<CustomAttributeValueKind> underlyingFromName(std::string_view name) const {
        if (const auto index = parseTypeReferenceIndex(name)) return underlyingFromReference(static_cast<int32_t>(*index));
        return integralKindFromName(name);
    }

    std::optional<CustomAttributeValueKind> enumUnderlyingKind(const TypeResolution& type) const {
        if (version_ < 35.0 && type.reference != nullptr) {
            if (const auto kind = underlyingFromReference(type.reference->elementTypeIndex)) return kind;
        }
        if (type.definitionIndex >= 0 && static_cast<size_t>(type.definitionIndex) < metadata_->types.size()) {
            const auto& definition = metadata_->types[static_cast<size_t>(type.definitionIndex)];
            for (const auto& field : definition.fields) {
                if (field.name != "value__" || field.isStatic || (field.flags & staticFieldFlag) != 0) continue;
                if (const auto kind = underlyingFromName(field.type)) return kind;
            }
            if (version_ >= 35.0) {
                if (const auto kind = underlyingFromName(definition.baseType)) return kind;
            }
        }
        if (type.reference != nullptr) return underlyingFromReference(type.reference->elementTypeIndex);
        return std::nullopt;
    }

    bool readPrimitive(BlobReader& reader, CustomAttributeValueKind kind, CustomAttributeScalar& value) {
        switch (kind) {
        case CustomAttributeValueKind::Boolean:
            if (!require(reader, 1, "bool constant")) return false;
            value = reader.byte() != 0;
            return true;
        case CustomAttributeValueKind::Char:
            if (!require(reader, 2, "char constant")) return false;
            value = static_cast<char16_t>(reader.u16());
            return true;
        case CustomAttributeValueKind::I1:
            if (!require(reader, 1, "sbyte constant")) return false;
            value = std::bit_cast<int8_t>(reader.byte());
            return true;
        case CustomAttributeValueKind::U1:
            if (!require(reader, 1, "byte constant")) return false;
            value = reader.byte();
            return true;
        case CustomAttributeValueKind::I2:
            if (!require(reader, 2, "short constant")) return false;
            value = std::bit_cast<int16_t>(reader.u16());
            return true;
        case CustomAttributeValueKind::U2:
            if (!require(reader, 2, "ushort constant")) return false;
            value = reader.u16();
            return true;
        case CustomAttributeValueKind::I4: {
            int32_t decoded = 0;
            if (!compressedInt(reader, decoded, "int constant")) return false;
            value = decoded;
            return true;
        }
        case CustomAttributeValueKind::U4: {
            uint32_t decoded = 0;
            if (!compressedUInt(reader, decoded, "uint constant")) return false;
            value = decoded;
            return true;
        }
        case CustomAttributeValueKind::I8:
            if (!require(reader, 8, "long constant")) return false;
            value = std::bit_cast<int64_t>(reader.u64());
            return true;
        case CustomAttributeValueKind::U8:
            if (!require(reader, 8, "ulong constant")) return false;
            value = reader.u64();
            return true;
        case CustomAttributeValueKind::R4:
            if (!require(reader, 4, "float constant")) return false;
            value = std::bit_cast<float>(reader.u32());
            return true;
        case CustomAttributeValueKind::R8:
            if (!require(reader, 8, "double constant")) return false;
            value = std::bit_cast<double>(reader.u64());
            return true;
        default:
            fail("invalid-primitive-kind", "Value is not a supported primitive custom attribute constant", reader.position());
            return false;
        }
    }

    bool readString(BlobReader& reader, CustomAttributeValue& output) {
        int32_t length = 0;
        if (!compressedInt(reader, length, "string length")) return false;
        if (length == -1) {
            output.value = std::monostate{};
            return true;
        }
        if (length < 0) {
            fail("invalid-string-length", "String constant has invalid negative length " + std::to_string(length), reader.position());
            return false;
        }
        const auto size = static_cast<size_t>(length);
        if (size > options_.maxStringLength) {
            fail("string-size-limit", "String constant exceeds the configured length limit", reader.position());
            return false;
        }
        if (!require(reader, size, "string constant")) return false;
        const auto bytes = reader.bytes(size);
        output.value = std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return true;
    }

    bool readValue(BlobReader& reader, CustomAttributeValue& output) {
        const size_t typeOffset = reader.position();
        if (!require(reader, 1, "constant type")) return false;
        const uint8_t rawKind = reader.byte();
        output.kind = static_cast<CustomAttributeValueKind>(rawKind);

        if (output.kind == CustomAttributeValueKind::String) return readString(reader, output);
        if (output.kind == CustomAttributeValueKind::Type) {
            int32_t typeIndex = 0;
            if (!compressedInt(reader, typeIndex, "type constant")) return false;
            if (typeIndex == -1) {
                output.value = std::monostate{};
                return true;
            }
            if (typeIndex < 0) {
                fail("invalid-type-constant", "Type constant has invalid negative Il2CppType index", typeOffset);
                return false;
            }
            TypeResolution type;
            if (!resolveType(static_cast<uint32_t>(typeIndex), type, typeOffset)) return false;
            output.typeIndex = static_cast<uint32_t>(typeIndex);
            output.typeName = std::move(type.name);
            output.value = output.typeName;
            return true;
        }
        if (output.kind == CustomAttributeValueKind::Enum) {
            int32_t typeIndex = 0;
            if (!compressedInt(reader, typeIndex, "enum type")) return false;
            if (typeIndex < 0) {
                fail("invalid-enum-type", "Enum constant has a negative Il2CppType index", typeOffset);
                return false;
            }
            TypeResolution type;
            if (!resolveType(static_cast<uint32_t>(typeIndex), type, typeOffset)) return false;
            const auto underlying = enumUnderlyingKind(type);
            if (!underlying) {
                unsupported("enum-underlying-unavailable", "Cannot determine underlying type for enum " + type.name, typeOffset);
                return false;
            }
            output.typeIndex = static_cast<uint32_t>(typeIndex);
            output.typeName = std::move(type.name);
            output.enumUnderlyingKind = *underlying;
            return readPrimitive(reader, *underlying, output.value);
        }

        switch (output.kind) {
        case CustomAttributeValueKind::Boolean:
        case CustomAttributeValueKind::Char:
        case CustomAttributeValueKind::I1:
        case CustomAttributeValueKind::U1:
        case CustomAttributeValueKind::I2:
        case CustomAttributeValueKind::U2:
        case CustomAttributeValueKind::I4:
        case CustomAttributeValueKind::U4:
        case CustomAttributeValueKind::I8:
        case CustomAttributeValueKind::U8:
        case CustomAttributeValueKind::R4:
        case CustomAttributeValueKind::R8:
            return readPrimitive(reader, output.kind, output.value);
        default:
            break;
        }

        if (rawKind == 0x1d) unsupported("array-value-unsupported", "Array custom attribute values are not supported", typeOffset);
        else if (rawKind == 0x12 || rawKind == 0x15 || rawKind == 0x1c) {
            unsupported("object-value-unsupported", "Object custom attribute values are not supported", typeOffset);
        } else {
            unsupported("value-type-unsupported", "Custom attribute value type 0x" +
                std::to_string(static_cast<unsigned>(rawKind)) + " is not supported", typeOffset);
        }
        return false;
    }

    bool accountArguments(uint64_t amount, size_t offset) {
        if (amount > options_.maxTotalArguments ||
            totalArguments_ > options_.maxTotalArguments - static_cast<size_t>(amount)) {
            fail("total-argument-limit", "Custom attribute argument count exceeds the configured total limit", offset);
            return false;
        }
        totalArguments_ += static_cast<size_t>(amount);
        return true;
    }

    bool readNamedArgument(
        BlobReader& reader,
        EvaluatedCustomAttribute& attribute,
        CustomAttributeNamedKind kind,
        CustomAttributeValue value) {
        CustomAttributeNamedArgument named;
        named.kind = kind;
        named.value = std::move(value);

        int32_t encodedMember = 0;
        if (!compressedInt(reader, encodedMember, "named member index")) return false;
        int32_t ownerDefinition = attribute.attributeTypeDefinitionIndex;
        uint64_t memberIndex = 0;
        if (encodedMember < 0) {
            memberIndex = static_cast<uint64_t>(-static_cast<int64_t>(encodedMember) - 1);
            uint32_t ownerIndex = 0;
            if (!compressedUInt(reader, ownerIndex, "named member declaring type")) return false;
            if (version_ >= 104.0) {
                named.ownerTypeReferenceIndex = ownerIndex;
                TypeResolution owner;
                if (!resolveType(ownerIndex, owner, reader.position())) return false;
                ownerDefinition = owner.definitionIndex;
            } else {
                ownerDefinition = ownerIndex > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())
                    ? -1
                    : static_cast<int32_t>(ownerIndex);
            }
        } else {
            memberIndex = static_cast<uint32_t>(encodedMember);
        }

        named.ownerTypeDefinitionIndex = ownerDefinition;
        if (ownerDefinition < 0 || static_cast<size_t>(ownerDefinition) >= metadata_->types.size() ||
            memberIndex > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
            fail("named-owner-out-of-range", "Named custom attribute member has an invalid declaring type or member index", reader.position());
            return false;
        }
        named.memberIndex = static_cast<int32_t>(memberIndex);

        if (kind == CustomAttributeNamedKind::Field) {
            const auto& fields = metadata_->types[static_cast<size_t>(ownerDefinition)].fields;
            if (memberIndex >= fields.size()) {
                fail("named-field-out-of-range", "Named field index " + std::to_string(memberIndex) +
                    " exceeds field count " + std::to_string(fields.size()), reader.position());
                return false;
            }
            named.name = fields[static_cast<size_t>(memberIndex)].name;
            named.resolved = true;
        } else {
            const auto found = properties_.find(ownerDefinition);
            if (found == properties_.end()) {
                unsupported("property-metadata-unavailable", "Property definitions are unavailable for declaring type " +
                    std::to_string(ownerDefinition), reader.position());
            } else if (memberIndex >= found->second.size()) {
                fail("named-property-out-of-range", "Named property index " + std::to_string(memberIndex) +
                    " exceeds property count " + std::to_string(found->second.size()), reader.position());
                return false;
            } else {
                named.name = found->second[static_cast<size_t>(memberIndex)]->name;
                named.resolved = true;
            }
        }

        attribute.namedArguments.push_back(std::move(named));
        return true;
    }

    bool readAttribute(BlobReader& reader, uint32_t encodedConstructor) {
        EvaluatedCustomAttribute attribute;
        attribute.constructorIndex = encodedConstructor;
        attribute.blobOffset = reader.position();

        uint32_t definitionIndex = 0;
        const auto* location = resolveConstructor(encodedConstructor, definitionIndex, reader.position());
        if (location == nullptr) return false;
        const auto& declaringType = metadata_->types[location->typeIndex];
        attribute.constructor = declaringType.methods[location->methodIndex];
        attribute.attributeTypeDefinitionIndex = static_cast<int32_t>(location->typeIndex);
        attribute.attributeTypeName = qualifiedName(declaringType);
        if (attribute.attributeTypeName.empty()) attribute.attributeTypeName = attribute.constructor.declaringType;

        uint32_t constructorCount = 0;
        uint32_t fieldCount = 0;
        uint32_t propertyCount = 0;
        if (!compressedUInt(reader, constructorCount, "constructor argument count") ||
            !compressedUInt(reader, fieldCount, "named field count") ||
            !compressedUInt(reader, propertyCount, "named property count")) return false;

        if (constructorCount > options_.maxConstructorArguments) {
            fail("constructor-argument-limit", "Constructor argument count exceeds the configured limit", reader.position());
            return false;
        }
        const uint64_t namedCount = static_cast<uint64_t>(fieldCount) + propertyCount;
        if (namedCount > options_.maxNamedArguments) {
            fail("named-argument-limit", "Named argument count exceeds the configured limit", reader.position());
            return false;
        }
        if (!accountArguments(static_cast<uint64_t>(constructorCount) + namedCount, reader.position())) return false;
        if (constructorCount != attribute.constructor.parameters.size()) {
            fail("constructor-argument-count", "Constructor " + attribute.attributeTypeName + " expects " +
                std::to_string(attribute.constructor.parameters.size()) + " arguments, but the blob contains " +
                std::to_string(constructorCount), reader.position());
            return false;
        }

        attribute.constructorArguments.reserve(constructorCount);
        attribute.namedArguments.reserve(static_cast<size_t>(namedCount));
        for (uint32_t index = 0; index < constructorCount; ++index) {
            CustomAttributeValue value;
            if (!readValue(reader, value)) return false;
            attribute.constructorArguments.push_back(std::move(value));
        }
        for (uint32_t index = 0; index < fieldCount; ++index) {
            CustomAttributeValue value;
            if (!readValue(reader, value) ||
                !readNamedArgument(reader, attribute, CustomAttributeNamedKind::Field, std::move(value))) return false;
        }
        for (uint32_t index = 0; index < propertyCount; ++index) {
            CustomAttributeValue value;
            if (!readValue(reader, value) ||
                !readNamedArgument(reader, attribute, CustomAttributeNamedKind::Property, std::move(value))) return false;
        }

        attribute.blobEnd = reader.position();
        result_.attributes.push_back(std::move(attribute));
        return true;
    }

    template<typename Range>
    bool rangesSorted(std::span<const Range> ranges) {
        for (size_t index = 1; index < ranges.size(); ++index) {
            if (ranges[index - 1].token >= ranges[index].token) return false;
        }
        return true;
    }

    CustomAttributeEvaluationResult evaluateModern(size_t start, size_t count, uint32_t token) {
        const auto scoped = input_.attributeDataRanges.subspan(start, count);
        if (!rangesSorted(scoped)) {
            fail("unsorted-image-ranges", "Image custom attribute data ranges are not strictly sorted by token");
            return std::move(result_);
        }
        const auto found = std::lower_bound(
            scoped.begin(), scoped.end(), token,
            [](const CustomAttributeDataRange& range, uint32_t value) { return range.token < value; });
        if (found == scoped.end() || found->token != token) return std::move(result_);

        const size_t foundIndex = start + static_cast<size_t>(found - scoped.begin());
        if (foundIndex + 1 >= input_.attributeDataRanges.size() || foundIndex + 1 > start + count) {
            fail("missing-attribute-sentinel", "Image has no terminating custom attribute data range");
            return std::move(result_);
        }
        const auto& next = input_.attributeDataRanges[foundIndex + 1];
        if (next.startOffset < found->startOffset || next.startOffset > input_.attributeData.size()) {
            fail("attribute-range-out-of-bounds", "Custom attribute data range has invalid start or end offsets");
            return std::move(result_);
        }
        return evaluateBlob(input_.attributeData.subspan(found->startOffset, next.startOffset - found->startOffset));
    }

    CustomAttributeEvaluationResult evaluateLegacy(size_t start, size_t count, uint32_t token) {
        const auto scoped = input_.attributeTypeRanges.subspan(start, count);
        if (!rangesSorted(scoped)) {
            fail("unsorted-image-ranges", "Image custom attribute type ranges are not strictly sorted by token");
            return std::move(result_);
        }
        const auto found = std::lower_bound(
            scoped.begin(), scoped.end(), token,
            [](const CustomAttributeTypeRange& range, uint32_t value) { return range.token < value; });
        if (found == scoped.end() || found->token != token) return std::move(result_);
        if (found->start < 0 || found->count < 0) {
            fail("negative-attribute-type-range", "Custom attribute type range has a negative start or count");
            return std::move(result_);
        }
        const size_t typeStart = static_cast<size_t>(found->start);
        const size_t typeCount = static_cast<size_t>(found->count);
        if (typeStart > input_.attributeTypeIndices.size() ||
            typeCount > input_.attributeTypeIndices.size() - typeStart) {
            fail("attribute-type-range-out-of-bounds", "Custom attribute type range lies outside the type index table");
            return std::move(result_);
        }
        if (typeCount > options_.maxAttributes) {
            fail("attribute-limit", "Custom attribute count exceeds the configured limit");
            return std::move(result_);
        }

        result_.attributes.reserve(typeCount);
        for (size_t index = 0; index < typeCount; ++index) {
            currentAttribute_ = index;
            const int32_t typeIndex = input_.attributeTypeIndices[typeStart + index];
            if (typeIndex < 0) {
                fail("negative-attribute-type-index", "Custom attribute has a negative Il2CppType index");
                return std::move(result_);
            }
            TypeResolution type;
            if (!resolveType(static_cast<uint32_t>(typeIndex), type, 0)) return std::move(result_);
            if (type.definitionIndex < 0 || static_cast<size_t>(type.definitionIndex) >= metadata_->types.size()) {
                unsupported("legacy-attribute-type-unavailable", "Legacy attribute type has no type definition");
                return std::move(result_);
            }

            const auto& definition = metadata_->types[static_cast<size_t>(type.definitionIndex)];
            std::vector<const MethodModel*> constructors;
            for (const auto& method : definition.methods) {
                if (method.name == ".ctor") constructors.push_back(&method);
            }
            const MethodModel* constructor = nullptr;
            for (const auto* candidate : constructors) {
                if (candidate->parameters.empty()) {
                    if (constructor != nullptr) {
                        unsupported("legacy-constructor-ambiguous", "Legacy attribute has multiple parameterless constructors");
                        return std::move(result_);
                    }
                    constructor = candidate;
                }
            }
            if (constructor == nullptr && constructors.size() == 1) constructor = constructors.front();
            if (constructor == nullptr) {
                unsupported("legacy-constructor-unavailable", "Cannot select a unique legacy attribute constructor");
                return std::move(result_);
            }

            EvaluatedCustomAttribute attribute;
            attribute.constructorIndex = constructor->definitionIndex < 0
                ? 0
                : static_cast<uint32_t>(constructor->definitionIndex);
            attribute.constructor = *constructor;
            attribute.attributeTypeDefinitionIndex = type.definitionIndex;
            attribute.attributeTypeName = type.name;
            result_.attributes.push_back(std::move(attribute));
        }
        currentAttribute_.reset();
        if (typeCount != 0) {
            unsupported("legacy-arguments-unsupported", "Version 27 constructor and named arguments require native attribute generator analysis");
        }
        return std::move(result_);
    }

    const AttributeEvaluationInput& input_;
    const AttributeEvaluatorOptions& options_;
    CustomAttributeEvaluationResult result_;
    const MetadataModel* metadata_ = nullptr;
    double version_ = 0;
    std::optional<uint32_t> token_;
    std::optional<size_t> imageIndex_;
    std::optional<size_t> currentAttribute_;
    size_t totalArguments_ = 0;
    std::unordered_map<int32_t, MethodLocation> methods_;
    std::unordered_set<int32_t> ambiguousMethods_;
    std::unordered_map<int32_t, std::vector<const CustomAttributeProperty*>> properties_;
};

} // namespace

bool CustomAttributeValue::isNull() const noexcept {
    return std::holds_alternative<std::monostate>(value);
}

bool CustomAttributeEvaluationResult::ok() const noexcept {
    return complete && std::none_of(diagnostics.begin(), diagnostics.end(), [](const CustomAttributeDiagnostic& entry) {
        return entry.severity == CustomAttributeDiagnosticSeverity::Error;
    });
}

AttributeEvaluator::AttributeEvaluator(AttributeEvaluatorOptions options)
    : options_(options) {
}

bool AttributeEvaluator::supports(double version) noexcept {
    return version >= 27.0;
}

CustomAttributeEvaluationResult AttributeEvaluator::evaluate(
    const AttributeEvaluationInput& input,
    uint32_t token,
    size_t imageIndex) const {
    CustomAttributeEvaluationResult result;
    return EvaluationSession(input, options_, result).evaluate(token, imageIndex);
}

CustomAttributeEvaluationResult AttributeEvaluator::evaluateBlob(
    const AttributeEvaluationInput& input,
    std::span<const uint8_t> blob) const {
    CustomAttributeEvaluationResult result;
    return EvaluationSession(input, options_, result).evaluateBlob(blob);
}

CustomAttributeEvaluationResult AttributeEvaluator::evaluateBlob(
    double version,
    const MetadataModel& metadata,
    std::span<const uint8_t> blob,
    std::span<const CustomAttributeProperty> properties) const {
    AttributeEvaluationInput input;
    input.version = version;
    input.metadata = &metadata;
    input.properties = properties;
    return evaluateBlob(input, blob);
}

} // namespace il2cpprec
