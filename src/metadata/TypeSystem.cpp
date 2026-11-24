#include <il2cpprec/metadata/TypeSystem.hpp>

#include <il2cpprec/ida/SourceProfile.hpp>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace il2cpprec {
namespace {

std::string trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c) != 0; });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) { return std::isspace(c) != 0; }).base();
    if (first >= last) return {};
    return std::string(first, last);
}

std::string withoutGenericArity(std::string name) {
    size_t position = 0;
    while ((position = name.find('`', position)) != std::string::npos) {
        size_t end = position + 1;
        while (end < name.size() && std::isdigit(static_cast<unsigned char>(name[end])) != 0) ++end;
        if (end == position + 1) {
            ++position;
            continue;
        }
        name.erase(position, end - position);
    }
    std::replace(name.begin(), name.end(), '+', '.');
    return name;
}

bool isKeyword(std::string_view identifier) {
    static const std::unordered_set<std::string_view> keywords = {
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
        "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else",
        "enum", "event", "explicit", "extern", "false", "finally", "fixed", "float", "for",
        "foreach", "goto", "if", "implicit", "in", "int", "interface", "internal", "is", "lock",
        "long", "namespace", "new", "null", "object", "operator", "out", "override", "params",
        "private", "protected", "public", "readonly", "ref", "return", "sbyte", "sealed", "short",
        "sizeof", "stackalloc", "static", "string", "struct", "switch", "this", "throw", "true",
        "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort", "using", "virtual",
        "void", "volatile", "while"
    };
    return keywords.contains(identifier);
}

std::string identifier(std::string_view name, std::string_view fallback) {
    if (name.empty()) name = fallback;
    std::string result;
    result.reserve(name.size() + 2);
    bool escaped = name.front() == '@';
    if (escaped) result.push_back('@');
    for (size_t i = escaped ? 1 : 0; i < name.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(name[i]);
        result.push_back(std::isalnum(c) != 0 || c == '_' || c >= 0x80 ? static_cast<char>(c) : '_');
    }
    if (result.empty() || result == "@") result = std::string(fallback);
    const size_t identifierStart = result.front() == '@' ? 1 : 0;
    if (identifierStart == result.size() || std::isdigit(static_cast<unsigned char>(result[identifierStart])) != 0) {
        result.insert(identifierStart, 1, '_');
    }
    if (!escaped && isKeyword(result)) result.insert(result.begin(), '@');
    return result;
}

struct NameSegment {
    std::string_view name;
    size_t genericArity = 0;
};

NameSegment nameSegment(std::string_view name) {
    NameSegment result{name};
    const size_t backtick = name.rfind('`');
    if (backtick == std::string_view::npos || backtick + 1 == name.size()) return result;

    size_t arity = 0;
    for (size_t i = backtick + 1; i < name.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(name[i]);
        if (std::isdigit(c) == 0) return result;
        const size_t digit = static_cast<size_t>(c - '0');
        if (arity > (std::numeric_limits<size_t>::max() - digit) / 10) {
            result.genericArity = 0;
            return result;
        }
        arity = arity * 10 + digit;
    }
    result.name = name.substr(0, backtick);
    result.genericArity = arity;
    return result;
}

void appendGenericArguments(
    std::string& result,
    const std::vector<std::string>& arguments,
    size_t& offset,
    size_t count) {
    if (count == 0) return;
    result.push_back('<');
    for (size_t i = 0; i < count; ++i) {
        if (i != 0) result += ", ";
        if (offset < arguments.size()) {
            result += arguments[offset].empty() ? "object" : arguments[offset];
            ++offset;
        } else {
            result += "object";
        }
    }
    result.push_back('>');
}

std::string formatTypeName(
    std::string_view name,
    std::string_view nameSpace,
    const std::vector<std::string>& genericArguments,
    bool genericInstance) {
    std::string fullName;
    if (nameSpace.starts_with("global::")) nameSpace.remove_prefix(8);
    if (name.starts_with("global::")) name.remove_prefix(8);
    if (!nameSpace.empty()) {
        fullName = nameSpace;
        if (!name.empty()) fullName.push_back('.');
    }
    fullName += name;
    if (fullName.empty()) return {};

    std::vector<NameSegment> segments;
    size_t start = 0;
    while (start <= fullName.size()) {
        const size_t end = fullName.find_first_of(".+/", start);
        const size_t length = (end == std::string::npos ? fullName.size() : end) - start;
        if (length != 0) segments.push_back(nameSegment(std::string_view(fullName).substr(start, length)));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (segments.empty()) return {};

    const bool hasExplicitArity = std::any_of(segments.begin(), segments.end(), [](const NameSegment& segment) {
        return segment.genericArity != 0;
    });
    std::string result;
    size_t argumentOffset = 0;
    for (size_t i = 0; i < segments.size(); ++i) {
        if (i != 0) result.push_back('.');
        result += identifier(segments[i].name, "UnknownType");
        if (!genericInstance) continue;
        if (segments[i].genericArity != 0) {
            appendGenericArguments(result, genericArguments, argumentOffset, segments[i].genericArity);
        } else if (i + 1 == segments.size() && !hasExplicitArity) {
            appendGenericArguments(result, genericArguments, argumentOffset, genericArguments.size());
        }
    }
    if (genericInstance && argumentOffset < genericArguments.size()) {
        appendGenericArguments(result, genericArguments, argumentOffset, genericArguments.size() - argumentOffset);
    }
    return result;
}

std::string qualifiedName(const TypeModel& type) {
    std::string result = formatTypeName(type.name, type.nameSpace, {}, false);
    return result.empty() ? "UnknownType" : result;
}

std::string byRefType(std::string type) {
    type = trim(std::move(type));
    if (type.empty()) return "ref object";
    if (type.starts_with("ref ")) return type;
    if (type.back() != '&') return type;
    type.pop_back();
    type = trim(std::move(type));
    return "ref " + (type.empty() ? std::string("object") : type);
}

bool parseTypeReference(std::string_view type, size_t& index) {
    if (type.size() <= 6 || !type.starts_with("type[") || type.back() != ']') return false;
    size_t value = 0;
    for (size_t i = 5; i + 1 < type.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(type[i]);
        if (std::isdigit(c) == 0) return false;
        const size_t digit = static_cast<size_t>(c - '0');
        if (value > (std::numeric_limits<size_t>::max() - digit) / 10) return false;
        value = value * 10 + digit;
    }
    index = value;
    return true;
}

class ReferenceResolver {
public:
    explicit ReferenceResolver(const MetadataModel& metadata)
        : metadata_(metadata), resolving_(metadata.typeReferences.size(), false) {}

    std::string resolve(size_t index, size_t depth = 0) {
        if (index >= metadata_.typeReferences.size() || depth > maxDepth || resolving_[index]) return "object";
        resolving_[index] = true;
        const TypeReferenceModel& reference = metadata_.typeReferences[index];
        const auto code = static_cast<Il2CppTypeCode>(reference.code);
        std::string result;

        if (auto primitive = TypeSystem::primitiveType(code)) {
            result = std::move(*primitive);
        } else {
            switch (code) {
            case Il2CppTypeCode::Ptr:
                result = element(reference, depth, "void") + "*";
                break;
            case Il2CppTypeCode::ByRef:
                result = "ref " + element(reference, depth, "object");
                break;
            case Il2CppTypeCode::ValueType:
                result = namedType(reference, {}, false, "System.ValueType");
                break;
            case Il2CppTypeCode::Class:
                result = namedType(reference, {}, false, "object");
                break;
            case Il2CppTypeCode::Var:
                result = identifier(reference.name, genericParameterName(reference.definitionIndex, "T"));
                break;
            case Il2CppTypeCode::Array:
                result = arrayType(element(reference, depth, "object"), reference.rank);
                break;
            case Il2CppTypeCode::GenericInst: {
                std::vector<std::string> arguments;
                arguments.reserve(reference.genericArgumentIndices.size());
                for (const int32_t argument : reference.genericArgumentIndices) {
                    arguments.push_back(argument < 0 ? "object" : resolve(static_cast<size_t>(argument), depth + 1));
                }
                result = namedType(reference, arguments, true, "object");
                break;
            }
            case Il2CppTypeCode::SzArray:
                result = element(reference, depth, "object") + "[]";
                break;
            case Il2CppTypeCode::MVar:
                result = identifier(reference.name, genericParameterName(reference.definitionIndex, "TMethod"));
                break;
            case Il2CppTypeCode::CModReqD:
            case Il2CppTypeCode::CModOpt:
            case Il2CppTypeCode::Modifier:
            case Il2CppTypeCode::Sentinel:
            case Il2CppTypeCode::Pinned:
                result = element(reference, depth, "object");
                break;
            case Il2CppTypeCode::Enum:
                result = namedType(reference, {}, false, "System.Enum");
                break;
            case Il2CppTypeCode::Internal:
                result = namedType(reference, {}, false, "object");
                break;
            case Il2CppTypeCode::TypeIndex:
                result = element(reference, depth, "object");
                break;
            default:
                result = "object";
                break;
            }
        }

        resolving_[index] = false;
        if (result.empty()) result = "object";
        if (reference.byRef && code != Il2CppTypeCode::ByRef && !result.starts_with("ref ")) {
            result.insert(0, "ref ");
        }
        return result;
    }

private:
    static constexpr size_t maxDepth = 64;
    static constexpr uint32_t maxArrayRank = 64;

    static std::string genericParameterName(int32_t index, std::string_view prefix) {
        std::string result(prefix);
        if (index > 0) result += std::to_string(index);
        return result;
    }

    static std::string arrayType(std::string element, uint32_t rank) {
        if (rank > maxArrayRank) return "object";
        element += '[';
        element.append(std::max(rank, 1u) - 1, ',');
        element.push_back(']');
        return element;
    }

    std::string element(const TypeReferenceModel& reference, size_t depth, std::string_view fallback) {
        if (reference.elementTypeIndex < 0) return std::string(fallback);
        return resolve(static_cast<size_t>(reference.elementTypeIndex), depth + 1);
    }

    std::string namedType(
        const TypeReferenceModel& reference,
        const std::vector<std::string>& genericArguments,
        bool genericInstance,
        std::string_view fallback) const {
        if (reference.definitionIndex >= 0) {
            const auto index = static_cast<size_t>(reference.definitionIndex);
            if (index < metadata_.types.size() && !metadata_.types[index].name.empty()) {
                const TypeModel& definition = metadata_.types[index];
                std::string result = formatTypeName(definition.name, definition.nameSpace, genericArguments, genericInstance);
                if (!result.empty()) return result;
            }
        }
        std::string result = formatTypeName(reference.name, {}, genericArguments, genericInstance);
        return result.empty() ? std::string(fallback) : result;
    }

    const MetadataModel& metadata_;
    std::vector<bool> resolving_;
};

std::string constructorName(const MethodModel& method) {
    std::string name = method.declaringType;
    const size_t separator = name.find_last_of(".+/");
    if (separator != std::string::npos) name.erase(0, separator + 1);
    name = withoutGenericArity(name);
    return identifier(name, "UnknownType");
}

double contextMetadataVersion(const TypeLayoutContext& context) {
    if (context.metadataVersion != 0) return context.metadataVersion;
    return context.metadata != nullptr ? context.metadata->version : 0;
}

ida::SourceLayoutSelection sourceSelection(const TypeLayoutContext& context) {
    const double version = contextMetadataVersion(context);
    if (context.sourceProfile != nullptr) return context.sourceProfile->resolve(version, context.pointerSize);
    if (version == 0) return ida::metadata24BaseProfile().resolve(24.1, context.pointerSize);
    if (const auto* profile = ida::Il2CppNativeProfileRegistry::findMetadata(version)) {
        return profile->resolve(version, context.pointerSize);
    }
    return ida::metadata24BaseProfile().resolve(version, context.pointerSize);
}

enum class ManagedLayoutKind {
    Object,
    Array,
    String
};

std::optional<size_t> managedLayoutSize(ManagedLayoutKind kind, const TypeLayoutContext& context) {
    const auto selection = sourceSelection(context);
    if (!selection.supported || !selection.capabilities.managedObjectLayout) return std::nullopt;
    size_t size = 0;
    switch (kind) {
    case ManagedLayoutKind::Object: size = selection.object.size; break;
    case ManagedLayoutKind::Array: size = selection.array.size; break;
    case ManagedLayoutKind::String: size = selection.string.size; break;
    }
    return size == 0 ? std::nullopt : std::optional<size_t>(size);
}

std::optional<size_t> objectHeaderSize(const TypeLayoutContext& context) {
    return managedLayoutSize(ManagedLayoutKind::Object, context);
}

struct NativeLayout {
    std::optional<size_t> size;
    std::optional<size_t> alignment;
    std::optional<size_t> naturalAlignment;
    std::optional<TypeLayoutDiagnostic> diagnostic = std::nullopt;
};

NativeLayout pointerLayout(size_t pointerSize) {
    return {pointerSize, pointerSize, pointerSize};
}

NativeLayout nativeLayoutName(std::string type, const TypeLayoutContext& context) {
    const size_t pointerSize = context.pointerSize;
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
    type = trim(std::move(type));
    for (const std::string_view prefix : {std::string_view("ref "), std::string_view("out "), std::string_view("in ")}) {
        if (type.starts_with(prefix)) return pointerLayout(pointerSize);
    }
    if (!type.empty() && (type.back() == '&' || type.back() == '*')) return pointerLayout(pointerSize);
    if (!type.empty() && type.back() == ']') return pointerLayout(pointerSize);
    if (type.starts_with("global::")) type.erase(0, 8);

    static const std::pair<std::string_view, size_t> fixedTypes[] = {
        {"bool", 1}, {"System.Boolean", 1},
        {"char", 2}, {"System.Char", 2},
        {"sbyte", 1}, {"System.SByte", 1}, {"byte", 1}, {"System.Byte", 1},
        {"short", 2}, {"System.Int16", 2}, {"ushort", 2}, {"System.UInt16", 2},
        {"int", 4}, {"System.Int32", 4}, {"uint", 4}, {"System.UInt32", 4},
        {"long", 8}, {"System.Int64", 8}, {"ulong", 8}, {"System.UInt64", 8},
        {"float", 4}, {"System.Single", 4}, {"double", 8}, {"System.Double", 8}
    };
    for (const auto& [name, size] : fixedTypes) {
        if (type == name) return {size, size, size};
    }
    if (type == "decimal" || type == "System.Decimal") return {size_t{16}, size_t{4}, size_t{4}};
    if (type == "System.TypedReference") {
        const auto selection = sourceSelection(context);
        if (!selection.supported || selection.typedReferencePointers == 0 ||
            selection.typedReferencePointers > std::numeric_limits<size_t>::max() / pointerSize) return {};
        return {selection.typedReferencePointers * pointerSize, pointerSize, pointerSize};
    }
    if (type == "nint" || type == "nuint" || type == "System.IntPtr" || type == "System.UIntPtr" ||
        type == "string" || type == "System.String" || type == "object" || type == "System.Object") {
        return pointerLayout(pointerSize);
    }
    return {};
}

const TypeLayoutInfo* definitionLayout(int32_t definitionIndex, const TypeLayoutContext& context) {
    if (definitionIndex < 0 || context.typeLayouts == nullptr) return nullptr;
    const auto index = static_cast<size_t>(definitionIndex);
    return index < context.typeLayouts->size() ? &(*context.typeLayouts)[index] : nullptr;
}

NativeLayout nativeLayout(std::string_view type, const TypeLayoutContext& context, size_t depth = 0);
std::optional<uint64_t> alignUp(uint64_t value, uint64_t alignment);
std::optional<uint64_t> fieldEnd(uint64_t offset, size_t size);

enum class DefinitionKind {
    Unknown,
    Reference,
    Value
};

DefinitionKind definitionKind(int32_t definitionIndex, const TypeLayoutContext& context) {
    const TypeLayoutInfo* layout = definitionLayout(definitionIndex, context);
    if (layout != nullptr && layout->valueType) return DefinitionKind::Value;
    if (definitionIndex >= 0 && context.metadata != nullptr) {
        const auto index = static_cast<size_t>(definitionIndex);
        if (index < context.metadata->types.size()) {
            std::string baseType = trim(context.metadata->types[index].baseType);
            if (baseType.starts_with("type[")) {
                baseType = TypeSystem::resolve(baseType, context.metadata);
                if (baseType == "object") baseType.clear();
            }
            if (baseType == "System.ValueType" || baseType == "System.Enum") return DefinitionKind::Value;
            if (!baseType.empty()) return DefinitionKind::Reference;
        }
    }
    if (layout != nullptr && (layout->array || layout->referenceType)) return DefinitionKind::Reference;
    return DefinitionKind::Unknown;
}

NativeLayout inferredValueTypeLayout(int32_t definitionIndex, const TypeLayoutContext& context, size_t depth) {
    if (definitionIndex < 0 || context.metadata == nullptr || depth >= 64) return {};
    const auto index = static_cast<size_t>(definitionIndex);
    if (index >= context.metadata->types.size()) return {};

    const TypeModel& definition = context.metadata->types[index];
    if (definition.name.find('`') != std::string::npos) return {};
    const TypeLayoutInfo* supplied = definitionLayout(definitionIndex, context);
    if (supplied != nullptr && supplied->generic) return {};

    const auto header = objectHeaderSize(context);
    if (!header) return {};
    const uint64_t headerSize = *header;
    uint64_t actualSize = headerSize;
    uint32_t minimumAlignment = supplied != nullptr && supplied->minimumAlignment != 0 ? supplied->minimumAlignment : 1;
    uint32_t naturalAlignment = supplied != nullptr ? supplied->naturalAlignment : 0;
    bool hasInstanceFields = false;

    for (size_t fieldIndex = 0; fieldIndex < definition.fields.size(); ++fieldIndex) {
        const FieldModel& field = definition.fields[fieldIndex];
        if (field.isStatic) continue;
        hasInstanceFields = true;
        const NativeLayout fieldLayout = nativeLayout(field.type, context, depth + 1);
        if (!fieldLayout.size || !fieldLayout.alignment) return {};

        size_t alignment = *fieldLayout.alignment;
        if (alignment < 4 && fieldLayout.naturalAlignment) alignment = *fieldLayout.naturalAlignment;
        if (supplied != nullptr && supplied->packingSize != 0) {
            alignment = std::min(*fieldLayout.alignment, static_cast<size_t>(supplied->packingSize));
        }
        if (alignment == 0) return {};
        minimumAlignment = std::max(minimumAlignment, static_cast<uint32_t>(alignment));
        naturalAlignment = std::max(naturalAlignment, static_cast<uint32_t>(*fieldLayout.alignment));

        std::optional<int64_t> offset;
        if (supplied != nullptr && fieldIndex < supplied->fieldOffsets.size()) {
            offset = supplied->fieldOffsets[fieldIndex];
        } else if (field.token != 0) {
            const auto found = context.metadata->fieldOffsetsByToken.find(field.token);
            if (found != context.metadata->fieldOffsetsByToken.end()) offset = found->second;
        }
        if (!offset && field.offset > 0) offset = field.offset;

        if (offset && *offset >= 0) {
            const auto end = fieldEnd(static_cast<uint64_t>(*offset), *fieldLayout.size);
            if (!end) return {};
            actualSize = std::max(actualSize, *end);
        } else {
            const auto aligned = alignUp(actualSize, alignment);
            if (!aligned) return {};
            const auto end = fieldEnd(*aligned, *fieldLayout.size);
            if (!end) return {};
            actualSize = *end;
        }
    }

    NativeLayout result;
    if (hasInstanceFields) {
        const auto classSize = alignUp(actualSize, minimumAlignment);
        if (!classSize || *classSize < headerSize) return {};
        const uint64_t valueSize = *classSize - headerSize;
        if (valueSize > std::numeric_limits<size_t>::max()) return {};
        result.size = static_cast<size_t>(valueSize);
    } else {
        result.size = 1;
    }
    result.alignment = minimumAlignment;
    result.naturalAlignment = naturalAlignment;
    return result;
}

NativeLayout valueTypeLayout(const TypeReferenceModel& reference, const TypeLayoutContext& context, size_t depth) {
    NativeLayout result;
    const auto header = objectHeaderSize(context);
    if (const TypeLayoutInfo* layout = definitionLayout(reference.definitionIndex, context)) {
        if (!layout->generic && header && layout->instanceSize >= *header) {
            const uint64_t valueSize = layout->instanceSize - *header;
            if (valueSize <= std::numeric_limits<size_t>::max()) result.size = static_cast<size_t>(valueSize);
        }
        if (layout->minimumAlignment != 0) result.alignment = layout->minimumAlignment;
        if (layout->naturalAlignment != 0) result.naturalAlignment = layout->naturalAlignment;
    }
    if (result.size && result.alignment) return result;

    if (reference.name != "string" && reference.name != "System.String" &&
        reference.name != "object" && reference.name != "System.Object") {
        const NativeLayout wellKnown = nativeLayoutName(reference.name, context);
        if (wellKnown.size) result.size = wellKnown.size;
        if (wellKnown.alignment) result.alignment = wellKnown.alignment;
        if (wellKnown.naturalAlignment) result.naturalAlignment = wellKnown.naturalAlignment;
    }
    if (result.size && result.alignment) return result;

    const NativeLayout inferred = inferredValueTypeLayout(reference.definitionIndex, context, depth + 1);
    if (!result.size && inferred.size) result.size = inferred.size;
    if (!result.alignment && inferred.alignment) result.alignment = inferred.alignment;
    if (!result.naturalAlignment && inferred.naturalAlignment) result.naturalAlignment = inferred.naturalAlignment;
    return result;
}

NativeLayout enumLayout(const TypeReferenceModel& reference, const TypeLayoutContext& context, size_t depth) {
    NativeLayout result = valueTypeLayout(reference, context, depth);
    if (result.size && result.alignment) return result;
    if (reference.definitionIndex < 0 || context.metadata == nullptr || depth > 64) return result;

    const auto index = static_cast<size_t>(reference.definitionIndex);
    if (index >= context.metadata->types.size()) return result;
    for (const FieldModel& field : context.metadata->types[index].fields) {
        if (!field.isStatic && field.name == "value__") return nativeLayout(field.type, context, depth + 1);
    }
    return result;
}

NativeLayout nativeReferenceLayout(size_t index, const TypeLayoutContext& context, size_t depth) {
    if (context.metadata == nullptr || depth > 64 || index >= context.metadata->typeReferences.size()) return {};
    const TypeReferenceModel& reference = context.metadata->typeReferences[index];
    if (reference.byRef) return pointerLayout(context.pointerSize);

    const auto code = static_cast<Il2CppTypeCode>(reference.code);
    if (auto primitive = TypeSystem::primitiveType(code)) {
        if (code == Il2CppTypeCode::Void) return {};
        return nativeLayoutName(*primitive, context);
    }

    switch (code) {
    case Il2CppTypeCode::Ptr:
    case Il2CppTypeCode::ByRef:
    case Il2CppTypeCode::Class:
    case Il2CppTypeCode::Array:
    case Il2CppTypeCode::SzArray:
        return pointerLayout(context.pointerSize);
    case Il2CppTypeCode::ValueType:
        return valueTypeLayout(reference, context, depth);
    case Il2CppTypeCode::GenericInst:
        switch (definitionKind(reference.definitionIndex, context)) {
        case DefinitionKind::Reference:
            return pointerLayout(context.pointerSize);
        case DefinitionKind::Value:
            return valueTypeLayout(reference, context, depth);
        default:
            return {};
        }
    case Il2CppTypeCode::CModReqD:
    case Il2CppTypeCode::CModOpt:
    case Il2CppTypeCode::Modifier:
    case Il2CppTypeCode::Sentinel:
    case Il2CppTypeCode::Pinned:
    case Il2CppTypeCode::TypeIndex:
        if (reference.elementTypeIndex < 0) return {};
        return nativeReferenceLayout(static_cast<size_t>(reference.elementTypeIndex), context, depth + 1);
    case Il2CppTypeCode::Enum:
        return enumLayout(reference, context, depth);
    default:
        return {};
    }
}

NativeLayout nativeLayout(std::string_view type, const TypeLayoutContext& context, size_t depth) {
    if (context.pointerSize != 4 && context.pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
    const std::string value = trim(std::string(type));
    NativeLayout result;
    size_t referenceIndex = 0;
    if (value.starts_with("type[")) {
        if (parseTypeReference(value, referenceIndex)) result = nativeReferenceLayout(referenceIndex, context, depth);
    } else {
        result = nativeLayoutName(value, context);
    }

    if ((!result.size || !result.alignment) && !result.diagnostic) {
        TypeLayoutDiagnostic diagnostic;
        diagnostic.typeName = value.empty() ? "<empty>" : value;
        diagnostic.pointerBits = static_cast<uint16_t>(context.pointerSize * 8);
        diagnostic.message = "native size or alignment is unknown at " + std::to_string(diagnostic.pointerBits) +
            "-bit pointer size; no width was assumed";
        if (!sourceSelection(context).supported) {
            diagnostic.message += "; no supported source profile matches the metadata version";
        }
        if (value.starts_with("type[") && context.metadata == nullptr) {
            diagnostic.message += "; type reference metadata is unavailable";
        }
        result.diagnostic = std::move(diagnostic);
    }
    return result;
}

std::optional<uint64_t> alignUp(uint64_t value, uint64_t alignment) {
    if (alignment == 0) return std::nullopt;
    const uint64_t remainder = value % alignment;
    if (remainder == 0) return value;
    const uint64_t padding = alignment - remainder;
    if (padding > std::numeric_limits<uint64_t>::max() - value) return std::nullopt;
    return value + padding;
}

std::optional<uint64_t> fieldEnd(uint64_t offset, size_t size) {
    const uint64_t amount = std::max<uint64_t>(static_cast<uint64_t>(size), 1);
    if (amount > std::numeric_limits<uint64_t>::max() - offset) return std::nullopt;
    return offset + amount;
}

std::string hex(uint64_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << std::uppercase << value;
    return output.str();
}

std::string elementType(const ManagedType& type, std::string_view fallback) {
    return type.elementType ? TypeSystem::cSharpType(*type.elementType) : std::string(fallback);
}

} // namespace

std::optional<std::string> TypeSystem::primitiveType(Il2CppTypeCode code) {
    switch (code) {
    case Il2CppTypeCode::Void: return "void";
    case Il2CppTypeCode::Boolean: return "bool";
    case Il2CppTypeCode::Char: return "char";
    case Il2CppTypeCode::I1: return "sbyte";
    case Il2CppTypeCode::U1: return "byte";
    case Il2CppTypeCode::I2: return "short";
    case Il2CppTypeCode::U2: return "ushort";
    case Il2CppTypeCode::I4: return "int";
    case Il2CppTypeCode::U4: return "uint";
    case Il2CppTypeCode::I8: return "long";
    case Il2CppTypeCode::U8: return "ulong";
    case Il2CppTypeCode::R4: return "float";
    case Il2CppTypeCode::R8: return "double";
    case Il2CppTypeCode::String: return "string";
    case Il2CppTypeCode::TypedByRef: return "System.TypedReference";
    case Il2CppTypeCode::I: return "nint";
    case Il2CppTypeCode::U: return "nuint";
    case Il2CppTypeCode::FnPtr: return "System.IntPtr";
    case Il2CppTypeCode::Object: return "object";
    default: return std::nullopt;
    }
}

std::string TypeSystem::cSharpType(Il2CppTypeCode code) {
    auto primitive = primitiveType(code);
    return primitive ? std::move(*primitive) : std::string();
}

std::string TypeSystem::cSharpType(const ManagedType& type) {
    std::string result;
    if (auto primitive = primitiveType(type.code)) {
        result = std::move(*primitive);
    } else {
        switch (type.code) {
        case Il2CppTypeCode::Ptr:
            result = elementType(type, "void") + "*";
            break;
        case Il2CppTypeCode::ByRef:
            result = "ref " + elementType(type, "object");
            break;
        case Il2CppTypeCode::ValueType:
            result = formatTypeName(type.name, {}, {}, false);
            if (result.empty()) result = "System.ValueType";
            break;
        case Il2CppTypeCode::Class:
            result = formatTypeName(type.name, {}, {}, false);
            if (result.empty()) result = "object";
            break;
        case Il2CppTypeCode::Var:
            result = identifier(type.name, "T");
            break;
        case Il2CppTypeCode::Array:
            if (type.rank > 64) {
                result = "object";
            } else {
                result = elementType(type, "object") + "[";
                result.append(std::max(type.rank, 1u) - 1, ',');
                result.push_back(']');
            }
            break;
        case Il2CppTypeCode::GenericInst: {
            std::vector<std::string> arguments;
            arguments.reserve(type.genericArguments.size());
            for (const ManagedType& argument : type.genericArguments) arguments.push_back(cSharpType(argument));
            result = formatTypeName(type.name, {}, arguments, true);
            if (result.empty()) result = "object";
            break;
        }
        case Il2CppTypeCode::SzArray:
            result = elementType(type, "object") + "[]";
            break;
        case Il2CppTypeCode::MVar:
            result = identifier(type.name, "TMethod");
            break;
        case Il2CppTypeCode::CModReqD:
        case Il2CppTypeCode::CModOpt:
        case Il2CppTypeCode::Modifier:
        case Il2CppTypeCode::Sentinel:
        case Il2CppTypeCode::Pinned:
            result = elementType(type, "object");
            break;
        case Il2CppTypeCode::Enum:
            result = formatTypeName(type.name, {}, {}, false);
            if (result.empty()) result = "System.Enum";
            break;
        case Il2CppTypeCode::Internal:
            result = formatTypeName(type.name, {}, {}, false);
            if (result.empty()) result = "object";
            break;
        default:
            result = "object";
            break;
        }
    }
    if (type.byRef && type.code != Il2CppTypeCode::ByRef && !result.starts_with("ref ")) {
        result.insert(0, "ref ");
    }
    return result;
}

std::string TypeSystem::resolve(std::string_view type, const MetadataModel* metadata) {
    std::string value = trim(std::string(type));
    if (value.empty()) return "object";
    if (!value.starts_with("type[")) return value;

    size_t index = 0;
    if (metadata == nullptr || !parseTypeReference(value, index)) return "object";
    return resolve(index, *metadata);
}

std::string TypeSystem::resolve(size_t typeReferenceIndex, const MetadataModel& metadata) {
    return ReferenceResolver(metadata).resolve(typeReferenceIndex);
}

std::string TypeSystem::returnType(const MethodModel& method, const MetadataModel* metadata) {
    return method.returnType.empty() ? "void" : byRefType(resolve(method.returnType, metadata));
}

std::string TypeSystem::parameter(const ParameterModel& parameter, size_t index, const MetadataModel* metadata) {
    std::string type = parameter.type.empty() ? "object" : byRefType(resolve(parameter.type, metadata));
    const std::string fallback = "param" + std::to_string(index);
    return type + " " + identifier(parameter.name, fallback);
}

std::string TypeSystem::parameterList(const MethodModel& method, const MetadataModel* metadata) {
    std::string result = "(";
    for (size_t i = 0; i < method.parameters.size(); ++i) {
        if (i != 0) result += ", ";
        result += TypeSystem::parameter(method.parameters[i], i, metadata);
    }
    result.push_back(')');
    return result;
}

std::string TypeSystem::methodSignature(const MethodModel& method, const MetadataModel* metadata) {
    const std::string parameters = parameterList(method, metadata);
    if (method.name == ".ctor") return "public " + constructorName(method) + parameters;
    if (method.name == ".cctor") return "static " + constructorName(method) + parameters;

    std::string result = method.isStatic ? "public static " : "public ";
    result += returnType(method, metadata);
    result.push_back(' ');
    result += identifier(method.name, "Method");
    result += parameters;
    return result;
}

std::optional<Il2CppTypeBitLayout> TypeSystem::il2CppTypeLayout(const TypeLayoutContext& context) {
    if (context.pointerSize != 4 && context.pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
    const auto selection = sourceSelection(context);
    if (!selection.supported || !selection.typeBits.present) return std::nullopt;

    const auto& source = selection.typeBits;
    Il2CppTypeBitLayout result;
    result.size = source.size;
    result.dataOffset = source.dataOffset;
    result.bitsOffset = source.bitsOffset;
    result.bitsSize = source.bitsSize;
    result.codeOffset = source.codeOffset;
    result.codeSize = source.codeSize;
    result.byRefOffset = source.byRefOffset;
    result.byRefSize = source.byRefMask != 0 ? 1 : 0;
    result.pinnedOffset = source.pinnedOffset;
    result.pinnedSize = source.pinnedMask != 0 ? 1 : 0;
    result.byRefMask = source.byRefMask;
    result.pinnedMask = source.pinnedMask;
    return result;
}

std::optional<size_t> TypeSystem::nativeSize(std::string_view type, const TypeLayoutContext& context) {
    return nativeLayout(type, context).size;
}

std::optional<size_t> TypeSystem::nativeAlignment(std::string_view type, const TypeLayoutContext& context) {
    return nativeLayout(type, context).alignment;
}

std::optional<TypeLayoutDiagnostic> TypeSystem::layoutDiagnostic(std::string_view type, const TypeLayoutContext& context) {
    return nativeLayout(type, context).diagnostic;
}

std::optional<size_t> TypeSystem::fieldSize(const FieldModel& field, size_t pointerSize) {
    return fieldSize(field, TypeLayoutContext{pointerSize});
}

std::optional<size_t> TypeSystem::fieldSize(const FieldModel& field, const TypeLayoutContext& context) {
    return nativeLayout(field.type, context).size;
}

std::optional<size_t> TypeSystem::fieldAlignment(const FieldModel& field, size_t pointerSize) {
    return fieldAlignment(field, TypeLayoutContext{pointerSize});
}

std::optional<size_t> TypeSystem::fieldAlignment(const FieldModel& field, const TypeLayoutContext& context) {
    return nativeLayout(field.type, context).alignment;
}

FieldLayout TypeSystem::fieldLayout(const TypeModel& declaringType, const FieldModel& field, size_t pointerSize) {
    return fieldLayout(declaringType, field, TypeLayoutContext{pointerSize});
}

FieldLayout TypeSystem::fieldLayout(
    const TypeModel& declaringType,
    const FieldModel& field,
    const TypeLayoutContext& context) {
    const auto native = nativeLayout(field.type, context);
    return {field, native.size, native.alignment, fieldAccess(declaringType, field), native.diagnostic};
}

ObjectLayout TypeSystem::objectLayout(
    const TypeModel& type,
    size_t pointerSize,
    uint64_t declaredInstanceSize,
    uint64_t declaredStaticSize) {
    TypeLayoutInfo layout;
    layout.instanceSize = declaredInstanceSize;
    layout.staticSize = declaredStaticSize;
    return objectLayout(type, layout, TypeLayoutContext{pointerSize});
}

ObjectLayout TypeSystem::objectLayout(
    const TypeModel& type,
    const TypeLayoutInfo& layout,
    const TypeLayoutContext& context) {
    if (context.pointerSize != 4 && context.pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }

    struct Cursor {
        uint64_t actualSize = 0;
        uint32_t minimumAlignment = 1;
        uint32_t naturalAlignment = 0;
        bool blocked = false;
    };

    const bool isString = type.nameSpace == "System" && type.name == "String";
    const ManagedLayoutKind managedKind = layout.array
        ? ManagedLayoutKind::Array
        : (isString ? ManagedLayoutKind::String : ManagedLayoutKind::Object);
    const auto managedBaseSize = managedLayoutSize(managedKind, context);
    const bool hasParent = layout.parentInstanceSize != 0 || layout.parentActualInstanceSize != 0;
    const bool baseLayoutKnown = hasParent || managedBaseSize.has_value();
    const uint64_t headerSize = managedBaseSize.value_or(0);
    Cursor instance;
    instance.actualSize = layout.parentActualInstanceSize != 0
        ? layout.parentActualInstanceSize
        : (layout.parentInstanceSize != 0 ? layout.parentInstanceSize : headerSize);
    instance.minimumAlignment = layout.minimumAlignment != 0
        ? layout.minimumAlignment
        : (layout.valueType ? 1u : static_cast<uint32_t>(context.pointerSize));
    Cursor normalStatic;
    Cursor threadStatic;
    const bool conservativeType = !baseLayoutKnown || layout.generic || layout.array || type.name.find('`') != std::string::npos;

    ObjectLayout result;
    result.typeName = qualifiedName(type);
    result.valueType = layout.valueType;
    if (!baseLayoutKnown) {
        result.diagnostics.push_back({
            result.typeName,
            static_cast<uint16_t>(context.pointerSize * 8),
            "managed " + std::string(layout.array ? "array" : (isString ? "string" : "object")) +
                " layout is unknown for the selected source profile at " +
                std::to_string(context.pointerSize * 8) + "-bit pointer size"
        });
    }

    for (size_t fieldIndex = 0; fieldIndex < type.fields.size(); ++fieldIndex) {
        const FieldModel& field = type.fields[fieldIndex];
        std::optional<int64_t> offset;
        if (fieldIndex < layout.fieldOffsets.size()) {
            offset = layout.fieldOffsets[fieldIndex];
        } else if (context.metadata != nullptr && field.token != 0) {
            const auto found = context.metadata->fieldOffsetsByToken.find(field.token);
            if (found != context.metadata->fieldOffsetsByToken.end()) offset = found->second;
        }
        if (!offset) {
            if (field.offset == -1 || field.offset > 0 || (field.offset == 0 && field.isStatic && result.staticFields.empty())) {
                offset = field.offset;
            }
        }

        const bool isThreadStatic = field.isStatic && offset && *offset == -1;
        Cursor& cursor = field.isStatic ? (isThreadStatic ? threadStatic : normalStatic) : instance;
        auto& outputFields = field.isStatic
            ? (isThreadStatic ? result.threadStaticFields : result.staticFields)
            : result.instanceFields;

        FieldLayout fieldResult = fieldLayout(type, field, context);
        const NativeLayout native = nativeLayout(field.type, context);
        std::optional<size_t> alignment = native.alignment;
        if (alignment) {
            if (*alignment < 4 && native.naturalAlignment) alignment = *native.naturalAlignment;
            if (!field.isStatic && layout.packingSize != 0) {
                alignment = std::min(*native.alignment, static_cast<size_t>(layout.packingSize));
            }
            if (*alignment == 0) alignment.reset();
        }
        fieldResult.alignment = alignment;
        if (alignment) cursor.minimumAlignment = std::max(cursor.minimumAlignment, static_cast<uint32_t>(*alignment));
        if (native.alignment) cursor.naturalAlignment = std::max(cursor.naturalAlignment, static_cast<uint32_t>(*native.alignment));

        if (!field.isStatic) fieldResult.field.offset = -1;
        if (isThreadStatic) fieldResult.field.offset = -1;
        if (offset && *offset >= 0 && !isThreadStatic) {
            fieldResult.field.offset = *offset;
            const uint64_t fieldOffset = static_cast<uint64_t>(*offset);
            if (native.size) {
                if (const auto end = fieldEnd(fieldOffset, *native.size)) {
                    cursor.actualSize = std::max(cursor.actualSize, *end);
                    cursor.blocked = false;
                } else {
                    cursor.blocked = true;
                }
            } else {
                cursor.actualSize = std::max(cursor.actualSize, fieldOffset);
                cursor.blocked = true;
            }
        } else {
            if (!isThreadStatic) fieldResult.field.offset = -1;
            if (!cursor.blocked && !conservativeType && native.size && alignment) {
                if (const auto aligned = alignUp(cursor.actualSize, *alignment)) {
                    if (const auto end = fieldEnd(*aligned, *native.size)) {
                        if (!isThreadStatic && *aligned <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
                            fieldResult.field.offset = static_cast<int64_t>(*aligned);
                        }
                        cursor.actualSize = *end;
                    } else {
                        cursor.blocked = true;
                    }
                } else {
                    cursor.blocked = true;
                }
            }
        }
        if (fieldResult.diagnostic) result.diagnostics.push_back(*fieldResult.diagnostic);
        outputFields.push_back(std::move(fieldResult));
    }

    const auto computedInstanceSize = alignUp(instance.actualSize, instance.minimumAlignment);
    const bool fixedManagedSize = managedKind != ManagedLayoutKind::Object && managedBaseSize.has_value();
    result.instanceSize = layout.instanceSize != 0
        ? layout.instanceSize
        : (fixedManagedSize
            ? *managedBaseSize
            : (baseLayoutKnown && computedInstanceSize ? *computedInstanceSize : (baseLayoutKnown ? instance.actualSize : 0)));
    result.actualInstanceSize = layout.actualInstanceSize;
    if (result.actualInstanceSize == 0) {
        if (fixedManagedSize) {
            result.actualInstanceSize = std::max<uint64_t>(*managedBaseSize, instance.actualSize);
        } else {
            result.actualInstanceSize = result.instanceFields.empty() && layout.instanceSize != 0 && !hasParent
                ? layout.instanceSize
                : instance.actualSize;
        }
    }
    if (layout.valueType && result.instanceFields.empty() && managedBaseSize) {
        if (layout.instanceSize == 0) result.instanceSize = headerSize + 1;
        if (layout.actualInstanceSize == 0) result.actualInstanceSize = headerSize + 1;
    }
    result.valueSize = layout.valueType && managedBaseSize && result.instanceSize >= headerSize
        ? result.instanceSize - headerSize
        : 0;

    const auto computedStaticSize = alignUp(normalStatic.actualSize, normalStatic.minimumAlignment);
    result.staticSize = layout.staticSize != 0
        ? layout.staticSize
        : (computedStaticSize ? *computedStaticSize : normalStatic.actualSize);
    const auto computedThreadStaticSize = alignUp(threadStatic.actualSize, threadStatic.minimumAlignment);
    result.threadStaticSize = layout.threadStaticSize != 0
        ? layout.threadStaticSize
        : (computedThreadStaticSize ? *computedThreadStaticSize : threadStatic.actualSize);
    result.minimumAlignment = instance.minimumAlignment;
    result.naturalAlignment = layout.naturalAlignment != 0 ? layout.naturalAlignment : instance.naturalAlignment;
    return result;
}

ObjectLayout TypeSystem::objectLayout(
    const TypeModel& type,
    const MetadataModel& metadata,
    size_t pointerSize,
    const TypeLayoutInfo& layout,
    const std::vector<TypeLayoutInfo>* typeLayouts) {
    return objectLayout(type, layout, TypeLayoutContext{pointerSize, &metadata, typeLayouts});
}

std::string TypeSystem::fieldAccess(
    const TypeModel& declaringType,
    const FieldModel& field,
    std::string_view instance) {
    const std::string name = identifier(field.name, "Field");
    if (field.isStatic) return qualifiedName(declaringType) + "." + name;
    return (instance.empty() ? std::string("this") : std::string(instance)) + "." + name;
}

std::string TypeSystem::describe(const ObjectLayout& layout) {
    std::ostringstream output;
    output << (layout.typeName.empty() ? "UnknownType" : layout.typeName) << ":\n";
    output << "  instance size: " << hex(layout.instanceSize) << "\n";
    output << "  actual instance size: " << hex(layout.actualInstanceSize) << "\n";
    if (layout.valueType) output << "  value size: " << hex(layout.valueSize) << "\n";
    output << "  static size: " << hex(layout.staticSize) << "\n";
    output << "  thread-static size: " << hex(layout.threadStaticSize) << "\n";
    output << "  minimum alignment: " << hex(layout.minimumAlignment) << "\n";
    output << "  natural alignment: " << hex(layout.naturalAlignment) << "\n";

    const auto emitFields = [&output](std::string_view heading, const std::vector<FieldLayout>& fields) {
        output << "  " << heading << ":\n";
        for (const auto& field : fields) {
            output << "    " << (field.field.offset < 0 ? std::string("?") : hex(static_cast<uint64_t>(field.field.offset)))
                   << ": " << (field.field.type.empty() ? "object" : field.field.type) << " "
                   << identifier(field.field.name, "Field")
                   << "; // size " << (field.size ? hex(*field.size) : "?")
                   << ", alignment " << (field.alignment ? hex(*field.alignment) : "?")
                   << ", access " << field.accessExpression << "\n";
        }
    };
    emitFields("instance fields", layout.instanceFields);
    emitFields("static fields", layout.staticFields);
    emitFields("thread-static fields", layout.threadStaticFields);
    for (const auto& diagnostic : layout.diagnostics) {
        output << "  diagnostic: " << diagnostic.typeName << ": " << diagnostic.message << "\n";
    }
    return output.str();
}

} // namespace il2cpprec
