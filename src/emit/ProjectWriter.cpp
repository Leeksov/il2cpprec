#include <il2cpprec/emit/ProjectWriter.hpp>
#include <il2cpprec/abi/AbiAdapter.hpp>
#include <il2cpprec/analysis/ManagedEmitter.hpp>
#include <il2cpprec/emit/RuntimeSupport.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>
#include <il2cpprec/metadata/GenericMethodResolver.hpp>
#include <il2cpprec/metadata/UniversalGenericResolver.hpp>

#include <algorithm>
#include <bit>
#include <charconv>
#include <cctype>
#include <cmath>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
namespace {

using Location = std::pair<size_t, size_t>;

std::string hexAddress(uint64_t value) {
    std::ostringstream output;
    output << std::hex << std::uppercase << value;
    return output.str();
}

std::string stableHash(const std::string& value) {
    uint64_t hash = 14695981039346656037ULL;
    for (const unsigned char c : value) {
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    std::ostringstream output;
    output << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << hash;
    return output.str();
}

std::string lowerAscii(std::string value) {
    for (char& c : value) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return value;
}

bool isReservedFileName(const std::string& value) {
    const auto upper = [&value] {
        std::string result = value;
        for (char& c : result) {
            if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        }
        return result;
    }();
    if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL") return true;
    if (upper.size() == 4 && upper.back() >= '1' && upper.back() <= '9') {
        return upper.substr(0, 3) == "COM" || upper.substr(0, 3) == "LPT";
    }
    return false;
}

bool isCSharpKeyword(const std::string& value) {
    static const std::set<std::string> keywords = {
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
    return keywords.contains(value);
}

std::string safeName(const std::string& value, const std::string& fallback) {
    std::string result;
    result.reserve(value.size());
    for (const unsigned char c : value) {
        const bool alphaNumeric = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        result.push_back(alphaNumeric || c == '_' ? static_cast<char>(c) : '_');
    }
    if (result.empty()) result = fallback;
    if (result.front() >= '0' && result.front() <= '9') result.insert(result.begin(), '_');
    if (isReservedFileName(result) || isCSharpKeyword(result)) result.insert(result.begin(), '_');
    constexpr size_t maximumLength = 80;
    if (result.size() > maximumLength) {
        result.resize(maximumLength - 17);
        result += '_' + stableHash(value);
    }
    return result;
}

std::vector<std::string> namespaceParts(const std::string& nameSpace) {
    std::vector<std::string> result;
    size_t start = 0;
    while (start <= nameSpace.size()) {
        const auto end = nameSpace.find('.', start);
        const auto part = nameSpace.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!part.empty()) result.push_back(safeName(part, "Namespace"));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}

std::string join(const std::vector<std::string>& values, const std::string& separator) {
    std::string result;
    for (const auto& value : values) {
        if (!result.empty()) result += separator;
        result += value;
    }
    return result;
}

std::string xmlEscape(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (const char c : value) {
        switch (c) {
        case '&': result += "&amp;"; break;
        case '<': result += "&lt;"; break;
        case '>': result += "&gt;"; break;
        case '\"': result += "&quot;"; break;
        case '\'': result += "&apos;"; break;
        default: result.push_back(c); break;
        }
    }
    return result;
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Cannot create output file: " + path.string());
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.close();
    if (!output) throw std::runtime_error("Cannot write output file: " + path.string());
}

std::vector<std::string> qualifiedNames(const TypeModel& type, const MethodModel& method) {
    std::vector<std::string> result;
    const auto typeName = type.nameSpace.empty() ? type.name : type.nameSpace + '.' + type.name;
    result.push_back(typeName + "." + method.name);
    result.push_back(typeName + "::" + method.name);
    result.push_back(typeName + "__" + method.name);
    result.push_back(type.name + "." + method.name);
    result.push_back(type.name + "::" + method.name);
    return result;
}

class MetadataIndex {
public:
    explicit MetadataIndex(const MetadataModel& metadata) : metadata_(metadata) {
        for (size_t typeIndex = 0; typeIndex < metadata.types.size(); ++typeIndex) {
            const auto& type = metadata.types[typeIndex];
            for (size_t methodIndex = 0; methodIndex < type.methods.size(); ++methodIndex) {
                const Location location{typeIndex, methodIndex};
                const auto& method = type.methods[methodIndex];
                if (method.address != 0) byAddress_.emplace(method.address, location);
                if (!method.name.empty()) byName_.emplace(method.name, location);
                for (const auto& name : qualifiedNames(type, method)) {
                    byQualifiedName_.emplace(name, location);
                }
            }
        }
    }

    std::optional<Location> find(const RecoveredFunction& function) const {
        if (function.address != 0) {
            const auto [begin, end] = byAddress_.equal_range(function.address);
            std::vector<Location> candidates;
            for (auto it = begin; it != end; ++it) candidates.push_back(it->second);
            if (!function.name.empty()) {
                std::vector<Location> named;
                for (const auto& location : candidates) {
                    const auto& type = metadata_.types[location.first];
                    const auto& method = type.methods[location.second];
                    if (method.name == function.name) {
                        named.push_back(location);
                        continue;
                    }
                    const auto names = qualifiedNames(type, method);
                    if (std::find(names.begin(), names.end(), function.name) != names.end()) named.push_back(location);
                }
                if (!named.empty()) candidates = std::move(named);
            }
            if (const auto result = selectInOneType(candidates)) return result;
        }

        if (function.name.empty()) return std::nullopt;
        std::vector<Location> candidates;
        const auto [qualifiedBegin, qualifiedEnd] = byQualifiedName_.equal_range(function.name);
        for (auto it = qualifiedBegin; it != qualifiedEnd; ++it) candidates.push_back(it->second);
        if (candidates.empty()) {
            const auto [begin, end] = byName_.equal_range(function.name);
            for (auto it = begin; it != end; ++it) candidates.push_back(it->second);
        }
        candidates.erase(std::remove_if(candidates.begin(), candidates.end(), [this, &function](const Location& location) {
            const auto address = metadata_.types[location.first].methods[location.second].address;
            return function.address != 0 && address != 0 && address != function.address;
        }), candidates.end());
        return selectInOneType(candidates);
    }

private:
    const MetadataModel& metadata_;
    std::multimap<uint64_t, Location> byAddress_;
    std::multimap<std::string, Location> byName_;
    std::multimap<std::string, Location> byQualifiedName_;

    std::optional<Location> selectInOneType(std::vector<Location> candidates) const {
        if (candidates.empty()) return std::nullopt;
        const auto keyFor = [](const Location& location) { return location.first; };
        const auto firstKey = keyFor(candidates.front());
        if (!std::all_of(candidates.begin(), candidates.end(), [&](const Location& location) {
            return keyFor(location) == firstKey;
        })) {
            return std::nullopt;
        }
        return *std::min_element(candidates.begin(), candidates.end(), [this](const Location& left, const Location& right) {
            const auto& leftType = metadata_.types[left.first];
            const auto& rightType = metadata_.types[right.first];
            const auto& leftMethod = leftType.methods[left.second];
            const auto& rightMethod = rightType.methods[right.second];
            return std::tie(leftType.nameSpace, leftType.name, leftMethod.name, leftMethod.token, leftMethod.definitionIndex, leftMethod.address, left.first, left.second) <
                   std::tie(rightType.nameSpace, rightType.name, rightMethod.name, rightMethod.token, rightMethod.definitionIndex, rightMethod.address, right.first, right.second);
        });
    }
};

struct MethodEntry {
    const RecoveredFunction* function = nullptr;
    const MethodModel* method = nullptr;
    std::string metadataName;
    std::string baseName;
    uint32_t token = 0;
    int definitionIndex = -1;
};

std::string methodImageName(const MethodEntry& entry, const TypeModel* owner) {
    if (entry.method && !entry.method->imageName.empty()) return entry.method->imageName;
    return owner ? owner->imageName : std::string{};
}

struct TypeGroup {
    std::vector<const TypeModel*> metadataTypes;
    std::vector<MethodEntry> methods;
};

template<typename T>
std::optional<uint32_t> nativeFlags(const T& value) {
    if constexpr (requires { value.flags; }) {
        return static_cast<uint32_t>(value.flags);
    } else {
        return std::nullopt;
    }
}

template<typename T>
std::optional<uint32_t> nativeBitfield(const T& value) {
    if constexpr (requires { value.bitfield; }) {
        return static_cast<uint32_t>(value.bitfield);
    } else {
        return std::nullopt;
    }
}

std::string memberVisibility(uint32_t flags) {
    switch (flags & 0x7) {
    case 0:
    case 1: return "private";
    case 2: return "private protected";
    case 3: return "internal";
    case 4: return "protected";
    case 5: return "protected internal";
    case 6: return "public";
    default: return "private";
    }
}

std::string typeVisibility(uint32_t flags, bool nested) {
    if (!nested) return (flags & 0x7) == 1 ? "public" : "internal";
    switch (flags & 0x7) {
    case 2: return "public";
    case 3: return "private";
    case 4: return "protected";
    case 5: return "internal";
    case 6: return "private protected";
    case 7: return "protected internal";
    default: return "private";
    }
}

enum class ManagedTypeKind {
    Class,
    Struct,
    Interface,
    Enum
};

struct TypeDeclarationInfo {
    std::string visibility = "public";
    std::string modifiers;
    ManagedTypeKind kind = ManagedTypeKind::Class;
    bool sealedType = false;
    bool partialMetadata = false;
};

TypeDeclarationInfo typeDeclaration(const TypeModel* type, bool staticType, bool nested) {
    TypeDeclarationInfo result;
    if (!type) {
        result.modifiers = "static ";
        return result;
    }
    const auto flags = nativeFlags(*type);
    if (!flags) {
        result.modifiers = staticType ? "static " : "";
        result.partialMetadata = true;
        return result;
    }
    result.visibility = typeVisibility(*flags, nested);
    const bool interface = (*flags & 0x20) != 0;
    if (interface) {
        result.kind = ManagedTypeKind::Interface;
        return result;
    }
    const bool abstractType = (*flags & 0x80) != 0;
    const bool sealedType = (*flags & 0x100) != 0;
    if (abstractType && sealedType) {
        result.modifiers = "static ";
        result.sealedType = true;
    } else {
        if (abstractType) result.modifiers += "abstract ";
        if (sealedType) {
            result.modifiers += "sealed ";
            result.sealedType = true;
        }
    }
    const auto bitfield = nativeBitfield(*type);
    if (!bitfield) {
        result.partialMetadata = true;
        return result;
    }
    if ((*bitfield & 0x2) != 0) {
        result.kind = ManagedTypeKind::Enum;
        result.modifiers.clear();
    } else if ((*bitfield & 0x1) != 0) {
        result.kind = ManagedTypeKind::Struct;
        result.modifiers.clear();
        result.sealedType = true;
    } else if (staticType && !(abstractType && sealedType)) {
        if (!result.modifiers.empty()) result.partialMetadata = true;
        result.modifiers = "static ";
        result.sealedType = true;
    }
    return result;
}

const TypeModel* emittedNestedParent(const MetadataModel& metadata, const TypeModel& child) {
    if (child.declaringTypeIndex < 0 ||
        static_cast<size_t>(child.declaringTypeIndex) >= metadata.types.size()) return nullptr;
    const auto& parent = metadata.types[static_cast<size_t>(child.declaringTypeIndex)];
    const bool simpleParent = parent.declaringTypeIndex < 0 && parent.genericContainerIndex < 0 &&
        parent.nameSpace == child.nameSpace && parent.name.find('`') == std::string::npos;
    if (!simpleParent || (parent.flags & 0x20) != 0 || (parent.bitfield & 0x2) != 0) return nullptr;
    const auto duplicates = std::count_if(metadata.types.begin(), metadata.types.end(),
        [&](const TypeModel& candidate) {
            return candidate.declaringTypeIndex < 0 && candidate.nameSpace == parent.nameSpace &&
                   candidate.name == parent.name;
        });
    return duplicates == 1 ? &parent : nullptr;
}

class TypeAccessibilityIndex {
public:
    explicit TypeAccessibilityIndex(const MetadataModel& metadata, bool frameworkCoreTypes)
        : frameworkCoreTypes_(frameworkCoreTypes) {
        for (const auto& type : metadata.types) {
            auto name = type.name;
            if (const auto arity = name.find('`'); arity != std::string::npos) name.resize(arity);
            if (name.empty()) continue;
            const auto qualify = [&](const std::string& value) {
                return type.nameSpace.empty() ? value : type.nameSpace + '.' + value;
            };
            const auto recordNames = [&](std::set<std::string>& names) {
                names.insert(name);
                names.insert(qualify(name));
                names.insert(safeName(name, "Type"));
                names.insert(qualify(safeName(name, "Type")));
            };
            const bool generic = type.genericContainerIndex >= 0 &&
                static_cast<size_t>(type.genericContainerIndex) < metadata.genericContainers.size() &&
                metadata.genericContainers[static_cast<size_t>(type.genericContainerIndex)].typeArgumentCount > 0;
            if (generic) {
                recordNames(genericNamesByImage_[type.imageName]);
                recordNames(globalGenericNames_);
            }
            if (frameworkCoreTypes && type.imageName == "mscorlib.dll") continue;
            const bool publiclyVisible = typeDeclaration(&type, false,
                emittedNestedParent(metadata, type) != nullptr).visibility == "public";
            const auto record = [&](VisibilityMap& map) {
                insert(map, qualify(name), publiclyVisible);
                insert(map, qualify(safeName(name, "Type")), publiclyVisible);
                insert(map, name, publiclyVisible);
                insert(map, safeName(name, "Type"), publiclyVisible);
            };
            record(publiclyVisible_);
            if (!type.imageName.empty()) record(byImage_[type.imageName]);
        }
    }

    bool hasInternalType(std::string_view signature, std::string_view imageName = {}) const {
        for (size_t begin = 0; begin < signature.size();) {
            while (begin < signature.size() && !identifierCharacter(signature[begin])) ++begin;
            if (begin == signature.size()) break;
            size_t end = begin;
            while (end < signature.size() && identifierCharacter(signature[end])) ++end;
            auto token = std::string(signature.substr(begin, end - begin));
            if (token.starts_with("global::")) token.erase(0, 8);
            const auto* found = visibility(token, imageName);
            if (found && *found && !**found) return true;
            begin = end;
        }
        return false;
    }

    bool hasAmbiguousType(std::string_view signature, std::string_view imageName) const {
        for (size_t begin = 0; begin < signature.size();) {
            while (begin < signature.size() && !identifierCharacter(signature[begin])) ++begin;
            if (begin == signature.size()) break;
            size_t end = begin;
            while (end < signature.size() && identifierCharacter(signature[end])) ++end;
            auto token = std::string(signature.substr(begin, end - begin));
            if (token.starts_with("global::")) token.erase(0, 8);
            const auto* found = visibility(token, imageName);
            if (found && !*found) return true;
            begin = end;
        }
        return false;
    }

    bool hasInternalTypeReference(std::string_view rawType, const MetadataModel& metadata) const {
        if (!rawType.starts_with("type[") || rawType.back() != ']') return false;
        const auto digits = rawType.substr(5, rawType.size() - 6);
        size_t index = 0;
        const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), index);
        if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) return false;
        return internalReference(index, metadata, 0);
    }

    bool hasUnboundGenericName(std::string_view type, std::string_view imageName) const {
        if (type.starts_with("type[") || type.find('<') != std::string_view::npos) return false;
        std::string base(type);
        for (const auto prefix : {"ref ", "out ", "in ", "global::"}) {
            if (base.starts_with(prefix)) base.erase(0, std::char_traits<char>::length(prefix));
        }
        while (base.ends_with(']')) {
            const auto open = base.find_last_of('[');
            if (open == std::string::npos || !std::all_of(base.begin() + static_cast<std::ptrdiff_t>(open + 1),
                                                         base.end() - 1, [](char c) { return c == ','; })) break;
            base.resize(open);
        }
        while (!base.empty() && (base.back() == '*' || base.back() == '?' || base.back() == '&')) base.pop_back();
        if (!imageName.empty()) {
            const auto image = genericNamesByImage_.find(std::string(imageName));
            if (image != genericNamesByImage_.end() && image->second.contains(base)) return true;
        }
        // A bare name shared by generic and nongeneric definitions has no
        // trustworthy identity here. Emitting it can bind the wrong arity.
        return globalGenericNames_.contains(base);
    }

private:
    using VisibilityMap = std::unordered_map<std::string, std::optional<bool>>;
    const std::optional<bool>* visibility(std::string_view token, std::string_view imageName) const {
        if (!imageName.empty()) {
            const auto image = byImage_.find(std::string(imageName));
            if (image != byImage_.end()) {
                const auto found = image->second.find(std::string(token));
                if (found != image->second.end()) return &found->second;
            }
        }
        const auto found = publiclyVisible_.find(std::string(token));
        return found == publiclyVisible_.end() ? nullptr : &found->second;
    }

    bool internalReference(size_t index, const MetadataModel& metadata, size_t depth) const {
        if (depth > 32 || index >= metadata.typeReferences.size()) return false;
        const auto& reference = metadata.typeReferences[index];
        if (reference.definitionIndex >= 0 &&
            static_cast<size_t>(reference.definitionIndex) < metadata.types.size()) {
            const auto& type = metadata.types[static_cast<size_t>(reference.definitionIndex)];
            if (!(frameworkCoreTypes_ && type.imageName == "mscorlib.dll") &&
                typeDeclaration(&type, false, emittedNestedParent(metadata, type) != nullptr).visibility != "public") {
                return true;
            }
        }
        if (reference.elementTypeIndex >= 0 &&
            internalReference(static_cast<size_t>(reference.elementTypeIndex), metadata, depth + 1)) return true;
        for (const auto argument : reference.genericArgumentIndices) {
            if (argument >= 0 && internalReference(static_cast<size_t>(argument), metadata, depth + 1)) return true;
        }
        return false;
    }

    static bool identifierCharacter(char value) {
        const auto c = static_cast<unsigned char>(value);
        return std::isalnum(c) != 0 || value == '_' || value == '.' || value == '+' || value == ':';
    }

    void insert(VisibilityMap& map, const std::string& name, bool publiclyVisible) {
        const auto [it, inserted] = map.emplace(name, publiclyVisible);
        if (!inserted && it->second != publiclyVisible) it->second = std::nullopt;
    }

    VisibilityMap publiclyVisible_;
    std::unordered_map<std::string, VisibilityMap> byImage_;
    std::unordered_map<std::string, std::set<std::string>> genericNamesByImage_;
    std::set<std::string> globalGenericNames_;
    bool frameworkCoreTypes_ = false;
};

std::string compilerVisibility(std::string visibility, bool internalTypeExposed) {
    if (!internalTypeExposed) return visibility;
    if (visibility == "public" || visibility == "protected" || visibility == "protected internal") {
        return "internal";
    }
    return visibility;
}

std::string staticClassVisibility(std::string visibility, const TypeDeclarationInfo& declaringType) {
    if (declaringType.modifiers == "static " && visibility.find("protected") != std::string::npos) {
        return "private";
    }
    return visibility;
}

std::string typeKindName(ManagedTypeKind kind) {
    switch (kind) {
    case ManagedTypeKind::Class: return "class";
    case ManagedTypeKind::Struct: return "struct";
    case ManagedTypeKind::Interface: return "interface";
    case ManagedTypeKind::Enum: return "enum";
    }
    return "class";
}

enum class MethodBodyStatus {
    Supported,
    Partial,
    Unsupported
};

struct MethodBodyEmission {
    MethodBodyStatus status = MethodBodyStatus::Unsupported;
    std::string source;
    std::string support;
    std::string diagnostic;
    std::vector<CSharpBodyEmissionResult::SupportFragment> supportFragments;
};

MethodBodyEmission unsupportedBody(std::string diagnostic) {
    return {MethodBodyStatus::Unsupported, {}, {}, std::move(diagnostic), {}};
}

std::string managedIdentifier(const std::string& value, const std::string& fallback) {
    std::string result;
    result.reserve(value.size() + 1);
    for (const unsigned char c : value) {
        const bool alphaNumeric = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        result.push_back(alphaNumeric || c == '_' || c >= 0x80 ? static_cast<char>(c) : '_');
    }
    if (result.empty()) result = fallback;
    if (result.front() >= '0' && result.front() <= '9') result.insert(result.begin(), '_');
    if (isCSharpKeyword(result)) result.insert(result.begin(), '@');
    return result;
}

bool hasUnresolvedGenericArity(std::string_view type) {
    return type.find('`') != std::string_view::npos;
}

class CSharpTypeSyntax {
public:
    explicit CSharpTypeSyntax(std::string_view text) : text_(text) {}

    bool valid() {
        return parseType() && (skipSpace(), position_ == text_.size());
    }

private:
    void skipSpace() {
        while (position_ < text_.size() && (text_[position_] == ' ' || text_[position_] == '\t')) ++position_;
    }

    bool consume(std::string_view token) {
        if (text_.substr(position_).starts_with(token)) {
            position_ += token.size();
            return true;
        }
        return false;
    }

    bool identifier() {
        if (position_ < text_.size() && text_[position_] == '@') ++position_;
        if (position_ >= text_.size()) return false;
        const auto first = text_[position_];
        if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_')) return false;
        ++position_;
        while (position_ < text_.size()) {
            const auto c = text_[position_];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_')) break;
            ++position_;
        }
        return true;
    }

    bool segment() {
        if (!identifier()) return false;
        if (!consume("<")) return true;
        if (!parseType()) return false;
        while (consume(",")) {
            skipSpace();
            if (!parseType()) return false;
        }
        return consume(">");
    }

    bool parseType() {
        if (++depth_ > 32) return false;
        skipSpace();
        if (depth_ == 1) {
            for (const auto prefix : {"ref ", "out ", "in "}) {
                if (consume(prefix)) break;
            }
        }
        consume("global::");
        if (!segment()) return false;
        while (consume(".")) {
            if (!segment()) return false;
        }
        while (position_ < text_.size()) {
            if (consume("*") || consume("?")) continue;
            if (!consume("[")) break;
            while (consume(",")) {}
            if (!consume("]")) return false;
        }
        skipSpace();
        --depth_;
        return true;
    }

    std::string_view text_;
    size_t position_ = 0;
    size_t depth_ = 0;
};

bool supportedCSharpType(std::string_view type) {
    return CSharpTypeSyntax(type).valid();
}

bool hasUnresolvedGenericArity(std::string_view type, const MetadataModel& metadata, size_t depth = 0) {
    if (hasUnresolvedGenericArity(type)) return true;
    if (depth > 32 || !type.starts_with("type[") || type.back() != ']') return false;
    size_t index = 0;
    const auto digits = type.substr(5, type.size() - 6);
    const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), index);
    if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size() ||
        index >= metadata.typeReferences.size()) return false;
    const auto& reference = metadata.typeReferences[index];
    size_t requiredArity = 0;
    if (reference.definitionIndex >= 0 &&
        static_cast<size_t>(reference.definitionIndex) < metadata.types.size()) {
        const auto& definition = metadata.types[static_cast<size_t>(reference.definitionIndex)];
        if (definition.genericContainerIndex >= 0 &&
            static_cast<size_t>(definition.genericContainerIndex) < metadata.genericContainers.size()) {
            const auto count = metadata.genericContainers[static_cast<size_t>(definition.genericContainerIndex)].typeArgumentCount;
            if (count > 0) requiredArity = static_cast<size_t>(count);
        }
    }
    const auto tick = reference.name.rfind('`');
    if (tick != std::string::npos) {
        size_t arity = 0;
        const auto arityText = std::string_view(reference.name).substr(tick + 1);
        const auto arityParsed = std::from_chars(arityText.data(), arityText.data() + arityText.size(), arity);
        if (arityParsed.ec != std::errc{} || arityParsed.ptr != arityText.data() + arityText.size()) return true;
        requiredArity = std::max(requiredArity, arity);
    }
    if (requiredArity != 0 &&
        (static_cast<Il2CppTypeCode>(reference.code) != Il2CppTypeCode::GenericInst ||
         reference.genericArgumentIndices.size() < requiredArity)) {
        return true;
    }
    if (reference.elementTypeIndex >= 0 &&
        hasUnresolvedGenericArity("type[" + std::to_string(reference.elementTypeIndex) + "]", metadata, depth + 1)) {
        return true;
    }
    for (const int32_t argument : reference.genericArgumentIndices) {
        if (argument >= 0 && hasUnresolvedGenericArity(
            "type[" + std::to_string(argument) + "]", metadata, depth + 1)) return true;
    }
    return false;
}

struct GenericDeclarationInfo {
    std::string parameters;
    std::string constraints;
    bool partialMetadata = false;
    bool omittedConstraint = false;
};

bool isClassConstraint(const MetadataModel& metadata, int64_t constraintIndex) {
    if (constraintIndex < 0 || static_cast<size_t>(constraintIndex) >= metadata.typeReferences.size()) return true;
    const auto& reference = metadata.typeReferences[static_cast<size_t>(constraintIndex)];
    const auto code = static_cast<Il2CppTypeCode>(reference.code);
    if (code == Il2CppTypeCode::Var || code == Il2CppTypeCode::MVar) return false;
    if (reference.definitionIndex >= 0 && static_cast<size_t>(reference.definitionIndex) < metadata.types.size()) {
        return (metadata.types[static_cast<size_t>(reference.definitionIndex)].flags & 0x20) == 0;
    }
    return true;
}

GenericDeclarationInfo genericDeclaration(
    const MetadataModel& metadata,
    int32_t containerIndex,
    bool method,
    bool varianceAllowed,
    const std::function<std::optional<std::string>(int32_t, std::string)>& validateConstraint = {}) {
    GenericDeclarationInfo result;
    if (containerIndex < 0) return result;
    if (static_cast<size_t>(containerIndex) >= metadata.genericContainers.size()) {
        result.partialMetadata = true;
        return result;
    }
    const auto& container = metadata.genericContainers[static_cast<size_t>(containerIndex)];
    if (container.typeArgumentCount < 0 || container.genericParameterStart < 0) {
        result.partialMetadata = true;
        return result;
    }
    const size_t begin = static_cast<size_t>(container.genericParameterStart);
    const size_t count = static_cast<size_t>(container.typeArgumentCount);
    if (begin > metadata.genericParameters.size() || count > metadata.genericParameters.size() - begin) {
        result.partialMetadata = true;
        return result;
    }

    std::vector<std::pair<uint16_t, size_t>> order;
    for (size_t index = 0; index < count; ++index) {
        order.emplace_back(metadata.genericParameters[begin + index].num, begin + index);
    }
    std::sort(order.begin(), order.end());
    result.parameters = "<";
    for (size_t position = 0; position < order.size(); ++position) {
        const auto& parameter = metadata.genericParameters[order[position].second];
        const auto name = managedIdentifier(parameter.name, "T" + std::to_string(position));
        if (position != 0) result.parameters += ", ";
        if (!method && varianceAllowed && (parameter.flags & 0x2) != 0) result.parameters += "in ";
        if (!method && varianceAllowed && (parameter.flags & 0x1) != 0) result.parameters += "out ";
        if (((method || !varianceAllowed) && (parameter.flags & 0x3) != 0) || (parameter.flags & 0x3) == 0x3) {
            result.partialMetadata = true;
        }
        result.parameters += name;

        const bool referenceConstraint = (parameter.flags & 0x4) != 0;
        const bool valueConstraint = (parameter.flags & 0x8) != 0;
        if (referenceConstraint && valueConstraint) {
            result.partialMetadata = true;
            continue;
        }
        std::vector<std::string> constraints;
        if (parameter.constraintsCount < 0) {
            result.partialMetadata = true;
            continue;
        }
        const int64_t constraintBegin = parameter.constraintsStart;
        const int64_t constraintEnd = constraintBegin + parameter.constraintsCount;
        if (constraintBegin < 0 || constraintEnd < constraintBegin ||
            static_cast<uint64_t>(constraintEnd) > metadata.genericParameterConstraints.size()) {
            if (parameter.constraintsCount != 0) {
                result.partialMetadata = true;
                continue;
            }
        }
        std::string baseConstraint;
        std::vector<std::string> interfaceConstraints;
        for (int64_t constraint = constraintBegin; constraint < constraintEnd; ++constraint) {
            const int32_t referenceIndex = metadata.genericParameterConstraints[static_cast<size_t>(constraint)];
            if (referenceIndex < 0 || static_cast<size_t>(referenceIndex) >= metadata.typeReferences.size()) {
                result.partialMetadata = true;
                continue;
            }
            if (hasUnresolvedGenericArity("type[" + std::to_string(referenceIndex) + "]", metadata)) {
                result.partialMetadata = true;
                continue;
            }
            auto resolved = TypeSystem::resolve(static_cast<size_t>(referenceIndex), metadata);
            if (hasUnresolvedGenericArity(resolved) || !supportedCSharpType(resolved)) {
                result.partialMetadata = true;
                continue;
            }
            if (resolved == "object" || resolved == "System.Object" || resolved == "System.ValueType") {
                result.partialMetadata = true;
                continue;
            }
            if (validateConstraint) {
                const auto validated = validateConstraint(referenceIndex, std::move(resolved));
                if (!validated) {
                    result.partialMetadata = true;
                    result.omittedConstraint = true;
                    continue;
                }
                resolved = *validated;
            }
            if (isClassConstraint(metadata, referenceIndex)) {
                if (!baseConstraint.empty() && baseConstraint != resolved) {
                    result.partialMetadata = true;
                    continue;
                }
                baseConstraint = std::move(resolved);
            } else if (std::find(interfaceConstraints.begin(), interfaceConstraints.end(), resolved) == interfaceConstraints.end()) {
                interfaceConstraints.push_back(std::move(resolved));
            }
        }
        if (valueConstraint) constraints.push_back("struct");
        else if (!baseConstraint.empty()) constraints.push_back(std::move(baseConstraint));
        else if (referenceConstraint) constraints.push_back("class");
        constraints.insert(constraints.end(), interfaceConstraints.begin(), interfaceConstraints.end());
        if ((parameter.flags & 0x10) != 0 && !valueConstraint) constraints.push_back("new()");
        if (!constraints.empty()) {
            result.constraints += " where " + name + " : ";
            for (size_t index = 0; index < constraints.size(); ++index) {
                if (index != 0) result.constraints += ", ";
                result.constraints += constraints[index];
            }
        }
    }
    result.parameters += ">";
    return result;
}

std::string genericTypeBaseName(const std::string& metadataName, const GenericDeclarationInfo& generic) {
    if (!generic.parameters.empty()) {
        const auto backtick = metadataName.rfind('`');
        if (backtick != std::string::npos && backtick + 1 < metadataName.size() &&
            std::all_of(metadataName.begin() + static_cast<std::ptrdiff_t>(backtick + 1), metadataName.end(), [](unsigned char c) {
                return c >= '0' && c <= '9';
            })) {
            return metadataName.substr(0, backtick);
        }
    }
    return metadataName;
}

std::set<std::string> nativeParameterRegisters(Architecture architecture) {
    switch (architecture) {
    case Architecture::Arm64: return {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    case Architecture::Arm32: return {"r0", "r1", "r2", "r3"};
    case Architecture::X64: return {"rcx", "rdx", "r8", "r9"};
    case Architecture::X86: return {"ecx", "edx"};
    }
    return {};
}

void collectInputRegisters(
    const ExpressionPtr& expression,
    const std::set<std::string>& defined,
    std::set<std::string>& inputs) {
    if (!expression) return;
    if (expression->kind == Expression::Kind::Register && !defined.contains(expression->name)) {
        inputs.insert(expression->name);
    }
    for (const auto& argument : expression->arguments) collectInputRegisters(argument, defined, inputs);
}

std::set<std::string> requiredInputRegisters(const RecoveredFunction& function) {
    std::set<std::string> inputs;
    for (const auto& block : function.blocks) {
        std::set<std::string> defined;
        for (const auto& statement : block.statements) {
            if (statement.kind == Statement::Kind::Store ||
                (statement.destination && statement.destination->kind != Expression::Kind::Register)) {
                collectInputRegisters(statement.destination, defined, inputs);
            }
            collectInputRegisters(statement.value, defined, inputs);
            collectInputRegisters(statement.condition, defined, inputs);
            collectInputRegisters(statement.target, defined, inputs);
            for (const auto& argument : statement.arguments) {
                collectInputRegisters(argument, defined, inputs);
            }
            if ((statement.kind == Statement::Kind::Assign || statement.kind == Statement::Kind::Call) &&
                statement.destination && statement.destination->kind == Expression::Kind::Register) {
                defined.insert(statement.destination->name);
            }
        }
    }
    return inputs;
}

std::string abiDiagnostic(const AbiBindingModel& model) {
    std::string result;
    for (const auto& diagnostic : model.diagnostics) {
        if (diagnostic.severity != AbiDiagnosticSeverity::Error) continue;
        if (!result.empty()) result += "; ";
        result += diagnostic.message;
    }
    return result.empty() ? "ABI binding is unsupported" : result;
}

std::string nativePointerTypeName(Architecture architecture) {
    return architecture == Architecture::Arm64 || architecture == Architecture::X64 ? "ulong" : "uint";
}

std::string nativeLiteral(uint64_t value, Architecture architecture) {
    const auto literal = "0x" + hexAddress(value) + "UL";
    return nativePointerTypeName(architecture) == "ulong" ? literal : "unchecked((uint)" + literal + ")";
}

std::string returnRegisterName(Architecture architecture) {
    switch (architecture) {
    case Architecture::Arm64: return "x0";
    case Architecture::Arm32: return "r0";
    case Architecture::X64: return "rax";
    case Architecture::X86: return "eax";
    }
    return {};
}

std::optional<std::string> wrapperType(const std::string& value, const MetadataModel& metadata) {
    static const std::set<std::string> primitives = {
        "void", "bool", "char", "sbyte", "byte", "short", "ushort", "int", "uint", "long", "ulong",
        "float", "double", "string", "object", "nint", "nuint"
    };
    const auto resolved = TypeSystem::resolve(value.empty() ? "object" : value, &metadata);
    auto base = resolved;
    while (base.ends_with(']')) {
        const auto open = base.find_last_of('[');
        if (open == std::string::npos || !std::all_of(base.begin() + static_cast<std::ptrdiff_t>(open + 1),
                                                     base.end() - 1, [](char c) { return c == ','; })) break;
        base.resize(open);
    }
    if (primitives.contains(base)) return resolved;
    if (resolved.empty() || resolved.find('`') != std::string::npos || resolved.find('<') != std::string::npos ||
        resolved.find('>') != std::string::npos || resolved.find('&') != std::string::npos) {
        return std::nullopt;
    }
    return resolved.starts_with("global::") ? resolved : "global::" + resolved;
}

std::optional<std::string> wrapperInput(
    const AbiBinding& binding,
    const std::string& argument,
    const MetadataModel& metadata) {
    const auto type = wrapperType(binding.managedType, metadata);
    if (!type) return std::nullopt;
    switch (binding.valueKind) {
    case AbiValueKind::ObjectReference:
        return "RuntimeCalls.NativePointerToObject<" + *type + ">(" + argument + ")";
    case AbiValueKind::FloatingPoint:
        if (binding.scalarType.bits == 32) return "RuntimeCalls.UInt32BitsToSingle(unchecked((uint)" + argument + "))";
        if (binding.scalarType.bits == 64) return "RuntimeCalls.UInt64BitsToDouble(" + argument + ")";
        return std::nullopt;
    case AbiValueKind::Integer:
        if (binding.scalarType.kind == ScalarKind::Boolean) return "(" + argument + " != 0)";
        return "unchecked((" + *type + ")" + argument + ")";
    case AbiValueKind::Pointer:
        return "unchecked((" + *type + ")" + argument + ")";
    default:
        return std::nullopt;
    }
}

std::optional<std::string> wrapperReturn(
    const AbiReturnModel& value,
    const std::string& invocation,
    Architecture architecture,
    const MetadataModel& metadata) {
    const auto type = wrapperType(value.managedType, metadata);
    if (!type) return std::nullopt;
    switch (value.valueKind) {
    case AbiValueKind::ObjectReference:
        return "RuntimeCalls.ObjectToNativePointer(" + invocation + ")";
    case AbiValueKind::FloatingPoint:
        if (value.scalarType.bits == 32) return "RuntimeCalls.SingleToUInt32Bits(" + invocation + ")";
        if (value.scalarType.bits == 64) return "RuntimeCalls.DoubleToUInt64Bits(" + invocation + ")";
        return std::nullopt;
    case AbiValueKind::Integer:
        if (value.scalarType.kind == ScalarKind::Boolean) {
            return "(" + invocation + " ? (" + nativePointerTypeName(architecture) + ")1 : (" +
                nativePointerTypeName(architecture) + ")0)";
        }
        return "unchecked((" + nativePointerTypeName(architecture) + ")(" + invocation + "))";
    case AbiValueKind::Pointer:
        return "unchecked((" + nativePointerTypeName(architecture) + ")(" + invocation + "))";
    default:
        return std::nullopt;
    }
}

uint64_t managedTarget(const RecoveredFunction& function, size_t index, Architecture architecture) {
    if (architecture == Architecture::Arm64 || architecture == Architecture::X64) {
        return 0x8000000000000000ULL | ((static_cast<uint64_t>(index + 1) & 0xFFFFULL) << 48) |
            (function.address & 0x0000FFFFFFFFFFFFULL);
    }
    return 0x80000000ULL | ((static_cast<uint64_t>(index + 1) & 0xFFULL) << 24) | (function.address & 0x00FFFFFFULL);
}

struct ManagedSupport {
    std::string source;
    std::string prelude;
    std::set<uint64_t> handledTargets;
};

ManagedSupport applyManagedCallSites(
    RecoveredFunction& function,
    const std::vector<ManagedCallSite>& callSites,
    const MetadataModel& metadata) {
    ManagedSupport result;
    const auto className = "ManagedCallSites_" + safeName(function.name, "Method") + "_0x" + hexAddress(function.address);
    std::ostringstream wrappers;
    std::ostringstream registrations;
    std::map<std::pair<size_t, size_t>, std::pair<uint64_t, const ManagedCallSite*>> rewrites;
    size_t emitted = 0;
    for (size_t index = 0; index < callSites.size(); ++index) {
        const auto& call = callSites[index];
        if (!call.emitted || !call.abi.supported() || call.blockIndex >= function.blocks.size() ||
            call.statementIndex >= function.blocks[call.blockIndex].statements.size()) {
            continue;
        }
        const auto& original = function.blocks[call.blockIndex].statements[call.statementIndex];
        if (original.kind != Statement::Kind::Call && original.kind != Statement::Kind::Branch) continue;
        if (call.method.name.empty() || call.method.name == ".ctor" || call.method.name == ".cctor" ||
            call.method.name.find('`') != std::string::npos) {
            continue;
        }
        const auto declaringType = wrapperType(call.method.declaringType, metadata);
        if (!declaringType) continue;

        std::vector<const AbiBinding*> inputs;
        for (const auto& binding : call.abi.signature.bindings) {
            if (binding.role == AbiValueRole::This || binding.role == AbiValueRole::Parameter) inputs.push_back(&binding);
        }
        const AbiBinding* receiver = nullptr;
        std::vector<std::string> arguments;
        std::vector<std::string> parameters;
        bool supported = true;
        for (size_t input = 0; input < inputs.size(); ++input) {
            const auto& binding = *inputs[input];
            const auto name = "arg" + std::to_string(input);
            parameters.push_back(nativePointerTypeName(function.architecture) + " " + name);
            auto converted = wrapperInput(binding, name, metadata);
            if (!converted) {
                supported = false;
                break;
            }
            if (binding.role == AbiValueRole::This) receiver = &binding;
            else arguments.push_back(std::move(*converted));
        }
        if (!supported) continue;

        std::string invocation;
        const auto methodName = managedIdentifier(call.method.name, "Method");
        if (call.method.isStatic && call.kind == CallSiteKind::GeneratedDirect) {
            invocation = *declaringType + "." + methodName;
        } else {
            if (!receiver) continue;
            const auto receiverIndex = static_cast<size_t>(std::find(inputs.begin(), inputs.end(), receiver) - inputs.begin());
            const auto receiverValue = wrapperInput(*receiver, "arg" + std::to_string(receiverIndex), metadata);
            if (!receiverValue) continue;
            invocation = call.kind == CallSiteKind::Interface
                ? "((" + *declaringType + ")" + *receiverValue + ")." + methodName
                : *receiverValue + "." + methodName;
        }
        invocation += "(";
        for (size_t argument = 0; argument < arguments.size(); ++argument) {
            if (argument != 0) invocation += ", ";
            invocation += arguments[argument];
        }
        invocation += ")";

        std::optional<std::string> convertedReturn;
        if (call.abi.typedReturn().valueKind != AbiValueKind::Void) {
            convertedReturn = wrapperReturn(call.abi.typedReturn(), invocation, function.architecture, metadata);
            if (!convertedReturn) continue;
        }
        const auto wrapperName = "Call_" + std::to_string(index);
        wrappers << "    public static " << nativePointerTypeName(function.architecture) << " " << wrapperName << "(";
        for (size_t input = 0; input < parameters.size(); ++input) {
            if (input != 0) wrappers << ", ";
            wrappers << parameters[input];
        }
        wrappers << ")\n    {\n";
        if (call.abi.typedReturn().valueKind == AbiValueKind::Void) {
            wrappers << "        " << invocation << ";\n        return " << nativeLiteral(0, function.architecture) << ";\n";
        } else {
            wrappers << "        return " << *convertedReturn << ";\n";
        }
        wrappers << "    }\n\n";

        const auto target = managedTarget(function, index, function.architecture);
        result.handledTargets.insert(target);
        registrations << "                case " << nativeLiteral(target, function.architecture) << ":\n";
        registrations << "                    return " << wrapperName << "(";
        for (size_t input = 0; input < inputs.size(); ++input) {
            if (input != 0) registrations << ", ";
            registrations << "arguments[" << input << "]";
        }
        registrations << ");\n";
        rewrites.emplace(std::pair{call.blockIndex, call.statementIndex}, std::pair{target, &call});
        ++emitted;
    }
    if (emitted == 0) return result;

    for (size_t blockIndex = 0; blockIndex < function.blocks.size(); ++blockIndex) {
        std::vector<Statement> statements;
        for (size_t statementIndex = 0; statementIndex < function.blocks[blockIndex].statements.size(); ++statementIndex) {
            const auto& original = function.blocks[blockIndex].statements[statementIndex];
            const auto found = rewrites.find({blockIndex, statementIndex});
            if (found == rewrites.end()) {
                statements.push_back(original);
                continue;
            }
            const auto target = found->second.first;
            const auto& call = *found->second.second;
            auto statement = original;
            statement.kind = Statement::Kind::Call;
            statement.target = constant(target, ScalarType::pointer(
                function.architecture == Architecture::Arm64 || function.architecture == Architecture::X64 ? 64 : 32));
            statement.arguments.clear();
            for (const auto& binding : call.abi.signature.bindings) {
                if ((binding.role == AbiValueRole::This || binding.role == AbiValueRole::Parameter) && binding.nativeValue) {
                    statement.arguments.push_back(binding.nativeValue);
                }
            }
            if (original.kind == Statement::Kind::Branch) {
                const auto resultRegister = returnRegisterName(function.architecture);
                statement.destination = reg(resultRegister, ScalarType::pointer(
                    function.architecture == Architecture::Arm64 || function.architecture == Architecture::X64 ? 64 : 32));
                statements.push_back(std::move(statement));
                Statement tailReturn;
                tailReturn.address = original.address;
                tailReturn.kind = Statement::Kind::Return;
                tailReturn.value = reg(resultRegister, ScalarType::pointer(
                    function.architecture == Architecture::Arm64 || function.architecture == Architecture::X64 ? 64 : 32));
                statements.push_back(std::move(tailReturn));
            } else {
                statements.push_back(std::move(statement));
            }
        }
        function.blocks[blockIndex].statements = std::move(statements);
    }

    std::ostringstream support;
    support << "public static unsafe class " << className << "\n{\n";
    support << "    private static bool _registered;\n";
    support << "    public static void Register()\n    {\n";
    support << "        if (_registered) return;\n";
    support << "        _registered = true;\n";
    support << "        RuntimeCallHandler previous = RuntimeCalls.DirectCallHandler;\n";
    support << "        RuntimeCalls.DirectCallHandler = (target, arguments) =>\n        {\n";
    support << "            switch (target)\n            {\n" << registrations.str();
    support << "                default:\n";
    support << "                    if (previous != null) return previous(target, arguments);\n";
    support << "                    throw new global::System.MissingMethodException(\"No direct-call handler is registered.\");\n";
    support << "            }\n        };\n    }\n\n";
    support << wrappers.str() << "}\n";
    result.source = support.str();
    result.prelude = "    " + className + ".Register();\n";
    return result;
}

std::optional<size_t> unmanagedThisPointerBias(const TypeModel* owner, const MetadataModel& metadata,
                                                Architecture architecture) {
    if (!owner || (architecture != Architecture::Arm64 && architecture != Architecture::X64) ||
        (owner->bitfield & 0x1) == 0 || (owner->bitfield & 0x2) != 0 ||
        owner->genericContainerIndex >= 0) return std::nullopt;

    size_t offset = 0;
    std::optional<size_t> bias;
    for (const auto& field : owner->fields) {
        if (field.isStatic || (field.flags & 0x10) != 0 || (field.flags & 0x40) != 0) continue;
        const auto type = TypeSystem::resolve(field.type, &metadata);
        size_t size = 0;
        if (type == "bool" || type == "byte" || type == "sbyte") size = 1;
        else if (type == "char" || type == "short" || type == "ushort") size = 2;
        else if (type == "int" || type == "uint" || type == "float") size = 4;
        else if (type == "long" || type == "ulong" || type == "double" ||
                 type == "nint" || type == "nuint" || type == "System.IntPtr" ||
                 type == "System.UIntPtr") size = 8;
        else return std::nullopt; // A managed reference makes fixed T* illegal.
        if (field.token == 0) return std::nullopt;
        const auto observed = metadata.fieldOffsetsByToken.find(field.token);
        if (observed == metadata.fieldOffsetsByToken.end() || observed->second != field.offset ||
            field.offset < 0) return std::nullopt;
        const size_t alignment = std::min(size, size_t{8});
        offset = (offset + alignment - 1) & ~(alignment - 1);
        const auto nativeOffset = static_cast<size_t>(field.offset);
        if (nativeOffset < offset) return std::nullopt;
        const auto observedBias = nativeOffset - offset;
        if (bias && *bias != observedBias) return std::nullopt;
        bias = observedBias;
        offset += size;
    }
    if (!bias || (*bias != 0 && *bias != 16)) return std::nullopt;
    return bias;
}

std::string indentCSharpSource(const std::string& source, std::string_view indentation) {
    std::ostringstream output;
    size_t start = 0;
    while (start < source.size()) {
        const auto end = source.find('\n', start);
        output << indentation;
        if (end == std::string::npos) {
            output << source.substr(start);
            break;
        }
        output << source.substr(start, end - start) << '\n';
        start = end + 1;
    }
    return output.str();
}

std::string stringLiteralContent(const std::string& value);
class EmittedNamePlan;
std::string managedReturnType(const MethodModel& method, const MetadataModel& metadata,
                             const EmittedNamePlan* emittedNames = nullptr);

bool integralPrimitiveType(std::string_view type) {
    return type == "bool" || type == "char" || type == "sbyte" || type == "byte" ||
        type == "short" || type == "ushort" || type == "int" || type == "uint" ||
        type == "long" || type == "ulong" || type == "nint" || type == "nuint" ||
        type == "System.Boolean" || type == "System.Char" ||
        type == "System.SByte" || type == "System.Byte" ||
        type == "System.Int16" || type == "System.UInt16" ||
        type == "System.Int32" || type == "System.UInt32" ||
        type == "System.Int64" || type == "System.UInt64";
}

bool enumUnderlyingMatches(const TypeModel& type, const MetadataModel& metadata, ScalarType nativeType) {
    if ((type.bitfield & 0x2) == 0 || type.genericContainerIndex >= 0) return false;
    const auto value = std::find_if(type.fields.begin(), type.fields.end(), [](const auto& field) {
        return field.name == "value__";
    });
    if (value == type.fields.end()) return false;
    const auto underlying = TypeSystem::resolve(value->type, &metadata);
    const auto match = [&](ScalarKind kind, uint16_t bits) {
        return nativeType.kind == kind && nativeType.bits == bits;
    };
    if (underlying == "sbyte" || underlying == "System.SByte") return match(ScalarKind::SignedInteger, 8);
    if (underlying == "byte" || underlying == "System.Byte") return match(ScalarKind::UnsignedInteger, 8);
    if (underlying == "short" || underlying == "System.Int16") return match(ScalarKind::SignedInteger, 16);
    if (underlying == "ushort" || underlying == "System.UInt16") return match(ScalarKind::UnsignedInteger, 16);
    if (underlying == "int" || underlying == "System.Int32") return match(ScalarKind::SignedInteger, 32);
    if (underlying == "uint" || underlying == "System.UInt32") return match(ScalarKind::UnsignedInteger, 32);
    if (underlying == "long" || underlying == "System.Int64") return match(ScalarKind::SignedInteger, 64);
    if (underlying == "ulong" || underlying == "System.UInt64") return match(ScalarKind::UnsignedInteger, 64);
    return false;
}

std::optional<std::string> enumReturnCast(
    const MethodModel& method, const MetadataModel& metadata, const TypeModel* owner,
    ScalarType nativeType, std::string_view emittedReturnType) {
    const TypeModel* definition = nullptr;
    const auto& raw = method.returnType;
    if (integralPrimitiveType(raw)) return std::nullopt;
    if (raw.starts_with("type[") && raw.back() == ']') {
        const auto digits = std::string_view(raw).substr(5, raw.size() - 6);
        size_t index = 0;
        const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), index);
        if (parsed.ec == std::errc{} && parsed.ptr == digits.data() + digits.size() &&
            index < metadata.typeReferences.size()) {
            const auto typeIndex = metadata.typeReferences[index].definitionIndex;
            if (typeIndex >= 0 && static_cast<size_t>(typeIndex) < metadata.types.size()) {
                definition = &metadata.types[static_cast<size_t>(typeIndex)];
            }
        }
    } else {
        // Older metadata may have lost the TypeIndex while resolving a short
        // managed name. A nested enum is still identifiable when its parent
        // reference resolves back to this exact declaring type in the image.
        std::optional<size_t> ownerIndex;
        if (owner) {
            for (size_t index = 0; index < metadata.types.size(); ++index) {
                if (&metadata.types[index] == owner) { ownerIndex = index; break; }
            }
        }
        const TypeModel* nested = nullptr;
        for (const auto& type : metadata.types) {
            if (type.name != raw || !enumUnderlyingMatches(type, metadata, nativeType) ||
                !ownerIndex || type.imageName != method.imageName) continue;
            const auto parent = type.declaringTypeIndex;
            const bool sameParent = parent >= 0 &&
                (static_cast<size_t>(parent) == *ownerIndex ||
                 (static_cast<size_t>(parent) < metadata.typeReferences.size() &&
                  metadata.typeReferences[static_cast<size_t>(parent)].definitionIndex ==
                      static_cast<int32_t>(*ownerIndex)));
            if (!sameParent) continue;
            if (nested && nested != &type) return std::nullopt;
            nested = &type;
        }
        if (nested) definition = nested;
        if (!definition) {
            const TypeModel* match = nullptr;
            for (const auto& type : metadata.types) {
                const auto qualified = type.nameSpace.empty() ? type.name : type.nameSpace + "." + type.name;
                if (raw != qualified && raw != type.name) continue;
                if (match && match != &type) return std::nullopt;
                match = &type;
            }
            definition = match;
        }
    }
    if (!definition || !enumUnderlyingMatches(*definition, metadata, nativeType)) {
        return std::nullopt;
    }
    return !emittedReturnType.empty()
        ? std::optional<std::string>(emittedReturnType) : std::nullopt;
}

class MethodBodyAdapter {
public:
    explicit MethodBodyAdapter(
        const MetadataModel& metadata,
        const GenericMethodInfoEvidence* genericEvidence,
        const ManagedEmissionSurface* emissionSurface = nullptr)
        : abi_({}, metadata), genericResolver_(metadata), metadataIndex_(metadata),
          metadataSource_(&metadata), genericEvidence_(genericEvidence), emissionSurface_(emissionSurface) {
        if (genericEvidence && !genericEvidence->typeReferencesByAddress.empty()) {
            UniversalGenericResolverOptions resolverOptions;
            resolverOptions.typeReferencesByAddress = genericEvidence->typeReferencesByAddress;
            universalGenerics_ = std::make_unique<UniversalGenericResolver>(metadata, std::move(resolverOptions));
        }
        for (const auto& type : metadata.types) {
            for (const auto& method : type.methods) {
                const auto& image = method.imageName.empty() ? type.imageName : method.imageName;
                if (!image.empty() && (method.token & 0xFF000000U) == 0x06000000U &&
                    (method.token & 0x00FFFFFFU) != 0) {
                    ++methodTokenCounts_[{image, method.token}];
                }
            }
        }
    }

    MethodBodyEmission emit(
        const RecoveredFunction& function,
        const MethodModel* method,
        const MetadataModel& metadata,
        const TypeModel* owner,
        const std::string& generatedTypeName,
        const std::string& emittedReturnType) const {
        if (!method) return unsupportedBody("managed method metadata is unavailable");
        if (function.blocks.empty()) return unsupportedBody("typed IR body is empty");

        const auto model = abi_.bind(*method, metadata, function.architecture);
        if (!model.supported()) return unsupportedBody(abiDiagnostic(model));

        const bool constructor = method->name == ".ctor" || method->name == ".cctor";
        const bool voidReturn = constructor || model.returnValue.valueKind == AbiValueKind::Void;
        const bool referenceReturn = model.returnValue.valueKind == AbiValueKind::ObjectReference &&
            model.returnValue.conversion == AbiConversion::NativePointerToObject;
        if (!voidReturn && ((model.returnValue.valueKind != AbiValueKind::Integer &&
                             model.returnValue.valueKind != AbiValueKind::FloatingPoint && !referenceReturn) ||
                            (!referenceReturn && model.returnValue.conversion != AbiConversion::None))) {
            return unsupportedBody("managed return value requires an unsupported ABI conversion");
        }

        const auto parameterRegisters = nativeParameterRegisters(function.architecture);
        const auto pointerType = function.architecture == Architecture::Arm64 || function.architecture == Architecture::X64
            ? "ulong" : "uint";
        std::map<std::string, std::string> nativeDeclarations;
        struct FloatParameterBinding {
            std::string storage;
            std::string view;
            std::string managedName;
            uint16_t bits = 0;
        };
        std::vector<FloatParameterBinding> floatBindings;
        std::vector<std::pair<std::string, std::string>> referenceParameterBindings;
        std::optional<std::pair<std::string, std::string>> thisDeclaration;
        std::optional<std::pair<std::string, std::string>> managedThisDeclaration;
        std::optional<std::pair<std::string, std::string>> methodInfoDeclaration;
        const auto thisBias = method->isStatic ? std::nullopt :
            unmanagedThisPointerBias(owner, metadata, function.architecture);
        for (const auto& binding : model.bindings) {
            if (binding.role == AbiValueRole::MethodInfo) {
                const auto& image = method->imageName.empty() && owner ? owner->imageName : method->imageName;
                const auto token = methodTokenCounts_.find({image, method->token});
                if (token != methodTokenCounts_.end() && token->second == 1 &&
                    method->genericContainerIndex < 0 && owner && owner->genericContainerIndex < 0 &&
                    binding.location.kind == AbiLocationKind::Register &&
                    parameterRegisters.contains(binding.location.registerName)) {
                    methodInfoDeclaration = {binding.location.registerName,
                        "    " + std::string(pointerType) + " " + binding.location.registerName +
                        " = RuntimeAbi.ResolveMethodInfo(\"" + stringLiteralContent(image) + "\", " +
                        std::to_string(method->token) + "U);\n"};
                }
                continue;
            }
            if (binding.role == AbiValueRole::This) {
                if (thisBias && binding.location.kind == AbiLocationKind::Register &&
                    !binding.location.registerName.empty()) {
                    std::string declaration = std::string("    ") + pointerType + " " + binding.location.registerName +
                        " = unchecked((" + pointerType + ")__il2cpp_this";
                    if (*thisBias != 0) declaration += " - " + std::to_string(*thisBias) + "UL";
                    declaration += ");\n";
                    thisDeclaration = {binding.location.registerName, std::move(declaration)};
                } else if (!method->isStatic && owner && owner->flags != 0 &&
                           (owner->flags & 0x20) == 0 && (owner->bitfield & 0x3) == 0 &&
                           binding.location.kind == AbiLocationKind::Register &&
                           parameterRegisters.contains(binding.location.registerName)) {
                    managedThisDeclaration = {binding.location.registerName,
                        "    " + std::string(pointerType) + " " + binding.location.registerName +
                        " = RuntimeAbi.ToNative(this);\n"};
                }
                continue;
            }
            if (binding.valueKind == AbiValueKind::FloatingPoint &&
                binding.conversion == AbiConversion::None && function.architecture == Architecture::Arm64 &&
                binding.location.kind == AbiLocationKind::Register &&
                binding.registerView && (binding.scalarType.bits == 32 || binding.scalarType.bits == 64)) {
                const auto index = binding.parameterIndex.value_or(0);
                floatBindings.push_back({binding.location.registerName, binding.registerView->viewName,
                    managedIdentifier(binding.managedName, "param" + std::to_string(index)), binding.scalarType.bits});
                continue;
            }
            if (binding.valueKind == AbiValueKind::ObjectReference &&
                binding.conversion == AbiConversion::ObjectToNativePointer &&
                binding.location.kind == AbiLocationKind::Register &&
                parameterRegisters.contains(binding.location.registerName)) {
                const auto index = binding.parameterIndex.value_or(0);
                const auto managedName = managedIdentifier(binding.managedName, "param" + std::to_string(index));
                referenceParameterBindings.push_back({binding.location.registerName,
                    "    " + std::string(pointerType) + " " + binding.location.registerName +
                    " = RuntimeAbi.ToNativeArgument(" + managedName + ");\n"});
                continue;
            }
            if (binding.valueKind != AbiValueKind::Integer || binding.conversion != AbiConversion::None) {
                return unsupportedBody("parameter '" + binding.managedName + "' requires an unsupported ABI conversion");
            }
            if (binding.location.kind != AbiLocationKind::Register ||
                !parameterRegisters.contains(binding.location.registerName)) {
                return unsupportedBody("parameter '" + binding.managedName + "' does not have a supported native register binding");
            }
            const auto index = binding.parameterIndex.value_or(0);
            const auto managedName = managedIdentifier(binding.managedName, "param" + std::to_string(index));
            std::string value = managedName;
            if (binding.scalarType.kind == ScalarKind::Boolean) {
                value = managedName + (std::string(pointerType) == "ulong" ? " ? 1UL : 0UL" : " ? 1U : 0U");
            }
            nativeDeclarations.emplace(
                binding.location.registerName,
                "    " + std::string(pointerType) + " " + binding.location.registerName +
                    " = unchecked((" + pointerType + ")(" + value + "));\n");
        }

        auto adapted = function;
        ManagedEmitterOptions managedOptions;
        managedOptions.patterns.genericResolver = &genericResolver_;
        managedOptions.patterns.metadataIndex = &metadataIndex_;
        managedOptions.patterns.collectAmbiguousFieldCandidates = false;
        managedOptions.dispatch.metadataIndex = &metadataIndex_;
        managedOptions.abiAdapter = &abi_;
        managedOptions.abiAdapterSource = &metadata;
        if (metadataSource_ == &metadata) managedOptions.emissionSurface = emissionSurface_;
        if (genericEvidence_ && metadataSource_ == &metadata) {
            managedOptions.patterns.genericMethodInfoByAddressView = &genericEvidence_->bySlotAddress;
            managedOptions.universalGenerics = universalGenerics_.get();
            managedOptions.universalGenericsSource = metadataSource_;
        }
        auto managed = ManagedEmitter{}.emit(function, metadata, managedOptions);
        auto managedSupport = applyManagedCallSites(adapted, managed.callSites, metadata);
        std::vector<uint64_t> unresolvedNativeCalls;
        for (const auto& block : adapted.blocks) {
            for (const auto& statement : block.statements) {
                if (statement.kind == Statement::Kind::Call && statement.target &&
                    statement.target->kind == Expression::Kind::Constant &&
                    !managedSupport.handledTargets.contains(statement.target->constant)) {
                    unresolvedNativeCalls.push_back(statement.address);
                }
            }
        }
        bool hasReturnValue = false;
        for (auto& block : adapted.blocks) {
            for (auto& statement : block.statements) {
                if (statement.kind != Statement::Kind::Return || voidReturn) continue;
                if (!statement.value) return unsupportedBody("value-returning method has a return without a value");
                statement.value = cast(statement.value, model.returnValue.scalarType);
                hasReturnValue = true;
            }
        }
        if (!voidReturn && !hasReturnValue) return unsupportedBody("value-returning method has no typed return statement");

        const auto registers = requiredInputRegisters(adapted);
        const bool useThisPointer = thisDeclaration && registers.contains(thisDeclaration->first);
        const bool useManagedThisHandler = managedThisDeclaration && registers.contains(managedThisDeclaration->first);
        const bool useMethodInfoHandler = methodInfoDeclaration && registers.contains(methodInfoDeclaration->first);
        if (useThisPointer) nativeDeclarations.emplace(thisDeclaration->first, thisDeclaration->second);
        if (useManagedThisHandler) nativeDeclarations.emplace(managedThisDeclaration->first, managedThisDeclaration->second);
        if (useMethodInfoHandler) nativeDeclarations.emplace(methodInfoDeclaration->first, methodInfoDeclaration->second);
        bool useReferenceParameterHandler = false;
        for (const auto& [name, declaration] : referenceParameterBindings) {
            if (registers.contains(name)) {
                nativeDeclarations.emplace(name, declaration);
                useReferenceParameterHandler = true;
            }
        }
        for (const auto& name : parameterRegisters) {
            if (registers.contains(name) && !nativeDeclarations.contains(name)) {
                return unsupportedBody("native register '" + name + "' has no managed ABI value");
            }
        }
        std::set<std::string> boundFloatInputs;
        for (const auto& binding : floatBindings) {
            const bool storageUsed = registers.contains(binding.storage);
            const bool viewUsed = registers.contains(binding.view);
            if (storageUsed && viewUsed) {
                return unsupportedBody("floating parameter register has mixed storage and scalar views");
            }
            if (storageUsed) boundFloatInputs.insert(binding.storage);
            if (viewUsed) boundFloatInputs.insert(binding.view);
        }
        if (function.architecture == Architecture::Arm64) {
            for (size_t index = 0; index < 8; ++index) {
                const auto name = "v" + std::to_string(index);
                if (registers.contains(name) && !boundFloatInputs.contains(name)) {
                    return unsupportedBody("native floating register '" + name + "' has no managed ABI value");
                }
            }
        }

        CSharpBodyOptions options;
        options.voidReturn = voidReturn;
        options.declareNativeParameters = false;
        for (const auto& [name, declaration] : nativeDeclarations) {
            (void)declaration;
            options.externalNativeRegisters.insert(name);
        }
        if (!voidReturn && model.returnValue.valueKind == AbiValueKind::Integer) {
            if (emittedReturnType == "char" || emittedReturnType == "System.Char") {
                if (model.returnValue.scalarType.kind != ScalarKind::UnsignedInteger ||
                    model.returnValue.scalarType.bits != 16) {
                    return unsupportedBody("char return has no verified 16-bit ABI value");
                }
                options.managedReturnCast = emittedReturnType;
            } else if (const auto enumType = enumReturnCast(*method, metadata, owner,
                                                            model.returnValue.scalarType, emittedReturnType)) {
                options.managedReturnCast = *enumType;
            } else if (!integralPrimitiveType(emittedReturnType)) {
                return unsupportedBody("integral return type has no verified enum identity");
            }
        }
        if (referenceReturn) {
            options.managedReturnReferenceType = emittedReturnType;
            if (!supportedCSharpType(options.managedReturnReferenceType)) {
                return unsupportedBody("managed reference return type has unresolved C# syntax");
            }
        }
        auto emitted = adapted.emitCSharpBody(options);
        std::vector<std::string> floatingInitializers;
        for (const auto& binding : floatBindings) {
            if (boundFloatInputs.contains(binding.storage)) {
                if (emitted.declarations.find("RuntimeVector128 " + binding.storage) == std::string::npos) {
                    return unsupportedBody("floating parameter has no vector storage declaration");
                }
                floatingInitializers.push_back("    " + binding.storage + " = RuntimeVector128.Zero.With" +
                    (binding.bits == 32 ? std::string("Single") : std::string("Double")) +
                    "(0, " + binding.managedName + ");\n");
            } else if (boundFloatInputs.contains(binding.view)) {
                const auto type = binding.bits == 32 ? "float" : "double";
                if (emitted.declarations.find(std::string(type) + " " + binding.view) == std::string::npos) {
                    return unsupportedBody("floating parameter has no scalar view declaration");
                }
                floatingInitializers.push_back("    " + binding.view + " = " + binding.managedName + ";\n");
            }
        }
        MethodBodyEmission result;
        result.status = emitted.partial ? MethodBodyStatus::Partial : MethodBodyStatus::Supported;
        result.support = managedSupport.source + emitted.support;
        if (!managedSupport.source.empty()) {
            result.supportFragments.push_back({"managed-callsite-" + hexAddress(function.address) + '-' +
                                               function.name, managedSupport.source});
        }
        result.supportFragments.insert(result.supportFragments.end(),
                                       emitted.supportFragments.begin(), emitted.supportFragments.end());
        result.source = managedSupport.prelude;
        std::string nativeBody;
        for (const auto& [name, declaration] : nativeDeclarations) nativeBody += declaration;
        nativeBody += emitted.declarations;
        for (const auto& initializer : floatingInitializers) nativeBody += initializer;
        nativeBody += emitted.body;
        if (useThisPointer) {
            result.source += "    fixed (" + generatedTypeName + "* __il2cpp_this = &this)\n    {\n";
            result.source += indentCSharpSource(nativeBody, "    ");
            result.source += "    }\n";
        } else {
            result.source += nativeBody;
        }
        for (const auto& diagnostic : emitted.diagnostics) {
            if (!result.diagnostic.empty()) result.diagnostic += "; ";
            result.diagnostic += "0x" + hexAddress(diagnostic.address) + ": " + diagnostic.message;
        }
        if (result.status == MethodBodyStatus::Partial && result.diagnostic.empty()) {
            result.diagnostic = "IR emitter reported partial recovery";
        }
        if (!unresolvedNativeCalls.empty()) {
            result.status = MethodBodyStatus::Partial;
            if (!result.diagnostic.empty()) result.diagnostic += "; ";
            result.diagnostic += "native direct call at 0x" + hexAddress(unresolvedNativeCalls.front()) +
                " requires a RuntimeCalls handler";
        }
        if (useManagedThisHandler || useMethodInfoHandler) {
            result.status = MethodBodyStatus::Partial;
            if (!result.diagnostic.empty()) result.diagnostic += "; ";
            if (useManagedThisHandler) result.diagnostic += "class receiver requires RuntimeAbi.ManagedToNativeHandler";
            if (useManagedThisHandler && useMethodInfoHandler) result.diagnostic += "; ";
            if (useMethodInfoHandler) result.diagnostic += "MethodInfo requires RuntimeAbi.MethodInfoResolver";
        }
        if (useReferenceParameterHandler || referenceReturn) {
            result.status = MethodBodyStatus::Partial;
            if (!result.diagnostic.empty()) result.diagnostic += "; ";
            if (useReferenceParameterHandler) result.diagnostic += "reference parameter requires RuntimeAbi.ManagedToNativeHandler";
            if (useReferenceParameterHandler && referenceReturn) result.diagnostic += "; ";
            if (referenceReturn) result.diagnostic += "reference return requires RuntimeAbi.NativeToManagedHandler";
        }
        return result;
    }

private:
    AbiAdapter abi_;
    GenericMethodResolver genericResolver_;
    ManagedMetadataIndex metadataIndex_;
    const MetadataModel* metadataSource_ = nullptr;
    const GenericMethodInfoEvidence* genericEvidence_ = nullptr;
    const ManagedEmissionSurface* emissionSurface_ = nullptr;
    std::unique_ptr<UniversalGenericResolver> universalGenerics_;
    std::map<std::pair<std::string, uint32_t>, size_t> methodTokenCounts_;
};

bool isConstructor(const MethodModel* method) {
    return method && (method->name == ".ctor" || method->name == ".cctor");
}

std::string methodBaseName(const RecoveredFunction& function, const MethodModel* method) {
    std::string name;
    if (method && !method->name.empty() && !isConstructor(method)) name = method->name;
    if (name.empty()) name = function.name;
    if (name.empty()) name = "Method_0x" + hexAddress(function.address);
    return safeName(name, "Method_0x" + hexAddress(function.address));
}

std::string trim(std::string value) {
    const auto isSpace = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    const auto first = std::find_if_not(value.begin(), value.end(), isSpace);
    const auto last = std::find_if_not(value.rbegin(), value.rend(), isSpace).base();
    if (first >= last) return {};
    return std::string(first, last);
}

class EmittedNamePlan {
public:
    struct Entry {
        std::string nameSpace;
        std::string typeName;
        GenericDeclarationInfo generic;
        std::string qualifiedName;
        bool renamed = false;
        bool publiclyVisible = true;
    };

    EmittedNamePlan(const MetadataModel& metadata, const std::map<size_t, TypeGroup>& groups);
    const Entry& at(size_t key) const { return entries_.at(key); }
    std::optional<std::string> render(std::string_view raw, std::string_view resolved,
                                      std::string_view imageName, const MetadataModel& metadata) const;
    bool isInternal(std::string_view raw, std::string_view imageName,
                    const MetadataModel& metadata) const;
    bool isInternalEmitted(std::string_view resolved, std::string_view imageName) const;
    std::optional<std::string> validateConstraint(int32_t referenceIndex, std::string resolved,
                                                  std::string_view imageName,
                                                  const MetadataModel& metadata) const;

private:
    static std::string key(std::string_view imageName, std::string_view rawName) {
        return std::string(imageName) + '\x1f' + std::string(rawName);
    }
    void indexName(std::string_view imageName, std::string_view rawName, size_t definitionIndex);
    std::optional<size_t> definitionFromRaw(std::string_view raw, std::string_view imageName,
                                            const MetadataModel& metadata) const;
    std::optional<size_t> definitionFromTypeRef(size_t index, const MetadataModel& metadata,
                                                size_t depth = 0) const;

    std::map<size_t, Entry> entries_;
    std::unordered_map<std::string, std::optional<size_t>> byImageName_;
    std::unordered_map<std::string, std::optional<size_t>> byEmittedName_;
};

std::string managedTypeName(
    const std::string& type,
    const MetadataModel& metadata,
    std::string_view imageName = {},
    const EmittedNamePlan* emittedNames = nullptr) {
    const auto resolved = TypeSystem::resolve(type.empty() ? "object" : type, &metadata);
    if (emittedNames) {
        if (const auto mapped = emittedNames->render(type, resolved, imageName, metadata)) return *mapped;
    }
    if (supportedCSharpType(resolved) || imageName.empty() || type.starts_with("type[")) return resolved;

    // Compiler-generated metadata names such as `<MoveNext>c__AnonStorey0`
    // are not C# type syntax. Reuse the exact identifier emitted for a unique
    // same-image type; ambiguity leaves the member unsupported.
    std::optional<std::string> unique;
    for (const auto& candidate : metadata.types) {
        if (candidate.imageName != imageName || candidate.genericContainerIndex >= 0 ||
            candidate.declaringTypeIndex >= 0) continue;
        const auto qualified = candidate.nameSpace.empty()
            ? candidate.name : candidate.nameSpace + '.' + candidate.name;
        if (type != candidate.name && type != qualified) continue;
        const auto parts = namespaceParts(candidate.nameSpace);
        auto emitted = join(parts, ".");
        if (!emitted.empty()) emitted += '.';
        emitted += safeName(candidate.name, "UnknownType");
        if (unique) return resolved;
        unique = std::move(emitted);
    }
    return unique.value_or(resolved);
}

std::string qualifyShadowedType(
    std::string resolved,
    std::string_view /*ownerTypeName*/,
    std::string_view imageName,
    const MetadataModel& metadata) {
    if (resolved.starts_with("global::") || resolved.find('.') == std::string::npos) return resolved;
    auto named = resolved;
    if (const auto generic = named.find('<'); generic != std::string::npos) named.resize(generic);
    if (const auto array = named.find('['); array != std::string::npos) named.resize(array);
    size_t matches = 0;
    for (const auto& candidate : metadata.types) {
        if (!imageName.empty() && candidate.imageName != imageName) continue;
        const auto qualified = candidate.nameSpace.empty()
            ? candidate.name : candidate.nameSpace + '.' + candidate.name;
        if (qualified == named) ++matches;
        if (matches > 1) return resolved;
    }
    return matches == 1 ? "global::" + resolved : resolved;
}

std::string managedReturnType(const MethodModel& method, const MetadataModel& metadata,
                             const EmittedNamePlan* emittedNames) {
    const auto resolved = TypeSystem::returnType(method, &metadata);
    if (method.returnType.empty()) return resolved;
    if (emittedNames) {
        if (const auto mapped = emittedNames->render(method.returnType, resolved,
                                                    method.imageName, metadata)) return *mapped;
    }
    if (supportedCSharpType(resolved)) return resolved;
    return managedTypeName(method.returnType, metadata, method.imageName, emittedNames);
}

void appendIndented(std::ostringstream& output, const std::string& source, const std::string& indentation) {
    size_t start = 0;
    while (start < source.size()) {
        const auto end = source.find('\n', start);
        output << indentation;
        if (end == std::string::npos) {
            output << source.substr(start);
            break;
        }
        output << source.substr(start, end - start) << '\n';
        start = end + 1;
    }
}

std::string uniqueTypeName(const std::string& nameSpace, const std::string& requested, std::set<std::pair<std::string, std::string>>& used) {
    auto candidate = requested;
    for (size_t suffix = 2; !used.insert({nameSpace, candidate}).second; ++suffix) {
        candidate = requested + '_' + std::to_string(suffix);
    }
    return candidate;
}

EmittedNamePlan::EmittedNamePlan(const MetadataModel& metadata, const std::map<size_t, TypeGroup>& groups) {
    std::set<std::pair<std::string, std::string>> used;
    for (const auto& [key, group] : groups) {
        const bool unmatched = key == metadata.types.size();
        const auto* type = unmatched ? nullptr : &metadata.types[key];
        const auto sourceNamespace = unmatched ? std::string("Il2CppRecovered") : type->nameSpace;
        const auto sourceName = unmatched ? std::string("UnmatchedMethods") : type->name;
        const auto nestedParent = type && group.metadataTypes.size() == 1
            ? emittedNestedParent(metadata, *type) : nullptr;
        const auto declaringType = typeDeclaration(type, false, nestedParent != nullptr);
        auto generic = type ? genericDeclaration(metadata, type->genericContainerIndex, false,
                                                 declaringType.kind == ManagedTypeKind::Interface)
                            : GenericDeclarationInfo{};
        const auto nameSpace = join(namespaceParts(sourceNamespace), ".");
        const auto requested = safeName(genericTypeBaseName(sourceName, generic), "UnnamedType");
        const auto typeName = uniqueTypeName(nameSpace, requested, used);
        std::string qualified = nameSpace.empty() ? std::string{} : nameSpace + '.';
        if (nestedParent) qualified += safeName(nestedParent->name, "OuterType") + '.';
        qualified += typeName;
        if (qualified.find('.') != std::string::npos) qualified.insert(0, "global::");
        entries_.emplace(key, Entry{nameSpace, typeName, std::move(generic), qualified,
                                    typeName != requested || nestedParent != nullptr,
                                    declaringType.visibility == "public"});
        if (!type) continue;
        const auto indexEmitted = [&](const std::string& name) {
            const auto [it, inserted] = byEmittedName_.emplace(EmittedNamePlan::key(type->imageName, name), key);
            if (!inserted && it->second != key) it->second = std::nullopt;
        };
        indexEmitted(typeName);
        indexEmitted(qualified);
        const auto rawQualified = type->nameSpace.empty() ? type->name : type->nameSpace + '.' + type->name;
        indexName(type->imageName, type->name, key);
        indexName(type->imageName, rawQualified, key);
        if (type->name.find('`') != std::string::npos) {
            auto base = type->name.substr(0, type->name.find('`'));
            indexName(type->imageName, base, key);
            if (!type->nameSpace.empty()) indexName(type->imageName, type->nameSpace + '.' + base, key);
        }
    }
    for (const auto& [index, group] : groups) {
        if (index >= metadata.types.size()) continue;
        const auto& type = metadata.types[index];
        auto& entry = entries_.at(index);
        const auto declaringType = typeDeclaration(&type, false,
            group.metadataTypes.size() == 1 && emittedNestedParent(metadata, type) != nullptr);
        entry.generic = genericDeclaration(metadata, type.genericContainerIndex, false,
            declaringType.kind == ManagedTypeKind::Interface,
            [this, &type, &metadata](int32_t ref, std::string resolved) {
                return validateConstraint(ref, std::move(resolved), type.imageName, metadata);
            });
    }
}

void EmittedNamePlan::indexName(std::string_view imageName, std::string_view rawName, size_t definitionIndex) {
    if (imageName.empty() || rawName.empty()) return;
    const auto [it, inserted] = byImageName_.emplace(key(imageName, rawName), definitionIndex);
    if (!inserted && it->second != definitionIndex) it->second = std::nullopt;
}

std::optional<size_t> EmittedNamePlan::definitionFromTypeRef(
    size_t index, const MetadataModel& metadata, size_t depth) const {
    if (depth > 32 || index >= metadata.typeReferences.size()) return std::nullopt;
    const auto& reference = metadata.typeReferences[index];
    if (reference.definitionIndex >= 0 &&
        static_cast<size_t>(reference.definitionIndex) < metadata.types.size()) {
        return static_cast<size_t>(reference.definitionIndex);
    }
    if (reference.elementTypeIndex >= 0) {
        return definitionFromTypeRef(static_cast<size_t>(reference.elementTypeIndex), metadata, depth + 1);
    }
    return std::nullopt;
}

std::optional<size_t> EmittedNamePlan::definitionFromRaw(
    std::string_view raw, std::string_view imageName, const MetadataModel& metadata) const {
    if (raw.starts_with("type[") && raw.ends_with(']')) {
        const auto digits = raw.substr(5, raw.size() - 6);
        size_t index = 0;
        const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), index);
        if (parsed.ec == std::errc{} && parsed.ptr == digits.data() + digits.size()) {
            return definitionFromTypeRef(index, metadata);
        }
        return std::nullopt;
    }
    if (imageName.empty()) return std::nullopt;
    auto name = std::string(raw);
    if (name.starts_with("global::")) name.erase(0, 8);
    if (const auto generic = name.find('<'); generic != std::string::npos) name.resize(generic);
    if (const auto array = name.find('['); array != std::string::npos) name.resize(array);
    while (!name.empty() && (name.back() == '*' || name.back() == '?' || name.back() == '&')) name.pop_back();
    const auto found = byImageName_.find(key(imageName, name));
    return found == byImageName_.end() ? std::nullopt : found->second;
}

std::optional<std::string> EmittedNamePlan::render(
    std::string_view raw, std::string_view resolved, std::string_view imageName,
    const MetadataModel& metadata) const {
    const auto definition = definitionFromRaw(raw, imageName, metadata);
    if (!definition) return std::nullopt;
    const auto planned = entries_.find(*definition);
    if (planned == entries_.end() || !planned->second.renamed) return std::nullopt;
    std::string value(resolved);
    std::string prefix;
    for (const auto lead : {"ref ", "out ", "in "}) {
        if (value.starts_with(lead)) {
            prefix = lead;
            value.erase(0, std::char_traits<char>::length(lead));
            break;
        }
    }
    const auto suffixStart = value.find_first_of("<[*?&");
    const auto suffix = suffixStart == std::string::npos ? std::string{} : value.substr(suffixStart);
    return prefix + planned->second.qualifiedName + suffix;
}

bool EmittedNamePlan::isInternal(std::string_view raw, std::string_view imageName,
                                const MetadataModel& metadata) const {
    const auto definition = definitionFromRaw(raw, imageName, metadata);
    if (!definition) return false;
    const auto planned = entries_.find(*definition);
    return planned != entries_.end() && !planned->second.publiclyVisible;
}

bool EmittedNamePlan::isInternalEmitted(std::string_view resolved, std::string_view imageName) const {
    std::string name(resolved);
    if (const auto suffix = name.find_first_of("<[?*&"); suffix != std::string::npos) name.resize(suffix);
    const auto found = byEmittedName_.find(key(imageName, name));
    if (found == byEmittedName_.end() || !found->second) return false;
    const auto planned = entries_.find(*found->second);
    return planned != entries_.end() && !planned->second.publiclyVisible;
}

std::optional<std::string> EmittedNamePlan::validateConstraint(
    int32_t referenceIndex, std::string resolved, std::string_view imageName,
    const MetadataModel& metadata) const {
    if (referenceIndex < 0 || static_cast<size_t>(referenceIndex) >= metadata.typeReferences.size()) return std::nullopt;
    const auto open = resolved.find('<');
    if (open == std::string::npos) return resolved;
    size_t depth = 0;
    size_t argumentCount = 1;
    size_t close = std::string::npos;
    for (size_t position = open; position < resolved.size(); ++position) {
        if (resolved[position] == '<') ++depth;
        else if (resolved[position] == '>') {
            if (--depth == 0) { close = position; break; }
        } else if (resolved[position] == ',' && depth == 1) ++argumentCount;
    }
    if (close == std::string::npos) return std::nullopt;
    const auto raw = "type[" + std::to_string(referenceIndex) + "]";
    const auto definition = definitionFromRaw(raw, imageName, metadata);
    std::optional<size_t> target = definition;
    if (!target) {
        const auto found = byEmittedName_.find(key(imageName, resolved.substr(0, open)));
        if (found != byEmittedName_.end()) target = found->second;
    }
    if (!target) return resolved;
    const auto planned = entries_.find(*target);
    if (planned == entries_.end()) return resolved;
    const auto& parameters = planned->second.generic.parameters;
    size_t emittedArity = 0;
    if (!parameters.empty()) {
        emittedArity = 1 + static_cast<size_t>(std::count(parameters.begin(), parameters.end(), ','));
    }
    if (argumentCount != emittedArity) return std::nullopt;
    if (planned->second.renamed) return planned->second.qualifiedName + resolved.substr(open);
    return resolved;
}

std::filesystem::path uniqueTypePath(
    const std::filesystem::path& directory,
    const std::string& requested,
    std::set<std::string>& used) {
    const auto candidateKey = [&directory](const std::string& name) {
        return lowerAscii((directory / (name + ".cs")).generic_string());
    };
    auto candidate = requested;
    size_t suffix = 2;
    while (!used.insert(candidateKey(candidate)).second) {
        candidate = requested + '_' + std::to_string(suffix++);
    }
    return directory / (candidate + ".cs");
}

bool isStaticType(const TypeGroup& group, bool unmatched) {
    if (unmatched) return true;
    if (group.metadataTypes.empty()) return false;
    return std::all_of(group.metadataTypes.begin(), group.metadataTypes.end(), [](const TypeModel* type) {
        const auto flags = nativeFlags(*type);
        return flags && (*flags & (0x80U | 0x100U)) == (0x80U | 0x100U);
    });
}

std::string uniqueFieldName(
    const FieldModel& field,
    const std::string& typeName,
    std::set<std::string>& used) {
    const auto base = safeName(field.name, "Field");
    auto candidate = base == typeName ? base + "_Field" : base;
    if (used.contains(candidate)) {
        candidate += "_0x" + hexAddress(static_cast<uint64_t>(std::max<int64_t>(field.offset, 0)));
    }
    const auto stem = candidate;
    for (size_t suffix = 2; !used.insert(candidate).second; ++suffix) {
        candidate = stem + '_' + std::to_string(suffix);
    }
    return candidate;
}

std::optional<uint64_t> defaultValueWord(const MetadataModel& metadata, int32_t offset, size_t size) {
    if (offset < 0) return std::nullopt;
    const auto begin = static_cast<size_t>(offset);
    if (begin > metadata.defaultValueData.size() || size > metadata.defaultValueData.size() - begin) return std::nullopt;
    uint64_t result = 0;
    for (size_t index = 0; index < size; ++index) result |= static_cast<uint64_t>(metadata.defaultValueData[begin + index]) << (index * 8);
    return result;
}

std::string quotedString(const std::string& value) {
    std::ostringstream output;
    output << '\"';
    for (const unsigned char c : value) {
        switch (c) {
        case '\\': output << "\\\\"; break;
        case '\"': output << "\\\""; break;
        case '\r': output << "\\r"; break;
        case '\n': output << "\\n"; break;
        case '\t': output << "\\t"; break;
        default:
            if (c < 0x20 || c == 0x7f) {
                output << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(c) << std::dec;
            } else {
                output << static_cast<char>(c);
            }
            break;
        }
    }
    output << '\"';
    return output.str();
}

std::string quotedChar(uint16_t value) {
    switch (value) {
    case '\\': return "'\\\\'";
    case '\'': return "'\\\''";
    case '\r': return "'\\r'";
    case '\n': return "'\\n'";
    case '\t': return "'\\t'";
    case '\0': return "'\\0'";
    default: break;
    }
    if (value < 0x20 || value >= 0x7f) {
        std::ostringstream output;
        output << "'\\u" << std::hex << std::setw(4) << std::setfill('0') << value << "'";
        return output.str();
    }
    std::string result = "'";
    result.push_back(static_cast<char>(value));
    result.push_back('\'');
    return result;
}

template<typename T>
std::string floatingLiteral(uint64_t bits, const std::string& suffix, const std::string& typeName) {
    using Bits = std::conditional_t<sizeof(T) == 4, uint32_t, uint64_t>;
    const T value = std::bit_cast<T>(static_cast<Bits>(bits));
    if (std::isnan(value)) return typeName + ".NaN";
    if (std::isinf(value)) return value < 0 ? typeName + ".NegativeInfinity" : typeName + ".PositiveInfinity";
    std::ostringstream output;
    output << std::setprecision(std::numeric_limits<T>::max_digits10) << value;
    auto text = output.str();
    if (text.find_first_of(".eE") == std::string::npos) text += ".0";
    return text + suffix;
}

Il2CppTypeCode defaultValueCode(const std::string& typeName) {
    if (typeName == "bool" || typeName == "System.Boolean") return Il2CppTypeCode::Boolean;
    if (typeName == "char" || typeName == "System.Char") return Il2CppTypeCode::Char;
    if (typeName == "sbyte" || typeName == "System.SByte") return Il2CppTypeCode::I1;
    if (typeName == "byte" || typeName == "System.Byte") return Il2CppTypeCode::U1;
    if (typeName == "short" || typeName == "System.Int16") return Il2CppTypeCode::I2;
    if (typeName == "ushort" || typeName == "System.UInt16") return Il2CppTypeCode::U2;
    if (typeName == "int" || typeName == "System.Int32") return Il2CppTypeCode::I4;
    if (typeName == "uint" || typeName == "System.UInt32") return Il2CppTypeCode::U4;
    if (typeName == "long" || typeName == "System.Int64") return Il2CppTypeCode::I8;
    if (typeName == "ulong" || typeName == "System.UInt64") return Il2CppTypeCode::U8;
    if (typeName == "float" || typeName == "System.Single") return Il2CppTypeCode::R4;
    if (typeName == "double" || typeName == "System.Double") return Il2CppTypeCode::R8;
    if (typeName == "string" || typeName == "System.String") return Il2CppTypeCode::String;
    return Il2CppTypeCode::Object;
}

std::optional<std::string> defaultValueLiteral(
    const std::string& typeName,
    Il2CppTypeCode code,
    int32_t dataIndex,
    const MetadataModel& metadata) {
    if (code == Il2CppTypeCode::Object) code = defaultValueCode(typeName);
    if (dataIndex < 0) {
        if (code == Il2CppTypeCode::String || code == Il2CppTypeCode::Class || code == Il2CppTypeCode::Object ||
            code == Il2CppTypeCode::Array || code == Il2CppTypeCode::SzArray || typeName == "string" ||
            typeName == "object" || typeName.ends_with("]")) {
            return "null";
        }
        return std::nullopt;
    }
    const auto word = [&](size_t size) { return defaultValueWord(metadata, dataIndex, size); };
    switch (code) {
    case Il2CppTypeCode::Boolean: {
        const auto value = word(1);
        if (!value) return std::nullopt;
        return *value == 0 ? "false" : "true";
    }
    case Il2CppTypeCode::Char: {
        const auto value = word(2);
        if (!value) return std::nullopt;
        return quotedChar(static_cast<uint16_t>(*value));
    }
    case Il2CppTypeCode::I1:
    case Il2CppTypeCode::I2:
    case Il2CppTypeCode::I4:
    case Il2CppTypeCode::I8:
    case Il2CppTypeCode::U1:
    case Il2CppTypeCode::U2:
    case Il2CppTypeCode::U4:
    case Il2CppTypeCode::U8: {
        size_t size = 0;
        bool isSigned = false;
        switch (code) {
        case Il2CppTypeCode::I1: size = 1; isSigned = true; break;
        case Il2CppTypeCode::I2: size = 2; isSigned = true; break;
        case Il2CppTypeCode::I4: size = 4; isSigned = true; break;
        case Il2CppTypeCode::I8: size = 8; isSigned = true; break;
        case Il2CppTypeCode::U1: size = 1; break;
        case Il2CppTypeCode::U2: size = 2; break;
        case Il2CppTypeCode::U4: size = 4; break;
        default: size = 8; break;
        }
        const auto value = word(size);
        if (!value) return std::nullopt;
        const auto literal = "0x" + hexAddress(*value) + "UL";
        return "unchecked((" + typeName + ")" + (isSigned ? literal : literal) + ")";
    }
    case Il2CppTypeCode::R4: {
        const auto value = word(4);
        if (!value) return std::nullopt;
        return floatingLiteral<float>(static_cast<uint32_t>(*value), "F", "float");
    }
    case Il2CppTypeCode::R8: {
        const auto value = word(8);
        if (!value) return std::nullopt;
        return floatingLiteral<double>(*value, "D", "double");
    }
    case Il2CppTypeCode::String: {
        const auto length = word(4);
        if (!length || *length > std::numeric_limits<uint32_t>::max()) return std::nullopt;
        const auto begin = static_cast<size_t>(dataIndex) + 4;
        const auto size = static_cast<size_t>(*length);
        if (begin > metadata.defaultValueData.size() || size > metadata.defaultValueData.size() - begin) return std::nullopt;
        return quotedString(std::string(reinterpret_cast<const char*>(metadata.defaultValueData.data() + begin), size));
    }
    default:
        return std::nullopt;
    }
}

std::optional<std::string> fieldDefaultValue(const FieldModel& field, const MetadataModel& metadata) {
    if (field.defaultValueIndex < 0 || static_cast<size_t>(field.defaultValueIndex) >= metadata.fieldDefaultValues.size()) {
        return std::nullopt;
    }
    const auto& value = metadata.fieldDefaultValues[static_cast<size_t>(field.defaultValueIndex)];
    auto code = Il2CppTypeCode::Object;
    if (value.typeIndex >= 0 && static_cast<size_t>(value.typeIndex) < metadata.typeReferences.size()) {
        code = static_cast<Il2CppTypeCode>(metadata.typeReferences[static_cast<size_t>(value.typeIndex)].code);
    }
    const auto dataType = value.typeIndex >= 0 && static_cast<size_t>(value.typeIndex) < metadata.typeReferences.size()
        ? TypeSystem::resolve(static_cast<size_t>(value.typeIndex), metadata)
        : managedTypeName(field.type, metadata);
    auto literal = defaultValueLiteral(dataType, code, value.dataIndex, metadata);
    if (!literal) return std::nullopt;
    const auto fieldType = managedTypeName(field.type, metadata);
    if (fieldType != dataType && defaultValueCode(dataType) != Il2CppTypeCode::Object && defaultValueCode(fieldType) == Il2CppTypeCode::Object) {
        literal = "unchecked((" + fieldType + ")(" + *literal + "))";
    }
    return literal;
}

std::optional<std::string> enumMemberLiteral(
    const FieldModel& field,
    std::string_view underlyingType,
    const MetadataModel& metadata) {
    if (field.defaultValueIndex < 0 ||
        static_cast<size_t>(field.defaultValueIndex) >= metadata.fieldDefaultValues.size()) return std::nullopt;
    size_t width = 0;
    if (underlyingType == "byte" || underlyingType == "sbyte") width = 1;
    else if (underlyingType == "short" || underlyingType == "ushort") width = 2;
    else if (underlyingType == "int" || underlyingType == "uint") width = 4;
    else if (underlyingType == "long" || underlyingType == "ulong") width = 8;
    if (width == 0) return std::nullopt;
    const auto& value = metadata.fieldDefaultValues[static_cast<size_t>(field.defaultValueIndex)];
    const auto raw = defaultValueWord(metadata, value.dataIndex, width);
    if (!raw) return std::nullopt;
    return "unchecked((" + std::string(underlyingType) + ")0x" + hexAddress(*raw) + "UL)";
}

std::optional<std::string> parameterDefaultValue(const ParameterModel& parameter, const MetadataModel& metadata) {
    if (parameter.defaultValueIndex < 0 || static_cast<size_t>(parameter.defaultValueIndex) >= metadata.parameterDefaultValues.size()) {
        return std::nullopt;
    }
    const auto& value = metadata.parameterDefaultValues[static_cast<size_t>(parameter.defaultValueIndex)];
    auto code = Il2CppTypeCode::Object;
    if (value.typeIndex >= 0 && static_cast<size_t>(value.typeIndex) < metadata.typeReferences.size()) {
        code = static_cast<Il2CppTypeCode>(metadata.typeReferences[static_cast<size_t>(value.typeIndex)].code);
    }
    const auto typeName = value.typeIndex >= 0 && static_cast<size_t>(value.typeIndex) < metadata.typeReferences.size()
        ? TypeSystem::resolve(static_cast<size_t>(value.typeIndex), metadata)
        : managedTypeName(parameter.type, metadata);
    auto literal = defaultValueLiteral(typeName, code, value.dataIndex, metadata);
    if (!literal) return std::nullopt;
    const auto parameterType = managedTypeName(parameter.type, metadata);
    if (parameterType != typeName && defaultValueCode(typeName) != Il2CppTypeCode::Object &&
        defaultValueCode(parameterType) == Il2CppTypeCode::Object) {
        literal = "unchecked((" + parameterType + ")(" + *literal + "))";
    }
    return literal;
}

struct FieldDeclarationInfo {
    std::string modifiers;
    bool isStatic = false;
    bool literal = false;
    bool hasDefault = false;
    bool partialMetadata = false;
};

FieldDeclarationInfo fieldDeclaration(const FieldModel& field) {
    FieldDeclarationInfo result;
    const auto flags = nativeFlags(field);
    if (!flags) {
        result.isStatic = field.isStatic;
        result.modifiers = "public " + std::string(field.isStatic ? "static " : "");
        result.partialMetadata = true;
        return result;
    }
    result.modifiers = memberVisibility(*flags) + " ";
    result.isStatic = (*flags & 0x10) != 0 || field.isStatic;
    result.literal = (*flags & 0x40) != 0;
    result.hasDefault = (*flags & 0x80) != 0;
    if (result.literal) {
        result.modifiers += "const ";
    } else {
        if (result.isStatic) result.modifiers += "static ";
        if ((*flags & 0x20) != 0) result.modifiers += "readonly ";
    }
    return result;
}

std::string stableMethodSuffix(const MethodEntry& entry) {
    if (entry.function->address != 0) return "_0x" + hexAddress(entry.function->address);
    if (entry.token != 0) {
        std::ostringstream suffix;
        suffix << "_Token_" << std::hex << std::uppercase << entry.token;
        return suffix.str();
    }
    if (entry.definitionIndex >= 0) return "_Method_" + std::to_string(entry.definitionIndex);
    return '_' + stableHash(entry.function->name + '|' + entry.metadataName);
}

std::string parameterDeclaration(
    const ParameterModel& parameter,
    size_t index,
    const MetadataModel& metadata,
    std::string_view imageName,
    bool includeDefault,
    const EmittedNamePlan* emittedNames) {
    std::string direction;
    std::string type = trim(parameter.type);
    for (const std::string_view candidate : {std::string_view("ref "), std::string_view("out "), std::string_view("in ")}) {
        if (type.starts_with(candidate)) {
            direction = std::string(candidate);
            type = trim(type.substr(candidate.size()));
            break;
        }
    }
    std::string resolved = managedTypeName(type.empty() ? "object" : type, metadata,
                                           imageName, emittedNames);
    if (direction.empty() && type.starts_with("type[") && type.back() == ']') {
        const auto digits = std::string_view(type).substr(5, type.size() - 6);
        if (!digits.empty() && std::all_of(digits.begin(), digits.end(), [](unsigned char c) {
            return c >= '0' && c <= '9';
        })) {
            size_t referenceIndex = 0;
            const auto conversion = std::from_chars(digits.data(), digits.data() + digits.size(), referenceIndex);
            if (conversion.ec == std::errc{} && conversion.ptr == digits.data() + digits.size() &&
                referenceIndex < metadata.typeReferences.size()) {
                const auto attributes = metadata.typeReferences[referenceIndex].attrs;
                const bool input = (attributes & 0x1) != 0;
                const bool output = (attributes & 0x2) != 0;
                if (output && !input) direction = "out ";
                if (input && !output) direction = "in ";
                if (input && output) direction = "ref ";
            }
        }
    }
    if (direction.empty() && !resolved.empty() && resolved.back() == '&') {
        resolved.pop_back();
        direction = "ref ";
    }
    if (resolved.starts_with("ref ") || resolved.starts_with("out ") || resolved.starts_with("in ")) {
        const auto separator = resolved.find(' ');
        if (direction.empty()) direction = resolved.substr(0, separator + 1);
        resolved = resolved.substr(separator + 1);
    }
    auto declaration = direction + resolved + " " + managedIdentifier(parameter.name, "param" + std::to_string(index));
    if (includeDefault && direction.empty()) {
        if (const auto defaultValue = parameterDefaultValue(parameter, metadata)) declaration += " = " + *defaultValue;
    }
    return declaration;
}

bool hasUnresolvedParameterDefaults(const MethodModel& method, const MetadataModel& metadata) {
    return std::any_of(method.parameters.begin(), method.parameters.end(), [&](const ParameterModel& parameter) {
        return parameter.defaultValueIndex >= 0 && !parameterDefaultValue(parameter, metadata).has_value();
    });
}

std::string parameterList(const MethodModel& method, const MetadataModel& metadata,
                          bool includeDefaults = true, const EmittedNamePlan* emittedNames = nullptr) {
    std::vector<std::string> declarations;
    declarations.reserve(method.parameters.size());
    for (size_t index = 0; index < method.parameters.size(); ++index) {
        declarations.push_back(parameterDeclaration(method.parameters[index], index, metadata,
                                                    method.imageName, includeDefaults, emittedNames));
    }
    if (includeDefaults) {
        // Native metadata can mark a parameter optional before a later required
        // parameter. C# cannot spell that order, so omit only the unusable
        // default syntax while preserving the parameters and their order.
        bool requiredAfter = false;
        for (size_t index = declarations.size(); index-- > 0;) {
            const auto defaultAt = declarations[index].find(" = ");
            if (defaultAt == std::string::npos) requiredAfter = true;
            else if (requiredAfter) declarations[index].erase(defaultAt);
        }
    }
    std::string result = "(";
    for (size_t index = 0; index < declarations.size(); ++index) {
        if (index != 0) result += ", ";
        result += declarations[index];
    }
    return result + ")";
}

std::string parameterSignatureKey(const MethodModel* method, const MetadataModel& metadata) {
    if (!method) return "()";
    auto normalized = *method;
    for (size_t index = 0; index < normalized.parameters.size(); ++index) {
        normalized.parameters[index].name = "param" + std::to_string(index);
    }
    std::string genericArity;
    if (method->genericContainerIndex >= 0 &&
        static_cast<size_t>(method->genericContainerIndex) < metadata.genericContainers.size()) {
        genericArity = "<" + std::to_string(metadata.genericContainers[static_cast<size_t>(method->genericContainerIndex)].typeArgumentCount) + ">";
    }
    // Default values and parameter names do not distinguish C# overloads.
    return genericArity + parameterList(normalized, metadata, false);
}

std::string uniqueMethodName(
    const MethodEntry& entry,
    const std::string& typeName,
    const std::string& signatureKey,
    const std::set<std::string>& fieldNames,
    std::set<std::string>& usedSignatures) {
    const auto base = entry.baseName;
    const auto available = [&](const std::string& candidate) {
        return candidate != typeName && !fieldNames.contains(candidate) &&
               !usedSignatures.contains(candidate + signatureKey);
    };
    auto candidate = base;
    if (!available(candidate)) candidate += stableMethodSuffix(entry);
    const auto stem = candidate;
    for (size_t suffix = 2; !available(candidate); ++suffix) {
        candidate = stem + '_' + std::to_string(suffix);
    }
    usedSignatures.insert(candidate + signatureKey);
    return candidate;
}

struct MethodDeclarationInfo {
    std::string signature;
    bool bodyAllowed = true;
    bool partialMetadata = false;
    bool signatureSupported = true;
    std::string signatureReason;
    std::string visibilityReason;
};

MethodDeclarationInfo methodDeclaration(
    const MethodEntry& entry,
    const std::string& name,
    const std::string& typeName,
    const std::string& parameters,
    const MetadataModel& metadata,
    const TypeDeclarationInfo& declaringType,
    const TypeAccessibilityIndex* accessibilityIndex,
    const EmittedNamePlan* emittedNames) {
    MethodDeclarationInfo result;
    if (!entry.method) {
        result.signature = "public static void " + name + parameters;
        result.partialMetadata = true;
        return result;
    }
    bool exposesInternalType = false;
    for (const auto& parameter : entry.method->parameters) {
        const auto resolved = managedTypeName(parameter.type, metadata, entry.method->imageName, emittedNames);
        if (hasUnresolvedGenericArity(parameter.type, metadata) ||
            (accessibilityIndex && accessibilityIndex->hasUnboundGenericName(
                parameter.type, entry.method->imageName)) || !supportedCSharpType(resolved)) {
            result.signatureSupported = false;
            result.signatureReason = "parameter type '" + resolved + "' has unresolved C# type syntax";
            return result;
        }
        if (accessibilityIndex && !parameter.type.starts_with("type[") &&
            accessibilityIndex->hasAmbiguousType(resolved, entry.method->imageName)) {
            result.signatureSupported = false;
            result.signatureReason = "parameter type '" + resolved + "' has ambiguous metadata identity";
            return result;
        }
        exposesInternalType = exposesInternalType ||
            (accessibilityIndex && (accessibilityIndex->hasInternalTypeReference(parameter.type, metadata) ||
                                    accessibilityIndex->hasInternalType(resolved, entry.method->imageName))) ||
            (emittedNames && (emittedNames->isInternal(parameter.type, entry.method->imageName, metadata) ||
                              emittedNames->isInternalEmitted(resolved, entry.method->imageName)));
    }
    if (entry.method->name != ".ctor" && entry.method->name != ".cctor") {
        const auto resolved = managedReturnType(*entry.method, metadata, emittedNames);
        if (hasUnresolvedGenericArity(entry.method->returnType, metadata) ||
            (accessibilityIndex && accessibilityIndex->hasUnboundGenericName(
                entry.method->returnType, entry.method->imageName)) ||
            !supportedCSharpType(resolved)) {
            result.signatureSupported = false;
            result.signatureReason = "return type '" + resolved + "' has unresolved C# type syntax";
            return result;
        }
        if (accessibilityIndex && !entry.method->returnType.starts_with("type[") &&
            accessibilityIndex->hasAmbiguousType(resolved, entry.method->imageName)) {
            result.signatureSupported = false;
            result.signatureReason = "return type '" + resolved + "' has ambiguous metadata identity";
            return result;
        }
        exposesInternalType = exposesInternalType ||
            (accessibilityIndex && (accessibilityIndex->hasInternalTypeReference(entry.method->returnType, metadata) ||
                                    accessibilityIndex->hasInternalType(resolved, entry.method->imageName))) ||
            (emittedNames && (emittedNames->isInternal(entry.method->returnType,
                                                       entry.method->imageName, metadata) ||
                              emittedNames->isInternalEmitted(resolved, entry.method->imageName)));
    }
    exposesInternalType = exposesInternalType && declaringType.visibility == "public";
    const auto generic = genericDeclaration(metadata, entry.method->genericContainerIndex, true, false);
    result.partialMetadata = generic.partialMetadata || hasUnresolvedParameterDefaults(*entry.method, metadata);
    const auto flags = nativeFlags(*entry.method);
    if (entry.method->name == ".cctor") {
        result.signature = "static " + typeName + parameters;
        return result;
    }
    if (entry.method->name == ".ctor") {
        const auto nativeVisibility = flags ? memberVisibility(*flags) : std::string("public");
        const auto visibility = staticClassVisibility(
            compilerVisibility(nativeVisibility, exposesInternalType), declaringType);
        if (visibility != nativeVisibility) {
            result.partialMetadata = true;
            result.visibilityReason = declaringType.modifiers == "static " &&
                nativeVisibility.find("protected") != std::string::npos
                    ? "protected constructor visibility is invalid in a static class"
                    : "C# visibility narrowed because a parameter type is internal";
        }
        result.signature = visibility + " " + typeName + parameters;
        result.partialMetadata = result.partialMetadata || !flags.has_value() || !generic.parameters.empty();
        return result;
    }

    if (declaringType.kind == ManagedTypeKind::Interface) {
        if (exposesInternalType) {
            result.signatureSupported = false;
            result.signatureReason = "public interface method exposes an internal type";
            return result;
        }
        result.signature = managedReturnType(*entry.method, metadata) + " " + name +
            generic.parameters + parameters + generic.constraints;
        result.bodyAllowed = false;
        result.partialMetadata = result.partialMetadata || !flags.has_value();
        return result;
    }

    const auto nativeVisibility = flags ? memberVisibility(*flags) : std::string("public");
    const auto visibility = staticClassVisibility(
        compilerVisibility(nativeVisibility, exposesInternalType), declaringType);
    if (visibility != nativeVisibility) {
        result.partialMetadata = true;
        result.visibilityReason = declaringType.modifiers == "static " &&
            nativeVisibility.find("protected") != std::string::npos
                ? "protected member visibility is invalid in a static class"
                : "C# visibility narrowed because the signature exposes an internal type";
    }
    std::string modifiers = visibility + " ";
    const bool isStatic = flags ? (*flags & 0x10) != 0 : entry.method->isStatic;
    if (isStatic) modifiers += "static ";
    if (flags) {
        const bool final = (*flags & 0x20) != 0;
        const bool virtualMethod = (*flags & 0x40) != 0;
        const bool newSlot = (*flags & 0x100) != 0;
        const bool abstract = (*flags & 0x400) != 0;
        const bool privateVirtual = (*flags & 0x7) != 0x6 && virtualMethod;
        const bool canBeVirtual = declaringType.kind == ManagedTypeKind::Class &&
            !declaringType.sealedType && declaringType.modifiers != "static " &&
            !isStatic && !privateVirtual;
        if (privateVirtual) result.partialMetadata = true;
        if (abstract && canBeVirtual && declaringType.modifiers.find("abstract ") != std::string::npos) {
            result.bodyAllowed = false;
            modifiers += "abstract ";
        } else if (virtualMethod && canBeVirtual && !abstract && !final) {
            modifiers += "virtual ";
        }
        // The generated project does not emit base-class declarations. An
        // `override` (or `sealed override`) would therefore claim a base member
        // which is absent from the generated C# type graph. Preserve the method
        // body and mark the relationship as incomplete instead.
        if (virtualMethod && (!newSlot || !canBeVirtual || final)) result.partialMetadata = true;
        if (abstract && result.bodyAllowed) result.partialMetadata = true;
        if (final && (abstract || !virtualMethod || newSlot)) result.partialMetadata = true;
        if (isStatic && (virtualMethod || abstract)) result.partialMetadata = true;
    } else {
        result.partialMetadata = true;
    }
    result.signature = modifiers + qualifyShadowedType(
        managedReturnType(*entry.method, metadata, emittedNames),
        typeName, entry.method->imageName, metadata) + " " + name +
        generic.parameters + parameters + generic.constraints;
    return result;
}

std::string singleLine(std::string value) {
    std::replace(value.begin(), value.end(), '\r', ' ');
    std::replace(value.begin(), value.end(), '\n', ' ');
    return value;
}

std::string stringLiteralContent(const std::string& value) {
    std::string result;
    for (const char c : value) {
        if (c == '\\' || c == '\"') result.push_back('\\');
        result.push_back(c);
    }
    return result;
}

using AttributeBlobSizes = std::unordered_map<std::string, std::unordered_map<uint32_t, size_t>>;

AttributeBlobSizes indexAttributeBlobs(const MetadataModel& metadata) {
    AttributeBlobSizes result;
    for (const auto& image : metadata.images) {
        if (image.customAttributeStart < 0 || image.customAttributeCount == 0) continue;
        const size_t begin = static_cast<size_t>(image.customAttributeStart);
        const size_t count = image.customAttributeCount;
        if (begin > metadata.attributeDataRanges.size() ||
            count > metadata.attributeDataRanges.size() - begin) continue;
        auto& sizes = result[image.name];
        for (size_t index = begin; index < begin + count; ++index) {
            if (index + 1 >= metadata.attributeDataRanges.size()) break;
            const auto& range = metadata.attributeDataRanges[index];
            const size_t end = metadata.attributeDataRanges[index + 1].start;
            if (range.token == 0 || range.start > end || end > metadata.attributeData.size()) continue;
            sizes.try_emplace(range.token, end - range.start);
        }
    }
    return result;
}

std::optional<size_t> attributeBlobSize(
    const AttributeBlobSizes& blobs,
    const std::string& imageName,
    uint32_t token) {
    if (token == 0) return std::nullopt;
    const auto image = blobs.find(imageName);
    if (image == blobs.end()) return std::nullopt;
    const auto entry = image->second.find(token);
    return entry == image->second.end() ? std::nullopt : std::optional<size_t>(entry->second);
}

const MethodModel* accessorMethod(const TypeModel& type, int32_t index, const std::string& expectedName) {
    if (index < 0) return nullptr;
    if (static_cast<size_t>(index) < type.methods.size() &&
        type.methods[static_cast<size_t>(index)].name == expectedName) {
        return &type.methods[static_cast<size_t>(index)];
    }
    const auto method = std::find_if(type.methods.begin(), type.methods.end(), [index](const MethodModel& candidate) {
        return candidate.definitionIndex == index;
    });
    return method == type.methods.end() || method->name != expectedName ? nullptr : &*method;
}

bool appendProperty(
    std::ostringstream& output,
    const TypeModel& type,
    const PropertyModel& property,
    const MetadataModel& metadata,
    const TypeDeclarationInfo& declaringType,
    const TypeAccessibilityIndex* accessibilityIndex,
    const EmittedNamePlan* emittedNames,
    const std::string& name,
    const std::string& indentation,
    std::set<int>& reservedMethods) {
    const MethodModel* getter = accessorMethod(type, property.get, "get_" + property.name);
    const MethodModel* setter = accessorMethod(type, property.set, "set_" + property.name);
    if (!getter && !setter) return false;
    if (getter && !getter->parameters.empty()) return false; // Indexers need parameterized C# syntax.
    if (setter && setter->parameters.size() != 1) return false;
    const std::string rawPropertyType = getter
        ? managedReturnType(*getter, metadata, emittedNames)
        : managedTypeName(setter->parameters.front().type, metadata, type.imageName, emittedNames);
    const std::string propertyType = qualifyShadowedType(
        rawPropertyType, type.name, type.imageName, metadata);
    if (propertyType.empty() || propertyType == "void" || !supportedCSharpType(propertyType) ||
        (getter && (hasUnresolvedGenericArity(getter->returnType, metadata) ||
                    (accessibilityIndex && accessibilityIndex->hasUnboundGenericName(
                        getter->returnType, type.imageName)))) ||
        (setter && (hasUnresolvedGenericArity(setter->parameters.front().type, metadata) ||
                    (accessibilityIndex && accessibilityIndex->hasUnboundGenericName(
                        setter->parameters.front().type, type.imageName))))) return false;
    if (accessibilityIndex &&
        ((getter && !getter->returnType.starts_with("type[") &&
          accessibilityIndex->hasAmbiguousType(propertyType, type.imageName)) ||
         (setter && !setter->parameters.front().type.starts_with("type[") &&
          accessibilityIndex->hasAmbiguousType(propertyType, type.imageName)))) return false;
    if (getter && setter && qualifyShadowedType(
            managedTypeName(setter->parameters.front().type, metadata, type.imageName, emittedNames),
            type.name, type.imageName, metadata) != propertyType) return false;
    if (getter && setter && getter->isStatic != setter->isStatic) return false;
    const MethodModel* principal = getter ? getter : setter;
    const bool internalTypeExposed = accessibilityIndex && declaringType.visibility == "public" &&
        (accessibilityIndex->hasInternalType(propertyType, type.imageName) ||
         (getter && accessibilityIndex->hasInternalTypeReference(getter->returnType, metadata)) ||
         (setter && accessibilityIndex->hasInternalTypeReference(setter->parameters.front().type, metadata)) ||
         (emittedNames && (emittedNames->isInternalEmitted(propertyType, type.imageName) ||
                           (getter && emittedNames->isInternal(getter->returnType, type.imageName, metadata)) ||
                           (setter && emittedNames->isInternal(setter->parameters.front().type,
                                                                type.imageName, metadata)))));
    if (internalTypeExposed && declaringType.kind == ManagedTypeKind::Interface) return false;
    if (declaringType.kind != ManagedTypeKind::Interface) {
        const auto originalVisibility = memberVisibility(principal->flags);
        const auto visibility = staticClassVisibility(
            compilerVisibility(originalVisibility, internalTypeExposed), declaringType);
        if (visibility != originalVisibility) {
            output << indentation << "// Partial recovery: C# visibility narrowed from "
                   << originalVisibility << " to " << visibility
                   << (declaringType.modifiers == "static " &&
                       originalVisibility.find("protected") != std::string::npos
                           ? " because protected members are invalid in a static class.\n"
                           : " because the property type is internal.\n");
        }
        output << indentation << visibility << ' ';
        if (principal->isStatic || declaringType.modifiers == "static ") output << "static ";
    }
    output << propertyType << ' ' << name << "\n" << indentation << "{\n";
    if (getter) {
        output << indentation << "    get";
        if (declaringType.kind == ManagedTypeKind::Interface) output << ";\n";
        else output << " => throw new global::System.NotSupportedException(\"Recovered property accessor body is unavailable.\");\n";
        reservedMethods.insert(getter->definitionIndex);
    }
    if (setter) {
        output << indentation << "    set";
        if (declaringType.kind == ManagedTypeKind::Interface) output << ";\n";
        else output << " => throw new global::System.NotSupportedException(\"Recovered property accessor body is unavailable.\");\n";
        reservedMethods.insert(setter->definitionIndex);
    }
    output << indentation << "}\n";
    return true;
}

bool appendEvent(
    std::ostringstream& output,
    const TypeModel& type,
    const EventModel& event,
    const MetadataModel& metadata,
    const TypeDeclarationInfo& declaringType,
    const TypeAccessibilityIndex* accessibilityIndex,
    const EmittedNamePlan* emittedNames,
    const std::string& name,
    const std::string& indentation,
    std::set<int>& reservedMethods) {
    if (event.typeIndex < 0 || static_cast<size_t>(event.typeIndex) >= metadata.typeReferences.size()) return false;
    const auto& reference = metadata.typeReferences[static_cast<size_t>(event.typeIndex)];
    const auto rawEventType = "type[" + std::to_string(event.typeIndex) + "]";
    const std::string eventType = managedTypeName(rawEventType, metadata, type.imageName, emittedNames);
    // Only the framework delegate families are known to be legal C# event
    // types here. Other metadata references need a proven delegate definition.
    const bool frameworkDelegate = reference.definitionIndex < 0 &&
        (eventType == "System.Action" || eventType == "System.EventHandler" ||
         eventType.starts_with("System.Action<") || eventType.starts_with("System.EventHandler<"));
    if (!frameworkDelegate || hasUnresolvedGenericArity(
        "type[" + std::to_string(event.typeIndex) + "]", metadata)) return false;
    const MethodModel* add = accessorMethod(type, event.add, "add_" + event.name);
    const MethodModel* remove = accessorMethod(type, event.remove, "remove_" + event.name);
    if (!add || !remove || add->parameters.size() != 1 || remove->parameters.size() != 1 ||
        add->isStatic != remove->isStatic) return false;
    const bool internalTypeExposed = accessibilityIndex && declaringType.visibility == "public" &&
        accessibilityIndex->hasInternalType(eventType, type.imageName);
    if (internalTypeExposed && declaringType.kind == ManagedTypeKind::Interface) return false;
    if (declaringType.kind != ManagedTypeKind::Interface) {
        const auto originalVisibility = memberVisibility(add->flags);
        const auto visibility = staticClassVisibility(
            compilerVisibility(originalVisibility, internalTypeExposed), declaringType);
        if (visibility != originalVisibility) {
            output << indentation << "// Partial recovery: C# visibility narrowed from "
                   << originalVisibility << " to " << visibility
                   << (declaringType.modifiers == "static " &&
                       originalVisibility.find("protected") != std::string::npos
                           ? " because protected members are invalid in a static class.\n"
                           : " because the event type is internal.\n");
        }
        output << indentation << visibility << ' ';
        if (add->isStatic || declaringType.modifiers == "static ") output << "static ";
    }
    if (declaringType.kind == ManagedTypeKind::Interface) {
        output << "event " << eventType << ' ' << name << ";\n";
    } else {
        output << "event " << eventType << ' ' << name << "\n" << indentation << "{\n";
        output << indentation << "    add { throw new global::System.NotSupportedException(\"Recovered event accessor body is unavailable.\"); }\n";
        output << indentation << "    remove { throw new global::System.NotSupportedException(\"Recovered event accessor body is unavailable.\"); }\n";
        output << indentation << "}\n";
    }
    reservedMethods.insert(add->definitionIndex);
    reservedMethods.insert(remove->definitionIndex);
    return true;
}

ProjectMethodEmission appendMethod(
    std::ostringstream& output,
    const MethodEntry& entry,
    const std::string& name,
    const std::string& typeName,
    const std::string& parameters,
    const MetadataModel& metadata,
    const TypeModel* owner,
    const TypeDeclarationInfo& declaringType,
    const TypeAccessibilityIndex* accessibilityIndex,
    const EmittedNamePlan* emittedNames,
    const MethodBodyAdapter& bodyAdapter,
    std::map<std::string, std::string>& emittedSupport,
    const std::string& indentation) {
    const auto declaration = methodDeclaration(entry, name, typeName, parameters, metadata,
                                               declaringType, accessibilityIndex, emittedNames);
    ProjectMethodEmission emission;
    emission.address = entry.function->address;
    emission.name = name;
    emission.imageName = methodImageName(entry, owner);
    emission.declarationPartial = declaration.partialMetadata;
    if (!declaration.visibilityReason.empty()) {
        output << indentation << "// Partial recovery: " << declaration.visibilityReason << ".\n";
    }
    if (!declaration.signatureSupported) {
        output << indentation << "// Partial recovery: " << singleLine(declaration.signatureReason)
               << "; method at 0x" << hexAddress(entry.function->address) << " was not emitted.\n";
        emission.status = ProjectMethodBodyStatus::Omitted;
        emission.reason = declaration.signatureReason;
        emission.declarationPartial = true;
        return emission;
    }
    if (declaration.partialMetadata) {
        output << indentation << "// Partial recovery: native method flags are unavailable or unsupported.\n";
    }
    if (!declaration.bodyAllowed) {
        output << indentation << declaration.signature << ";\n";
        emission.status = ProjectMethodBodyStatus::DeclarationOnly;
        emission.reason = "managed declaration has no body";
        return emission;
    }
    const auto emittedReturnType = entry.method
        ? qualifyShadowedType(managedReturnType(*entry.method, metadata, emittedNames),
                              typeName, entry.method->imageName, metadata)
        : std::string{};
    auto body = bodyAdapter.emit(*entry.function, entry.method, metadata, owner, typeName,
                                 emittedReturnType);
    for (const auto& fragment : body.supportFragments) {
        const auto existing = emittedSupport.find(fragment.key);
        if (existing != emittedSupport.end() && existing->second != fragment.source) {
            body = unsupportedBody("conflicting C# support helper for '" + fragment.key + "'");
            break;
        }
    }
    emission.reason = body.diagnostic;
    emission.status = body.status == MethodBodyStatus::Supported ? ProjectMethodBodyStatus::Supported :
        body.status == MethodBodyStatus::Partial ? ProjectMethodBodyStatus::Partial :
        ProjectMethodBodyStatus::Unsupported;
    if (body.source.empty()) emission.status = ProjectMethodBodyStatus::Unsupported;
    for (const auto& fragment : body.supportFragments) {
        if (fragment.source.empty()) continue;
        if (emittedSupport.emplace(fragment.key, fragment.source).second) {
            appendIndented(output, fragment.source, indentation);
            output << '\n';
        }
    }
    output << indentation << declaration.signature << '\n';
    output << indentation << "{\n";
    if (body.status != MethodBodyStatus::Supported) {
        output << indentation << "    // Partial recovery: " << singleLine(body.diagnostic) << '\n';
    }
    if (body.status == MethodBodyStatus::Unsupported || body.source.empty()) {
        output << indentation << "    throw new System.NotSupportedException(\"Partial recovery of method 0x"
               << hexAddress(entry.function->address) << ": "
               << stringLiteralContent(singleLine(body.diagnostic)) << ".\");\n";
    } else {
        appendIndented(output, body.source, indentation + "    ");
    }
    output << indentation << "}\n";
    return emission;
}

struct ProjectReference {
    std::string include;
    std::string hintPath;
};

ProjectReference projectReference(const std::string& value) {
    const auto separator = value.find_last_of("/\\");
    const auto fileName = separator == std::string::npos ? value : value.substr(separator + 1);
    const auto extension = fileName.size() >= 4 ? lowerAscii(fileName.substr(fileName.size() - 4)) : std::string{};
    const bool isAssemblyFile = extension == ".dll" || extension == ".exe";
    auto include = isAssemblyFile ? fileName.substr(0, fileName.size() - 4) : fileName;
    if (include.empty()) include = "Reference";
    const bool hasHintPath = separator != std::string::npos || isAssemblyFile;
    return {include, hasHintPath ? value : std::string{}};
}

std::string projectFile(
    const ProjectWriterOptions& options,
    const std::vector<std::filesystem::path>& sourceFiles,
    const std::filesystem::path& outputDirectory) {
    const auto projectName = safeName(options.projectName, "Il2CppRecovered");
    const auto targetFramework = options.targetFramework.empty() ? "netstandard2.1" : options.targetFramework;
    std::ostringstream output;
    output << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    output << "<Project Sdk=\"Microsoft.NET.Sdk\">\n";
    output << "  <PropertyGroup>\n";
    output << "    <TargetFramework>" << xmlEscape(targetFramework) << "</TargetFramework>\n";
    output << "    <AssemblyName>" << xmlEscape(projectName) << "</AssemblyName>\n";
    output << "    <RootNamespace>" << xmlEscape(projectName) << "</RootNamespace>\n";
    output << "    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>\n";
    output << "    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n";
    output << "    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n";
    output << "    <LangVersion>latest</LangVersion>\n";
    output << "  </PropertyGroup>\n";
    if (!sourceFiles.empty()) {
        output << "  <ItemGroup>\n";
        for (const auto& file : sourceFiles) {
            const auto relative = std::filesystem::relative(file, outputDirectory).generic_string();
            output << "    <Compile Include=\"" << xmlEscape(relative) << "\" />\n";
        }
        output << "  </ItemGroup>\n";
    }
    std::vector<ProjectReference> references;
    for (const auto& value : options.assemblyReferences) {
        if (!value.empty()) references.push_back(projectReference(value));
    }
    std::sort(references.begin(), references.end(), [](const ProjectReference& left, const ProjectReference& right) {
        return std::tie(left.include, left.hintPath) < std::tie(right.include, right.hintPath);
    });
    references.erase(std::unique(references.begin(), references.end(), [](const ProjectReference& left, const ProjectReference& right) {
        return left.include == right.include && left.hintPath == right.hintPath;
    }), references.end());
    if (!references.empty()) {
        output << "  <ItemGroup>\n";
        for (const auto& reference : references) {
            if (reference.hintPath.empty()) {
                output << "    <Reference Include=\"" << xmlEscape(reference.include) << "\" />\n";
            } else {
                output << "    <Reference Include=\"" << xmlEscape(reference.include) << "\">\n";
                output << "      <HintPath>" << xmlEscape(reference.hintPath) << "</HintPath>\n";
                output << "    </Reference>\n";
            }
        }
        output << "  </ItemGroup>\n";
    }
    output << "</Project>\n";
    return output.str();
}

} // namespace

ProjectWriter::ProjectWriter(ProjectWriterOptions options) : options_(std::move(options)) {}

ProjectWriteReport ProjectWriter::write(
    const std::filesystem::path& outputDirectory,
    const MetadataModel& metadata,
    const std::vector<RecoveredFunction>& functions) const {
    if (outputDirectory.empty()) throw std::invalid_argument("Project output directory cannot be empty");
    std::filesystem::create_directories(outputDirectory);

    const MetadataIndex index(metadata);
    const auto attributeBlobs = indexAttributeBlobs(metadata);
    const std::set<std::string> includedImages(options_.includedImages.begin(), options_.includedImages.end());
    // netstandard2.1 supplies the core System types and compiler-required
    // attributes. Re-emitting old mscorlib declarations into that project
    // shadows those real framework types with incomplete metadata shells.
    const bool frameworkCoreTypes = options_.includeExternalDeclarations &&
        !includedImages.empty() && !includedImages.contains("mscorlib.dll") &&
        (options_.targetFramework.empty() || options_.targetFramework == "netstandard2.1");
    std::optional<TypeAccessibilityIndex> accessibilityIndex;
    if (options_.includeExternalDeclarations) accessibilityIndex.emplace(metadata, frameworkCoreTypes);
    std::vector<bool> includedTypes(metadata.types.size(), true);
    if (!includedImages.empty() && !options_.includeExternalDeclarations) {
        for (size_t index = 0; index < metadata.types.size(); ++index) {
            const auto& type = metadata.types[index];
            bool hasImageEvidence = !type.imageName.empty();
            bool included = hasImageEvidence && includedImages.contains(type.imageName);
            if (!hasImageEvidence) {
                for (const auto& method : type.methods) {
                    if (method.imageName.empty()) continue;
                    hasImageEvidence = true;
                    if (includedImages.contains(method.imageName)) included = true;
                }
            }
            includedTypes[index] = included || !hasImageEvidence;
        }
    } else if (frameworkCoreTypes) {
        for (size_t index = 0; index < metadata.types.size(); ++index) {
            if (metadata.types[index].imageName == "mscorlib.dll") includedTypes[index] = false;
        }
    }

    // A single metadata corpus can contain assemblies declaring different
    // types with the same namespace and name. Keep their members separate;
    // C# project names are disambiguated at emission time.
    std::map<size_t, TypeGroup> groups;
    for (size_t index = 0; index < metadata.types.size(); ++index) {
        if (!includedTypes[index]) continue;
        const auto& type = metadata.types[index];
        groups[index].metadataTypes.push_back(&type);
    }
    std::vector<ProjectMethodEmission> filteredBodies;
    for (const auto& function : functions) {
        const auto location = index.find(function);
        if (options_.includeExternalDeclarations && !includedImages.empty()) {
            const MethodModel* matchedMethod = nullptr;
            const TypeModel* matchedType = nullptr;
            if (location) {
                matchedType = &metadata.types[location->first];
                matchedMethod = &matchedType->methods[location->second];
            }
            const std::string image = matchedMethod && !matchedMethod->imageName.empty()
                ? matchedMethod->imageName
                : matchedType ? matchedType->imageName : std::string{};
            if (!includedImages.contains(image)) {
                filteredBodies.push_back({function.address, function.name, ProjectMethodBodyStatus::Omitted,
                    frameworkCoreTypes && image == "mscorlib.dll"
                        ? "native body filtered; core type supplied by target framework"
                        : "native body filtered; metadata declaration retained when available",
                    true, image});
                continue;
            }
        } else if (location && !includedTypes[location->first]) {
            continue;
        }
        size_t key = metadata.types.size();
        const MethodModel* method = nullptr;
        if (location) {
            const auto& type = metadata.types[location->first];
            key = location->first;
            method = &type.methods[location->second];
        }
        MethodEntry entry;
        entry.function = &function;
        entry.method = method;
        entry.metadataName = method ? method->name : std::string{};
        entry.baseName = methodBaseName(function, method);
        entry.token = method ? method->token : 0;
        entry.definitionIndex = method ? method->definitionIndex : -1;
        groups[key].methods.push_back(std::move(entry));
    }
    const EmittedNamePlan emittedNames(metadata, groups);

    std::vector<std::filesystem::path> sourceFiles;
    const auto runtimePath = outputDirectory / "RuntimeSupport.cs";
    sourceFiles.push_back(runtimePath);
    writeFile(runtimePath, generateRuntimeSupport(functions.empty() ? Architecture::X64 : functions.front().architecture));

    // In full-declarations mode, an emitted managed call needs an exact,
    // callable member in this project's output. Until a member has been
    // validated against its final declaration and body, the surface is empty
    // and the native call remains partial instead of binding a guessed name.
    ManagedEmissionSurface emissionSurface;
    emissionSurface.source = &metadata;
    const MethodBodyAdapter bodyAdapter(metadata, options_.genericMethodInfoEvidence.get(),
        options_.includeExternalDeclarations ? &emissionSurface : nullptr);
    ProjectWriteReport report;
    const auto record = [&report](ProjectMethodEmission emission) {
        switch (emission.status) {
        case ProjectMethodBodyStatus::Supported: ++report.supported; break;
        case ProjectMethodBodyStatus::Partial: ++report.partial; break;
        case ProjectMethodBodyStatus::Unsupported: ++report.unsupported; break;
        case ProjectMethodBodyStatus::DeclarationOnly: ++report.declarationOnly; break;
        case ProjectMethodBodyStatus::Omitted: ++report.omitted; break;
        }
        report.methods.push_back(std::move(emission));
    };
    for (auto& filtered : filteredBodies) record(std::move(filtered));
    std::set<std::string> usedFilePaths;
    for (auto& [key, group] : groups) {
        const bool unmatched = key == metadata.types.size();
        const std::string sourceNamespace = unmatched ? "Il2CppRecovered" : metadata.types[key].nameSpace;
        auto& methods = group.methods;
        std::sort(methods.begin(), methods.end(), [](const MethodEntry& left, const MethodEntry& right) {
            return std::tie(left.metadataName, left.baseName, left.token, left.definitionIndex, left.function->address, left.function->name) <
                   std::tie(right.metadataName, right.baseName, right.token, right.definitionIndex, right.function->address, right.function->name);
        });

        const TypeModel* nestedParent = group.metadataTypes.size() == 1
            ? emittedNestedParent(metadata, *group.metadataTypes.front()) : nullptr;
        const auto& namePlan = emittedNames.at(key);
        const bool staticType = isStaticType(group, unmatched);
        auto declaringType = typeDeclaration(group.metadataTypes.empty() ? nullptr : group.metadataTypes.front(),
                                             staticType, nestedParent != nullptr);
        const auto& generic = namePlan.generic;
        declaringType.partialMetadata = declaringType.partialMetadata || generic.partialMetadata;
        if (declaringType.kind == ManagedTypeKind::Enum && !generic.parameters.empty()) {
            // CLR/C# enums cannot be generic. Conflicting metadata still has a
            // value-type shape, so represent it as a partial struct and keep
            // the members available for inspection.
            declaringType.kind = ManagedTypeKind::Struct;
            declaringType.modifiers.clear();
            declaringType.sealedType = true;
            declaringType.partialMetadata = true;
        }

        const auto parts = namespaceParts(sourceNamespace);
        const auto& nameSpace = namePlan.nameSpace;
        const auto& typeName = namePlan.typeName;
        std::filesystem::path directory = outputDirectory;
        for (const auto& part : parts) directory /= part;
        std::filesystem::create_directories(directory);
        const auto filePath = uniqueTypePath(directory, typeName, usedFilePaths);
        sourceFiles.push_back(filePath);

        if (declaringType.kind == ManagedTypeKind::Enum) {
            const auto valueField = std::find_if(group.metadataTypes.front()->fields.begin(), group.metadataTypes.front()->fields.end(), [](const FieldModel& field) {
                return field.name == "value__";
            });
            if (valueField == group.metadataTypes.front()->fields.end()) declaringType.partialMetadata = true;
        }

        std::ostringstream output;
        const std::string outerIndent = nameSpace.empty() ? "" : "    ";
        const std::string typeIndent = outerIndent + (nestedParent ? "    " : "");
        const std::string bodyIndent = typeIndent + "    ";
        if (!nameSpace.empty()) output << "namespace " << nameSpace << "\n{\n";
        if (nestedParent) {
            TypeGroup parentGroup;
            parentGroup.metadataTypes.push_back(nestedParent);
            const auto parentDeclaration = typeDeclaration(nestedParent, isStaticType(parentGroup, false), false);
            output << outerIndent << parentDeclaration.visibility << ' ' << parentDeclaration.modifiers
                   << "unsafe partial " << typeKindName(parentDeclaration.kind) << ' '
                   << safeName(nestedParent->name, "OuterType") << "\n"
                   << outerIndent << "{\n";
        }
        output << typeIndent << declaringType.visibility << " " << declaringType.modifiers;
        if (declaringType.kind != ManagedTypeKind::Enum) output << "unsafe partial ";
        output << typeKindName(declaringType.kind) << " " << typeName << generic.parameters;
        std::optional<std::string> enumUnderlyingType;
        if (declaringType.kind == ManagedTypeKind::Enum) {
            const auto valueField = std::find_if(group.metadataTypes.front()->fields.begin(), group.metadataTypes.front()->fields.end(), [](const FieldModel& field) {
                return field.name == "value__";
            });
            if (valueField != group.metadataTypes.front()->fields.end()) {
                const auto underlying = managedTypeName(valueField->type, metadata);
                static const std::set<std::string> integralTypes = {
                    "byte", "sbyte", "short", "ushort", "int", "uint", "long", "ulong"
                };
                if (integralTypes.contains(underlying)) {
                    output << " : " << underlying;
                    enumUnderlyingType = underlying;
                } else {
                    declaringType.partialMetadata = true;
                }
            }
        } else {
            output << generic.constraints;
        }
        output << "\n" << typeIndent << "{\n";
        if (declaringType.partialMetadata) {
            output << bodyIndent << "// Partial recovery: native type flags or layout are unavailable or unsupported.\n";
        }
        if (generic.omittedConstraint) {
            output << bodyIndent << "// Partial recovery: generic constraint omitted because its emitted type arity does not match metadata.\n";
        }
        if (!group.metadataTypes.empty()) {
            if (const auto blobSize = attributeBlobSize(attributeBlobs,
                                                        group.metadataTypes.front()->imageName,
                                                        group.metadataTypes.front()->token)) {
                output << bodyIndent << "// Custom attribute blob: " << *blobSize
                       << " bytes; constructor and arguments are not decoded.\n";
            }
        }

        std::set<std::string> fieldNames;
        bool first = true;
        for (const auto* type : group.metadataTypes) {
            for (const auto& field : type->fields) {
                if (!first) output << '\n';
                first = false;
                const auto fieldName = uniqueFieldName(field, typeName, fieldNames);
                const auto fieldType = qualifyShadowedType(
                    managedTypeName(field.type, metadata, type->imageName, &emittedNames),
                    typeName, type->imageName, metadata);
                if (accessibilityIndex && !field.type.starts_with("type[") &&
                    accessibilityIndex->hasAmbiguousType(fieldType, type->imageName)) {
                    output << bodyIndent << "// Partial recovery: field '" << fieldName
                           << "' has ambiguous metadata type identity; member was not emitted.\n";
                    continue;
                }
                if (hasUnresolvedGenericArity(field.type, metadata) ||
                    (accessibilityIndex && accessibilityIndex->hasUnboundGenericName(field.type, type->imageName)) ||
                    !supportedCSharpType(fieldType)) {
                    output << bodyIndent << "// Partial recovery: field '" << fieldName
                           << "' has unresolved C# type syntax; member was not emitted.\n";
                    continue;
                }
                if (const auto blobSize = attributeBlobSize(attributeBlobs, type->imageName, field.token)) {
                    output << bodyIndent << "// Custom attribute blob: " << *blobSize
                           << " bytes; constructor and arguments are not decoded.\n";
                }
                auto declaration = fieldDeclaration(field);
                if (accessibilityIndex && declaringType.visibility == "public" &&
                    (accessibilityIndex->hasInternalType(fieldType, type->imageName) ||
                     accessibilityIndex->hasInternalTypeReference(field.type, metadata) ||
                     emittedNames.isInternal(field.type, type->imageName, metadata) ||
                     emittedNames.isInternalEmitted(fieldType, type->imageName))) {
                    const auto originalVisibility = memberVisibility(field.flags);
                    const auto narrowed = compilerVisibility(originalVisibility, true);
                    const auto prefix = originalVisibility + " ";
                    if (narrowed != originalVisibility && declaration.modifiers.starts_with(prefix)) {
                        declaration.modifiers.replace(0, prefix.size(), narrowed + " ");
                        output << bodyIndent << "// Partial recovery: C# visibility narrowed from "
                               << originalVisibility << " to " << narrowed
                               << " because the field type is internal.\n";
                    }
                }
                if (declaringType.modifiers == "static ") {
                    const auto originalVisibility = memberVisibility(field.flags);
                    const auto narrowed = staticClassVisibility(originalVisibility, declaringType);
                    const auto prefix = originalVisibility + " ";
                    if (narrowed != originalVisibility && declaration.modifiers.starts_with(prefix)) {
                        declaration.modifiers.replace(0, prefix.size(), narrowed + " ");
                        output << bodyIndent << "// Partial recovery: protected field visibility narrowed to "
                               << narrowed << " because the containing class is static.\n";
                    }
                }
                if (declaringType.kind == ManagedTypeKind::Class && declaringType.modifiers == "static " &&
                    !declaration.isStatic && !declaration.literal) {
                    declaration.isStatic = true;
                    declaration.modifiers += "static ";
                    declaration.partialMetadata = true;
                }
                const auto defaultValue = fieldDefaultValue(field, metadata);
                if (declaringType.kind == ManagedTypeKind::Enum) {
                    if (field.name == "value__") continue;
                    const auto enumValue = enumUnderlyingType
                        ? enumMemberLiteral(field, *enumUnderlyingType, metadata) : std::nullopt;
                    if (enumValue) {
                        output << bodyIndent << fieldName << " = " << *enumValue << ",\n";
                    } else {
                        output << bodyIndent << "// Partial recovery: constant value for '" << fieldName
                               << "' is unavailable; the member was not emitted.\n";
                    }
                    continue;
                }
                if (declaration.literal) {
                    if (defaultValue) {
                        output << bodyIndent << declaration.modifiers << fieldType << ' '
                               << fieldName << " = " << *defaultValue << ";\n";
                    } else {
                        output << bodyIndent << "// Partial recovery: constant value for '" << fieldName
                               << "' is unavailable; the member was not emitted.\n";
                    }
                    continue;
                }
                if (declaration.partialMetadata || (declaration.hasDefault && !defaultValue)) {
                    output << bodyIndent << "// Partial recovery: native field flags or default value are incomplete.\n";
                }
                output << bodyIndent << declaration.modifiers << fieldType << ' ' << fieldName;
                if (defaultValue) output << " = " << *defaultValue;
                output << ";\n";
            }
        }

        std::set<int> reservedMethodDefinitions;
        std::set<std::string> reservedAccessorNames;
        if (declaringType.kind != ManagedTypeKind::Enum) {
            for (const auto* type : group.metadataTypes) {
                if (type->propertyCount == 0) continue;
                if (type->propertyStart < 0 ||
                    static_cast<size_t>(type->propertyStart) > metadata.properties.size() ||
                    type->propertyCount > metadata.properties.size() - static_cast<size_t>(type->propertyStart)) {
                    output << bodyIndent << "// Partial recovery: property metadata range is invalid.\n";
                    continue;
                }
                for (size_t offset = 0; offset < type->propertyCount; ++offset) {
                    const auto& property = metadata.properties[static_cast<size_t>(type->propertyStart) + offset];
                    const auto name = safeName(property.name, "Property_0x" + hexAddress(property.token));
                    const bool methodConflict = std::any_of(methods.begin(), methods.end(), [&](const MethodEntry& entry) {
                        return entry.baseName == name && entry.definitionIndex != property.get &&
                               entry.definitionIndex != property.set;
                    });
                    if (name == typeName || fieldNames.contains(name) || methodConflict) {
                        output << bodyIndent << "// Partial recovery: property name conflicts with another member.\n";
                        continue;
                    }
                    if (!first) output << '\n';
                    if (const auto blobSize = attributeBlobSize(attributeBlobs, type->imageName, property.token)) {
                        output << bodyIndent << "// Custom attribute blob: " << *blobSize
                               << " bytes; constructor and arguments are not decoded.\n";
                    }
                    if (appendProperty(output, *type, property, metadata, declaringType,
                                       accessibilityIndex ? &*accessibilityIndex : nullptr, &emittedNames,
                                       name, bodyIndent,
                                       reservedMethodDefinitions)) {
                        fieldNames.insert(name);
                        if (property.get >= 0) reservedAccessorNames.insert("get_" + property.name);
                        if (property.set >= 0) reservedAccessorNames.insert("set_" + property.name);
                        first = false;
                    } else {
                        output << bodyIndent << "// Partial recovery: property type or accessor metadata is unresolved.\n";
                    }
                }
            }
            for (const auto* type : group.metadataTypes) {
                if (type->eventCount == 0) continue;
                if (type->eventStart < 0 ||
                    static_cast<size_t>(type->eventStart) > metadata.events.size() ||
                    type->eventCount > metadata.events.size() - static_cast<size_t>(type->eventStart)) {
                    output << bodyIndent << "// Partial recovery: event metadata range is invalid.\n";
                    continue;
                }
                for (size_t offset = 0; offset < type->eventCount; ++offset) {
                    const auto& event = metadata.events[static_cast<size_t>(type->eventStart) + offset];
                    const auto name = safeName(event.name, "Event_0x" + hexAddress(event.token));
                    const bool methodConflict = std::any_of(methods.begin(), methods.end(), [&](const MethodEntry& entry) {
                        return entry.baseName == name && entry.definitionIndex != event.add &&
                               entry.definitionIndex != event.remove && entry.definitionIndex != event.raise;
                    });
                    if (name == typeName || fieldNames.contains(name) || methodConflict) {
                        output << bodyIndent << "// Partial recovery: event name conflicts with another member.\n";
                        continue;
                    }
                    if (!first) output << '\n';
                    if (const auto blobSize = attributeBlobSize(attributeBlobs, type->imageName, event.token)) {
                        output << bodyIndent << "// Custom attribute blob: " << *blobSize
                               << " bytes; constructor and arguments are not decoded.\n";
                    }
                    if (appendEvent(output, *type, event, metadata, declaringType,
                                    accessibilityIndex ? &*accessibilityIndex : nullptr, &emittedNames,
                                    name, bodyIndent,
                                    reservedMethodDefinitions)) {
                        fieldNames.insert(name);
                        reservedAccessorNames.insert("add_" + event.name);
                        reservedAccessorNames.insert("remove_" + event.name);
                        first = false;
                    } else {
                        output << bodyIndent << "// Partial recovery: event delegate or accessor metadata is incomplete.\n";
                    }
                }
            }
        }

        std::set<std::string> usedMethodSignatures;
        std::set<std::string> usedConstructors;
        std::map<std::string, std::string> emittedSupport;
        for (const auto& entry : methods) {
            const auto parameters = entry.method
                ? parameterList(*entry.method, metadata, true, &emittedNames) : "()";
            const auto signatureKey = parameterSignatureKey(entry.method, metadata);
            if (isConstructor(entry.method)) {
                const auto constructorKey = entry.method->name + signatureKey;
                if (!usedConstructors.insert(constructorKey).second) {
                    if (!first) output << '\n';
                    first = false;
                    output << bodyIndent << "// Unsupported duplicate constructor at 0x"
                           << hexAddress(entry.function->address) << ".\n";
                    record({entry.function->address, typeName, ProjectMethodBodyStatus::Omitted,
                            "duplicate constructor signature", true,
                            methodImageName(entry, group.metadataTypes.empty() ? nullptr : group.metadataTypes.front())});
                    continue;
                }
                if (!first) output << '\n';
                first = false;
                if (entry.method->name == ".cctor" && !entry.method->parameters.empty()) {
                    output << bodyIndent << "// Unsupported static constructor parameters at 0x"
                           << hexAddress(entry.function->address) << ".\n";
                    record({entry.function->address, typeName, ProjectMethodBodyStatus::Omitted,
                            "static constructor has parameters", true,
                            methodImageName(entry, group.metadataTypes.empty() ? nullptr : group.metadataTypes.front())});
                    continue;
                }
                record(appendMethod(output, entry, typeName, typeName, parameters, metadata,
                                    group.metadataTypes.empty() ? nullptr : group.metadataTypes.front(),
                                    declaringType, accessibilityIndex ? &*accessibilityIndex : nullptr,
                                    &emittedNames, bodyAdapter, emittedSupport, bodyIndent));
                continue;
            }

            MethodEntry namingEntry = entry;
            if (reservedMethodDefinitions.contains(entry.definitionIndex) ||
                reservedAccessorNames.contains(entry.baseName)) {
                // A C# property reserves get_/set_ accessor names. Keep any
                // recovered native method body under a stable, explicit name.
                namingEntry.baseName += stableMethodSuffix(entry);
            }
            const auto functionName = uniqueMethodName(namingEntry, typeName, signatureKey, fieldNames, usedMethodSignatures);
            if (!first) output << '\n';
            first = false;
            if (entry.method) {
                if (const auto blobSize = attributeBlobSize(attributeBlobs, entry.method->imageName,
                                                            entry.method->token)) {
                    output << bodyIndent << "// Custom attribute blob: " << *blobSize
                           << " bytes; constructor and arguments are not decoded.\n";
                }
            }
            if (metadata.generatedMethodsStart >= 0 &&
                entry.definitionIndex >= metadata.generatedMethodsStart) {
                output << bodyIndent << "// Generated method metadata token: 0x"
                       << hexAddress(entry.token) << ".\n";
            }
            auto emitted = appendMethod(output, entry, functionName, typeName, parameters, metadata,
                                        group.metadataTypes.empty() ? nullptr : group.metadataTypes.front(),
                                        declaringType, accessibilityIndex ? &*accessibilityIndex : nullptr,
                                        &emittedNames, bodyAdapter, emittedSupport, bodyIndent);
            // Only a completed, accessible declaration already written to
            // this project's source can become a managed-call target for
            // later methods. Forward calls and uncertain signatures stay
            // native; the surface grows monotonically in emission order.
            if (options_.includeExternalDeclarations && entry.method && !unmatched && !nestedParent &&
                emitted.status == ProjectMethodBodyStatus::Supported && !emitted.declarationPartial &&
                !declaringType.partialMetadata && generic.parameters.empty() &&
                entry.method->genericContainerIndex < 0 &&
                (declaringType.visibility == "public" || declaringType.visibility == "internal")) {
                const auto flags = nativeFlags(*entry.method);
                if (flags && ((*flags & 0x7) == 3 || (*flags & 0x7) == 6) &&
                    ((*flags & 0x10) != 0) == entry.method->isStatic) {
                    const auto& sourceType = metadata.types[key];
                    ManagedEmittedMember member;
                    member.imageName = entry.method->imageName;
                    member.metadataDeclaringType = entry.method->declaringType.empty()
                        ? (sourceType.nameSpace.empty() ? sourceType.name
                           : sourceType.nameSpace + "." + sourceType.name)
                        : entry.method->declaringType;
                    member.metadataMethodName = entry.method->name;
                    member.emittedDeclaringType = nameSpace.empty() ? typeName : nameSpace + "." + typeName;
                    member.emittedName = functionName;
                    member.isStatic = entry.method->isStatic;
                    member.bodyAvailable = true;
                    emissionSurface.byDefinitionIndex[entry.definitionIndex].push_back(std::move(member));
                }
            }
            record(std::move(emitted));
        }
        output << typeIndent << "}\n";
        if (nestedParent) output << outerIndent << "}\n";
        if (!nameSpace.empty()) output << "}\n";
        writeFile(filePath, output.str());
    }

    const auto projectPath = outputDirectory / (safeName(options_.projectName, "Il2CppRecovered") + ".csproj");
    writeFile(projectPath, projectFile(options_, sourceFiles, outputDirectory));
    return report;
}

ProjectWriteReport ProjectWriter::write(
    const std::filesystem::path& outputDirectory,
    const MetadataModel& metadata,
    const std::vector<RecoveredFunction>& functions,
    const ProjectWriterOptions& options) {
    ProjectWriter writer(options);
    return writer.write(outputDirectory, metadata, functions);
}

} // namespace il2cpprec
