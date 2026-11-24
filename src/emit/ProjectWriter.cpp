#include <il2cpprec/emit/ProjectWriter.hpp>
#include <il2cpprec/abi/AbiAdapter.hpp>
#include <il2cpprec/analysis/ManagedEmitter.hpp>
#include <il2cpprec/emit/RuntimeSupport.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>

#include <algorithm>
#include <bit>
#include <charconv>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
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
using TypeKey = std::pair<std::string, std::string>;

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
        const auto keyFor = [this](const Location& location) {
            const auto& type = metadata_.types[location.first];
            return TypeKey{type.nameSpace, type.name};
        };
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
};

MethodBodyEmission unsupportedBody(std::string diagnostic) {
    return {MethodBodyStatus::Unsupported, {}, {}, std::move(diagnostic)};
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

struct GenericDeclarationInfo {
    std::string parameters;
    std::string constraints;
    bool partialMetadata = false;
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
    bool varianceAllowed) {
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
            auto resolved = TypeSystem::resolve(static_cast<size_t>(referenceIndex), metadata);
            if (resolved == "object" || resolved == "System.Object" || resolved == "System.ValueType") {
                result.partialMetadata = true;
                continue;
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

void collectRegisters(const ExpressionPtr& expression, std::set<std::string>& registers) {
    if (!expression) return;
    if (expression->kind == Expression::Kind::Register) registers.insert(expression->name);
    for (const auto& argument : expression->arguments) collectRegisters(argument, registers);
}

std::set<std::string> usedRegisters(const RecoveredFunction& function) {
    std::set<std::string> result;
    for (const auto& block : function.blocks) {
        for (const auto& statement : block.statements) {
            collectRegisters(statement.destination, result);
            collectRegisters(statement.value, result);
            collectRegisters(statement.condition, result);
            collectRegisters(statement.target, result);
            for (const auto& argument : statement.arguments) collectRegisters(argument, result);
        }
    }
    return result;
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
    if (primitives.contains(resolved)) return resolved;
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

class MethodBodyAdapter {
public:
    MethodBodyEmission emit(
        const RecoveredFunction& function,
        const MethodModel* method,
        const MetadataModel& metadata) const {
        if (!method) return unsupportedBody("managed method metadata is unavailable");
        if (function.blocks.empty()) return unsupportedBody("typed IR body is empty");

        const AbiAdapter abi;
        const auto model = abi.bind(*method, metadata, function.architecture);
        if (!model.supported()) return unsupportedBody(abiDiagnostic(model));

        const bool constructor = method->name == ".ctor" || method->name == ".cctor";
        const bool voidReturn = constructor || model.returnValue.valueKind == AbiValueKind::Void;
        if (!voidReturn && (model.returnValue.valueKind != AbiValueKind::Integer ||
                            model.returnValue.conversion != AbiConversion::None)) {
            return unsupportedBody("managed return value requires an unsupported ABI conversion");
        }

        const auto parameterRegisters = nativeParameterRegisters(function.architecture);
        const auto pointerType = function.architecture == Architecture::Arm64 || function.architecture == Architecture::X64
            ? "ulong" : "uint";
        std::map<std::string, std::string> nativeDeclarations;
        for (const auto& binding : model.bindings) {
            if (binding.role == AbiValueRole::MethodInfo) continue;
            if (binding.role == AbiValueRole::This) continue;
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
        auto managed = ManagedEmitter{}.emit(function, metadata);
        auto managedSupport = applyManagedCallSites(adapted, managed.callSites, metadata);
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

        const auto registers = usedRegisters(adapted);
        for (const auto& name : parameterRegisters) {
            if (registers.contains(name) && !nativeDeclarations.contains(name)) {
                return unsupportedBody("native register '" + name + "' has no managed ABI value");
            }
        }

        CSharpBodyOptions options;
        options.voidReturn = voidReturn;
        options.declareNativeParameters = false;
        auto emitted = adapted.emitCSharpBody(options);
        MethodBodyEmission result;
        result.status = emitted.partial ? MethodBodyStatus::Partial : MethodBodyStatus::Supported;
        result.support = managedSupport.source + emitted.support;
        result.source = managedSupport.prelude;
        for (const auto& [name, declaration] : nativeDeclarations) result.source += declaration;
        result.source += emitted.declarations;
        result.source += emitted.body;
        for (const auto& diagnostic : emitted.diagnostics) {
            if (!result.diagnostic.empty()) result.diagnostic += "; ";
            result.diagnostic += "0x" + hexAddress(diagnostic.address) + ": " + diagnostic.message;
        }
        if (result.status == MethodBodyStatus::Partial && result.diagnostic.empty()) {
            result.diagnostic = "IR emitter reported partial recovery";
        }
        return result;
    }
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

std::string managedTypeName(const std::string& type, const MetadataModel& metadata) {
    return TypeSystem::resolve(type.empty() ? "object" : type, &metadata);
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
    bool hasMember = false;
    for (const auto* type : group.metadataTypes) {
        for (const auto& field : type->fields) {
            hasMember = true;
            if (!field.isStatic) return false;
        }
        for (const auto& method : type->methods) {
            hasMember = true;
            if (method.name == ".ctor" || (!method.isStatic && method.name != ".cctor")) return false;
        }
    }
    return hasMember;
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
    if (value < 0x20 || value == 0x7f) {
        std::ostringstream output;
        output << "'\\u" << std::hex << std::setw(4) << std::setfill('0') << value << "'";
        return output.str();
    }
    std::string result = "'";
    if (value < 0x80) result.push_back(static_cast<char>(value));
    else {
        result.push_back(static_cast<char>(0xC0 | (value >> 6)));
        result.push_back(static_cast<char>(0x80 | (value & 0x3F)));
    }
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
    bool includeDefault) {
    std::string direction;
    std::string type = trim(parameter.type);
    for (const std::string_view candidate : {std::string_view("ref "), std::string_view("out "), std::string_view("in ")}) {
        if (type.starts_with(candidate)) {
            direction = std::string(candidate);
            type = trim(type.substr(candidate.size()));
            break;
        }
    }
    std::string resolved = TypeSystem::resolve(type.empty() ? "object" : type, &metadata);
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

std::string parameterList(const MethodModel& method, const MetadataModel& metadata, bool includeDefaults = true) {
    std::vector<std::string> declarations;
    declarations.reserve(method.parameters.size());
    for (size_t index = 0; index < method.parameters.size(); ++index) {
        declarations.push_back(parameterDeclaration(method.parameters[index], index, metadata, includeDefaults));
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
};

MethodDeclarationInfo methodDeclaration(
    const MethodEntry& entry,
    const std::string& name,
    const std::string& typeName,
    const std::string& parameters,
    const MetadataModel& metadata,
    const TypeDeclarationInfo& declaringType) {
    MethodDeclarationInfo result;
    if (!entry.method) {
        result.signature = "public static void " + name + parameters;
        result.partialMetadata = true;
        return result;
    }
    const auto generic = genericDeclaration(metadata, entry.method->genericContainerIndex, true, false);
    result.partialMetadata = generic.partialMetadata || hasUnresolvedParameterDefaults(*entry.method, metadata);
    const auto flags = nativeFlags(*entry.method);
    if (entry.method->name == ".cctor") {
        result.signature = "static " + typeName + parameters;
        return result;
    }
    if (entry.method->name == ".ctor") {
        result.signature = (flags ? memberVisibility(*flags) : "public") + " " + typeName + parameters;
        result.partialMetadata = result.partialMetadata || !flags.has_value() || !generic.parameters.empty();
        return result;
    }

    if (declaringType.kind == ManagedTypeKind::Interface) {
        result.signature = TypeSystem::returnType(*entry.method, &metadata) + " " + name +
            generic.parameters + parameters + generic.constraints;
        result.bodyAllowed = false;
        result.partialMetadata = result.partialMetadata || !flags.has_value();
        return result;
    }

    std::string modifiers = (flags ? memberVisibility(*flags) : "public") + " ";
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
    result.signature = modifiers + TypeSystem::returnType(*entry.method, &metadata) + " " + name +
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
    const std::string& name,
    const std::string& indentation,
    std::set<int>& reservedMethods) {
    const MethodModel* getter = accessorMethod(type, property.get, "get_" + property.name);
    const MethodModel* setter = accessorMethod(type, property.set, "set_" + property.name);
    if (!getter && !setter) return false;
    if (getter && !getter->parameters.empty()) return false; // Indexers need parameterized C# syntax.
    if (setter && setter->parameters.size() != 1) return false;
    const std::string propertyType = getter
        ? TypeSystem::returnType(*getter, &metadata)
        : managedTypeName(setter->parameters.front().type, metadata);
    if (propertyType.empty() || propertyType == "void") return false;
    if (getter && setter && managedTypeName(setter->parameters.front().type, metadata) != propertyType) return false;
    if (getter && setter && getter->isStatic != setter->isStatic) return false;
    const MethodModel* principal = getter ? getter : setter;
    if (declaringType.kind != ManagedTypeKind::Interface) {
        output << indentation << memberVisibility(principal->flags) << ' ';
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
    const std::string& name,
    const std::string& indentation,
    std::set<int>& reservedMethods) {
    if (event.typeIndex < 0 || static_cast<size_t>(event.typeIndex) >= metadata.typeReferences.size()) return false;
    const auto& reference = metadata.typeReferences[static_cast<size_t>(event.typeIndex)];
    const std::string eventType = TypeSystem::resolve(static_cast<size_t>(event.typeIndex), metadata);
    // Only the framework delegate families are known to be legal C# event
    // types here. Other metadata references need a proven delegate definition.
    const bool frameworkDelegate = reference.definitionIndex < 0 &&
        (eventType == "System.Action" || eventType == "System.EventHandler" ||
         eventType.starts_with("System.Action<") || eventType.starts_with("System.EventHandler<"));
    if (!frameworkDelegate) return false;
    const MethodModel* add = accessorMethod(type, event.add, "add_" + event.name);
    const MethodModel* remove = accessorMethod(type, event.remove, "remove_" + event.name);
    if (!add || !remove || add->parameters.size() != 1 || remove->parameters.size() != 1 ||
        add->isStatic != remove->isStatic) return false;
    if (declaringType.kind != ManagedTypeKind::Interface) {
        output << indentation << memberVisibility(add->flags) << ' ';
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

void appendMethod(
    std::ostringstream& output,
    const MethodEntry& entry,
    const std::string& name,
    const std::string& typeName,
    const std::string& parameters,
    const MetadataModel& metadata,
    const TypeDeclarationInfo& declaringType,
    const MethodBodyAdapter& bodyAdapter,
    std::set<std::string>& emittedSupport,
    const std::string& indentation) {
    const auto declaration = methodDeclaration(entry, name, typeName, parameters, metadata, declaringType);
    if (declaration.partialMetadata) {
        output << indentation << "// Partial recovery: native method flags are unavailable or unsupported.\n";
    }
    if (!declaration.bodyAllowed) {
        output << indentation << declaration.signature << ";\n";
        return;
    }
    const auto body = bodyAdapter.emit(*entry.function, entry.method, metadata);
    if (!body.support.empty() && emittedSupport.insert(body.support).second) {
        appendIndented(output, body.support, indentation);
        output << '\n';
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

void ProjectWriter::write(
    const std::filesystem::path& outputDirectory,
    const MetadataModel& metadata,
    const std::vector<RecoveredFunction>& functions) const {
    if (outputDirectory.empty()) throw std::invalid_argument("Project output directory cannot be empty");
    std::filesystem::create_directories(outputDirectory);

    const MetadataIndex index(metadata);
    const auto attributeBlobs = indexAttributeBlobs(metadata);
    const std::set<std::string> includedImages(options_.includedImages.begin(), options_.includedImages.end());
    std::vector<bool> includedTypes(metadata.types.size(), true);
    if (!includedImages.empty()) {
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
    }

    std::map<TypeKey, TypeGroup> groups;
    for (size_t index = 0; index < metadata.types.size(); ++index) {
        if (!includedTypes[index]) continue;
        const auto& type = metadata.types[index];
        groups[{type.nameSpace, type.name}].metadataTypes.push_back(&type);
    }
    for (const auto& function : functions) {
        const auto location = index.find(function);
        if (location && !includedTypes[location->first]) continue;
        TypeKey key{"Il2CppRecovered", "UnmatchedMethods"};
        const MethodModel* method = nullptr;
        if (location) {
            const auto& type = metadata.types[location->first];
            key = {type.nameSpace, type.name};
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

    std::vector<std::filesystem::path> sourceFiles;
    const auto runtimePath = outputDirectory / "RuntimeSupport.cs";
    sourceFiles.push_back(runtimePath);
    writeFile(runtimePath, generateRuntimeSupport(functions.empty() ? Architecture::X64 : functions.front().architecture));

    const MethodBodyAdapter bodyAdapter;
    std::set<std::pair<std::string, std::string>> usedTypeNames;
    std::set<std::string> usedFilePaths;
    for (auto& [key, group] : groups) {
        auto& methods = group.methods;
        std::sort(methods.begin(), methods.end(), [](const MethodEntry& left, const MethodEntry& right) {
            return std::tie(left.metadataName, left.baseName, left.token, left.definitionIndex, left.function->address, left.function->name) <
                   std::tie(right.metadataName, right.baseName, right.token, right.definitionIndex, right.function->address, right.function->name);
        });

        const TypeModel* nestedParent = nullptr;
        if (group.metadataTypes.size() == 1) {
            const auto* child = group.metadataTypes.front();
            if (child->declaringTypeIndex >= 0 &&
                static_cast<size_t>(child->declaringTypeIndex) < metadata.types.size()) {
                const auto& parent = metadata.types[static_cast<size_t>(child->declaringTypeIndex)];
                const bool simpleParent = parent.declaringTypeIndex < 0 && parent.genericContainerIndex < 0 &&
                    parent.nameSpace == child->nameSpace && parent.name.find('`') == std::string::npos;
                const auto duplicates = std::count_if(metadata.types.begin(), metadata.types.end(), [&](const TypeModel& candidate) {
                    return candidate.declaringTypeIndex < 0 && candidate.nameSpace == parent.nameSpace &&
                           candidate.name == parent.name;
                });
                if (simpleParent && duplicates == 1 &&
                    (parent.flags & 0x20) == 0 && (parent.bitfield & 0x2) == 0) nestedParent = &parent;
            }
        }
        const bool staticType = isStaticType(group, key == TypeKey{"Il2CppRecovered", "UnmatchedMethods"});
        auto declaringType = typeDeclaration(group.metadataTypes.empty() ? nullptr : group.metadataTypes.front(),
                                             staticType, nestedParent != nullptr);
        const auto generic = group.metadataTypes.empty() ? GenericDeclarationInfo{} : genericDeclaration(
            metadata,
            group.metadataTypes.front()->genericContainerIndex,
            false,
            declaringType.kind == ManagedTypeKind::Interface);
        declaringType.partialMetadata = declaringType.partialMetadata || generic.partialMetadata;

        const auto parts = namespaceParts(key.first);
        const auto nameSpace = join(parts, ".");
        const auto typeName = uniqueTypeName(
            nameSpace,
            safeName(genericTypeBaseName(key.second, generic), "UnnamedType"),
            usedTypeNames);
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
                if (const auto blobSize = attributeBlobSize(attributeBlobs, type->imageName, field.token)) {
                    output << bodyIndent << "// Custom attribute blob: " << *blobSize
                           << " bytes; constructor and arguments are not decoded.\n";
                }
                auto declaration = fieldDeclaration(field);
                if (declaringType.kind == ManagedTypeKind::Class && declaringType.modifiers == "static " &&
                    !declaration.isStatic && !declaration.literal) {
                    declaration.isStatic = true;
                    declaration.modifiers += "static ";
                    declaration.partialMetadata = true;
                }
                const auto defaultValue = fieldDefaultValue(field, metadata);
                if (declaringType.kind == ManagedTypeKind::Enum) {
                    if (field.name == "value__") continue;
                    if (defaultValue) {
                        output << bodyIndent << fieldName << " = " << *defaultValue << ",\n";
                    } else {
                        output << bodyIndent << "// Partial recovery: constant value for '" << fieldName
                               << "' is unavailable; the member was not emitted.\n";
                    }
                    continue;
                }
                if (declaration.literal) {
                    if (defaultValue) {
                        output << bodyIndent << declaration.modifiers << managedTypeName(field.type, metadata) << ' '
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
                output << bodyIndent << declaration.modifiers << managedTypeName(field.type, metadata) << ' ' << fieldName;
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
                    if (appendProperty(output, *type, property, metadata, declaringType, name, bodyIndent,
                                       reservedMethodDefinitions)) {
                        fieldNames.insert(name);
                        if (property.get >= 0) reservedAccessorNames.insert("get_" + property.name);
                        if (property.set >= 0) reservedAccessorNames.insert("set_" + property.name);
                        first = false;
                    } else {
                        output << bodyIndent << "// Partial recovery: property accessor metadata is incomplete.\n";
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
                    if (appendEvent(output, *type, event, metadata, declaringType, name, bodyIndent,
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
        std::set<std::string> emittedSupport;
        for (const auto& entry : methods) {
            const auto parameters = entry.method ? parameterList(*entry.method, metadata) : "()";
            const auto signatureKey = parameterSignatureKey(entry.method, metadata);
            if (isConstructor(entry.method)) {
                const auto constructorKey = entry.method->name + signatureKey;
                if (!usedConstructors.insert(constructorKey).second) {
                    if (!first) output << '\n';
                    first = false;
                    output << bodyIndent << "// Unsupported duplicate constructor at 0x"
                           << hexAddress(entry.function->address) << ".\n";
                    continue;
                }
                if (!first) output << '\n';
                first = false;
                if (entry.method->name == ".cctor" && !entry.method->parameters.empty()) {
                    output << bodyIndent << "// Unsupported static constructor parameters at 0x"
                           << hexAddress(entry.function->address) << ".\n";
                    continue;
                }
                appendMethod(output, entry, typeName, typeName, parameters, metadata, declaringType, bodyAdapter, emittedSupport, bodyIndent);
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
            appendMethod(output, entry, functionName, typeName, parameters, metadata, declaringType, bodyAdapter, emittedSupport, bodyIndent);
        }
        output << typeIndent << "}\n";
        if (nestedParent) output << outerIndent << "}\n";
        if (!nameSpace.empty()) output << "}\n";
        writeFile(filePath, output.str());
    }

    const auto projectPath = outputDirectory / (safeName(options_.projectName, "Il2CppRecovered") + ".csproj");
    writeFile(projectPath, projectFile(options_, sourceFiles, outputDirectory));
}

void ProjectWriter::write(
    const std::filesystem::path& outputDirectory,
    const MetadataModel& metadata,
    const std::vector<RecoveredFunction>& functions,
    const ProjectWriterOptions& options) {
    ProjectWriter writer(options);
    writer.write(outputDirectory, metadata, functions);
}

} // namespace il2cpprec
