#include <il2cpprec/metadata/UniversalGenericResolver.hpp>

#include <il2cpprec/metadata/TypeSystem.hpp>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <tuple>
#include <utility>

namespace il2cpprec {
namespace {

constexpr size_t maxTypeDepth = 64;
constexpr uint32_t maxArrayRank = 64;

void appendDiagnostics(std::vector<std::string>& destination, const std::vector<std::string>& source) {
    destination.insert(destination.end(), source.begin(), source.end());
}

void mergeStatus(MetadataUsageStatus& destination, MetadataUsageStatus source) {
    if (source == MetadataUsageStatus::Ambiguous || destination == MetadataUsageStatus::Ambiguous) {
        destination = MetadataUsageStatus::Ambiguous;
    } else if (source == MetadataUsageStatus::Unresolved || destination == MetadataUsageStatus::Unresolved) {
        destination = MetadataUsageStatus::Unresolved;
    } else {
        destination = MetadataUsageStatus::Resolved;
    }
}

std::string indexText(int32_t index) {
    return std::to_string(index);
}

std::string typeToken(int32_t index) {
    return "type[" + indexText(index) + "]";
}

std::optional<size_t> parseTypeToken(std::string_view value) {
    if (value.size() <= 6 || !value.starts_with("type[") || value.back() != ']') return std::nullopt;
    size_t index = 0;
    const char* begin = value.data() + 5;
    const char* end = value.data() + value.size() - 1;
    const auto parsed = std::from_chars(begin, end, index);
    if (parsed.ec != std::errc{} || parsed.ptr != end) return std::nullopt;
    return index;
}

std::optional<uint16_t> genericParameterPosition(
    const TypeReferenceModel& reference,
    const MetadataModel& metadata,
    bool methodParameter) {
    if (reference.definitionIndex >= 0) {
        const auto index = static_cast<size_t>(reference.definitionIndex);
        if (index < metadata.genericParameters.size()) {
            return metadata.genericParameters[index].num;
        }
        if (index <= std::numeric_limits<uint16_t>::max()) {
            return static_cast<uint16_t>(index);
        }
        return std::nullopt;
    }

    const std::string_view prefix = methodParameter ? std::string_view("!!") : std::string_view("!");
    if (!reference.name.starts_with(prefix) || reference.name.size() == prefix.size()) return std::nullopt;
    if (!methodParameter && reference.name.starts_with("!!")) return std::nullopt;
    uint32_t position = 0;
    const char* begin = reference.name.data() + prefix.size();
    const char* end = reference.name.data() + reference.name.size();
    const auto parsed = std::from_chars(begin, end, position);
    if (parsed.ec != std::errc{} || parsed.ptr != end || position > std::numeric_limits<uint16_t>::max()) {
        return std::nullopt;
    }
    return static_cast<uint16_t>(position);
}

std::string qualifiedDefinitionName(const TypeReferenceModel& reference, const MetadataModel& metadata) {
    if (reference.definitionIndex >= 0 &&
        static_cast<size_t>(reference.definitionIndex) < metadata.types.size()) {
        const auto& definition = metadata.types[static_cast<size_t>(reference.definitionIndex)];
        if (!definition.nameSpace.empty() && !definition.name.empty()) {
            return definition.nameSpace + "." + definition.name;
        }
        if (!definition.name.empty()) return definition.name;
        if (!definition.nameSpace.empty()) return definition.nameSpace;
    }
    return reference.name;
}

std::string withoutGenericArity(std::string name) {
    const size_t separator = name.find_last_of(".+/");
    const size_t start = separator == std::string::npos ? 0 : separator + 1;
    const size_t backtick = name.find('`', start);
    if (backtick != std::string::npos) name.erase(backtick);
    return name;
}

std::string renderType(
    const TypeReferenceModel& reference,
    const MetadataModel& metadata,
    const std::vector<TypeReferenceModel>& references,
    size_t depth = 0) {
    if (depth > maxTypeDepth) return "<unresolved-type-depth>";
    const auto code = static_cast<Il2CppTypeCode>(reference.code);
    std::string result;
    if (auto primitive = TypeSystem::primitiveType(code)) {
        result = std::move(*primitive);
    } else {
        const auto element = [&]() -> std::string {
            if (reference.elementTypeIndex < 0 ||
                static_cast<size_t>(reference.elementTypeIndex) >= references.size()) {
                return "<unresolved-element:" + indexText(reference.elementTypeIndex) + ">";
            }
            return renderType(
                references[static_cast<size_t>(reference.elementTypeIndex)], metadata, references, depth + 1);
        };
        const auto named = [&](std::string_view kind) {
            std::string name = qualifiedDefinitionName(reference, metadata);
            if (name.empty()) return "<unresolved-" + std::string(kind) + ">";
            return name;
        };

        switch (code) {
        case Il2CppTypeCode::Ptr:
            result = element() + "*";
            break;
        case Il2CppTypeCode::ByRef:
            result = "ref " + element();
            break;
        case Il2CppTypeCode::ValueType:
            result = named("value-type");
            break;
        case Il2CppTypeCode::Class:
            result = named("class");
            break;
        case Il2CppTypeCode::Var:
        case Il2CppTypeCode::MVar: {
            result = reference.name;
            if (result.empty()) {
                const bool method = code == Il2CppTypeCode::MVar;
                const auto position = genericParameterPosition(reference, metadata, method);
                result = method ? "!!" : "!";
                result += position ? std::to_string(*position) : "?";
            }
            break;
        }
        case Il2CppTypeCode::Array: {
            if (reference.rank > maxArrayRank) {
                result = "<unresolved-array-rank:" + std::to_string(reference.rank) + ">";
                break;
            }
            result = element() + "[";
            result.append(reference.rank == 0 ? 0 : reference.rank - 1, ',');
            result += "]";
            break;
        }
        case Il2CppTypeCode::GenericInst: {
            result = withoutGenericArity(named("generic-class"));
            result += "<";
            for (size_t index = 0; index < reference.genericArgumentIndices.size(); ++index) {
                if (index != 0) result += ", ";
                const int32_t argument = reference.genericArgumentIndices[index];
                if (argument < 0 || static_cast<size_t>(argument) >= references.size()) {
                    result += "<unresolved-type:" + indexText(argument) + ">";
                } else {
                    result += renderType(
                        references[static_cast<size_t>(argument)], metadata, references, depth + 1);
                }
            }
            result += ">";
            break;
        }
        case Il2CppTypeCode::SzArray:
            result = element() + "[]";
            break;
        case Il2CppTypeCode::CModReqD:
        case Il2CppTypeCode::CModOpt:
        case Il2CppTypeCode::Modifier:
        case Il2CppTypeCode::Sentinel:
        case Il2CppTypeCode::Pinned:
        case Il2CppTypeCode::Internal:
        case Il2CppTypeCode::TypeIndex:
            result = element();
            break;
        case Il2CppTypeCode::Enum:
            result = named("enum");
            break;
        default: {
            std::ostringstream text;
            text << "<unresolved-type-code:0x" << std::hex << std::setw(2) << std::setfill('0')
                 << static_cast<unsigned>(reference.code) << ">";
            result = text.str();
            break;
        }
        }
    }
    if (reference.byRef && code != Il2CppTypeCode::ByRef && !result.starts_with("ref ")) {
        result.insert(0, "ref ");
    }
    return result;
}

class SubstitutionEngine {
public:
    SubstitutionEngine(
        const MetadataModel& metadata,
        const UniversalGenericSubstitution& substitution)
        : metadata_(metadata), substitution_(substitution), types_(metadata.typeReferences) {}

    UniversalGenericTypeResolution resolve(int32_t index) {
        if (index < 0 || static_cast<size_t>(index) >= types_.size()) {
            UniversalGenericTypeResolution result;
            result.sourceTypeIndex = index;
            result.type.code = static_cast<uint8_t>(Il2CppTypeCode::End);
            result.name = "<unresolved-type:" + indexText(index) + ">";
            result.diagnostics.push_back("Type reference " + typeToken(index) + " is outside the type table");
            return result;
        }
        auto result = resolveReference(
            types_[static_cast<size_t>(index)], index, 0);
        result.sourceTypeIndex = index;
        result.name = renderType(result.type, metadata_, types_);
        finish(result);
        return result;
    }

    UniversalGenericTypeResolution resolve(const TypeReferenceModel& reference) {
        auto result = resolveReference(reference, -1, 0);
        result.name = renderType(result.type, metadata_, types_);
        finish(result);
        return result;
    }

private:
    UniversalGenericTypeResolution resolveReference(
        const TypeReferenceModel& reference,
        int32_t sourceIndex,
        size_t depth) {
        UniversalGenericTypeResolution result;
        result.sourceTypeIndex = sourceIndex;
        result.type = reference;
        result.status = MetadataUsageStatus::Resolved;
        result.confidence = UniversalGenericConfidence::Resolved;
        if (depth > maxTypeDepth) {
            fail(result, "Generic type substitution exceeds the maximum nesting depth");
            return result;
        }
        if (sourceIndex >= 0) {
            if (!active_.insert(sourceIndex).second) {
                fail(result, "Cyclic generic type substitution involving " + typeToken(sourceIndex),
                     MetadataUsageStatus::Ambiguous);
                return result;
            }
        }

        const auto code = static_cast<Il2CppTypeCode>(reference.code);
        if (code == Il2CppTypeCode::Var || code == Il2CppTypeCode::MVar) {
            const bool method = code == Il2CppTypeCode::MVar;
            const auto& arguments = method ? substitution_.methodArguments : substitution_.classArguments;
            const auto position = genericParameterPosition(reference, metadata_, method);
            if (!position) {
                fail(result, std::string("Cannot determine ") + (method ? "MVAR" : "VAR") +
                    " position for " + (reference.name.empty() ? std::string("an unnamed parameter") : reference.name));
            } else if (*position >= arguments.size() || arguments[*position] < 0) {
                fail(result, std::string(method ? "MVAR" : "VAR") + " " + std::to_string(*position) +
                    " has no resolved generic argument");
            } else {
                const int32_t argument = arguments[*position];
                if (static_cast<size_t>(argument) >= types_.size()) {
                    fail(result, "Generic argument " + typeToken(argument) + " is outside the type table");
                } else {
                    auto nested = resolveReference(
                        types_[static_cast<size_t>(argument)], argument, depth + 1);
                    nested.sourceTypeIndex = sourceIndex;
                    nested.substituted = true;
                    if (reference.byRef && nested.type.code != static_cast<uint8_t>(Il2CppTypeCode::ByRef)) {
                        nested.type.byRef = true;
                    }
                    mergeStatus(result.status, nested.status);
                    appendDiagnostics(result.diagnostics, nested.diagnostics);
                    result.type = std::move(nested.type);
                    result.substituted = true;
                }
            }
        } else {
            const bool hasElement = code == Il2CppTypeCode::Ptr || code == Il2CppTypeCode::ByRef ||
                code == Il2CppTypeCode::Array || code == Il2CppTypeCode::SzArray ||
                code == Il2CppTypeCode::CModReqD || code == Il2CppTypeCode::CModOpt ||
                code == Il2CppTypeCode::Modifier || code == Il2CppTypeCode::Sentinel ||
                code == Il2CppTypeCode::Pinned || code == Il2CppTypeCode::Internal ||
                code == Il2CppTypeCode::TypeIndex;
            if (hasElement) {
                if (reference.elementTypeIndex < 0 ||
                    static_cast<size_t>(reference.elementTypeIndex) >= types_.size()) {
                    fail(result, "Type element " + typeToken(reference.elementTypeIndex) +
                        " is outside the type table");
                } else {
                    auto nested = resolveReference(
                        types_[static_cast<size_t>(reference.elementTypeIndex)],
                        reference.elementTypeIndex,
                        depth + 1);
                    result.type.elementTypeIndex = nested.sourceTypeIndex;
                    if (nested.substituted) {
                        result.type.elementTypeIndex = intern(nested.type);
                        result.substituted = true;
                    }
                    mergeStatus(result.status, nested.status);
                    appendDiagnostics(result.diagnostics, nested.diagnostics);
                }
            }

            if (code == Il2CppTypeCode::GenericInst) {
                for (auto& argument : result.type.genericArgumentIndices) {
                    if (argument < 0 || static_cast<size_t>(argument) >= types_.size()) {
                        fail(result, "Generic argument " + typeToken(argument) + " is outside the type table");
                        continue;
                    }
                    auto nested = resolveReference(
                        types_[static_cast<size_t>(argument)], argument, depth + 1);
                    if (nested.substituted) {
                        argument = intern(nested.type);
                        result.substituted = true;
                    }
                    mergeStatus(result.status, nested.status);
                    appendDiagnostics(result.diagnostics, nested.diagnostics);
                }
                if (qualifiedDefinitionName(reference, metadata_).empty()) {
                    fail(result, "Generic class instance has no type definition or reference name");
                }
            }

            if ((code == Il2CppTypeCode::Class || code == Il2CppTypeCode::ValueType ||
                 code == Il2CppTypeCode::Enum) && qualifiedDefinitionName(reference, metadata_).empty()) {
                fail(result, "Named type has no type definition or reference name");
            }
            if (code == Il2CppTypeCode::Array && reference.rank > maxArrayRank) {
                fail(result, "Array rank " + std::to_string(reference.rank) + " exceeds the supported maximum");
            }
            if (!TypeSystem::primitiveType(code) && !hasElement && code != Il2CppTypeCode::GenericInst &&
                code != Il2CppTypeCode::Class && code != Il2CppTypeCode::ValueType &&
                code != Il2CppTypeCode::Enum) {
                fail(result, "Unsupported IL2CPP type code " + std::to_string(reference.code));
            }
        }

        if (sourceIndex >= 0) active_.erase(sourceIndex);
        return result;
    }

    int32_t intern(const TypeReferenceModel& type) {
        const auto existing = std::find_if(
            types_.begin(), types_.end(), [&](const TypeReferenceModel& candidate) {
                return std::tie(
                    candidate.code,
                    candidate.name,
                    candidate.definitionIndex,
                    candidate.elementTypeIndex,
                    candidate.genericArgumentIndices,
                    candidate.rank,
                    candidate.byRef,
                    candidate.attrs) == std::tie(
                    type.code,
                    type.name,
                    type.definitionIndex,
                    type.elementTypeIndex,
                    type.genericArgumentIndices,
                    type.rank,
                    type.byRef,
                    type.attrs);
            });
        if (existing != types_.end()) {
            return static_cast<int32_t>(std::distance(types_.begin(), existing));
        }
        if (types_.size() >= static_cast<size_t>(std::numeric_limits<int32_t>::max())) return -1;
        types_.push_back(type);
        return static_cast<int32_t>(types_.size() - 1);
    }

    static void fail(
        UniversalGenericTypeResolution& result,
        std::string diagnostic,
        MetadataUsageStatus status = MetadataUsageStatus::Unresolved) {
        mergeStatus(result.status, status);
        result.confidence = UniversalGenericConfidence::Unresolved;
        result.diagnostics.push_back(std::move(diagnostic));
    }

    static void finish(UniversalGenericTypeResolution& result) {
        if (result.diagnostics.empty() && result.status == MetadataUsageStatus::Resolved) {
            result.confidence = UniversalGenericConfidence::Resolved;
        } else {
            result.confidence = UniversalGenericConfidence::Unresolved;
            if (result.status == MetadataUsageStatus::Resolved) result.status = MetadataUsageStatus::Unresolved;
        }
    }

    const MetadataModel& metadata_;
    const UniversalGenericSubstitution& substitution_;
    std::vector<TypeReferenceModel> types_;
    std::set<int32_t> active_;
};

struct MethodRecord {
    const MethodModel* method = nullptr;
    int32_t declaringTypeIndex = -1;
};

std::vector<MethodRecord> findMethods(const MetadataModel& metadata, int32_t definitionIndex) {
    std::vector<MethodRecord> result;
    for (size_t typeIndex = 0; typeIndex < metadata.types.size(); ++typeIndex) {
        for (const auto& method : metadata.types[typeIndex].methods) {
            if (method.definitionIndex == definitionIndex) {
                result.push_back({&method, static_cast<int32_t>(typeIndex)});
            }
        }
    }
    return result;
}

bool sameMapping(const GenericMethodPointerModel& left, const GenericMethodPointerModel& right) {
    return std::tie(
        left.genericMethodIndex,
        left.methodIndex,
        left.invokerIndex,
        left.classInstAddress,
        left.methodInstAddress,
        left.methodPointer,
        left.invokerPointer,
        left.adjustorThunkIndex,
        left.adjustorThunk) == std::tie(
        right.genericMethodIndex,
        right.methodIndex,
        right.invokerIndex,
        right.classInstAddress,
        right.methodInstAddress,
        right.methodPointer,
        right.invokerPointer,
        right.adjustorThunkIndex,
        right.adjustorThunk);
}

void fail(
    UniversalGenericMethodResolution& result,
    std::string diagnostic,
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved) {
    mergeStatus(result.status, status);
    result.diagnostics.push_back(std::move(diagnostic));
}

void fail(
    UniversalGenericClassResolution& result,
    std::string diagnostic,
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved) {
    mergeStatus(result.status, status);
    result.diagnostics.push_back(std::move(diagnostic));
}

void mergeType(
    UniversalGenericMethodResolution& result,
    const UniversalGenericTypeResolution& type) {
    mergeStatus(result.status, type.status);
    appendDiagnostics(result.diagnostics, type.diagnostics);
}

int32_t expectedArgumentCount(const MetadataModel& metadata, int32_t containerIndex) {
    if (containerIndex < 0 || static_cast<size_t>(containerIndex) >= metadata.genericContainers.size()) return -1;
    return metadata.genericContainers[static_cast<size_t>(containerIndex)].typeArgumentCount;
}

void validateArgumentCount(
    UniversalGenericMethodResolution& result,
    const MetadataModel& metadata,
    int32_t containerIndex,
    size_t actual,
    std::string_view owner) {
    const int32_t expected = expectedArgumentCount(metadata, containerIndex);
    if (expected >= 0 && actual != static_cast<size_t>(expected)) {
        fail(result, std::string(owner) + " expects " + std::to_string(expected) +
            " generic arguments, but the instantiation contains " + std::to_string(actual));
    }
}

const MethodSignatureModel* uniqueSignature(const MetadataModel& metadata, const MethodModel& method) {
    if (method.signatureOffset < 0) return nullptr;
    const MethodSignatureModel* result = nullptr;
    for (const auto& signature : metadata.methodSignatures) {
        if (signature.signatureOffset != method.signatureOffset) continue;
        if (result != nullptr) return nullptr;
        result = &signature;
    }
    return result;
}

uint64_t selectPointer(
    UniversalGenericMethodResolution& result,
    uint64_t direct,
    int32_t index,
    const std::vector<uint64_t>& pointers,
    std::string_view label) {
    if (index < -1) {
        fail(result, std::string(label) + " index " + std::to_string(index) + " is invalid",
             MetadataUsageStatus::Ambiguous);
        return direct;
    }
    uint64_t indexed = 0;
    if (index >= 0) {
        if (static_cast<size_t>(index) >= pointers.size()) {
            fail(result, std::string(label) + " index " + std::to_string(index) +
                " is outside the pointer table");
        } else {
            indexed = pointers[static_cast<size_t>(index)];
        }
    }
    if (direct != 0 && indexed != 0 && direct != indexed) {
        fail(result, std::string(label) + " direct pointer conflicts with the indexed pointer",
             MetadataUsageStatus::Ambiguous);
        return direct;
    }
    return direct != 0 ? direct : indexed;
}

void selectInvokerFromImage(
    UniversalGenericMethodResolution& result,
    const MetadataModel& metadata,
    const MethodRecord& record) {
    const MethodModel& method = *record.method;
    const ImageModel* selected = nullptr;
    for (const auto& image : metadata.images) {
        if (image.name != method.imageName) continue;
        if (selected != nullptr) {
            fail(result, "Method image " + method.imageName + " has multiple invoker index tables",
                 MetadataUsageStatus::Ambiguous);
            return;
        }
        selected = &image;
    }
    if (selected == nullptr || selected->invokerIndicesStart < 0) return;

    int64_t localIndex = method.methodIndex;
    if (localIndex < 0 && selected->methodStart >= 0 && method.definitionIndex >= selected->methodStart) {
        localIndex = static_cast<int64_t>(method.definitionIndex) - selected->methodStart;
    }
    if (localIndex < 0 || localIndex > std::numeric_limits<int32_t>::max()) return;
    const int64_t tableIndex = static_cast<int64_t>(selected->invokerIndicesStart) + localIndex;
    if (tableIndex < 0 || static_cast<uint64_t>(tableIndex) >= metadata.invokerIndices.size()) {
        fail(result, "Per-image invoker index " + std::to_string(tableIndex) + " is outside the invoker table");
        return;
    }
    result.selectedInvokerIndex = metadata.invokerIndices[static_cast<size_t>(tableIndex)];
    if (result.selectedInvokerIndex < 0) return;
    if (static_cast<size_t>(result.selectedInvokerIndex) >= metadata.invokerPointers.size()) {
        fail(result, "Selected invoker index " + std::to_string(result.selectedInvokerIndex) +
            " is outside the pointer table");
        return;
    }
    result.invokerPointer = metadata.invokerPointers[static_cast<size_t>(result.selectedInvokerIndex)];
}

UniversalGenericMethodResolution resolveMethod(
    const MetadataModel& metadata,
    const UniversalGenericResolverOptions& options,
    uint32_t genericMethodIndex,
    const UniversalGenericSubstitution* explicitSubstitution) {
    UniversalGenericMethodResolution result;
    result.genericMethodIndex = genericMethodIndex;
    result.status = MetadataUsageStatus::Resolved;
    result.confidence = UniversalGenericConfidence::Resolved;
    const auto profile = UniversalGenericResolver::versionProfile(metadata.version);
    if (!profile.supported) {
        std::ostringstream version;
        version << metadata.version;
        fail(result, "Unsupported metadata version " + version.str() + " for generic method resolution");
        return result;
    }
    if (genericMethodIndex > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
        fail(result, "Generic method index exceeds the signed genericMethodTable index range");
        return result;
    }
    if (genericMethodIndex >= metadata.methodSpecs.size()) {
        fail(result, "Generic method " + std::to_string(genericMethodIndex) +
            " exceeds methodSpecs count " + std::to_string(metadata.methodSpecs.size()));
        return result;
    }

    const auto& spec = metadata.methodSpecs[genericMethodIndex];
    result.methodSpec = spec;
    result.methodDefinitionIndex = spec.methodDefinitionIndex;
    if (spec.methodDefinitionIndex < 0) {
        fail(result, "Generic method has no method definition");
    }

    const GenericMethodPointerModel* mapping = nullptr;
    for (const auto& candidate : metadata.genericMethodTable) {
        if (candidate.genericMethodIndex != static_cast<int32_t>(genericMethodIndex)) continue;
        if (mapping != nullptr && !sameMapping(*mapping, candidate)) {
            fail(result, "Generic method has conflicting genericMethodTable entries",
                 MetadataUsageStatus::Ambiguous);
            break;
        }
        mapping = &candidate;
    }
    if (mapping == nullptr) {
        fail(result, "Generic method is absent from genericMethodTable");
    } else {
        result.mapping = *mapping;
    }

    std::vector<MethodRecord> methods;
    if (spec.methodDefinitionIndex >= 0) methods = findMethods(metadata, spec.methodDefinitionIndex);
    if (methods.empty()) {
        fail(result, "Generic method definition " + std::to_string(spec.methodDefinitionIndex) +
            " was not found in MetadataModel");
    } else if (methods.size() != 1) {
        fail(result, "Generic method definition " + std::to_string(spec.methodDefinitionIndex) +
            " has multiple MethodModel records", MetadataUsageStatus::Ambiguous);
    }

    UniversalGenericResolver resolver(metadata, options);
    result.classInst = resolver.resolveGenericInst(spec.classInstIndex, spec.classInstAddress);
    result.methodInst = resolver.resolveGenericInst(spec.methodInstIndex, spec.methodInstAddress);
    if (explicitSubstitution == nullptr) {
        result.substitution.classArguments = result.classInst.typeArgumentIndices;
        result.substitution.methodArguments = result.methodInst.typeArgumentIndices;
        mergeStatus(result.status, result.classInst.status);
        mergeStatus(result.status, result.methodInst.status);
        appendDiagnostics(result.diagnostics, result.classInst.diagnostics);
        appendDiagnostics(result.diagnostics, result.methodInst.diagnostics);
    } else {
        result.substitution = *explicitSubstitution;
    }

    if (methods.size() == 1) {
        const MethodRecord& record = methods.front();
        const MethodModel& definition = *record.method;
        result.method = definition;
        MethodModel& method = *result.method;
        const auto* signature = uniqueSignature(metadata, definition);

        const auto& declaringDefinition = metadata.types[static_cast<size_t>(record.declaringTypeIndex)];
        validateArgumentCount(
            result, metadata, declaringDefinition.genericContainerIndex,
            result.substitution.classArguments.size(), "Declaring generic type");
        validateArgumentCount(
            result, metadata, definition.genericContainerIndex,
            result.substitution.methodArguments.size(), "Generic method");

        if (!result.substitution.classArguments.empty() || declaringDefinition.genericContainerIndex >= 0) {
            TypeReferenceModel declaringType;
            declaringType.code = static_cast<uint8_t>(Il2CppTypeCode::GenericInst);
            declaringType.definitionIndex = record.declaringTypeIndex;
            declaringType.genericArgumentIndices = result.substitution.classArguments;
            result.declaringType = resolver.substitute(declaringType, result.substitution);
            method.declaringType = result.declaringType->name;
            mergeType(result, *result.declaringType);
        }

        const auto substituteSignatureType = [&](
            std::string& destination,
            int32_t signatureIndex) -> std::optional<UniversalGenericTypeResolution> {
            std::optional<int32_t> referenceIndex;
            if (const auto parsed = parseTypeToken(destination)) {
                if (*parsed <= static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
                    referenceIndex = static_cast<int32_t>(*parsed);
                }
            } else if (signatureIndex >= 0) {
                referenceIndex = signatureIndex;
            }
            if (!referenceIndex) return std::nullopt;
            auto resolved = resolver.substitute(*referenceIndex, result.substitution);
            destination = resolved.name;
            mergeType(result, resolved);
            return resolved;
        };

        auto returnResolution = substituteSignatureType(
            method.returnType, signature != nullptr ? signature->returnTypeIndex : -1);
        if (returnResolution) result.returnType = std::move(*returnResolution);
        for (size_t index = 0; index < method.parameters.size(); ++index) {
            const int32_t signatureIndex = signature != nullptr && index < signature->parameterTypeIndices.size()
                ? signature->parameterTypeIndices[index]
                : -1;
            auto parameter = substituteSignatureType(method.parameters[index].type, signatureIndex);
            if (parameter) result.parameterTypes.push_back(std::move(*parameter));
        }

        if (mapping != nullptr) {
            result.methodPointer = selectPointer(
                result, mapping->methodPointer, mapping->methodIndex,
                metadata.genericMethodPointers, "Generic method pointer");
            result.entryPoint = result.methodPointer;
            result.selectedInvokerIndex = mapping->invokerIndex;
            result.invokerPointer = selectPointer(
                result, mapping->invokerPointer, mapping->invokerIndex,
                metadata.invokerPointers, "Generic method invoker");
            if (result.invokerPointer == 0 && mapping->invokerPointer == 0 &&
                mapping->invokerIndex < 0 && profile.perImageInvokerIndices) {
                selectInvokerFromImage(result, metadata, record);
            }
            if (profile.adjustorThunks) {
                result.adjustorThunk = mapping->adjustorThunk;
                if (mapping->adjustorThunkIndex >= 0) {
                    if (static_cast<size_t>(mapping->adjustorThunkIndex) >= metadata.adjustorThunks.size()) {
                        fail(result, "Generic method adjustor index " +
                            std::to_string(mapping->adjustorThunkIndex) + " is outside the adjustor table");
                    } else {
                        const uint64_t indexed = metadata.adjustorThunks[
                            static_cast<size_t>(mapping->adjustorThunkIndex)].address;
                        if (result.adjustorThunk != 0 && indexed != 0 && result.adjustorThunk != indexed) {
                            fail(result, "Generic method adjustor pointer conflicts with the indexed pointer",
                                 MetadataUsageStatus::Ambiguous);
                        } else if (result.adjustorThunk == 0) {
                            result.adjustorThunk = indexed;
                        }
                    }
                } else if (mapping->adjustorThunkIndex < -1) {
                    fail(result, "Generic method adjustor index is invalid", MetadataUsageStatus::Ambiguous);
                }
                if (result.adjustorThunk != 0) {
                    result.entryPoint = result.adjustorThunk;
                    result.adjustorThunkSelected = true;
                }
            }
            if (result.methodPointer == 0) fail(result, "Generic method has no resolved native method pointer");
            if (result.invokerPointer == 0) fail(result, "Generic method has no resolved invoker pointer");
        }
    }

    if (result.status == MetadataUsageStatus::Resolved && result.diagnostics.empty()) {
        result.confidence = UniversalGenericConfidence::Resolved;
    } else {
        result.confidence = UniversalGenericConfidence::Unresolved;
        if (result.status == MetadataUsageStatus::Resolved) result.status = MetadataUsageStatus::Unresolved;
    }
    return result;
}

} // namespace

bool UniversalGenericTypeResolution::ok() const noexcept {
    return status == MetadataUsageStatus::Resolved && confidence == UniversalGenericConfidence::Resolved;
}

bool UniversalGenericInstResolution::ok() const noexcept {
    return status == MetadataUsageStatus::Resolved && confidence == UniversalGenericConfidence::Resolved;
}

bool UniversalGenericClassResolution::ok() const noexcept {
    return status == MetadataUsageStatus::Resolved && confidence == UniversalGenericConfidence::Resolved;
}

bool UniversalGenericMethodResolution::ok() const noexcept {
    return status == MetadataUsageStatus::Resolved && confidence == UniversalGenericConfidence::Resolved;
}

UniversalGenericResolver::UniversalGenericResolver(
    const MetadataModel& metadata,
    UniversalGenericResolverOptions options)
    : metadata_(&metadata), options_(std::move(options)) {}

UniversalGenericVersionProfile UniversalGenericResolver::versionProfile(double version) noexcept {
    UniversalGenericVersionProfile profile;
    if (!std::isfinite(version)) return profile;
    const bool legacy = version >= 24.0 && version <= 24.5;
    const bool v27 = version >= 27.0 && version <= 27.2;
    const bool v29 = version >= 29.0 && version <= 29.1;
    const bool v31 = version == 31.0;
    const bool modern = version >= 33.0;
    profile.supported = legacy || v27 || v29 || v31 || modern;
    if (!profile.supported) return profile;
    profile.adjustorThunks = version == 24.5 || (v27 && version >= 27.1) || v29 || v31 || modern;
    profile.perImageInvokerIndices = (legacy && version >= 24.2) || v27 || v29 || v31 ||
        (modern && version < 108.0);
    return profile;
}

bool UniversalGenericResolver::supportsVersion(double metadataVersion) noexcept {
    return versionProfile(metadataVersion).supported;
}

UniversalGenericTypeResolution UniversalGenericResolver::substitute(
    int32_t typeReferenceIndex,
    const UniversalGenericSubstitution& substitution) const {
    return SubstitutionEngine(*metadata_, substitution).resolve(typeReferenceIndex);
}

UniversalGenericTypeResolution UniversalGenericResolver::substitute(
    const TypeReferenceModel& type,
    const UniversalGenericSubstitution& substitution) const {
    return SubstitutionEngine(*metadata_, substitution).resolve(type);
}

UniversalGenericInstResolution UniversalGenericResolver::resolveGenericInst(
    int32_t genericInstIndex,
    uint64_t genericInstAddress) const {
    UniversalGenericInstResolution result;
    result.status = MetadataUsageStatus::Resolved;
    result.confidence = UniversalGenericConfidence::Resolved;
    result.genericInstIndex = genericInstIndex;
    result.genericInstAddress = genericInstAddress;
    if (genericInstIndex < -1) {
        result.status = MetadataUsageStatus::Unresolved;
        result.confidence = UniversalGenericConfidence::Unresolved;
        result.diagnostics.push_back("Generic inst index " + std::to_string(genericInstIndex) + " is invalid");
        return result;
    }

    const GenericInstModel* inst = nullptr;
    if (genericInstIndex >= 0) {
        if (static_cast<size_t>(genericInstIndex) >= metadata_->genericInsts.size()) {
            result.status = MetadataUsageStatus::Unresolved;
            result.diagnostics.push_back("Generic inst index " + std::to_string(genericInstIndex) +
                " is outside the generic inst table");
        } else {
            inst = &metadata_->genericInsts[static_cast<size_t>(genericInstIndex)];
            if (genericInstAddress != 0 && inst->address != 0 && genericInstAddress != inst->address) {
                result.status = MetadataUsageStatus::Ambiguous;
                result.diagnostics.push_back("Generic inst index and address identify different records");
            }
            result.genericInstAddress = genericInstAddress != 0 ? genericInstAddress : inst->address;
        }
    } else if (genericInstAddress != 0) {
        for (const auto& candidate : metadata_->genericInsts) {
            if (candidate.address != genericInstAddress) continue;
            if (inst != nullptr) {
                result.status = MetadataUsageStatus::Ambiguous;
                result.diagnostics.push_back("Generic inst address has multiple table entries");
                break;
            }
            inst = &candidate;
            result.genericInstIndex = static_cast<int32_t>(&candidate - metadata_->genericInsts.data());
        }
        if (inst == nullptr && result.status != MetadataUsageStatus::Ambiguous &&
            !options_.genericInstArgumentsByAddress.contains(genericInstAddress)) {
            result.status = MetadataUsageStatus::Unresolved;
            result.diagnostics.push_back("Generic inst address is absent from the generic inst table");
        }
    }

    const std::vector<int32_t>* explicitArguments = nullptr;
    const auto explicitByRequested = options_.genericInstArgumentsByAddress.find(genericInstAddress);
    if (explicitByRequested != options_.genericInstArgumentsByAddress.end()) {
        explicitArguments = &explicitByRequested->second;
    }
    if (inst != nullptr && inst->address != genericInstAddress) {
        const auto explicitByModel = options_.genericInstArgumentsByAddress.find(inst->address);
        if (explicitByModel != options_.genericInstArgumentsByAddress.end()) {
            if (explicitArguments != nullptr && *explicitArguments != explicitByModel->second) {
                result.status = MetadataUsageStatus::Ambiguous;
                result.diagnostics.push_back("Generic inst has conflicting explicit argument lists");
            } else {
                explicitArguments = &explicitByModel->second;
            }
        }
    }

    if (explicitArguments != nullptr) {
        result.typeArgumentIndices = *explicitArguments;
    } else if (inst != nullptr) {
        result.typeArgumentIndices.reserve(inst->typeAddresses.size());
        for (const uint64_t address : inst->typeAddresses) {
            const auto reference = options_.typeReferencesByAddress.find(address);
            if (reference == options_.typeReferencesByAddress.end()) {
                result.typeArgumentIndices.push_back(-1);
                result.status = MetadataUsageStatus::Unresolved;
                result.diagnostics.push_back("Generic argument type address " + std::to_string(address) +
                    " has no type reference mapping");
            } else {
                result.typeArgumentIndices.push_back(reference->second);
            }
        }
    }

    for (const int32_t argument : result.typeArgumentIndices) {
        if (argument < 0 || static_cast<size_t>(argument) >= metadata_->typeReferences.size()) {
            result.status = MetadataUsageStatus::Unresolved;
            result.diagnostics.push_back("Generic argument " + typeToken(argument) +
                " is outside the type table");
        }
    }
    if (result.status != MetadataUsageStatus::Resolved || !result.diagnostics.empty()) {
        result.confidence = UniversalGenericConfidence::Unresolved;
        if (result.status == MetadataUsageStatus::Resolved) result.status = MetadataUsageStatus::Unresolved;
    }
    return result;
}

UniversalGenericClassResolution UniversalGenericResolver::resolveGenericClass(uint32_t genericClassIndex) const {
    UniversalGenericClassResolution result;
    result.genericClassIndex = genericClassIndex;
    result.status = MetadataUsageStatus::Resolved;
    result.confidence = UniversalGenericConfidence::Resolved;
    if (genericClassIndex >= metadata_->genericClasses.size()) {
        fail(result, "Generic class index " + std::to_string(genericClassIndex) +
            " is outside the generic class table");
    } else {
        const auto& genericClass = metadata_->genericClasses[genericClassIndex];
        result.genericClass = genericClass;
        if (genericClass.definitionIndex < 0 ||
            static_cast<size_t>(genericClass.definitionIndex) >= metadata_->types.size()) {
            fail(result, "Generic class definition " + std::to_string(genericClass.definitionIndex) +
                " is outside the type table");
        } else {
            result.classInst = resolveGenericInst(-1, genericClass.classInstAddress);
            result.methodInst = resolveGenericInst(-1, genericClass.methodInstAddress);
            result.substitution.classArguments = result.classInst.typeArgumentIndices;
            result.substitution.methodArguments = result.methodInst.typeArgumentIndices;
            mergeStatus(result.status, result.classInst.status);
            mergeStatus(result.status, result.methodInst.status);
            appendDiagnostics(result.diagnostics, result.classInst.diagnostics);
            appendDiagnostics(result.diagnostics, result.methodInst.diagnostics);

            const auto& definition = metadata_->types[static_cast<size_t>(genericClass.definitionIndex)];
            const int32_t expected = expectedArgumentCount(*metadata_, definition.genericContainerIndex);
            if (expected >= 0 && result.substitution.classArguments.size() != static_cast<size_t>(expected)) {
                fail(result, "Generic class expects " + std::to_string(expected) +
                    " arguments, but the instantiation contains " +
                    std::to_string(result.substitution.classArguments.size()));
            }
            TypeReferenceModel instance;
            instance.code = static_cast<uint8_t>(Il2CppTypeCode::GenericInst);
            instance.definitionIndex = genericClass.definitionIndex;
            instance.genericArgumentIndices = result.substitution.classArguments;
            result.type = substitute(instance, result.substitution);
            mergeStatus(result.status, result.type.status);
            appendDiagnostics(result.diagnostics, result.type.diagnostics);
        }
    }
    if (result.status == MetadataUsageStatus::Resolved && result.diagnostics.empty()) {
        result.confidence = UniversalGenericConfidence::Resolved;
    } else {
        result.confidence = UniversalGenericConfidence::Unresolved;
        if (result.status == MetadataUsageStatus::Resolved) result.status = MetadataUsageStatus::Unresolved;
    }
    return result;
}

UniversalGenericMethodResolution UniversalGenericResolver::resolve(uint32_t genericMethodIndex) const {
    return resolveMethod(*metadata_, options_, genericMethodIndex, nullptr);
}

UniversalGenericMethodResolution UniversalGenericResolver::resolve(
    uint32_t genericMethodIndex,
    const UniversalGenericSubstitution& substitution) const {
    return resolveMethod(*metadata_, options_, genericMethodIndex, &substitution);
}

UniversalGenericMethodResolution UniversalGenericResolver::resolveMethodSpec(uint32_t genericMethodIndex) const {
    return resolve(genericMethodIndex);
}

const char* toString(UniversalGenericConfidence confidence) noexcept {
    switch (confidence) {
    case UniversalGenericConfidence::Unresolved: return "unresolved";
    case UniversalGenericConfidence::Partial: return "partial";
    case UniversalGenericConfidence::Resolved: return "resolved";
    }
    return "unresolved";
}

} // namespace il2cpprec
