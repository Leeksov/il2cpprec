#include <il2cpprec/metadata/MetadataUsage.hpp>

#include <il2cpprec/metadata/GenericMethodResolver.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>

#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint32_t metadataSanity = 0xfab11baf;
constexpr size_t unity2017HeaderSize = 216;

uint32_t readU32(const uint8_t* data, size_t offset) {
    return static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset + 1]) << 8) |
        (static_cast<uint32_t>(data[offset + 2]) << 16) |
        (static_cast<uint32_t>(data[offset + 3]) << 24);
}

int32_t readI32(const uint8_t* data, size_t offset) {
    const uint32_t value = readU32(data, offset);
    if (value <= static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
        return static_cast<int32_t>(value);
    }
    return -static_cast<int32_t>(std::numeric_limits<uint32_t>::max() - value) - 1;
}

void addDiagnostic(
    std::vector<MetadataUsageDiagnostic>& diagnostics,
    MetadataUsageStatus status,
    std::string code,
    std::string message,
    std::optional<uint32_t> listIndex = std::nullopt,
    std::optional<size_t> pairIndex = std::nullopt,
    std::optional<uint32_t> destinationIndex = std::nullopt) {
    diagnostics.push_back({status, std::move(code), std::move(message), listIndex, pairIndex, destinationIndex});
}

void addDiagnostic(
    MetadataUsageResult& result,
    MetadataUsageStatus status,
    std::string code,
    std::string message,
    std::optional<uint32_t> listIndex = std::nullopt,
    std::optional<size_t> pairIndex = std::nullopt,
    std::optional<uint32_t> destinationIndex = std::nullopt) {
    result.diagnostics.push_back({status, std::move(code), std::move(message), listIndex, pairIndex, destinationIndex});
}

void failEntry(
    MetadataUsageEntry& entry,
    MetadataUsageResult& result,
    MetadataUsageStatus status,
    std::string code,
    std::string message) {
    entry.status = status;
    std::optional<uint32_t> listIndex;
    if (entry.listIndices.size() == 1) listIndex = entry.listIndices.front();
    addDiagnostic(result, status, std::move(code), std::move(message), listIndex, entry.pairIndex, entry.destinationIndex);
}

bool validRange(size_t offset, size_t byteSize, size_t fileSize) {
    return offset <= fileSize && byteSize <= fileSize - offset;
}

bool validateTable(
    const MetadataUsageTableView& tables,
    size_t offset,
    size_t byteSize,
    size_t stride,
    const char* name,
    MetadataUsageResult& result) {
    if (byteSize % stride != 0) {
        addDiagnostic(
            result,
            MetadataUsageStatus::Unresolved,
            "misaligned-table-size",
            std::string(name) + " byte size " + std::to_string(byteSize) +
                " is not divisible by stride " + std::to_string(stride));
        return false;
    }
    if (!validRange(offset, byteSize, tables.size)) {
        addDiagnostic(
            result,
            MetadataUsageStatus::Unresolved,
            "table-out-of-range",
            std::string(name) + " range [" + std::to_string(offset) + ", " +
                std::to_string(static_cast<uint64_t>(offset) + byteSize) + ") exceeds input size " +
                std::to_string(tables.size));
        return false;
    }
    const size_t count = byteSize / stride;
    if (count > std::numeric_limits<uint32_t>::max()) {
        addDiagnostic(
            result,
            MetadataUsageStatus::Unresolved,
            "table-count-overflow",
            std::string(name) + " count exceeds the 32-bit MetadataUsage index range");
        return false;
    }
    return true;
}

bool makeUnity2017View(
    const std::vector<uint8_t>& data,
    MetadataUsageTableView& view,
    MetadataUsageResult& result) {
    if (data.size() < unity2017HeaderSize) {
        addDiagnostic(
            result,
            MetadataUsageStatus::Unresolved,
            "truncated-header",
            "Unity 2017 MetadataUsage header requires 216 bytes, got " + std::to_string(data.size()));
        return false;
    }
    if (readU32(data.data(), 0) != metadataSanity) {
        addDiagnostic(result, MetadataUsageStatus::Unresolved, "invalid-sanity", "Global metadata sanity value is invalid");
        return false;
    }
    if (readI32(data.data(), 4) != 24) {
        addDiagnostic(result, MetadataUsageStatus::Unresolved, "unsupported-version", "Unity 2017 MetadataUsage requires version 24");
        return false;
    }

    const int32_t listsSize = readI32(data.data(), 196);
    const int32_t pairsSize = readI32(data.data(), 204);
    const int32_t fieldRefsSize = readI32(data.data(), 212);
    if (listsSize < 0 || pairsSize < 0 || fieldRefsSize < 0) {
        addDiagnostic(result, MetadataUsageStatus::Unresolved, "negative-table-size", "MetadataUsage table sizes must not be negative");
        return false;
    }

    view.data = data.data();
    view.size = data.size();
    view.listsOffset = readU32(data.data(), 192);
    view.listsSize = static_cast<uint32_t>(listsSize);
    view.pairsOffset = readU32(data.data(), 200);
    view.pairsSize = static_cast<uint32_t>(pairsSize);
    view.fieldRefsOffset = readU32(data.data(), 208);
    view.fieldRefsSize = static_cast<uint32_t>(fieldRefsSize);
    return true;
}

size_t variableIndexWidth(uint64_t count) {
    if (count <= 0xff) return 1;
    if (count <= 0xffff) return 2;
    return 4;
}

uint32_t readVariableIndex(const uint8_t* data, size_t offset, size_t width) {
    uint32_t value = 0;
    for (size_t index = 0; index < width; ++index) value |= static_cast<uint32_t>(data[offset + index]) << (index * 8);
    return value;
}

bool parseVersionedHeader(
    const std::vector<uint8_t>& data,
    double version,
    MetadataUsageHeaderInfo& info,
    std::vector<MetadataUsageDiagnostic>& diagnostics) {
    if (version < 23 || version > 108) {
        addDiagnostic(diagnostics, MetadataUsageStatus::Unresolved, "unsupported-version", "MetadataUsage header version must be between 23 and 108");
        return false;
    }
    if (data.size() < 8) {
        addDiagnostic(diagnostics, MetadataUsageStatus::Unresolved, "truncated-header", "Global metadata header is truncated");
        return false;
    }
    if (readU32(data.data(), 0) != metadataSanity) {
        addDiagnostic(diagnostics, MetadataUsageStatus::Unresolved, "invalid-sanity", "Global metadata sanity value is invalid");
        return false;
    }
    const int32_t rawVersion = readI32(data.data(), 4);
    if (rawVersion != 24 && rawVersion != static_cast<int32_t>(version)) {
        addDiagnostic(diagnostics, MetadataUsageStatus::Unresolved, "version-mismatch", "Header version does not match the requested MetadataUsage profile");
        return false;
    }
    if (rawVersion == 24 && (version < 24 || version >= 25)) {
        addDiagnostic(diagnostics, MetadataUsageStatus::Unresolved, "version-mismatch", "Header version 24 requires a 24.x MetadataUsage profile");
        return false;
    }

    info.rawVersion = rawVersion;
    info.version = version;
    const size_t sectionStride = version >= 38 ? 12 : 8;
    size_t cursor = 8;
    auto section = [&](MetadataUsageSection* output, const char* name) {
        if (cursor > data.size() || sectionStride > data.size() - cursor) {
            addDiagnostic(diagnostics, MetadataUsageStatus::Unresolved, "truncated-header", std::string("Global metadata header ends before ") + name);
            return false;
        }
        const int32_t offset = readI32(data.data(), cursor);
        const int32_t byteSize = readI32(data.data(), cursor + 4);
        int32_t count = 0;
        if (sectionStride == 12) count = readI32(data.data(), cursor + 8);
        cursor += sectionStride;
        if (offset < 0 || byteSize < 0 || count < 0) {
            addDiagnostic(diagnostics, MetadataUsageStatus::Unresolved, "negative-table-size", std::string(name) + " has a negative header value");
            return false;
        }
        if (output != nullptr) {
            output->offset = static_cast<uint32_t>(offset);
            output->size = static_cast<uint32_t>(byteSize);
            output->count = static_cast<uint32_t>(count);
        }
        if (!validRange(static_cast<size_t>(offset), static_cast<size_t>(byteSize), data.size())) {
            addDiagnostic(diagnostics, MetadataUsageStatus::Unresolved, "header-section-out-of-range", std::string(name) + " section is outside the metadata file");
            return false;
        }
        return true;
    };

    MetadataUsageSection* leading[] = {
        nullptr, nullptr, nullptr, nullptr, nullptr, &info.methods, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &info.interfaceOffsets, nullptr
    };
    for (auto* entry : leading) if (!section(entry, "leading metadata")) return false;
    if (version >= 104 && !section(nullptr, "typeInlineArrays")) return false;
    if (version <= 24.15 && !section(nullptr, "rgctxEntries")) return false;
    if (!section(nullptr, "images")) return false;
    if (!section(nullptr, "assemblies")) return false;
    if (version < 27) {
        if (!section(&info.metadataUsageLists, "metadataUsageLists")) return false;
        if (!section(&info.metadataUsagePairs, "metadataUsagePairs")) return false;
    }
    if (!section(&info.fieldRefs, "fieldRefs")) return false;
    if (!section(nullptr, "referencedAssemblies")) return false;
    if (!section(nullptr, "attributesInfo")) return false;
    if (!section(nullptr, "attributeTypes")) return false;
    if (!section(&info.unresolvedVirtualCallParameterTypes, "unresolvedVirtualCallParameterTypes")) return false;
    if (!section(&info.unresolvedVirtualCallParameterRanges, "unresolvedVirtualCallParameterRanges")) return false;
    if (!section(nullptr, "windowsRuntimeTypeNames")) return false;
    if (version >= 27 && !section(nullptr, "windowsRuntimeStrings")) return false;
    if (version >= 24 && !section(nullptr, "exportedTypeDefinitions")) return false;

    if (version >= 108) {
        if (!section(&info.methodSpecsOnGenericType, "methodSpecsOnGenericType") ||
            !section(&info.genericMethodSpecsOnType, "genericMethodSpecsOnType") ||
            !section(&info.methodSpecs, "methodSpecs") ||
            !section(&info.genericMethodFunctionsDefinitions, "genericMethodFunctionsDefinitions") ||
            !section(&info.genericMethodFunctionsDefinitionsWithAdjustor, "genericMethodFunctionsDefinitionsWithAdjustor") ||
            !section(&info.invokerIndices, "invokerIndices") ||
            !section(&info.rgctxRanges, "rgctxRanges") ||
            !section(&info.rgctxValues, "rgctxValues") ||
            !section(&info.staticConstructorTypeIndices, "staticConstructorTypeIndices")) {
            return false;
        }
    }

    if (version >= 105) info.methodDefinitionIndexWidth = variableIndexWidth(info.methods.count);
    if (version >= 38 && info.interfaceOffsets.count != 0) {
        const size_t stride = info.interfaceOffsets.size / info.interfaceOffsets.count;
        if (info.interfaceOffsets.size % info.interfaceOffsets.count != 0 || stride <= 4 || stride - 4 > 4) {
            addDiagnostic(diagnostics, MetadataUsageStatus::Unresolved, "invalid-type-index-width", "Cannot derive Il2CppType index width from interfaceOffsets");
            return false;
        }
        info.typeIndexWidth = stride - 4;
    }
    return true;
}

struct FieldRef {
    uint32_t typeIndex = 0;
    uint32_t fieldIndex = 0;
};

MetadataUsageResult readImpl(
    const MetadataUsageTableView& tables,
    const MetadataModel* metadata,
    const MetadataUsageGenericMethodResolver& genericMethods,
    std::optional<uint32_t> selectedList) {
    MetadataUsageResult result;
    if (tables.data == nullptr && tables.size != 0) {
        addDiagnostic(result, MetadataUsageStatus::Unresolved, "null-input", "MetadataUsage input is null but its size is nonzero");
        return result;
    }

    const bool listsValid = validateTable(
        tables, tables.listsOffset, tables.listsSize, MetadataUsageReader::listStride, "metadataUsageLists", result);
    const bool pairsValid = validateTable(
        tables, tables.pairsOffset, tables.pairsSize, MetadataUsageReader::pairStride, "metadataUsagePairs", result);
    const bool fieldRefsValid = validateTable(
        tables, tables.fieldRefsOffset, tables.fieldRefsSize, MetadataUsageReader::fieldRefStride, "fieldRefs", result);
    if (!listsValid || !pairsValid || !fieldRefsValid) return result;

    const size_t listCount = tables.listsSize / MetadataUsageReader::listStride;
    const size_t pairCount = tables.pairsSize / MetadataUsageReader::pairStride;
    result.lists.reserve(listCount);
    for (size_t index = 0; index < listCount; ++index) {
        const size_t offset = tables.listsOffset + index * MetadataUsageReader::listStride;
        result.lists.push_back({readU32(tables.data, offset), readU32(tables.data, offset + 4)});
    }
    result.pairs.reserve(pairCount);
    for (size_t index = 0; index < pairCount; ++index) {
        const size_t offset = tables.pairsOffset + index * MetadataUsageReader::pairStride;
        result.pairs.push_back({readU32(tables.data, offset), readU32(tables.data, offset + 4)});
    }

    std::vector<FieldRef> fieldRefs;
    const size_t fieldRefCount = tables.fieldRefsSize / MetadataUsageReader::fieldRefStride;
    fieldRefs.reserve(fieldRefCount);
    for (size_t index = 0; index < fieldRefCount; ++index) {
        const size_t offset = tables.fieldRefsOffset + index * MetadataUsageReader::fieldRefStride;
        fieldRefs.push_back({readU32(tables.data, offset), readU32(tables.data, offset + 4)});
    }

    result.tablesValid = true;
    if (selectedList && *selectedList >= listCount) {
        addDiagnostic(
            result,
            MetadataUsageStatus::Unresolved,
            "metadata-usage-list-out-of-range",
            "MetadataUsage list index " + std::to_string(*selectedList) +
                " exceeds list count " + std::to_string(listCount),
            *selectedList);
        return result;
    }

    std::vector<std::vector<uint32_t>> owners(pairCount);
    for (size_t listIndex = 0; listIndex < listCount; ++listIndex) {
        const auto& list = result.lists[listIndex];
        const uint64_t end = static_cast<uint64_t>(list.start) + list.count;
        if (end > pairCount) {
            addDiagnostic(
                result,
                MetadataUsageStatus::Unresolved,
                "metadata-usage-list-range-out-of-bounds",
                "MetadataUsage list " + std::to_string(listIndex) + " pair range [" +
                    std::to_string(list.start) + ", " + std::to_string(end) + ") exceeds pair count " +
                    std::to_string(pairCount),
                static_cast<uint32_t>(listIndex));
            result.tablesValid = false;
            continue;
        }
        for (size_t pairIndex = list.start; pairIndex < static_cast<size_t>(end); ++pairIndex) {
            owners[pairIndex].push_back(static_cast<uint32_t>(listIndex));
        }
    }
    if (!result.tablesValid) return result;

    for (const auto& listOwners : owners) {
        if (listOwners.empty()) ++result.unreferencedPairCount;
        else ++result.referencedPairCount;
    }

    std::unordered_map<int, std::vector<const MethodModel*>> methodDefinitions;
    if (metadata != nullptr) {
        for (const auto& type : metadata->types) {
            for (const auto& method : type.methods) {
                if (method.definitionIndex >= 0) methodDefinitions[method.definitionIndex].push_back(&method);
            }
        }
    }

    auto resolveMethod = [&](uint32_t definitionIndex, MetadataUsageEntry& entry) {
        if (metadata == nullptr) {
            failEntry(entry, result, MetadataUsageStatus::Unresolved, "method-definition-table-unavailable", "Method definition table is unavailable");
            return;
        }
        if (definitionIndex > static_cast<uint32_t>(std::numeric_limits<int>::max())) {
            failEntry(entry, result, MetadataUsageStatus::Unresolved, "method-definition-index-overflow", "Method definition index exceeds MethodModel.definitionIndex range");
            return;
        }
        const auto found = methodDefinitions.find(static_cast<int>(definitionIndex));
        if (found == methodDefinitions.end() || found->second.empty()) {
            failEntry(
                entry,
                result,
                MetadataUsageStatus::Unresolved,
                "method-definition-not-found",
                "Method definition " + std::to_string(definitionIndex) + " was not found in MetadataModel");
            return;
        }
        if (found->second.size() != 1) {
            failEntry(
                entry,
                result,
                MetadataUsageStatus::Ambiguous,
                "ambiguous-method-definition",
                "Method definition " + std::to_string(definitionIndex) + " has " +
                    std::to_string(found->second.size()) + " MethodModel records");
            return;
        }
        entry.method = *found->second.front();
        entry.status = MetadataUsageStatus::Resolved;
    };

    auto resolveType = [&](uint32_t typeIndex, MetadataUsageEntry& entry) -> bool {
        if (metadata == nullptr) {
            failEntry(entry, result, MetadataUsageStatus::Unresolved, "type-reference-table-unavailable", "Il2CppType reference table is unavailable");
            return false;
        }
        if (typeIndex >= metadata->typeReferences.size()) {
            failEntry(
                entry,
                result,
                MetadataUsageStatus::Unresolved,
                "type-reference-out-of-range",
                "Il2CppType index " + std::to_string(typeIndex) + " exceeds type reference count " +
                    std::to_string(metadata->typeReferences.size()));
            return false;
        }
        const auto& reference = metadata->typeReferences[typeIndex];
        if (reference.code == 0) {
            failEntry(
                entry,
                result,
                MetadataUsageStatus::Unresolved,
                "null-type-reference",
                "Il2CppType index " + std::to_string(typeIndex) + " is a null type reference");
            return false;
        }
        entry.type = reference;
        return true;
    };

    auto resolvePair = [&](size_t pairIndex) {
        const auto& pair = result.pairs[pairIndex];
        const auto decoded = MetadataUsageReader::decode(pair.encodedSourceIndex);
        MetadataUsageEntry entry;
        entry.kind = decoded.kind;
        entry.sourceIndex = decoded.index;
        entry.destinationIndex = pair.destinationIndex;
        entry.pairIndex = pairIndex;
        entry.listIndices = owners[pairIndex];

        switch (decoded.kind) {
        case MetadataUsageKind::TypeInfo:
        case MetadataUsageKind::Il2CppType:
            if (resolveType(decoded.index, entry)) entry.status = MetadataUsageStatus::Resolved;
            break;
        case MetadataUsageKind::MethodDef:
            if (decoded.index == 0) {
                failEntry(entry, result, MetadataUsageStatus::Unresolved, "null-method-index", "Method metadata index zero resolves to null");
            } else {
                resolveMethod(decoded.index, entry);
            }
            break;
        case MetadataUsageKind::MethodRef:
            entry.genericMethodIndex = decoded.index;
            if (decoded.index == 0) {
                failEntry(entry, result, MetadataUsageStatus::Unresolved, "null-method-index", "Method metadata index zero resolves to null");
            } else if (!genericMethods) {
                failEntry(
                    entry,
                    result,
                    MetadataUsageStatus::Unresolved,
                    "generic-method-table-unavailable",
                    "MethodRef " + std::to_string(decoded.index) + " requires the genericMethodTable extension API");
            } else {
                MetadataUsageGenericMethodResolution resolution;
                try {
                    resolution = genericMethods(decoded.index);
                } catch (...) {
                    failEntry(entry, result, MetadataUsageStatus::Unresolved, "generic-method-resolver-failed", "Generic method resolver threw an exception");
                    break;
                }
                if (resolution.status == MetadataUsageStatus::Resolved) {
                    if (!resolution.methodDefinitionIndex) {
                        failEntry(
                            entry,
                            result,
                            MetadataUsageStatus::Unresolved,
                            "invalid-generic-method-resolution",
                            "Generic method resolver returned Resolved without a method definition index");
                    } else {
                        resolveMethod(*resolution.methodDefinitionIndex, entry);
                    }
                } else {
                    failEntry(
                        entry,
                        result,
                        resolution.status,
                        resolution.status == MetadataUsageStatus::Ambiguous
                            ? "ambiguous-generic-method"
                            : "generic-method-unresolved",
                        resolution.diagnostic.empty()
                            ? "Generic method " + std::to_string(decoded.index) + " could not be resolved"
                            : resolution.diagnostic);
                }
            }
            break;
        case MetadataUsageKind::FieldInfo:
            if (tables.fieldRefsSize == 0) {
                failEntry(entry, result, MetadataUsageStatus::Unresolved, "field-reference-table-unavailable", "Field reference table is unavailable");
            } else if (decoded.index >= fieldRefs.size()) {
                failEntry(
                    entry,
                    result,
                    MetadataUsageStatus::Unresolved,
                    "field-reference-out-of-range",
                    "Field reference index " + std::to_string(decoded.index) + " exceeds field reference count " +
                        std::to_string(fieldRefs.size()));
            } else {
                const auto& fieldRef = fieldRefs[decoded.index];
                if (resolveType(fieldRef.typeIndex, entry)) {
                    const int32_t typeDefinitionIndex = entry.type->definitionIndex;
                    if (typeDefinitionIndex < 0 || static_cast<size_t>(typeDefinitionIndex) >= metadata->types.size()) {
                        failEntry(
                            entry,
                            result,
                            MetadataUsageStatus::Unresolved,
                            "field-declaring-type-unresolved",
                            "Field reference " + std::to_string(decoded.index) + " has no valid declaring type definition");
                    } else {
                        const auto& type = metadata->types[static_cast<size_t>(typeDefinitionIndex)];
                        if (fieldRef.fieldIndex >= type.fields.size()) {
                            failEntry(
                                entry,
                                result,
                                MetadataUsageStatus::Unresolved,
                                "field-index-out-of-range",
                                "Field index " + std::to_string(fieldRef.fieldIndex) +
                                    " exceeds declaring type field count " + std::to_string(type.fields.size()));
                        } else {
                            entry.field = MetadataUsageField{
                                fieldRef.typeIndex,
                                typeDefinitionIndex,
                                fieldRef.fieldIndex,
                                type.fields[fieldRef.fieldIndex]
                            };
                            entry.status = MetadataUsageStatus::Resolved;
                        }
                    }
                }
            }
            break;
        case MetadataUsageKind::StringLiteral:
            if (metadata == nullptr) {
                failEntry(entry, result, MetadataUsageStatus::Unresolved, "string-literal-table-unavailable", "String literal table is unavailable");
            } else {
                const auto literal = metadata->stringLiterals.find(decoded.index);
                if (literal == metadata->stringLiterals.end()) {
                    failEntry(
                        entry,
                        result,
                        MetadataUsageStatus::Unresolved,
                        "string-literal-not-found",
                        "String literal " + std::to_string(decoded.index) + " was not found in MetadataModel");
                } else {
                    entry.stringLiteral = literal->second;
                    entry.status = MetadataUsageStatus::Resolved;
                }
            }
            break;
        case MetadataUsageKind::Invalid:
        default:
            failEntry(
                entry,
                result,
                MetadataUsageStatus::Unresolved,
                "invalid-metadata-usage-kind",
                "Encoded source has invalid kIl2CppMetadataUsage value " +
                    std::to_string(static_cast<unsigned>(decoded.kind)));
            break;
        }
        result.entries.push_back(std::move(entry));
    };

    if (selectedList) {
        const auto& list = result.lists[*selectedList];
        const size_t end = static_cast<size_t>(static_cast<uint64_t>(list.start) + list.count);
        for (size_t pairIndex = list.start; pairIndex < end; ++pairIndex) resolvePair(pairIndex);
    } else {
        for (size_t pairIndex = 0; pairIndex < pairCount; ++pairIndex) resolvePair(pairIndex);
    }

    std::unordered_map<uint32_t, uint32_t> sourceByDestination;
    std::unordered_set<uint32_t> conflictingDestinations;
    for (const auto& entry : result.entries) {
        const uint32_t encodedSource = result.pairs[entry.pairIndex].encodedSourceIndex;
        const auto [position, inserted] = sourceByDestination.try_emplace(entry.destinationIndex, encodedSource);
        if (!inserted && position->second != encodedSource) conflictingDestinations.insert(entry.destinationIndex);
    }
    if (!conflictingDestinations.empty()) {
        for (auto& entry : result.entries) {
            if (!conflictingDestinations.contains(entry.destinationIndex)) continue;
            failEntry(
                entry,
                result,
                MetadataUsageStatus::Ambiguous,
                "conflicting-destination-index",
                "Destination " + std::to_string(entry.destinationIndex) + " is initialized from conflicting encoded sources");
        }
    }

    for (const auto& entry : result.entries) {
        switch (entry.status) {
        case MetadataUsageStatus::Resolved: ++result.resolvedCount; break;
        case MetadataUsageStatus::Ambiguous: ++result.ambiguousCount; break;
        case MetadataUsageStatus::Unresolved: ++result.unresolvedCount; break;
        }
    }
    if (result.unresolvedCount != 0) result.status = MetadataUsageStatus::Unresolved;
    else if (result.ambiguousCount != 0) result.status = MetadataUsageStatus::Ambiguous;
    else result.status = MetadataUsageStatus::Resolved;
    return result;
}

MetadataUsageTableView versionedView(const std::vector<uint8_t>& data, const MetadataUsageHeaderInfo& header) {
    MetadataUsageTableView view;
    view.data = data.data();
    view.size = data.size();
    view.listsOffset = header.metadataUsageLists.offset;
    view.listsSize = header.metadataUsageLists.size;
    view.pairsOffset = header.metadataUsagePairs.offset;
    view.pairsSize = header.metadataUsagePairs.size;
    view.fieldRefsOffset = header.fieldRefs.offset;
    view.fieldRefsSize = header.fieldRefs.size;
    return view;
}

} // namespace

MetadataUsageHeaderResult readMetadataUsageHeader(const std::vector<uint8_t>& globalMetadata, double version) {
    MetadataUsageHeaderResult result;
    result.ok = parseVersionedHeader(globalMetadata, version, result.header, result.diagnostics);
    return result;
}

MetadataUsageSignatureResult readUnresolvedSignatures(
    const std::vector<uint8_t>& globalMetadata,
    double version,
    const MetadataModel& metadata) {
    MetadataUsageSignatureResult result;
    MetadataUsageHeaderInfo header;
    if (!parseVersionedHeader(globalMetadata, version, header, result.diagnostics)) return result;

    const auto& types = header.unresolvedVirtualCallParameterTypes;
    const auto& ranges = header.unresolvedVirtualCallParameterRanges;
    if (types.size % header.typeIndexWidth != 0 || ranges.size % 8 != 0) {
        addDiagnostic(result.diagnostics, MetadataUsageStatus::Unresolved, "misaligned-signature-table", "Unresolved signature tables have invalid element strides");
        return result;
    }
    const size_t typeCount = types.size / header.typeIndexWidth;
    const size_t rangeCount = ranges.size / 8;
    result.tablesValid = true;
    result.signatures.reserve(rangeCount);
    for (size_t rangeIndex = 0; rangeIndex < rangeCount; ++rangeIndex) {
        const size_t offset = ranges.offset + rangeIndex * 8;
        const int32_t start = readI32(globalMetadata.data(), offset);
        const int32_t length = readI32(globalMetadata.data(), offset + 4);
        MetadataUsageSignature signature;
        signature.rangeIndex = static_cast<uint32_t>(rangeIndex);
        if (length < 0 || (length > 0 && start < 0)) {
            signature.diagnostic = "Unresolved signature has a negative parameter range";
            result.tablesValid = false;
            addDiagnostic(result.diagnostics, MetadataUsageStatus::Unresolved, "invalid-signature-range", signature.diagnostic, static_cast<uint32_t>(rangeIndex));
            result.signatures.push_back(std::move(signature));
            continue;
        }
        if (length == 0) {
            signature.status = MetadataUsageStatus::Resolved;
            result.signatures.push_back(std::move(signature));
            continue;
        }
        const uint64_t end = static_cast<uint64_t>(static_cast<uint32_t>(start)) + static_cast<uint32_t>(length);
        if (end > typeCount) {
            signature.diagnostic = "Unresolved signature parameter range exceeds the type table";
            result.tablesValid = false;
            addDiagnostic(result.diagnostics, MetadataUsageStatus::Unresolved, "signature-range-out-of-bounds", signature.diagnostic, static_cast<uint32_t>(rangeIndex));
            result.signatures.push_back(std::move(signature));
            continue;
        }

        signature.status = MetadataUsageStatus::Resolved;
        for (uint32_t parameter = 0; parameter < static_cast<uint32_t>(length); ++parameter) {
            const size_t element = static_cast<size_t>(start) + parameter;
            const uint32_t typeIndex = readVariableIndex(
                globalMetadata.data(), types.offset + element * header.typeIndexWidth, header.typeIndexWidth);
            if (typeIndex >= metadata.typeReferences.size() || metadata.typeReferences[typeIndex].code == 0) {
                signature.status = MetadataUsageStatus::Unresolved;
                signature.diagnostic = "Unresolved signature parameter " + std::to_string(parameter) +
                    " has invalid Il2CppType index " + std::to_string(typeIndex);
                signature.parameterTypes.clear();
                addDiagnostic(
                    result.diagnostics,
                    MetadataUsageStatus::Unresolved,
                    "unresolved-signature-type",
                    signature.diagnostic,
                    static_cast<uint32_t>(rangeIndex));
                break;
            }
            signature.parameterTypes.push_back(metadata.typeReferences[typeIndex]);
        }
        result.signatures.push_back(std::move(signature));
    }
    return result;
}

bool MetadataUsageResult::ok() const {
    return tablesValid && status == MetadataUsageStatus::Resolved;
}

MetadataUsageResolver::MetadataUsageResolver(const MetadataModel& metadata, MetadataUsageResult usages)
    : metadata_(&metadata), usages_(std::move(usages)) {
}

const MetadataUsageResult& MetadataUsageResolver::usages() const {
    return usages_;
}

const MetadataUsageEntry* MetadataUsageResolver::findDestination(uint32_t destinationIndex) const {
    for (const auto& entry : usages_.entries) {
        if (entry.destinationIndex == destinationIndex) return &entry;
    }
    return nullptr;
}

MetadataUsageLinkResult MetadataUsageResolver::link(const MetadataUsageLinkOptions& options) const {
    MetadataUsageLinkResult result;
    result.metadata = *metadata_;
    result.managed = options.managed;
    result.virtualDispatch = options.virtualDispatch;
    result.diagnostics = usages_.diagnostics;

    GenericMethodResolver genericMethods(*metadata_);
    std::unordered_map<int32_t, std::pair<size_t, size_t>> methodLocations;
    std::unordered_set<int32_t> duplicateMethodLocations;
    for (size_t typeIndex = 0; typeIndex < metadata_->types.size(); ++typeIndex) {
        const auto& methods = metadata_->types[typeIndex].methods;
        for (size_t methodIndex = 0; methodIndex < methods.size(); ++methodIndex) {
            const int32_t definitionIndex = methods[methodIndex].definitionIndex;
            if (definitionIndex < 0) continue;
            const auto [position, inserted] = methodLocations.try_emplace(definitionIndex, typeIndex, methodIndex);
            if (!inserted && position->second != std::make_pair(typeIndex, methodIndex)) {
                duplicateMethodLocations.insert(definitionIndex);
            }
        }
    }

    std::unordered_set<uint32_t> inflatedMethods;
    for (const auto& mapping : metadata_->genericMethodTable) {
        if (mapping.genericMethodIndex < 0) continue;
        const auto genericIndex = static_cast<uint32_t>(mapping.genericMethodIndex);
        if (!inflatedMethods.insert(genericIndex).second) continue;
        const auto target = genericMethods.resolve(genericIndex);
        if (target.status != MetadataUsageStatus::Resolved || !target.methodDefinitionIndex ||
            !target.mapping || target.mapping->methodPointer == 0 ||
            duplicateMethodLocations.contains(*target.methodDefinitionIndex)) {
            continue;
        }
        const auto location = methodLocations.find(*target.methodDefinitionIndex);
        if (location == methodLocations.end()) continue;
        auto& methods = result.metadata.types[location->second.first].methods;
        auto inflated = methods[location->second.second];
        inflated.address = target.mapping->methodPointer;
        methods.push_back(std::move(inflated));
    }

    auto addDiagnostic = [&](MetadataUsageStatus status, std::string code, std::string message,
                             const MetadataUsageEntry* entry = nullptr) {
        std::optional<uint32_t> listIndex;
        std::optional<size_t> pairIndex;
        std::optional<uint32_t> destinationIndex;
        if (entry != nullptr) {
            if (entry->listIndices.size() == 1) listIndex = entry->listIndices.front();
            pairIndex = entry->pairIndex;
            destinationIndex = entry->destinationIndex;
        }
        result.diagnostics.push_back({status, std::move(code), std::move(message), listIndex, pairIndex, destinationIndex});
    };

    for (const auto& entry : usages_.entries) {
        const auto address = options.destinationAddresses.find(entry.destinationIndex);
        if (address == options.destinationAddresses.end() || address->second == 0) continue;
        if (entry.status != MetadataUsageStatus::Resolved) continue;

        switch (entry.kind) {
        case MetadataUsageKind::StringLiteral: {
            if (!entry.stringLiteral) {
                addDiagnostic(MetadataUsageStatus::Unresolved, "string-literal-link-unavailable", "Resolved string literal destination has no literal value", &entry);
                break;
            }
            const auto [position, inserted] = result.managed.stringLiteralAddresses.try_emplace(entry.sourceIndex, address->second);
            if (!inserted && position->second != address->second) {
                addDiagnostic(
                    MetadataUsageStatus::Ambiguous,
                    "ambiguous-string-literal-address",
                    "String literal " + std::to_string(entry.sourceIndex) + " has multiple native destination addresses",
                    &entry);
            }
            break;
        }
        case MetadataUsageKind::TypeInfo:
        case MetadataUsageKind::Il2CppType: {
            const auto name = TypeSystem::resolve(entry.sourceIndex, *metadata_);
            if (name.empty()) {
                addDiagnostic(MetadataUsageStatus::Unresolved, "type-name-unresolved", "TypeInfo destination has no resolved managed type name", &entry);
                break;
            }
            const auto [position, inserted] = result.managed.runtimeTypeAddresses.try_emplace(address->second, name);
            if (!inserted && position->second != name) {
                addDiagnostic(
                    MetadataUsageStatus::Ambiguous,
                    "ambiguous-runtime-type-address",
                    "Native type destination resolves to conflicting managed type names",
                    &entry);
            }
            break;
        }
        case MetadataUsageKind::MethodRef: {
            const auto target = genericMethods.resolve(*entry.genericMethodIndex);
            if (target.status != MetadataUsageStatus::Resolved || !target.mapping) {
                addDiagnostic(
                    target.status,
                    "inflated-method-target-unresolved",
                    target.diagnostic.empty() ? "Generic inflated method target is unresolved" : target.diagnostic,
                    &entry);
                break;
            }
            if (target.mapping->methodPointer == 0) {
                addDiagnostic(
                    MetadataUsageStatus::Unresolved,
                    "inflated-method-pointer-unavailable",
                    "Generic method " + std::to_string(*entry.genericMethodIndex) + " has no inflated native method pointer",
                    &entry);
                break;
            }
            const auto [position, inserted] = result.virtualDispatch.methodInfoTargets.try_emplace(
                address->second, target.mapping->methodPointer);
            if (!inserted && position->second != target.mapping->methodPointer) {
                addDiagnostic(
                    MetadataUsageStatus::Ambiguous,
                    "ambiguous-inflated-method-target",
                    "MethodInfo destination maps to conflicting inflated native targets",
                    &entry);
                break;
            }
            result.virtualDispatch.genericMethodInfo.insert(address->second);
            break;
        }
        case MetadataUsageKind::MethodDef:
            break;
        case MetadataUsageKind::FieldInfo:
            if (!entry.field || entry.field->typeDefinitionIndex < 0 ||
                static_cast<size_t>(entry.field->typeDefinitionIndex) >= result.metadata.types.size() ||
                entry.field->fieldIndex >= result.metadata.types[static_cast<size_t>(entry.field->typeDefinitionIndex)].fields.size()) {
                addDiagnostic(MetadataUsageStatus::Unresolved, "field-info-link-unavailable", "Resolved FieldInfo destination has no valid analysis field", &entry);
            } else {
                result.metadata.types[static_cast<size_t>(entry.field->typeDefinitionIndex)].fields[entry.field->fieldIndex] =
                    entry.field->field;
            }
            break;
        case MetadataUsageKind::Invalid:
        default:
            addDiagnostic(MetadataUsageStatus::Unresolved, "invalid-metadata-usage-link", "Invalid usage kind cannot be linked", &entry);
            break;
        }
    }

    for (const uint32_t destination : options.requiredDestinations) {
        const auto* entry = findDestination(destination);
        if (entry == nullptr) {
            addDiagnostic(
                MetadataUsageStatus::Unresolved,
                "metadata-usage-destination-not-found",
                "Required MetadataUsage destination " + std::to_string(destination) + " was not found");
            continue;
        }
        const auto address = options.destinationAddresses.find(destination);
        if (address == options.destinationAddresses.end() || address->second == 0) {
            addDiagnostic(
                MetadataUsageStatus::Unresolved,
                "metadata-usage-destination-address-unavailable",
                "Required MetadataUsage destination " + std::to_string(destination) + " has no native address",
                entry);
        }
    }
    return result;
}

MetadataUsageManagedResult MetadataUsageResolver::analyzeManaged(
    const RecoveredFunction& function,
    const MetadataUsageLinkOptions& options) const {
    auto linked = link(options);
    MetadataUsageManagedResult result;
    result.analysis = ManagedPatterns{}.analyze(function, linked.metadata, linked.managed);
    result.diagnostics = std::move(linked.diagnostics);
    return result;
}

MetadataUsageVirtualResult MetadataUsageResolver::analyzeVirtualDispatch(
    const RecoveredFunction& function,
    const MetadataUsageLinkOptions& options) const {
    auto linked = link(options);
    MetadataUsageVirtualResult result;
    result.analysis = VirtualDispatch{}.analyze(function, linked.metadata, linked.virtualDispatch);
    result.diagnostics = std::move(linked.diagnostics);
    return result;
}

const char* toString(MetadataUsageKind kind) {
    switch (kind) {
    case MetadataUsageKind::Invalid: return "invalid";
    case MetadataUsageKind::TypeInfo: return "typeInfo";
    case MetadataUsageKind::Il2CppType: return "il2cppType";
    case MetadataUsageKind::MethodDef: return "methodDef";
    case MetadataUsageKind::FieldInfo: return "fieldInfo";
    case MetadataUsageKind::StringLiteral: return "stringLiteral";
    case MetadataUsageKind::MethodRef: return "methodRef";
    }
    return "unknown";
}

const char* toString(MetadataUsageStatus status) {
    switch (status) {
    case MetadataUsageStatus::Resolved: return "resolved";
    case MetadataUsageStatus::Ambiguous: return "ambiguous";
    case MetadataUsageStatus::Unresolved: return "unresolved";
    }
    return "unresolved";
}

MetadataUsageEncoded MetadataUsageReader::decode(uint32_t encodedSourceIndex) {
    return {
        static_cast<MetadataUsageKind>(encodedSourceIndex >> usageShift),
        encodedSourceIndex & indexMask
    };
}

MetadataUsageResult MetadataUsageReader::read(
    const MetadataUsageTableView& tables,
    const MetadataModel* metadata,
    const MetadataUsageGenericMethodResolver& genericMethods) const {
    return readImpl(tables, metadata, genericMethods, std::nullopt);
}

MetadataUsageResult MetadataUsageReader::readUnity2017(
    const std::vector<uint8_t>& globalMetadata,
    const MetadataModel* metadata,
    const MetadataUsageGenericMethodResolver& genericMethods) const {
    MetadataUsageTableView view;
    MetadataUsageResult error;
    if (!makeUnity2017View(globalMetadata, view, error)) return error;
    return readImpl(view, metadata, genericMethods, std::nullopt);
}

MetadataUsageResult MetadataUsageReader::readVersioned(
    const std::vector<uint8_t>& globalMetadata,
    double version,
    const MetadataModel* metadata,
    const MetadataUsageGenericMethodResolver& genericMethods) const {
    MetadataUsageHeaderInfo header;
    MetadataUsageResult error;
    if (!parseVersionedHeader(globalMetadata, version, header, error.diagnostics)) return error;
    return readImpl(versionedView(globalMetadata, header), metadata, genericMethods, std::nullopt);
}

MetadataUsageResult MetadataUsageReader::initializeMethodMetadata(
    const MetadataUsageTableView& tables,
    uint32_t listIndex,
    const MetadataModel* metadata,
    const MetadataUsageGenericMethodResolver& genericMethods) const {
    return readImpl(tables, metadata, genericMethods, listIndex);
}

MetadataUsageResult MetadataUsageReader::initializeMethodMetadataUnity2017(
    const std::vector<uint8_t>& globalMetadata,
    uint32_t listIndex,
    const MetadataModel* metadata,
    const MetadataUsageGenericMethodResolver& genericMethods) const {
    MetadataUsageTableView view;
    MetadataUsageResult error;
    if (!makeUnity2017View(globalMetadata, view, error)) return error;
    return readImpl(view, metadata, genericMethods, listIndex);
}

MetadataUsageResult MetadataUsageReader::initializeMethodMetadataVersioned(
    const std::vector<uint8_t>& globalMetadata,
    double version,
    uint32_t listIndex,
    const MetadataModel* metadata,
    const MetadataUsageGenericMethodResolver& genericMethods) const {
    MetadataUsageHeaderInfo header;
    MetadataUsageResult error;
    if (!parseVersionedHeader(globalMetadata, version, header, error.diagnostics)) return error;
    return readImpl(versionedView(globalMetadata, header), metadata, genericMethods, listIndex);
}

} // namespace il2cpprec
