#include <il2cpprec/metadata/MethodResolver.hpp>

#include <il2cpprec/metadata/CodeGenModules.hpp>

#include <algorithm>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint32_t methodTokenType = 0x06000000;
constexpr uint32_t tokenRowIdMask = 0x00FFFFFF;

struct PointerLookup {
    uint64_t pointer = 0;
    std::optional<size_t> index;
    std::optional<MethodResolutionError> error;
};

struct AddressLocation {
    uint64_t address = 0;
    size_t sectionIndex = 0;
    size_t fileOffset = 0;
};

struct ResolvedFunction {
    FunctionImage image;
    size_t sectionIndex = 0;
    size_t fileOffset = 0;
};

std::string methodName(const MethodModel& method) {
    if (method.declaringType.empty()) return method.name;
    return method.declaringType + "__" + method.name;
}

std::string dumperMethodName(const MethodModel& method) {
    if (method.declaringType.empty()) return method.name;
    return method.declaringType + "$$" + method.name;
}

std::string diagnosticFor(MethodResolutionError error) {
    switch (error) {
    case MethodResolutionError::MissingDefinitionIndex:
        return "method has no metadata definition index";
    case MethodResolutionError::MissingMethodPointerTable:
        return "no non-empty method pointer table was found for the method image";
    case MethodResolutionError::UnsupportedLegacyMapping:
        return "legacy method pointer mapping is unavailable";
    case MethodResolutionError::MissingMethodIndex:
        return "legacy method has no global method pointer index";
    case MethodResolutionError::InvalidMethodToken:
        return "per-image method pointers require a non-zero MethodDef token row id";
    case MethodResolutionError::InvalidGeneratedMethodToken:
        return "generated method token does not match its definition index";
    case MethodResolutionError::DuplicateMethodToken:
        return "MethodDef token is duplicated within its image";
    case MethodResolutionError::PointerIndexOutOfRange:
        return "method pointer index is outside the image method pointer table";
    case MethodResolutionError::NullPointer:
        return "method pointer is null";
    case MethodResolutionError::UnmappedAddress:
        return "method pointer does not identify a file-backed virtual address";
    case MethodResolutionError::NonExecutableAddress:
        return "method pointer identifies a non-executable section";
    }
    return "method pointer could not be resolved";
}

uint64_t normalizePointer(const BinaryImage& binary, uint64_t pointer) {
    pointer &= 0x0000FFFFFFFFFFFFULL;
    if (binary.architecture == Architecture::Arm32) pointer &= ~uint64_t{1};
    return pointer;
}

std::optional<AddressLocation> findSectionRVA(const BinaryImage& binary, uint64_t rva) {
    if (!binary.bytes) return std::nullopt;
    for (size_t index = 0; index < binary.sections.size(); ++index) {
        const auto& section = binary.sections[index];
        if (rva < section.virtualAddress) continue;
        const auto offset = rva - section.virtualAddress;
        if (offset >= section.fileSize || section.fileOffset >= binary.bytes->size()) continue;
        if (offset >= binary.bytes->size() - static_cast<size_t>(section.fileOffset)) continue;
        return AddressLocation{0, index, static_cast<size_t>(section.fileOffset + offset)};
    }
    return std::nullopt;
}

bool addOverflows(uint64_t left, uint64_t right) {
    return left > std::numeric_limits<uint64_t>::max() - right;
}

bool usesRelativeSections(const BinaryImage& binary) {
    if (binary.format == BinaryFormat::PE) return true;
    if (binary.imageBase == 0) return false;
    return std::any_of(binary.sections.begin(), binary.sections.end(), [&](const Section& section) {
        return section.fileSize != 0 && section.virtualAddress < binary.imageBase;
    });
}

std::optional<AddressLocation> locateAddress(const BinaryImage& binary, uint64_t pointer) {
    pointer = normalizePointer(binary, pointer);
    if (pointer == 0) return std::nullopt;

    if (usesRelativeSections(binary)) {
        if (pointer >= binary.imageBase) {
            auto location = findSectionRVA(binary, pointer - binary.imageBase);
            if (location) {
                location->address = pointer;
                return location;
            }
        }

        auto location = findSectionRVA(binary, pointer);
        if (!location || addOverflows(binary.imageBase, pointer)) return std::nullopt;
        location->address = binary.imageBase + pointer;
        return location;
    }

    auto location = findSectionRVA(binary, pointer);
    if (location) {
        location->address = pointer;
        return location;
    }

    if (pointer >= binary.imageBase) {
        location = findSectionRVA(binary, pointer - binary.imageBase);
        if (location) {
            location->address = pointer;
            return location;
        }
    }

    if (addOverflows(binary.imageBase, pointer)) return std::nullopt;
    const auto absoluteAddress = binary.imageBase + pointer;
    location = findSectionRVA(binary, absoluteAddress);
    if (location) location->address = absoluteAddress;
    return location;
}

PointerLookup methodPointer(const MethodModel& method, const MetadataModel& metadata) {
    PointerLookup result;
    if (metadata.version >= 110.0 && metadata.generatedMethodsStart >= 0 &&
        method.definitionIndex >= metadata.generatedMethodsStart) {
        const auto tokenIndex = static_cast<size_t>(method.definitionIndex - metadata.generatedMethodsStart);
        if (tokenIndex >= metadata.generatedMethodTokens.size() ||
            metadata.generatedMethodTokens[tokenIndex].token != method.token) {
            result.error = MethodResolutionError::InvalidGeneratedMethodToken;
            return result;
        }
    }
    const auto image = metadata.methodPointersByImage.find(method.imageName);
    if (image == metadata.methodPointersByImage.end() || image->second.empty()) {
        result.error = MethodResolutionError::MissingMethodPointerTable;
        return result;
    }

    if (metadata.version != 0 && metadata.version < 24.2) {
        if (method.methodIndex < 0) {
            result.error = MethodResolutionError::MissingMethodIndex;
            return result;
        }
        result.index = static_cast<size_t>(method.methodIndex);
    } else {
        if (method.definitionIndex < 0) {
            result.error = MethodResolutionError::MissingDefinitionIndex;
            return result;
        }
        const auto rowId = method.token & tokenRowIdMask;
        if ((method.token & ~tokenRowIdMask) != methodTokenType || rowId == 0) {
            result.error = MethodResolutionError::InvalidMethodToken;
            return result;
        }
        result.index = static_cast<size_t>(rowId - 1);
    }

    if (*result.index >= image->second.size()) {
        result.error = MethodResolutionError::PointerIndexOutOfRange;
        return result;
    }
    result.pointer = image->second[*result.index];
    return result;
}

size_t sectionFileEnd(const BinaryImage& binary, const Section& section) {
    if (!binary.bytes || section.fileOffset >= binary.bytes->size()) return 0;
    const auto offset = static_cast<size_t>(section.fileOffset);
    const auto available = binary.bytes->size() - offset;
    const auto declaredSize = section.fileSize > available ? available : static_cast<size_t>(section.fileSize);
    return offset + declaredSize;
}

size_t nativePointerSize(const BinaryImage& binary) {
    return binary.architecture == Architecture::X86 || binary.architecture == Architecture::Arm32 ? 4 : 8;
}

uint64_t readNativeOffset(const BinaryImage& binary, size_t offset, size_t size) {
    uint64_t value = 0;
    for (size_t index = 0; index < size; ++index) {
        value |= static_cast<uint64_t>((*binary.bytes)[offset + index]) << (index * 8);
    }
    return value;
}

std::optional<size_t> mappedRange(const BinaryImage& binary, uint64_t address, size_t size) {
    const auto location = locateAddress(binary, address);
    if (!location) return std::nullopt;
    const auto end = sectionFileEnd(binary, binary.sections[location->sectionIndex]);
    if (location->fileOffset > end || size > end - location->fileOffset) return std::nullopt;
    return location->fileOffset;
}

bool moduleNameMatches(const BinaryImage& binary, uint64_t address, const std::string& expected) {
    const auto offset = mappedRange(binary, address, 1);
    if (!offset) return false;
    const auto location = locateAddress(binary, address);
    const auto end = sectionFileEnd(binary, binary.sections[location->sectionIndex]);
    const auto limit = std::min(end - *offset, size_t{1025});
    for (size_t index = 0; index < limit; ++index) {
        const auto value = (*binary.bytes)[*offset + index];
        if (value == 0) return index == expected.size() &&
            std::equal(expected.begin(), expected.end(), binary.bytes->begin() + static_cast<std::ptrdiff_t>(*offset));
        if (index >= expected.size() || value != static_cast<uint8_t>(expected[index])) return false;
    }
    return false;
}

bool methodTableMatches(
    const BinaryImage& binary,
    uint64_t address,
    const std::vector<uint64_t>& expected) {
    const auto pointerBytes = nativePointerSize(binary);
    if (expected.size() > std::numeric_limits<size_t>::max() / pointerBytes) return false;
    const auto offset = mappedRange(binary, address, expected.size() * pointerBytes);
    if (!offset) return false;
    for (size_t index = 0; index < expected.size(); ++index) {
        const auto pointer = readNativeOffset(binary, *offset + index * pointerBytes, pointerBytes);
        if (normalizePointer(binary, pointer) != normalizePointer(binary, expected[index])) return false;
    }
    return true;
}

bool supportsAdjustorThunks(double version) {
    return version >= 24.5 && version != 27.0;
}

void discoverAdjustorThunks(
    const BinaryImage& binary,
    MethodResolutionResult& result) {
    const auto& metadata = result.metadata;
    if (metadata.version < 24.2 || !supportsAdjustorThunks(metadata.version) || !binary.bytes) return;

    // Registration readers can provide token/pointer pairs directly. A token is
    // only an identity when it occurs in exactly one image.
    std::map<uint32_t, const MethodModel*> uniqueTokens;
    std::set<uint32_t> ambiguousTokens;
    for (const auto& type : metadata.types) {
        for (const auto& method : type.methods) {
            if (method.token == 0) continue;
            if (!uniqueTokens.emplace(method.token, &method).second) ambiguousTokens.insert(method.token);
        }
    }
    for (const auto& thunk : metadata.adjustorThunks) {
        if (ambiguousTokens.contains(thunk.token) || !uniqueTokens.contains(thunk.token)) {
            result.report.auxiliaryDiagnostics.push_back("adjustor thunk token has no unique method identity: " +
                std::to_string(thunk.token));
            continue;
        }
        const auto location = locateAddress(binary, thunk.address);
        if (!location || !binary.sections[location->sectionIndex].executable) {
            result.report.auxiliaryDiagnostics.push_back("adjustor thunk points outside executable code");
            continue;
        }
        const auto& method = *uniqueTokens.at(thunk.token);
        MethodAddressMetadata exported;
        exported.fullName = dumperMethodName(method);
        exported.token = method.token;
        exported.imageName = method.imageName;
        exported.declaringType = method.declaringType;
        exported.methodIndex = method.methodIndex;
        const auto existing = result.adjustorThunkMapping.find(location->address);
        if (existing == result.adjustorThunkMapping.end()) {
            result.adjustorThunkMapping.emplace(location->address, std::move(exported));
        } else if (existing->second.token != exported.token ||
                   existing->second.imageName != exported.imageName) {
            result.report.auxiliaryDiagnostics.push_back("conflicting adjustor thunk address: " +
                std::to_string(location->address));
        }
    }
    const auto pointerBytes = nativePointerSize(binary);
    if (binary.bytes->size() < 5 * pointerBytes) return;

    std::unordered_map<uint64_t, std::vector<std::string>> imagesByCount;
    for (const auto& [name, pointers] : metadata.methodPointersByImage) {
        if (!pointers.empty()) imagesByCount[pointers.size()].push_back(name);
    }

    std::map<std::pair<std::string, uint32_t>, const MethodModel*> identities;
    for (const auto& type : metadata.types) {
        for (const auto& method : type.methods) identities.try_emplace({method.imageName, method.token}, &method);
    }

    std::map<std::string, bool> completed;
    for (size_t offset = 0; offset <= binary.bytes->size() - 5 * pointerBytes; offset += pointerBytes) {
        const auto count = readNativeOffset(binary, offset + pointerBytes, pointerBytes);
        const auto candidates = imagesByCount.find(count);
        if (candidates == imagesByCount.end()) continue;

        const auto namePointer = readNativeOffset(binary, offset, pointerBytes);
        const auto methodPointers = readNativeOffset(binary, offset + 2 * pointerBytes, pointerBytes);
        for (const auto& name : candidates->second) {
            if (completed.contains(name) || !moduleNameMatches(binary, namePointer, name) ||
                !methodTableMatches(binary, methodPointers, metadata.methodPointersByImage.at(name))) {
                continue;
            }
            completed.emplace(name, true);

            const auto thunkCount = readNativeOffset(binary, offset + 3 * pointerBytes, pointerBytes);
            const auto thunkTable = readNativeOffset(binary, offset + 4 * pointerBytes, pointerBytes);
            if (thunkCount == 0) continue;
            if (thunkCount > 1000000) {
                result.report.auxiliaryDiagnostics.push_back(name + " adjustor thunk count exceeds the supported limit");
                continue;
            }
            const auto stride = pointerBytes == 8 ? size_t{16} : size_t{8};
            if (thunkCount > std::numeric_limits<size_t>::max() / stride) continue;
            const auto tableOffset = mappedRange(binary, thunkTable, static_cast<size_t>(thunkCount) * stride);
            if (!tableOffset) {
                result.report.auxiliaryDiagnostics.push_back(name + " adjustor thunk table is not file-backed");
                continue;
            }

            for (size_t index = 0; index < thunkCount; ++index) {
                const auto entry = *tableOffset + index * stride;
                const auto token = static_cast<uint32_t>(readNativeOffset(binary, entry, 4));
                const auto pointer = readNativeOffset(binary, entry + (pointerBytes == 8 ? 8 : 4), pointerBytes);
                if (normalizePointer(binary, pointer) == 0) continue;
                const auto location = locateAddress(binary, pointer);
                if (!location || !binary.sections[location->sectionIndex].executable) {
                    result.report.auxiliaryDiagnostics.push_back(name + " adjustor thunk points outside executable code");
                    continue;
                }

                MethodAddressMetadata exported;
                exported.token = token;
                exported.imageName = name;
                const auto identity = identities.find({name, token});
                if (identity != identities.end()) {
                    exported.fullName = dumperMethodName(*identity->second);
                    exported.declaringType = identity->second->declaringType;
                    exported.methodIndex = identity->second->methodIndex;
                } else {
                    exported.fullName = name + "$$AdjustorThunk_" + std::to_string(token);
                }
                const auto existing = result.adjustorThunkMapping.find(location->address);
                if (existing == result.adjustorThunkMapping.end()) {
                    result.adjustorThunkMapping.emplace(location->address, std::move(exported));
                } else if (existing->second.token != exported.token ||
                           existing->second.imageName != exported.imageName) {
                    result.report.auxiliaryDiagnostics.push_back(name + " conflicting adjustor thunk address: " +
                        std::to_string(location->address));
                }
            }
        }
    }
    result.report.adjustorThunks = result.adjustorThunkMapping.size();
}

struct UnresolvedLayout {
    size_t countField = 0;
    size_t virtualTableField = 0;
    bool splitInstanceAndStatic = false;
};

UnresolvedLayout unresolvedLayout(double version) {
    size_t field = 0;
    const auto consume = [&](bool present, size_t count = 1) {
        if (present) field += count;
    };
    consume(version <= 24.1, 2);
    consume(true, 2);
    consume(version <= 22.0, 2);
    consume(version <= 22.0, 2);
    consume(version >= 21.0 && version <= 22.0, 2);
    consume(true, 2);
    consume(supportsAdjustorThunks(version));
    consume(true, 2);
    consume(version <= 24.5, 2);
    consume(version >= 21.0 && version <= 22.0, 2);
    return {field, field + 1, version >= 29.1 && version != 31.0};
}

std::string unresolvedStubPrefix(UnresolvedStubKind kind) {
    switch (kind) {
    case UnresolvedStubKind::Virtual: return "UnresolvedVirtualCall_";
    case UnresolvedStubKind::Instance: return "UnresolvedInstanceCall_";
    case UnresolvedStubKind::Static: return "UnresolvedStaticCall_";
    }
    return "UnresolvedCall_";
}

void discoverUnresolvedStubs(
    const BinaryImage& binary,
    MethodResolutionResult& result) {
    const auto& metadata = result.metadata;
    if (metadata.version < 22.0 || metadata.codeRegistrationAddress == 0 || !binary.bytes) return;
    const auto pointerBytes = nativePointerSize(binary);
    const auto layout = unresolvedLayout(metadata.version);
    const auto registration = locateAddress(binary, metadata.codeRegistrationAddress);
    if (!registration) {
        result.report.auxiliaryDiagnostics.push_back("code registration is not file-backed");
        return;
    }
    const auto readField = [&](size_t field) -> std::optional<uint64_t> {
        if (field > std::numeric_limits<size_t>::max() / pointerBytes) return std::nullopt;
        const auto offset = registration->fileOffset + field * pointerBytes;
        const auto end = sectionFileEnd(binary, binary.sections[registration->sectionIndex]);
        if (offset > end || pointerBytes > end - offset) return std::nullopt;
        return readNativeOffset(binary, offset, pointerBytes);
    };

    const auto count = readField(layout.countField);
    const auto virtualTable = readField(layout.virtualTableField);
    if (!count || !virtualTable) {
        result.report.auxiliaryDiagnostics.push_back("unresolved call registration is truncated");
        return;
    }
    if (*count == 0) return;
    if (*count > 1000000) {
        result.report.auxiliaryDiagnostics.push_back("unresolved call count exceeds the supported limit");
        return;
    }

    const auto readTable = [&](uint64_t tableAddress, UnresolvedStubKind kind) {
        if (tableAddress == 0) return;
        if (*count > std::numeric_limits<size_t>::max() / pointerBytes) return;
        const auto tableOffset = mappedRange(binary, tableAddress, static_cast<size_t>(*count) * pointerBytes);
        if (!tableOffset) {
            result.report.auxiliaryDiagnostics.push_back(unresolvedStubPrefix(kind) + "table is not file-backed");
            return;
        }
        for (size_t index = 0; index < *count; ++index) {
            const auto pointer = readNativeOffset(binary, *tableOffset + index * pointerBytes, pointerBytes);
            if (normalizePointer(binary, pointer) == 0) continue;
            if (index >= tokenRowIdMask) {
                result.report.auxiliaryDiagnostics.push_back(unresolvedStubPrefix(kind) + "index exceeds signature token range");
                continue;
            }
            const auto location = locateAddress(binary, pointer);
            if (!location || !binary.sections[location->sectionIndex].executable) {
                result.report.auxiliaryDiagnostics.push_back(unresolvedStubPrefix(kind) + "entry points outside executable code");
                continue;
            }
            UnresolvedStub stub;
            stub.address = location->address;
            stub.token = 0x11000000U | static_cast<uint32_t>(index + 1);
            stub.kind = kind;
            stub.index = index;
            stub.fullName = "Il2Cpp$$" + unresolvedStubPrefix(kind) + std::to_string(index);
            if (!result.unresolvedStubs.emplace(stub.address, std::move(stub)).second) {
                result.report.auxiliaryDiagnostics.push_back(unresolvedStubPrefix(kind) +
                    "duplicate unresolved stub address: " + std::to_string(location->address));
            }
        }
    };

    readTable(*virtualTable, UnresolvedStubKind::Virtual);
    if (layout.splitInstanceAndStatic) {
        const auto instanceTable = readField(layout.virtualTableField + 1);
        const auto staticTable = readField(layout.virtualTableField + 2);
        if (instanceTable) readTable(*instanceTable, UnresolvedStubKind::Instance);
        if (staticTable) readTable(*staticTable, UnresolvedStubKind::Static);
    }
    result.report.unresolvedStubs = result.unresolvedStubs.size();
}

bool expectedDeclarationOnly(const MethodModel& method) {
    constexpr uint16_t abstract = 0x0400;
    constexpr uint16_t pInvoke = 0x2000;
    constexpr uint16_t internalCall = 0x1000;
    return (method.flags & (abstract | pInvoke)) != 0 ||
        (method.iflags & internalCall) != 0 || (method.iflags & 0x000F) == 3;
}

} // namespace

MethodResolver::MethodResolver(MethodResolverOptions options)
    : options_(std::move(options)) {}

std::vector<FunctionImage> MethodResolver::resolve(const MetadataModel& metadata, const BinaryImage& binary) const {
    auto result = resolveWithReport(metadata, binary);
    return std::move(result.functions);
}

MethodResolutionResult MethodResolver::resolveWithReport(const MetadataModel& metadata, const BinaryImage& binary) const {
    MethodResolutionResult result;
    result.metadata = metadata;
    if (options_.discoverModules && binary.bytes) {
        discoverCodeGenModules(binary, result.metadata);
    }

    std::map<uint64_t, ResolvedFunction> methods;
    std::set<std::pair<std::string, uint32_t>> seenTokens;
    for (auto& type : result.metadata.types) {
        for (auto& method : type.methods) {
            ++result.report.totalMethods;
            const auto suppliedAddress = method.address;
            method.address = 0;

            const bool legacy = result.metadata.version != 0 && result.metadata.version < 24.2;
            const auto declare = [&](DeclarationOnlyReason reason) {
                DeclarationOnlyMethod declaration;
                declaration.imageName = method.imageName;
                declaration.declaringType = method.declaringType;
                declaration.name = method.name;
                declaration.token = method.token;
                declaration.definitionIndex = method.definitionIndex;
                declaration.methodIndex = method.methodIndex;
                declaration.reason = reason;
                declaration.diagnostic = reason == DeclarationOnlyReason::EmptyAssembly
                    ? "assembly has no native method pointer table; declarations only"
                    : reason == DeclarationOnlyReason::GeneratedWithoutNativePointer
                        ? "generated method has no confirmed native method pointer"
                        : "declaration has no native method body";
                ++result.report.declarationOnly;
                result.report.declarations.push_back(std::move(declaration));
            };
            if ((method.flags & 0x0400U) != 0) {
                declare(DeclarationOnlyReason::ExpectedNoNativeBody);
                continue;
            }
            if (suppliedAddress == 0 && legacy && method.methodIndex == -1) {
                const auto image = result.metadata.methodPointersByImage.find(method.imageName);
                declare(image == result.metadata.methodPointersByImage.end() || image->second.empty()
                    ? DeclarationOnlyReason::EmptyAssembly
                    : DeclarationOnlyReason::ExpectedNoNativeBody);
                continue;
            }

            PointerLookup lookup;
            if (suppliedAddress == 0) {
                lookup = methodPointer(method, result.metadata);
            } else {
                lookup.pointer = suppliedAddress;
            }

            const auto fail = [&](MethodResolutionError error) {
                UnresolvedMethod unresolved;
                unresolved.imageName = method.imageName;
                unresolved.declaringType = method.declaringType;
                unresolved.name = method.name;
                unresolved.token = method.token;
                unresolved.definitionIndex = method.definitionIndex;
                unresolved.methodIndex = method.methodIndex;
                unresolved.pointerIndex = lookup.index;
                unresolved.pointer = lookup.pointer;
                unresolved.error = error;
                unresolved.diagnostic = diagnosticFor(error);
                ++result.report.actualUnresolved;
                result.report.unresolved.push_back(std::move(unresolved));
            };

            if (!legacy && (method.token & ~tokenRowIdMask) == methodTokenType &&
                (method.token & tokenRowIdMask) != 0 &&
                !seenTokens.emplace(method.imageName, method.token).second) {
                ++result.report.duplicateMethodTokens;
                fail(MethodResolutionError::DuplicateMethodToken);
                continue;
            }

            if (lookup.error) {
                const bool generated = result.metadata.version >= 110.0 &&
                    result.metadata.generatedMethodsStart >= 0 &&
                    method.definitionIndex >= result.metadata.generatedMethodsStart;
                if (!legacy && *lookup.error == MethodResolutionError::MissingMethodPointerTable &&
                    (expectedDeclarationOnly(method) || generated)) {
                    declare(generated ? DeclarationOnlyReason::GeneratedWithoutNativePointer
                                      : DeclarationOnlyReason::EmptyAssembly);
                } else {
                    fail(*lookup.error);
                }
                continue;
            }
            if (normalizePointer(binary, lookup.pointer) == 0) {
                const bool generated = result.metadata.version >= 110.0 &&
                    result.metadata.generatedMethodsStart >= 0 &&
                    method.definitionIndex >= result.metadata.generatedMethodsStart;
                if (!legacy && (expectedDeclarationOnly(method) || generated)) {
                    declare(generated ? DeclarationOnlyReason::GeneratedWithoutNativePointer
                                      : DeclarationOnlyReason::ExpectedNoNativeBody);
                } else {
                    fail(MethodResolutionError::NullPointer);
                }
                continue;
            }

            const bool thumb = binary.architecture == Architecture::Arm32 && (lookup.pointer & 1) != 0;
            const auto location = locateAddress(binary, lookup.pointer);
            if (!location) {
                fail(MethodResolutionError::UnmappedAddress);
                continue;
            }
            if (!binary.sections[location->sectionIndex].executable) {
                fail(MethodResolutionError::NonExecutableAddress);
                continue;
            }

            method.address = location->address;
            ++result.report.resolvedMethods;

            FunctionImage image;
            image.architecture = binary.architecture;
            image.arm32Mode = thumb ? Arm32Mode::Thumb : Arm32Mode::Arm;
            image.address = location->address;
            image.name = methodName(method);
            auto [unused, inserted] = methods.emplace(location->address, ResolvedFunction{
                std::move(image), location->sectionIndex, location->fileOffset});
            (void)unused;
            if (!inserted) {
                ++result.report.duplicateAddresses;
                result.report.auxiliaryDiagnostics.push_back("duplicate native method address " +
                    std::to_string(location->address) + " for " + dumperMethodName(method));
            }
        }
    }

    result.functions.reserve(methods.size());
    for (auto current = methods.begin(); current != methods.end(); ++current) {
        auto& resolved = current->second;
        size_t end = sectionFileEnd(binary, binary.sections[resolved.sectionIndex]);
        const auto next = std::next(current);
        if (next != methods.end() && next->second.sectionIndex == resolved.sectionIndex &&
            next->second.fileOffset > resolved.fileOffset) {
            end = std::min(end, next->second.fileOffset);
        }

        size_t size = end > resolved.fileOffset ? end - resolved.fileOffset : 0;
        if (options_.maxFunctionSize != 0 && size > options_.maxFunctionSize) {
            size = options_.maxFunctionSize;
            ++result.report.sizeLimitedFunctions;
        }
        if (size == 0) continue;

        resolved.image.size = size;
        resolved.image.code = binary.bytes->data() + resolved.fileOffset;
        result.functions.push_back(std::move(resolved.image));
    }

    for (const auto& type : result.metadata.types) {
        for (const auto& method : type.methods) {
            if (method.address == 0) continue;
            MethodAddressMetadata exported;
            exported.fullName = dumperMethodName(method);
            exported.token = method.token;
            exported.imageName = method.imageName;
            exported.declaringType = method.declaringType;
            exported.methodIndex = method.methodIndex;
            result.methodMapping.emplace(method.address, std::move(exported));
        }
    }
    discoverAdjustorThunks(binary, result);
    discoverUnresolvedStubs(binary, result);
    return result;
}

} // namespace il2cpprec
