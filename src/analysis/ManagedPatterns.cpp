#include <il2cpprec/analysis/ManagedPatterns.hpp>
#include <il2cpprec/analysis/RuntimeHelpers.hpp>

#include <il2cpprec/metadata/GenericMethodResolver.hpp>
#include <il2cpprec/metadata/MetadataUsage.hpp>

#include <algorithm>
#include <bit>
#include <cstring>
#include <exception>
#include <limits>
#include <map>
#include <memory>
#include <tuple>
#include <unordered_set>
#include <utility>

namespace il2cpprec {
namespace {

ExpressionPtr stripCasts(ExpressionPtr expression) {
    while (expression && expression->kind == Expression::Kind::Cast && expression->arguments.size() == 1) {
        expression = expression->arguments[0];
    }
    return expression;
}

std::string registerName(const ExpressionPtr& expression) {
    return expression && expression->kind == Expression::Kind::Register ? expression->name : std::string{};
}

std::string qualifiedTypeName(const TypeModel& type) {
    if (type.nameSpace.empty()) return type.name;
    if (type.name.empty()) return type.nameSpace;
    return type.nameSpace + "." + type.name;
}

uint64_t methodAddress(
    const MethodModel& method,
    const MetadataModel& metadata,
    const std::unordered_map<std::string, int>& firstDefinitionByImage) {
    if (method.address != 0) return method.address;
    const auto pointers = metadata.methodPointersByImage.find(method.imageName);
    if (pointers == metadata.methodPointersByImage.end()) return 0;
    const double version = metadata.versionInfo.preciseVersion != 0
        ? metadata.versionInfo.preciseVersion : metadata.version;
    int64_t index = -1;
    if (version != 0 && version < 24.2) {
        index = method.methodIndex;
    } else if ((method.token & 0xFF000000) == 0x06000000 && (method.token & 0x00FFFFFF) != 0) {
        index = static_cast<int64_t>(method.token & 0x00FFFFFF) - 1;
    } else if (version == 0 && method.definitionIndex >= 0) {
        const auto first = firstDefinitionByImage.find(method.imageName);
        if (first != firstDefinitionByImage.end()) index = static_cast<int64_t>(method.definitionIndex) - first->second;
    }
    if (index < 0 || static_cast<uint64_t>(index) >= pointers->second.size()) return 0;
    return pointers->second[static_cast<size_t>(index)];
}

bool addOffset(int64_t left, int64_t right, int64_t& result) {
    if ((right > 0 && left > std::numeric_limits<int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<int64_t>::min() - right)) {
        return false;
    }
    result = left + right;
    return true;
}

std::optional<uint64_t> readNativeU64(const BinaryImage& binary, uint64_t address) {
    try {
        const auto offset = binary.mapVATR(address);
        uint64_t value = 0;
        std::memcpy(&value, binary.data(offset, sizeof(value)), sizeof(value));
        return value;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool virtualSlotMapped(const BinaryImage& binary, uint64_t address) {
    if (address == 0 || address % sizeof(uint64_t) != 0) return false;
    for (const auto& section : binary.sections) {
        if (section.virtualSize < sizeof(uint64_t) || address < section.virtualAddress) continue;
        if (address - section.virtualAddress <= section.virtualSize - sizeof(uint64_t)) return true;
    }
    return false;
}

} // namespace

GenericMethodInfoEvidence deriveEarlyArm64MethodInfoEvidence(
    const BinaryImage& binary,
    const MetadataModel& metadata) {
    GenericMethodInfoEvidence result;
    const double version = metadata.versionInfo.preciseVersion != 0
        ? metadata.versionInfo.preciseVersion : metadata.version;
    if (binary.format != BinaryFormat::MachO || binary.architecture != Architecture::Arm64 ||
        version < 24.0 || version >= 24.2 || metadata.metadataRegistrationAddress == 0 ||
        metadata.metadataUsagePairs.empty()) return result;

    // The verified v24.0/24.1 64-bit metadata registration has eight
    // count/pointer pairs; pair 7 lists addresses of metadata-usage slots.
    constexpr uint64_t countOffset = 7 * 2 * sizeof(uint64_t);
    if (metadata.metadataRegistrationAddress > std::numeric_limits<uint64_t>::max() - countOffset - sizeof(uint64_t))
        return result;
    const auto count = readNativeU64(binary, metadata.metadataRegistrationAddress + countOffset);
    const auto table = readNativeU64(binary, metadata.metadataRegistrationAddress + countOffset + sizeof(uint64_t));
    if (!count || !table || *count == 0 || *count > 1'000'000 ||
        (metadata.metadataUsagesCount != 0 && metadata.metadataUsagesCount != *count) ||
        *count > std::numeric_limits<size_t>::max() / sizeof(uint64_t)) return result;
    const auto tableBytes = static_cast<size_t>(*count) * sizeof(uint64_t);
    if (*table > std::numeric_limits<uint64_t>::max() - (tableBytes - 1)) return result;
    size_t tableOffset = 0;
    try {
        tableOffset = binary.mapVATR(*table);
        const auto lastOffset = binary.mapVATR(*table + tableBytes - 1);
        if (lastOffset < tableOffset || lastOffset - tableOffset != tableBytes - 1) return result;
        binary.data(tableOffset, tableBytes);
    } catch (const std::exception&) {
        return result;
    }

    // The same validated registration contains the native Il2CppType*
    // table at pair 3. Its order is the TypeReference index order. Keep only
    // file-backed descriptors with unique addresses; an unresolved argument
    // remains unresolved in UniversalGenericResolver.
    constexpr uint64_t typeCountOffset = 3 * 2 * sizeof(uint64_t);
    const auto typeCount = readNativeU64(binary, metadata.metadataRegistrationAddress + typeCountOffset);
    const auto typeTable = readNativeU64(binary, metadata.metadataRegistrationAddress + typeCountOffset + sizeof(uint64_t));
    if (typeCount && typeTable && *typeCount == metadata.typeReferences.size() &&
        *typeCount <= static_cast<uint64_t>(std::numeric_limits<int32_t>::max()) &&
        *typeCount <= std::numeric_limits<size_t>::max() / sizeof(uint64_t) && *typeCount != 0) {
        const auto typeBytes = static_cast<size_t>(*typeCount) * sizeof(uint64_t);
        if (*typeTable <= std::numeric_limits<uint64_t>::max() - (typeBytes - 1)) {
            try {
                const auto typeTableOffset = binary.mapVATR(*typeTable);
                const auto lastTypeOffset = binary.mapVATR(*typeTable + typeBytes - 1);
                if (lastTypeOffset >= typeTableOffset && lastTypeOffset - typeTableOffset == typeBytes - 1) {
                    binary.data(typeTableOffset, typeBytes);
                    std::unordered_set<uint64_t> conflictingTypes;
                    for (size_t index = 0; index < *typeCount; ++index) {
                        uint64_t address = 0;
                        std::memcpy(&address,
                                    binary.data(typeTableOffset + index * sizeof(uint64_t), sizeof(uint64_t)),
                                    sizeof(uint64_t));
                        try {
                            const auto descriptorOffset = binary.mapVATR(address);
                            binary.data(descriptorOffset, 16);
                        } catch (const std::exception&) {
                            ++result.unmappedTypeDescriptors;
                            continue;
                        }
                        const auto [entry, inserted] = result.typeReferencesByAddress.emplace(address, static_cast<int32_t>(index));
                        if (!inserted && entry->second != static_cast<int32_t>(index)) conflictingTypes.insert(address);
                    }
                    for (const auto address : conflictingTypes) result.typeReferencesByAddress.erase(address);
                    result.conflictingTypeAddresses = conflictingTypes.size();
                }
            } catch (const std::exception&) {
                // Type-address evidence is optional. Slot evidence below can
                // still be used for a guarded, non-emitting identification.
            }
        }
    }

    std::vector<std::optional<uint32_t>> encoded(static_cast<size_t>(*count));
    std::vector<bool> conflicts(static_cast<size_t>(*count));
    for (const auto& pair : metadata.metadataUsagePairs) {
        if (pair.destinationIndex >= *count) continue;
        auto& first = encoded[pair.destinationIndex];
        if (!first) first = pair.encodedSourceIndex;
        else if (*first != pair.encodedSourceIndex) conflicts[pair.destinationIndex] = true;
    }
    const GenericMethodResolver resolver(metadata);
    std::unordered_map<uint64_t, uint32_t> admitted;
    std::unordered_set<uint64_t> conflictingSlots;
    for (size_t destination = 0; destination < encoded.size(); ++destination) {
        if (conflicts[destination]) {
            ++result.conflictingDestinations;
            continue;
        }
        if (!encoded[destination]) continue;
        const auto source = MetadataUsageReader::decode(*encoded[destination]);
        if (source.kind != MetadataUsageKind::MethodRef) continue;
        const auto target = resolver.resolve(source.index);
        if (target.status != MetadataUsageStatus::Resolved || !target.mapping ||
            target.mapping->methodPointer == 0) continue;
        uint64_t slot = 0;
        std::memcpy(&slot, binary.data(tableOffset + destination * sizeof(uint64_t), sizeof(uint64_t)), sizeof(uint64_t));
        if (!virtualSlotMapped(binary, slot)) {
            ++result.unmappedSlots;
            continue;
        }
        const auto [entry, inserted] = admitted.emplace(slot, source.index);
        if (!inserted && entry->second != source.index) conflictingSlots.insert(slot);
    }
    for (const auto slot : conflictingSlots) admitted.erase(slot);
    result.conflictingDestinations += conflictingSlots.size();
    result.bySlotAddress = std::move(admitted);
    return result;
}

ManagedMetadataIndex::ManagedMetadataIndex(const MetadataModel& metadata) : source(&metadata) {
    std::unordered_map<std::string, int> firstDefinitionByImage;
    for (const auto& type : metadata.types) {
        for (const auto& method : type.methods) {
            if (method.definitionIndex < 0) continue;
            auto [it, inserted] = firstDefinitionByImage.emplace(method.imageName, method.definitionIndex);
            if (!inserted) it->second = std::min(it->second, method.definitionIndex);
        }
    }
    for (const auto& type : metadata.types) {
        const auto declaringType = qualifiedTypeName(type);
        for (const auto& method : type.methods) {
            const uint64_t address = methodAddress(method, metadata, firstDefinitionByImage);
            if (address == 0) continue;
            ManagedMethodReference reference;
            reference.token = method.token;
            reference.definitionIndex = method.definitionIndex;
            reference.address = address;
            reference.imageName = method.imageName;
            reference.declaringType = method.declaringType.empty() ? declaringType : method.declaringType;
            reference.name = method.name;
            reference.isStatic = method.isStatic;
            methodsByAddress[address].push_back(std::move(reference));
        }
        for (const auto& field : type.fields) {
            ManagedFieldReference reference;
            reference.declaringType = declaringType;
            reference.name = field.name;
            reference.type = field.type;
            reference.offset = field.offset;
            reference.isStatic = field.isStatic;
            fieldsByOffset[field.offset].push_back(std::move(reference));
        }
    }
    for (const auto& mapping : metadata.genericMethodTable) {
        if (mapping.genericMethodIndex >= 0 && mapping.methodPointer != 0) {
            genericsByAddress[mapping.methodPointer].push_back({mapping.genericMethodIndex, mapping, false});
        }
        if (mapping.genericMethodIndex >= 0 && mapping.adjustorThunk != 0) {
            genericsByAddress[mapping.adjustorThunk].push_back({mapping.genericMethodIndex, mapping, true});
        }
    }
    for (auto& [address, candidates] : genericsByAddress) {
        std::sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
            return std::tie(left.index, left.adjustor) < std::tie(right.index, right.adjustor);
        });
        candidates.erase(std::unique(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
            return left.index == right.index && left.adjustor == right.adjustor;
        }), candidates.end());
    }
    for (auto& [address, methods] : methodsByAddress) {
        std::sort(methods.begin(), methods.end(), [](const auto& left, const auto& right) {
            return std::tie(left.address, left.imageName, left.declaringType, left.name, left.token, left.definitionIndex) <
                std::tie(right.address, right.imageName, right.declaringType, right.name, right.token, right.definitionIndex);
        });
    }
    for (auto& [offset, fields] : fieldsByOffset) {
        std::sort(fields.begin(), fields.end(), [](const auto& left, const auto& right) {
            return std::tie(left.declaringType, left.name, left.type, left.offset) <
                std::tie(right.declaringType, right.name, right.type, right.offset);
        });
    }
}

namespace {

struct AddressParts {
    std::vector<ExpressionPtr> terms;
    int64_t displacement = 0;
    bool valid = true;
};

struct AllocationState {
    size_t statementIndex = 0;
    uint64_t address = 0;
    ExpressionPtr destination;
};

using GenericCandidate = ManagedGenericCandidate;

class AnalysisContext {
public:
    AnalysisContext(
        const RecoveredFunction& function,
        const MetadataModel& metadata,
        const ManagedPatternOptions& options,
        ManagedAnalysisResult& result)
        : function_(function), metadata_(metadata), options_(options), result_(result),
          genericResolver_(options.genericResolver),
          pointerBits_(function.architecture == Architecture::Arm64 || function.architecture == Architecture::X64 ? 64 : 32) {
        if (options.metadataIndex && options.metadataIndex->source == &metadata) {
            metadataIndex_ = options.metadataIndex;
        } else {
            ownedMetadataIndex_ = std::make_unique<ManagedMetadataIndex>(metadata);
            metadataIndex_ = ownedMetadataIndex_.get();
        }
        buildOptionOverlays();
    }

    void run() {
        for (const auto& evidence : RuntimeHelpers{}.infer(function_)) {
            if (evidence.role == RuntimeHelperRole::ClassInit &&
                !methodsByAddress().contains(evidence.targetAddress) &&
                !hasGenericAddress(evidence.targetAddress)) {
                inferredClassInitSites_.insert({evidence.blockIndex, evidence.statementIndex});
            }
        }
        for (size_t blockIndex = 0; blockIndex < function_.blocks.size(); ++blockIndex) {
            constants_.clear();
            symbolic_.clear();
            allocations_.clear();
            memoryMayHaveChanged_ = false;
            const auto& block = function_.blocks[blockIndex];
            for (size_t statementIndex = 0; statementIndex < block.statements.size(); ++statementIndex) {
                processStatement(blockIndex, statementIndex, block.statements[statementIndex]);
            }
        }
    }

private:
    const RecoveredFunction& function_;
    const MetadataModel& metadata_;
    const ManagedPatternOptions& options_;
    ManagedAnalysisResult& result_;
    const GenericMethodResolver* genericResolver_ = nullptr;
    std::unique_ptr<GenericMethodResolver> ownedGenericResolver_;
    uint16_t pointerBits_;
    bool memoryMayHaveChanged_ = false;

    const ManagedMetadataIndex* metadataIndex_ = nullptr;
    std::unique_ptr<ManagedMetadataIndex> ownedMetadataIndex_;
    std::map<uint64_t, std::vector<GenericCandidate>> additionalGenericsByAddress_;
    std::map<uint64_t, std::vector<uint32_t>> stringsByAddress_;
    std::unordered_map<std::string, uint64_t> constants_;
    std::unordered_map<std::string, ExpressionPtr> symbolic_;
    std::unordered_map<std::string, AllocationState> allocations_;
    std::set<std::pair<size_t, size_t>> inferredClassInitSites_;

    ScalarType pointerType() const {
        return ScalarType::pointer(pointerBits_);
    }

    const std::map<uint64_t, std::vector<ManagedMethodReference>>& methodsByAddress() const {
        return metadataIndex_->methodsByAddress;
    }
    const std::map<int64_t, std::vector<ManagedFieldReference>>& fieldsByOffset() const {
        return metadataIndex_->fieldsByOffset;
    }

    std::vector<GenericCandidate> genericCandidates(uint64_t address) const {
        std::vector<GenericCandidate> result;
        const auto base = metadataIndex_->genericsByAddress.find(address);
        if (base != metadataIndex_->genericsByAddress.end()) result = base->second;
        const auto extra = additionalGenericsByAddress_.find(address);
        if (extra != additionalGenericsByAddress_.end()) {
            result.insert(result.end(), extra->second.begin(), extra->second.end());
            std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
                return std::tie(left.index, left.adjustor) < std::tie(right.index, right.adjustor);
            });
            result.erase(std::unique(result.begin(), result.end(), [](const auto& left, const auto& right) {
                return left.index == right.index && left.adjustor == right.adjustor;
            }), result.end());
        }
        return result;
    }

    bool hasGenericAddress(uint64_t address) const {
        return metadataIndex_->genericsByAddress.contains(address) || additionalGenericsByAddress_.contains(address);
    }

    void buildOptionOverlays() {
        for (const auto& [address, genericIndex] : options_.profile.genericAdjustorTargets) {
            if (genericIndex > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) continue;
            const auto mapping = std::find_if(metadata_.genericMethodTable.begin(), metadata_.genericMethodTable.end(), [&](const auto& candidate) {
                return candidate.genericMethodIndex == static_cast<int32_t>(genericIndex);
            });
            if (mapping != metadata_.genericMethodTable.end()) {
                additionalGenericsByAddress_[address].push_back({static_cast<int32_t>(genericIndex), *mapping, true});
            }
        }
        for (const auto& [token, address] : options_.stringLiteralAddresses) {
            stringsByAddress_[address].push_back(token);
        }
        for (auto& [address, tokens] : stringsByAddress_) std::sort(tokens.begin(), tokens.end());
    }

    std::optional<uint64_t> readPointer(uint64_t address) const {
        const auto* binary = options_.binary;
        if (!binary || binary->architecture != function_.architecture || !binary->bytes ||
            memoryMayHaveChanged_ || (pointerBits_ != 32 && pointerBits_ != 64)) {
            return std::nullopt;
        }

        std::vector<uint64_t> candidates;
        if (address >= binary->imageBase) candidates.push_back(address - binary->imageBase);
        if (candidates.empty() || candidates.back() != address) candidates.push_back(address);

        std::optional<uint64_t> fileOffset;
        for (const auto rva : candidates) {
            for (const auto& section : binary->sections) {
                if (rva < section.virtualAddress) continue;
                const auto sectionOffset = rva - section.virtualAddress;
                if (sectionOffset >= section.fileSize || sectionOffset > std::numeric_limits<uint64_t>::max() - section.fileOffset) continue;
                const auto candidate = section.fileOffset + sectionOffset;
                if (candidate <= binary->bytes->size()) {
                    fileOffset = candidate;
                    break;
                }
            }
            if (fileOffset) break;
        }
        if (!fileOffset) return std::nullopt;

        const size_t width = pointerBits_ / 8;
        const auto offset = *fileOffset;
        if (offset > binary->bytes->size() || width > binary->bytes->size() - static_cast<size_t>(offset)) {
            return std::nullopt;
        }
        uint64_t value = 0;
        for (size_t index = 0; index < width; ++index) {
            value |= static_cast<uint64_t>((*binary->bytes)[static_cast<size_t>(offset) + index]) << (index * 8);
        }
        return value;
    }

    std::optional<uint64_t> evaluate(const ExpressionPtr& input) const {
        const auto& expression = input;
        if (!expression) return std::nullopt;
        switch (expression->kind) {
        case Expression::Kind::Constant:
            return expression->constant;
        case Expression::Kind::Register: {
            const auto it = constants_.find(expression->name);
            if (it == constants_.end()) return std::nullopt;
            return it->second;
        }
        case Expression::Kind::Cast: {
            if (expression->arguments.size() != 1) return std::nullopt;
            auto value = evaluate(expression->arguments[0]);
            if (!value) return std::nullopt;
            const auto bits = expression->type.bits;
            if (bits == 0 || bits >= 64) return value;
            const uint64_t mask = (uint64_t{1} << bits) - 1;
            uint64_t narrowed = *value & mask;
            if (expression->type.kind == ScalarKind::SignedInteger && (narrowed & (uint64_t{1} << (bits - 1)))) {
                narrowed |= ~mask;
            }
            return narrowed;
        }
        case Expression::Kind::Unary: {
            if (expression->arguments.size() != 1) return std::nullopt;
            auto value = evaluate(expression->arguments[0]);
            if (!value) return std::nullopt;
            if (expression->op == "-") return uint64_t{0} - *value;
            if (expression->op == "~") return ~*value;
            if (expression->op == "+") return value;
            return std::nullopt;
        }
        case Expression::Kind::Binary: {
            if (expression->arguments.size() != 2) return std::nullopt;
            const auto left = evaluate(expression->arguments[0]);
            const auto right = evaluate(expression->arguments[1]);
            if (!left || !right) return std::nullopt;
            if (expression->op == "+") return *left + *right;
            if (expression->op == "-") return *left - *right;
            if (expression->op == "*") return *left * *right;
            if (expression->op == "&") return *left & *right;
            if (expression->op == "|") return *left | *right;
            if (expression->op == "^") return *left ^ *right;
            if (expression->op == "<<") {
                if (*right >= 64) return std::nullopt;
                return *left << *right;
            }
            if (expression->op == ">>") {
                if (*right >= 64) return std::nullopt;
                return *left >> *right;
            }
            return std::nullopt;
        }
        case Expression::Kind::Load: {
            if (expression->arguments.size() != 1 || expression->type.bits != pointerBits_) {
                return std::nullopt;
            }
            const auto address = evaluate(expression->arguments[0]);
            if (!address) return std::nullopt;
            return readPointer(*address);
        }
        default:
            return std::nullopt;
        }
    }

    void collectAddress(const ExpressionPtr& input, bool negate, AddressParts& parts) const {
        const auto expression = stripCasts(input);
        if (!expression) {
            parts.valid = false;
            return;
        }
        if (expression->kind == Expression::Kind::Binary && expression->arguments.size() == 2 &&
            (expression->op == "+" || expression->op == "-")) {
            if (expression->op == "+" || evaluate(expression->arguments[1])) {
                collectAddress(expression->arguments[0], negate, parts);
                collectAddress(expression->arguments[1], negate != (expression->op == "-"), parts);
                return;
            }
        }
        if (const auto value = evaluate(expression)) {
            int64_t displacement = std::bit_cast<int64_t>(*value);
            if (negate) {
                if (displacement == std::numeric_limits<int64_t>::min()) {
                    parts.valid = false;
                    return;
                }
                displacement = -displacement;
            }
            if (!addOffset(parts.displacement, displacement, parts.displacement)) parts.valid = false;
            return;
        }
        if (negate) {
            parts.valid = false;
            return;
        }
        parts.terms.push_back(expression);
    }

    AddressParts decomposeAddress(const ExpressionPtr& address) const {
        AddressParts parts;
        collectAddress(address, false, parts);
        return parts;
    }

    ManagedOperation operation(
        ManagedOperationKind kind,
        size_t blockIndex,
        size_t statementIndex,
        const Statement& statement) const {
        ManagedOperation result;
        result.kind = kind;
        result.address = statement.address;
        result.blockIndex = blockIndex;
        result.statementIndex = statementIndex;
        result.nativeStatements = {statement};
        return result;
    }

    bool recognizeStringLiteral(size_t blockIndex, size_t statementIndex, const Statement& statement) {
        if (statement.kind != Statement::Kind::Assign) return false;
        const auto address = evaluate(statement.value);
        if (!address) return false;
        const auto strings = stringsByAddress_.find(*address);
        if (strings == stringsByAddress_.end()) return false;

        auto result = operation(ManagedOperationKind::StringLiteralReference, blockIndex, statementIndex, statement);
        result.destination = statement.destination;
        result.value = statement.value;
        result.stringLiteralTokens = strings->second;
        if (strings->second.size() == 1) {
            result.status = ManagedPatternStatus::Resolved;
            result.confidence = ManagedPatternConfidence::High;
            result.stringLiteralToken = strings->second.front();
            const auto literal = metadata_.stringLiterals.find(result.stringLiteralToken);
            if (literal != metadata_.stringLiterals.end()) {
                result.stringLiteral = literal->second;
            } else {
                result.status = ManagedPatternStatus::Unresolved;
                result.confidence = ManagedPatternConfidence::Low;
                result.reason = "The literal address is configured, but its token is absent from stringLiterals.";
            }
        } else {
            result.status = ManagedPatternStatus::Ambiguous;
            result.confidence = ManagedPatternConfidence::Low;
            result.reason = "Multiple string literal tokens have the same native address.";
        }
        result_.operations.push_back(std::move(result));
        return true;
    }

    bool resolveGeneric(ManagedOperation& result, const GenericCandidate& candidate, uint64_t targetAddress) {
        if (!genericResolver_) {
            ownedGenericResolver_ = std::make_unique<GenericMethodResolver>(metadata_);
            genericResolver_ = ownedGenericResolver_.get();
        }
        const auto resolved = genericResolver_->resolve(static_cast<uint32_t>(candidate.index));
        if (resolved.status != MetadataUsageStatus::Resolved || !resolved.method || !resolved.mapping) return false;
        const auto& method = *resolved.method;
        result.method.token = method.token;
        result.method.definitionIndex = method.definitionIndex;
        result.method.address = targetAddress;
        result.method.imageName = method.imageName;
        result.method.declaringType = method.declaringType;
        result.method.name = method.name;
        result.method.isStatic = method.isStatic;
        result.methodCandidates = {result.method};
        result.genericTarget.present = true;
        result.genericTarget.adjustor = candidate.adjustor;
        result.genericTarget.genericMethodIndex = candidate.index;
        result.genericTarget.mapping = *resolved.mapping;
        if (static_cast<size_t>(candidate.index) < metadata_.methodSpecs.size()) {
            const auto& spec = metadata_.methodSpecs[static_cast<size_t>(candidate.index)];
            result.genericTarget.classInstIndex = spec.classInstIndex;
            result.genericTarget.methodInstIndex = spec.methodInstIndex;
        }
        return true;
    }

    const std::unordered_map<uint64_t, uint32_t>& genericMethodInfoAddresses() const {
        return options_.genericMethodInfoByAddressView
            ? *options_.genericMethodInfoByAddressView : options_.genericMethodInfoByAddress;
    }

    std::optional<size_t> provenMethodInfoArgumentIndex(const std::vector<GenericCandidate>& candidates) {
        if (options_.genericMethodInfoArgumentIndex) return options_.genericMethodInfoArgumentIndex;
        const double version = metadata_.versionInfo.preciseVersion != 0
            ? metadata_.versionInfo.preciseVersion : metadata_.version;
        if (genericMethodInfoAddresses().empty() ||
            function_.architecture != Architecture::Arm64 || version < 24.0 || version >= 24.2)
            return std::nullopt;
        // Only the verified early-v24 ARM64 zero-parameter instance shape has
        // `this` in x0 and hidden MethodInfo in x1. Shared native bodies may
        // represent many different instantiations, but their MethodDef and
        // incoming ABI must agree before the caller's slot may choose one.
        std::optional<int32_t> definition;
        if (!genericResolver_) {
            ownedGenericResolver_ = std::make_unique<GenericMethodResolver>(metadata_);
            genericResolver_ = ownedGenericResolver_.get();
        }
        for (const auto& candidate : candidates) {
            if (candidate.adjustor) return std::nullopt;
            const auto resolved = genericResolver_->resolve(static_cast<uint32_t>(candidate.index));
            if (resolved.status != MetadataUsageStatus::Resolved || !resolved.method ||
                !resolved.methodDefinitionIndex || resolved.method->isStatic ||
                !resolved.method->parameters.empty()) return std::nullopt;
            if (definition && *definition != *resolved.methodDefinitionIndex) return std::nullopt;
            definition = *resolved.methodDefinitionIndex;
        }
        return definition ? std::optional<size_t>{1} : std::nullopt;
    }

    std::optional<int32_t> configuredGenericIndex(
        const Statement& statement,
        const std::vector<GenericCandidate>& candidates) {
        const auto argumentIndex = provenMethodInfoArgumentIndex(candidates);
        if (!argumentIndex || *argumentIndex >= statement.arguments.size()) return std::nullopt;
        const auto argument = stripCasts(expandTarget(statement.arguments[*argumentIndex]));
        if (!argument) return std::nullopt;
        // A runtime-initialized slot may not be backed by the input file.
        // The caller may provide its identity explicitly; we never infer the
        // MethodInfo value from the shared target or from an unreadable slot.
        const auto address = argument->kind == Expression::Kind::Load && argument->arguments.size() == 1
            ? evaluate(argument->arguments.front()) : evaluate(argument);
        if (!address) return std::nullopt;
        const auto& addresses = genericMethodInfoAddresses();
        const auto match = addresses.find(*address);
        if (match == addresses.end() ||
            match->second > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) return std::nullopt;
        return static_cast<int32_t>(match->second);
    }

    void recognizeDirectCall(
        size_t blockIndex,
        size_t statementIndex,
        const Statement& statement,
        uint64_t targetAddress) {
        auto result = operation(ManagedOperationKind::DirectMethodCall, blockIndex, statementIndex, statement);
        result.destination = statement.destination;
        result.targetAddress = targetAddress;
        if (options_.profile.unresolvedVirtualCallStubs.contains(targetAddress) ||
            std::find(metadata_.unresolvedVirtualCallPointers.begin(),
                      metadata_.unresolvedVirtualCallPointers.end(), targetAddress) != metadata_.unresolvedVirtualCallPointers.end()) {
            result.status = ManagedPatternStatus::Unresolved;
            result.confidence = ManagedPatternConfidence::Medium;
            result.unresolvedStub = true;
            result.reason = "The target is an IL2CPP unresolved virtual-call stub.";
            result_.operations.push_back(std::move(result));
            return;
        }
        const auto methods = methodsByAddress().find(targetAddress);
        const auto generics = genericCandidates(targetAddress);
        if (methods == methodsByAddress().end() && generics.size() > 1) {
            if (const auto selected = configuredGenericIndex(statement, generics)) {
                const auto match = std::find_if(generics.begin(), generics.end(), [&](const GenericCandidate& candidate) {
                    return candidate.index == *selected;
                });
                const auto count = std::count_if(generics.begin(), generics.end(), [&](const GenericCandidate& candidate) {
                    return candidate.index == *selected;
                });
                if (count == 1 && resolveGeneric(result, *match, targetAddress)) {
                    result.status = ManagedPatternStatus::Resolved;
                    result.confidence = ManagedPatternConfidence::High;
                } else {
                    result.status = count > 1 ? ManagedPatternStatus::Ambiguous : ManagedPatternStatus::Unresolved;
                    result.confidence = ManagedPatternConfidence::Low;
                    result.reason = count == 0
                        ? "Explicit MethodInfo evidence conflicts with the native generic target."
                        : "Explicit MethodInfo evidence does not resolve one valid generic method spec.";
                }
                result_.operations.push_back(std::move(result));
                return;
            }
        }
        size_t resolvedGenerics = 0;
        if (methods == methodsByAddress().end() && !generics.empty()) {
            for (const auto& candidate : generics) {
                ManagedOperation generic = result;
                if (resolveGeneric(generic, candidate, targetAddress)) {
                    ++resolvedGenerics;
                    if (resolvedGenerics == 1) result = std::move(generic);
                }
            }
        }
        if (methods == methodsByAddress().end() && resolvedGenerics == 1 && generics.size() == 1) {
            result.status = ManagedPatternStatus::Resolved;
            result.confidence = ManagedPatternConfidence::High;
        } else if (methods == methodsByAddress().end() && resolvedGenerics == 0) {
            result.status = ManagedPatternStatus::Unresolved;
            result.reason = "The direct target has no unique managed or generic method mapping.";
        } else if (methods == methodsByAddress().end() && resolvedGenerics > 0) {
            result.status = ManagedPatternStatus::Ambiguous;
            result.confidence = ManagedPatternConfidence::Low;
            result.reason = std::to_string(generics.size()) +
                " generic instantiations share the native target; explicit MethodInfo evidence is required.";
        } else if (methods != methodsByAddress().end()) {
            result.methodCandidates = methods->second;
            if (methods->second.size() == 1 && generics.empty()) {
                result.status = ManagedPatternStatus::Resolved;
                result.confidence = ManagedPatternConfidence::High;
                result.method = methods->second.front();
            } else {
                result.status = ManagedPatternStatus::Ambiguous;
                result.confidence = ManagedPatternConfidence::Low;
                result.reason = "Multiple managed methods have the same native address.";
            }
        }
        result_.operations.push_back(std::move(result));
    }

    ExpressionPtr expandTarget(ExpressionPtr target) const {
        target = stripCasts(std::move(target));
        std::set<std::string> visited;
        while (target && target->kind == Expression::Kind::Register && visited.insert(target->name).second) {
            const auto value = symbolic_.find(target->name);
            if (value == symbolic_.end()) break;
            target = stripCasts(value->second);
        }
        return target;
    }

    void recognizeVirtualDispatch(size_t blockIndex, size_t statementIndex, const Statement& statement) {
        const auto target = stripCasts(expandTarget(statement.target));
        if (!target || target->kind != Expression::Kind::Load || target->arguments.size() != 1) return;
        const auto slot = decomposeAddress(target->arguments[0]);
        if (!slot.valid || slot.terms.size() != 1 || slot.displacement < 0) return;
        const auto vtable = stripCasts(slot.terms.front());
        if (!vtable || vtable->kind != Expression::Kind::Load || vtable->arguments.size() != 1) return;
        const auto object = decomposeAddress(vtable->arguments[0]);
        if (!object.valid || object.terms.size() != 1 || object.displacement != 0) return;

        auto result = operation(ManagedOperationKind::VirtualDispatch, blockIndex, statementIndex, statement);
        result.status = ManagedPatternStatus::Placeholder;
        result.confidence = ManagedPatternConfidence::Medium;
        result.destination = statement.destination;
        result.object = object.terms.front();
        result.value = target;
        result.offset = slot.displacement;
        result.reason = "The vtable slot is recognizable, but no managed method identity is available.";
        result_.operations.push_back(std::move(result));
    }

    void addFieldCandidates(ManagedOperation& result, const std::vector<ManagedFieldReference>& candidates) const {
        result.fieldCandidateCount = candidates.size();
        if (candidates.size() == 1 || options_.collectAmbiguousFieldCandidates)
            result.fieldCandidates = candidates;
        if (candidates.size() == 1) {
            result.status = ManagedPatternStatus::Resolved;
            result.confidence = ManagedPatternConfidence::High;
            result.field = candidates.front();
            result.typeName = candidates.front().declaringType;
        } else {
            result.status = ManagedPatternStatus::Ambiguous;
            result.confidence = ManagedPatternConfidence::Low;
            result.reason = "Multiple managed fields have the same native offset.";
        }
    }

    bool scaledIndex(const ExpressionPtr& expression, ExpressionPtr& index) const {
        const auto product = stripCasts(expression);
        if (product && product->kind == Expression::Kind::Binary && product->op == "*" && product->arguments.size() == 2) {
            const auto leftScale = evaluate(product->arguments[0]);
            const auto rightScale = evaluate(product->arguments[1]);
            if (leftScale && !rightScale) {
                index = product->arguments[1];
                return *leftScale != 0 && *leftScale <= 16 && (*leftScale & (*leftScale - 1)) == 0;
            }
            if (rightScale && !leftScale) {
                index = product->arguments[0];
                return *rightScale != 0 && *rightScale <= 16 && (*rightScale & (*rightScale - 1)) == 0;
            }
        }
        return false;
    }

    bool arrayElementParts(const AddressParts& parts, ExpressionPtr& object, ExpressionPtr& index) const {
        const auto elementsOffset = options_.arrayElementsOffset.value_or(pointerBits_ == 64 ? 32 : 16);
        if (!parts.valid || parts.displacement != elementsOffset) return false;
        if (parts.terms.size() == 1) {
            object = parts.terms.front();
            index = constant(0, ScalarType::uintBits(32));
            return true;
        }
        if (parts.terms.size() != 2) return false;
        if (scaledIndex(parts.terms[0], index)) {
            object = parts.terms[1];
            return true;
        }
        if (scaledIndex(parts.terms[1], index)) {
            object = parts.terms[0];
            return true;
        }
        object = parts.terms[0];
        index = parts.terms[1];
        return true;
    }

    void recognizeLoad(size_t blockIndex, size_t statementIndex, const Statement& statement) {
        if (statement.kind != Statement::Kind::Assign) return;
        const auto value = stripCasts(statement.value);
        if (!value || value->kind != Expression::Kind::Load || value->arguments.size() != 1) return;
        const auto address = decomposeAddress(value->arguments[0]);
        if (!address.valid) return;

        const auto fields = address.terms.size() == 1
            ? fieldsByOffset().find(address.displacement)
            : fieldsByOffset().end();
        if (fields != fieldsByOffset().end()) {
            auto result = operation(ManagedOperationKind::FieldLoad, blockIndex, statementIndex, statement);
            result.destination = statement.destination;
            result.object = address.terms.front();
            result.value = statement.value;
            result.offset = address.displacement;
            addFieldCandidates(result, fields->second);
            result_.operations.push_back(std::move(result));
            return;
        }

        if (!options_.recognizeArrayLayout) return;
        const auto lengthOffset = options_.arrayLengthOffset.value_or(pointerBits_ == 64 ? 24 : 12);
        if (address.terms.size() == 1 && address.displacement == lengthOffset && value->type.bits == 32) {
            auto result = operation(ManagedOperationKind::ArrayLength, blockIndex, statementIndex, statement);
            result.status = ManagedPatternStatus::Placeholder;
            result.confidence = ManagedPatternConfidence::Low;
            result.destination = statement.destination;
            result.object = address.terms.front();
            result.value = statement.value;
            result.offset = address.displacement;
            result.reason = "The access matches the configured array-length layout; the object's managed type is unknown.";
            result_.operations.push_back(std::move(result));
            return;
        }

        ExpressionPtr object;
        ExpressionPtr index;
        if (arrayElementParts(address, object, index)) {
            auto result = operation(ManagedOperationKind::ArrayElementLoad, blockIndex, statementIndex, statement);
            result.status = ManagedPatternStatus::Placeholder;
            result.confidence = ManagedPatternConfidence::Low;
            result.destination = statement.destination;
            result.object = std::move(object);
            result.index = std::move(index);
            result.value = statement.value;
            result.offset = address.displacement;
            result.reason = "The address matches the configured array-data layout; the object's managed type is unknown.";
            result_.operations.push_back(std::move(result));
        }
    }

    void recognizeStore(size_t blockIndex, size_t statementIndex, const Statement& statement) {
        if (statement.kind != Statement::Kind::Store) return;
        const auto address = decomposeAddress(statement.destination);
        if (!address.valid) return;

        const auto fields = address.terms.size() == 1
            ? fieldsByOffset().find(address.displacement)
            : fieldsByOffset().end();
        if (fields != fieldsByOffset().end()) {
            auto result = operation(ManagedOperationKind::FieldStore, blockIndex, statementIndex, statement);
            result.object = address.terms.front();
            result.value = statement.value;
            result.offset = address.displacement;
            addFieldCandidates(result, fields->second);
            result_.operations.push_back(std::move(result));
            return;
        }

        if (!options_.recognizeArrayLayout) return;
        ExpressionPtr object;
        ExpressionPtr index;
        if (arrayElementParts(address, object, index)) {
            auto result = operation(ManagedOperationKind::ArrayElementStore, blockIndex, statementIndex, statement);
            result.status = ManagedPatternStatus::Placeholder;
            result.confidence = ManagedPatternConfidence::Low;
            result.object = std::move(object);
            result.index = std::move(index);
            result.value = statement.value;
            result.offset = address.displacement;
            result.reason = "The address matches the configured array-data layout; the object's managed type is unknown.";
            result_.operations.push_back(std::move(result));
        }
    }

    void recognizeObjectConstruction(
        size_t blockIndex,
        size_t statementIndex,
        const Statement& statement,
        uint64_t targetAddress) {
        if (statement.arguments.empty()) return;
        const auto object = stripCasts(statement.arguments.front());
        const auto name = registerName(object);
        if (name.empty()) return;
        const auto allocation = allocations_.find(name);
        if (allocation == allocations_.end()) return;
        const auto methods = methodsByAddress().find(targetAddress);
        if (methods == methodsByAddress().end() || methods->second.size() != 1) return;
        const auto& constructor = methods->second.front();
        if (constructor.name != ".ctor" || constructor.isStatic) return;

        auto result = operation(ManagedOperationKind::ObjectConstruction, blockIndex, statementIndex, statement);
        result.status = ManagedPatternStatus::Resolved;
        result.confidence = ManagedPatternConfidence::High;
        result.destination = allocation->second.destination;
        result.object = object;
        result.targetAddress = targetAddress;
        result.allocationAddress = allocation->second.address;
        result.method = constructor;
        result.methodCandidates = methods->second;
        result.typeName = constructor.declaringType;
        const auto& statements = function_.blocks[blockIndex].statements;
        result.nativeStatements.assign(
            statements.begin() + static_cast<std::ptrdiff_t>(allocation->second.statementIndex),
            statements.begin() + static_cast<std::ptrdiff_t>(statementIndex + 1));
        result_.operations.push_back(std::move(result));
    }

    void setRuntimeType(ManagedOperation& result, const Statement& statement, size_t argumentIndex) const {
        if (argumentIndex >= statement.arguments.size()) return;
        result.value = statement.arguments[argumentIndex];
        const auto address = evaluate(result.value);
        if (!address) return;
        result.typeAddress = *address;
        const auto type = options_.runtimeTypeAddresses.find(*address);
        if (type != options_.runtimeTypeAddresses.end()) result.typeName = type->second;
    }

    bool recognizeRuntimeCall(
        size_t blockIndex,
        size_t statementIndex,
        const Statement& statement,
        uint64_t targetAddress) {
        std::optional<ManagedOperationKind> kind;
        size_t typeArgument = 0;
        size_t valueArgument = 0;
        if (options_.arrayAllocatorAddresses.contains(targetAddress)) {
            kind = ManagedOperationKind::ArrayAllocation;
            typeArgument = options_.arrayTypeArgument;
        } else if (options_.boxAddresses.contains(targetAddress)) {
            kind = ManagedOperationKind::Box;
            typeArgument = options_.boxTypeArgument;
            valueArgument = options_.boxValueArgument;
        } else if (options_.unboxAddresses.contains(targetAddress)) {
            kind = ManagedOperationKind::UnBox;
            typeArgument = options_.unboxTypeArgument;
            valueArgument = options_.unboxValueArgument;
        } else if (options_.isInstAddresses.contains(targetAddress)) {
            kind = ManagedOperationKind::IsInst;
            typeArgument = options_.isInstTypeArgument;
            valueArgument = options_.isInstValueArgument;
        } else if (options_.nullCheckAddresses.contains(targetAddress)) {
            kind = ManagedOperationKind::NullCheck;
        } else if (options_.runtimeClassInitAddresses.contains(targetAddress) ||
                   inferredClassInitSites_.contains({blockIndex, statementIndex})) {
            kind = ManagedOperationKind::RuntimeClassInit;
            typeArgument = options_.runtimeClassInitTypeArgument;
        }
        if (!kind) return false;

        auto result = operation(*kind, blockIndex, statementIndex, statement);
        result.status = ManagedPatternStatus::Resolved;
        const bool inferred = *kind == ManagedOperationKind::RuntimeClassInit &&
            !options_.runtimeClassInitAddresses.contains(targetAddress);
        result.confidence = inferred ? ManagedPatternConfidence::Medium : ManagedPatternConfidence::High;
        if (inferred) {
            result.reason = "The guarded zero test and matching write to one identify a class-init call site.";
        }
        result.destination = statement.destination;
        result.targetAddress = targetAddress;
        if (valueArgument < statement.arguments.size()) result.object = statement.arguments[valueArgument];
        if (*kind == ManagedOperationKind::ArrayAllocation) {
            setRuntimeType(result, statement, typeArgument);
            if (options_.arrayLengthArgument < statement.arguments.size()) {
                result.length = statement.arguments[options_.arrayLengthArgument];
            }
        } else if (*kind != ManagedOperationKind::NullCheck) {
            setRuntimeType(result, statement, typeArgument);
        }
        result_.operations.push_back(std::move(result));
        return true;
    }

    void recognizeNullBranch(size_t blockIndex, size_t statementIndex, const Statement& statement) {
        if (!options_.recognizeNullBranches || statement.kind != Statement::Kind::ConditionalBranch) return;
        const auto condition = stripCasts(statement.condition);
        if (!condition || condition->kind != Expression::Kind::Binary || condition->arguments.size() != 2 ||
            (condition->op != "==" && condition->op != "!=")) {
            return;
        }
        const auto leftZero = evaluate(condition->arguments[0]);
        const auto rightZero = evaluate(condition->arguments[1]);
        ExpressionPtr object;
        if (leftZero && *leftZero == 0 && !rightZero) object = condition->arguments[1];
        if (rightZero && *rightZero == 0 && !leftZero) object = condition->arguments[0];
        if (!object) return;

        auto result = operation(ManagedOperationKind::NullCheck, blockIndex, statementIndex, statement);
        result.status = ManagedPatternStatus::Placeholder;
        result.confidence = ManagedPatternConfidence::Low;
        result.object = object;
        result.value = condition;
        result.reason = "The null comparison may be an IL2CPP null check or a managed null branch.";
        result_.operations.push_back(std::move(result));
    }

    void clearAfterCall() {
        constants_.clear();
        symbolic_.clear();
        allocations_.clear();
        memoryMayHaveChanged_ = true;
    }

    void processCall(size_t blockIndex, size_t statementIndex, const Statement& statement) {
        const auto target = evaluate(statement.target);
        if (target) {
            recognizeDirectCall(blockIndex, statementIndex, statement, *target);
            if (recognizeRuntimeCall(blockIndex, statementIndex, statement, *target)) {
                clearAfterCall();
                return;
            }
            if (options_.objectAllocatorAddresses.contains(*target)) {
                clearAfterCall();
                const auto destination = registerName(statement.destination);
                if (!destination.empty()) {
                    allocations_[destination] = {statementIndex, *target, statement.destination};
                }
                return;
            }
            recognizeObjectConstruction(blockIndex, statementIndex, statement, *target);
        } else {
            recognizeVirtualDispatch(blockIndex, statementIndex, statement);
        }
        clearAfterCall();
    }

    ExpressionPtr inlineSymbolic(const ExpressionPtr& expression, std::set<std::string>& visiting) const {
        if (!expression) return {};
        if (expression->kind == Expression::Kind::Register) {
            if (!visiting.insert(expression->name).second) return expression;
            const auto value = symbolic_.find(expression->name);
            auto result = value == symbolic_.end() ? expression : inlineSymbolic(value->second, visiting);
            visiting.erase(expression->name);
            return result;
        }
        if (expression->arguments.empty()) return expression;

        std::vector<ExpressionPtr> arguments;
        arguments.reserve(expression->arguments.size());
        bool changed = false;
        for (const auto& argument : expression->arguments) {
            auto inlined = inlineSymbolic(argument, visiting);
            changed = changed || inlined != argument;
            arguments.push_back(std::move(inlined));
        }
        if (!changed) return expression;
        auto result = std::make_shared<Expression>(*expression);
        result->arguments = std::move(arguments);
        return result;
    }

    void processAssignment(const Statement& statement) {
        const auto destination = registerName(statement.destination);
        const auto value = evaluate(statement.value);
        std::optional<AllocationState> allocation;
        const auto source = stripCasts(statement.value);
        const auto sourceName = registerName(source);
        if (!sourceName.empty()) {
            const auto it = allocations_.find(sourceName);
            if (it != allocations_.end()) allocation = it->second;
        }

        if (!destination.empty()) {
            if (value) constants_[destination] = *value;
            else constants_.erase(destination);
            std::set<std::string> visiting;
            symbolic_[destination] = inlineSymbolic(statement.value, visiting);
            if (allocation) allocations_[destination] = *allocation;
            else allocations_.erase(destination);
        }
    }

    void processStatement(size_t blockIndex, size_t statementIndex, const Statement& statement) {
        if (recognizeStringLiteral(blockIndex, statementIndex, statement)) {
            processAssignment(statement);
            return;
        }
        recognizeNullBranch(blockIndex, statementIndex, statement);
        switch (statement.kind) {
        case Statement::Kind::Assign:
            recognizeLoad(blockIndex, statementIndex, statement);
            processAssignment(statement);
            break;
        case Statement::Kind::Store:
            recognizeStore(blockIndex, statementIndex, statement);
            constants_.clear();
            symbolic_.clear();
            memoryMayHaveChanged_ = true;
            break;
        case Statement::Kind::Call:
            processCall(blockIndex, statementIndex, statement);
            break;
        default:
            break;
        }
    }
};

} // namespace

ManagedAnalysisResult ManagedPatterns::analyze(
    const RecoveredFunction& function,
    const MetadataModel& metadata,
    const ManagedPatternOptions& options) const {
    ManagedAnalysisResult result;
    result.native = function;
    AnalysisContext(function, metadata, options, result).run();
    return result;
}

} // namespace il2cpprec
