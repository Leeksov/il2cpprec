#include <il2cpprec/analysis/VirtualDispatch.hpp>

#include <il2cpprec/metadata/GenericMethodResolver.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <tuple>
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

bool addAddress(uint64_t left, uint64_t right, uint64_t& result) {
    if (left > std::numeric_limits<uint64_t>::max() - right) return false;
    result = left + right;
    return true;
}

bool sameExpression(const ExpressionPtr& left, const ExpressionPtr& right) {
    if (left == right) return true;
    if (!left || !right || left->kind != right->kind || left->constant != right->constant ||
        left->name != right->name || left->op != right->op || left->arguments.size() != right->arguments.size()) {
        return false;
    }
    for (size_t index = 0; index < left->arguments.size(); ++index) {
        if (!sameExpression(left->arguments[index], right->arguments[index])) return false;
    }
    return true;
}

struct AddressParts {
    std::vector<ExpressionPtr> terms;
    int64_t displacement = 0;
    bool valid = true;
};

struct VtableAddress {
    ExpressionPtr klass;
    ExpressionPtr slotExpression;
    int64_t displacement = 0;
    bool valid = false;
};

class DispatchContext {
public:
    DispatchContext(
        const RecoveredFunction& function,
        const MetadataModel& metadata,
        const VirtualDispatchOptions& options,
        VirtualDispatchAnalysisResult& result)
        : function_(function), metadata_(metadata), options_(options), result_(result),
          metadataIndex_(options.metadataIndex && options.metadataIndex->source == &metadata
              ? options.metadataIndex : nullptr),
          pointerBits_(function.architecture == Architecture::Arm64 || function.architecture == Architecture::X64 ? 64 : 32),
          pointerSize_(pointerBits_ / 8) {
        if (!metadataIndex_) buildMethodIndex();
    }

    void run() {
        for (size_t blockIndex = 0; blockIndex < function_.blocks.size(); ++blockIndex) {
            constants_.clear();
            symbolic_.clear();
            genericResults_.clear();
            genericResultIndices_.clear();
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
    const VirtualDispatchOptions& options_;
    VirtualDispatchAnalysisResult& result_;
    const ManagedMetadataIndex* metadataIndex_ = nullptr;
    uint16_t pointerBits_;
    size_t pointerSize_;
    bool memoryMayHaveChanged_ = false;

    std::map<uint64_t, std::vector<ManagedMethodReference>> methodsByAddress_;
    std::unordered_map<std::string, uint64_t> constants_;
    std::unordered_map<std::string, ExpressionPtr> symbolic_;
    std::unordered_map<std::string, VirtualDispatchOperation> genericResults_;
    std::unordered_map<std::string, size_t> genericResultIndices_;

    uint32_t invokeDataSize() const {
        return options_.virtualInvokeDataSize == 0 ? static_cast<uint32_t>(pointerSize_ * 2) : options_.virtualInvokeDataSize;
    }

    uint32_t methodPointerOffset() const {
        return options_.methodPointerOffset;
    }

    uint32_t methodInfoOffset() const {
        return options_.methodInfoOffset == 0 ? static_cast<uint32_t>(pointerSize_) : options_.methodInfoOffset;
    }

    int64_t methodInfoDelta() const {
        return static_cast<int64_t>(methodInfoOffset()) - methodPointerOffset();
    }

    uint32_t interfaceEntrySize() const {
        if (options_.interfaceOffsetEntrySize != 0) return options_.interfaceOffsetEntrySize;
        return pointerBits_ == 64 ? 16 : 8;
    }

    uint32_t interfaceOffsetValueOffset() const {
        return options_.interfaceOffsetValueOffset == 0 ? static_cast<uint32_t>(pointerSize_) : options_.interfaceOffsetValueOffset;
    }

    bool legacyLayout() const {
        const double version = metadata_.versionInfo.preciseVersion != 0
            ? metadata_.versionInfo.preciseVersion : metadata_.version;
        return options_.unity2017Layout && version == 24.0;
    }

    std::optional<uint64_t> vtableOffset() const {
        if (options_.vtableOffset) return options_.vtableOffset;
        if (options_.vtablePointer) return uint64_t{0};
        if (legacyLayout() && pointerBits_ == 64) return 272;
        return std::nullopt;
    }

    std::optional<uint64_t> interfaceOffsetsPointerOffset() const {
        if (options_.classInterfaceOffsetsPointerOffset) return options_.classInterfaceOffsetsPointerOffset;
        if (legacyLayout() && pointerBits_ == 64) return 152;
        return std::nullopt;
    }

    std::optional<uint64_t> interfaceOffsetsCountOffset() const {
        if (options_.classInterfaceOffsetsCountOffset) return options_.classInterfaceOffsetsCountOffset;
        if (legacyLayout() && pointerBits_ == 64) return 258;
        return std::nullopt;
    }

    void buildMethodIndex() {
        std::unordered_map<std::string, int> firstDefinitionByImage;
        for (const auto& type : metadata_.types) {
            for (const auto& method : type.methods) {
                if (method.definitionIndex < 0) continue;
                auto [it, inserted] = firstDefinitionByImage.emplace(method.imageName, method.definitionIndex);
                if (!inserted) it->second = std::min(it->second, method.definitionIndex);
            }
        }
        for (const auto& type : metadata_.types) {
            const auto declaringType = qualifiedTypeName(type);
            for (const auto& method : type.methods) {
                const uint64_t address = methodAddress(method, metadata_, firstDefinitionByImage);
                if (address == 0) continue;
                ManagedMethodReference reference;
                reference.token = method.token;
                reference.definitionIndex = method.definitionIndex;
                reference.address = address;
                reference.imageName = method.imageName;
                reference.declaringType = method.declaringType.empty() ? declaringType : method.declaringType;
                reference.name = method.name;
                reference.isStatic = method.isStatic;
                methodsByAddress_[address].push_back(std::move(reference));
            }
        }
        for (auto& [address, methods] : methodsByAddress_) {
            std::sort(methods.begin(), methods.end(), [](const auto& left, const auto& right) {
                return std::tie(left.address, left.imageName, left.declaringType, left.name, left.token, left.definitionIndex) <
                    std::tie(right.address, right.imageName, right.declaringType, right.name, right.token, right.definitionIndex);
            });
        }
    }

    const std::map<uint64_t, std::vector<ManagedMethodReference>>& methodsByAddress() const {
        return metadataIndex_ ? metadataIndex_->methodsByAddress : methodsByAddress_;
    }

    std::optional<uint64_t> readImage(uint64_t address, size_t width) const {
        const auto* binary = options_.binary;
        if (!binary || binary->architecture != function_.architecture || !binary->bytes || width > 8) return std::nullopt;
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
        if (!fileOffset || *fileOffset > binary->bytes->size() || width > binary->bytes->size() - static_cast<size_t>(*fileOffset)) {
            return std::nullopt;
        }
        uint64_t value = 0;
        for (size_t index = 0; index < width; ++index) {
            value |= static_cast<uint64_t>((*binary->bytes)[static_cast<size_t>(*fileOffset) + index]) << (index * 8);
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
            if (expression->type.kind == ScalarKind::SignedInteger && (narrowed & (uint64_t{1} << (bits - 1)))) narrowed |= ~mask;
            return narrowed;
        }
        case Expression::Kind::Unary: {
            if (expression->arguments.size() != 1) return std::nullopt;
            const auto value = evaluate(expression->arguments[0]);
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
            if (memoryMayHaveChanged_ || expression->arguments.size() != 1 || expression->type.bits != pointerBits_) {
                return std::nullopt;
            }
            const auto address = evaluate(expression->arguments[0]);
            if (!address) return std::nullopt;
            return readImage(*address, pointerSize_);
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
        if (expression->kind == Expression::Kind::Load) {
            if (negate) parts.valid = false;
            else parts.terms.push_back(expression);
            return;
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

    ExpressionPtr managedObject(const ExpressionPtr& klass) const {
        if (!klass || klass->kind != Expression::Kind::Load || klass->arguments.size() != 1) return {};
        const auto object = decomposeAddress(klass->arguments[0]);
        if (!object.valid) return {};
        const auto klassOffset = std::bit_cast<int64_t>(options_.objectKlassOffset);
        if (object.terms.size() == 1 && object.displacement == klassOffset) return object.terms.front();
        if (object.terms.empty()) {
            const auto address = evaluate(klass->arguments[0]);
            if (address && *address >= options_.objectKlassOffset) {
                return constant(*address - options_.objectKlassOffset, ScalarType::pointer(pointerBits_));
            }
        }
        return {};
    }

    bool scaledSlot(const ExpressionPtr& input, ExpressionPtr& slot) const {
        const auto expression = stripCasts(input);
        if (!expression || expression->kind != Expression::Kind::Binary || expression->arguments.size() != 2) return false;
        if (expression->op == "*") {
            const auto left = evaluate(expression->arguments[0]);
            const auto right = evaluate(expression->arguments[1]);
            if (left && *left == invokeDataSize()) {
                slot = expression->arguments[1];
                return true;
            }
            if (right && *right == invokeDataSize()) {
                slot = expression->arguments[0];
                return true;
            }
        }
        if (expression->op == "<<") {
            const auto shift = evaluate(expression->arguments[1]);
            if (shift && *shift < 64 && (uint64_t{1} << *shift) == invokeDataSize()) {
                slot = expression->arguments[0];
                return true;
            }
        }
        return false;
    }

    VtableAddress parseVtableAddress(const ExpressionPtr& expression) const {
        const auto parts = decomposeAddress(expression);
        VtableAddress result;
        if (!parts.valid || parts.displacement < 0) return result;
        result.displacement = parts.displacement;
        if (parts.terms.size() == 1) {
            result.klass = stripCasts(parts.terms.front());
        } else if (parts.terms.size() == 2) {
            if (scaledSlot(parts.terms[0], result.slotExpression)) result.klass = stripCasts(parts.terms[1]);
            else if (scaledSlot(parts.terms[1], result.slotExpression)) result.klass = stripCasts(parts.terms[0]);
        }
        result.valid = result.klass && result.klass->kind == Expression::Kind::Load;
        return result;
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

    ExpressionPtr expand(ExpressionPtr expression) const {
        std::set<std::string> visiting;
        return inlineSymbolic(std::move(expression), visiting);
    }

    VirtualDispatchOperation operation(
        VirtualDispatchKind kind,
        size_t blockIndex,
        size_t statementIndex,
        const Statement& statement) const {
        VirtualDispatchOperation result;
        result.kind = kind;
        result.address = statement.address;
        result.blockIndex = blockIndex;
        result.statementIndex = statementIndex;
        result.nativeStatements = {statement};
        return result;
    }

    void appendMethods(uint64_t address, std::vector<ManagedMethodReference>& methods) const {
        if (address == 0) return;
        const auto& index = methodsByAddress();
        const auto found = index.find(address);
        if (found != index.end()) methods.insert(methods.end(), found->second.begin(), found->second.end());
    }

    void appendGenerics(VirtualDispatchOperation& result, uint64_t address) const {
        if (address == 0) return;
        std::vector<std::pair<int32_t, GenericMethodPointerModel>> candidates;
        for (const auto& mapping : metadata_.genericMethodTable) {
            if (mapping.methodPointer == address && mapping.genericMethodIndex >= 0) {
                candidates.emplace_back(mapping.genericMethodIndex, mapping);
            }
            if (mapping.adjustorThunk == address && address != 0 && mapping.genericMethodIndex >= 0) {
                candidates.emplace_back(mapping.genericMethodIndex, mapping);
            }
        }
        const auto adjustor = options_.profile.genericAdjustorTargets.find(address);
        if (adjustor != options_.profile.genericAdjustorTargets.end() &&
            adjustor->second <= static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
            const auto mapping = std::find_if(metadata_.genericMethodTable.begin(), metadata_.genericMethodTable.end(), [&](const auto& candidate) {
                return candidate.genericMethodIndex == static_cast<int32_t>(adjustor->second);
            });
            if (mapping != metadata_.genericMethodTable.end()) candidates.emplace_back(mapping->genericMethodIndex, *mapping);
        }
        std::sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) { return left.first < right.first; });
        candidates.erase(std::unique(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) { return left.first == right.first; }), candidates.end());
        if (candidates.size() != 1) return;
        const auto [index, mapping] = candidates.front();
        const auto resolved = GenericMethodResolver(metadata_).resolve(static_cast<uint32_t>(index));
        if (resolved.status != MetadataUsageStatus::Resolved || !resolved.method) return;
        ManagedMethodReference reference;
        reference.token = resolved.method->token;
        reference.definitionIndex = resolved.method->definitionIndex;
        reference.address = mapping.methodPointer;
        reference.imageName = resolved.method->imageName;
        reference.declaringType = resolved.method->declaringType;
        reference.name = resolved.method->name;
        reference.isStatic = resolved.method->isStatic;
        result.methodCandidates.push_back(reference);
        result.genericTarget.present = true;
        result.genericTarget.adjustor = mapping.adjustorThunk == address || adjustor != options_.profile.genericAdjustorTargets.end();
        result.genericTarget.genericMethodIndex = index;
        result.genericTarget.mapping = mapping;
        if (static_cast<size_t>(index) < metadata_.methodSpecs.size()) {
            result.genericTarget.classInstIndex = metadata_.methodSpecs[static_cast<size_t>(index)].classInstIndex;
            result.genericTarget.methodInstIndex = metadata_.methodSpecs[static_cast<size_t>(index)].methodInstIndex;
        }
    }

    void applyGenericKind(VirtualDispatchOperation& result) const {
        bool generic = result.genericTarget.present || (result.hasMethodInfo && options_.genericMethodInfo.contains(result.invokeData.methodInfo));
        if (result.slot) {
            generic = generic || (result.kind == VirtualDispatchKind::Interface || result.kind == VirtualDispatchKind::GenericInterface
                ? options_.genericInterfaceSlots.contains(*result.slot)
                : options_.genericVirtualSlots.contains(*result.slot));
        }
        if (!generic) {
            for (const auto& method : result.methodCandidates) {
                if (method.name.find('<') != std::string::npos || method.name.find('`') != std::string::npos) {
                    generic = true;
                    break;
                }
            }
        }
        if (!generic) return;
        if (result.kind == VirtualDispatchKind::Interface || result.kind == VirtualDispatchKind::GenericInterface) {
            result.kind = VirtualDispatchKind::GenericInterface;
        } else {
            result.kind = VirtualDispatchKind::GenericVirtual;
        }
    }

    void resolveManaged(VirtualDispatchOperation& result) const {
        result.methodCandidates.clear();
        if (result.invokeData.methodPointer != 0 &&
            (options_.profile.unresolvedVirtualCallStubs.contains(result.invokeData.methodPointer) ||
             std::find(metadata_.unresolvedVirtualCallPointers.begin(), metadata_.unresolvedVirtualCallPointers.end(),
                       result.invokeData.methodPointer) != metadata_.unresolvedVirtualCallPointers.end())) {
            result.status = ManagedPatternStatus::Unresolved;
            result.confidence = ManagedPatternConfidence::Medium;
            result.reason = "VirtualInvokeData points to an unresolved virtual-call stub.";
            return;
        }
        appendMethods(result.invokeData.methodPointer, result.methodCandidates);
        appendGenerics(result, result.invokeData.methodPointer);
        const auto inflated = options_.methodInfoTargets.find(result.invokeData.methodInfo);
        if (result.hasMethodInfo && inflated != options_.methodInfoTargets.end()) {
            appendMethods(inflated->second, result.methodCandidates);
            appendGenerics(result, inflated->second);
        }
        std::sort(result.methodCandidates.begin(), result.methodCandidates.end(), [](const auto& left, const auto& right) {
            return std::tie(left.address, left.imageName, left.declaringType, left.name, left.token, left.definitionIndex) <
                std::tie(right.address, right.imageName, right.declaringType, right.name, right.token, right.definitionIndex);
        });
        result.methodCandidates.erase(std::unique(result.methodCandidates.begin(), result.methodCandidates.end(), [](const auto& left, const auto& right) {
            return left.address == right.address && left.token == right.token && left.declaringType == right.declaringType && left.name == right.name;
        }), result.methodCandidates.end());
        applyGenericKind(result);

        const bool generic = result.kind == VirtualDispatchKind::GenericVirtual || result.kind == VirtualDispatchKind::GenericInterface;
        const bool exactInflated = result.genericTarget.present || (result.hasMethodInfo && inflated != options_.methodInfoTargets.end());
        if (result.methodCandidates.size() > 1) {
            result.status = ManagedPatternStatus::Ambiguous;
            result.confidence = ManagedPatternConfidence::Low;
            result.reason = "Multiple managed methods match the recovered VirtualInvokeData.";
            return;
        }
        if (result.methodCandidates.size() == 1) {
            result.method = result.methodCandidates.front();
            if (!generic || exactInflated) {
                result.status = ManagedPatternStatus::Resolved;
                result.confidence = ManagedPatternConfidence::High;
                result.reason.clear();
                return;
            }
            result.status = ManagedPatternStatus::Placeholder;
            result.confidence = ManagedPatternConfidence::Medium;
            result.reason = "The open generic method is known, but the exact inflated target is not configured.";
            return;
        }
        result.status = ManagedPatternStatus::Placeholder;
        result.confidence = result.hasMethodPointer || result.hasMethodInfo
            ? ManagedPatternConfidence::Medium
            : ManagedPatternConfidence::Low;
        result.reason = generic
            ? "The generic dispatch shape is known, but its inflated managed target is unresolved."
            : "The dispatch shape is known, but its managed target is unresolved.";
    }

    void resolveInvokeData(VirtualDispatchOperation& result) const {
        if (result.invokeDataAddress == 0) return;
        const auto configured = options_.invokeDataByAddress.find(result.invokeDataAddress);
        if (configured != options_.invokeDataByAddress.end()) {
            result.invokeData = configured->second;
            result.hasMethodPointer = true;
            result.hasMethodInfo = true;
        } else {
            uint64_t methodPointerAddress = 0;
            uint64_t methodInfoAddress = 0;
            const auto methodPointer = addAddress(result.invokeDataAddress, methodPointerOffset(), methodPointerAddress)
                ? readImage(methodPointerAddress, pointerSize_)
                : std::nullopt;
            const auto methodInfo = addAddress(result.invokeDataAddress, methodInfoOffset(), methodInfoAddress)
                ? readImage(methodInfoAddress, pointerSize_)
                : std::nullopt;
            if (methodPointer) {
                result.invokeData.methodPointer = *methodPointer;
                result.hasMethodPointer = true;
            }
            if (methodInfo) {
                result.invokeData.methodInfo = *methodInfo;
                result.hasMethodInfo = true;
            }
        }
        resolveManaged(result);
    }

    void resolveEntry(VirtualDispatchOperation& result, uint64_t klassAddress, uint64_t byteOffset) const {
        result.klassAddress = klassAddress;
        uint64_t base = klassAddress;
        if (options_.vtablePointer) {
            if (result.vtableAddress == 0) {
                if (!options_.classVtablePointerOffset) {
                    resolveManaged(result);
                    return;
                }
                uint64_t pointerAddress = 0;
                if (!addAddress(klassAddress, *options_.classVtablePointerOffset, pointerAddress)) {
                    resolveManaged(result);
                    return;
                }
                const auto vtable = readImage(pointerAddress, pointerSize_);
                if (!vtable) {
                    resolveManaged(result);
                    return;
                }
                result.vtableAddress = *vtable;
            }
            base = result.vtableAddress;
        } else {
            result.vtableAddress = klassAddress;
        }
        if (!addAddress(base, byteOffset, result.invokeDataAddress)) {
            resolveManaged(result);
            return;
        }
        resolveInvokeData(result);
    }

    void resolveObjectClass(VirtualDispatchOperation& result) const {
        const auto objectAddress = evaluate(result.object);
        if (!objectAddress) return;
        uint64_t klassAddress = 0;
        if (!addAddress(*objectAddress, options_.objectKlassOffset, klassAddress)) return;
        const auto klass = readImage(klassAddress, pointerSize_);
        if (klass) result.klassAddress = *klass;
    }

    std::optional<uint64_t> slotOffset(uint32_t slot) const {
        const auto base = vtableOffset();
        if (!base || slot > (std::numeric_limits<uint64_t>::max() - *base) / invokeDataSize()) return std::nullopt;
        return *base + static_cast<uint64_t>(slot) * invokeDataSize();
    }

    void resolveInterface(VirtualDispatchOperation& result) const {
        if (result.klassAddress == 0 || result.interfaceAddress == 0 || !result.slot) return;
        std::vector<VirtualInterfaceOffset> offsets;
        const auto configured = options_.interfaceOffsetsByClass.find(result.klassAddress);
        if (configured != options_.interfaceOffsetsByClass.end()) {
            offsets = configured->second;
        } else {
            const auto pointerOffset = interfaceOffsetsPointerOffset();
            const auto countOffset = interfaceOffsetsCountOffset();
            if (!pointerOffset || !countOffset) return;
            uint64_t pointerAddress = 0;
            uint64_t countAddress = 0;
            if (!addAddress(result.klassAddress, *pointerOffset, pointerAddress) ||
                !addAddress(result.klassAddress, *countOffset, countAddress)) {
                return;
            }
            const auto table = readImage(pointerAddress, pointerSize_);
            const auto count = readImage(countAddress, 2);
            if (!table || !count || *count > 4096) return;
            offsets.reserve(static_cast<size_t>(*count));
            for (uint64_t index = 0; index < *count; ++index) {
                uint64_t entry = 0;
                if (index > (std::numeric_limits<uint64_t>::max() - *table) / interfaceEntrySize() ||
                    !addAddress(*table, index * interfaceEntrySize(), entry)) {
                    offsets.clear();
                    break;
                }
                uint64_t offsetAddress = 0;
                const auto interfaceType = readImage(entry, pointerSize_);
                const auto offset = addAddress(entry, interfaceOffsetValueOffset(), offsetAddress)
                    ? readImage(offsetAddress, 4)
                    : std::nullopt;
                if (!interfaceType || !offset) {
                    offsets.clear();
                    break;
                }
                offsets.push_back({*interfaceType, std::bit_cast<int32_t>(static_cast<uint32_t>(*offset))});
            }
        }

        std::vector<int32_t> matches;
        for (const auto& entry : offsets) {
            if (entry.interfaceType == result.interfaceAddress) matches.push_back(entry.offset);
        }
        std::sort(matches.begin(), matches.end());
        matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
        if (matches.size() != 1) {
            result.status = matches.empty() ? ManagedPatternStatus::Unresolved : ManagedPatternStatus::Ambiguous;
            result.confidence = ManagedPatternConfidence::Low;
            result.reason = matches.empty()
                ? "No interface offset matches the recovered interface and class."
                : "Multiple interface offsets match the recovered interface and class.";
            return;
        }
        result.interfaceOffset = matches.front();
        result.hasInterfaceOffset = true;
        if (matches.front() < 0) {
            result.status = ManagedPatternStatus::Unresolved;
            result.confidence = ManagedPatternConfidence::Low;
            result.reason = "The recovered interface offset is negative.";
            return;
        }
        uint64_t relative = 0;
        if (*result.slot > std::numeric_limits<uint64_t>::max() / invokeDataSize() ||
            !addAddress(static_cast<uint64_t>(matches.front()), static_cast<uint64_t>(*result.slot) * invokeDataSize(), relative)) {
            result.status = ManagedPatternStatus::Unresolved;
            result.confidence = ManagedPatternConfidence::Low;
            result.reason = "The interface vtable offset overflows the native address range.";
            return;
        }
        resolveEntry(result, result.klassAddress, relative);
    }

    bool recognizeInline(size_t blockIndex, size_t statementIndex, const Statement& statement) {
        const auto target = stripCasts(expand(statement.target));
        if (!target || target->kind != Expression::Kind::Load || target->arguments.size() != 1) return false;
        const auto genericBase = stripCasts(target->arguments[0]);
        const auto genericName = registerName(genericBase);
        if (!genericName.empty()) {
            const auto generic = genericResults_.find(genericName);
            if (generic != genericResults_.end()) {
                auto result = generic->second;
                const auto firstStatement = result.statementIndex;
                result.address = statement.address;
                result.statementIndex = statementIndex;
                result.methodPointerExpression = target;
                result.methodInfoPassed = std::any_of(statement.arguments.begin(), statement.arguments.end(), [&](const auto& argument) {
                    return registerName(stripCasts(argument)) == genericName;
                });
                const auto& statements = function_.blocks[blockIndex].statements;
                result.nativeStatements.assign(
                    statements.begin() + static_cast<std::ptrdiff_t>(firstStatement),
                    statements.begin() + static_cast<std::ptrdiff_t>(statementIndex + 1));
                resolveManaged(result);
                const auto outputIndex = genericResultIndices_.find(genericName);
                if (outputIndex != genericResultIndices_.end() && outputIndex->second < result_.operations.size()) {
                    result_.operations[outputIndex->second] = std::move(result);
                } else {
                    result_.operations.push_back(std::move(result));
                }
                return true;
            }
        }

        const auto slot = parseVtableAddress(target->arguments[0]);
        if (!slot.valid || slot.displacement < methodPointerOffset()) return false;
        const auto& klass = slot.klass;
        auto classExpression = klass;
        ExpressionPtr object;
        if (options_.vtablePointer) {
            if (!options_.classVtablePointerOffset) return false;
            const auto classPointer = decomposeAddress(klass->arguments[0]);
            if (!classPointer.valid || classPointer.terms.size() != 1 ||
                classPointer.displacement != std::bit_cast<int64_t>(*options_.classVtablePointerOffset)) {
                return false;
            }
            classExpression = stripCasts(classPointer.terms.front());
        }
        object = managedObject(classExpression);
        if (!object) return false;
        const int64_t entryOffset = slot.displacement - methodPointerOffset();

        auto result = operation(VirtualDispatchKind::Virtual, blockIndex, statementIndex, statement);
        result.object = object;
        result.methodPointerExpression = target;
        result.slotExpression = slot.slotExpression;
        result.vtableOffset = entryOffset;
        const auto base = vtableOffset();
        if (!slot.slotExpression && base && static_cast<uint64_t>(entryOffset) >= *base) {
            const auto relative = static_cast<uint64_t>(entryOffset) - *base;
            if (relative % invokeDataSize() == 0 && relative / invokeDataSize() <= std::numeric_limits<uint32_t>::max()) {
                result.slot = static_cast<uint32_t>(relative / invokeDataSize());
            }
        }

        auto matchMethodInfo = [&](const ExpressionPtr& input) {
            const auto candidate = stripCasts(expand(input));
            if (!candidate || candidate->kind != Expression::Kind::Load || candidate->arguments.size() != 1) return false;
            const auto info = parseVtableAddress(candidate->arguments[0]);
            if (!info.valid || !sameExpression(info.klass, klass) || !sameExpression(info.slotExpression, slot.slotExpression) ||
                info.displacement != slot.displacement + methodInfoDelta()) {
                return false;
            }
            result.methodInfoExpression = candidate;
            result.methodInfoPassed = true;
            return true;
        };
        for (const auto& argument : statement.arguments) {
            if (matchMethodInfo(argument)) break;
        }
        if (!result.methodInfoPassed && statement.kind == Statement::Kind::Branch) {
            std::vector<std::pair<std::string, ExpressionPtr>> registers(symbolic_.begin(), symbolic_.end());
            std::sort(registers.begin(), registers.end(), [](const auto& left, const auto& right) { return left.first < right.first; });
            for (const auto& [name, value] : registers) {
                if (matchMethodInfo(value)) break;
            }
        }
        const auto klassAddress = evaluate(classExpression);
        if (klassAddress) result.klassAddress = *klassAddress;
        else resolveObjectClass(result);
        if (options_.vtablePointer) {
            if (const auto vtable = evaluate(klass)) result.vtableAddress = *vtable;
        }
        if (result.klassAddress != 0 && !slot.slotExpression) resolveEntry(result, result.klassAddress, static_cast<uint64_t>(entryOffset));
        else resolveManaged(result);
        result_.operations.push_back(std::move(result));
        return true;
    }

    bool recognizeHelper(size_t blockIndex, size_t statementIndex, const Statement& statement, uint64_t target) {
        VirtualDispatchKind kind;
        bool interfaceCall = false;
        if (options_.virtualHelperAddresses.contains(target)) kind = VirtualDispatchKind::Virtual;
        else if (options_.genericVirtualHelperAddresses.contains(target)) kind = VirtualDispatchKind::GenericVirtual;
        else if (options_.interfaceHelperAddresses.contains(target)) {
            kind = VirtualDispatchKind::Interface;
            interfaceCall = true;
        } else if (options_.genericInterfaceHelperAddresses.contains(target)) {
            kind = VirtualDispatchKind::GenericInterface;
            interfaceCall = true;
        } else {
            return false;
        }

        auto result = operation(kind, blockIndex, statementIndex, statement);
        auto argument = [&](size_t index) -> ExpressionPtr {
            if (index < statement.arguments.size()) return statement.arguments[index];
            if (statement.kind != Statement::Kind::Branch) return {};
            static constexpr const char* arm64Registers[] = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
            static constexpr const char* arm32Registers[] = {"r0", "r1", "r2", "r3"};
            static constexpr const char* x64Registers[] = {"rcx", "rdx", "r8", "r9"};
            static constexpr const char* x86Registers[] = {"ecx", "edx"};
            const char* name = nullptr;
            switch (function_.architecture) {
            case Architecture::Arm64:
                if (index < 8) name = arm64Registers[index];
                break;
            case Architecture::Arm32:
                if (index < 4) name = arm32Registers[index];
                break;
            case Architecture::X64:
                if (index < 4) name = x64Registers[index];
                break;
            case Architecture::X86:
                if (index < 2) name = x86Registers[index];
                break;
            }
            return name ? expand(reg(name, ScalarType::pointer(pointerBits_))) : ExpressionPtr{};
        };
        const auto slotArgument = interfaceCall ? options_.interfaceSlotArgument : options_.virtualSlotArgument;
        const auto objectArgument = interfaceCall ? options_.interfaceObjectArgument : options_.virtualObjectArgument;
        if (const auto value = argument(slotArgument)) {
            result.slotExpression = value;
            const auto slot = evaluate(value);
            if (slot && *slot <= std::numeric_limits<uint32_t>::max()) result.slot = static_cast<uint32_t>(*slot);
        }
        result.object = argument(objectArgument);
        if (interfaceCall) {
            if (const auto value = argument(options_.interfaceTypeArgument)) {
                const auto interfaceType = evaluate(value);
                if (interfaceType) result.interfaceAddress = *interfaceType;
            }
        }
        resolveObjectClass(result);
        if (interfaceCall) {
            resolveInterface(result);
        } else if (result.klassAddress != 0 && result.slot) {
            const auto offset = slotOffset(*result.slot);
            if (offset) resolveEntry(result, result.klassAddress, *offset);
        }
        if (result.status == ManagedPatternStatus::Placeholder && result.reason.empty()) resolveManaged(result);
        result_.operations.push_back(std::move(result));
        return true;
    }

    bool captureGenericResolver(size_t blockIndex, size_t statementIndex, const Statement& statement, uint64_t target) {
        if (!options_.genericMethodResolverAddresses.contains(target)) return false;
        genericResults_.clear();
        genericResultIndices_.clear();
        const auto destination = registerName(statement.destination);
        if (!destination.empty()) {
            for (const auto& argument : statement.arguments) {
                const auto info = stripCasts(expand(argument));
                if (!info || info->kind != Expression::Kind::Load || info->arguments.size() != 1) continue;
                const auto address = parseVtableAddress(info->arguments[0]);
                if (!address.valid || address.displacement < methodInfoOffset()) continue;
                const auto& klass = address.klass;
                auto classExpression = klass;
                if (options_.vtablePointer) {
                    if (!options_.classVtablePointerOffset) continue;
                    const auto classPointer = decomposeAddress(klass->arguments[0]);
                    if (!classPointer.valid || classPointer.terms.size() != 1 ||
                        classPointer.displacement != std::bit_cast<int64_t>(*options_.classVtablePointerOffset)) {
                        continue;
                    }
                    classExpression = stripCasts(classPointer.terms.front());
                }
                const auto object = managedObject(classExpression);
                if (!object) continue;

                auto result = operation(VirtualDispatchKind::GenericVirtual, blockIndex, statementIndex, statement);
                result.object = object;
                result.methodInfoExpression = info;
                result.slotExpression = address.slotExpression;
                result.vtableOffset = address.displacement - methodInfoOffset();
                const auto base = vtableOffset();
                if (!address.slotExpression && base && static_cast<uint64_t>(result.vtableOffset) >= *base) {
                    const auto relative = static_cast<uint64_t>(result.vtableOffset) - *base;
                    if (relative % invokeDataSize() == 0 && relative / invokeDataSize() <= std::numeric_limits<uint32_t>::max()) {
                        result.slot = static_cast<uint32_t>(relative / invokeDataSize());
                    }
                }
                const auto klassAddress = evaluate(classExpression);
                if (klassAddress) result.klassAddress = *klassAddress;
                if (options_.vtablePointer) {
                    if (const auto vtable = evaluate(klass)) result.vtableAddress = *vtable;
                }
                if (result.klassAddress != 0 && !address.slotExpression) {
                    resolveEntry(result, result.klassAddress, static_cast<uint64_t>(result.vtableOffset));
                } else {
                    resolveManaged(result);
                }
                if (result.status == ManagedPatternStatus::Resolved) {
                    result.status = ManagedPatternStatus::Placeholder;
                    result.confidence = ManagedPatternConfidence::Medium;
                    result.reason = "The generic target is configured, but the resolver has not yet been linked to an invocation.";
                }
                genericResultIndices_[destination] = result_.operations.size();
                result_.operations.push_back(result);
                genericResults_[destination] = std::move(result);
                break;
            }
        }
        constants_.clear();
        symbolic_.clear();
        memoryMayHaveChanged_ = true;
        return true;
    }

    void clearAfterCall() {
        constants_.clear();
        symbolic_.clear();
        genericResults_.clear();
        genericResultIndices_.clear();
        memoryMayHaveChanged_ = true;
    }

    void processAssignment(const Statement& statement) {
        const auto destination = registerName(statement.destination);
        const auto value = evaluate(statement.value);
        std::optional<VirtualDispatchOperation> generic;
        std::optional<size_t> genericIndex;
        const auto sourceName = registerName(stripCasts(statement.value));
        if (!sourceName.empty()) {
            const auto found = genericResults_.find(sourceName);
            if (found != genericResults_.end()) generic = found->second;
            const auto index = genericResultIndices_.find(sourceName);
            if (index != genericResultIndices_.end()) genericIndex = index->second;
        }
        if (!destination.empty()) {
            if (value) constants_[destination] = *value;
            else constants_.erase(destination);
            symbolic_[destination] = expand(statement.value);
            if (generic) genericResults_[destination] = *generic;
            else genericResults_.erase(destination);
            if (genericIndex) genericResultIndices_[destination] = *genericIndex;
            else genericResultIndices_.erase(destination);
        }
    }

    void processStatement(size_t blockIndex, size_t statementIndex, const Statement& statement) {
        switch (statement.kind) {
        case Statement::Kind::Assign:
            processAssignment(statement);
            break;
        case Statement::Kind::Store:
            constants_.clear();
            symbolic_.clear();
            genericResults_.clear();
            genericResultIndices_.clear();
            memoryMayHaveChanged_ = true;
            break;
        case Statement::Kind::Call: {
            const auto target = evaluate(statement.target);
            if (target && captureGenericResolver(blockIndex, statementIndex, statement, *target)) return;
            recognizeInline(blockIndex, statementIndex, statement);
            if (target) recognizeHelper(blockIndex, statementIndex, statement, *target);
            clearAfterCall();
            break;
        }
        case Statement::Kind::Branch: {
            const auto target = evaluate(statement.target);
            recognizeInline(blockIndex, statementIndex, statement);
            if (target) recognizeHelper(blockIndex, statementIndex, statement, *target);
            clearAfterCall();
            break;
        }
        default:
            break;
        }
    }
};

} // namespace

VirtualDispatchAnalysisResult VirtualDispatch::analyze(
    const RecoveredFunction& function,
    const MetadataModel& metadata,
    const VirtualDispatchOptions& options) const {
    VirtualDispatchAnalysisResult result;
    result.native = function;
    DispatchContext(function, metadata, options, result).run();
    return result;
}

} // namespace il2cpprec
