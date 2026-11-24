#include <il2cpprec/metadata/GenericMethodResolver.hpp>

#include <tuple>

namespace il2cpprec {
namespace {

bool sameMapping(const GenericMethodPointerModel& left, const GenericMethodPointerModel& right) {
    return std::tie(
        left.genericMethodIndex,
        left.methodIndex,
        left.invokerIndex,
        left.classInstAddress,
        left.methodInstAddress,
        left.methodPointer,
        left.invokerPointer) == std::tie(
        right.genericMethodIndex,
        right.methodIndex,
        right.invokerIndex,
        right.classInstAddress,
        right.methodInstAddress,
        right.methodPointer,
        right.invokerPointer);
}

} // namespace

GenericMethodResolver::GenericMethodResolver(const MetadataModel& metadata)
    : metadata_(&metadata) {
    for (const auto& mapping : metadata.genericMethodTable) {
        if (mapping.genericMethodIndex >= 0) table_[mapping.genericMethodIndex].push_back(mapping);
    }
    for (const auto& type : metadata.types) {
        for (const auto& method : type.methods) {
            if (method.definitionIndex >= 0) methodDefinitions_[method.definitionIndex].push_back(&method);
        }
    }
}

GenericMethodTarget GenericMethodResolver::resolve(uint32_t genericMethodIndex) const {
    GenericMethodTarget result;
    result.genericMethodIndex = genericMethodIndex;
    if (genericMethodIndex > static_cast<uint32_t>(INT32_MAX)) {
        result.diagnostic = "Generic method index exceeds the signed genericMethodTable index range";
        return result;
    }

    const auto mappings = table_.find(static_cast<int32_t>(genericMethodIndex));
    if (mappings == table_.end() || mappings->second.empty()) {
        result.diagnostic = "Generic method " + std::to_string(genericMethodIndex) + " is absent from genericMethodTable";
        return result;
    }
    const auto& mapping = mappings->second.front();
    for (const auto& candidate : mappings->second) {
        if (!sameMapping(mapping, candidate)) {
            result.status = MetadataUsageStatus::Ambiguous;
            result.diagnostic = "Generic method " + std::to_string(genericMethodIndex) +
                " has conflicting genericMethodTable entries";
            return result;
        }
    }
    result.mapping = mapping;

    if (genericMethodIndex >= metadata_->methodSpecs.size()) {
        result.diagnostic = "Generic method " + std::to_string(genericMethodIndex) +
            " exceeds methodSpecs count " + std::to_string(metadata_->methodSpecs.size());
        return result;
    }
    const auto& spec = metadata_->methodSpecs[genericMethodIndex];
    if (spec.methodDefinitionIndex < 0) {
        result.diagnostic = "Generic method " + std::to_string(genericMethodIndex) + " has no method definition";
        return result;
    }
    result.methodDefinitionIndex = spec.methodDefinitionIndex;

    const auto methods = methodDefinitions_.find(spec.methodDefinitionIndex);
    if (methods == methodDefinitions_.end() || methods->second.empty()) {
        result.diagnostic = "Generic method definition " + std::to_string(spec.methodDefinitionIndex) +
            " was not found in MetadataModel";
        return result;
    }
    if (methods->second.size() != 1) {
        result.status = MetadataUsageStatus::Ambiguous;
        result.diagnostic = "Generic method definition " + std::to_string(spec.methodDefinitionIndex) +
            " has multiple MethodModel records";
        return result;
    }

    result.method = *methods->second.front();
    result.status = MetadataUsageStatus::Resolved;
    return result;
}

MetadataUsageGenericMethodResolver GenericMethodResolver::usageResolver() const {
    return [this](uint32_t genericMethodIndex) {
        auto target = resolve(genericMethodIndex);
        MetadataUsageGenericMethodResolution result;
        result.status = target.status;
        result.diagnostic = target.diagnostic;
        if (target.methodDefinitionIndex && *target.methodDefinitionIndex >= 0) {
            result.methodDefinitionIndex = static_cast<uint32_t>(*target.methodDefinitionIndex);
        }
        return result;
    };
}

} // namespace il2cpprec
