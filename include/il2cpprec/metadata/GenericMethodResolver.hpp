#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <il2cpprec/metadata/MetadataUsage.hpp>

namespace il2cpprec {

struct GenericMethodTarget {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    uint32_t genericMethodIndex = 0;
    std::optional<int32_t> methodDefinitionIndex;
    std::optional<GenericMethodPointerModel> mapping;
    std::optional<MethodModel> method;
    std::string diagnostic;
};

class GenericMethodResolver {
public:
    explicit GenericMethodResolver(const MetadataModel& metadata);

    GenericMethodTarget resolve(uint32_t genericMethodIndex) const;
    GenericMethodTarget resolveSpec(uint32_t genericMethodIndex) const;
    MetadataUsageGenericMethodResolver usageResolver() const;

private:
    const MetadataModel* metadata_;
    std::unordered_map<int32_t, std::vector<GenericMethodPointerModel>> table_;
    std::unordered_map<int32_t, std::vector<const MethodModel*>> methodDefinitions_;
};

} // namespace il2cpprec
