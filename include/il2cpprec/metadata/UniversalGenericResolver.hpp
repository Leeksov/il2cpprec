#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <il2cpprec/metadata/MetadataUsage.hpp>

namespace il2cpprec {

enum class UniversalGenericConfidence {
    Unresolved,
    Partial,
    Resolved
};

struct UniversalGenericVersionProfile {
    bool supported = false;
    bool adjustorThunks = false;
    bool perImageInvokerIndices = false;
};

struct UniversalGenericSubstitution {
    std::vector<int32_t> classArguments;
    std::vector<int32_t> methodArguments;
};

struct UniversalGenericResolverOptions {
    std::unordered_map<uint64_t, int32_t> typeReferencesByAddress;
    std::unordered_map<uint64_t, std::vector<int32_t>> genericInstArgumentsByAddress;
};

struct UniversalGenericTypeResolution {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    UniversalGenericConfidence confidence = UniversalGenericConfidence::Unresolved;
    int32_t sourceTypeIndex = -1;
    TypeReferenceModel type;
    std::string name;
    bool substituted = false;
    std::vector<std::string> diagnostics;

    bool ok() const noexcept;
};

struct UniversalGenericInstResolution {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    UniversalGenericConfidence confidence = UniversalGenericConfidence::Unresolved;
    int32_t genericInstIndex = -1;
    uint64_t genericInstAddress = 0;
    std::vector<int32_t> typeArgumentIndices;
    std::vector<std::string> diagnostics;

    bool ok() const noexcept;
};

struct UniversalGenericClassResolution {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    UniversalGenericConfidence confidence = UniversalGenericConfidence::Unresolved;
    uint32_t genericClassIndex = 0;
    std::optional<GenericClassModel> genericClass;
    UniversalGenericInstResolution classInst;
    UniversalGenericInstResolution methodInst;
    UniversalGenericTypeResolution type;
    UniversalGenericSubstitution substitution;
    std::vector<std::string> diagnostics;

    bool ok() const noexcept;
};

struct UniversalGenericMethodResolution {
    MetadataUsageStatus status = MetadataUsageStatus::Unresolved;
    UniversalGenericConfidence confidence = UniversalGenericConfidence::Unresolved;
    uint32_t genericMethodIndex = 0;
    std::optional<int32_t> methodDefinitionIndex;
    std::optional<GenericMethodSpecModel> methodSpec;
    std::optional<GenericMethodPointerModel> mapping;
    std::optional<MethodModel> method;
    UniversalGenericSubstitution substitution;
    UniversalGenericInstResolution classInst;
    UniversalGenericInstResolution methodInst;
    std::optional<UniversalGenericTypeResolution> declaringType;
    std::optional<UniversalGenericTypeResolution> returnType;
    std::vector<UniversalGenericTypeResolution> parameterTypes;
    uint64_t methodPointer = 0;
    uint64_t entryPoint = 0;
    uint64_t invokerPointer = 0;
    uint64_t adjustorThunk = 0;
    int32_t selectedInvokerIndex = -1;
    bool adjustorThunkSelected = false;
    std::vector<std::string> diagnostics;

    bool ok() const noexcept;
};

class UniversalGenericResolver {
public:
    explicit UniversalGenericResolver(
        const MetadataModel& metadata,
        UniversalGenericResolverOptions options = {});

    static UniversalGenericVersionProfile versionProfile(double metadataVersion) noexcept;
    static bool supportsVersion(double metadataVersion) noexcept;

    UniversalGenericTypeResolution substitute(
        int32_t typeReferenceIndex,
        const UniversalGenericSubstitution& substitution = {}) const;
    UniversalGenericTypeResolution substitute(
        const TypeReferenceModel& type,
        const UniversalGenericSubstitution& substitution = {}) const;

    UniversalGenericInstResolution resolveGenericInst(
        int32_t genericInstIndex,
        uint64_t genericInstAddress = 0) const;
    UniversalGenericClassResolution resolveGenericClass(uint32_t genericClassIndex) const;

    UniversalGenericMethodResolution resolve(uint32_t genericMethodIndex) const;
    UniversalGenericMethodResolution resolve(
        uint32_t genericMethodIndex,
        const UniversalGenericSubstitution& substitution) const;
    UniversalGenericMethodResolution resolveMethodSpec(uint32_t genericMethodIndex) const;

private:
    const MetadataModel* metadata_;
    UniversalGenericResolverOptions options_;
};

const char* toString(UniversalGenericConfidence confidence) noexcept;

} // namespace il2cpprec
