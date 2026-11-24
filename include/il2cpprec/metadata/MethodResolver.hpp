#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>
#include <il2cpprec/Recovery.hpp>

namespace il2cpprec {

struct MethodResolverOptions {
    bool discoverModules = true;
    size_t maxFunctionSize = 64 * 1024;
};

enum class MethodResolutionError {
    MissingDefinitionIndex,
    MissingMethodPointerTable,
    UnsupportedLegacyMapping,
    MissingMethodIndex,
    InvalidMethodToken,
    PointerIndexOutOfRange,
    NullPointer,
    UnmappedAddress,
    NonExecutableAddress,
};

struct UnresolvedMethod {
    std::string imageName;
    std::string declaringType;
    std::string name;
    uint32_t token = 0;
    int definitionIndex = -1;
    int methodIndex = -1;
    std::optional<size_t> pointerIndex;
    uint64_t pointer = 0;
    MethodResolutionError error = MethodResolutionError::UnmappedAddress;
    std::string diagnostic;
};

enum class DeclarationOnlyReason {
    ExpectedNoNativeBody,
    EmptyAssembly,
};

struct DeclarationOnlyMethod {
    std::string imageName;
    std::string declaringType;
    std::string name;
    uint32_t token = 0;
    int definitionIndex = -1;
    int methodIndex = -1;
    DeclarationOnlyReason reason = DeclarationOnlyReason::ExpectedNoNativeBody;
    std::string diagnostic;
};

struct MethodResolutionReport {
    size_t totalMethods = 0;
    size_t resolvedMethods = 0;
    size_t declarationOnly = 0;
    size_t actualUnresolved = 0;
    size_t adjustorThunks = 0;
    size_t unresolvedStubs = 0;
    size_t duplicateAddresses = 0;
    size_t sizeLimitedFunctions = 0;
    std::vector<DeclarationOnlyMethod> declarations;
    std::vector<UnresolvedMethod> unresolved;
    std::vector<std::string> auxiliaryDiagnostics;
};

struct MethodAddressMetadata {
    std::string fullName;
    uint32_t token = 0;
    std::string imageName;
    std::string declaringType;
    int methodIndex = -1;
};

using MethodAddressMapping = std::map<uint64_t, MethodAddressMetadata>;
using AdjustorThunkMapping = std::map<uint64_t, MethodAddressMetadata>;

enum class UnresolvedStubKind {
    Virtual,
    Instance,
    Static,
};

struct UnresolvedStub {
    uint64_t address = 0;
    uint32_t token = 0;
    UnresolvedStubKind kind = UnresolvedStubKind::Virtual;
    size_t index = 0;
    std::string fullName;
};

using UnresolvedStubMapping = std::map<uint64_t, UnresolvedStub>;

struct MethodResolutionResult {
    std::vector<FunctionImage> functions;
    MetadataModel metadata;
    MethodAddressMapping methodMapping;
    AdjustorThunkMapping adjustorThunkMapping;
    UnresolvedStubMapping unresolvedStubs;
    MethodResolutionReport report;
};

class MethodResolver {
public:
    explicit MethodResolver(MethodResolverOptions options = {});

    std::vector<FunctionImage> resolve(const MetadataModel& metadata, const BinaryImage& binary) const;
    MethodResolutionResult resolveWithReport(const MetadataModel& metadata, const BinaryImage& binary) const;

private:
    MethodResolverOptions options_;
};

} // namespace il2cpprec
