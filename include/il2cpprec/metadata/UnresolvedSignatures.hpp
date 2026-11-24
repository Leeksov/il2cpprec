#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <il2cpprec/metadata/TypeSystem.hpp>

namespace il2cpprec {

enum class UnresolvedCallKind : uint8_t {
    Virtual,
    Instance,
    Static
};

struct UnresolvedStubPointers {
    std::vector<uint64_t> virtualCalls;
    std::vector<uint64_t> instanceCalls;
    std::vector<uint64_t> staticCalls;
};

struct UnresolvedSignature {
    size_t index = 0;
    int32_t start = -1;
    int32_t count = 0;
    std::vector<int32_t> parameterTypeIndices;
    std::vector<std::optional<Il2CppTypeCode>> reducedParameterTypes;
    bool valid = false;
    std::string diagnostic;
};

struct UnresolvedStub {
    uint64_t address = 0;
    UnresolvedCallKind kind = UnresolvedCallKind::Virtual;
    std::optional<size_t> signatureIndex;

    friend bool operator==(const UnresolvedStub&, const UnresolvedStub&) = default;
};

enum class UnresolvedCallsiteStatus : uint8_t {
    NotStub,
    SignatureResolved,
    AmbiguousSignature,
    InvalidSignature
};

enum class CallsiteResolutionConfidence : uint8_t {
    None,
    Low,
    Medium,
    High
};

struct UnresolvedCallsiteResolution {
    UnresolvedCallsiteStatus status = UnresolvedCallsiteStatus::NotStub;
    CallsiteResolutionConfidence confidence = CallsiteResolutionConfidence::None;
    uint64_t address = 0;
    bool sharedStub = false;
    std::optional<size_t> signatureIndex;
    std::vector<UnresolvedStub> candidates;
    std::string diagnostic;
};

class UnresolvedSignatureSet {
public:
    static UnresolvedSignatureSet build(
        const MetadataModel& metadata,
        const UnresolvedStubPointers& pointers = {},
        double metadataVersion = 0);

    const std::vector<UnresolvedSignature>& signatures() const noexcept { return signatures_; }
    const std::vector<UnresolvedStub>& stubs() const noexcept { return stubs_; }
    const std::vector<std::string>& diagnostics() const noexcept { return diagnostics_; }

    const std::set<uint64_t>& allStubs() const noexcept { return allStubs_; }
    const std::set<uint64_t>& sharedStubs() const noexcept { return sharedStubs_; }
    const std::set<uint64_t>& stubs(UnresolvedCallKind kind) const noexcept;

    bool contains(uint64_t address, std::optional<UnresolvedCallKind> kind = std::nullopt) const;
    const UnresolvedSignature* signature(size_t index) const noexcept;

    UnresolvedCallsiteResolution resolveCallsite(
        uint64_t address,
        std::optional<UnresolvedCallKind> kind = std::nullopt) const;

private:
    std::vector<UnresolvedSignature> signatures_;
    std::vector<UnresolvedStub> stubs_;
    std::vector<std::string> diagnostics_;
    std::set<uint64_t> allStubs_;
    std::set<uint64_t> sharedStubs_;
    std::set<uint64_t> virtualStubs_;
    std::set<uint64_t> instanceStubs_;
    std::set<uint64_t> staticStubs_;
};

bool supportsUnresolvedCallKind(double metadataVersion, UnresolvedCallKind kind) noexcept;

std::optional<Il2CppTypeCode> reduceUnityType(
    Il2CppTypeCode code,
    double metadataVersion,
    bool byRef = false,
    bool valueType = false) noexcept;

std::optional<Il2CppTypeCode> reduceUnityType(
    const ManagedType& type,
    double metadataVersion,
    bool valueType = false) noexcept;

std::optional<Il2CppTypeCode> reduceUnityType(
    const TypeReferenceModel& type,
    const MetadataModel& metadata,
    double metadataVersion = 0) noexcept;

} // namespace il2cpprec
