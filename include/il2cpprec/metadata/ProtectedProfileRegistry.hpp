#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <il2cpprec/metadata/ProtectedMetadata.hpp>

namespace il2cpprec {

struct ProtectedProfileEvidence {
    std::string kind;
    std::string value;
    std::string source;
};

struct ProtectedProfileDescriptor {
    std::string id;
    std::string metadataSha256;
    std::vector<ProtectedProfileEvidence> evidence;
    ProtectedMetadataProfile normalized;

    const ProtectedMetadataProfile& normalizedView() const noexcept;
};

struct ProtectedProfileRequest {
    std::string metadataSha256;
    std::string profileIdOverride;
};

enum class ProtectedProfileResolveError {
    None,
    ProfileRequired,
    MalformedHash,
    UnknownProfile
};

struct ProtectedProfileResolution {
    std::optional<ProtectedProfileDescriptor> profile;
    ProtectedProfileResolveError error = ProtectedProfileResolveError::ProfileRequired;
    std::string message;
    bool usedExplicitOverride = false;

    bool ok() const noexcept;
    const ProtectedMetadataProfile* normalizedView() const noexcept;
};

class ProtectedProfileRegistry {
public:
    ProtectedProfileRegistry();

    static ProtectedProfileDescriptor blockStrikeResearched();

    bool registerProfile(ProtectedProfileDescriptor profile, std::string* error = nullptr);

    const ProtectedProfileDescriptor* findById(std::string_view id) const noexcept;
    const ProtectedProfileDescriptor* findByMetadataSha256(std::string_view hash) const;
    const std::vector<ProtectedProfileDescriptor>& profiles() const noexcept;

    // Without an override, resolution requires an exact registered SHA-256. Evidence is audit data,
    // not a heuristic matcher. An override selects a known ID even when the input hash is absent.
    ProtectedProfileResolution resolve(const ProtectedProfileRequest& request) const;

private:
    std::vector<ProtectedProfileDescriptor> profiles_;
};

} // namespace il2cpprec
