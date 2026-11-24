#include <il2cpprec/metadata/ProtectedProfileRegistry.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>

#ifdef IL2CPPREC_PROTECTED_PROFILE_REGISTRY_TESTS
#include <iostream>
#include <stdexcept>
#endif

namespace il2cpprec {
namespace {

constexpr size_t tableIndex(ProtectedMetadataTableId id) {
    return static_cast<size_t>(id);
}

bool canonicalSha256(std::string_view value, std::string& canonical) {
    if (value.size() != 64) return false;
    canonical.resize(value.size());
    for (size_t index = 0; index < value.size(); ++index) {
        const char digit = value[index];
        const bool decimal = digit >= '0' && digit <= '9';
        const bool lower = digit >= 'a' && digit <= 'f';
        const bool upper = digit >= 'A' && digit <= 'F';
        if (!decimal && !lower && !upper) return false;
        canonical[index] = upper ? static_cast<char>(digit - 'A' + 'a') : digit;
    }
    return true;
}

bool headerFieldFits(const ProtectedMetadataProfile& profile, size_t offset) {
    return offset <= profile.headerSize && 4 <= profile.headerSize - offset;
}

bool typeFieldFits(size_t offset, size_t width, size_t stride) {
    return offset <= stride && width <= stride - offset;
}

bool validCipher(ProtectedMetadataCipher cipher) {
    switch (cipher) {
    case ProtectedMetadataCipher::Raw:
    case ProtectedMetadataCipher::XorSizePlus35ByIndex:
    case ProtectedMetadataCipher::XorNegativeSizeMinus35ByIndex:
        return true;
    }
    return false;
}

bool validateNormalized(const ProtectedMetadataProfile& profile, std::string& error) {
    if (profile.headerSize == 0) {
        error = "Protected profile header size must not be zero";
        return false;
    }

    for (size_t index = 0; index < ProtectedMetadataProfile::tableCount; ++index) {
        const auto& table = profile.tables[index];
        if (!headerFieldFits(profile, table.sourceHeaderOffset)) {
            error = "Source header offset does not fit table " + std::to_string(index);
            return false;
        }
        if (!headerFieldFits(profile, table.sizeHeaderOffset)) {
            error = "Size header offset does not fit table " + std::to_string(index);
            return false;
        }
        if (!validCipher(table.cipher)) {
            error = "Unknown cipher in table " + std::to_string(index);
            return false;
        }
    }

    if (!profile.typeLayout.has_value()) return true;
    const auto& types = profile.tables[tableIndex(ProtectedMetadataTableId::Types)];
    if (types.stride != 88) {
        error = "A confirmed type layout requires the researched 88-byte type stride";
        return false;
    }

    const auto& layout = *profile.typeLayout;
    const std::array<std::pair<size_t, size_t>, 7> fields{{
        {layout.nameIndexOffset, 4},
        {layout.namespaceIndexOffset, 4},
        {layout.parentIndexOffset, 4},
        {layout.fieldStartOffset, 4},
        {layout.methodStartOffset, 4},
        {layout.fieldCountOffset, 2},
        {layout.methodCountOffset, 2}
    }};
    for (const auto& [offset, width] : fields) {
        if (!typeFieldFits(offset, width, types.stride)) {
            error = "A type layout field lies outside the configured type stride";
            return false;
        }
    }
    return true;
}

bool registrationError(std::string* error, std::string message) {
    if (error != nullptr) *error = std::move(message);
    return false;
}

#ifdef IL2CPPREC_PROTECTED_PROFILE_REGISTRY_TESTS

void expect(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

bool sameLayout(
    const std::optional<ProtectedMetadataTypeLayout>& left,
    const std::optional<ProtectedMetadataTypeLayout>& right) {
    if (left.has_value() != right.has_value()) return false;
    if (!left.has_value()) return true;
    return left->nameIndexOffset == right->nameIndexOffset &&
        left->namespaceIndexOffset == right->namespaceIndexOffset &&
        left->parentIndexOffset == right->parentIndexOffset &&
        left->fieldStartOffset == right->fieldStartOffset &&
        left->methodStartOffset == right->methodStartOffset &&
        left->fieldCountOffset == right->fieldCountOffset &&
        left->methodCountOffset == right->methodCountOffset;
}

void expectSameNormalized(
    const ProtectedMetadataProfile& actual,
    const ProtectedMetadataProfile& expected) {
    expect(actual.name == expected.name, "Normalized profile name changed");
    expect(actual.headerSize == expected.headerSize, "Normalized header size changed");
    expect(actual.headerKeyBase == expected.headerKeyBase, "Normalized header key changed");
    expect(sameLayout(actual.typeLayout, expected.typeLayout), "Normalized type layout changed");
    for (size_t index = 0; index < ProtectedMetadataProfile::tableCount; ++index) {
        const auto& actualTable = actual.tables[index];
        const auto& expectedTable = expected.tables[index];
        expect(actualTable.sourceHeaderOffset == expectedTable.sourceHeaderOffset, "Source offset mapping changed");
        expect(actualTable.sourceAdjustment == expectedTable.sourceAdjustment, "Source adjustment changed");
        expect(actualTable.sizeHeaderOffset == expectedTable.sizeHeaderOffset, "Size offset mapping changed");
        expect(actualTable.stride == expectedTable.stride, "Table stride changed");
        expect(actualTable.cipher == expectedTable.cipher, "Table cipher changed");
    }
}

uint8_t testTableKey(ProtectedMetadataCipher cipher, uint32_t size, size_t index) {
    const auto position = static_cast<uint64_t>(index);
    if (cipher == ProtectedMetadataCipher::XorSizePlus35ByIndex) {
        return static_cast<uint8_t>(((static_cast<uint64_t>(size) + 35) ^ position) & 0xff);
    }
    const uint64_t counter = uint64_t{0} - static_cast<uint64_t>(size) - 35;
    return static_cast<uint8_t>((counter ^ position) & 0xff);
}

void writeU32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    bytes[offset] = static_cast<uint8_t>(value & 0xff);
    bytes[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xff);
    bytes[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xff);
    bytes[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xff);
}

void testRoundtrip() {
    ProtectedProfileRegistry registry;
    const auto* plugin = registry.findById("blockstrike.researched.v1");
    expect(plugin != nullptr, "BlockStrike plugin is not registered");
    expect(plugin->metadataSha256.empty(), "An unverified BlockStrike sample hash was invented");

    auto expected = ProtectedMetadataProfile::researched();
    expected.name = plugin->id;
    expectSameNormalized(plugin->normalizedView(), expected);

    ProtectedProfileDescriptor hashedCopy = *plugin;
    hashedCopy.id = "test.blockstrike.roundtrip";
    hashedCopy.metadataSha256 = std::string(64, 'A');
    std::string error;
    if (!registry.registerProfile(hashedCopy, &error)) throw std::runtime_error(error);
    const auto* registeredCopy = registry.findById(hashedCopy.id);
    expect(registeredCopy != nullptr, "Registered roundtrip profile is missing");
    expect(registeredCopy->metadataSha256 == std::string(64, 'a'), "Profile SHA-256 was not canonicalized");

    ProtectedProfileRequest request;
    request.metadataSha256 = std::string(64, 'a');
    auto selected = registry.resolve(request);
    expect(selected.ok(), "Exact profile hash did not resolve");
    expect(!selected.usedExplicitOverride, "Hash resolution was marked as an override");
    auto normalized = *selected.normalizedView();
    hashedCopy.normalized.name = hashedCopy.id;
    expectSameNormalized(normalized, hashedCopy.normalized);

    std::array<std::vector<uint8_t>, ProtectedMetadataProfile::tableCount> plainTables;
    std::vector<uint8_t> decodedHeader(normalized.headerSize, 0);
    std::vector<uint8_t> protectedData(normalized.headerSize, 0);
    size_t source = normalized.headerSize;

    for (size_t index = 0; index < ProtectedMetadataProfile::tableCount; ++index) {
        const auto& mapping = normalized.tables[index];
        const auto id = static_cast<ProtectedMetadataTableId>(index);
        size_t byteSize = mapping.stride == 0 ? 12 : mapping.stride * 2;
        if (id == ProtectedMetadataTableId::Types) byteSize = 1056;
        if (id == ProtectedMetadataTableId::Parameters) byteSize = 496;

        if (mapping.sourceHeaderOffset == mapping.sizeHeaderOffset) {
            const auto adjustedSource = static_cast<int64_t>(byteSize) + mapping.sourceAdjustment;
            expect(adjustedSource >= 0, "Invalid shared source/size test mapping");
            source = static_cast<size_t>(adjustedSource);
        } else {
            source = (source + 15) & ~size_t{15};
        }
        expect(source <= std::numeric_limits<uint32_t>::max(), "Test source offset overflow");
        expect(byteSize <= std::numeric_limits<uint32_t>::max(), "Test table size overflow");

        const auto encodedSource = static_cast<int64_t>(source) - mapping.sourceAdjustment;
        expect(encodedSource >= 0 && encodedSource <= std::numeric_limits<uint32_t>::max(), "Invalid test source adjustment");
        writeU32(decodedHeader, mapping.sourceHeaderOffset, static_cast<uint32_t>(encodedSource));
        writeU32(decodedHeader, mapping.sizeHeaderOffset, static_cast<uint32_t>(byteSize));

        auto& plain = plainTables[index];
        plain.resize(byteSize);
        for (size_t byteIndex = 0; byteIndex < byteSize; ++byteIndex) {
            plain[byteIndex] = static_cast<uint8_t>((index * 37 + byteIndex * 11 + 7) & 0xff);
        }
        if (protectedData.size() < source + byteSize) protectedData.resize(source + byteSize);
        for (size_t byteIndex = 0; byteIndex < byteSize; ++byteIndex) {
            const uint8_t key = mapping.cipher == ProtectedMetadataCipher::Raw
                ? 0
                : testTableKey(mapping.cipher, static_cast<uint32_t>(byteSize), byteIndex);
            protectedData[source + byteIndex] = static_cast<uint8_t>(plain[byteIndex] ^ key);
        }
        source += byteSize;
    }

    for (size_t index = 0; index < normalized.headerSize; ++index) {
        const uint8_t key = static_cast<uint8_t>((static_cast<uint64_t>(normalized.headerKeyBase) + index) & 0xff);
        protectedData[index] = static_cast<uint8_t>(decodedHeader[index] ^ key);
    }

    ProtectedMetadata decoder(normalized);
    const auto decoded = decoder.decode(protectedData);
    if (!decoded.ok()) {
        std::string message = "Protected metadata roundtrip decode failed";
        for (const auto& diagnostic : decoded.diagnostics) {
            message += "; " + diagnostic.code + ": " + diagnostic.message;
        }
        throw std::runtime_error(message);
    }
    expect(decoded.header == decodedHeader, "Protected header roundtrip failed");
    expect(decoded.tables.size() == plainTables.size(), "Protected table count roundtrip failed");
    for (size_t index = 0; index < decoded.tables.size(); ++index) {
        expect(decoded.tables[index].bytes == plainTables[index], "Protected table bytes roundtrip failed");
    }
}

void testUnknownProfile() {
    ProtectedProfileRegistry registry;

    auto missing = registry.resolve({});
    expect(!missing.ok(), "A request without hash or override did not fail closed");
    expect(missing.error == ProtectedProfileResolveError::ProfileRequired, "Missing profile returned the wrong error");
    expect(missing.normalizedView() == nullptr, "Missing profile exposed a normalized fallback");

    ProtectedProfileRequest request;
    request.metadataSha256 = std::string(64, '0');
    auto unknownHash = registry.resolve(request);
    expect(!unknownHash.ok(), "Unknown metadata hash did not fail closed");
    expect(unknownHash.error == ProtectedProfileResolveError::UnknownProfile, "Unknown hash returned the wrong error");
    expect(!unknownHash.profile.has_value(), "Unknown hash selected a profile");

    request.metadataSha256.clear();
    request.profileIdOverride = "unknown.game.v1";
    auto unknownId = registry.resolve(request);
    expect(!unknownId.ok(), "Unknown profile override did not fail closed");
    expect(unknownId.error == ProtectedProfileResolveError::UnknownProfile, "Unknown ID returned the wrong error");

    request.profileIdOverride = "blockstrike.researched.v1";
    auto explicitSelection = registry.resolve(request);
    expect(explicitSelection.ok(), "Known explicit profile override was rejected");
    expect(explicitSelection.usedExplicitOverride, "Explicit selection was not reported");
    expect(explicitSelection.profile->id == request.profileIdOverride, "Explicit override selected another profile");

    request.metadataSha256 = std::string(64, '0');
    auto forcedSelection = registry.resolve(request);
    expect(forcedSelection.ok(), "Known override did not bypass hash evidence");
    expect(forcedSelection.usedExplicitOverride, "Forced selection was not reported");

    request.profileIdOverride.clear();
    request.metadataSha256 = "not-a-sha256";
    auto malformed = registry.resolve(request);
    expect(!malformed.ok(), "Malformed metadata hash did not fail closed");
    expect(malformed.error == ProtectedProfileResolveError::MalformedHash, "Malformed hash returned the wrong error");
}

#endif

} // namespace

const ProtectedMetadataProfile& ProtectedProfileDescriptor::normalizedView() const noexcept {
    return normalized;
}

bool ProtectedProfileResolution::ok() const noexcept {
    return profile.has_value() && error == ProtectedProfileResolveError::None;
}

const ProtectedMetadataProfile* ProtectedProfileResolution::normalizedView() const noexcept {
    return profile.has_value() ? &profile->normalizedView() : nullptr;
}

ProtectedProfileRegistry::ProtectedProfileRegistry() {
    profiles_.push_back(blockStrikeResearched());
}

ProtectedProfileDescriptor ProtectedProfileRegistry::blockStrikeResearched() {
    ProtectedProfileDescriptor profile;
    profile.id = "blockstrike.researched.v1";
    profile.evidence = {
        {
            "game",
            "BlockStrike",
            "Existing researched protected-metadata sample; exact build hash was not recorded"
        },
        {
            "header",
            "0x150-byte header; XOR key byte is (0xb5 + header offset) modulo 256",
            "Researched BlockStrike layout"
        },
        {
            "tables",
            "Explicit source/size header offsets, source adjustments, strides, and per-table XOR modes",
            "Researched BlockStrike layout; no cross-game heuristic"
        }
    };
    profile.normalized = ProtectedMetadataProfile::researched();
    profile.normalized.name = profile.id;
    return profile;
}

bool ProtectedProfileRegistry::registerProfile(ProtectedProfileDescriptor profile, std::string* error) {
    if (error != nullptr) error->clear();
    if (profile.id.empty()) return registrationError(error, "Protected profile ID must not be empty");
    if (findById(profile.id) != nullptr) return registrationError(error, "Duplicate protected profile ID: " + profile.id);
    if (profile.evidence.empty()) return registrationError(error, "Protected profile requires research evidence");

    if (!profile.metadataSha256.empty()) {
        std::string canonical;
        if (!canonicalSha256(profile.metadataSha256, canonical)) {
            return registrationError(error, "Protected profile metadata hash must be a 64-digit SHA-256 value");
        }
        if (findByMetadataSha256(canonical) != nullptr) {
            return registrationError(error, "Duplicate protected profile metadata SHA-256");
        }
        profile.metadataSha256 = std::move(canonical);
    }

    std::string validationError;
    if (!validateNormalized(profile.normalized, validationError)) {
        return registrationError(error, std::move(validationError));
    }
    profile.normalized.name = profile.id;
    profiles_.push_back(std::move(profile));
    return true;
}

const ProtectedProfileDescriptor* ProtectedProfileRegistry::findById(std::string_view id) const noexcept {
    for (const auto& profile : profiles_) {
        if (profile.id == id) return &profile;
    }
    return nullptr;
}

const ProtectedProfileDescriptor* ProtectedProfileRegistry::findByMetadataSha256(std::string_view hash) const {
    std::string canonical;
    if (!canonicalSha256(hash, canonical)) return nullptr;
    for (const auto& profile : profiles_) {
        if (!profile.metadataSha256.empty() && profile.metadataSha256 == canonical) return &profile;
    }
    return nullptr;
}

const std::vector<ProtectedProfileDescriptor>& ProtectedProfileRegistry::profiles() const noexcept {
    return profiles_;
}

ProtectedProfileResolution ProtectedProfileRegistry::resolve(const ProtectedProfileRequest& request) const {
    ProtectedProfileResolution result;
    if (!request.profileIdOverride.empty()) {
        const auto* profile = findById(request.profileIdOverride);
        if (profile == nullptr) {
            result.error = ProtectedProfileResolveError::UnknownProfile;
            result.message = "Unknown protected profile override: " + request.profileIdOverride;
            return result;
        }
        result.profile = *profile;
        result.error = ProtectedProfileResolveError::None;
        result.usedExplicitOverride = true;
        return result;
    }

    if (request.metadataSha256.empty()) {
        result.error = ProtectedProfileResolveError::ProfileRequired;
        result.message = "Protected profile is unknown; provide an exact metadata SHA-256 or an explicit known profile ID";
        return result;
    }

    std::string canonical;
    if (!canonicalSha256(request.metadataSha256, canonical)) {
        result.error = ProtectedProfileResolveError::MalformedHash;
        result.message = "Protected metadata SHA-256 must contain exactly 64 hexadecimal digits";
        return result;
    }

    const auto* profile = findByMetadataSha256(canonical);
    if (profile == nullptr) {
        result.error = ProtectedProfileResolveError::UnknownProfile;
        result.message = "No protected profile is registered for metadata SHA-256 " + canonical;
        return result;
    }
    result.profile = *profile;
    result.error = ProtectedProfileResolveError::None;
    return result;
}

} // namespace il2cpprec

#ifdef IL2CPPREC_PROTECTED_PROFILE_REGISTRY_TESTS

int main() {
    struct Test {
        const char* name;
        void (*function)();
    };
    const std::array tests{
        Test{"protected profile roundtrip", &il2cpprec::testRoundtrip},
        Test{"unknown protected profile fails closed", &il2cpprec::testUnknownProfile}
    };

    size_t failures = 0;
    for (const auto& test : tests) {
        try {
            test.function();
            std::cout << "[PASS] " << test.name << '\n';
        } catch (const std::exception& exception) {
            ++failures;
            std::cerr << "[FAIL] " << test.name << ": " << exception.what() << '\n';
        }
    }
    return failures == 0 ? 0 : 1;
}

#endif
