#include "TestSupport.hpp"

#include <il2cpprec/abi/AbiAdapter.hpp>
#include <il2cpprec/metadata/MetadataRegistration.hpp>
#include <il2cpprec/versions/Legacy16.hpp>
#include <il2cpprec/versions/Legacy21.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace il2cpprec::tests {
namespace {

void word(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    for (size_t index = 0; index != 4; ++index) {
        bytes.at(offset + index) = static_cast<uint8_t>(value >> (index * 8));
    }
}

void pointer(std::vector<uint8_t>& bytes, size_t offset, uint64_t value, size_t width) {
    for (size_t index = 0; index != width; ++index) {
        bytes.at(offset + index) = static_cast<uint8_t>(value >> (index * 8));
    }
}

std::vector<uint8_t> emptyLegacyHeader(int version, uint32_t firstTableOffset) {
    // Hand-written wire offsets: magic/version at 0/4, first table at 8/12.
    // The remaining offset/size pairs are zero and denote empty tables.
    std::vector<uint8_t> bytes(firstTableOffset, 0);
    word(bytes, 0, 0xFAB11BAF);
    word(bytes, 4, static_cast<uint32_t>(version));
    word(bytes, 8, firstTableOffset);
    return bytes;
}

BinaryImage offsetImage(Architecture architecture) {
    BinaryImage image;
    image.architecture = architecture;
    image.format = BinaryFormat::ELF;
    image.imageBase = 0x50000000;
    image.bytes = std::make_shared<std::vector<uint8_t>>(0x200, 0);
    image.sections.push_back({".data", 0, 0x200, 0, 0x200, false});
    return image;
}

MetadataModel singleField(double version) {
    MetadataModel metadata;
    metadata.version = version;
    TypeModel type;
    type.name = "Example";
    type.fields.push_back({"value", "int", 0, false, 0x04000001});
    metadata.types.push_back(type);
    return metadata;
}

} // namespace

TEST_CASE("legacy v18 MetadataUsage extension parses actual wire entries") {
    auto bytes = emptyLegacyHeader(18, 208);
    bytes.resize(224, 0);
    word(bytes, 192, 208); // metadataUsageLists offset
    word(bytes, 196, 8);   // one 8-byte list
    word(bytes, 200, 216); // metadataUsagePairs offset
    word(bytes, 204, 8);   // one 8-byte pair
    word(bytes, 208, 0);   // list start
    word(bytes, 212, 1);   // list count
    word(bytes, 216, 7);   // destination index
    word(bytes, 220, 1U << 29); // TypeInfo, index zero

    const auto result = Legacy16Reader{}.read(bytes);
    CHECK(result.ok());
    CHECK_EQ(result.profile.headerSize, 208);
    CHECK_EQ(result.metadata.metadataUsageLists.size(), 1);
    CHECK_EQ(result.metadata.metadataUsagePairs.size(), 1);
    CHECK_EQ(result.metadata.metadataUsagePairs[0].destinationIndex, 7);
    CHECK_EQ(result.metadata.metadataUsagePairs[0].kind, 1);
    CHECK_EQ(result.metadata.metadataUsagesCount, 8);

    word(bytes, 212, 2); // one list now claims two pairs
    const auto invalidRange = Legacy16Reader{}.read(bytes);
    CHECK(!invalidRange.ok());
    CHECK_EQ(invalidRange.diagnostics.at(0).code, "metadata-usage-list-out-of-bounds");

    word(bytes, 212, 1);
    word(bytes, 220, 7U << 29); // reserved kind
    const auto invalidKind = Legacy16Reader{}.read(bytes);
    CHECK(!invalidKind.ok());
    CHECK_EQ(invalidKind.diagnostics.at(0).code, "invalid-metadata-usage-kind");
}

TEST_CASE("legacy v16 and v17 do not accept the v18 usage header") {
    auto v16 = emptyLegacyHeader(16, 208);
    const auto wrongHeader = Legacy16Reader{}.read(v16);
    CHECK(!wrongHeader.ok());
    CHECK_EQ(wrongHeader.diagnostics.at(0).code, "invalid-header-size");

    word(v16, 4, 17);
    const auto rejectedVersion = Legacy16Reader{}.read(v16);
    CHECK(!rejectedVersion.ok());
    CHECK_EQ(rejectedVersion.diagnostics.at(0).code, "unsupported-version");
}

TEST_CASE("legacy v21 detector rejects mixed and incomplete native layouts") {
    Legacy21DetectionEvidence evidence;
    evidence.metadataVersion = 21;
    evidence.fieldOffsets = Legacy21FieldOffsetStorage::FlatInt32;
    evidence.typeDefinitionSizes = Legacy21TypeDefinitionSizeStorage::InlineRecords;
    evidence.vtable = Legacy21VTableKind::VirtualInvokeData;
    auto result = detectLegacy21Layout(evidence, 4);
    CHECK(result.status == Legacy21DetectionStatus::Ambiguous);
    CHECK(!result.layout.has_value());

    evidence.vtable = Legacy21VTableKind::MethodInfoPointers;
    result = detectLegacy21Layout(evidence, 4);
    CHECK(result.ok());
    CHECK(result.layout->variant == Legacy21Variant::Unity535);
    CHECK_EQ(result.layout->pointerSize, 4);
    CHECK_EQ(result.layout->vtable.elementSize, 4);

    evidence.fieldOffsets = Legacy21FieldOffsetStorage::PerTypePointers;
    result = detectLegacy21Layout(evidence, 4);
    CHECK(result.status == Legacy21DetectionStatus::ConflictingEvidence);
    CHECK(!result.layout.has_value());

    evidence = {};
    evidence.metadataVersion = 21;
    evidence.fieldOffsets = Legacy21FieldOffsetStorage::PerTypePointers;
    evidence.typeDefinitionSizes = Legacy21TypeDefinitionSizeStorage::PointerArray;
    evidence.vtable = Legacy21VTableKind::VirtualInvokeData;
    result = detectLegacy21Layout(evidence, 8);
    CHECK(result.status == Legacy21DetectionStatus::Ambiguous);
    evidence.hasGenericRecursionDepth = true;
    result = detectLegacy21Layout(evidence, 8);
    CHECK(result.ok());
    CHECK(result.layout->variant == Legacy21Variant::Unity54);
    CHECK_EQ(result.layout->vtable.elementSize, 16);
}

TEST_CASE("legacy flat and per-type offset tables have distinct bounds") {
    constexpr uint64_t base = 0x50000000;
    for (const auto architecture : {Architecture::X86, Architecture::X64}) {
        const size_t width = architecture == Architecture::X86 ? 4 : 8;
        auto image = offsetImage(architecture);
        auto flat = singleField(20);
        word(*image.bytes, 0x40, 0xFFFFFFFC); // negative field offset is valid
        MetadataRegistrationReader{}.readFieldOffsets(image, flat, base + 0x40, 1);
        CHECK_EQ(flat.types[0].fields[0].offset, static_cast<uint64_t>(-4));

        auto perType = singleField(22);
        pointer(*image.bytes, 0x80, base + 0x100, width);
        word(*image.bytes, 0x100, 48);
        MetadataRegistrationReader{}.readFieldOffsets(image, perType, base + 0x80, 1);
        CHECK_EQ(perType.types[0].fields[0].offset, 48);

        pointer(*image.bytes, 0x80, base + 0x1FF, width);
        CHECK_THROWS(
            MetadataRegistrationReader{}.readFieldOffsets(image, perType, base + 0x80, 1),
            "");
    }
}

TEST_CASE("legacy invoker profile changes at v19 and v24") {
    for (const double version : {19.0, 20.0, 21.0, 22.0, 23.0}) {
        CHECK(AbiRuntimeProfile::forMetadataVersion(version).invoker ==
            AbiInvokerSignature::LegacyThreeArguments);
    }
    CHECK(AbiRuntimeProfile::forMetadataVersion(18).invoker == AbiInvokerSignature::FourArguments);
    CHECK(AbiRuntimeProfile::forMetadataVersion(24).invoker == AbiInvokerSignature::FourArguments);
}

} // namespace il2cpprec::tests
