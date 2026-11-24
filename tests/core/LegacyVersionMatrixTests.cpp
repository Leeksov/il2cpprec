#include "TestSupport.hpp"

#include <il2cpprec/abi/AbiAdapter.hpp>
#include <il2cpprec/metadata/GenericMethodResolver.hpp>
#include <il2cpprec/metadata/GlobalMetadata.hpp>
#include <il2cpprec/metadata/MetadataRegistration.hpp>
#include <il2cpprec/metadata/MetadataUsage.hpp>
#include <il2cpprec/versions/Legacy16.hpp>
#include <il2cpprec/versions/Legacy21.hpp>
#include <il2cpprec/versions/Legacy22.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace il2cpprec::tests {
namespace {

constexpr uint64_t matrixImageBase = 0x10000000;

struct LegacyLayout {
    size_t headerSize;
    size_t typeStride;
    size_t fieldStride;
    size_t imageStride;
    size_t assemblyStride;
};

LegacyLayout layoutFor(int version) {
    const double value = static_cast<double>(version);
    size_t typeSize = 8;
    if (value <= 24.0) typeSize += 4;
    typeSize += 4;
    if (value <= 24.5) typeSize += 4;
    typeSize += 12;
    if (value <= 24.1) typeSize += 8;
    typeSize += 4;
    if (value <= 22.0) typeSize += 8;
    if (value >= 21.0 && value <= 22.0) typeSize += 8;
    typeSize += 4 + 32 + 16 + 4;
    if (value >= 19.0) typeSize += 4;

    size_t imageSize = 16;
    if (value >= 24.0) imageSize += 8;
    imageSize += 4;
    if (value >= 19.0) imageSize += 4;
    if (value >= 24.1) imageSize += 8;

    size_t assemblySize = 4;
    if (value >= 24.1) assemblySize += 4;
    if (value <= 24.0) assemblySize += 4;
    if (value >= 20.0) assemblySize += 8;
    assemblySize += 48;
    if (value <= 24.3) assemblySize += 4;

    size_t headerSize = 168;
    if (value <= 24.1) headerSize += 8;
    headerSize += 16;
    if (value >= 19.0 && value <= 24.5) headerSize += 16;
    if (value >= 19.0) headerSize += 8;
    if (value >= 20.0) headerSize += 8;
    if (value >= 21.0 && value <= 27.2) headerSize += 16;
    if (value >= 29.0) headerSize += 16;
    if (value >= 22.0) headerSize += 16;
    if (value >= 23.0) headerSize += 8;
    if (value >= 27.0) headerSize += 8;
    if (value >= 24.0) headerSize += 8;
    return {headerSize, typeSize, value < 19.0 ? 12U : 16U, imageSize, assemblySize};
}

void put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value) {
    bytes[offset] = static_cast<uint8_t>(value);
    bytes[offset + 1] = static_cast<uint8_t>(value >> 8);
}

void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    for (size_t index = 0; index < 4; ++index) bytes[offset + index] = static_cast<uint8_t>(value >> (index * 8));
}

void put64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    for (size_t index = 0; index < 8; ++index) bytes[offset + index] = static_cast<uint8_t>(value >> (index * 8));
}

struct Strings {
    std::vector<uint8_t> bytes;
    uint32_t add(const std::string& value) {
        const auto result = static_cast<uint32_t>(bytes.size());
        bytes.insert(bytes.end(), value.begin(), value.end());
        bytes.push_back(0);
        return result;
    }
};

std::vector<uint8_t> metadataFixture(int version) {
    const auto layout = layoutFor(version);
    std::vector<uint8_t> bytes(0x600, 0);
    Strings strings;
    const auto image = strings.add("Assembly-CSharp.dll");
    const auto nameSpace = strings.add("Legacy");
    const auto type = strings.add("Type" + std::to_string(version));
    const auto method = strings.add("Method" + std::to_string(version));
    const auto field = strings.add("value");
    std::memcpy(bytes.data() + 0x200, strings.bytes.data(), strings.bytes.size());
    std::memcpy(bytes.data() + 0x290, "legacy", 6);

    put32(bytes, 0, 0xFAB11BAF);
    put32(bytes, 4, static_cast<uint32_t>(version));
    put32(bytes, 8, 0x280);
    put32(bytes, 12, 8);
    put32(bytes, 16, 0x290);
    put32(bytes, 20, 6);
    put32(bytes, 24, 0x200);
    put32(bytes, 28, static_cast<uint32_t>(strings.bytes.size()));
    put32(bytes, 48, 0x300);
    put32(bytes, 52, 56);
    put32(bytes, 88, 0);
    put32(bytes, 92, 0);
    put32(bytes, 96, 0x340);
    put32(bytes, 100, static_cast<uint32_t>(layout.fieldStride));
    put32(bytes, 160, 0x360);
    put32(bytes, 164, static_cast<uint32_t>(layout.typeStride));
    put32(bytes, 176, 0x400);
    put32(bytes, 180, static_cast<uint32_t>(layout.imageStride));
    put32(bytes, 184, 0x420);
    put32(bytes, 188, static_cast<uint32_t>(layout.assemblyStride));
    put32(bytes, 0x280, 6);
    put32(bytes, 0x284, 0);

    if (version >= 19) {
        put32(bytes, 192, 0x480);
        put32(bytes, 196, 8);
        put32(bytes, 200, 0x490);
        put32(bytes, 204, 8);
        put32(bytes, 208, 0x4A0);
        put32(bytes, 212, 8);
        put32(bytes, 0x480, 0);
        put32(bytes, 0x484, 1);
        put32(bytes, 0x490, 2);
        put32(bytes, 0x494, (5U << 29));
        put32(bytes, 0x4A0, 0);
        put32(bytes, 0x4A4, 0);
    }

    put32(bytes, 0x300, method);
    put32(bytes, 0x304, 0);
    put32(bytes, 0x308, 0);
    put32(bytes, 0x30C, 0xFFFFFFFF);
    put32(bytes, 0x310, 0xFFFFFFFF);
    put32(bytes, 0x314, 0xFFFFFFFF);
    put32(bytes, 0x318, static_cast<uint32_t>(version - 16));
    put32(bytes, 0x31C, 3);
    put32(bytes, 0x320, 0xFFFFFFFF);
    put32(bytes, 0x324, 0xFFFFFFFF);
    put32(bytes, 0x328, 0xFFFFFFFF);
    put32(bytes, 0x32C, 0x06000001);
    put16(bytes, 0x330, 0x0010);
    put16(bytes, 0x332, 0);
    put16(bytes, 0x334, 0);
    put16(bytes, 0x336, 0);

    put32(bytes, 0x340, field);
    put32(bytes, 0x344, 0);
    put32(bytes, 0x348, 0xFFFFFFFF);
    if (version >= 19) put32(bytes, 0x34C, 0x04000001);

    size_t cursor = 8;
    if (version <= 24) cursor += 4;
    cursor += 4;
    if (version <= 24) cursor += 4;
    cursor += 12;
    if (version <= 24) cursor += 8;
    const size_t genericContainer = cursor;
    cursor += 4;
    if (version <= 22) cursor += 8;
    if (version >= 21 && version <= 22) cursor += 8;
    const size_t flags = cursor;
    const size_t counts = flags + 4 + 32;
    put32(bytes, 0x360, type);
    put32(bytes, 0x364, nameSpace);
    put32(bytes, 0x360 + 20, 0xFFFFFFFF);
    put32(bytes, 0x360 + 24, 0xFFFFFFFF);
    put32(bytes, 0x360 + 28, 0xFFFFFFFF);
    put32(bytes, 0x360 + genericContainer, 0xFFFFFFFF);
    put32(bytes, 0x360 + flags, 0);
    put32(bytes, 0x360 + flags + 4, 0);
    put32(bytes, 0x360 + flags + 8, 0);
    put16(bytes, 0x360 + counts, 1);
    put16(bytes, 0x360 + counts + 4, 1);
    put32(bytes, 0x360 + counts + 16, 0);
    if (version >= 19) put32(bytes, 0x360 + counts + 20, 0x02000001);

    put32(bytes, 0x400, image);
    put32(bytes, 0x404, 0);
    put32(bytes, 0x408, 0);
    put32(bytes, 0x40C, 1);
    put32(bytes, 0x410, 0xFFFFFFFF);
    put32(bytes, 0x414, 0);
    return bytes;
}

MetadataModel parsed(int version) {
    return GlobalMetadata{}.read(metadataFixture(version));
}

std::vector<uint8_t> legacy16Fixture(int version) {
    auto bytes = metadataFixture(version);
    put32(bytes, 8, version == 18 ? 208 : 192);
    put32(bytes, 164, 108);
    put32(bytes, 100, 12);
    put32(bytes, 180, 20);
    put32(bytes, 188, 60);
    return bytes;
}

MetadataModel parsedLegacy16(int version) {
    const auto result = Legacy16Reader{}.read(legacy16Fixture(version));
    if (!result.ok()) fail(result.diagnosticText(), __FILE__, __LINE__);
    CHECK_EQ(result.profile.version, version);
    CHECK_EQ(result.profile.headerSize, version == 18 ? 208 : 192);
    CHECK_EQ(result.profile.typeDefinitionStride, 108);
    CHECK_EQ(result.profile.methodDefinitionStride, 56);
    CHECK_EQ(result.profile.parameterDefinitionStride, 16);
    CHECK_EQ(result.profile.fieldDefinitionStride, 12);
    CHECK_EQ(result.profile.imageDefinitionStride, 20);
    CHECK_EQ(result.profile.assemblyDefinitionStride, 60);
    CHECK_EQ(result.profile.codeRegistrationPairs, 7);
    CHECK_EQ(result.profile.fieldOffsetsPair, version == 16 ? 6 : 5);
    CHECK_EQ(result.profile.metadataRegistrationPairs, version == 16 ? 8 : 7);
    return result.metadata;
}

void checkMetadata(int version) {
    const auto metadata = version <= 18 ? parsedLegacy16(version) : parsed(version);
    CHECK(metadata.version == static_cast<double>(version));
    CHECK_EQ(metadata.types.size(), 1);
    CHECK_EQ(metadata.types[0].nameSpace, "Legacy");
    CHECK_EQ(metadata.types[0].name, "Type" + std::to_string(version));
    CHECK_EQ(metadata.types[0].fields.size(), 1);
    CHECK_EQ(metadata.types[0].methods.size(), 1);
    CHECK_EQ(metadata.types[0].methods[0].name, "Method" + std::to_string(version));
    CHECK_EQ(metadata.types[0].methods[0].methodIndex, version - 16);
    CHECK_EQ(metadata.types[0].methods[0].definitionIndex, 0);
    CHECK_EQ(metadata.stringLiterals.at(0), "legacy");
    if (version < 19) {
        CHECK_EQ(metadata.types[0].fields[0].token, 0);
        CHECK(metadata.metadataUsageLists.empty());
        CHECK(metadata.metadataUsagePairs.empty());
    } else {
        CHECK_EQ(metadata.types[0].fields[0].token, 0x04000001);
        CHECK_EQ(metadata.metadataUsageLists.size(), 1);
        CHECK_EQ(metadata.metadataUsageLists[0].start, 0);
        CHECK_EQ(metadata.metadataUsageLists[0].count, 1);
        CHECK_EQ(metadata.metadataUsagePairs.size(), 1);
        CHECK_EQ(metadata.metadataUsagePairs[0].kind, 5);
        CHECK_EQ(metadata.metadataUsagePairs[0].decodedIndex, 0);
        CHECK_EQ(metadata.metadataUsagePairs[0].destinationIndex, 2);
    }
}

MetadataModel registrationMetadata(int version, bool nullPrefix) {
    MetadataModel metadata;
    metadata.version = static_cast<double>(version);
    if (nullPrefix) metadata.types.resize(3);
    TypeModel target;
    target.name = "Offsets";
    target.fields.push_back({"value", "int", 0, false, 0x04000001});
    metadata.types.push_back(target);
    return metadata;
}

BinaryImage registrationBinary() {
    BinaryImage binary;
    binary.architecture = Architecture::X64;
    binary.format = BinaryFormat::ELF;
    binary.imageBase = matrixImageBase;
    binary.bytes = std::make_shared<std::vector<uint8_t>>(0x400, 0);
    binary.sections.push_back({".text", 0, binary.bytes->size(), 0, binary.bytes->size(), true});
    return binary;
}

void checkDirectOffsets(int version) {
    auto metadata = registrationMetadata(version, false);
    auto binary = registrationBinary();
    put32(*binary.bytes, 0x100, 36);
    MetadataRegistrationReader{}.readFieldOffsets(binary, metadata, matrixImageBase + 0x100, 1);
    CHECK_EQ(metadata.types[0].fields[0].offset, 36);
    CHECK_EQ(metadata.fieldOffsetsByToken.at(0x04000001), 36);
}

void checkPointerOffsets(int version) {
    auto metadata = registrationMetadata(version, false);
    auto binary = registrationBinary();
    put64(*binary.bytes, 0x100, matrixImageBase + 0x180);
    put32(*binary.bytes, 0x180, 40);
    MetadataRegistrationReader{}.readFieldOffsets(binary, metadata, matrixImageBase + 0x100, 1);
    CHECK_EQ(metadata.types[0].fields[0].offset, 40);
    CHECK_EQ(metadata.fieldOffsetsByToken.at(0x04000001), 40);
}

void checkLegacy16Registration(int version) {
    auto binary = registrationBinary();
    binary.bytes->resize(0x1000, 0);
    auto& bytes = *binary.bytes;
    const auto profile = describeLegacy16Profile(version);
    const auto pair = [&](size_t pairIndex, uint64_t address, uint64_t count, uint64_t pointer) {
        put64(bytes, address + pairIndex * 16, count);
        put64(bytes, address + pairIndex * 16 + 8, pointer);
    };
    pair(profile.fieldOffsetsPair, 0x200, 1, matrixImageBase + 0x100);
    pair(0, 0x300, 3, matrixImageBase + 0x400);
    pair(5, 0x300, 1, matrixImageBase + 0x440);
    put32(bytes, 0x100, 36);
    for (size_t index = 0; index < 3; ++index) {
        put64(bytes, 0x400 + index * 8, matrixImageBase + 0x800 + index * 0x20);
    }
    put64(bytes, 0x440, matrixImageBase + 0x900);

    const auto result = Legacy16Reader{}.read(
        legacy16Fixture(version), binary, matrixImageBase + 0x200, matrixImageBase + 0x300);
    if (!result.ok()) fail(result.diagnosticText(), __FILE__, __LINE__);
    const auto methodIndex = static_cast<size_t>(version - 16);
    CHECK_EQ(result.metadata.types[0].methods[0].address, matrixImageBase + 0x800 + methodIndex * 0x20);
    CHECK_EQ(result.metadata.types[0].fields[0].offset, 36);
    CHECK_EQ(result.metadata.invokerPointers.size(), 1);
    CHECK_EQ(result.metadata.invokerPointers[0], matrixImageBase + 0x900);
    CHECK_EQ(result.metadata.metadataRegistrationAddress, matrixImageBase + 0x200);
    CHECK_EQ(result.metadata.codeRegistrationAddress, matrixImageBase + 0x300);
}

} // namespace

TEST_CASE("legacy metadata v16 header and strides") { checkMetadata(16); }
TEST_CASE("legacy metadata v18 header strides and pre-usage literals") { checkMetadata(18); }
TEST_CASE("legacy metadata v19 header strides and usage") { checkMetadata(19); }
TEST_CASE("legacy metadata v20 header strides and usage") { checkMetadata(20); }
TEST_CASE("legacy metadata v21 header strides and usage") { checkMetadata(21); }
TEST_CASE("legacy metadata v22 header strides and usage") { checkMetadata(22); }
TEST_CASE("legacy metadata v23 header strides and usage") { checkMetadata(23); }

TEST_CASE("legacy v22-v23 specialized reader accepts their metadata layouts") {
    for (const int version : {22, 23}) {
        CHECK(Legacy22Reader::supports(version));
        const auto metadata = Legacy22Reader{}.readGlobalMetadata(metadataFixture(version));
        CHECK(metadata.version == static_cast<double>(version));
        CHECK_EQ(metadata.types.size(), 1);
        CHECK_EQ(metadata.types[0].methods[0].methodIndex, version - 16);
        CHECK_EQ(metadata.metadataUsagePairs.size(), 1);
        CHECK_EQ(metadata.stringLiterals.at(0), "legacy");
    }
}

TEST_CASE("legacy v16-v18 registration reads native layouts and invoker pointers") {
    for (const int version : {16, 18}) checkLegacy16Registration(version);
}

TEST_CASE("legacy v19-v20 registration uses direct field offsets") {
    for (const int version : {19, 20}) checkDirectOffsets(version);
}

TEST_CASE("legacy v21 registration accepts direct field offsets") {
    checkDirectOffsets(21);
}

TEST_CASE("legacy v21 registration accepts pointer field offsets with null prefix") {
    auto metadata = registrationMetadata(21, true);
    auto binary = registrationBinary();
    put64(*binary.bytes, 0x100, 0);
    put64(*binary.bytes, 0x108, 0);
    put64(*binary.bytes, 0x110, 0);
    put64(*binary.bytes, 0x118, matrixImageBase + 0x180);
    put32(*binary.bytes, 0x180, 42);
    MetadataRegistrationReader{}.readFieldOffsets(binary, metadata, matrixImageBase + 0x100, 4);
    CHECK_EQ(metadata.types[3].fields[0].offset, 42);
    CHECK_EQ(metadata.fieldOffsetsByToken.at(0x04000001), 42);
}

TEST_CASE("legacy v21 Unity535 layout uses flat offsets and MethodInfo vtable") {
    const auto layout = makeLegacy21Layout(Legacy21Variant::Unity535, 8);
    CHECK(layout.pointerSize == 8);
    CHECK(layout.fieldOffsetStorage == Legacy21FieldOffsetStorage::FlatInt32);
    CHECK(layout.typeDefinitionSizeStorage == Legacy21TypeDefinitionSizeStorage::InlineRecords);
    CHECK(layout.vtable.kind == Legacy21VTableKind::MethodInfoPointers);
    CHECK(layout.codeRegistration.methodPointers.count.present);
    CHECK(layout.codeRegistration.methodPointers.pointer.present);
    CHECK(layout.metadataRegistration.fieldOffsets.count.present);
    CHECK(validateLegacy21Layout(layout).empty());

    Legacy21DetectionEvidence evidence;
    evidence.metadataVersion = 21;
    evidence.fieldOffsets = Legacy21FieldOffsetStorage::FlatInt32;
    evidence.typeDefinitionSizes = Legacy21TypeDefinitionSizeStorage::InlineRecords;
    evidence.vtable = Legacy21VTableKind::MethodInfoPointers;
    const auto detected = detectLegacy21Layout(evidence, 8);
    CHECK(detected.ok());
    CHECK(detected.layout.has_value());
    CHECK(detected.layout->variant == Legacy21Variant::Unity535);
}

TEST_CASE("legacy v21 Unity54 layout uses per-type offsets and VirtualInvokeData") {
    const auto layout = makeLegacy21Layout(Legacy21Variant::Unity54, 8);
    CHECK(layout.pointerSize == 8);
    CHECK(layout.fieldOffsetStorage == Legacy21FieldOffsetStorage::PerTypePointers);
    CHECK(layout.typeDefinitionSizeStorage == Legacy21TypeDefinitionSizeStorage::PointerArray);
    CHECK(layout.vtable.kind == Legacy21VTableKind::VirtualInvokeData);
    CHECK_EQ(layout.vtable.methodPointer.size, 8);
    CHECK_EQ(layout.vtable.methodInfo.size, 8);
    CHECK(validateLegacy21Layout(layout).empty());

    Legacy21DetectionEvidence evidence;
    evidence.metadataVersion = 21;
    evidence.fieldOffsets = Legacy21FieldOffsetStorage::PerTypePointers;
    evidence.typeDefinitionSizes = Legacy21TypeDefinitionSizeStorage::PointerArray;
    evidence.vtable = Legacy21VTableKind::VirtualInvokeData;
    const auto detected = detectLegacy21Layout(evidence, 8);
    CHECK(detected.ok());
    CHECK(detected.layout.has_value());
    CHECK(detected.layout->variant == Legacy21Variant::Unity54);
}

TEST_CASE("legacy v22-v23 registration uses pointer field offsets") {
    for (const int version : {22, 23}) checkPointerOffsets(version);
}

TEST_CASE("legacy vtable method-def and method-ref forms resolve distinctly") {
    auto metadata = parsed(21);
    GenericMethodSpecModel spec;
    spec.methodDefinitionIndex = 0;
    spec.classInstIndex = -1;
    spec.methodInstIndex = -1;
    metadata.methodSpecs.push_back(spec);
    GenericMethodPointerModel mapping;
    mapping.genericMethodIndex = 0;
    mapping.methodIndex = 1;
    mapping.invokerIndex = 2;
    mapping.methodPointer = 0x5000;
    mapping.invokerPointer = 0x6000;
    metadata.genericMethodTable.push_back(mapping);

    const auto direct = MetadataUsageReader::decode(3U << 29);
    CHECK(direct.kind == MetadataUsageKind::MethodDef);
    CHECK_EQ(direct.index, 0);
    const auto reference = MetadataUsageReader::decode(6U << 29);
    CHECK(reference.kind == MetadataUsageKind::MethodRef);
    CHECK_EQ(reference.index, 0);

    const auto resolved = GenericMethodResolver(metadata).resolve(reference.index);
    CHECK(resolved.status == MetadataUsageStatus::Resolved);
    CHECK(resolved.methodDefinitionIndex.has_value());
    CHECK_EQ(*resolved.methodDefinitionIndex, 0);
    CHECK(resolved.method.has_value());
    CHECK_EQ(resolved.method->name, "Method21");
    CHECK(resolved.mapping.has_value());
    CHECK_EQ(resolved.mapping->methodPointer, 0x5000);
    CHECK_EQ(resolved.mapping->invokerPointer, 0x6000);
}

TEST_CASE("legacy invoker ABI preserves method info instance and params order") {
    MetadataModel metadata;
    metadata.version = 16;
    MethodModel method;
    method.address = 0x5000;
    method.returnType = "int";
    method.parameters = {{"x", "int", -1}, {"y", "float", -1}};
    method.isStatic = false;

    CallSiteAbiSpec spec;
    spec.kind = CallSiteKind::Invoker;
    spec.methodPointer = constant(0x5000, ScalarType::pointer(32));
    spec.invokerMethod = constant(0x6000, ScalarType::pointer(32));
    spec.methodInfo = constant(0x7000, ScalarType::pointer(32));
    const auto call = AbiAdapter{}.bindCallSite(method, metadata, Architecture::Arm32, spec);
    CHECK(call.supported());
    CHECK(call.kind == CallSiteKind::Invoker);
    CHECK(call.targetKind == CallTargetKind::InvokerMethod);
    CHECK(call.methodInfoPolicy == MethodInfoArgumentPolicy::Omit);
    CHECK(call.target == spec.invokerMethod);
    CHECK_EQ(call.signature.bindings.size(), 4);
    const AbiValueRole roles[] = {
        AbiValueRole::MethodPointer, AbiValueRole::MethodInfo,
        AbiValueRole::Instance, AbiValueRole::Parameters
    };
    for (size_t index = 0; index < call.signature.bindings.size(); ++index) {
        CHECK(call.signature.bindings[index].role == roles[index]);
    }
    CHECK(call.signature.diagnostics.empty());
}

TEST_CASE("legacy metadata rejects v17 explicitly") {
    CHECK_THROWS(GlobalMetadata{}.read(metadataFixture(17)), "Unsupported global metadata version");
    const auto rejected = Legacy16Reader{}.read(legacy16Fixture(17));
    CHECK(!rejected.ok());
    CHECK(!rejected.diagnostics.empty());
    CHECK_EQ(rejected.diagnostics[0].code, "unsupported-version");
}

TEST_CASE("legacy matrix rejects truncated and malformed tables") {
    for (const int version : {16, 18, 19, 20, 21, 22, 23}) {
        auto truncated = metadataFixture(version);
        truncated.resize(layoutFor(version).headerSize - 1);
        CHECK_THROWS(GlobalMetadata{}.read(truncated), "");

        auto badFields = metadataFixture(version);
        put32(badFields, 100, 0xFFFFFFFF);
        CHECK_THROWS(GlobalMetadata{}.read(badFields), "fields table has negative size");
    }

    auto badUsage = metadataFixture(19);
    put32(badUsage, 0x484, 2);
    CHECK_THROWS(GlobalMetadata{}.read(badUsage), "metadata usage list range");

    auto metadata = registrationMetadata(22, false);
    auto binary = registrationBinary();
    put64(*binary.bytes, 0x100, 24);
    CHECK_THROWS(
        MetadataRegistrationReader{}.readFieldOffsets(binary, metadata, matrixImageBase + 0x100, 1),
        "virtual address is below the image base");
}

} // namespace il2cpprec::tests
