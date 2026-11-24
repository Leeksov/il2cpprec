#include "TestSupport.hpp"

#include <il2cpprec/metadata/CodeGenModules.hpp>
#include <il2cpprec/metadata/GlobalMetadata.hpp>
#include <il2cpprec/metadata/MethodResolver.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace il2cpprec::tests {
namespace {

void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}

void put64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}

std::vector<uint8_t> minimalMetadata(bool modern = false) {
    std::vector<uint8_t> bytes(modern ? 264 : 240, 0);
    put32(bytes, 0, 0xFAB11BAF);
    put32(bytes, 4, 24);
    put32(bytes, 8, modern ? 264 : 240);
    return bytes;
}

void expectMetadataError(const std::vector<uint8_t>& bytes, std::string_view message) {
    checkThrows<std::runtime_error>([&] { static_cast<void>(GlobalMetadata{}.read(bytes)); }, message, __FILE__, __LINE__);
}

BinaryImage moduleBinary() {
    BinaryImage binary;
    binary.architecture = Architecture::X64;
    binary.format = BinaryFormat::ELF;
    binary.imageBase = 0x10000000;
    binary.bytes = std::make_shared<std::vector<uint8_t>>(0xC0, 0);
    binary.sections.push_back({".text", 0, binary.bytes->size(), 0, binary.bytes->size(), true});
    auto& bytes = *binary.bytes;
    put64(bytes, 0x00, 0xFFFF000000000000ULL | (binary.imageBase + 0x80));
    put64(bytes, 0x08, 2);
    put64(bytes, 0x10, binary.imageBase + 0x40);
    put64(bytes, 0x40, binary.imageBase + 0x20);
    put64(bytes, 0x48, 0xABCD000000000000ULL | (binary.imageBase + 0x24));
    const std::string name = "Assembly-CSharp.dll";
    std::memcpy(bytes.data() + 0x80, name.c_str(), name.size() + 1);
    return binary;
}

} // namespace

TEST_CASE("metadata accepts minimal legacy and modern headers") {
    const auto legacy = GlobalMetadata{}.read(minimalMetadata());
    CHECK_EQ(legacy.version, 24.0);
    CHECK(legacy.types.empty());
    const auto modern = GlobalMetadata{}.read(minimalMetadata(true));
    CHECK(modern.version == 24.2);
    CHECK(modern.types.empty());
}

TEST_CASE("metadata rejects every truncated header prefix") {
    const auto bytes = minimalMetadata();
    for (size_t size = 0; size < 240; ++size) {
        checkThrows<std::runtime_error>([&] {
            static_cast<void>(GlobalMetadata{}.read(bytes.data(), size));
        }, "", __FILE__, __LINE__);
    }
    CHECK_THROWS(GlobalMetadata{}.read(nullptr, 1), "null data with nonzero size");
    CHECK_THROWS(GlobalMetadata{}.read(nullptr, 0), "read past end of file");
}

TEST_CASE("metadata validates sanity version and header layout") {
    auto bytes = minimalMetadata();
    put32(bytes, 0, 0);
    expectMetadataError(bytes, "incorrect sanity value");

    bytes = minimalMetadata();
    put32(bytes, 4, 29);
    expectMetadataError(bytes, "Unsupported global metadata version");

    bytes = minimalMetadata();
    put32(bytes, 8, 256);
    expectMetadataError(bytes, "Unsupported metadata 24 header layout");
}

TEST_CASE("metadata rejects negative and overflowing blob ranges") {
    auto bytes = minimalMetadata();
    put32(bytes, 28, 0xFFFFFFFF);
    expectMetadataError(bytes, "string table has negative size");

    bytes = minimalMetadata();
    put32(bytes, 20, 0xFFFFFFFF);
    expectMetadataError(bytes, "string literal data has negative size");

    bytes = minimalMetadata();
    put32(bytes, 24, std::numeric_limits<uint32_t>::max());
    put32(bytes, 28, 4);
    expectMetadataError(bytes, "string table is outside the file");

    bytes = minimalMetadata();
    put32(bytes, 16, 238);
    put32(bytes, 20, 4);
    expectMetadataError(bytes, "string literal data is outside the file");
}

TEST_CASE("metadata validates every table's size alignment and bounds") {
    struct Table {
        size_t offsetField;
        size_t sizeField;
        std::string_view name;
    };
    const Table tables[] = {
        {48, 52, "methods"},
        {88, 92, "parameters"},
        {96, 100, "fields"},
        {160, 164, "type definitions"},
        {176, 180, "images"},
        {8, 12, "string literals"},
    };
    for (const auto& table : tables) {
        const bool isLiteralTable = table.name == "string literals";
        auto negative = minimalMetadata();
        put32(negative, table.sizeField, 0xFFFFFFFF);
        expectMetadataError(negative, table.name);

        auto misaligned = minimalMetadata();
        put32(misaligned, table.offsetField, isLiteralTable ? 240 : 200);
        put32(misaligned, table.sizeField, 1);
        expectMetadataError(misaligned, std::string(table.name) + " table is misaligned or outside the file");

        auto outside = minimalMetadata();
        put32(outside, table.offsetField, isLiteralTable ? 240 : std::numeric_limits<uint32_t>::max());
        put32(outside, table.sizeField, isLiteralTable ? 8 : 0);
        expectMetadataError(outside, std::string(table.name) + " table is misaligned or outside the file");
    }
}

TEST_CASE("metadata string literal payload bounds are enforced") {
    auto bytes = minimalMetadata();
    bytes.resize(256, 0);
    put32(bytes, 8, 240);
    put32(bytes, 12, 8);
    put32(bytes, 16, 248);
    put32(bytes, 20, 8);
    put32(bytes, 240, 9);
    put32(bytes, 244, 0);
    auto metadata = GlobalMetadata{}.read(bytes);
    CHECK(metadata.stringLiterals.empty());

    put32(bytes, 240, 3);
    put32(bytes, 244, 2);
    std::memcpy(bytes.data() + 248, "xxabcxx", 7);
    metadata = GlobalMetadata{}.read(bytes);
    CHECK_EQ(metadata.stringLiterals.at(0), "abc");

    put32(bytes, 244, 0xFFFFFFFF);
    metadata = GlobalMetadata{}.read(bytes);
    CHECK(metadata.stringLiterals.empty());
}

TEST_CASE("binary image mapping and reads reject out-of-bounds ranges") {
    auto binary = moduleBinary();
    CHECK_EQ(binary.mapVATR(0x20), 0x20);
    CHECK_EQ(binary.mapRTVA(0x20), 0x20);
    CHECK(binary.data(binary.bytes->size(), 0) == binary.bytes->data() + binary.bytes->size());
    checkThrows<std::out_of_range>([&] { static_cast<void>(binary.data(binary.bytes->size(), 1)); }, "outside the file", __FILE__, __LINE__);
    checkThrows<std::out_of_range>([&] { static_cast<void>(binary.data(std::numeric_limits<uint64_t>::max(), 2)); }, "outside the file", __FILE__, __LINE__);
}

TEST_CASE("codegen module discovery reads normalized method pointers") {
    const auto binary = moduleBinary();
    MetadataModel metadata;
    discoverCodeGenModules(binary, metadata);
    const auto& pointers = metadata.methodPointersByImage.at("Assembly-CSharp.dll");
    CHECK_EQ(pointers.size(), 2);
    CHECK_EQ(pointers[0], 0x10000020);
    CHECK_EQ(pointers[1], 0x10000024);
}

TEST_CASE("codegen module discovery rejects invalid pointer ranges and counts") {
    auto binary = moduleBinary();
    put64(*binary.bytes, 0x10, 0x20000000);
    MetadataModel metadata;
    discoverCodeGenModules(binary, metadata);
    CHECK(metadata.methodPointersByImage.empty() || metadata.methodPointersByImage.at("Assembly-CSharp.dll").empty());

    binary = moduleBinary();
    put64(*binary.bytes, 0x08, 100);
    discoverCodeGenModules(binary, metadata);
    CHECK(metadata.methodPointersByImage.empty() || metadata.methodPointersByImage.at("Assembly-CSharp.dll").empty());

    binary = moduleBinary();
    put64(*binary.bytes, 0x08, 0);
    discoverCodeGenModules(binary, metadata);
    CHECK(metadata.methodPointersByImage.empty() || metadata.methodPointersByImage.at("Assembly-CSharp.dll").empty());
}

TEST_CASE("method resolver uses discovered module pointers and sorted ranges") {
    const auto binary = moduleBinary();
    MetadataModel metadata;
    metadata.version = 24.2;
    TypeModel type;
    type.nameSpace = "Demo";
    type.name = "C";
    MethodModel first;
    first.token = 0x06000001;
    first.definitionIndex = 0;
    first.imageName = "Assembly-CSharp.dll";
    first.declaringType = "Demo.C";
    first.name = "First";
    MethodModel second = first;
    second.token = 0x06000002;
    second.definitionIndex = 1;
    second.name = "Second";
    type.methods = {second, first};
    metadata.types.push_back(type);

    const auto images = MethodResolver{}.resolve(metadata, binary);
    CHECK_EQ(images.size(), 2);
    CHECK_EQ(images[0].address, 0x10000020);
    CHECK_EQ(images[1].address, 0x10000024);
    CHECK_EQ(images[0].size, 4);
    CHECK_EQ(images[1].size, binary.bytes->size() - 0x24);
    CHECK_EQ(images[0].name, "Demo.C__First");
    CHECK_EQ(images[1].name, "Demo.C__Second");
    CHECK(images[0].code == binary.bytes->data() + 0x20);
    CHECK(images[1].code == binary.bytes->data() + 0x24);
}

} // namespace il2cpprec::tests
