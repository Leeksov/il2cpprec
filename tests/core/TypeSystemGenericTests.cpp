#include "TestSupport.hpp"

#include <il2cpprec/metadata/TypeSystem.hpp>
#include <il2cpprec/emit/ProjectWriter.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>

namespace il2cpprec::tests {
namespace {

MetadataModel genericReferences() {
    MetadataModel metadata;
    metadata.types.resize(2);
    metadata.types[0].name = "Outer`1";
    metadata.types[0].genericContainerIndex = 0;
    metadata.types[1].name = "Inner`1";
    metadata.types[1].declaringTypeIndex = 0;
    metadata.types[1].genericContainerIndex = 1;
    metadata.genericContainers = {{0, 1, 0, 66}, {1, 1, 0, 67}, {7, 1, 1, 68}};
    metadata.genericParameters.resize(69);
    metadata.genericParameters[66] = {0, "T", -1, 0, 0, 0};
    metadata.genericParameters[67] = {1, "U", -1, 0, 0, 0};
    metadata.genericParameters[68] = {2, "M", -1, 0, 0, 0};
    MethodModel method;
    method.definitionIndex = 7;
    method.genericContainerIndex = 2;
    metadata.types[1].methods.push_back(method);
    metadata.typeReferences.resize(5);
    metadata.typeReferences[0].code = static_cast<uint8_t>(Il2CppTypeCode::Var);
    metadata.typeReferences[0].name = "!66";
    metadata.typeReferences[1].code = static_cast<uint8_t>(Il2CppTypeCode::SzArray);
    metadata.typeReferences[1].elementTypeIndex = 0;
    metadata.typeReferences[2].code = static_cast<uint8_t>(Il2CppTypeCode::Var);
    metadata.typeReferences[2].name = "!67";
    metadata.typeReferences[3].code = static_cast<uint8_t>(Il2CppTypeCode::MVar);
    metadata.typeReferences[3].name = "!!68";
    metadata.typeReferences[4].code = static_cast<uint8_t>(Il2CppTypeCode::MVar);
    metadata.typeReferences[4].name = "!66";
    return metadata;
}

} // namespace

TEST_CASE("global VAR indices resolve through their owning generic container") {
    const auto metadata = genericReferences();
    CHECK_EQ(TypeSystem::resolve(0, metadata), "T");
    CHECK_EQ(TypeSystem::resolve(1, metadata), "T[]");
    CHECK_EQ(TypeSystem::resolve(2, metadata), "U");
}

TEST_CASE("MVAR needs a matching method container and numeric prefix") {
    auto metadata = genericReferences();
    CHECK_EQ(TypeSystem::resolve(3, metadata), "M");
    CHECK_EQ(TypeSystem::resolve(4, metadata), "!66");
    metadata.types[1].methods.clear();
    CHECK_EQ(TypeSystem::resolve(3, metadata), "!!68");
}

TEST_CASE("generic index ambiguity and malformed ownership fail closed") {
    auto metadata = genericReferences();
    metadata.genericContainers.push_back({0, 1, 0, 66});
    CHECK_EQ(TypeSystem::resolve(1, metadata), "!66[]");
    metadata.genericContainers.pop_back();
    metadata.genericParameters[66].ownerIndex = 1;
    CHECK_EQ(TypeSystem::resolve(0, metadata), "!66");
    metadata.genericParameters[66].ownerIndex = 0;
    metadata.types[0].genericContainerIndex = -1;
    CHECK_EQ(TypeSystem::resolve(0, metadata), "!66");
    metadata.types[0].genericContainerIndex = 0;
    metadata.typeReferences[0].name = "!999999999999999999999999";
    CHECK_EQ(TypeSystem::resolve(0, metadata), "!999999999999999999999999");
}

TEST_CASE("generic array field emits T array and omits unresolved ownership") {
    auto metadata = genericReferences();
    metadata.types.resize(1);
    metadata.types[0].name = "ArrayReadOnlyList`1";
    metadata.types[0].nameSpace = "Regression";
    metadata.types[0].imageName = "Assembly-CSharp.dll";
    metadata.types[0].flags = 1;
    metadata.types[0].fields.push_back({"Items", "type[1]"});
    const auto output = std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
        "build/tests/generic-index-emission";
    std::filesystem::remove_all(output);
    ProjectWriter{}.write(output, metadata, {});
    const auto sourcePath = output / "Regression/ArrayReadOnlyList.cs";
    std::ifstream input(sourcePath, std::ios::binary);
    const std::string source{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    CHECK(source.find("T[] Items") != std::string::npos);
    CHECK(source.find("_66") == std::string::npos);
    metadata.genericContainers.push_back({0, 1, 0, 66});
    std::filesystem::remove_all(output);
    ProjectWriter{}.write(output, metadata, {});
    std::ifstream invalidInput(sourcePath, std::ios::binary);
    const std::string invalid{std::istreambuf_iterator<char>(invalidInput), std::istreambuf_iterator<char>()};
    CHECK(invalid.find("field 'Items' has unresolved C# type syntax") != std::string::npos);
    CHECK(invalid.find("object[] Items") == std::string::npos);
    std::filesystem::remove_all(output);
}

} // namespace il2cpprec::tests
