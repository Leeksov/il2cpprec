#include "../core/TestSupport.hpp"
#include "MetadataFixtures.hpp"

#include <il2cpprec/metadata/GlobalMetadata.hpp>
#include <il2cpprec/versions/Version38.hpp>
#include <il2cpprec/versions/Version108.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace il2cpprec::tests {
namespace {

using modern::MetadataFixture;
using modern::RecordWriter;
using modern::Section;
using modern::SectionBytes;

struct StringTable {
    RecordWriter writer;

    uint32_t add(std::string_view value) {
        const auto offset = static_cast<uint32_t>(writer.bytes.size());
        writer.bytes.insert(writer.bytes.end(), value.begin(), value.end());
        writer.u8(0);
        return offset;
    }
};

struct Names {
    uint32_t image;
    uint32_t nameSpace;
    uint32_t type;
    uint32_t method;
    uint32_t secondMethod;
    uint32_t thirdMethod;
    uint32_t parameter;
    uint32_t secondParameter;
    uint32_t thirdParameter;
    uint32_t field;
    uint32_t genericParameter;
};

Names addNames(StringTable& strings) {
    return {
        strings.add("Modern.dll"),
        strings.add("Modern"),
        strings.add("Sample"),
        strings.add("Run"),
        strings.add("GeneratedA"),
        strings.add("GeneratedB"),
        strings.add("value"),
        strings.add("second"),
        strings.add("third"),
        strings.add("field"),
        strings.add("T"),
    };
}

SectionBytes section(Section id, const RecordWriter& writer, int32_t count) {
    return {id, writer.bytes, count};
}

SectionBytes section(Section id, const std::vector<uint8_t>& bytes, int32_t count) {
    return {id, bytes, count};
}

MetadataModel read(const MetadataFixture& fixture) {
    return GlobalMetadata{}.read(fixture.bytes);
}

void expectInvalid(const MetadataFixture& fixture) {
    CHECK_THROWS(GlobalMetadata{}.read(fixture.bytes), "");
}

size_t parameterWidth(int version) {
    return version >= 39 ? 1 : 4;
}

size_t methodWidth(int version) {
    return version >= 105 ? 1 : 4;
}

size_t fieldWidth(int version) {
    return version >= 106 ? 1 : 4;
}

size_t defaultValueWidth(int version) {
    return version >= 106 ? 1 : 4;
}

size_t smallIndexWidth(int version, bool introducedIn104 = false) {
    return !introducedIn104 || version >= 104 ? 1 : 4;
}

void writeMethod(RecordWriter& writer, int version, uint32_t name, int32_t parameterStart,
                 uint16_t parameterCount, uint32_t token, int32_t signatureOffset = 0,
                 int32_t returnType = 3) {
    writer.u32(name);
    writer.index(0, 1);
    if (version >= 111) {
        writer.index(parameterStart, 1);
        writer.index(-1, 1);
        writer.u16(0x0010);
        writer.u16(0x0002);
        writer.u16(7);
        writer.u32(static_cast<uint32_t>(signatureOffset));
        return;
    }
    writer.index(returnType, 1);
    writer.u32(0x0A000001);
    writer.index(parameterStart, parameterWidth(version));
    writer.index(-1, 1);
    if (version < 110) writer.u32(token);
    writer.u16(0x0010);
    writer.u16(0x0002);
    writer.u16(7);
    writer.u16(parameterCount);
}

void writeParameter(RecordWriter& writer, int version, uint32_t name, int32_t type = 4) {
    writer.u32(name);
    if (version < 111) {
        writer.u32(0x08000001);
        writer.index(type, 1);
    }
}

void writeField(RecordWriter& writer, int version, uint32_t name) {
    writer.u32(name);
    writer.index(4, 1);
    if (version < 110) writer.u32(0x04000003);
}

struct TypeOptions {
    uint16_t methodCount = 1;
    uint16_t fieldCount = 1;
    uint32_t bitfield = 0;
    int32_t methodStart = 0;
};

void writeType(RecordWriter& writer, int version, const Names& names, const TypeOptions& options = {}) {
    writer.u32(names.type);
    writer.u32(names.nameSpace);
    writer.index(0, 1);
    writer.index(-1, 1);
    writer.index(2, 1);
    writer.index(-1, 1);
    writer.u32(0x00000001);
    writer.index(options.fieldCount == 0 ? -1 : 0, fieldWidth(version));
    writer.index(options.methodStart, methodWidth(version));
    writer.index(-1, smallIndexWidth(version, true));
    writer.index(-1, smallIndexWidth(version, true));
    writer.index(-1, smallIndexWidth(version, true));
    writer.index(-1, smallIndexWidth(version, true));
    writer.u32(0xFFFFFFFF);
    writer.index(-1, smallIndexWidth(version, true));
    writer.u16(options.methodCount);
    writer.u16(0);
    writer.u16(options.fieldCount);
    writer.u16(0);
    writer.u16(0);
    writer.u16(0);
    writer.u16(0);
    writer.u16(0);
    writer.u32(options.bitfield);
    if (version < 110) writer.u32(0x02000003);
}

struct ImageOptions {
    uint32_t typeCount = 1;
    int32_t rgctxRangesStart = 0;
    uint32_t rgctxRangesCount = 0;
    uint32_t staticConstructorCount = 0;
    int32_t methodStart = 0;
};

void writeImage(RecordWriter& writer, int version, const Names& names, const ImageOptions& options = {}) {
    writer.u32(names.image);
    writer.u32(0);
    writer.index(0, 1);
    writer.u32(options.typeCount);
    writer.index(-1, 1);
    writer.u32(0);
    writer.index(0, methodWidth(version));
    writer.u32(1);
    writer.u32(0xFFFFFFFF);
    writer.u32(0);
    if (version >= 108) {
        writer.u32(0);
        writer.u32(static_cast<uint32_t>(options.rgctxRangesStart));
        writer.u32(options.rgctxRangesCount);
        writer.index(options.staticConstructorCount == 0 ? -1 : 0, 1);
        writer.u32(options.staticConstructorCount);
    }
    if (version >= 110) {
        writer.u32(0);
        writer.u32(0);
        writer.u32(0);
        writer.index(options.methodStart, 1);
    }
}

MetadataFixture makeLegacyFixture(int version) {
    StringTable strings;
    const auto names = addNames(strings);

    RecordWriter literals;
    if (version == 33) {
        literals.u32(3);
        literals.u32(0);
        literals.u32(3);
        literals.u32(3);
    } else {
        literals.u32(0);
        literals.u32(3);
        literals.u32(6);
    }
    RecordWriter literalData;
    literalData.bytes = {'o', 'n', 'e', 'T', 'W', 'O', 's', 'i', 'x'};

    RecordWriter methods;
    methods.u32(names.method);
    methods.u32(0);
    methods.u32(3);
    methods.u32(0x0A000001);
    methods.u32(0);
    methods.u32(0xFFFFFFFF);
    methods.u32(0x06000007);
    methods.u16(0x0010);
    methods.u16(0x0002);
    methods.u16(7);
    methods.u16(1);

    RecordWriter parameters;
    parameters.u32(names.parameter);
    parameters.u32(0x08000001);
    parameters.u32(4);

    RecordWriter fields;
    fields.u32(names.field);
    fields.u32(4);
    fields.u32(0x04000003);

    RecordWriter types;
    types.u32(names.type);
    types.u32(names.nameSpace);
    types.u32(0);
    types.u32(0xFFFFFFFF);
    types.u32(2);
    if (version == 33) types.u32(9);
    types.u32(0xFFFFFFFF);
    types.u32(1);
    types.u32(0);
    types.u32(0);
    types.u32(0xFFFFFFFF);
    types.u32(0xFFFFFFFF);
    types.u32(0xFFFFFFFF);
    types.u32(0xFFFFFFFF);
    types.u32(0xFFFFFFFF);
    types.u32(0xFFFFFFFF);
    types.u16(1);
    types.u16(0);
    types.u16(1);
    types.u16(0);
    types.u16(0);
    types.u16(0);
    types.u16(0);
    types.u16(0);
    types.u32(2);
    types.u32(0x02000003);

    RecordWriter image;
    image.u32(names.image);
    image.u32(0);
    image.u32(0);
    image.u32(1);
    image.u32(0xFFFFFFFF);
    image.u32(0);
    image.u32(0);
    image.u32(1);
    image.u32(0xFFFFFFFF);
    image.u32(0);

    return modern::buildMetadataFixture(version, {
        section(Section::StringLiterals, literals, version == 33 ? 2 : 3),
        section(Section::StringLiteralData, literalData, 9),
        section(Section::Strings, strings.writer, static_cast<int32_t>(strings.writer.bytes.size())),
        section(Section::Methods, methods, 1),
        section(Section::Parameters, parameters, 1),
        section(Section::Fields, fields, 1),
        section(Section::TypeDefinitions, types, 1),
        section(Section::Images, image, 1),
    });
}

MetadataFixture makeDefinitionFixture(int version) {
    StringTable strings;
    const auto names = addNames(strings);

    RecordWriter interfaceOffsets;
    interfaceOffsets.index(7, 1);
    interfaceOffsets.u32(32);

    RecordWriter methods;
    writeMethod(methods, version, names.method, 0, 1, 0x06000007);
    RecordWriter parameters;
    writeParameter(parameters, version, names.parameter);
    RecordWriter fields;
    writeField(fields, version, names.field);
    RecordWriter types;
    writeType(types, version, names);
    RecordWriter images;
    writeImage(images, version, names);

    RecordWriter genericContainers;
    genericContainers.u32(0);
    if (version >= 106) {
        genericContainers.u16(1);
        genericContainers.u8(1);
    } else {
        genericContainers.u32(1);
        genericContainers.u32(1);
    }
    genericContainers.index(0, version >= 106 ? 1 : 4);

    RecordWriter genericParameters;
    genericParameters.index(0, 1);
    genericParameters.u32(names.genericParameter);
    genericParameters.u16(0xFFFF);
    genericParameters.u16(0);
    genericParameters.u16(0);
    genericParameters.u16(0x0001);

    RecordWriter fieldDefaults;
    fieldDefaults.index(0, fieldWidth(version));
    fieldDefaults.index(3, 1);
    fieldDefaults.index(0, defaultValueWidth(version));
    RecordWriter parameterDefaults;
    parameterDefaults.index(0, parameterWidth(version));
    parameterDefaults.index(3, 1);
    parameterDefaults.index(0, defaultValueWidth(version));

    RecordWriter unresolvedTypes;
    unresolvedTypes.index(4, 1);
    unresolvedTypes.index(5, 1);
    RecordWriter unresolvedRanges;
    unresolvedRanges.u32(0);
    unresolvedRanges.u32(2);

    return modern::buildMetadataFixture(version, {
        section(Section::Strings, strings.writer, static_cast<int32_t>(strings.writer.bytes.size())),
        section(Section::InterfaceOffsets, interfaceOffsets, 1),
        section(Section::Methods, methods, 1),
        section(Section::Parameters, parameters, 1),
        section(Section::Fields, fields, 1),
        section(Section::TypeDefinitions, types, 1),
        section(Section::Images, images, 1),
        section(Section::GenericContainers, genericContainers, 1),
        section(Section::GenericParameters, genericParameters, 1),
        section(Section::FieldDefaultValues, fieldDefaults, 1),
        section(Section::ParameterDefaultValues, parameterDefaults, 1),
        section(Section::DefaultValueData, std::vector<uint8_t>{2, 0, 0, 0}, 4),
        section(Section::UnresolvedParameterTypes, unresolvedTypes, 2),
        section(Section::UnresolvedParameterRanges, unresolvedRanges, 1),
    });
}

void checkDefinition(const MetadataModel& metadata) {
    CHECK_EQ(metadata.types.size(), 1);
    const auto& type = metadata.types.at(0);
    CHECK_EQ(type.nameSpace, "Modern");
    CHECK_EQ(type.name, "Sample");
    CHECK_EQ(type.imageName, "Modern.dll");
    CHECK_EQ(type.baseType, "type[2]");
    CHECK_EQ(type.fields.size(), 1);
    CHECK_EQ(type.fields[0].name, "field");
    CHECK_EQ(type.fields[0].type, "type[4]");
    CHECK_EQ(type.methods.size(), 1);
    const auto& method = type.methods[0];
    CHECK_EQ(method.name, "Run");
    CHECK_EQ(method.declaringType, "Modern.Sample");
    CHECK_EQ(method.returnType, "type[3]");
    CHECK(method.isStatic);
    CHECK_EQ(method.iflags, 2);
    CHECK_EQ(method.slot, 7);
    CHECK_EQ(method.parameters.size(), 1);
    CHECK_EQ(method.parameters[0].name, "value");
    CHECK_EQ(method.parameters[0].type, "type[4]");
    CHECK_EQ(metadata.genericContainers.size(), 1);
    CHECK_EQ(metadata.genericContainers[0].typeArgumentCount, 1);
    CHECK_EQ(metadata.genericContainers[0].isMethod, 1);
    CHECK_EQ(metadata.genericContainers[0].genericParameterStart, 0);
    CHECK_EQ(metadata.genericParameters.size(), 1);
    CHECK_EQ(metadata.genericParameters[0].name, "T");
    CHECK_EQ(metadata.fieldDefaultValues.size(), 1);
    CHECK_EQ(metadata.fieldDefaultValues[0].dataIndex, 0);
    CHECK_EQ(metadata.parameterDefaultValues.size(), 1);
    CHECK_EQ(metadata.parameterDefaultValues[0].dataIndex, 0);
    CHECK_EQ(type.fields[0].defaultValueIndex, 0);
    CHECK_EQ(method.parameters[0].defaultValueIndex, 0);
    CHECK_EQ(metadata.unresolvedSignatures.size(), 1);
    CHECK_EQ(metadata.unresolvedSignatures[0].start, 0);
    CHECK_EQ(metadata.unresolvedSignatures[0].count, 2);
    CHECK_EQ(metadata.unresolvedSignatures[0].parameterTypeIndices.size(), 2);
    CHECK_EQ(metadata.unresolvedSignatures[0].parameterTypeIndices[0], 4);
    CHECK_EQ(metadata.unresolvedSignatures[0].parameterTypeIndices[1], 5);
}

MetadataFixture makeSpecFixture(int version) {
    StringTable strings;
    const auto names = addNames(strings);
    RecordWriter interfaceOffsets;
    interfaceOffsets.index(7, 1);
    interfaceOffsets.u32(32);

    RecordWriter methods;
    writeMethod(methods, version, names.method, 0, 0, 0x06000011);
    writeMethod(methods, version, names.secondMethod, 0, 0, 0x06000012);
    writeMethod(methods, version, names.thirdMethod, 0, 0, 0x06000013);
    RecordWriter types;
    writeType(types, version, names, TypeOptions{3, 0});
    RecordWriter images;
    writeImage(images, version, names, ImageOptions{1, 0, 2, 2});

    RecordWriter classSpecs;
    classSpecs.index(0, 1);
    classSpecs.index(0x0102, 2);
    RecordWriter methodSpecs;
    methodSpecs.index(1, 1);
    methodSpecs.index(0x0203, 2);
    RecordWriter fullSpecs;
    fullSpecs.index(2, 1);
    fullSpecs.index(0x0304, 2);
    fullSpecs.index(0x0405, 2);

    RecordWriter functions;
    functions.index(0, 1);
    functions.index(0x1122, 2);
    functions.index(0x0334, 2);
    RecordWriter functionsWithAdjustor;
    functionsWithAdjustor.index(2, 1);
    functionsWithAdjustor.index(0x5566, 2);
    functionsWithAdjustor.index(0x0778, 2);
    functionsWithAdjustor.index(0, 1);

    RecordWriter invokers;
    invokers.u16(0x0334);
    invokers.u16(0x0778);

    RecordWriter ranges;
    ranges.u32(0x06000011);
    ranges.u32(0);
    ranges.u32(1);
    ranges.u32(0x02000003);
    ranges.u32(1);
    ranges.u32(1);
    RecordWriter values;
    values.u8(2);
    values.u32(0x12345678);
    values.u8(0);
    values.u16(0);
    values.u8(3);
    values.u32(0x23456789);
    values.u8(0);
    values.u16(0);

    return modern::buildMetadataFixture(version, {
        section(Section::Strings, strings.writer, static_cast<int32_t>(strings.writer.bytes.size())),
        section(Section::InterfaceOffsets, interfaceOffsets, 1),
        section(Section::Methods, methods, 3),
        section(Section::TypeDefinitions, types, 1),
        section(Section::Images, images, 1),
        section(Section::MethodSpecsOnGenericType, classSpecs, 1),
        section(Section::GenericMethodSpecsOnType, methodSpecs, 1),
        section(Section::MethodSpecs, fullSpecs, 1),
        section(Section::GenericMethodFunctions, functions, 1),
        section(Section::GenericMethodFunctionsWithAdjustor, functionsWithAdjustor, 1),
        section(Section::InvokerIndices, invokers, 2),
        section(Section::RgctxRanges, ranges, 2),
        section(Section::RgctxValues, values, 2),
        section(Section::StaticConstructorTypeIndices, std::vector<uint8_t>{0, 0xFF}, 2),
    });
}

void checkSpecs(const MetadataModel& metadata) {
    CHECK_EQ(metadata.methodSpecsOnGenericType.size(), 1);
    CHECK_EQ(metadata.methodSpecsOnGenericType[0].classIndexIndex, 0x0102);
    CHECK_EQ(metadata.genericMethodSpecsOnType.size(), 1);
    CHECK_EQ(metadata.genericMethodSpecsOnType[0].methodIndexIndex, 0x0203);
    CHECK_EQ(metadata.methodSpecs.size(), 3);
    CHECK_EQ(metadata.methodSpecs[0].methodDefinitionIndex, 0);
    CHECK_EQ(metadata.methodSpecs[0].classInstIndex, 0x0102);
    CHECK_EQ(metadata.methodSpecs[0].methodInstIndex, -1);
    CHECK_EQ(metadata.methodSpecs[1].methodDefinitionIndex, 1);
    CHECK_EQ(metadata.methodSpecs[1].classInstIndex, -1);
    CHECK_EQ(metadata.methodSpecs[1].methodInstIndex, 0x0203);
    CHECK_EQ(metadata.methodSpecs[2].methodDefinitionIndex, 2);
    CHECK_EQ(metadata.methodSpecs[2].classInstIndex, 0x0304);
    CHECK_EQ(metadata.methodSpecs[2].methodInstIndex, 0x0405);

    CHECK_EQ(metadata.genericMethodTable.size(), 2);
    CHECK_EQ(metadata.genericMethodTable[0].genericMethodIndex, 0);
    CHECK_EQ(metadata.genericMethodTable[0].methodIndex, 0x1122);
    CHECK_EQ(metadata.genericMethodTable[0].invokerIndex, 0x0334);
    CHECK_EQ(metadata.genericMethodTable[0].adjustorThunkIndex, -1);
    CHECK_EQ(metadata.genericMethodTable[1].genericMethodIndex, 2);
    CHECK_EQ(metadata.genericMethodTable[1].methodIndex, 0x5566);
    CHECK_EQ(metadata.genericMethodTable[1].invokerIndex, 0x0778);
    CHECK_EQ(metadata.genericMethodTable[1].adjustorThunkIndex, 0);
    CHECK_EQ(metadata.invokerIndices.size(), 2);
    CHECK_EQ(metadata.invokerIndices[0], 0x0334);
    CHECK_EQ(metadata.invokerIndices[1], 0x0778);
    CHECK_EQ(metadata.rgctxRanges.size(), 2);
    CHECK_EQ(metadata.rgctxRanges[0].token, 0x06000011);
    CHECK_EQ(metadata.rgctxRanges[1].start, 1);
    CHECK_EQ(metadata.rgctxValues.size(), 2);
    CHECK_EQ(metadata.rgctxValues[0].kind, 2);
    CHECK_EQ(metadata.rgctxValues[0].value, 0x12345678);
    CHECK_EQ(metadata.rgctxValues[1].kind, 3);
    CHECK_EQ(metadata.rgctxValues[1].value, 0x23456789);
    CHECK_EQ(metadata.staticConstructorTypeIndices.size(), 2);
    CHECK_EQ(metadata.staticConstructorTypeIndices[0], 0);
    CHECK_EQ(metadata.staticConstructorTypeIndices[1], -1);
    CHECK_EQ(metadata.images.size(), 1);
    CHECK_EQ(metadata.images[0].rgctxRangesStart, 0);
    CHECK_EQ(metadata.images[0].rgctxRangesCount, 2);
    CHECK_EQ(metadata.images[0].staticConstructorCount, 2);
}

MetadataFixture makeGeneratedFixture() {
    constexpr int version = 110;
    StringTable strings;
    const auto names = addNames(strings);
    RecordWriter interfaceOffsets;
    interfaceOffsets.index(7, 1);
    interfaceOffsets.u32(32);
    RecordWriter methods;
    writeMethod(methods, version, names.method, 0, 0, 0);
    writeMethod(methods, version, names.secondMethod, 0, 0, 0);
    writeMethod(methods, version, names.thirdMethod, 0, 0, 0);
    RecordWriter fields;
    writeField(fields, version, names.field);
    RecordWriter types;
    writeType(types, version, names, TypeOptions{3, 1, 1U << 19});
    RecordWriter images;
    writeImage(images, version, names);
    RecordWriter generatedInfo;
    generatedInfo.u32(0);
    generatedInfo.u32(1);
    generatedInfo.u32(2);
    RecordWriter generatedTokens;
    generatedTokens.u32(0x0600012A);
    generatedTokens.u32(0x0600012B);

    return modern::buildMetadataFixture(version, {
        section(Section::Strings, strings.writer, static_cast<int32_t>(strings.writer.bytes.size())),
        section(Section::InterfaceOffsets, interfaceOffsets, 1),
        section(Section::Methods, methods, 3),
        section(Section::Fields, fields, 1),
        section(Section::TypeDefinitions, types, 1),
        section(Section::Images, images, 1),
        section(Section::GeneratedMethodTypeInfos, generatedInfo, 1),
        section(Section::GeneratedMethodTokens, generatedTokens, 2),
    });
}

MetadataFixture makeSignatureFixture() {
    constexpr int version = 111;
    StringTable strings;
    const auto names = addNames(strings);
    RecordWriter interfaceOffsets;
    interfaceOffsets.index(7, 1);
    interfaceOffsets.u32(32);
    RecordWriter methods;
    writeMethod(methods, version, names.method, 0, 0, 0, 0, 7);
    writeMethod(methods, version, names.secondMethod, 2, 0, 0, 4, 10);
    RecordWriter parameters;
    writeParameter(parameters, version, names.parameter);
    writeParameter(parameters, version, names.secondParameter);
    writeParameter(parameters, version, names.thirdParameter);
    RecordWriter types;
    writeType(types, version, names, TypeOptions{2, 0});
    RecordWriter images;
    writeImage(images, version, names);

    RecordWriter signatures;
    signatures.index(7, 1);
    signatures.u8(2);
    signatures.index(8, 1);
    signatures.index(9, 1);
    signatures.index(10, 1);
    signatures.u8(1);
    signatures.index(11, 1);

    return modern::buildMetadataFixture(version, {
        section(Section::Strings, strings.writer, static_cast<int32_t>(strings.writer.bytes.size())),
        section(Section::InterfaceOffsets, interfaceOffsets, 1),
        section(Section::MethodSignatures, signatures, 0),
        section(Section::Methods, methods, 2),
        section(Section::Parameters, parameters, 3),
        section(Section::TypeDefinitions, types, 1),
        section(Section::Images, images, 1),
    });
}

TEST_CASE("modern metadata accepts exact header sizes for versions 33 35 38 39 and 104 through 111") {
    constexpr int versions[] = {33, 35, 38, 39, 104, 105, 106, 107, 108, 109, 110, 111};
    constexpr size_t sizes[] = {256, 256, 380, 380, 392, 392, 392, 392, 500, 500, 524, 536};
    for (size_t index = 0; index < std::size(versions); ++index) {
        const auto fixture = modern::buildMetadataFixture(versions[index]);
        CHECK_EQ(fixture.headerSize, sizes[index]);
        CHECK_EQ(fixture.bytes.size(), sizes[index]);
        const auto metadata = read(fixture);
        CHECK(metadata.version == static_cast<double>(versions[index]));
        CHECK(metadata.types.empty());
        CHECK_THROWS(GlobalMetadata{}.read(fixture.bytes.data(), fixture.headerSize - 1), "");
    }
}

TEST_CASE("modern fixture section positions match independent wire offsets") {
    const auto v33 = modern::buildMetadataFixture(33);
    CHECK_EQ(v33.layout(Section::Methods).headerOffset, 48);
    CHECK_EQ(v33.layout(Section::TypeDefinitions).headerOffset, 160);
    CHECK_EQ(v33.layout(Section::AttributeDataRanges).headerOffset, 208);

    const auto v38 = modern::buildMetadataFixture(38);
    CHECK_EQ(v38.layout(Section::Methods).headerOffset, 68);
    CHECK_EQ(v38.layout(Section::TypeDefinitions).headerOffset, 236);
    CHECK_EQ(v38.layout(Section::ExportedTypeDefinitions).headerOffset, 368);

    const auto v104 = modern::buildMetadataFixture(104);
    CHECK_EQ(v104.layout(Section::TypeInlineArrays).headerOffset, 248);
    CHECK_EQ(v104.layout(Section::Images).headerOffset, 260);

    const auto v108 = modern::buildMetadataFixture(108);
    CHECK_EQ(v108.layout(Section::MethodSpecsOnGenericType).headerOffset, 392);
    CHECK_EQ(v108.layout(Section::RgctxValues).headerOffset, 476);

    const auto v110 = modern::buildMetadataFixture(110);
    CHECK_EQ(v110.layout(Section::GeneratedMethodTypeInfos).headerOffset, 500);
    CHECK_EQ(v110.layout(Section::GeneratedMethodTokens).headerOffset, 512);

    const auto v111 = modern::buildMetadataFixture(111);
    CHECK_EQ(v111.layout(Section::MethodSignatures).headerOffset, 68);
    CHECK_EQ(v111.layout(Section::Methods).headerOffset, 80);
    CHECK_EQ(v111.layout(Section::GeneratedMethodTokens).headerOffset, 524);
}

TEST_CASE("modern fixture builder rejects duplicate and unavailable sections") {
    const SectionBytes strings{Section::Strings, {'a', 0}, 2};
    checkThrows<std::invalid_argument>(
        [&] { modern::buildMetadataFixture(38, {strings, strings}); },
        "Duplicate fixture section", __FILE__, __LINE__);
    checkThrows<std::invalid_argument>(
        [&] { modern::buildMetadataFixture(33, {{Section::MethodSignatures, {1}, 1}}); },
        "Section is not present", __FILE__, __LINE__);
    checkThrows<std::invalid_argument>(
        [&] { modern::buildMetadataFixture(107, {{Section::GeneratedMethodTokens, {1}, 1}}); },
        "Section is not present", __FILE__, __LINE__);
}

TEST_CASE("modern index width boundaries preserve the negative sentinel") {
    CHECK_EQ(Version38Header::indexWidth(254), 1);
    CHECK_EQ(Version38Header::indexWidth(255), 2);
    CHECK_EQ(Version38Header::indexWidth(65534), 2);
    CHECK_EQ(Version38Header::indexWidth(65535), 4);
    CHECK_EQ(Version108Header::indexWidth(254), 1);
    CHECK_EQ(Version108Header::indexWidth(255), 1);
    CHECK_EQ(Version108Header::indexWidth(256), 2);
    CHECK_EQ(Version108Header::indexWidth(65534), 2);
    CHECK_EQ(Version108Header::indexWidth(65535), 2);
    CHECK_EQ(Version108Header::indexWidth(65536), 4);
    RecordWriter sentinels;
    sentinels.index(-1, 1);
    sentinels.index(-1, 2);
    sentinels.index(-1, 4);
    CHECK_EQ(sentinels.bytes.size(), 7);
    for (const auto byte : sentinels.bytes) CHECK_EQ(byte, 0xFF);
    checkThrows<std::out_of_range>(
        [&] { sentinels.index(255, 1); }, "sentinel", __FILE__, __LINE__);
    checkThrows<std::out_of_range>(
        [&] { sentinels.index(65535, 2); }, "sentinel", __FILE__, __LINE__);
    checkThrows<std::out_of_range>(
        [&] { sentinels.index(-2, 4); }, "sentinel", __FILE__, __LINE__);
}

TEST_CASE("modern metadata rejects newer binary layouts labeled with older versions") {
    auto fixture = makeLegacyFixture(35);
    modern::put32(fixture.bytes, 4, 33);
    expectInvalid(fixture);
    fixture = makeLegacyFixture(33);
    modern::put32(fixture.bytes, 4, 35);
    expectInvalid(fixture);

    fixture = makeDefinitionFixture(38);
    modern::put32(fixture.bytes, 4, 37);
    expectInvalid(fixture);
    fixture = makeDefinitionFixture(39);
    modern::put32(fixture.bytes, 4, 38);
    expectInvalid(fixture);
    fixture = makeDefinitionFixture(104);
    modern::put32(fixture.bytes, 4, 103);
    expectInvalid(fixture);
    fixture = makeDefinitionFixture(105);
    modern::put32(fixture.bytes, 4, 104);
    expectInvalid(fixture);
    fixture = makeDefinitionFixture(106);
    modern::put32(fixture.bytes, 4, 105);
    expectInvalid(fixture);
    fixture = makeSpecFixture(108);
    modern::put32(fixture.bytes, 4, 107);
    expectInvalid(fixture);
    fixture = makeGeneratedFixture();
    modern::put32(fixture.bytes, 4, 109);
    expectInvalid(fixture);
    fixture = makeSignatureFixture();
    modern::put32(fixture.bytes, 4, 110);
    expectInvalid(fixture);
}

TEST_CASE("v38 section headers reject negative counts sizes and out of file ranges") {
    const auto valid = modern::buildMetadataFixture(111);
    for (const auto id : modern::sectionOrder(111)) {
        const auto& layout = valid.layout(id);
        auto fixture = valid;
        modern::put32(fixture.bytes, layout.headerOffset, 0xFFFFFFFF);
        expectInvalid(fixture);
        fixture = valid;
        modern::put32(fixture.bytes, layout.headerOffset + 4, 0xFFFFFFFF);
        expectInvalid(fixture);
        fixture = valid;
        modern::put32(fixture.bytes, layout.headerOffset + 8, 0xFFFFFFFF);
        expectInvalid(fixture);
        fixture = valid;
        modern::put32(fixture.bytes, layout.headerOffset, static_cast<uint32_t>(fixture.bytes.size() - 4));
        modern::put32(fixture.bytes, layout.headerOffset + 4, 8);
        modern::put32(fixture.bytes, layout.headerOffset + 8, 1);
        expectInvalid(fixture);
    }

    auto misaligned = valid;
    const auto& methods = misaligned.layout(Section::Methods);
    modern::put32(misaligned.bytes, methods.headerOffset + 4, 1);
    modern::put32(misaligned.bytes, methods.headerOffset + 8, 1);
    expectInvalid(misaligned);
}

TEST_CASE("v33 reads length prefixed literals and the pre-v35 type layout") {
    const auto fixture = makeLegacyFixture(33);
    CHECK_EQ(fixture.layout(Section::StringLiterals).size, 16);
    CHECK_EQ(fixture.layout(Section::TypeDefinitions).size, 88);
    const auto metadata = read(fixture);
    CHECK_EQ(metadata.stringLiterals.at(0), "one");
    CHECK_EQ(metadata.stringLiterals.at(1), "TWO");
    CHECK_EQ(metadata.types.size(), 1);
    CHECK_EQ(metadata.types[0].name, "Sample");
    CHECK_EQ(metadata.types[0].baseType, "type[2]");
    CHECK_EQ(metadata.types[0].methods.size(), 1);
    CHECK_EQ(metadata.types[0].methods[0].parameters.size(), 1);
    CHECK_EQ(metadata.types[0].methods[0].parameters[0].type, "type[4]");

    auto shortLiterals = fixture;
    const auto& literals = shortLiterals.layout(Section::StringLiterals);
    modern::put32(shortLiterals.bytes, literals.headerOffset + 4, 4);
    expectInvalid(shortLiterals);
}

TEST_CASE("v35 derives literal lengths from offsets and removes elementTypeIndex") {
    const auto fixture = makeLegacyFixture(35);
    CHECK_EQ(fixture.layout(Section::StringLiterals).size, 12);
    CHECK_EQ(fixture.layout(Section::TypeDefinitions).size, 84);
    const auto metadata = read(fixture);
    CHECK_EQ(metadata.stringLiterals.at(0), "one");
    CHECK_EQ(metadata.stringLiterals.at(1), "TWO");
    CHECK_EQ(metadata.types.size(), 1);
    CHECK_EQ(metadata.types[0].methods.size(), 1);
    CHECK_EQ(metadata.types[0].fields.size(), 1);
}

TEST_CASE("v38 and v39 use independent widths and delay parameter indices until v39") {
    const auto v38 = makeDefinitionFixture(38);
    CHECK_EQ(v38.layout(Section::TypeDefinitions).size, 72);
    CHECK_EQ(v38.layout(Section::Methods).size, 27);
    CHECK_EQ(v38.layout(Section::Parameters).size, 9);
    CHECK_EQ(v38.layout(Section::Images).size, 34);
    const auto metadata38 = read(v38);
    CHECK_EQ(metadata38.sections.methods.count, 1);
    CHECK_EQ(metadata38.sections.parameters.count, 1);
    checkDefinition(metadata38);

    const auto v39 = makeDefinitionFixture(39);
    CHECK_EQ(v39.layout(Section::TypeDefinitions).size, 72);
    CHECK_EQ(v39.layout(Section::Methods).size, 24);
    CHECK_EQ(v39.layout(Section::Parameters).size, 9);
    const auto metadata39 = read(v39);
    checkDefinition(metadata39);
}

TEST_CASE("v104 through v107 expand variable widths and compact generic containers") {
    constexpr int versions[] = {104, 105, 106, 107};
    constexpr int typeSizes[] = {57, 54, 51, 51};
    constexpr int imageSizes[] = {34, 31, 31, 31};
    for (size_t index = 0; index < std::size(versions); ++index) {
        const auto fixture = makeDefinitionFixture(versions[index]);
        CHECK_EQ(fixture.layout(Section::TypeDefinitions).size, typeSizes[index]);
        CHECK_EQ(fixture.layout(Section::Images).size, imageSizes[index]);
        CHECK_EQ(fixture.layout(Section::Methods).size, 24);
        CHECK_EQ(fixture.layout(Section::Fields).size, 9);
        CHECK_EQ(fixture.layout(Section::GenericContainers).size, versions[index] >= 106 ? 8 : 16);
        CHECK_EQ(fixture.layout(Section::FieldDefaultValues).size, versions[index] >= 106 ? 3 : 9);
        CHECK_EQ(fixture.layout(Section::ParameterDefaultValues).size, versions[index] >= 106 ? 3 : 6);
        const auto metadata = read(fixture);
        CHECK_EQ(metadata.sections.typeDefinitions.sectionSize, typeSizes[index]);
        CHECK_EQ(metadata.sections.images.sectionSize, imageSizes[index]);
        CHECK_EQ(metadata.types[0].methods[0].token, 0x06000007);
        CHECK_EQ(metadata.types[0].fields[0].token, 0x04000003);
        checkDefinition(metadata);
    }
}

TEST_CASE("v108 and v109 normalize three spec tables and mixed width generic mappings") {
    for (const int version : {108, 109}) {
        const auto fixture = makeSpecFixture(version);
        CHECK_EQ(fixture.layout(Section::MethodSpecsOnGenericType).size, 3);
        CHECK_EQ(fixture.layout(Section::GenericMethodSpecsOnType).size, 3);
        CHECK_EQ(fixture.layout(Section::MethodSpecs).size, 5);
        CHECK_EQ(fixture.layout(Section::GenericMethodFunctions).size, 5);
        CHECK_EQ(fixture.layout(Section::GenericMethodFunctionsWithAdjustor).size, 6);
        CHECK_EQ(fixture.layout(Section::InvokerIndices).size, 4);
        CHECK_EQ(fixture.layout(Section::RgctxValues).size, 16);
        const auto metadata = read(fixture);
        CHECK_EQ(metadata.sections.methodSpecs.count, 1);
        CHECK_EQ(metadata.sections.genericMethodFunctionsDefinitionsWithAdjustor.count, 1);
        checkSpecs(metadata);
    }
}

TEST_CASE("v110 reconstructs generated method ranges and metadata tokens") {
    const auto fixture = makeGeneratedFixture();
    CHECK_EQ(fixture.layout(Section::Methods).size, 60);
    CHECK_EQ(fixture.layout(Section::TypeDefinitions).size, 47);
    CHECK_EQ(fixture.layout(Section::GeneratedMethodTypeInfos).size, 12);
    CHECK_EQ(fixture.layout(Section::GeneratedMethodTokens).size, 8);
    const auto metadata = read(fixture);
    CHECK_EQ(metadata.generatedMethodsStart, 1);
    CHECK_EQ(metadata.generatedMethodTypeInfos.size(), 1);
    CHECK_EQ(metadata.generatedMethodTypeInfos[0].typeIndex, 0);
    CHECK_EQ(metadata.generatedMethodTypeInfos[0].generatedMethodStart, 1);
    CHECK_EQ(metadata.generatedMethodTypeInfos[0].generatedMethodCount, 2);
    CHECK_EQ(metadata.generatedMethodTokens.size(), 2);
    CHECK_EQ(metadata.generatedMethodTokens[0].token, 0x0600012A);
    CHECK_EQ(metadata.generatedMethodTokens[1].token, 0x0600012B);
    CHECK_EQ(metadata.types.size(), 1);
    CHECK_EQ(metadata.types[0].token, 0x02000001);
    CHECK_EQ(metadata.types[0].fields[0].token, 0x04000001);
    CHECK_EQ(metadata.types[0].methods.size(), 3);
    CHECK_EQ(metadata.types[0].methods[0].name, "Run");
    CHECK_EQ(metadata.types[0].methods[0].definitionIndex, 0);
    CHECK_EQ(metadata.types[0].methods[0].token, 0x06000001);
    CHECK_EQ(metadata.types[0].methods[1].name, "GeneratedA");
    CHECK_EQ(metadata.types[0].methods[1].definitionIndex, 1);
    CHECK_EQ(metadata.types[0].methods[1].token, 0x0600012A);
    CHECK_EQ(metadata.types[0].methods[2].name, "GeneratedB");
    CHECK_EQ(metadata.types[0].methods[2].definitionIndex, 2);
    CHECK_EQ(metadata.types[0].methods[2].token, 0x0600012B);
}

TEST_CASE("v111 applies signature blobs to methods and parameters") {
    const auto fixture = makeSignatureFixture();
    CHECK_EQ(fixture.layout(Section::Methods).size, 34);
    CHECK_EQ(fixture.layout(Section::Parameters).size, 12);
    CHECK_EQ(fixture.layout(Section::MethodSignatures).size, 7);
    const auto metadata = read(fixture);
    CHECK_EQ(metadata.methodSignatures.size(), 2);
    CHECK_EQ(metadata.methodSignatures[0].signatureOffset, 0);
    CHECK_EQ(metadata.methodSignatures[0].returnTypeIndex, 7);
    CHECK_EQ(metadata.methodSignatures[0].parameterTypeIndices.size(), 2);
    CHECK_EQ(metadata.methodSignatures[0].parameterTypeIndices[0], 8);
    CHECK_EQ(metadata.methodSignatures[0].parameterTypeIndices[1], 9);
    CHECK_EQ(metadata.methodSignatures[1].signatureOffset, 4);
    CHECK_EQ(metadata.methodSignatures[1].returnTypeIndex, 10);
    CHECK_EQ(metadata.methodSignatures[1].parameterTypeIndices[0], 11);
    CHECK_EQ(metadata.types.size(), 1);
    CHECK_EQ(metadata.types[0].methods.size(), 2);
    const auto& first = metadata.types[0].methods[0];
    CHECK_EQ(first.returnType, "type[7]");
    CHECK_EQ(first.signatureOffset, 0);
    CHECK_EQ(first.parameters.size(), 2);
    CHECK_EQ(first.parameters[0].type, "type[8]");
    CHECK_EQ(first.parameters[1].type, "type[9]");
    const auto& second = metadata.types[0].methods[1];
    CHECK_EQ(second.returnType, "type[10]");
    CHECK_EQ(second.signatureOffset, 4);
    CHECK_EQ(second.parameters.size(), 1);
    CHECK_EQ(second.parameters[0].name, "third");
    CHECK_EQ(second.parameters[0].type, "type[11]");
}

TEST_CASE("modern metadata rejects malformed unresolved signature ranges") {
    const auto valid = makeDefinitionFixture(39);
    const auto offset = valid.layout(Section::UnresolvedParameterRanges).dataOffset;
    auto fixture = valid;
    modern::put32(fixture.bytes, offset, 0xFFFFFFFF);
    expectInvalid(fixture);
    fixture = valid;
    modern::put32(fixture.bytes, offset, 1);
    modern::put32(fixture.bytes, offset + 4, 2);
    expectInvalid(fixture);
    fixture = valid;
    modern::put32(fixture.bytes, offset, 0x7FFFFFFF);
    modern::put32(fixture.bytes, offset + 4, 2);
    expectInvalid(fixture);
}

TEST_CASE("v108 rejects spec and generic mapping indices outside their normalized tables") {
    const auto valid = makeSpecFixture(108);
    auto fixture = valid;
    modern::put32(fixture.bytes, valid.layout(Section::MethodSpecsOnGenericType).dataOffset, 9);
    expectInvalid(fixture);
    fixture = valid;
    fixture.bytes[valid.layout(Section::GenericMethodFunctions).dataOffset] = 9;
    expectInvalid(fixture);
    fixture = valid;
    fixture.bytes[valid.layout(Section::GenericMethodFunctionsWithAdjustor).dataOffset] = 0;
    expectInvalid(fixture);
}

TEST_CASE("v108 rejects invalid static constructor indices and image RGCTX ranges") {
    const auto valid = makeSpecFixture(108);
    auto fixture = valid;
    fixture.bytes[valid.layout(Section::StaticConstructorTypeIndices).dataOffset + 1] = 1;
    expectInvalid(fixture);
    fixture = valid;
    const auto images = valid.layout(Section::Images).dataOffset;
    // The RGCTX start follows the invoker start in the v108 image record.
    modern::put32(fixture.bytes, images + 35, 5);
    expectInvalid(fixture);
}

TEST_CASE("v110 rejects generated method ranges outside methods tokens and declaring types") {
    const auto valid = makeGeneratedFixture();
    const auto offset = valid.layout(Section::GeneratedMethodTypeInfos).dataOffset;
    auto fixture = valid;
    modern::put32(fixture.bytes, offset, 1);
    expectInvalid(fixture);
    fixture = valid;
    modern::put32(fixture.bytes, offset + 4, 2);
    modern::put32(fixture.bytes, offset + 8, 2);
    expectInvalid(fixture);
    fixture = valid;
    modern::put32(fixture.bytes, offset + 8, 4);
    expectInvalid(fixture);
}

TEST_CASE("v111 rejects negative truncated and parameter overflowing signatures") {
    const auto valid = makeSignatureFixture();
    const auto methods = valid.layout(Section::Methods).dataOffset;
    auto fixture = valid;
    modern::put32(fixture.bytes, methods + 13, 0xFFFFFFFF);
    expectInvalid(fixture);
    fixture = valid;
    modern::put32(fixture.bytes, methods + 13, 7);
    expectInvalid(fixture);
    fixture = valid;
    fixture.bytes[valid.layout(Section::MethodSignatures).dataOffset + 1] = 3;
    expectInvalid(fixture);
    fixture = valid;
    fixture.bytes[methods + 5] = 2;
    expectInvalid(fixture);
}

} // namespace
} // namespace il2cpprec::tests
