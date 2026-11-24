#include "TestSupport.hpp"

#include <il2cpprec/Recovery.hpp>
#include <il2cpprec/abi/AbiAdapter.hpp>
#include <il2cpprec/analysis/VirtualDispatch.hpp>
#include <il2cpprec/ida/SourceProfile.hpp>
#include <il2cpprec/metadata/GlobalMetadata.hpp>
#include <il2cpprec/metadata/MetadataRegistration.hpp>
#include <il2cpprec/metadata/MetadataUsage.hpp>
#include <il2cpprec/metadata/MethodResolver.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

namespace il2cpprec::tests {
namespace {

constexpr uint64_t legacyImageBase = 0x10000000;

struct Il2CppMethodDefinition2017 {
    uint32_t nameIndex;
    int32_t declaringType;
    int32_t returnType;
    int32_t parameterStart;
    int32_t customAttributeIndex;
    int32_t genericContainerIndex;
    int32_t methodIndex;
    int32_t invokerIndex;
    int32_t delegateWrapperIndex;
    int32_t rgctxStartIndex;
    int32_t rgctxCount;
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint16_t parameterCount;
};

struct Il2CppTypeDefinition2017 {
    uint32_t nameIndex;
    uint32_t namespaceIndex;
    int32_t customAttributeIndex;
    int32_t byvalTypeIndex;
    int32_t byrefTypeIndex;
    int32_t declaringTypeIndex;
    int32_t parentIndex;
    int32_t elementTypeIndex;
    int32_t rgctxStartIndex;
    int32_t rgctxCount;
    int32_t genericContainerIndex;
    int32_t delegateWrapperFromManagedToNativeIndex;
    int32_t marshalingFunctionsIndex;
    int32_t ccwFunctionIndex;
    int32_t guidIndex;
    uint32_t flags;
    int32_t fieldStart;
    int32_t methodStart;
    int32_t eventStart;
    int32_t propertyStart;
    int32_t nestedTypesStart;
    int32_t interfacesStart;
    int32_t vtableStart;
    int32_t interfaceOffsetsStart;
    uint16_t methodCount;
    uint16_t propertyCount;
    uint16_t fieldCount;
    uint16_t eventCount;
    uint16_t nestedTypeCount;
    uint16_t vtableCount;
    uint16_t interfacesCount;
    uint16_t interfaceOffsetsCount;
    uint32_t bitfield;
    uint32_t token;
};

struct Il2CppFieldDefinition2017 {
    uint32_t nameIndex;
    int32_t typeIndex;
    int32_t customAttributeIndex;
    uint32_t token;
};

struct Il2CppImageDefinition2017 {
    uint32_t nameIndex;
    int32_t assemblyIndex;
    int32_t typeStart;
    uint32_t typeCount;
    int32_t exportedTypeStart;
    uint32_t exportedTypeCount;
    int32_t entryPointIndex;
    uint32_t token;
};

struct Il2CppCodeRegistration2017 {
    int64_t methodPointersCount;
    uint64_t methodPointers;
    int64_t reversePInvokeWrapperCount;
    uint64_t reversePInvokeWrappers;
    int64_t genericMethodPointersCount;
    uint64_t genericMethodPointers;
    int64_t invokerPointersCount;
    uint64_t invokerPointers;
    int64_t customAttributeCount;
    uint64_t customAttributeGenerators;
    int64_t guidCount;
    uint64_t guids;
    int64_t unresolvedVirtualCallCount;
    uint64_t unresolvedVirtualCallPointers;
    uint64_t unresolvedInstanceCallPointers;
    uint64_t unresolvedStaticCallPointers;
    uint64_t interopDataCount;
    uint64_t interopData;
    uint64_t windowsRuntimeFactoryCount;
    uint64_t windowsRuntimeFactoryTable;
    int64_t codeGenModulesCount;
    uint64_t codeGenModules;
};

struct Il2CppMetadataRegistration2017 {
    int64_t genericClassesCount;
    uint64_t genericClasses;
    int64_t genericInstsCount;
    uint64_t genericInsts;
    int64_t genericMethodTableCount;
    uint64_t genericMethodTable;
    int64_t typesCount;
    uint64_t types;
    int64_t methodSpecsCount;
    uint64_t methodSpecs;
    int64_t fieldOffsetsCount;
    uint64_t fieldOffsets;
    int64_t typeDefinitionsSizesCount;
    uint64_t typeDefinitionsSizes;
    uint64_t metadataUsagesCount;
    uint64_t metadataUsages;
};

struct Il2CppGenericMethodFunctionsDefinitions2017 {
    int32_t genericMethodIndex;
    int32_t methodIndex;
    int32_t invokerIndex;
};

struct Il2CppMethodSpec2017 {
    int32_t methodDefinitionIndex;
    int32_t classInstIndex;
    int32_t methodInstIndex;
};

struct Il2CppGenericInst2017 {
    uint64_t typeCount;
    uint64_t typeArguments;
};

struct Il2CppMetadataUsageList2017 {
    uint32_t start;
    uint32_t count;
};

struct Il2CppMetadataUsagePair2017 {
    uint32_t destinationIndex;
    uint32_t encodedSourceIndex;
};

struct VirtualInvokeData2017 {
    uint64_t methodPointer;
    uint64_t methodInfo;
};

struct Il2CppInterfaceOffsetPair2017 {
    uint64_t interfaceType;
    int32_t offset;
    uint32_t padding;
};

static_assert(sizeof(Il2CppMethodDefinition2017) == 56);
static_assert(sizeof(Il2CppTypeDefinition2017) == 120);
static_assert(sizeof(Il2CppFieldDefinition2017) == 16);
static_assert(sizeof(Il2CppImageDefinition2017) == 32);
static_assert(sizeof(Il2CppCodeRegistration2017) == 176);
static_assert(sizeof(Il2CppMetadataRegistration2017) == 128);
static_assert(sizeof(Il2CppGenericMethodFunctionsDefinitions2017) == 12);
static_assert(sizeof(Il2CppMethodSpec2017) == 12);
static_assert(sizeof(Il2CppGenericInst2017) == 16);
static_assert(sizeof(Il2CppMetadataUsageList2017) == 8);
static_assert(sizeof(Il2CppMetadataUsagePair2017) == 8);
static_assert(sizeof(VirtualInvokeData2017) == 16);
static_assert(sizeof(Il2CppInterfaceOffsetPair2017) == 16);

void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    for (size_t index = 0; index < 4; ++index) bytes[offset + index] = static_cast<uint8_t>(value >> (index * 8));
}

void put64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    for (size_t index = 0; index < 8; ++index) bytes[offset + index] = static_cast<uint8_t>(value >> (index * 8));
}

template<typename T>
void putStruct(std::vector<uint8_t>& bytes, size_t offset, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

struct StringTable2017 {
    std::vector<uint8_t> bytes;
    uint32_t add(const std::string& value) {
        const auto index = static_cast<uint32_t>(bytes.size());
        bytes.insert(bytes.end(), value.begin(), value.end());
        bytes.push_back(0);
        return index;
    }
};

std::vector<uint8_t> globalMetadata2017() {
    std::vector<uint8_t> bytes(0x400, 0);
    StringTable2017 strings;
    const auto imageName = strings.add("Assembly-CSharp.dll");
    const auto nameSpace = strings.add("Legacy");
    const auto typeName = strings.add("Sample");
    const auto methodName = strings.add("LegacyMethod");
    const auto firstFieldName = strings.add("first");
    const auto secondFieldName = strings.add("second");
    std::memcpy(bytes.data() + 0x110, strings.bytes.data(), strings.bytes.size());
    const std::string literal = "legacy-string";
    std::memcpy(bytes.data() + 248, literal.data(), literal.size());

    put32(bytes, 0, 0xFAB11BAF);
    put32(bytes, 4, 24);
    put32(bytes, 8, 240);
    put32(bytes, 12, 8);
    put32(bytes, 16, 248);
    put32(bytes, 20, static_cast<uint32_t>(literal.size()));
    put32(bytes, 24, 0x110);
    put32(bytes, 28, static_cast<uint32_t>(strings.bytes.size()));
    put32(bytes, 48, 0x180);
    put32(bytes, 52, sizeof(Il2CppMethodDefinition2017));
    put32(bytes, 88, 0);
    put32(bytes, 92, 0);
    put32(bytes, 96, 0x1C0);
    put32(bytes, 100, 2 * sizeof(Il2CppFieldDefinition2017));
    put32(bytes, 160, 0x200);
    put32(bytes, 164, sizeof(Il2CppTypeDefinition2017));
    put32(bytes, 176, 0x280);
    put32(bytes, 180, sizeof(Il2CppImageDefinition2017));
    put32(bytes, 184, 0x2C0);
    put32(bytes, 188, 72);
    put32(bytes, 192, 0x320);
    put32(bytes, 196, sizeof(Il2CppMetadataUsageList2017));
    put32(bytes, 200, 0x328);
    put32(bytes, 204, 4 * sizeof(Il2CppMetadataUsagePair2017));
    put32(bytes, 240, static_cast<uint32_t>(literal.size()));
    put32(bytes, 244, 0);

    const Il2CppMethodDefinition2017 method{
        methodName, 0, 0, -1, -1, -1, 3, 5, -1, -1, -1,
        0x06000001, 0x0010, 0, 0, 0
    };
    putStruct(bytes, 0x180, method);

    const Il2CppFieldDefinition2017 fields[] = {
        {firstFieldName, 0, -1, 0x04000001},
        {secondFieldName, 0, -1, 0x04000002},
    };
    putStruct(bytes, 0x1C0, fields);

    const Il2CppTypeDefinition2017 type{
        typeName, nameSpace, -1, 0, 0, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, 0, 0, 0, -1, -1, -1, -1, -1, -1,
        1, 0, 2, 0, 0, 0, 0, 0, 0, 0x02000001
    };
    putStruct(bytes, 0x200, type);

    const Il2CppImageDefinition2017 image{imageName, 0, 0, 1, -1, 0, -1, 1};
    putStruct(bytes, 0x280, image);
    const Il2CppMetadataUsageList2017 usageList{0, 4};
    putStruct(bytes, 0x320, usageList);
    const Il2CppMetadataUsagePair2017 usagePairs[] = {
        {4, (1U << 29) | 0},
        {5, (2U << 29) | 0},
        {6, (5U << 29) | 0},
        {7, (6U << 29) | 0},
    };
    putStruct(bytes, 0x328, usagePairs);
    return bytes;
}

BinaryImage legacyBinary() {
    BinaryImage binary;
    binary.architecture = Architecture::X64;
    binary.format = BinaryFormat::ELF;
    binary.imageBase = legacyImageBase;
    binary.bytes = std::make_shared<std::vector<uint8_t>>(0x1000, 0);
    binary.sections.push_back({".text", 0, binary.bytes->size(), 0, binary.bytes->size(), true});
    return binary;
}

void writeRegistrationFixture(BinaryImage& binary) {
    auto& bytes = *binary.bytes;
    const Il2CppCodeRegistration2017 code{
        4, legacyImageBase + 0x400,
        0, 0,
        1, legacyImageBase + 0x420,
        6, legacyImageBase + 0x440,
        0, 0,
        0, 0,
        2, legacyImageBase + 0x480, legacyImageBase + 0x490, legacyImageBase + 0x4A0,
        0, 0,
        0, 0,
        0, 0
    };
    putStruct(bytes, 0x200, code);
    const Il2CppMetadataRegistration2017 registration{
        0, 0,
        2, legacyImageBase + 0x540,
        1, legacyImageBase + 0x500,
        0, 0,
        1, legacyImageBase + 0x510,
        0, 0,
        0, 0,
        8, legacyImageBase + 0x600
    };
    putStruct(bytes, 0x300, registration);
    const Il2CppGenericMethodFunctionsDefinitions2017 genericMethod{0, 0, 5};
    putStruct(bytes, 0x500, genericMethod);
    const Il2CppMethodSpec2017 spec{0, 0, 1};
    putStruct(bytes, 0x510, spec);
    put64(bytes, 0x540, legacyImageBase + 0x560);
    put64(bytes, 0x548, legacyImageBase + 0x580);
    const Il2CppGenericInst2017 classInst{1, legacyImageBase + 0x5A0};
    const Il2CppGenericInst2017 methodInst{1, legacyImageBase + 0x5A8};
    putStruct(bytes, 0x560, classInst);
    putStruct(bytes, 0x580, methodInst);
    put64(bytes, 0x5A0, 0x1111);
    put64(bytes, 0x5A8, 0x2222);
    for (size_t index = 0; index < 4; ++index) {
        put64(bytes, 0x400 + index * 8, legacyImageBase + 0x800 + index * 0x20);
    }
    put64(bytes, 0x420, legacyImageBase + 0x8E0);
    for (size_t index = 0; index < 6; ++index) {
        put64(bytes, 0x440 + index * 8, legacyImageBase + 0x900 + index * 8);
    }
    for (size_t index = 0; index < 8; ++index) {
        put64(bytes, 0x600 + index * 8, legacyImageBase + 0xA00 + index * 0x20);
    }
}

MetadataModel metadata2017() {
    return GlobalMetadata{}.read(globalMetadata2017());
}

MetadataModel dispatchMetadata() {
    MetadataModel metadata;
    metadata.version = 24.0;
    TypeModel type;
    type.nameSpace = "Legacy";
    type.name = "Sample";
    MethodModel method;
    method.token = 0x06000001;
    method.definitionIndex = 0;
    method.address = 0x900;
    method.imageName = "Assembly-CSharp.dll";
    method.declaringType = "Legacy.Sample";
    method.name = "LegacyMethod";
    type.methods.push_back(method);
    metadata.types.push_back(type);
    return metadata;
}

BinaryImage dispatchBinary() {
    BinaryImage binary;
    binary.architecture = Architecture::Arm64;
    binary.format = BinaryFormat::ELF;
    binary.imageBase = 0;
    binary.bytes = std::make_shared<std::vector<uint8_t>>(0x1000, 0);
    binary.sections.push_back({".text", 0, binary.bytes->size(), 0, binary.bytes->size(), true});
    auto& bytes = *binary.bytes;
    put64(bytes, 0xB00, 0xC00);
    put64(bytes, 0xC98, 0xE80);
    bytes[0xD02] = 1;
    const Il2CppInterfaceOffsetPair2017 interfaceOffset{0xE00, 64, 0};
    putStruct(bytes, 0xE80, interfaceOffset);
    const VirtualInvokeData2017 interfaceInvoke{0x900, 0x910};
    putStruct(bytes, 0xC60, interfaceInvoke);
    const VirtualInvokeData2017 virtualInvoke{0x900, 0x910};
    putStruct(bytes, 0xD40, virtualInvoke);
    return binary;
}

RecoveredFunction recoverDispatch(const std::vector<uint8_t>& code, const std::string& name) {
    return Recovery{}.recover({Architecture::Arm64, 0x1000, code.data(), code.size(), name});
}

} // namespace

TEST_CASE("IL2CPP 2017.4 global metadata reads real v24 definitions") {
    const auto metadata = metadata2017();
    CHECK(metadata.version == 24.0);
    CHECK_EQ(metadata.types.size(), 1);
    const auto& type = metadata.types[0];
    CHECK_EQ(type.nameSpace, "Legacy");
    CHECK_EQ(type.name, "Sample");
    CHECK_EQ(type.fields.size(), 2);
    CHECK_EQ(type.fields[0].name, "first");
    CHECK_EQ(type.fields[0].token, 0x04000001);
    CHECK_EQ(type.fields[1].name, "second");
    CHECK_EQ(type.fields[1].token, 0x04000002);
    CHECK_EQ(type.methods.size(), 1);
    const auto& method = type.methods[0];
    CHECK_EQ(method.name, "LegacyMethod");
    CHECK_EQ(method.imageName, "Assembly-CSharp.dll");
    CHECK_EQ(method.definitionIndex, 0);
    CHECK_EQ(method.methodIndex, 3);
    CHECK_EQ(method.token, 0x06000001);
    CHECK(method.isStatic);
}

TEST_CASE("IL2CPP 2017.4 resolver maps methodIndex through global method pointers") {
    auto metadata = metadata2017();
    auto binary = legacyBinary();
    metadata.methodPointersByImage["Assembly-CSharp.dll"] = {
        legacyImageBase + 0x20, legacyImageBase + 0x30, legacyImageBase + 0x40,
        legacyImageBase + 0x80, legacyImageBase + 0x90
    };
    const auto result = MethodResolver({false, 64}).resolveWithReport(metadata, binary);
    CHECK_EQ(result.report.totalMethods, 1);
    CHECK_EQ(result.report.resolvedMethods, 1);
    CHECK(result.report.unresolved.empty());
    CHECK_EQ(result.functions.size(), 1);
    CHECK_EQ(result.functions[0].address, legacyImageBase + 0x80);
    CHECK_EQ(result.functions[0].size, 64);
    CHECK(result.functions[0].code == binary.bytes->data() + 0x80);

    metadata.types[0].methods[0].methodIndex = 9;
    const auto invalid = MethodResolver({false, 64}).resolveWithReport(metadata, binary);
    CHECK(invalid.functions.empty());
    CHECK_EQ(invalid.report.unresolved.size(), 1);
    CHECK(invalid.report.unresolved[0].error == MethodResolutionError::PointerIndexOutOfRange);
    CHECK(invalid.report.unresolved[0].pointerIndex.has_value());
    CHECK_EQ(*invalid.report.unresolved[0].pointerIndex, 9);

    metadata.types[0].methods[0].methodIndex = -1;
    const auto missing = MethodResolver({false, 64}).resolveWithReport(metadata, binary);
    CHECK(missing.functions.empty());
    CHECK(missing.report.unresolved.empty());
    CHECK_EQ(missing.report.declarationOnly, 1);
    CHECK_EQ(missing.report.declarations.size(), 1);
    CHECK(missing.report.declarations[0].reason == DeclarationOnlyReason::ExpectedNoNativeBody);
    CHECK_EQ(missing.report.declarations[0].methodIndex, -1);
}

TEST_CASE("IL2CPP 2017.4 registration reads per-type field offsets") {
    auto metadata = metadata2017();
    auto binary = legacyBinary();
    put64(*binary.bytes, 0x100, legacyImageBase + 0x180);
    put64(*binary.bytes, 0x108, legacyImageBase + 0x190);
    put32(*binary.bytes, 0x180, 24);
    put32(*binary.bytes, 0x184, 28);

    const MetadataRegistrationInfo registration{
        legacyImageBase + 0x300,
        legacyImageBase + 0x200,
        0, 0,
        legacyImageBase + 0x100, 2
    };
    MetadataRegistrationReader{}.read(binary, metadata, registration);
    CHECK_EQ(metadata.types[0].fields[0].offset, 24);
    CHECK_EQ(metadata.types[0].fields[1].offset, 28);
    CHECK_EQ(metadata.fieldOffsetsByToken.at(0x04000001), 24);
    CHECK_EQ(metadata.fieldOffsetsByToken.at(0x04000002), 28);
    CHECK_EQ(metadata.metadataRegistrationAddress, legacyImageBase + 0x300);
    CHECK_EQ(metadata.codeRegistrationAddress, legacyImageBase + 0x200);

    put64(*binary.bytes, 0x100, legacyImageBase + binary.bytes->size() - 4);
    CHECK_THROWS(MetadataRegistrationReader{}.read(binary, metadata, registration), "outside the binary image");
}

TEST_CASE("IL2CPP 2017.4 MetadataUsage decodes kinds destinations and strings") {
    const auto metadata = metadata2017();
    CHECK_EQ(metadata.stringLiterals.at(0), "legacy-string");
    CHECK_EQ(metadata.metadataUsageLists.size(), 1);
    CHECK_EQ(metadata.metadataUsageLists[0].start, 0);
    CHECK_EQ(metadata.metadataUsageLists[0].count, 4);
    CHECK_EQ(metadata.metadataUsagePairs.size(), 4);
    const uint32_t kinds[] = {1, 2, 5, 6};
    for (size_t index = 0; index < metadata.metadataUsagePairs.size(); ++index) {
        const auto& pair = metadata.metadataUsagePairs[index];
        CHECK_EQ(pair.kind, kinds[index]);
        CHECK_EQ(pair.destinationIndex, 4 + index);
        CHECK_EQ(pair.encodedSourceIndex, (kinds[index] << 29));
        CHECK_EQ(pair.decodedIndex, 0);
    }
    CHECK_EQ(metadata.metadataUsagePairs[2].kind, 5);
    CHECK_EQ(metadata.stringLiterals.at(metadata.metadataUsagePairs[2].decodedIndex), "legacy-string");
}

TEST_CASE("IL2CPP 2017.4 global registrations decode generic methods and specs") {
    auto metadata = metadata2017();
    auto binary = legacyBinary();
    writeRegistrationFixture(binary);
    MetadataRegistrationReader{}.read(
        binary, metadata, legacyImageBase + 0x300, legacyImageBase + 0x200);

    CHECK_EQ(metadata.metadataRegistrationAddress, legacyImageBase + 0x300);
    CHECK_EQ(metadata.codeRegistrationAddress, legacyImageBase + 0x200);
    const auto& methods = metadata.methodPointersByImage.at("Assembly-CSharp.dll");
    CHECK_EQ(methods.size(), 4);
    CHECK_EQ(methods[3], legacyImageBase + 0x860);
    CHECK_EQ(metadata.genericMethodPointers.size(), 1);
    CHECK_EQ(metadata.genericMethodPointers[0], legacyImageBase + 0x8E0);
    CHECK_EQ(metadata.invokerPointers.size(), 6);
    CHECK_EQ(metadata.invokerPointers[5], legacyImageBase + 0x928);
    CHECK_EQ(metadata.genericInsts.size(), 2);
    CHECK_EQ(metadata.genericInsts[0].address, legacyImageBase + 0x560);
    CHECK_EQ(metadata.genericInsts[0].typeAddresses.size(), 1);
    CHECK_EQ(metadata.genericInsts[0].typeAddresses[0], 0x1111);
    CHECK_EQ(metadata.genericInsts[1].address, legacyImageBase + 0x580);
    CHECK_EQ(metadata.genericInsts[1].typeAddresses.size(), 1);
    CHECK_EQ(metadata.genericInsts[1].typeAddresses[0], 0x2222);
    CHECK_EQ(metadata.methodSpecs.size(), 1);
    CHECK_EQ(metadata.methodSpecs[0].methodDefinitionIndex, 0);
    CHECK_EQ(metadata.methodSpecs[0].classInstIndex, 0);
    CHECK_EQ(metadata.methodSpecs[0].methodInstIndex, 1);
    CHECK_EQ(metadata.methodSpecs[0].classInstAddress, legacyImageBase + 0x560);
    CHECK_EQ(metadata.methodSpecs[0].methodInstAddress, legacyImageBase + 0x580);
    CHECK_EQ(metadata.genericMethodTable.size(), 1);
    const auto& generic = metadata.genericMethodTable[0];
    CHECK_EQ(generic.genericMethodIndex, 0);
    CHECK_EQ(generic.methodIndex, 0);
    CHECK_EQ(generic.invokerIndex, 5);
    CHECK_EQ(generic.classInstAddress, legacyImageBase + 0x560);
    CHECK_EQ(generic.methodInstAddress, legacyImageBase + 0x580);
    CHECK_EQ(generic.methodPointer, legacyImageBase + 0x8E0);
    CHECK_EQ(generic.invokerPointer, legacyImageBase + 0x928);
    CHECK_EQ(metadata.metadataUsagesCount, 8);
}

TEST_CASE("IL2CPP 2017.4 MetadataUsage reader resolves literal entries") {
    const auto metadata = metadata2017();
    const auto result = MetadataUsageReader{}.readUnity2017(globalMetadata2017(), &metadata);
    CHECK(result.tablesValid);
    CHECK_EQ(result.lists.size(), 1);
    CHECK_EQ(result.pairs.size(), 4);
    CHECK_EQ(result.entries.size(), 4);
    CHECK_EQ(result.referencedPairCount, 4);
    CHECK_EQ(result.unreferencedPairCount, 0);
    const auto& literal = result.entries[2];
    CHECK(literal.kind == MetadataUsageKind::StringLiteral);
    CHECK(literal.status == MetadataUsageStatus::Resolved);
    CHECK_EQ(literal.destinationIndex, 6);
    CHECK_EQ(literal.sourceIndex, 0);
    CHECK(literal.stringLiteral.has_value());
    CHECK_EQ(*literal.stringLiteral, "legacy-string");
    CHECK_EQ(literal.listIndices.size(), 1);
    CHECK_EQ(literal.listIndices[0], 0);
}

TEST_CASE("IL2CPP 2017.4 MetadataUsage rejects invalid list and table ranges") {
    auto bytes = globalMetadata2017();
    put32(bytes, 0x324, 5);
    const auto invalidList = MetadataUsageReader{}.readUnity2017(bytes, nullptr);
    CHECK(!invalidList.tablesValid);
    CHECK(invalidList.entries.empty());
    CHECK_EQ(invalidList.diagnostics.size(), 1);
    CHECK_EQ(invalidList.diagnostics[0].code, "metadata-usage-list-range-out-of-bounds");
    CHECK(invalidList.diagnostics[0].listIndex.has_value());
    CHECK_EQ(*invalidList.diagnostics[0].listIndex, 0);

    bytes = globalMetadata2017();
    put32(bytes, 204, 7);
    const auto misaligned = MetadataUsageReader{}.readUnity2017(bytes, nullptr);
    CHECK(!misaligned.tablesValid);
    CHECK_EQ(misaligned.diagnostics.size(), 1);
    CHECK_EQ(misaligned.diagnostics[0].code, "misaligned-table-size");

    bytes = globalMetadata2017();
    put32(bytes, 204, 0xFFFFFFFF);
    const auto negative = MetadataUsageReader{}.readUnity2017(bytes, nullptr);
    CHECK(!negative.tablesValid);
    CHECK_EQ(negative.diagnostics.size(), 1);
    CHECK_EQ(negative.diagnostics[0].code, "negative-table-size");
}

TEST_CASE("IL2CPP 2017.4 generic registration rejects invalid spec ranges") {
    auto metadata = metadata2017();
    auto binary = legacyBinary();
    writeRegistrationFixture(binary);
    put32(*binary.bytes, 0x500, 1);
    CHECK_THROWS(
        MetadataRegistrationReader{}.read(binary, metadata, legacyImageBase + 0x300, legacyImageBase + 0x200),
        "generic method table index is outside the method spec table");
}

TEST_CASE("IL2CPP 2017.4 value type layout excludes the object header") {
    auto metadata = metadata2017();
    auto binary = legacyBinary();
    put64(*binary.bytes, 0x100, legacyImageBase + 0x180);
    put32(*binary.bytes, 0x180, 24);
    put32(*binary.bytes, 0x184, 28);
    const MetadataRegistrationInfo registration{0, 0, 0, 0, legacyImageBase + 0x100, 1};
    MetadataRegistrationReader{}.read(binary, metadata, registration);

    TypeLayoutInfo layout;
    layout.instanceSize = 40;
    layout.actualInstanceSize = 40;
    layout.minimumAlignment = 8;
    layout.naturalAlignment = 8;
    layout.valueType = true;
    layout.fieldOffsets = {24, 28};
    const auto object64 = TypeSystem::objectLayout(
        metadata.types[0], layout, TypeLayoutContext{8, &metadata, nullptr});
    CHECK(object64.valueType);
    CHECK_EQ(object64.instanceSize, 40);
    CHECK_EQ(object64.actualInstanceSize, 40);
    CHECK_EQ(object64.valueSize, 24);
    CHECK_EQ(object64.instanceFields.size(), 2);
    CHECK_EQ(object64.instanceFields[0].field.offset, 24);
    CHECK_EQ(object64.instanceFields[1].field.offset, 28);

    const auto object32 = TypeSystem::objectLayout(
        metadata.types[0], layout, TypeLayoutContext{4, &metadata, nullptr});
    CHECK_EQ(object32.valueSize, 32);
}

TEST_CASE("IL2CPP 2017.4 virtual call resolves VirtualInvokeData") {
    std::vector<uint8_t> code(20, 0);
    put32(code, 0, 0xD2816000);
    put32(code, 4, 0xF9400008);
    put32(code, 8, 0xF940A108);
    put32(code, 12, 0xD63F0100);
    put32(code, 16, 0xD65F03C0);
    auto binary = dispatchBinary();
    VirtualDispatchOptions options;
    options.binary = &binary;
    const auto result = VirtualDispatch{}.analyze(
        recoverDispatch(code, "VirtualCall"), dispatchMetadata(), options);
    if (result.operations.empty()) fail(serializeFunction(result.native), __FILE__, __LINE__);
    CHECK_EQ(result.operations.size(), 1);
    const auto& call = result.operations[0];
    CHECK(call.kind == VirtualDispatchKind::Virtual);
    CHECK(call.status == ManagedPatternStatus::Resolved);
    CHECK(call.confidence == ManagedPatternConfidence::High);
    CHECK(call.slot.has_value());
    CHECK_EQ(*call.slot, 3);
    CHECK_EQ(call.vtableOffset, 320);
    CHECK_EQ(call.klassAddress, 0xC00);
    CHECK_EQ(call.invokeDataAddress, 0xD40);
    CHECK(call.hasMethodPointer);
    CHECK(call.hasMethodInfo);
    CHECK_EQ(call.invokeData.methodPointer, 0x900);
    CHECK_EQ(call.invokeData.methodInfo, 0x910);
    CHECK_EQ(call.method.name, "LegacyMethod");
    CHECK_EQ(call.method.address, 0x900);
}

TEST_CASE("IL2CPP 2017.4 interface call resolves interface offset and target") {
    std::vector<uint8_t> code(20, 0);
    put32(code, 0, 0xD2800040);
    put32(code, 4, 0xD281C001);
    put32(code, 8, 0xD2816002);
    put32(code, 12, 0x97FFFC3D);
    put32(code, 16, 0xD65F03C0);
    auto binary = dispatchBinary();
    VirtualDispatchOptions options;
    options.binary = &binary;
    options.interfaceHelperAddresses = {0x100};
    const auto result = VirtualDispatch{}.analyze(
        recoverDispatch(code, "InterfaceCall"), dispatchMetadata(), options);
    CHECK_EQ(result.operations.size(), 1);
    const auto& call = result.operations[0];
    CHECK(call.kind == VirtualDispatchKind::Interface);
    CHECK(call.status == ManagedPatternStatus::Resolved);
    CHECK(call.slot.has_value());
    CHECK_EQ(*call.slot, 2);
    CHECK_EQ(call.interfaceAddress, 0xE00);
    CHECK(call.hasInterfaceOffset);
    CHECK_EQ(call.interfaceOffset, 64);
    CHECK_EQ(call.klassAddress, 0xC00);
    CHECK_EQ(call.invokeDataAddress, 0xC60);
    CHECK_EQ(call.invokeData.methodPointer, 0x900);
    CHECK_EQ(call.method.name, "LegacyMethod");
    CHECK_EQ(call.method.address, 0x900);
}

TEST_CASE("ABI resolves generic reference types without erasing generic parameters") {
    MetadataModel metadata;
    TypeModel enumerator;
    enumerator.nameSpace = "System.Collections.Generic";
    enumerator.name = "IEnumerator`1";
    enumerator.baseType = "System.Object";
    metadata.types.push_back(enumerator);
    TypeModel nullable;
    nullable.nameSpace = "System";
    nullable.name = "Nullable`1";
    nullable.baseType = "System.ValueType";
    metadata.types.push_back(nullable);

    TypeReferenceModel reference;
    reference.code = static_cast<uint8_t>(Il2CppTypeCode::GenericInst);
    reference.definitionIndex = 0;
    metadata.typeReferences.push_back(reference);
    reference = {};
    reference.code = static_cast<uint8_t>(Il2CppTypeCode::Var);
    reference.definitionIndex = 0;
    reference.name = "T";
    metadata.typeReferences.push_back(reference);
    reference = {};
    reference.code = static_cast<uint8_t>(Il2CppTypeCode::GenericInst);
    reference.definitionIndex = 1;
    metadata.typeReferences.push_back(reference);

    MethodModel method;
    method.isStatic = true;
    method.returnType = "type[0]";
    method.parameters = {{"current", "type[0]"}};
    const auto model = AbiAdapter{}.bind(method, metadata, Architecture::Arm64);
    CHECK(model.supported());
    CHECK_EQ(model.bindings.size(), 2);
    CHECK(model.bindings[0].valueKind == AbiValueKind::ObjectReference);
    CHECK(model.bindings[0].conversion == AbiConversion::ObjectToNativePointer);
    CHECK(model.bindings[1].role == AbiValueRole::MethodInfo);
    CHECK(model.returnValue.conversion == AbiConversion::NativePointerToObject);

    method.returnType = "System.Collections.Generic.IEnumerator<object>";
    CHECK(AbiAdapter{}.bind(method, metadata, Architecture::Arm64).supported());

    method.returnType = "type[1]";
    const auto generic = AbiAdapter{}.bind(method, metadata, Architecture::Arm64);
    CHECK(!generic.supported());
    CHECK(generic.returnValue.genericParameter.has_value());
    CHECK(!generic.diagnostics.empty());
    CHECK(generic.diagnostics.back().code == AbiDiagnosticCode::UnresolvedGenericType);

    method.returnType = "type[2]";
    const auto valueType = AbiAdapter{}.bind(method, metadata, Architecture::Arm64);
    CHECK(!valueType.supported());
    CHECK(valueType.returnValue.valueKind == AbiValueKind::Unsupported);
}

void checkAbiExpressionScalars(const ExpressionPtr& expression) {
    if (!expression) return;
    CHECK(expression->type.kind != ScalarKind::Vector);
    if (expression->kind == Expression::Kind::Load) CHECK(expression->type.bits != 0);
    for (const auto& argument : expression->arguments) checkAbiExpressionScalars(argument);
}

void checkAbiStatementScalars(const Statement& statement) {
    checkAbiExpressionScalars(statement.destination);
    checkAbiExpressionScalars(statement.value);
    checkAbiExpressionScalars(statement.condition);
    checkAbiExpressionScalars(statement.target);
    for (const auto& argument : statement.arguments) checkAbiExpressionScalars(argument);
}

void checkAbiModelScalars(const AbiBindingModel& model) {
    for (const auto& statement : model.statements) checkAbiStatementScalars(statement);
    for (const auto& statement : AbiAdapter{}.returnStatements(model)) checkAbiStatementScalars(statement);
}

TEST_CASE("ABI uses scalar register views for arguments and 32/64 returns") {
    MetadataModel metadata;
    MethodModel method;
    method.isStatic = true;
    method.returnType = "double";
    method.parameters = {{"a", "int"}, {"b", "float"}, {"c", "double"}, {"d", "long"}};

    const auto arm64 = AbiAdapter{}.bind(method, metadata, Architecture::Arm64);
    CHECK(arm64.supported());
    CHECK(arm64.bindings[0].registerView.has_value());
    CHECK_EQ(arm64.bindings[0].registerView->viewName, "w0");
    CHECK_EQ(arm64.bindings[1].registerView->viewName, "s0");
    CHECK_EQ(arm64.bindings[2].registerView->viewName, "d1");
    CHECK(!arm64.bindings[3].registerView.has_value());
    CHECK(arm64.bindings[4].role == AbiValueRole::MethodInfo);
    CHECK_EQ(arm64.bindings[4].location.registerName, "x2");
    CHECK_EQ(arm64.returnValue.registerView->viewName, "d0");
    checkAbiModelScalars(arm64);

    const auto x64 = AbiAdapter{}.bind(method, metadata, Architecture::X64);
    CHECK(x64.supported());
    CHECK_EQ(x64.bindings[0].registerView->viewName, "ecx");
    CHECK_EQ(x64.bindings[1].registerView->viewName, "xmm1_f32");
    CHECK_EQ(x64.bindings[2].registerView->viewName, "xmm2_f64");
    CHECK(!x64.bindings[3].registerView.has_value());
    CHECK(x64.bindings[4].role == AbiValueRole::MethodInfo);
    CHECK_EQ(x64.returnValue.registerView->viewName, "xmm0_f64");
    checkAbiModelScalars(x64);

    method.parameters.clear();
    method.returnType = "int";
    const auto arm64Int = AbiAdapter{}.bind(method, metadata, Architecture::Arm64);
    const auto x64Int = AbiAdapter{}.bind(method, metadata, Architecture::X64);
    const auto arm32Int = AbiAdapter{}.bind(method, metadata, Architecture::Arm32);
    const auto x86Int = AbiAdapter{}.bind(method, metadata, Architecture::X86);
    CHECK_EQ(arm64Int.returnValue.registerView->viewName, "w0");
    CHECK_EQ(x64Int.returnValue.registerView->viewName, "eax");
    CHECK_EQ(arm32Int.returnValue.location.registerName, "r0");
    CHECK_EQ(x86Int.returnValue.location.registerName, "eax");
    CHECK_EQ(arm32Int.returnValue.scalarType.bits, 32);
    CHECK_EQ(x86Int.returnValue.scalarType.bits, 32);
    CHECK(arm32Int.bindings.back().role == AbiValueRole::MethodInfo);
    CHECK(x86Int.bindings.back().role == AbiValueRole::MethodInfo);

    method.returnType = "long";
    const auto arm64Long = AbiAdapter{}.bind(method, metadata, Architecture::Arm64);
    const auto x64Long = AbiAdapter{}.bind(method, metadata, Architecture::X64);
    const auto arm32Long = AbiAdapter{}.bind(method, metadata, Architecture::Arm32);
    const auto x86Long = AbiAdapter{}.bind(method, metadata, Architecture::X86);
    CHECK_EQ(arm64Long.returnValue.location.registerName, "x0");
    CHECK_EQ(x64Long.returnValue.location.registerName, "rax");
    CHECK(arm32Long.returnValue.location.kind == AbiLocationKind::RegisterPair);
    CHECK_EQ(arm32Long.returnValue.location.registerName, "r0");
    CHECK_EQ(arm32Long.returnValue.location.secondRegisterName, "r1");
    CHECK(x86Long.returnValue.location.kind == AbiLocationKind::RegisterPair);
    CHECK_EQ(x86Long.returnValue.location.registerName, "eax");
    CHECK_EQ(x86Long.returnValue.location.secondRegisterName, "edx");
    checkAbiModelScalars(arm64Long);
    checkAbiModelScalars(x64Long);
    checkAbiModelScalars(arm32Long);
    checkAbiModelScalars(x86Long);

    method.returnType = "void";
    for (size_t index = 0; index < 10; ++index) {
        method.parameters.push_back({"p" + std::to_string(index), "int"});
    }
    const auto stackModel = AbiAdapter{}.bind(method, metadata, Architecture::Arm64);
    CHECK(stackModel.supported());
    checkAbiModelScalars(stackModel);
}

TEST_CASE("ABI runtime profiles select invoker and MethodInfo pointer layouts") {
    MetadataModel metadata;
    MethodModel method;
    method.isStatic = true;
    method.returnType = "int";
    CallSiteAbiSpec invokerSpec;
    invokerSpec.kind = CallSiteKind::Invoker;

    metadata.version = 23;
    const auto legacy = AbiAdapter{}.bindCallSite(method, metadata, Architecture::Arm64, invokerSpec);
    CHECK(legacy.supported());
    CHECK(legacy.runtimeProfile.invoker == AbiInvokerSignature::LegacyThreeArguments);
    CHECK_EQ(legacy.signature.bindings.size(), 3);
    CHECK(legacy.signature.bindings[0].role == AbiValueRole::MethodInfo);
    CHECK(legacy.signature.bindings[1].role == AbiValueRole::Instance);
    CHECK(legacy.signature.bindings[2].role == AbiValueRole::Parameters);
    CHECK_EQ(legacy.signature.bindings[0].location.registerName, "x0");
    CHECK_EQ(legacy.signature.bindings[2].location.registerName, "x2");

    metadata.version = 24.1;
    const auto criticalOps = AbiAdapter{}.bindCallSite(method, metadata, Architecture::Arm64, invokerSpec);
    CHECK(criticalOps.supported());
    CHECK(criticalOps.runtimeProfile.invoker == AbiInvokerSignature::FourArguments);
    CHECK_EQ(criticalOps.signature.bindings.size(), 4);
    CHECK(criticalOps.signature.bindings[0].role == AbiValueRole::MethodPointer);
    CHECK_EQ(criticalOps.signature.bindings[0].location.registerName, "x0");
    CHECK_EQ(criticalOps.signature.bindings[3].location.registerName, "x3");

    metadata.version = 29;
    invokerSpec.invokerContext = reg("context", ScalarType::pointer(64));
    const auto modern = AbiAdapter{}.bindCallSite(method, metadata, Architecture::Arm64, invokerSpec);
    CHECK(modern.supported());
    CHECK(modern.runtimeProfile.invoker == AbiInvokerSignature::FiveArguments);
    CHECK_EQ(modern.signature.bindings.size(), 5);
    CHECK(modern.signature.bindings[4].role == AbiValueRole::InvokerContext);
    CHECK_EQ(modern.signature.bindings[4].location.registerName, "x4");
    CHECK(modern.invokerContext->name == "context");

    MethodModel virtualMethod;
    virtualMethod.returnType = "void";
    CallSiteAbiSpec virtualSpec;
    virtualSpec.kind = CallSiteKind::Virtual;
    virtualSpec.methodPointer = reg("direct_pointer", ScalarType::pointer(64));
    virtualSpec.virtualMethodPointer = reg("virtual_pointer", ScalarType::pointer(64));
    metadata.version = 27.1;
    const auto virtualModern = AbiAdapter{}.bindCallSite(virtualMethod, metadata, Architecture::Arm64, virtualSpec);
    CHECK(virtualModern.supported());
    CHECK(virtualModern.target->name == "virtual_pointer");
    CHECK(virtualModern.runtimeProfile.methodInfoPointers == AbiMethodInfoPointerLayout::MethodAndVirtualMethodPointer);

    metadata.version = 24.1;
    const auto virtualLegacy = AbiAdapter{}.bindCallSite(virtualMethod, metadata, Architecture::Arm64, virtualSpec);
    CHECK(!virtualLegacy.supported());
    CHECK(virtualLegacy.target->name == "direct_pointer");
    CHECK(!virtualLegacy.diagnostics.empty());
    CHECK(virtualLegacy.diagnostics[0].code == AbiDiagnosticCode::ProfileConflict);

    const auto selection = ida::unity2017_4_11f1Profile().resolve(24.1, 8);
    const auto sourceDriven = AbiRuntimeProfile::fromSourceLayout(selection);
    CHECK(sourceDriven.invoker == AbiInvokerSignature::FourArguments);
    CHECK(sourceDriven.adjustorThunks);
}

TEST_CASE("ABI profiles handle adjustor thunks reduced signatures and target conventions") {
    MetadataModel metadata;
    metadata.version = 24.1;
    MethodModel method;
    method.returnType = "int";
    method.parameters = {{"a", "int"}, {"b", "float"}};

    CallSiteAbiSpec adjustorSpec;
    adjustorSpec.kind = CallSiteKind::GenericInstance;
    adjustorSpec.methodPointer = reg("method_pointer", ScalarType::pointer(64));
    adjustorSpec.adjustorThunk = reg("thunk", ScalarType::pointer(64));
    adjustorSpec.adjustorThunkThis = reg("this_pointer", ScalarType::pointer(64));
    adjustorSpec.adjustorThunkThisOffset = -16;
    const auto adjustor = AbiAdapter{}.bindCallSite(method, metadata, Architecture::Arm64, adjustorSpec);
    CHECK(adjustor.supported());
    CHECK(adjustor.targetKind == CallTargetKind::AdjustorThunk);
    CHECK(adjustor.target->name == "thunk");
    CHECK(adjustor.adjustorThunk.present);
    CHECK_EQ(adjustor.adjustorThunk.thisOffset, -16);
    CHECK(adjustor.adjustorThunk.methodPointer->name == "method_pointer");
    CHECK(adjustor.genericContext.present);

    metadata.version = 23;
    const auto noThunks = AbiAdapter{}.bindCallSite(method, metadata, Architecture::Arm64, adjustorSpec);
    CHECK(!noThunks.supported());
    CHECK(!noThunks.diagnostics.empty());
    CHECK(noThunks.diagnostics[0].code == AbiDiagnosticCode::ProfileConflict);

    CallSiteAbiSpec unresolvedSpec;
    unresolvedSpec.kind = CallSiteKind::Unresolved;
    const auto reduced = AbiAdapter{}.bindCallSite(method, metadata, Architecture::Arm64, unresolvedSpec);
    CHECK(reduced.supported());
    CHECK(reduced.signature.reducedSignature);
    CHECK_EQ(reduced.signature.omittedParameterCount, 2);
    CHECK_EQ(reduced.signature.bindings.size(), 2);
    CHECK(reduced.signature.returnValue.valueKind == AbiValueKind::Unknown);
    CHECK_EQ(AbiAdapter{}.returnStatements(reduced.signature).size(), 1);

    metadata.version = 24.1;
    const auto fullOnly = AbiAdapter{}.bindCallSite(method, metadata, Architecture::Arm64, unresolvedSpec);
    CHECK(!fullOnly.supported());
    CHECK(fullOnly.signature.returnValue.valueKind == AbiValueKind::Unsupported);

    method.isStatic = true;
    method.returnType = "void";
    CallSiteAbiSpec targetSpec;
    targetSpec.kind = CallSiteKind::GeneratedDirect;
    targetSpec.x64 = X64CallingConvention::SystemV;
    const auto systemV = AbiAdapter{}.bindCallSite(method, metadata, Architecture::X64, targetSpec);
    CHECK(systemV.supported());
    CHECK_EQ(systemV.signature.bindings[0].location.registerName, "rdi");
    CHECK_EQ(systemV.signature.bindings[1].location.registerName, "xmm0");
    CHECK(systemV.targetOptions.x64 == X64CallingConvention::SystemV);

    targetSpec.x86 = X86CallingConvention::StdCall;
    const auto stdCall = AbiAdapter{}.bindCallSite(method, metadata, Architecture::X86, targetSpec);
    CHECK(stdCall.supported());
    CHECK(stdCall.targetOptions.x86 == X86CallingConvention::StdCall);
    CHECK_EQ(stdCall.signature.bindings[0].location.stackOffset, 4);

    targetSpec.arm32Float = Arm32FloatAbi::Soft;
    const auto softFloat = AbiAdapter{}.bindCallSite(method, metadata, Architecture::Arm32, targetSpec);
    CHECK(softFloat.supported());
    CHECK(softFloat.signature.bindings[1].conversion == AbiConversion::RawBitsToFloat);
}

} // namespace il2cpprec::tests
