#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <il2cpprec/Disassembler.hpp>

namespace il2cpprec {

enum class BinaryFormat {
    PE,
    ELF,
    MachO
};

struct Section {
    std::string name;
    uint64_t virtualAddress = 0;
    uint64_t virtualSize = 0;
    uint64_t fileOffset = 0;
    uint64_t fileSize = 0;
    bool executable = false;
};

struct BinaryImage {
    Architecture architecture = Architecture::X64;
    BinaryFormat format = BinaryFormat::PE;
    uint64_t imageBase = 0;
    std::shared_ptr<std::vector<uint8_t>> bytes = std::make_shared<std::vector<uint8_t>>();
    std::vector<Section> sections;

    uint64_t mapVATR(uint64_t virtualAddress) const;
    uint64_t mapRTVA(uint64_t fileOffset) const;
    const uint8_t* data(uint64_t fileOffset, size_t size) const;
};

enum class MetadataVersionConfidence {
    Unknown,
    RawHeader,
    InferredLayout,
    Registration,
    Explicit
};

struct MetadataVersionModel {
    int32_t rawVersion = 0;
    double preciseVersion = 0;
    double registrationVersion = 0;
    MetadataVersionConfidence confidence = MetadataVersionConfidence::Unknown;
    std::string provenance;
};

struct MetadataSectionModel {
    int32_t offset = 0;
    int32_t sectionSize = 0;
    int32_t count = 0;
};

struct MetadataSectionsModel {
    MetadataSectionModel stringLiterals;
    MetadataSectionModel stringLiteralData;
    MetadataSectionModel strings;
    MetadataSectionModel events;
    MetadataSectionModel properties;
    MetadataSectionModel methods;
    MetadataSectionModel methodSignatures;
    MetadataSectionModel parameterDefaultValues;
    MetadataSectionModel fieldDefaultValues;
    MetadataSectionModel defaultValueData;
    MetadataSectionModel fieldMarshaledSizes;
    MetadataSectionModel parameters;
    MetadataSectionModel fields;
    MetadataSectionModel genericParameters;
    MetadataSectionModel genericParameterConstraints;
    MetadataSectionModel genericContainers;
    MetadataSectionModel nestedTypes;
    MetadataSectionModel interfaces;
    MetadataSectionModel vtableMethods;
    MetadataSectionModel interfaceOffsets;
    MetadataSectionModel typeDefinitions;
    MetadataSectionModel typeInlineArrays;
    MetadataSectionModel images;
    MetadataSectionModel assemblies;
    MetadataSectionModel fieldRefs;
    MetadataSectionModel referencedAssemblies;
    MetadataSectionModel attributeData;
    MetadataSectionModel attributeDataRanges;
    MetadataSectionModel unresolvedIndirectCallParameterTypes;
    MetadataSectionModel unresolvedIndirectCallParameterRanges;
    MetadataSectionModel windowsRuntimeTypeNames;
    MetadataSectionModel windowsRuntimeStrings;
    MetadataSectionModel exportedTypeDefinitions;
    MetadataSectionModel methodSpecsOnGenericType;
    MetadataSectionModel genericMethodSpecsOnType;
    MetadataSectionModel methodSpecs;
    MetadataSectionModel genericMethodFunctionsDefinitions;
    MetadataSectionModel genericMethodFunctionsDefinitionsWithAdjustor;
    MetadataSectionModel invokerIndices;
    MetadataSectionModel rgctxRanges;
    MetadataSectionModel rgctxValues;
    MetadataSectionModel staticConstructorTypeIndices;
    MetadataSectionModel generatedMethodTypeInfos;
    MetadataSectionModel generatedMethodTokens;
    MetadataSectionModel metadataUsageLists;
    MetadataSectionModel metadataUsagePairs;
};

struct ParameterModel {
    std::string name;
    std::string type;
    int32_t defaultValueIndex = -1;
};

struct MethodModel {
    uint32_t token = 0;
    int definitionIndex = -1;
    uint64_t address = 0;
    std::string imageName;
    std::string declaringType;
    std::string name;
    std::string returnType;
    std::vector<ParameterModel> parameters;
    bool isStatic = false;
    int methodIndex = -1;
    uint16_t flags = 0;
    uint16_t iflags = 0;
    uint16_t slot = 0;
    int32_t genericContainerIndex = -1;
    uint32_t returnParameterToken = 0;
    int32_t signatureOffset = -1;
};

struct FieldModel {
    std::string name;
    std::string type;
    int64_t offset = 0;
    bool isStatic = false;
    uint32_t token = 0;
    uint32_t flags = 0;
    int32_t defaultValueIndex = -1;
};

struct TypeReferenceModel {
    uint8_t code = 0;
    std::string name;
    int32_t definitionIndex = -1;
    int32_t elementTypeIndex = -1;
    std::vector<int32_t> genericArgumentIndices;
    uint32_t rank = 0;
    bool byRef = false;
    uint16_t attrs = 0;
};

struct TypeModel {
    std::string nameSpace;
    std::string name;
    std::string baseType;
    std::vector<FieldModel> fields;
    std::vector<MethodModel> methods;
    std::string imageName;
    int32_t declaringTypeIndex = -1;
    int32_t genericContainerIndex = -1;
    uint32_t flags = 0;
    uint32_t bitfield = 0;
    uint32_t token = 0;
    int32_t eventStart = -1;
    uint16_t eventCount = 0;
    int32_t propertyStart = -1;
    uint16_t propertyCount = 0;
    int32_t nestedTypeStart = -1;
    uint16_t nestedTypeCount = 0;
};

struct EventModel {
    std::string name;
    int32_t typeIndex = -1;
    int32_t add = -1;
    int32_t remove = -1;
    int32_t raise = -1;
    uint32_t token = 0;
};

struct PropertyModel {
    std::string name;
    int32_t get = -1;
    int32_t set = -1;
    uint32_t attrs = 0;
    uint32_t token = 0;
};

struct AttributeDataRangeModel {
    uint32_t token = 0;
    uint32_t start = 0;
};

struct GenericInstModel {
    uint64_t address = 0;
    std::vector<uint64_t> typeAddresses;
};

struct GenericClassModel {
    uint64_t address = 0;
    int32_t definitionIndex = -1;
    uint64_t classInstAddress = 0;
    uint64_t methodInstAddress = 0;
    uint64_t cachedClassAddress = 0;
};

struct GenericMethodSpecModel {
    int32_t methodDefinitionIndex = -1;
    int32_t classInstIndex = -1;
    int32_t methodInstIndex = -1;
    uint64_t classInstAddress = 0;
    uint64_t methodInstAddress = 0;
};

struct GenericMethodPointerModel {
    int32_t genericMethodIndex = -1;
    int32_t methodIndex = -1;
    int32_t invokerIndex = -1;
    uint64_t classInstAddress = 0;
    uint64_t methodInstAddress = 0;
    uint64_t methodPointer = 0;
    uint64_t invokerPointer = 0;
    int32_t adjustorThunkIndex = -1;
    uint64_t adjustorThunk = 0;
};

struct MetadataUsageListModel {
    uint32_t start = 0;
    uint32_t count = 0;
};

struct MetadataUsageModel {
    uint32_t kind = 0;
    uint32_t destinationIndex = 0;
    uint32_t encodedSourceIndex = 0;
    uint32_t decodedIndex = 0;
};

struct GenericContainerModel {
    int32_t ownerIndex = -1;
    int32_t typeArgumentCount = 0;
    int32_t isMethod = 0;
    int32_t genericParameterStart = -1;
};

struct GenericParameterModel {
    int32_t ownerIndex = -1;
    std::string name;
    int16_t constraintsStart = -1;
    int16_t constraintsCount = 0;
    uint16_t num = 0;
    uint16_t flags = 0;
};

struct FieldDefaultValueModel {
    int32_t fieldIndex = -1;
    int32_t typeIndex = -1;
    int32_t dataIndex = -1;
};

struct ParameterDefaultValueModel {
    int32_t parameterIndex = -1;
    int32_t typeIndex = -1;
    int32_t dataIndex = -1;
};

struct ImageModel {
    std::string name;
    int32_t assemblyIndex = -1;
    int32_t typeStart = -1;
    uint32_t typeCount = 0;
    int32_t exportedTypeStart = -1;
    uint32_t exportedTypeCount = 0;
    int32_t entryPointIndex = -1;
    uint32_t token = 0;
    int32_t customAttributeStart = -1;
    uint32_t customAttributeCount = 0;
    int32_t invokerIndicesStart = -1;
    int32_t rgctxRangesStart = -1;
    int32_t rgctxRangesCount = 0;
    int32_t staticConstructorStart = -1;
    int32_t staticConstructorCount = 0;
    int32_t fieldStart = -1;
    int32_t propertyStart = -1;
    int32_t eventStart = -1;
    int32_t methodStart = -1;
};

struct AssemblyModel {
    int32_t imageIndex = -1;
    uint32_t token = 0;
    int32_t referencedAssemblyStart = -1;
    int32_t referencedAssemblyCount = 0;
    uint32_t moduleToken = 0;
};

struct RgctxRangeModel {
    uint32_t token = 0;
    int32_t start = -1;
    int32_t count = 0;
};

struct RgctxValueModel {
    uint64_t kind = 0;
    uint64_t value = 0;
};

struct UnresolvedSignatureModel {
    int32_t start = -1;
    int32_t count = 0;
    std::vector<int32_t> parameterTypeIndices;
};

struct MethodSignatureModel {
    int32_t signatureOffset = -1;
    int32_t returnTypeIndex = -1;
    std::vector<int32_t> parameterTypeIndices;
};

struct GeneratedMethodTypeInfoModel {
    int32_t typeIndex = -1;
    int32_t generatedMethodStart = -1;
    int32_t generatedMethodCount = 0;
};

struct GeneratedMethodTokenModel {
    uint32_t token = 0;
};

struct MethodSpecOnGenericTypeModel {
    int32_t methodDefinitionIndex = -1;
    int32_t classIndexIndex = -1;
};

struct GenericMethodSpecOnTypeModel {
    int32_t methodDefinitionIndex = -1;
    int32_t methodIndexIndex = -1;
};

struct AdjustorThunkModel {
    uint32_t token = 0;
    uint64_t address = 0;
};

struct MetadataModel {
    double version = 0;
    std::vector<TypeModel> types;
    std::unordered_map<uint32_t, std::string> stringLiterals;
    std::unordered_map<std::string, std::vector<uint64_t>> methodPointersByImage;
    std::vector<TypeReferenceModel> typeReferences;
    std::unordered_map<uint32_t, int64_t> fieldOffsetsByToken;
    uint64_t metadataRegistrationAddress = 0;
    uint64_t codeRegistrationAddress = 0;
    std::vector<GenericClassModel> genericClasses;
    std::vector<GenericInstModel> genericInsts;
    std::vector<GenericMethodPointerModel> genericMethodTable;
    std::vector<GenericMethodSpecModel> methodSpecs;
    std::vector<uint64_t> genericMethodPointers;
    std::vector<uint64_t> invokerPointers;
    std::vector<MetadataUsageListModel> metadataUsageLists;
    std::vector<MetadataUsageModel> metadataUsagePairs;
    uint64_t metadataUsagesCount = 0;
    std::vector<GenericContainerModel> genericContainers;
    std::vector<GenericParameterModel> genericParameters;
    std::vector<FieldDefaultValueModel> fieldDefaultValues;
    std::vector<ParameterDefaultValueModel> parameterDefaultValues;
    std::vector<uint8_t> defaultValueData;
    std::vector<EventModel> events;
    std::vector<PropertyModel> properties;
    std::vector<int32_t> genericParameterConstraints;
    std::vector<int32_t> nestedTypes;
    std::vector<uint8_t> attributeData;
    std::vector<AttributeDataRangeModel> attributeDataRanges;
    MetadataVersionModel versionInfo;
    MetadataSectionsModel sections;
    std::vector<ImageModel> images;
    std::vector<AssemblyModel> assemblies;
    std::vector<RgctxRangeModel> rgctxRanges;
    std::vector<RgctxValueModel> rgctxValues;
    std::vector<uint64_t> unresolvedVirtualCallPointers;
    std::vector<UnresolvedSignatureModel> unresolvedSignatures;
    std::vector<MethodSignatureModel> methodSignatures;
    std::vector<GeneratedMethodTypeInfoModel> generatedMethodTypeInfos;
    std::vector<GeneratedMethodTokenModel> generatedMethodTokens;
    int32_t generatedMethodsStart = -1;
    std::vector<MethodSpecOnGenericTypeModel> methodSpecsOnGenericType;
    std::vector<GenericMethodSpecOnTypeModel> genericMethodSpecsOnType;
    std::vector<int32_t> invokerIndices;
    std::vector<int32_t> staticConstructorTypeIndices;
    std::vector<AdjustorThunkModel> adjustorThunks;
};

} // namespace il2cpprec
