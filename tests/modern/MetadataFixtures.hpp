#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace il2cpprec::tests::modern {

enum class Section : size_t {
    StringLiterals,
    StringLiteralData,
    Strings,
    Events,
    Properties,
    MethodSignatures,
    Methods,
    ParameterDefaultValues,
    FieldDefaultValues,
    DefaultValueData,
    FieldMarshaledSizes,
    Parameters,
    Fields,
    GenericParameters,
    GenericParameterConstraints,
    GenericContainers,
    NestedTypes,
    Interfaces,
    VtableMethods,
    InterfaceOffsets,
    TypeDefinitions,
    TypeInlineArrays,
    Images,
    Assemblies,
    FieldRefs,
    ReferencedAssemblies,
    AttributeData,
    AttributeDataRanges,
    UnresolvedParameterTypes,
    UnresolvedParameterRanges,
    WindowsRuntimeTypeNames,
    WindowsRuntimeStrings,
    ExportedTypeDefinitions,
    MethodSpecsOnGenericType,
    GenericMethodSpecsOnType,
    MethodSpecs,
    GenericMethodFunctions,
    GenericMethodFunctionsWithAdjustor,
    InvokerIndices,
    RgctxRanges,
    RgctxValues,
    StaticConstructorTypeIndices,
    GeneratedMethodTypeInfos,
    GeneratedMethodTokens,
    Count
};

struct SectionBytes {
    Section section = Section::StringLiterals;
    std::vector<uint8_t> bytes;
    int32_t count = 0;
};

struct SectionLayout {
    size_t headerOffset = 0;
    uint32_t dataOffset = 0;
    int32_t size = 0;
    int32_t count = 0;
};

struct MetadataFixture {
    int version = 0;
    size_t headerSize = 0;
    std::vector<uint8_t> bytes;
    std::array<SectionLayout, static_cast<size_t>(Section::Count)> sections{};

    const SectionLayout& layout(Section section) const;
};

class RecordWriter {
public:
    std::vector<uint8_t> bytes;

    void u8(uint8_t value);
    void u16(uint16_t value);
    void u32(uint32_t value);
    void index(int32_t value, size_t width);
};

size_t expectedHeaderSize(int version);
const std::vector<Section>& sectionOrder(int version);
MetadataFixture buildMetadataFixture(int version, const std::vector<SectionBytes>& sections = {});

void put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value);
void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value);

} // namespace il2cpprec::tests::modern
