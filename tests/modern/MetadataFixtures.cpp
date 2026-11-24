#include "MetadataFixtures.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace il2cpprec::tests::modern {
namespace {

constexpr size_t sectionCount = static_cast<size_t>(Section::Count);

size_t indexOf(Section section) {
    return static_cast<size_t>(section);
}

const std::vector<Section>& baseSections() {
    static const std::vector<Section> sections{
        Section::StringLiterals,
        Section::StringLiteralData,
        Section::Strings,
        Section::Events,
        Section::Properties,
        Section::Methods,
        Section::ParameterDefaultValues,
        Section::FieldDefaultValues,
        Section::DefaultValueData,
        Section::FieldMarshaledSizes,
        Section::Parameters,
        Section::Fields,
        Section::GenericParameters,
        Section::GenericParameterConstraints,
        Section::GenericContainers,
        Section::NestedTypes,
        Section::Interfaces,
        Section::VtableMethods,
        Section::InterfaceOffsets,
        Section::TypeDefinitions,
        Section::Images,
        Section::Assemblies,
        Section::FieldRefs,
        Section::ReferencedAssemblies,
        Section::AttributeData,
        Section::AttributeDataRanges,
        Section::UnresolvedParameterTypes,
        Section::UnresolvedParameterRanges,
        Section::WindowsRuntimeTypeNames,
        Section::WindowsRuntimeStrings,
        Section::ExportedTypeDefinitions,
    };
    return sections;
}

void append(std::vector<uint8_t>& bytes, uint32_t value, size_t width) {
    for (size_t index = 0; index < width; ++index) {
        bytes.push_back(static_cast<uint8_t>(value >> (index * 8)));
    }
}

} // namespace

const SectionLayout& MetadataFixture::layout(Section section) const {
    return sections.at(indexOf(section));
}

void RecordWriter::u8(uint8_t value) {
    bytes.push_back(value);
}

void RecordWriter::u16(uint16_t value) {
    append(bytes, value, 2);
}

void RecordWriter::u32(uint32_t value) {
    append(bytes, value, 4);
}

void RecordWriter::index(int32_t value, size_t width) {
    if (width != 1 && width != 2 && width != 4) throw std::invalid_argument("Invalid fixture index width");
    uint32_t encoded = static_cast<uint32_t>(value);
    if (value == -1) {
        encoded = width == 1 ? std::numeric_limits<uint8_t>::max()
            : width == 2 ? std::numeric_limits<uint16_t>::max()
            : std::numeric_limits<uint32_t>::max();
    }
    append(bytes, encoded, width);
}

size_t expectedHeaderSize(int version) {
    if (version == 33 || version == 35) return 8 + baseSections().size() * 8;
    if (version < 38) throw std::invalid_argument("Fixture version has no supported header layout");
    return 8 + sectionOrder(version).size() * 12;
}

const std::vector<Section>& sectionOrder(int version) {
    static const std::vector<Section> v38 = baseSections();
    static const std::vector<Section> v104 = [] {
        auto result = v38;
        result.insert(result.begin() + 20, Section::TypeInlineArrays);
        return result;
    }();
    static const std::vector<Section> v108 = [] {
        auto result = v104;
        result.insert(result.end(), {
            Section::MethodSpecsOnGenericType,
            Section::GenericMethodSpecsOnType,
            Section::MethodSpecs,
            Section::GenericMethodFunctions,
            Section::GenericMethodFunctionsWithAdjustor,
            Section::InvokerIndices,
            Section::RgctxRanges,
            Section::RgctxValues,
            Section::StaticConstructorTypeIndices,
        });
        return result;
    }();
    static const std::vector<Section> v110 = [] {
        auto result = v108;
        result.insert(result.end(), {Section::GeneratedMethodTypeInfos, Section::GeneratedMethodTokens});
        return result;
    }();
    static const std::vector<Section> v111 = [] {
        auto result = v110;
        result.insert(result.begin() + 5, Section::MethodSignatures);
        return result;
    }();

    if (version == 33 || version == 35) return baseSections();
    if (version >= 111) return v111;
    if (version >= 110) return v110;
    if (version >= 108) return v108;
    if (version >= 104) return v104;
    if (version >= 38) return v38;
    throw std::invalid_argument("Fixture version has no supported section order");
}

MetadataFixture buildMetadataFixture(int version, const std::vector<SectionBytes>& inputs) {
    const auto& order = sectionOrder(version);
    MetadataFixture fixture;
    fixture.version = version;
    fixture.headerSize = expectedHeaderSize(version);
    fixture.bytes.resize(fixture.headerSize, 0);
    put32(fixture.bytes, 0, 0xFAB11BAF);
    put32(fixture.bytes, 4, static_cast<uint32_t>(version));

    std::array<bool, sectionCount> seen{};
    size_t headerOffset = 8;
    for (const auto section : order) {
        auto& layout = fixture.sections[indexOf(section)];
        layout.headerOffset = headerOffset;
        const auto input = std::find_if(inputs.begin(), inputs.end(), [&](const SectionBytes& candidate) {
            return candidate.section == section;
        });
        if (input != inputs.end()) {
            if (seen[indexOf(section)]) throw std::invalid_argument("Duplicate fixture section");
            seen[indexOf(section)] = true;
            if (!input->bytes.empty()) {
                const auto padding = (4 - fixture.bytes.size() % 4) % 4;
                fixture.bytes.insert(fixture.bytes.end(), padding, 0);
                if (fixture.bytes.size() > std::numeric_limits<uint32_t>::max() ||
                    input->bytes.size() > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
                    throw std::overflow_error("Fixture section is too large");
                }
                layout.dataOffset = static_cast<uint32_t>(fixture.bytes.size());
                layout.size = static_cast<int32_t>(input->bytes.size());
                layout.count = input->count;
                fixture.bytes.insert(fixture.bytes.end(), input->bytes.begin(), input->bytes.end());
            }
        }

        put32(fixture.bytes, headerOffset, layout.dataOffset);
        put32(fixture.bytes, headerOffset + 4, static_cast<uint32_t>(layout.size));
        if (version >= 38) put32(fixture.bytes, headerOffset + 8, static_cast<uint32_t>(layout.count));
        headerOffset += version >= 38 ? 12 : 8;
    }

    for (const auto& input : inputs) {
        if (!seen[indexOf(input.section)]) {
            throw std::invalid_argument("Section is not present in this metadata version");
        }
    }
    return fixture;
}

void put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value) {
    for (size_t index = 0; index < 2; ++index) bytes.at(offset + index) = static_cast<uint8_t>(value >> (index * 8));
}

void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    for (size_t index = 0; index < 4; ++index) bytes.at(offset + index) = static_cast<uint8_t>(value >> (index * 8));
}

} // namespace il2cpprec::tests::modern
