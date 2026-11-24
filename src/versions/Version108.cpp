#include <il2cpprec/versions/Version108.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint32_t sanityValue = 0xFAB11BAF;

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 108/109 data: " + message);
}

uint64_t checkedAdd(uint64_t value, uint64_t amount) {
    if (amount > std::numeric_limits<uint64_t>::max() - value) invalid("address overflow");
    return value + amount;
}

size_t checkedSize(uint64_t count, size_t stride) {
    if (stride != 0 && count > std::numeric_limits<size_t>::max() / stride) {
        invalid("table size overflow");
    }
    return static_cast<size_t>(count) * stride;
}

bool validIndexWidth(size_t width) {
    return width == 1 || width == 2 || width == 4;
}

size_t inferredPointerSize(const BinaryImage& binary, size_t requested) {
    if (requested == 4 || requested == 8) return requested;
    if (requested != 0) throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    return Version108::pointerSize(binary);
}

class MetadataReader {
public:
    MetadataReader(const uint8_t* data, size_t size)
        : data_(data), size_(size) {
        if (data == nullptr && size != 0) invalid("null global metadata with nonzero size");
    }

    size_t size() const noexcept { return size_; }

    uint8_t u8(size_t offset) const {
        require(offset, 1);
        return data_[offset];
    }

    uint16_t u16(size_t offset) const {
        require(offset, 2);
        return static_cast<uint16_t>(data_[offset]) |
            static_cast<uint16_t>(static_cast<uint16_t>(data_[offset + 1]) << 8);
    }

    uint32_t u32(size_t offset) const {
        require(offset, 4);
        return static_cast<uint32_t>(data_[offset]) |
            (static_cast<uint32_t>(data_[offset + 1]) << 8) |
            (static_cast<uint32_t>(data_[offset + 2]) << 16) |
            (static_cast<uint32_t>(data_[offset + 3]) << 24);
    }

    int32_t i32(size_t offset) const { return std::bit_cast<int32_t>(u32(offset)); }

    int32_t index(size_t offset, size_t width) const {
        switch (width) {
        case 1: {
            const uint8_t value = u8(offset);
            return value == std::numeric_limits<uint8_t>::max() ? -1 : value;
        }
        case 2: {
            const uint16_t value = u16(offset);
            return value == std::numeric_limits<uint16_t>::max() ? -1 : value;
        }
        case 4: {
            const int32_t value = i32(offset);
            return value < 0 ? -1 : value;
        }
        default:
            invalid("unsupported variable-width index");
        }
    }

    const uint8_t* bytes(size_t offset, size_t amount) const {
        require(offset, amount);
        return data_ + offset;
    }

    void require(size_t offset, size_t amount) const {
        if (offset > size_ || amount > size_ - offset) invalid("read is outside global metadata");
    }

private:
    const uint8_t* data_;
    size_t size_;
};

class ImageReader {
public:
    ImageReader(const BinaryImage& binary, size_t pointerSize)
        : binary_(binary), pointerSize_(inferredPointerSize(binary, pointerSize)) {
        if (!binary.bytes) invalid("binary image has no data");
    }

    size_t pointerSize() const noexcept { return pointerSize_; }

    uint32_t u32(uint64_t address) const {
        const auto* data = bytes(address, 4);
        return static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << 8) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 24);
    }

    int32_t i32(uint64_t address) const { return std::bit_cast<int32_t>(u32(address)); }

    uint64_t u64(uint64_t address) const {
        const auto* data = bytes(address, 8);
        uint64_t value = 0;
        for (size_t index = 0; index < 8; ++index) {
            value |= static_cast<uint64_t>(data[index]) << (index * 8);
        }
        return value;
    }

    uint64_t pointer(uint64_t address) const {
        return pointerSize_ == 4 ? u32(address) : u64(address);
    }

    uint64_t count(uint64_t address) const {
        const int32_t low = i32(address);
        if (low < 0) invalid("negative native table count");
        if (pointerSize_ == 8 && u32(checkedAdd(address, 4)) != 0) {
            invalid("native table count exceeds 32 bits");
        }
        return static_cast<uint32_t>(low);
    }

    void require(uint64_t address, size_t size) const { static_cast<void>(bytes(address, size)); }

    std::vector<uint64_t> pointerTable(uint64_t address, uint64_t count) const {
        const size_t size = checkedSize(count, pointerSize_);
        if (size != 0) require(address, size);
        std::vector<uint64_t> result;
        result.reserve(static_cast<size_t>(count));
        for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
            result.push_back(pointer(checkedAdd(address, index * pointerSize_)));
        }
        return result;
    }

    std::string string(uint64_t address) const {
        const size_t offset = fileOffset(address, 1);
        const auto& data = *binary_.bytes;
        constexpr size_t maximumLength = 1024 * 1024;
        const size_t limit = std::min(data.size() - offset, maximumLength + 1);
        size_t length = 0;
        while (length < limit && data[offset + length] != 0) ++length;
        if (length == limit || length > maximumLength) invalid("unterminated code-gen module name");
        return std::string(reinterpret_cast<const char*>(data.data() + offset), length);
    }

private:
    const uint8_t* bytes(uint64_t address, size_t size) const {
        return binary_.data(fileOffset(address, size), size);
    }

    size_t fileOffset(uint64_t address, size_t size) const {
        const auto map = [&](uint64_t candidate, uint64_t& mapped) {
            try {
                mapped = binary_.mapVATR(candidate);
                return true;
            } catch (const std::out_of_range&) {
                return false;
            } catch (const std::overflow_error&) {
                return false;
            }
        };

        uint64_t mapped = 0;
        if (!map(address, mapped)) {
            bool found = false;
            if (address >= binary_.imageBase) found = map(address - binary_.imageBase, mapped);
            if (!found && address <= std::numeric_limits<uint64_t>::max() - binary_.imageBase) {
                found = map(binary_.imageBase + address, mapped);
            }
            if (!found) invalid("virtual address is not backed by a file range");
        }
        if (mapped > std::numeric_limits<size_t>::max()) invalid("file offset exceeds the host size type");
        const size_t offset = static_cast<size_t>(mapped);
        if (!binary_.bytes || offset > binary_.bytes->size() || size > binary_.bytes->size() - offset) {
            invalid("read is outside the binary image");
        }
        return offset;
    }

    const BinaryImage& binary_;
    size_t pointerSize_;
};

std::array<MetadataSectionModel*, Version108Header::sectionCount> sectionPointers(
    MetadataSectionsModel& sections) {
    return {
        &sections.stringLiterals,
        &sections.stringLiteralData,
        &sections.strings,
        &sections.events,
        &sections.properties,
        &sections.methods,
        &sections.parameterDefaultValues,
        &sections.fieldDefaultValues,
        &sections.defaultValueData,
        &sections.fieldMarshaledSizes,
        &sections.parameters,
        &sections.fields,
        &sections.genericParameters,
        &sections.genericParameterConstraints,
        &sections.genericContainers,
        &sections.nestedTypes,
        &sections.interfaces,
        &sections.vtableMethods,
        &sections.interfaceOffsets,
        &sections.typeDefinitions,
        &sections.typeInlineArrays,
        &sections.images,
        &sections.assemblies,
        &sections.fieldRefs,
        &sections.referencedAssemblies,
        &sections.attributeData,
        &sections.attributeDataRanges,
        &sections.unresolvedIndirectCallParameterTypes,
        &sections.unresolvedIndirectCallParameterRanges,
        &sections.windowsRuntimeTypeNames,
        &sections.windowsRuntimeStrings,
        &sections.exportedTypeDefinitions,
        &sections.methodSpecsOnGenericType,
        &sections.genericMethodSpecsOnType,
        &sections.methodSpecs,
        &sections.genericMethodFunctionsDefinitions,
        &sections.genericMethodFunctionsDefinitionsWithAdjustor,
        &sections.invokerIndices,
        &sections.rgctxRanges,
        &sections.rgctxValues,
        &sections.staticConstructorTypeIndices,
    };
}

size_t strideOf(const MetadataSectionModel& section, const char* name) {
    if (section.offset < 0 || section.sectionSize < 0 || section.count < 0) {
        invalid(std::string(name) + " has a negative section field");
    }
    if (section.count == 0) {
        if (section.sectionSize != 0) invalid(std::string(name) + " has data but zero elements");
        return 0;
    }
    if (section.sectionSize % section.count != 0) {
        invalid(std::string(name) + " byte size is not divisible by its element count");
    }
    return static_cast<size_t>(section.sectionSize / section.count);
}

size_t derivedWidth(size_t value, const char* name) {
    if (!validIndexWidth(value)) invalid(std::string(name) + " has an invalid index width");
    return value;
}

void requireSection(
    const MetadataReader& reader,
    const MetadataSectionModel& section,
    size_t expectedStride,
    const char* name) {
    const size_t stride = strideOf(section, name);
    if (stride != expectedStride) invalid(std::string(name) + " has an unexpected element size");
    const auto offset = static_cast<size_t>(section.offset);
    const auto size = static_cast<size_t>(section.sectionSize);
    reader.require(offset, size);
}

std::string metadataString(
    const MetadataReader& reader,
    const MetadataSectionModel& strings,
    uint32_t index) {
    if (strings.offset < 0 || strings.sectionSize < 0) invalid("negative string table range");
    const auto stringSize = static_cast<size_t>(strings.sectionSize);
    if (index >= stringSize) invalid("string index is outside the string table");
    const size_t start = static_cast<size_t>(strings.offset) + index;
    const size_t remaining = stringSize - index;
    const auto* data = reinterpret_cast<const char*>(reader.bytes(start, remaining));
    const void* terminator = std::memchr(data, 0, remaining);
    if (terminator == nullptr) invalid("unterminated metadata string");
    return std::string(data, static_cast<const char*>(terminator) - data);
}

void validateDefinitionIndex(int32_t index, int32_t methodCount) {
    if (index < 0 || methodCount < 0 || index >= methodCount) {
        invalid("generic method spec definition index is outside the method table");
    }
}

void validateRange(int32_t start, int32_t count, size_t available, const char* name) {
    if (count == 0) return;
    if (start < 0 || count < 0) invalid(std::string(name) + " has a negative range");
    const auto begin = static_cast<size_t>(start);
    const auto length = static_cast<size_t>(count);
    if (begin > available || length > available - begin) {
        invalid(std::string(name) + " is outside its target table");
    }
}

Version108NativeTable readNativeTable(
    const ImageReader& reader,
    uint64_t address,
    size_t pointerSize) {
    return {reader.count(address), reader.pointer(checkedAdd(address, pointerSize))};
}

uint64_t selectedPointer(const std::vector<uint64_t>& pointers, int32_t index) noexcept {
    if (index < 0 || static_cast<size_t>(index) >= pointers.size()) return 0;
    return pointers[static_cast<size_t>(index)];
}

uint64_t requiredPointer(
    const std::vector<uint64_t>& pointers,
    int32_t index,
    const char* message) {
    if (index == -1) return 0;
    if (index < -1 || static_cast<size_t>(index) >= pointers.size()) invalid(message);
    return pointers[static_cast<size_t>(index)];
}

size_t methodDefinitionCount(const MetadataModel& metadata) {
    if (metadata.sections.methods.count > 0) {
        return static_cast<size_t>(metadata.sections.methods.count);
    }
    size_t count = 0;
    for (const auto& type : metadata.types) {
        if (type.methods.size() > std::numeric_limits<size_t>::max() - count) {
            invalid("method definition count overflow");
        }
        count += type.methods.size();
    }
    return count;
}

size_t typeDefinitionCount(const MetadataModel& metadata) {
    if (metadata.sections.typeDefinitions.count > 0) {
        return static_cast<size_t>(metadata.sections.typeDefinitions.count);
    }
    return metadata.types.size();
}

} // namespace

size_t Version108Header::recordStride(const MetadataSectionModel& section) const {
    return strideOf(section, "metadata table");
}

size_t Version108Header::indexWidth(int32_t count) {
    if (count < 0) invalid("negative element count used for index width");
    if (count <= std::numeric_limits<uint8_t>::max()) return 1;
    if (count <= std::numeric_limits<uint16_t>::max()) return 2;
    return 4;
}

Version108Header Version108::readHeader(const std::vector<uint8_t>& data) {
    return readHeader(data.data(), data.size());
}

Version108Header Version108::readHeader(const uint8_t* data, size_t size) {
    MetadataReader reader(data, size);
    reader.require(0, Version108Header::serializedSize);
    if (reader.u32(0) != sanityValue) invalid("incorrect global metadata sanity value");

    Version108Header header;
    header.version = reader.i32(4);
    if (!supports(header.version)) {
        throw std::runtime_error("Unsupported global metadata version: " + std::to_string(header.version));
    }

    auto pointers = sectionPointers(header.sections);
    for (size_t index = 0; index < pointers.size(); ++index) {
        const size_t offset = 8 + index * 12;
        auto& section = *pointers[index];
        section.offset = reader.i32(offset);
        section.sectionSize = reader.i32(offset + 4);
        section.count = reader.i32(offset + 8);
        if (section.offset < 0 || section.sectionSize < 0 || section.count < 0) {
            invalid("negative global metadata section field");
        }
        reader.require(
            static_cast<size_t>(section.offset),
            static_cast<size_t>(section.sectionSize));
    }

    auto& sections = header.sections;
    auto& widths = header.indices;
    widths.methodDefinition = Version108Header::indexWidth(sections.methods.count);
    widths.typeDefinition = Version108Header::indexWidth(sections.typeDefinitions.count);
    widths.methodSpec = Version108Header::indexWidth(
        sections.methodSpecsOnGenericType.count +
        sections.genericMethodSpecsOnType.count +
        sections.methodSpecs.count);

    const size_t interfaceStride = strideOf(sections.interfaceOffsets, "interface offsets");
    if (interfaceStride != 0) {
        if (interfaceStride <= sizeof(int32_t)) invalid("interface offset element is too small");
        widths.type = derivedWidth(interfaceStride - sizeof(int32_t), "type index");
    }

    const size_t shortStride = widths.methodDefinition + widths.genericInst;
    const size_t fullStride = widths.methodDefinition + 2 * widths.genericInst;
    bool genericInstKnown = false;
    const auto deriveGenericInst = [&](const MetadataSectionModel& section, bool full, const char* name) {
        const size_t stride = strideOf(section, name);
        if (stride == 0) return;
        const size_t fixed = full ? widths.methodDefinition : widths.methodDefinition;
        if (stride <= fixed || (full && (stride - fixed) % 2 != 0)) {
            invalid(std::string(name) + " has an invalid element size");
        }
        const size_t width = derivedWidth(full ? (stride - fixed) / 2 : stride - fixed, "generic inst index");
        if (genericInstKnown && widths.genericInst != width) {
            invalid("method spec tables disagree on generic inst index width");
        }
        widths.genericInst = width;
        genericInstKnown = true;
    };
    deriveGenericInst(sections.methodSpecsOnGenericType, false, "method specs on generic type");
    deriveGenericInst(sections.genericMethodSpecsOnType, false, "generic method specs on type");
    deriveGenericInst(sections.methodSpecs, true, "method specs");

    const size_t invokerStride = strideOf(sections.invokerIndices, "invoker indices");
    if (invokerStride != 0) widths.invoker = derivedWidth(invokerStride, "invoker index");

    const size_t plainStride = strideOf(
        sections.genericMethodFunctionsDefinitions,
        "generic method functions");
    if (plainStride != 0) {
        const size_t fixed = widths.methodSpec + widths.invoker;
        if (plainStride <= fixed) invalid("generic method function element is too small");
        widths.genericMethodPointer = derivedWidth(
            plainStride - fixed,
            "generic method pointer index");
    }

    const size_t adjustorStride = strideOf(
        sections.genericMethodFunctionsDefinitionsWithAdjustor,
        "generic method functions with adjustor");
    if (adjustorStride != 0) {
        const size_t fixed = widths.methodSpec + widths.genericMethodPointer + widths.invoker;
        if (adjustorStride <= fixed) invalid("generic method function with adjustor element is too small");
        widths.adjustorThunk = derivedWidth(adjustorStride - fixed, "adjustor thunk index");
    }

    (void)shortStride;
    (void)fullStride;
    return header;
}

Version108::Version108(size_t pointerSize)
    : pointerSize_(pointerSize) {
    if (pointerSize != 0 && pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
}

bool Version108::supports(double version) noexcept {
    return version == 108.0 || version == 109.0;
}

bool Version108::supports(int32_t rawVersion) noexcept {
    return rawVersion == 108 || rawVersion == 109;
}

size_t Version108::pointerSize(const BinaryImage& binary) {
    switch (binary.architecture) {
    case Architecture::X86:
    case Architecture::Arm32:
        return 4;
    case Architecture::X64:
    case Architecture::Arm64:
        return 8;
    }
    throw std::invalid_argument("Unsupported IL2CPP binary architecture");
}

Version108Layout Version108::makeLayout(size_t pointerSize) {
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
    Version108Layout layout;
    layout.pointerSize = pointerSize;
    layout.codeRegistrationSize = 17 * pointerSize;
    layout.metadataRegistrationSize = 14 * pointerSize;
    layout.codeGenModuleSize = 11 * pointerSize;
    layout.genericAdjustorThunksOffset = 4 * pointerSize;
    layout.invokerPointersCountOffset = 5 * pointerSize;
    layout.invokerPointersOffset = 6 * pointerSize;
    layout.codeGenModulesCountOffset = 15 * pointerSize;
    layout.codeGenModulesOffset = 16 * pointerSize;
    layout.adjustorThunkCountOffset = 3 * pointerSize;
    layout.adjustorThunksOffset = 4 * pointerSize;
    return layout;
}

Version108Layout Version108::layout() const {
    return makeLayout(pointerSize_ == 0 ? 8 : pointerSize_);
}

MetadataModel Version108::read(const std::vector<uint8_t>& data) const {
    return read(data.data(), data.size());
}

MetadataModel Version108::read(const uint8_t* data, size_t size) const {
    const Version108Header header = readHeader(data, size);
    MetadataReader reader(data, size);
    const auto& sections = header.sections;
    const auto& widths = header.indices;

    MetadataModel model;
    model.version = static_cast<double>(header.version);
    model.versionInfo.rawVersion = header.version;
    model.versionInfo.preciseVersion = model.version;
    model.versionInfo.confidence = MetadataVersionConfidence::RawHeader;
    model.sections = sections;

    requireSection(
        reader,
        sections.methodSpecsOnGenericType,
        widths.methodDefinition + widths.genericInst,
        "method specs on generic type");
    requireSection(
        reader,
        sections.genericMethodSpecsOnType,
        widths.methodDefinition + widths.genericInst,
        "generic method specs on type");
    requireSection(
        reader,
        sections.methodSpecs,
        widths.methodDefinition + 2 * widths.genericInst,
        "method specs");

    model.methodSpecsOnGenericType.reserve(
        static_cast<size_t>(sections.methodSpecsOnGenericType.count));
    for (int32_t index = 0; index < sections.methodSpecsOnGenericType.count; ++index) {
        const size_t offset = static_cast<size_t>(sections.methodSpecsOnGenericType.offset) +
            static_cast<size_t>(index) * (widths.methodDefinition + widths.genericInst);
        MethodSpecOnGenericTypeModel spec;
        spec.methodDefinitionIndex = reader.index(offset, widths.methodDefinition);
        spec.classIndexIndex = reader.index(offset + widths.methodDefinition, widths.genericInst);
        validateDefinitionIndex(spec.methodDefinitionIndex, sections.methods.count);
        model.methodSpecsOnGenericType.push_back(spec);

        GenericMethodSpecModel normalized;
        normalized.methodDefinitionIndex = spec.methodDefinitionIndex;
        normalized.classInstIndex = spec.classIndexIndex;
        model.methodSpecs.push_back(normalized);
    }

    model.genericMethodSpecsOnType.reserve(
        static_cast<size_t>(sections.genericMethodSpecsOnType.count));
    for (int32_t index = 0; index < sections.genericMethodSpecsOnType.count; ++index) {
        const size_t offset = static_cast<size_t>(sections.genericMethodSpecsOnType.offset) +
            static_cast<size_t>(index) * (widths.methodDefinition + widths.genericInst);
        GenericMethodSpecOnTypeModel spec;
        spec.methodDefinitionIndex = reader.index(offset, widths.methodDefinition);
        spec.methodIndexIndex = reader.index(offset + widths.methodDefinition, widths.genericInst);
        validateDefinitionIndex(spec.methodDefinitionIndex, sections.methods.count);
        model.genericMethodSpecsOnType.push_back(spec);

        GenericMethodSpecModel normalized;
        normalized.methodDefinitionIndex = spec.methodDefinitionIndex;
        normalized.methodInstIndex = spec.methodIndexIndex;
        model.methodSpecs.push_back(normalized);
    }

    for (int32_t index = 0; index < sections.methodSpecs.count; ++index) {
        const size_t stride = widths.methodDefinition + 2 * widths.genericInst;
        const size_t offset = static_cast<size_t>(sections.methodSpecs.offset) +
            static_cast<size_t>(index) * stride;
        GenericMethodSpecModel spec;
        spec.methodDefinitionIndex = reader.index(offset, widths.methodDefinition);
        spec.classInstIndex = reader.index(offset + widths.methodDefinition, widths.genericInst);
        spec.methodInstIndex = reader.index(
            offset + widths.methodDefinition + widths.genericInst,
            widths.genericInst);
        validateDefinitionIndex(spec.methodDefinitionIndex, sections.methods.count);
        model.methodSpecs.push_back(spec);
    }

    const auto readFunctionTable = [&](const MetadataSectionModel& section, bool withAdjustor) {
        const size_t stride = widths.methodSpec + widths.genericMethodPointer + widths.invoker +
            (withAdjustor ? widths.adjustorThunk : 0);
        requireSection(reader, section, stride, "generic method function table");
        for (int32_t index = 0; index < section.count; ++index) {
            size_t offset = static_cast<size_t>(section.offset) + static_cast<size_t>(index) * stride;
            GenericMethodPointerModel mapping;
            mapping.genericMethodIndex = reader.index(offset, widths.methodSpec);
            offset += widths.methodSpec;
            mapping.methodIndex = reader.index(offset, widths.genericMethodPointer);
            offset += widths.genericMethodPointer;
            mapping.invokerIndex = reader.index(offset, widths.invoker);
            if (withAdjustor) {
                offset += widths.invoker;
                mapping.adjustorThunkIndex = reader.index(offset, widths.adjustorThunk);
            }
            if (mapping.genericMethodIndex < 0 ||
                static_cast<size_t>(mapping.genericMethodIndex) >= model.methodSpecs.size()) {
                invalid("generic method table index is outside the normalized method spec table");
            }
            model.genericMethodTable.push_back(mapping);
        }
    };
    readFunctionTable(sections.genericMethodFunctionsDefinitions, false);
    readFunctionTable(sections.genericMethodFunctionsDefinitionsWithAdjustor, true);

    requireSection(reader, sections.invokerIndices, widths.invoker, "invoker indices");
    model.invokerIndices.reserve(static_cast<size_t>(sections.invokerIndices.count));
    for (int32_t index = 0; index < sections.invokerIndices.count; ++index) {
        model.invokerIndices.push_back(reader.index(
            static_cast<size_t>(sections.invokerIndices.offset) +
                static_cast<size_t>(index) * widths.invoker,
            widths.invoker));
    }

    requireSection(reader, sections.rgctxRanges, 12, "RGCTX ranges");
    model.rgctxRanges.reserve(static_cast<size_t>(sections.rgctxRanges.count));
    for (int32_t index = 0; index < sections.rgctxRanges.count; ++index) {
        const size_t offset = static_cast<size_t>(sections.rgctxRanges.offset) +
            static_cast<size_t>(index) * 12;
        model.rgctxRanges.push_back({
            reader.u32(offset),
            reader.i32(offset + 4),
            reader.i32(offset + 8)});
    }

    requireSection(reader, sections.rgctxValues, 5, "RGCTX values");
    model.rgctxValues.reserve(static_cast<size_t>(sections.rgctxValues.count));
    for (int32_t index = 0; index < sections.rgctxValues.count; ++index) {
        const size_t offset = static_cast<size_t>(sections.rgctxValues.offset) +
            static_cast<size_t>(index) * 5;
        model.rgctxValues.push_back({reader.u8(offset), reader.u32(offset + 1)});
    }
    validateRgctxRanges(model.rgctxRanges, model.rgctxValues.size());

    requireSection(
        reader,
        sections.staticConstructorTypeIndices,
        widths.typeDefinition,
        "static constructor type indices");
    model.staticConstructorTypeIndices.reserve(
        static_cast<size_t>(sections.staticConstructorTypeIndices.count));
    for (int32_t index = 0; index < sections.staticConstructorTypeIndices.count; ++index) {
        const int32_t type = reader.index(
            static_cast<size_t>(sections.staticConstructorTypeIndices.offset) +
                static_cast<size_t>(index) * widths.typeDefinition,
            widths.typeDefinition);
        if (type < 0 || type >= sections.typeDefinitions.count) {
            invalid("static constructor type index is outside the type table");
        }
        model.staticConstructorTypeIndices.push_back(type);
    }

    const size_t imageStride = 8 + widths.typeDefinition + 4 + widths.typeDefinition + 4 +
        widths.methodDefinition + 4 + 8 + 4 + 8 + widths.typeDefinition + 4;
    requireSection(reader, sections.images, imageStride, "images");
    model.images.reserve(static_cast<size_t>(sections.images.count));
    for (int32_t index = 0; index < sections.images.count; ++index) {
        size_t offset = static_cast<size_t>(sections.images.offset) +
            static_cast<size_t>(index) * imageStride;
        const uint32_t nameIndex = reader.u32(offset);
        ImageModel image;
        image.name = metadataString(reader, sections.strings, nameIndex);
        offset += 4;
        image.assemblyIndex = reader.i32(offset);
        offset += 4;
        image.typeStart = reader.index(offset, widths.typeDefinition);
        offset += widths.typeDefinition;
        image.typeCount = reader.u32(offset);
        offset += 4;
        image.exportedTypeStart = reader.index(offset, widths.typeDefinition);
        offset += widths.typeDefinition;
        image.exportedTypeCount = reader.u32(offset);
        offset += 4;
        image.entryPointIndex = reader.index(offset, widths.methodDefinition);
        offset += widths.methodDefinition;
        image.token = reader.u32(offset);
        offset += 4;
        image.customAttributeStart = reader.i32(offset);
        image.customAttributeCount = reader.u32(offset + 4);
        offset += 8;
        image.invokerIndicesStart = reader.i32(offset);
        offset += 4;
        image.rgctxRangesStart = reader.i32(offset);
        image.rgctxRangesCount = reader.i32(offset + 4);
        offset += 8;
        image.staticConstructorStart = reader.index(offset, widths.typeDefinition);
        offset += widths.typeDefinition;
        image.staticConstructorCount = reader.u32(offset);

        validateRange(image.typeStart, static_cast<int32_t>(image.typeCount),
                      sections.typeDefinitions.count, "image type range");
        validateRange(image.rgctxRangesStart, image.rgctxRangesCount,
                      model.rgctxRanges.size(), "image RGCTX range");
        if (image.staticConstructorCount > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
            invalid("image static constructor range is too large");
        }
        validateRange(image.staticConstructorStart,
                      static_cast<int32_t>(image.staticConstructorCount),
                      model.staticConstructorTypeIndices.size(),
                      "image static constructor range");
        model.methodPointersByImage.try_emplace(image.name);
        model.images.push_back(std::move(image));
    }

    return model;
}

MetadataModel Version108::readFile(const std::string& path) const {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open global metadata file: " + path);
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("Cannot determine global metadata file size: " + path);
    const auto fileSize = static_cast<uint64_t>(end);
    if (fileSize > std::numeric_limits<size_t>::max() ||
        fileSize > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("Global metadata file is too large: " + path);
    }
    std::vector<uint8_t> data(static_cast<size_t>(fileSize));
    stream.seekg(0, std::ios::beg);
    if (!data.empty()) {
        stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!stream) throw std::runtime_error("Cannot read global metadata file: " + path);
    }
    return read(data);
}

Version108CodeRegistration Version108::readCodeRegistration(
    const BinaryImage& binary,
    uint64_t address) const {
    ImageReader reader(binary, pointerSize_);
    const Version108Layout current = makeLayout(reader.pointerSize());
    const size_t p = current.pointerSize;
    reader.require(address, current.codeRegistrationSize);

    Version108CodeRegistration code;
    code.reversePInvokeWrappers = readNativeTable(reader, address, p);
    code.genericMethodPointers = readNativeTable(reader, checkedAdd(address, 2 * p), p);
    code.genericAdjustorThunks = reader.pointer(checkedAdd(address, current.genericAdjustorThunksOffset));
    code.invokerPointers = readNativeTable(
        reader, checkedAdd(address, current.invokerPointersCountOffset), p);
    code.unresolvedVirtualCallPointers = readNativeTable(reader, checkedAdd(address, 7 * p), p);
    code.unresolvedInstanceCallPointers = reader.pointer(checkedAdd(address, 9 * p));
    code.unresolvedStaticCallPointers = reader.pointer(checkedAdd(address, 10 * p));
    code.interopData = readNativeTable(reader, checkedAdd(address, 11 * p), p);
    code.windowsRuntimeFactoryTable = readNativeTable(reader, checkedAdd(address, 13 * p), p);
    code.codeGenModules = readNativeTable(
        reader, checkedAdd(address, current.codeGenModulesCountOffset), p);
    return code;
}

Version108MetadataRegistration Version108::readMetadataRegistration(
    const BinaryImage& binary,
    uint64_t address) const {
    ImageReader reader(binary, pointerSize_);
    const size_t p = reader.pointerSize();
    reader.require(address, makeLayout(p).metadataRegistrationSize);

    Version108MetadataRegistration registration;
    registration.genericClasses = readNativeTable(reader, address, p);
    registration.genericInsts = readNativeTable(reader, checkedAdd(address, 2 * p), p);
    registration.types = readNativeTable(reader, checkedAdd(address, 4 * p), p);
    registration.fieldOffsets = readNativeTable(reader, checkedAdd(address, 6 * p), p);
    registration.typeDefinitionsSizes = readNativeTable(reader, checkedAdd(address, 8 * p), p);
    registration.metadataUsages = readNativeTable(reader, checkedAdd(address, 10 * p), p);
    registration.alwaysInitMetadataUsages = readNativeTable(reader, checkedAdd(address, 12 * p), p);
    return registration;
}

Version108Registration Version108::readRegistration(
    const BinaryImage& binary,
    MetadataModel& metadata,
    uint64_t metadataRegistrationAddress,
    uint64_t codeRegistrationAddress) const {
    if (!supports(metadata.version)) invalid("registration requires metadata version 108 or 109");
    ImageReader reader(binary, pointerSize_);
    const Version108Layout current = makeLayout(reader.pointerSize());
    const size_t p = current.pointerSize;

    Version108Registration result;
    result.layout = current;
    result.metadataRegistrationAddress = metadataRegistrationAddress;
    result.codeRegistrationAddress = codeRegistrationAddress;
    result.metadataRegistration = readMetadataRegistration(binary, metadataRegistrationAddress);
    result.codeRegistration = readCodeRegistration(binary, codeRegistrationAddress);
    const auto& native = result.metadataRegistration;
    const auto& code = result.codeRegistration;

    std::vector<GenericInstModel> genericInsts;
    const auto instPointers = reader.pointerTable(native.genericInsts.address, native.genericInsts.count);
    genericInsts.reserve(instPointers.size());
    for (const uint64_t address : instPointers) {
        GenericInstModel inst;
        inst.address = address;
        if (address != 0) {
            reader.require(address, 2 * p);
            const uint32_t count = reader.u32(address);
            const uint64_t arguments = reader.pointer(checkedAdd(address, p));
            inst.typeAddresses = reader.pointerTable(arguments, count);
        }
        genericInsts.push_back(std::move(inst));
    }

    std::vector<GenericClassModel> genericClasses;
    const auto classPointers = reader.pointerTable(native.genericClasses.address, native.genericClasses.count);
    genericClasses.reserve(classPointers.size());
    const size_t typeCount = typeDefinitionCount(metadata);
    for (const uint64_t address : classPointers) {
        GenericClassModel genericClass;
        genericClass.address = address;
        if (address != 0) {
            reader.require(address, 4 * p);
            genericClass.definitionIndex = reader.i32(address);
            if (genericClass.definitionIndex < -1 ||
                (genericClass.definitionIndex >= 0 &&
                 static_cast<size_t>(genericClass.definitionIndex) >= typeCount)) {
                invalid("generic class definition index is outside the type table");
            }
            genericClass.classInstAddress = reader.pointer(checkedAdd(address, p));
            genericClass.methodInstAddress = reader.pointer(checkedAdd(address, 2 * p));
            genericClass.cachedClassAddress = reader.pointer(checkedAdd(address, 3 * p));
        }
        genericClasses.push_back(genericClass);
    }

    for (auto& spec : metadata.methodSpecs) {
        validateDefinitionIndex(
            spec.methodDefinitionIndex,
            static_cast<int32_t>(std::min<size_t>(methodDefinitionCount(metadata), std::numeric_limits<int32_t>::max())));
        const auto instAddress = [&](int32_t index) {
            if (index == -1) return uint64_t{0};
            if (index < -1 || static_cast<size_t>(index) >= genericInsts.size()) {
                invalid("generic method spec instantiation index is outside the generic inst table");
            }
            return genericInsts[static_cast<size_t>(index)].address;
        };
        spec.classInstAddress = instAddress(spec.classInstIndex);
        spec.methodInstAddress = instAddress(spec.methodInstIndex);
    }

    result.genericMethodPointers = reader.pointerTable(
        code.genericMethodPointers.address, code.genericMethodPointers.count);
    result.invokerPointers = reader.pointerTable(code.invokerPointers.address, code.invokerPointers.count);
    metadata.genericMethodPointers = result.genericMethodPointers;
    metadata.invokerPointers = result.invokerPointers;
    metadata.unresolvedVirtualCallPointers = reader.pointerTable(
        code.unresolvedVirtualCallPointers.address,
        code.unresolvedVirtualCallPointers.count);

    int32_t maximumAdjustor = -1;
    for (const auto& mapping : metadata.genericMethodTable) {
        maximumAdjustor = std::max(maximumAdjustor, mapping.adjustorThunkIndex);
    }
    if (maximumAdjustor >= 0) {
        result.genericAdjustorThunks = reader.pointerTable(
            code.genericAdjustorThunks,
            static_cast<uint64_t>(maximumAdjustor) + 1);
    }

    result.genericMethodTable = metadata.genericMethodTable;
    for (auto& mapping : result.genericMethodTable) {
        if (mapping.genericMethodIndex < 0 ||
            static_cast<size_t>(mapping.genericMethodIndex) >= metadata.methodSpecs.size()) {
            invalid("generic method table index is outside the normalized method spec table");
        }
        mapping.methodPointer = requiredPointer(
            result.genericMethodPointers,
            mapping.methodIndex,
            "generic method pointer index is outside the pointer table");
        mapping.invokerPointer = requiredPointer(
            result.invokerPointers,
            mapping.invokerIndex,
            "generic method invoker index is outside the pointer table");
        if (mapping.adjustorThunkIndex >= 0) {
            mapping.adjustorThunk = requiredPointer(
                result.genericAdjustorThunks,
                mapping.adjustorThunkIndex,
                "generic method adjustor index is outside the adjustor table");
        }
        const auto& spec = metadata.methodSpecs[static_cast<size_t>(mapping.genericMethodIndex)];
        mapping.classInstAddress = spec.classInstAddress;
        mapping.methodInstAddress = spec.methodInstAddress;
    }
    metadata.genericMethodTable = result.genericMethodTable;
    metadata.genericInsts = std::move(genericInsts);
    metadata.genericClasses = std::move(genericClasses);
    metadata.adjustorThunks.clear();

    const auto modulePointers = reader.pointerTable(code.codeGenModules.address, code.codeGenModules.count);
    for (const uint64_t moduleAddress : modulePointers) {
        reader.require(moduleAddress, current.codeGenModuleSize);
        Version108CodeGenModule module;
        module.address = moduleAddress;
        module.name = reader.string(reader.pointer(moduleAddress));
        const uint64_t methodCount = reader.count(checkedAdd(moduleAddress, p));
        module.methodPointers = reader.pointerTable(
            reader.pointer(checkedAdd(moduleAddress, 2 * p)), methodCount);

        const uint64_t adjustorCount = reader.count(
            checkedAdd(moduleAddress, current.adjustorThunkCountOffset));
        const uint64_t adjustorAddress = reader.pointer(
            checkedAdd(moduleAddress, current.adjustorThunksOffset));
        const size_t adjustorSize = checkedSize(adjustorCount, 2 * p);
        if (adjustorSize != 0) reader.require(adjustorAddress, adjustorSize);
        for (size_t index = 0; index < static_cast<size_t>(adjustorCount); ++index) {
            const uint64_t pair = checkedAdd(adjustorAddress, index * 2 * p);
            const uint32_t token = reader.u32(pair);
            const uint64_t thunk = reader.pointer(checkedAdd(pair, p));
            const auto [position, inserted] = module.adjustorThunks.emplace(token, thunk);
            if (!inserted && position->second != thunk) {
                invalid("conflicting virtual adjustor thunks for a method token");
            }
            metadata.adjustorThunks.push_back({token, thunk});
        }

        module.debuggerMetadata = reader.pointer(checkedAdd(moduleAddress, 7 * p));
        module.moduleInitializer = reader.pointer(checkedAdd(moduleAddress, 8 * p));
        module.metadataRegistration = reader.pointer(checkedAdd(moduleAddress, 9 * p));
        module.codeRegistration = reader.pointer(checkedAdd(moduleAddress, 10 * p));

        const auto image = std::find_if(
            metadata.images.begin(), metadata.images.end(),
            [&](const ImageModel& candidate) { return candidate.name == module.name; });
        if (methodCount != 0) {
            if (image == metadata.images.end()) invalid("code-gen module has no matching metadata image");
            if (methodCount > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
                invalid("module invoker index range is too large");
            }
            validateRange(
                image->invokerIndicesStart,
                static_cast<int32_t>(methodCount),
                metadata.invokerIndices.size(),
                "image invoker index range");
            const auto begin = metadata.invokerIndices.begin() + image->invokerIndicesStart;
            module.invokerIndices.assign(begin, begin + static_cast<size_t>(methodCount));
        }

        metadata.methodPointersByImage.insert_or_assign(module.name, module.methodPointers);
        const auto [position, inserted] = result.modules.emplace(module.name, std::move(module));
        if (!inserted) invalid("duplicate code-gen module name: " + position->first);
    }

    metadata.metadataRegistrationAddress = metadataRegistrationAddress;
    metadata.codeRegistrationAddress = codeRegistrationAddress;
    metadata.metadataUsagesCount = native.metadataUsages.count;
    return result;
}

void Version108::validateRgctxRanges(
    const std::vector<RgctxRangeModel>& ranges,
    size_t valueCount) {
    for (const auto& range : ranges) {
        validateRange(range.start, range.count, valueCount, "RGCTX range");
    }
}

uint64_t Version108Registration::select(
    std::string_view imageName,
    uint32_t methodToken,
    Version108MethodPointerKind kind) const noexcept {
    const auto module = modules.find(std::string(imageName));
    if (module == modules.end()) return 0;
    if (kind == Version108MethodPointerKind::Adjustor) {
        const auto thunk = module->second.adjustorThunks.find(methodToken);
        return thunk == module->second.adjustorThunks.end() ? 0 : thunk->second;
    }

    const uint32_t row = methodToken & 0x00FFFFFFU;
    if (row == 0) return 0;
    const size_t index = static_cast<size_t>(row - 1);
    if (kind == Version108MethodPointerKind::Ordinary) {
        return index < module->second.methodPointers.size() ? module->second.methodPointers[index] : 0;
    }
    if (kind == Version108MethodPointerKind::Invoker) {
        if (index >= module->second.invokerIndices.size()) return 0;
        return selectedPointer(invokerPointers, module->second.invokerIndices[index]);
    }
    return 0;
}

uint64_t Version108Registration::select(
    const GenericMethodPointerModel& method,
    Version108MethodPointerKind kind) const noexcept {
    switch (kind) {
    case Version108MethodPointerKind::Ordinary:
        return selectedPointer(genericMethodPointers, method.methodIndex);
    case Version108MethodPointerKind::Adjustor:
        return selectedPointer(genericAdjustorThunks, method.adjustorThunkIndex);
    case Version108MethodPointerKind::Invoker:
        return selectedPointer(invokerPointers, method.invokerIndex);
    }
    return 0;
}

} // namespace il2cpprec
