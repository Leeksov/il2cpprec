#include <il2cpprec/versions/Version27Base.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace il2cpprec::versions {
namespace {

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 27.0 data: " + message);
}

uint64_t checkedAdd(uint64_t value, uint64_t amount) {
    if (amount > std::numeric_limits<uint64_t>::max() - value) {
        invalid("virtual address overflow");
    }
    return value + amount;
}

size_t checkedTableSize(uint64_t count, size_t stride) {
    if (stride != 0 && (count > std::numeric_limits<size_t>::max() ||
                        static_cast<size_t>(count) > std::numeric_limits<size_t>::max() / stride)) {
        invalid("table size overflow");
    }
    return static_cast<size_t>(count) * stride;
}

size_t inferredPointerSize(const BinaryImage& binary, size_t requested) {
    if (requested == 4 || requested == 8) return requested;
    if (requested != 0) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
    switch (binary.architecture) {
    case Architecture::Arm32:
    case Architecture::X86:
        return 4;
    case Architecture::Arm64:
    case Architecture::X64:
        return 8;
    }
    throw std::invalid_argument("Unsupported IL2CPP binary architecture");
}

class ImageReader {
public:
    ImageReader(const BinaryImage& binary, size_t pointerSize)
        : binary_(binary), pointerSize_(inferredPointerSize(binary, pointerSize)) {
        if (!binary.bytes) invalid("binary image has no data");
    }

    size_t pointerSize() const noexcept {
        return pointerSize_;
    }

    uint32_t u32(uint64_t address) const {
        const auto* data = bytes(address, 4);
        return static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << 8) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 24);
    }

    int32_t i32(uint64_t address) const {
        return std::bit_cast<int32_t>(u32(address));
    }

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
        const uint64_t raw = pointer(address);
        if (raw > std::numeric_limits<uint32_t>::max()) {
            invalid("table count exceeds 32 bits");
        }
        const int32_t value = std::bit_cast<int32_t>(static_cast<uint32_t>(raw));
        if (value < 0) invalid("negative table count");
        return static_cast<uint32_t>(value);
    }

    Version27NativeTable table(uint64_t address) const {
        return Version27NativeTable{count(address), pointer(checkedAdd(address, pointerSize_))};
    }

    std::vector<uint64_t> pointerTable(uint64_t address, uint64_t count) const {
        const size_t size = checkedTableSize(count, pointerSize_);
        if (size != 0) require(address, size);
        std::vector<uint64_t> result;
        result.reserve(static_cast<size_t>(count));
        for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
            result.push_back(pointer(checkedAdd(address, index * pointerSize_)));
        }
        return result;
    }

    std::vector<int32_t> int32Table(uint64_t address, uint64_t count) const {
        const size_t size = checkedTableSize(count, sizeof(int32_t));
        if (size != 0) require(address, size);
        std::vector<int32_t> result;
        result.reserve(static_cast<size_t>(count));
        for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
            result.push_back(i32(checkedAdd(address, index * sizeof(int32_t))));
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
        if (length == limit) invalid("unterminated code-gen module name");
        return std::string(reinterpret_cast<const char*>(data.data() + offset), length);
    }

    void require(uint64_t address, size_t size) const {
        static_cast<void>(bytes(address, size));
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
            if (address >= binary_.imageBase) {
                found = map(address - binary_.imageBase, mapped);
            }
            if (!found && address <= std::numeric_limits<uint64_t>::max() - binary_.imageBase) {
                found = map(binary_.imageBase + address, mapped);
            }
            if (!found) invalid("virtual address is not backed by a file range");
        }
        if (mapped > std::numeric_limits<size_t>::max()) invalid("file offset exceeds the host size type");
        const size_t offset = static_cast<size_t>(mapped);
        if (offset > binary_.bytes->size() || size > binary_.bytes->size() - offset) {
            invalid("read is outside the binary image");
        }
        return offset;
    }

    const BinaryImage& binary_;
    size_t pointerSize_;
};

template<typename Range>
void validateRanges(const std::vector<Range>& ranges, size_t totalCount, const char* label) {
    for (const auto& range : ranges) {
        if (range.start < 0 || range.count < 0) {
            invalid(std::string(label) + " has a negative range");
        }
        const auto start = static_cast<size_t>(range.start);
        const auto count = static_cast<size_t>(range.count);
        if (start > totalCount || count > totalCount - start) {
            invalid(std::string(label) + " is outside its target table");
        }
    }
}

} // namespace

GenericClassModel Version27GenericClass::toModel() const {
    GenericClassModel model;
    model.address = address;
    model.definitionIndex = definitionIndex;
    model.classInstAddress = classInstAddress;
    model.methodInstAddress = methodInstAddress;
    model.cachedClassAddress = cachedClassAddress;
    return model;
}

const Version27CodeGenModule* Version27Registration::findModule(std::string_view imageName) const noexcept {
    const auto found = std::find_if(modules.begin(), modules.end(), [&](const auto& module) {
        return module.name == imageName;
    });
    return found == modules.end() ? nullptr : &*found;
}

std::optional<uint64_t> Version27Registration::methodPointer(
    std::string_view imageName,
    uint32_t methodDefToken) const noexcept {
    const auto* module = findModule(imageName);
    const auto index = Version27Base::methodPointerIndex(methodDefToken);
    if (!module || !index || *index >= module->methodPointers.size()) return std::nullopt;
    return module->methodPointers[*index];
}

uint64_t Version27Registration::select(
    std::string_view imageName,
    uint32_t methodDefToken,
    Version27MethodPointerKind kind) const noexcept {
    const auto* module = findModule(imageName);
    const auto index = Version27Base::methodPointerIndex(methodDefToken);
    if (!module || !index || *index >= module->methodPointers.size()) return 0;
    if (kind == Version27MethodPointerKind::Ordinary) return module->methodPointers[*index];
    if (*index >= module->invokerIndices.size()) return 0;
    const int32_t invokerIndex = module->invokerIndices[*index];
    if (invokerIndex < 0 || static_cast<size_t>(invokerIndex) >= invokerPointers.size()) return 0;
    return invokerPointers[static_cast<size_t>(invokerIndex)];
}

bool Version27Base::supports(int32_t rawVersion) noexcept {
    return rawVersion == 27;
}

bool Version27Base::supports(double metadataVersion) noexcept {
    return metadataVersion == 27.0;
}

size_t Version27Base::pointerSize(const BinaryImage& binary) {
    return inferredPointerSize(binary, 0);
}

Version27Layout Version27Base::layout(size_t pointerSize) {
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }

    Version27Layout result;
    result.pointerSize = pointerSize;
    result.typeSize = pointerSize + sizeof(uint32_t);
    result.codeRegistrationSize = Version27Layout::codeRegistrationSlotCount * pointerSize;
    result.codeGenModuleSize = Version27Layout::codeGenModuleSlotCount * pointerSize;
    result.genericClassClassInstOffset = pointerSize;
    result.genericClassMethodInstOffset = 2 * pointerSize;
    result.genericClassCachedClassOffset = 3 * pointerSize;
    result.genericClassSize = 4 * pointerSize;
    result.methodPointerCountOffset = pointerSize;
    result.methodPointersOffset = 2 * pointerSize;
    result.invokerIndicesOffset = 3 * pointerSize;
    result.rgctxRangesCountOffset = 6 * pointerSize;
    result.rgctxRangesOffset = 7 * pointerSize;
    result.rgctxsCountOffset = 8 * pointerSize;
    result.rgctxsOffset = 9 * pointerSize;
    result.customAttributeCacheGeneratorOffset = 11 * pointerSize;
    result.metadataRegistrationOffset = 14 * pointerSize;
    result.codeRegistrationOffset = 15 * pointerSize;
    return result;
}

std::optional<size_t> Version27Base::methodPointerIndex(uint32_t token) noexcept {
    constexpr uint32_t methodDefinitionToken = 0x06000000;
    constexpr uint32_t rowIdMask = 0x00ffffff;
    if ((token & ~rowIdMask) != methodDefinitionToken) return std::nullopt;
    const uint32_t rowId = token & rowIdMask;
    if (rowId == 0) return std::nullopt;
    return static_cast<size_t>(rowId - 1);
}

Version27CodeRegistration Version27Base::readCodeRegistration(
    const BinaryImage& binary,
    uint64_t address,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const auto currentLayout = layout(reader.pointerSize());
    reader.require(address, currentLayout.codeRegistrationSize);

    Version27CodeRegistration result;
    result.address = address;
    result.reversePInvokeWrappers = reader.table(address);
    result.genericMethodPointers = reader.table(checkedAdd(address, 2 * reader.pointerSize()));
    result.invokerPointers = reader.table(checkedAdd(address, 4 * reader.pointerSize()));
    result.unresolvedVirtualCallPointers = reader.table(checkedAdd(address, 6 * reader.pointerSize()));
    result.interopData = reader.table(checkedAdd(address, 8 * reader.pointerSize()));
    result.windowsRuntimeFactoryTable = reader.table(checkedAdd(address, 10 * reader.pointerSize()));
    result.codeGenModules = reader.table(checkedAdd(address, 12 * reader.pointerSize()));
    return result;
}

Version27TypeBits Version27Base::decodeTypeBits(uint32_t bits) noexcept {
    Version27TypeBits result;
    result.attrs = static_cast<uint16_t>(bits & 0xffffU);
    result.type = static_cast<uint8_t>((bits >> 16) & 0xffU);
    result.numMods = static_cast<uint8_t>((bits >> 24) & 0x3fU);
    result.byRef = ((bits >> 30) & 1U) != 0;
    result.pinned = (bits >> 31) != 0;
    return result;
}

Version27Type Version27Base::readType(
    const BinaryImage& binary,
    uint64_t address,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    reader.require(address, layout(reader.pointerSize()).typeSize);

    Version27Type result;
    result.address = address;
    result.data = reader.pointer(address);
    result.bits = reader.u32(checkedAdd(address, reader.pointerSize()));
    result.decoded = decodeTypeBits(result.bits);
    return result;
}

Version27GenericClass Version27Base::readGenericClass(
    const BinaryImage& binary,
    uint64_t address,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const auto currentLayout = layout(reader.pointerSize());
    reader.require(address, currentLayout.genericClassSize);

    Version27GenericClass result;
    result.address = address;
    result.typeAddress = reader.pointer(checkedAdd(address, currentLayout.genericClassTypeOffset));
    result.classInstAddress = reader.pointer(checkedAdd(address, currentLayout.genericClassClassInstOffset));
    result.methodInstAddress = reader.pointer(checkedAdd(address, currentLayout.genericClassMethodInstOffset));
    result.cachedClassAddress = reader.pointer(checkedAdd(address, currentLayout.genericClassCachedClassOffset));
    if (result.typeAddress != 0) result.definitionIndex = reader.i32(result.typeAddress);
    return result;
}

std::vector<Version27GenericClass> Version27Base::readGenericClasses(
    const BinaryImage& binary,
    uint64_t address,
    uint64_t count,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const auto addresses = reader.pointerTable(address, count);
    std::vector<Version27GenericClass> result;
    result.reserve(addresses.size());
    for (const uint64_t classAddress : addresses) {
        if (classAddress == 0) {
            result.emplace_back();
        } else {
            result.push_back(readGenericClass(binary, classAddress, reader.pointerSize()));
        }
    }
    return result;
}

std::vector<RgctxRangeModel> Version27Base::readRgctxRanges(
    const BinaryImage& binary,
    uint64_t address,
    uint64_t count,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const size_t size = checkedTableSize(count, Version27Layout::rgctxRangeSize);
    if (size != 0) reader.require(address, size);

    std::vector<RgctxRangeModel> result;
    result.reserve(static_cast<size_t>(count));
    for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
        const uint64_t entry = checkedAdd(address, index * Version27Layout::rgctxRangeSize);
        result.push_back(RgctxRangeModel{
            reader.u32(entry),
            reader.i32(checkedAdd(entry, 4)),
            reader.i32(checkedAdd(entry, 8))});
    }
    return result;
}

std::vector<RgctxValueModel> Version27Base::readRgctxDefinitions(
    const BinaryImage& binary,
    uint64_t address,
    uint64_t count,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const size_t size = checkedTableSize(count, Version27Layout::rgctxDefinitionSize);
    if (size != 0) reader.require(address, size);

    std::vector<RgctxValueModel> result;
    result.reserve(static_cast<size_t>(count));
    for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
        const uint64_t entry = checkedAdd(address, index * Version27Layout::rgctxDefinitionSize);
        result.push_back(RgctxValueModel{
            static_cast<uint32_t>(reader.i32(entry)),
            static_cast<uint32_t>(reader.i32(checkedAdd(entry, 4)))});
    }
    return result;
}

void Version27Base::validateRgctxRanges(
    const std::vector<RgctxRangeModel>& ranges,
    size_t definitionCount) {
    validateRanges(ranges, definitionCount, "RGCTX range");
}

Version27CodeGenModule Version27Base::readCodeGenModule(
    const BinaryImage& binary,
    uint64_t address,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const auto currentLayout = layout(reader.pointerSize());
    reader.require(address, currentLayout.codeGenModuleSize);

    Version27CodeGenModule result;
    result.address = address;
    result.name = reader.string(reader.pointer(address));
    const uint64_t methodCount = reader.count(checkedAdd(address, currentLayout.methodPointerCountOffset));
    result.methodPointers = reader.pointerTable(
        reader.pointer(checkedAdd(address, currentLayout.methodPointersOffset)),
        methodCount);
    result.invokerIndices = reader.int32Table(
        reader.pointer(checkedAdd(address, currentLayout.invokerIndicesOffset)),
        methodCount);
    result.reversePInvokeWrapperIndices = reader.table(checkedAdd(address, 4 * reader.pointerSize()));

    const auto ranges = reader.table(checkedAdd(address, currentLayout.rgctxRangesCountOffset));
    const auto values = reader.table(checkedAdd(address, currentLayout.rgctxsCountOffset));
    result.rgctxRanges = readRgctxRanges(binary, ranges.address, ranges.count, reader.pointerSize());
    result.rgctxValues = readRgctxDefinitions(binary, values.address, values.count, reader.pointerSize());
    validateRgctxRanges(result.rgctxRanges, result.rgctxValues.size());

    result.debuggerMetadata = reader.pointer(checkedAdd(address, 10 * reader.pointerSize()));
    result.customAttributeCacheGenerator = reader.pointer(
        checkedAdd(address, currentLayout.customAttributeCacheGeneratorOffset));
    result.moduleInitializer = reader.pointer(checkedAdd(address, 12 * reader.pointerSize()));
    result.staticConstructorTypeIndicesAddress = reader.pointer(checkedAdd(address, 13 * reader.pointerSize()));
    result.metadataRegistrationAddress = reader.pointer(
        checkedAdd(address, currentLayout.metadataRegistrationOffset));
    result.codeRegistrationAddress = reader.pointer(checkedAdd(address, currentLayout.codeRegistrationOffset));
    return result;
}

std::vector<Version27CodeGenModule> Version27Base::readCodeGenModules(
    const BinaryImage& binary,
    uint64_t address,
    uint64_t count,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const auto addresses = reader.pointerTable(address, count);
    std::vector<Version27CodeGenModule> result;
    result.reserve(addresses.size());
    for (const uint64_t moduleAddress : addresses) {
        if (moduleAddress == 0) invalid("null code-gen module pointer");
        result.push_back(readCodeGenModule(binary, moduleAddress, reader.pointerSize()));
    }
    return result;
}

Version27Registration Version27Base::read(
    const BinaryImage& binary,
    uint64_t codeRegistrationAddress,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    Version27Registration result;
    result.layout = layout(reader.pointerSize());
    result.codeRegistrationAddress = codeRegistrationAddress;
    result.codeRegistration = readCodeRegistration(binary, codeRegistrationAddress, reader.pointerSize());
    result.genericMethodPointers = reader.pointerTable(
        result.codeRegistration.genericMethodPointers.address,
        result.codeRegistration.genericMethodPointers.count);
    result.invokerPointers = reader.pointerTable(
        result.codeRegistration.invokerPointers.address,
        result.codeRegistration.invokerPointers.count);
    result.modules = readCodeGenModules(
        binary,
        result.codeRegistration.codeGenModules.address,
        result.codeRegistration.codeGenModules.count,
        reader.pointerSize());
    for (size_t index = 0; index < result.modules.size(); ++index) {
        for (size_t previous = 0; previous < index; ++previous) {
            if (result.modules[index].name == result.modules[previous].name) {
                invalid("duplicate code-gen module name: " + result.modules[index].name);
            }
        }
    }
    return result;
}

std::vector<Version27CustomAttributeTypeRange> Version27Base::readCustomAttributeTypeRanges(
    const BinaryImage& binary,
    uint64_t address,
    uint64_t count,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const size_t size = checkedTableSize(count, Version27Layout::customAttributeTypeRangeSize);
    if (size != 0) reader.require(address, size);

    std::vector<Version27CustomAttributeTypeRange> result;
    result.reserve(static_cast<size_t>(count));
    for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
        const uint64_t entry = checkedAdd(address, index * Version27Layout::customAttributeTypeRangeSize);
        result.push_back(Version27CustomAttributeTypeRange{
            reader.u32(entry),
            reader.i32(checkedAdd(entry, 4)),
            reader.i32(checkedAdd(entry, 8))});
    }
    return result;
}

void Version27Base::validateCustomAttributeTypeRanges(
    const std::vector<Version27CustomAttributeTypeRange>& ranges,
    size_t attributeTypeCount) {
    validateRanges(ranges, attributeTypeCount, "custom attribute type range");
}

Version27CustomAttributeGenerators Version27Base::readCustomAttributeGenerators(
    const BinaryImage& binary,
    const Version27CodeGenModule& module,
    int32_t imageStart,
    uint32_t imageCount,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    if (imageCount == 0) return Version27CustomAttributeGenerators{imageStart, {}};
    if (imageStart < 0) invalid("custom attribute image start is negative");
    if (imageCount > static_cast<uint32_t>(std::numeric_limits<int32_t>::max() - imageStart)) {
        invalid("custom attribute image range overflows the global table");
    }
    if (module.customAttributeCacheGenerator == 0) {
        invalid("custom attribute generator table is null");
    }

    Version27CustomAttributeGenerators result;
    result.imageStart = imageStart;
    result.addresses = reader.pointerTable(module.customAttributeCacheGenerator, imageCount);
    return result;
}

} // namespace il2cpprec::versions
