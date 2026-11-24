#include <il2cpprec/versions/Version29.hpp>

#include <bit>
#include <limits>
#include <stdexcept>
#include <utility>

namespace il2cpprec::versions {
namespace {

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 29 data: " + message);
}

uint64_t checkedAdd(uint64_t value, uint64_t amount) {
    if (amount > std::numeric_limits<uint64_t>::max() - value) {
        invalid("virtual address overflow");
    }
    return value + amount;
}

size_t checkedSize(uint64_t count, size_t stride) {
    if (count > std::numeric_limits<size_t>::max() ||
        static_cast<size_t>(count) > std::numeric_limits<size_t>::max() / stride) {
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

    size_t pointerSize() const {
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
        const int32_t value = i32(address);
        if (value < 0) invalid("negative table count");
        return static_cast<uint32_t>(value);
    }

    void require(uint64_t address, size_t size) const {
        static_cast<void>(bytes(address, size));
    }

    bool readable(uint64_t address, size_t size) const noexcept {
        try {
            require(address, size);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

private:
    const uint8_t* bytes(uint64_t address, size_t size) const {
        uint64_t fileOffset = 0;
        try {
            if (address < binary_.imageBase) throw std::out_of_range("below image base");
            fileOffset = binary_.mapVATR(address - binary_.imageBase);
        } catch (const std::out_of_range&) {
            fileOffset = binary_.mapVATR(address);
        } catch (const std::overflow_error&) {
            fileOffset = binary_.mapVATR(address);
        }
        const auto& data = *binary_.bytes;
        if (fileOffset > data.size() || size > data.size() - static_cast<size_t>(fileOffset)) {
            invalid("read is outside the binary image");
        }
        return data.data() + static_cast<size_t>(fileOffset);
    }

    const BinaryImage& binary_;
    size_t pointerSize_;
};

Version29CodeRegistration readRegistration(
    const ImageReader& reader,
    uint64_t address,
    Version29Subversion subversion) {
    const auto layout = Version29::layout(subversion, reader.pointerSize());
    const size_t p = layout.pointerSize;
    reader.require(address, layout.codeRegistrationSize);

    Version29CodeRegistration registration;
    registration.subversion = subversion;
    registration.address = address;
    registration.reversePInvokeWrapperCount = reader.count(address);
    registration.reversePInvokeWrappersAddress = reader.pointer(checkedAdd(address, p));
    registration.genericMethodPointersCount = reader.count(checkedAdd(address, 2 * p));
    registration.genericMethodPointersAddress = reader.pointer(checkedAdd(address, 3 * p));
    registration.genericAdjustorThunksAddress = reader.pointer(checkedAdd(address, 4 * p));
    registration.invokerPointersCount = reader.count(checkedAdd(address, 5 * p));
    registration.invokerPointersAddress = reader.pointer(checkedAdd(address, 6 * p));
    registration.unresolvedCallCount = reader.count(
        checkedAdd(address, layout.unresolvedCallCountOffset));
    registration.unresolvedVirtualCallPointersAddress = reader.pointer(
        checkedAdd(address, layout.unresolvedVirtualCallPointersOffset));
    if (layout.unresolvedInstanceCallPointersOffset) {
        registration.unresolvedInstanceCallPointersAddress = reader.pointer(
            checkedAdd(address, *layout.unresolvedInstanceCallPointersOffset));
        registration.unresolvedStaticCallPointersAddress = reader.pointer(
            checkedAdd(address, *layout.unresolvedStaticCallPointersOffset));
    }

    const size_t interopOffset = subversion == Version29Subversion::V29_0 ? 9 * p : 11 * p;
    const size_t windowsRuntimeOffset = subversion == Version29Subversion::V29_0 ? 11 * p : 13 * p;
    registration.interopDataCount = reader.count(checkedAdd(address, interopOffset));
    registration.interopDataAddress = reader.pointer(checkedAdd(address, interopOffset + p));
    registration.windowsRuntimeFactoryCount = reader.count(checkedAdd(address, windowsRuntimeOffset));
    registration.windowsRuntimeFactoryTableAddress = reader.pointer(
        checkedAdd(address, windowsRuntimeOffset + p));
    registration.codeGenModulesCount = reader.count(
        checkedAdd(address, layout.codeGenModulesCountOffset));
    registration.codeGenModulesAddress = reader.pointer(
        checkedAdd(address, layout.codeGenModulesOffset));
    return registration;
}

bool hasReadableModuleTable(const Version29CodeRegistration& registration, const ImageReader& reader) {
    if (registration.codeGenModulesCount == 0 || registration.codeGenModulesAddress == 0) return false;
    try {
        const size_t size = checkedSize(registration.codeGenModulesCount, reader.pointerSize());
        return reader.readable(registration.codeGenModulesAddress, size);
    } catch (const std::exception&) {
        return false;
    }
}

MetadataVersionModel detected(
    int32_t rawVersion,
    Version29Subversion subversion,
    MetadataVersionConfidence confidence) {
    MetadataVersionModel model;
    model.rawVersion = rawVersion;
    model.preciseVersion = subversion == Version29Subversion::V29_0 ? 29.0 : 29.1;
    model.registrationVersion = model.preciseVersion;
    model.confidence = confidence;
    return model;
}

} // namespace

GenericClassModel Version29GenericClass::toModel() const {
    GenericClassModel model;
    model.address = address;
    model.definitionIndex = definitionIndex;
    model.classInstAddress = classInstAddress;
    model.methodInstAddress = methodInstAddress;
    model.cachedClassAddress = cachedClassAddress;
    return model;
}

bool Version29::supports(int32_t rawVersion) {
    return rawVersion == 29;
}

Version29Subversion Version29::subversion(double version) {
    if (version >= 29.0 && version < 29.1) return Version29Subversion::V29_0;
    if (version >= 29.1 && version < 29.2) return Version29Subversion::V29_1;
    throw std::invalid_argument("Version29 supports only IL2CPP 29.0 and 29.1");
}

Version29Layout Version29::layout(Version29Subversion subversionValue, size_t pointerSize) {
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
    Version29Layout result;
    result.subversion = subversionValue;
    result.pointerSize = pointerSize;
    result.codeRegistrationSize = (subversionValue == Version29Subversion::V29_0 ? 15 : 17) * pointerSize;
    result.unresolvedCallCountOffset = 7 * pointerSize;
    result.unresolvedVirtualCallPointersOffset = 8 * pointerSize;
    if (subversionValue == Version29Subversion::V29_1) {
        result.unresolvedInstanceCallPointersOffset = 9 * pointerSize;
        result.unresolvedStaticCallPointersOffset = 10 * pointerSize;
    }
    const size_t modulesIndex = subversionValue == Version29Subversion::V29_0 ? 13 : 15;
    result.codeGenModulesCountOffset = modulesIndex * pointerSize;
    result.codeGenModulesOffset = (modulesIndex + 1) * pointerSize;
    result.genericClassTypeOffset = 0;
    result.genericClassClassInstOffset = pointerSize;
    result.genericClassMethodInstOffset = 2 * pointerSize;
    result.genericClassCachedClassOffset = 3 * pointerSize;
    result.genericClassSize = 4 * pointerSize;
    return result;
}

Version29Layout Version29::layout(double version, size_t pointerSize) {
    return layout(subversion(version), pointerSize);
}

MetadataVersionModel Version29::detect(int32_t rawVersion) {
    MetadataVersionModel model;
    model.rawVersion = rawVersion;
    model.preciseVersion = static_cast<double>(rawVersion);
    if (supports(rawVersion)) model.confidence = MetadataVersionConfidence::RawHeader;
    return model;
}

MetadataVersionModel Version29::detect(
    const BinaryImage& binary,
    int32_t rawVersion,
    uint64_t codeRegistrationAddress,
    size_t pointerSize) {
    if (!supports(rawVersion) || codeRegistrationAddress == 0) return detect(rawVersion);
    ImageReader reader(binary, pointerSize);

    std::optional<Version29CodeRegistration> registration29_0;
    std::optional<Version29CodeRegistration> registration29_1;
    try {
        registration29_0 = readRegistration(reader, codeRegistrationAddress, Version29Subversion::V29_0);
    } catch (const std::exception&) {
    }
    try {
        registration29_1 = readRegistration(reader, codeRegistrationAddress, Version29Subversion::V29_1);
    } catch (const std::exception&) {
    }

    const bool modules29_0 = registration29_0 && hasReadableModuleTable(*registration29_0, reader);
    const bool modules29_1 = registration29_1 && hasReadableModuleTable(*registration29_1, reader);
    if (modules29_1 && !modules29_0) {
        return detected(rawVersion, Version29Subversion::V29_1, MetadataVersionConfidence::Registration);
    }
    if (modules29_0) {
        return detected(
            rawVersion,
            Version29Subversion::V29_0,
            modules29_1 ? MetadataVersionConfidence::InferredLayout : MetadataVersionConfidence::Registration);
    }
    return detect(rawVersion);
}

Version29CodeRegistration Version29::readCodeRegistration(
    const BinaryImage& binary,
    uint64_t address,
    Version29Subversion subversionValue,
    size_t pointerSize) {
    return readRegistration(ImageReader(binary, pointerSize), address, subversionValue);
}

Version29CodeRegistration Version29::readCodeRegistration(
    const BinaryImage& binary,
    uint64_t address,
    double version,
    size_t pointerSize) {
    return readCodeRegistration(binary, address, subversion(version), pointerSize);
}

Version29TypeBits Version29::decodeTypeBits(uint32_t bits) {
    Version29TypeBits result;
    result.attrs = static_cast<uint16_t>(bits & 0xFFFFU);
    result.type = static_cast<uint8_t>((bits >> 16) & 0xFFU);
    result.numMods = static_cast<uint8_t>((bits >> 24) & 0x1FU);
    result.byRef = ((bits >> 29) & 1U) != 0;
    result.pinned = ((bits >> 30) & 1U) != 0;
    result.valueType = (bits >> 31) != 0;
    return result;
}

Version29Type Version29::readType(const BinaryImage& binary, uint64_t address, size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    Version29Type result;
    result.address = address;
    result.data = reader.pointer(address);
    result.bits = reader.u32(checkedAdd(address, reader.pointerSize()));
    result.decoded = decodeTypeBits(result.bits);
    return result;
}

Version29GenericClass Version29::readGenericClass(
    const BinaryImage& binary,
    uint64_t address,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const auto currentLayout = layout(Version29Subversion::V29_0, reader.pointerSize());
    reader.require(address, currentLayout.genericClassSize);

    Version29GenericClass result;
    result.address = address;
    result.typeAddress = reader.pointer(checkedAdd(address, currentLayout.genericClassTypeOffset));
    result.classInstAddress = reader.pointer(checkedAdd(address, currentLayout.genericClassClassInstOffset));
    result.methodInstAddress = reader.pointer(checkedAdd(address, currentLayout.genericClassMethodInstOffset));
    result.cachedClassAddress = reader.pointer(checkedAdd(address, currentLayout.genericClassCachedClassOffset));
    if (result.typeAddress != 0) result.definitionIndex = reader.i32(result.typeAddress);
    return result;
}

std::vector<Version29GenericClass> Version29::readGenericClasses(
    const BinaryImage& binary,
    uint64_t address,
    uint64_t count,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);
    const size_t tableSize = checkedSize(count, reader.pointerSize());
    if (tableSize != 0) reader.require(address, tableSize);

    std::vector<Version29GenericClass> result;
    result.reserve(static_cast<size_t>(count));
    for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
        const uint64_t classAddress = reader.pointer(
            checkedAdd(address, index * reader.pointerSize()));
        if (classAddress == 0) {
            result.emplace_back();
        } else {
            result.push_back(readGenericClass(binary, classAddress, reader.pointerSize()));
        }
    }
    return result;
}

GenericMethodPointerModel Version29::readGenericMethodRow(const BinaryImage& binary, uint64_t address) {
    ImageReader reader(binary, 4);
    reader.require(address, 16);
    GenericMethodPointerModel result;
    result.genericMethodIndex = reader.i32(address);
    result.methodIndex = reader.i32(checkedAdd(address, 4));
    result.invokerIndex = reader.i32(checkedAdd(address, 8));
    result.adjustorThunkIndex = reader.i32(checkedAdd(address, 12));
    return result;
}

std::vector<GenericMethodPointerModel> Version29::readGenericMethodRows(
    const BinaryImage& binary,
    uint64_t address,
    uint64_t count) {
    ImageReader reader(binary, 4);
    const size_t tableSize = checkedSize(count, 16);
    if (tableSize != 0) reader.require(address, tableSize);

    std::vector<GenericMethodPointerModel> result;
    result.reserve(static_cast<size_t>(count));
    for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
        result.push_back(readGenericMethodRow(binary, checkedAdd(address, index * 16)));
    }
    return result;
}

} // namespace il2cpprec::versions
