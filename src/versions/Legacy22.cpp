#include <il2cpprec/versions/Legacy22.hpp>

#include <il2cpprec/metadata/GlobalMetadata.hpp>
#include <il2cpprec/metadata/MetadataRegistration.hpp>

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace il2cpprec {
namespace {

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 22/23 registration: " + message);
}

[[noreturn]] void invalidGlobal(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 22/23 global metadata: " + message);
}

uint64_t checkedAdd(uint64_t value, uint64_t amount) {
    if (amount > std::numeric_limits<uint64_t>::max() - value) {
        invalid("virtual address overflow");
    }
    return value + amount;
}

size_t checkedTableSize(uint64_t count, size_t stride) {
    if (stride == 0) invalid("table stride is zero");
    if (count > std::numeric_limits<size_t>::max() ||
        static_cast<size_t>(count) > std::numeric_limits<size_t>::max() / stride) {
        invalid("table size overflow");
    }
    return static_cast<size_t>(count) * stride;
}

size_t inferredPointerSize(const BinaryImage& binary, size_t requested) {
    if (requested != 0) return requested;
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

void requirePointerSize(size_t pointerSize) {
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
}

class ImageReader {
public:
    ImageReader(const BinaryImage& binary, size_t pointerSize)
        : binary_(binary), pointerSize_(pointerSize) {
        requirePointerSize(pointerSize);
        if (!binary.bytes) invalid("binary image has no data");
    }

    size_t pointerSize() const { return pointerSize_; }

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

    int64_t i64(uint64_t address) const {
        return std::bit_cast<int64_t>(u64(address));
    }

    uint64_t pointer(uint64_t address) const {
        return pointerSize_ == 4 ? u32(address) : u64(address);
    }

    uint64_t count(uint64_t address, const char* tableName) const {
        const int64_t value = pointerSize_ == 4 ? i32(address) : i64(address);
        if (value < 0) invalid(std::string(tableName) + " has a negative count");
        return static_cast<uint64_t>(value);
    }

    std::vector<uint64_t> pointerTable(uint64_t address, uint64_t count, const char* tableName) const {
        const size_t size = checkedTableSize(count, pointerSize_);
        if (size != 0) {
            if (address == 0) invalid(std::string(tableName) + " has a null address");
            require(address, size);
        }
        std::vector<uint64_t> result;
        result.reserve(static_cast<size_t>(count));
        for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
            result.push_back(pointer(checkedAdd(address, index * pointerSize_)));
        }
        return result;
    }

    void require(uint64_t address, size_t size) const {
        bytes(address, size);
    }

    std::array<uint8_t, 16> guid(uint64_t address) const {
        const auto* data = bytes(address, 16);
        std::array<uint8_t, 16> result{};
        std::copy_n(data, result.size(), result.begin());
        return result;
    }

private:
    const uint8_t* bytes(uint64_t address, size_t size) const {
        if (address < binary_.imageBase) invalid("virtual address is below the image base");
        uint64_t fileOffset = 0;
        try {
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

struct NativeTable {
    uint64_t address = 0;
    uint64_t count = 0;
};

NativeTable readTable(
    const ImageReader& reader,
    uint64_t base,
    size_t pairIndex,
    const char* name) {
    const size_t pointerSize = reader.pointerSize();
    const uint64_t address = checkedAdd(base, pairIndex * 2 * pointerSize);
    return {
        reader.pointer(checkedAdd(address, pointerSize)),
        reader.count(address, name)
    };
}

std::vector<uint64_t> readPointers(
    const ImageReader& reader,
    const NativeTable& table,
    const char* name) {
    return reader.pointerTable(table.address, table.count, name);
}

struct NativeMetadataRegistration {
    MetadataRegistrationInfo info;
    NativeTable metadataUsages;
};

NativeMetadataRegistration readMetadataRegistration(
    const ImageReader& reader,
    uint64_t metadataRegistrationAddress,
    uint64_t codeRegistrationAddress) {
    const size_t pointerSize = reader.pointerSize();
    reader.require(metadataRegistrationAddress, 16 * pointerSize);

    NativeMetadataRegistration result;
    result.info.metadataRegistrationAddress = metadataRegistrationAddress;
    result.info.codeRegistrationAddress = codeRegistrationAddress;

    const auto genericClasses = readTable(reader, metadataRegistrationAddress, 0, "genericClasses");
    const auto genericInsts = readTable(reader, metadataRegistrationAddress, 1, "genericInsts");
    const auto genericMethodTable = readTable(reader, metadataRegistrationAddress, 2, "genericMethodTable");
    const auto types = readTable(reader, metadataRegistrationAddress, 3, "types");
    const auto methodSpecs = readTable(reader, metadataRegistrationAddress, 4, "methodSpecs");
    const auto fieldOffsets = readTable(reader, metadataRegistrationAddress, 5, "fieldOffsets");
    readTable(reader, metadataRegistrationAddress, 6, "typeDefinitionsSizes");
    result.metadataUsages = readTable(reader, metadataRegistrationAddress, 7, "metadataUsages");

    result.info.genericClassesAddress = genericClasses.address;
    result.info.genericClassesCount = genericClasses.count;
    result.info.genericInstsAddress = genericInsts.address;
    result.info.genericInstsCount = genericInsts.count;
    result.info.genericMethodTableAddress = genericMethodTable.address;
    result.info.genericMethodTableCount = genericMethodTable.count;
    result.info.typesAddress = types.address;
    result.info.typesCount = types.count;
    result.info.methodSpecsAddress = methodSpecs.address;
    result.info.methodSpecsCount = methodSpecs.count;
    result.info.fieldOffsetsAddress = fieldOffsets.address;
    result.info.fieldOffsetsCount = fieldOffsets.count;
    result.info.metadataUsagesCount = result.metadataUsages.count;
    return result;
}

class FileReader {
public:
    explicit FileReader(const std::vector<uint8_t>& data) : data_(data) {}

    uint32_t u32(size_t offset) const {
        require(offset, 4);
        return static_cast<uint32_t>(data_[offset]) |
            (static_cast<uint32_t>(data_[offset + 1]) << 8) |
            (static_cast<uint32_t>(data_[offset + 2]) << 16) |
            (static_cast<uint32_t>(data_[offset + 3]) << 24);
    }

    int32_t i32(size_t offset) const {
        return std::bit_cast<int32_t>(u32(offset));
    }

    void require(size_t offset, size_t size) const {
        if (offset > data_.size() || size > data_.size() - offset) {
            invalidGlobal("read is outside the file");
        }
    }

private:
    const std::vector<uint8_t>& data_;
};

size_t fileTableCount(
    const FileReader& reader,
    size_t offsetField,
    size_t stride,
    const char* name,
    uint32_t& offset) {
    offset = reader.u32(offsetField);
    const int32_t signedSize = reader.i32(offsetField + 4);
    if (signedSize < 0) invalidGlobal(std::string(name) + " has a negative size");
    const size_t size = static_cast<size_t>(signedSize);
    if (size % stride != 0) invalidGlobal(std::string(name) + " has a misaligned size");
    if (size != 0) reader.require(offset, size);
    return size / stride;
}

void readUnresolvedSignatures(const std::vector<uint8_t>& data, MetadataModel& metadata) {
    FileReader reader(data);
    reader.require(0, metadata.version == 22.0 ? 256 : 264);
    uint32_t parameterTypesOffset = 0;
    uint32_t parameterRangesOffset = 0;
    const size_t parameterTypeCount = fileTableCount(
        reader, 240, sizeof(int32_t), "unresolved virtual parameter types", parameterTypesOffset);
    const size_t rangeCount = fileTableCount(
        reader, 248, 8, "unresolved virtual parameter ranges", parameterRangesOffset);

    std::vector<UnresolvedSignatureModel> signatures;
    signatures.reserve(rangeCount);
    for (size_t index = 0; index < rangeCount; ++index) {
        const size_t offset = static_cast<size_t>(parameterRangesOffset) + index * 8;
        UnresolvedSignatureModel signature;
        signature.start = reader.i32(offset);
        signature.count = reader.i32(offset + 4);
        if (signature.start < 0 || signature.count < 0 ||
            static_cast<uint64_t>(static_cast<uint32_t>(signature.start)) +
                static_cast<uint32_t>(signature.count) > parameterTypeCount) {
            invalidGlobal("unresolved virtual parameter range is outside the type table");
        }
        signature.parameterTypeIndices.reserve(static_cast<size_t>(signature.count));
        for (size_t parameterIndex = 0; parameterIndex < static_cast<size_t>(signature.count); ++parameterIndex) {
            const size_t parameterOffset = static_cast<size_t>(parameterTypesOffset) +
                (static_cast<size_t>(signature.start) + parameterIndex) * sizeof(int32_t);
            signature.parameterTypeIndices.push_back(reader.i32(parameterOffset));
        }
        signatures.push_back(std::move(signature));
    }
    metadata.unresolvedSignatures = std::move(signatures);
}

void validateGlobalVersion(const std::vector<uint8_t>& data) {
    FileReader reader(data);
    reader.require(0, 8);
    if (reader.u32(0) != 0xFAB11BAF) invalidGlobal("incorrect sanity value");
    const int32_t version = reader.i32(4);
    if (version != 22 && version != 23) {
        throw std::invalid_argument("Legacy22Reader requires global metadata version 22 or 23");
    }
}

} // namespace

Legacy22Reader::Legacy22Reader(size_t pointerSize) : pointerSize_(pointerSize) {
    if (pointerSize != 0) requirePointerSize(pointerSize);
}

bool Legacy22Reader::supports(double metadataVersion) noexcept {
    return metadataVersion == 22.0 || metadataVersion == 23.0;
}

size_t Legacy22Reader::codeRegistrationSize(double metadataVersion, size_t pointerSize) {
    if (!supports(metadataVersion)) {
        throw std::invalid_argument("Legacy22Reader requires metadata version 22 or 23");
    }
    requirePointerSize(pointerSize);
    return (metadataVersion == 22.0 ? 20 : 14) * pointerSize;
}

size_t Legacy22Reader::interopDataSize(size_t pointerSize) {
    requirePointerSize(pointerSize);
    return 7 * pointerSize;
}

MetadataModel Legacy22Reader::readGlobalMetadata(const std::vector<uint8_t>& globalMetadata) const {
    validateGlobalVersion(globalMetadata);
    auto metadata = GlobalMetadata{}.read(globalMetadata);
    if (!supports(metadata.version)) {
        throw std::invalid_argument("Legacy22Reader requires global metadata version 22 or 23");
    }
    readUnresolvedSignatures(globalMetadata, metadata);
    return metadata;
}

MetadataUsageResult Legacy22Reader::readMetadataUsages(
    const std::vector<uint8_t>& globalMetadata,
    const MetadataModel* metadata,
    const MetadataUsageGenericMethodResolver& genericMethods) const {
    validateGlobalVersion(globalMetadata);
    FileReader reader(globalMetadata);
    reader.require(0, reader.i32(4) == 22 ? 256 : 264);

    const int32_t listsSize = reader.i32(196);
    const int32_t pairsSize = reader.i32(204);
    const int32_t fieldRefsSize = reader.i32(212);
    if (listsSize < 0 || pairsSize < 0 || fieldRefsSize < 0) {
        MetadataUsageResult result;
        result.diagnostics.push_back({
            MetadataUsageStatus::Unresolved,
            "negative-table-size",
            "MetadataUsage table sizes must not be negative",
            std::nullopt,
            std::nullopt,
            std::nullopt
        });
        return result;
    }

    MetadataUsageTableView tables;
    tables.data = globalMetadata.data();
    tables.size = globalMetadata.size();
    tables.listsOffset = reader.u32(192);
    tables.listsSize = static_cast<size_t>(listsSize);
    tables.pairsOffset = reader.u32(200);
    tables.pairsSize = static_cast<size_t>(pairsSize);
    tables.fieldRefsOffset = reader.u32(208);
    tables.fieldRefsSize = static_cast<size_t>(fieldRefsSize);
    return MetadataUsageReader{}.read(tables, metadata, genericMethods);
}

Legacy22CodeRegistration Legacy22Reader::readCodeRegistration(
    const BinaryImage& binary,
    double metadataVersion,
    uint64_t codeRegistrationAddress) const {
    if (!supports(metadataVersion)) {
        throw std::invalid_argument("Legacy22Reader requires metadata version 22 or 23");
    }
    if (codeRegistrationAddress == 0) {
        throw std::invalid_argument("IL2CPP code registration address is zero");
    }

    const size_t pointerSize = inferredPointerSize(binary, pointerSize_);
    ImageReader reader(binary, pointerSize);
    reader.require(codeRegistrationAddress, codeRegistrationSize(metadataVersion, pointerSize));

    Legacy22CodeRegistration result;
    const auto methodPointers = readTable(reader, codeRegistrationAddress, 0, "methodPointers");
    const auto reversePInvokeWrappers = readTable(reader, codeRegistrationAddress, 1, "reversePInvokeWrappers");
    result.methodPointers = readPointers(reader, methodPointers, "methodPointers");
    result.reversePInvokeWrappers = readPointers(reader, reversePInvokeWrappers, "reversePInvokeWrappers");

    size_t genericMethodPair = 2;
    if (metadataVersion == 22.0) {
        const auto delegates = readTable(reader, codeRegistrationAddress, 2, "delegateWrappersFromManagedToNative");
        const auto marshaling = readTable(reader, codeRegistrationAddress, 3, "marshalingFunctions");
        const auto ccw = readTable(reader, codeRegistrationAddress, 4, "ccwMarshalingFunctions");
        result.delegateWrappersFromManagedToNative = readPointers(
            reader, delegates, "delegateWrappersFromManagedToNative");
        result.marshalingFunctions = readPointers(reader, marshaling, "marshalingFunctions");
        result.ccwMarshalingFunctions = readPointers(reader, ccw, "ccwMarshalingFunctions");
        genericMethodPair = 5;
    }

    const auto genericMethods = readTable(reader, codeRegistrationAddress, genericMethodPair, "genericMethodPointers");
    const auto invokers = readTable(reader, codeRegistrationAddress, genericMethodPair + 1, "invokerPointers");
    const auto customAttributes = readTable(reader, codeRegistrationAddress, genericMethodPair + 2, "customAttributeGenerators");
    result.genericMethodPointers = readPointers(reader, genericMethods, "genericMethodPointers");
    result.invokerPointers = readPointers(reader, invokers, "invokerPointers");
    result.customAttributeGenerators = readPointers(reader, customAttributes, "customAttributeGenerators");

    size_t unresolvedPair = genericMethodPair + 3;
    if (metadataVersion == 22.0) {
        const auto guids = readTable(reader, codeRegistrationAddress, genericMethodPair + 3, "guids");
        const auto guidPointers = readPointers(reader, guids, "guids");
        result.guids.reserve(guidPointers.size());
        for (const uint64_t address : guidPointers) {
            if (address == 0) invalid("guids contains a null entry");
            result.guids.push_back({address, reader.guid(address)});
        }
        unresolvedPair = genericMethodPair + 4;
    }

    const auto unresolved = readTable(reader, codeRegistrationAddress, unresolvedPair, "unresolvedVirtualCallPointers");
    result.unresolvedVirtualCallPointers = readPointers(reader, unresolved, "unresolvedVirtualCallPointers");

    if (metadataVersion == 23.0) {
        const auto interop = readTable(reader, codeRegistrationAddress, unresolvedPair + 1, "interopData");
        const size_t stride = interopDataSize(pointerSize);
        const size_t size = checkedTableSize(interop.count, stride);
        if (size != 0) {
            if (interop.address == 0) invalid("interopData has a null address");
            reader.require(interop.address, size);
        }
        result.interopData.reserve(static_cast<size_t>(interop.count));
        for (size_t index = 0; index < static_cast<size_t>(interop.count); ++index) {
            const uint64_t address = checkedAdd(interop.address, index * stride);
            result.interopData.push_back({
                reader.pointer(address),
                reader.pointer(checkedAdd(address, pointerSize)),
                reader.pointer(checkedAdd(address, 2 * pointerSize)),
                reader.pointer(checkedAdd(address, 3 * pointerSize)),
                reader.pointer(checkedAdd(address, 4 * pointerSize)),
                reader.pointer(checkedAdd(address, 5 * pointerSize)),
                reader.pointer(checkedAdd(address, 6 * pointerSize))
            });
        }
    }
    return result;
}

Legacy22ReadResult Legacy22Reader::read(
    const BinaryImage& binary,
    const MetadataModel& metadata,
    uint64_t metadataRegistrationAddress,
    uint64_t codeRegistrationAddress) const {
    if (!supports(metadata.version)) {
        throw std::invalid_argument("Legacy22Reader requires metadata version 22 or 23");
    }
    if (metadataRegistrationAddress == 0) {
        throw std::invalid_argument("IL2CPP metadata registration address is zero");
    }

    const size_t pointerSize = inferredPointerSize(binary, pointerSize_);
    ImageReader reader(binary, pointerSize);
    auto native = readMetadataRegistration(reader, metadataRegistrationAddress, codeRegistrationAddress);

    Legacy22ReadResult result;
    result.metadata = metadata;
    if (codeRegistrationAddress != 0) {
        result.code = readCodeRegistration(binary, metadata.version, codeRegistrationAddress);
        native.info.methodPointersAddress = 0;
        native.info.methodPointersCount = 0;
        const auto methodPointers = readTable(reader, codeRegistrationAddress, 0, "methodPointers");
        native.info.methodPointersAddress = methodPointers.address;
        native.info.methodPointersCount = methodPointers.count;
        const size_t genericPair = metadata.version == 22.0 ? 5 : 2;
        const auto genericMethods = readTable(reader, codeRegistrationAddress, genericPair, "genericMethodPointers");
        const auto invokers = readTable(reader, codeRegistrationAddress, genericPair + 1, "invokerPointers");
        native.info.genericMethodPointersAddress = genericMethods.address;
        native.info.genericMethodPointersCount = genericMethods.count;
        native.info.invokerPointersAddress = invokers.address;
        native.info.invokerPointersCount = invokers.count;
    }

    MetadataRegistrationReader{pointerSize}.read(binary, result.metadata, native.info);
    result.metadataUsages = readPointers(reader, native.metadataUsages, "metadataUsages");
    result.metadata.metadataUsagesCount = result.metadataUsages.size();
    result.metadataUsageAddresses.reserve(result.metadata.metadataUsagePairs.size());
    for (const auto& pair : result.metadata.metadataUsagePairs) {
        if (pair.destinationIndex >= result.metadataUsages.size()) {
            invalid("metadata usage destination is outside the native usage table");
        }
        result.metadataUsageAddresses.insert_or_assign(
            pair.destinationIndex,
            result.metadataUsages[pair.destinationIndex]);
    }
    for (const uint64_t pointer : result.code.unresolvedVirtualCallPointers) {
        if (pointer != 0) result.managedTargets.unresolvedVirtualCallStubs.insert(pointer);
    }
    return result;
}

void Legacy22Reader::readInto(
    const BinaryImage& binary,
    MetadataModel& metadata,
    uint64_t metadataRegistrationAddress,
    uint64_t codeRegistrationAddress) const {
    auto result = read(binary, metadata, metadataRegistrationAddress, codeRegistrationAddress);
    metadata = std::move(result.metadata);
}

VirtualInvokeData Legacy22Reader::readVirtualInvokeData(
    const BinaryImage& binary,
    uint64_t invokeDataAddress) const {
    const size_t pointerSize = inferredPointerSize(binary, pointerSize_);
    ImageReader reader(binary, pointerSize);
    reader.require(invokeDataAddress, 2 * pointerSize);
    return {
        reader.pointer(invokeDataAddress),
        reader.pointer(checkedAdd(invokeDataAddress, pointerSize))
    };
}

VirtualDispatchOptions Legacy22Reader::virtualDispatchOptions(
    const BinaryImage& binary,
    const Legacy22ReadResult& registration,
    std::optional<uint64_t> vtableOffset) const {
    const size_t pointerSize = inferredPointerSize(binary, pointerSize_);
    VirtualDispatchOptions options;
    options.binary = &binary;
    options.profile = registration.managedTargets;
    options.unity2017Layout = false;
    options.virtualInvokeDataSize = static_cast<uint32_t>(2 * pointerSize);
    options.methodInfoOffset = static_cast<uint32_t>(pointerSize);
    options.interfaceOffsetEntrySize = pointerSize == 4 ? 8 : 16;
    options.interfaceOffsetValueOffset = static_cast<uint32_t>(pointerSize);
    if (vtableOffset) options.vtableOffset = vtableOffset;
    return options;
}

} // namespace il2cpprec
