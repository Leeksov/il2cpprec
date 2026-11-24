#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include <il2cpprec/Model.hpp>
#include <il2cpprec/analysis/VirtualDispatch.hpp>
#include <il2cpprec/metadata/MetadataUsage.hpp>

namespace il2cpprec {

struct Legacy22InteropData {
    uint64_t delegatePInvokeWrapperFunction = 0;
    uint64_t pinvokeMarshalToNativeFunction = 0;
    uint64_t pinvokeMarshalFromNativeFunction = 0;
    uint64_t pinvokeMarshalCleanupFunction = 0;
    uint64_t createCCWFunction = 0;
    uint64_t guid = 0;
    uint64_t type = 0;
};

struct Legacy22Guid {
    uint64_t address = 0;
    std::array<uint8_t, 16> value{};
};

struct Legacy22CodeRegistration {
    std::vector<uint64_t> methodPointers;
    std::vector<uint64_t> reversePInvokeWrappers;
    std::vector<uint64_t> delegateWrappersFromManagedToNative;
    std::vector<uint64_t> marshalingFunctions;
    std::vector<uint64_t> ccwMarshalingFunctions;
    std::vector<uint64_t> genericMethodPointers;
    std::vector<uint64_t> invokerPointers;
    std::vector<uint64_t> customAttributeGenerators;
    std::vector<Legacy22Guid> guids;
    std::vector<uint64_t> unresolvedVirtualCallPointers;
    std::vector<Legacy22InteropData> interopData;
};

struct Legacy22ReadResult {
    MetadataModel metadata;
    Legacy22CodeRegistration code;
    std::vector<uint64_t> metadataUsages;
    std::unordered_map<uint32_t, uint64_t> metadataUsageAddresses;
    ManagedTargetProfile managedTargets;
};

class Legacy22Reader {
public:
    explicit Legacy22Reader(size_t pointerSize = 0);

    static bool supports(double metadataVersion) noexcept;
    static size_t codeRegistrationSize(double metadataVersion, size_t pointerSize);
    static size_t interopDataSize(size_t pointerSize);

    MetadataModel readGlobalMetadata(const std::vector<uint8_t>& globalMetadata) const;

    MetadataUsageResult readMetadataUsages(
        const std::vector<uint8_t>& globalMetadata,
        const MetadataModel* metadata = nullptr,
        const MetadataUsageGenericMethodResolver& genericMethods = {}) const;

    Legacy22CodeRegistration readCodeRegistration(
        const BinaryImage& binary,
        double metadataVersion,
        uint64_t codeRegistrationAddress) const;

    Legacy22ReadResult read(
        const BinaryImage& binary,
        const MetadataModel& metadata,
        uint64_t metadataRegistrationAddress,
        uint64_t codeRegistrationAddress = 0) const;

    void readInto(
        const BinaryImage& binary,
        MetadataModel& metadata,
        uint64_t metadataRegistrationAddress,
        uint64_t codeRegistrationAddress = 0) const;

    VirtualInvokeData readVirtualInvokeData(
        const BinaryImage& binary,
        uint64_t invokeDataAddress) const;

    VirtualDispatchOptions virtualDispatchOptions(
        const BinaryImage& binary,
        const Legacy22ReadResult& registration,
        std::optional<uint64_t> vtableOffset = std::nullopt) const;

private:
    size_t pointerSize_;
};

} // namespace il2cpprec
