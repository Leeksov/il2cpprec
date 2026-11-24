#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

struct MetadataRegistrationInfo {
    uint64_t metadataRegistrationAddress = 0;
    uint64_t codeRegistrationAddress = 0;
    uint64_t typesAddress = 0;
    uint64_t typesCount = 0;
    uint64_t fieldOffsetsAddress = 0;
    uint64_t fieldOffsetsCount = 0;
    uint64_t genericClassesAddress = 0;
    uint64_t genericClassesCount = 0;
    uint64_t genericInstsAddress = 0;
    uint64_t genericInstsCount = 0;
    uint64_t genericMethodTableAddress = 0;
    uint64_t genericMethodTableCount = 0;
    uint64_t methodSpecsAddress = 0;
    uint64_t methodSpecsCount = 0;
    uint64_t genericMethodPointersAddress = 0;
    uint64_t genericMethodPointersCount = 0;
    uint64_t invokerPointersAddress = 0;
    uint64_t invokerPointersCount = 0;
    uint64_t methodPointersAddress = 0;
    uint64_t methodPointersCount = 0;
    uint64_t metadataUsagesCount = 0;
    uint64_t unresolvedVirtualCallPointersAddress = 0;
    uint64_t unresolvedVirtualCallPointersCount = 0;
    uint64_t adjustorThunksAddress = 0;
    uint64_t adjustorThunksCount = 0;
    uint32_t genericMethodTableEntrySize = 0;
    double registrationVersion = 0;
    MetadataVersionConfidence versionConfidence = MetadataVersionConfidence::Unknown;
    std::string versionProvenance;
};

class MetadataRegistrationReader {
public:
    explicit MetadataRegistrationReader(size_t pointerSize = 0);

    std::vector<TypeReferenceModel> readTypes(
        const BinaryImage& binary,
        uint64_t typesAddress,
        uint64_t typesCount,
        const MetadataModel& metadata) const;

    void readFieldOffsets(
        const BinaryImage& binary,
        MetadataModel& metadata,
        uint64_t fieldOffsetsAddress,
        uint64_t fieldOffsetsCount) const;

    void read(const BinaryImage& binary, MetadataModel& metadata) const;

    void read(
        const BinaryImage& binary,
        MetadataModel& metadata,
        const MetadataRegistrationInfo& registration) const;

    void read(
        const BinaryImage& binary,
        MetadataModel& metadata,
        uint64_t metadataRegistrationAddress,
        uint64_t codeRegistrationAddress = 0) const;

private:
    size_t pointerSize_;
};

} // namespace il2cpprec
