#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>
#include <il2cpprec/analysis/ManagedPatterns.hpp>

namespace il2cpprec {

enum class VersionedVtableForm {
    MethodInfoPointers,
    VirtualInvokeDataPointer,
    InlineVirtualInvokeData
};

struct VersionedDispatchLayout {
    double metadataVersion = 0;
    size_t pointerSize = 0;
    VersionedVtableForm vtableForm = VersionedVtableForm::InlineVirtualInvokeData;
    size_t vtableOffset = 0;
    size_t vtableEntrySize = 0;
    size_t methodPointerOffset = 0;
    std::optional<size_t> methodInfoOffset;
    size_t methodInfoMethodPointerOffset = 0;
    std::optional<size_t> classInterfaceOffsetsPointerOffset;
    std::optional<size_t> classInterfaceOffsetsCountOffset;
    size_t interfaceOffsetEntrySize = 0;
    size_t interfaceOffsetValueOffset = 0;
    std::optional<size_t> unresolvedCallCountOffset;
    std::optional<size_t> unresolvedVirtualCallPointersOffset;
    std::optional<size_t> unresolvedInstanceCallPointersOffset;
    std::optional<size_t> unresolvedStaticCallPointersOffset;
    size_t genericMethodRowSize = 0;
    std::optional<size_t> genericAdjustorThunkIndexOffset;
    ManagedPatternConfidence confidence = ManagedPatternConfidence::None;

    bool hasSplitUnresolvedStubs() const noexcept;
};

struct VersionedDispatchEntry {
    ManagedPatternStatus status = ManagedPatternStatus::Unresolved;
    ManagedPatternConfidence confidence = ManagedPatternConfidence::None;
    uint64_t klassAddress = 0;
    uint64_t vtableAddress = 0;
    uint64_t entryAddress = 0;
    uint64_t methodPointer = 0;
    std::optional<uint64_t> methodInfo;
    std::optional<uint32_t> slot;
    uint64_t interfaceAddress = 0;
    int32_t interfaceOffset = 0;
    bool hasInterfaceOffset = false;
    std::string reason;
};

struct VersionedUnresolvedStubs {
    std::vector<uint64_t> virtualCalls;
    std::vector<uint64_t> instanceCalls;
    std::vector<uint64_t> staticCalls;

    bool empty() const noexcept;
    bool containsVirtual(uint64_t address) const noexcept;
    bool containsInstance(uint64_t address) const noexcept;
    bool containsStatic(uint64_t address) const noexcept;
};

enum class VersionedDispatchTargetKind {
    Direct,
    Generic,
    GenericAdjustor,
    UnresolvedVirtual,
    UnresolvedInstance,
    UnresolvedStatic
};

struct VersionedDispatchTarget {
    VersionedDispatchTargetKind kind = VersionedDispatchTargetKind::Direct;
    ManagedPatternStatus status = ManagedPatternStatus::Unresolved;
    ManagedPatternConfidence confidence = ManagedPatternConfidence::Low;
    uint64_t targetAddress = 0;
    ManagedMethodReference method;
    std::vector<ManagedMethodReference> methodCandidates;
    ManagedGenericTarget genericTarget;
    std::vector<ManagedGenericTarget> genericCandidates;
    bool unresolvedStub = false;
    std::string reason;
};

class VersionedDispatch {
public:
    explicit VersionedDispatch(double metadataVersion, size_t pointerSize);
    explicit VersionedDispatch(VersionedDispatchLayout layout);

    static bool supports(double metadataVersion) noexcept;
    static VersionedDispatchLayout layout(double metadataVersion, size_t pointerSize);

    const VersionedDispatchLayout& layout() const noexcept;

    VersionedDispatchEntry readVirtual(
        const BinaryImage& binary,
        uint64_t klassAddress,
        uint32_t slot) const;
    VersionedDispatchEntry readInterface(
        const BinaryImage& binary,
        uint64_t klassAddress,
        uint64_t interfaceAddress,
        uint32_t slot) const;

    VersionedUnresolvedStubs readUnresolvedStubs(
        const BinaryImage& binary,
        uint64_t codeRegistrationAddress) const;

    VersionedDispatchTarget resolveTarget(
        const MetadataModel& metadata,
        uint64_t targetAddress,
        const VersionedUnresolvedStubs& unresolved = {}) const;
    VersionedDispatchTarget resolveTarget(
        const MetadataModel& metadata,
        const VersionedDispatchEntry& entry,
        const VersionedUnresolvedStubs& unresolved = {}) const;

private:
    VersionedDispatchLayout layout_;
};

} // namespace il2cpprec

namespace il2cpprec::versions {

using il2cpprec::VersionedDispatch;
using il2cpprec::VersionedDispatchEntry;
using il2cpprec::VersionedDispatchLayout;
using il2cpprec::VersionedDispatchTarget;
using il2cpprec::VersionedDispatchTargetKind;
using il2cpprec::VersionedUnresolvedStubs;
using il2cpprec::VersionedVtableForm;

} // namespace il2cpprec::versions
