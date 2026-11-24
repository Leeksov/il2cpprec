#include <il2cpprec/versions/VersionedDispatch.hpp>

#include <il2cpprec/metadata/GenericMethodResolver.hpp>
#include <il2cpprec/versions/ObjectLayouts.hpp>

#include <algorithm>
#include <bit>
#include <cmath>
#include <limits>
#include <tuple>

namespace il2cpprec {
namespace {

std::optional<uint64_t> add(uint64_t base, uint64_t offset) {
    if (offset > std::numeric_limits<uint64_t>::max() - base) return {};
    return base + offset;
}

std::optional<uint64_t> read(const BinaryImage& binary, uint64_t address, size_t width) {
    if (!binary.bytes || width == 0 || width > 8) return {};
    try {
        const uint64_t offset = binary.mapVATR(address);
        // mapVATR validates the first byte. Validate the whole field against one file-backed section.
        bool backed = false;
        for (const auto& section : binary.sections) {
            if (offset < section.fileOffset) continue;
            const uint64_t relative = offset - section.fileOffset;
            const uint64_t limit = section.virtualSize == 0
                ? section.fileSize : std::min(section.fileSize, section.virtualSize);
            if (relative <= limit && width <= limit - relative) { backed = true; break; }
        }
        if (!backed) return {};
        const auto* bytes = binary.data(offset, width);
        uint64_t value = 0;
        for (size_t i = 0; i < width; ++i) value |= uint64_t(bytes[i]) << (8 * i);
        return value;
    } catch (const std::exception&) {
        return {};
    }
}

std::optional<uint64_t> field(const BinaryImage& binary, uint64_t base, size_t offset, size_t width) {
    const auto address = add(base, offset);
    return address ? read(binary, *address, width) : std::nullopt;
}

bool contains(const std::vector<uint64_t>& values, uint64_t address) {
    return address != 0 && std::find(values.begin(), values.end(), address) != values.end();
}

ManagedMethodReference reference(const MethodModel& method, uint64_t address) {
    ManagedMethodReference result;
    result.token = method.token;
    result.definitionIndex = method.definitionIndex;
    result.address = address;
    result.imageName = method.imageName;
    result.declaringType = method.declaringType;
    result.name = method.name;
    result.isStatic = method.isStatic;
    return result;
}

bool sameMethod(const ManagedMethodReference& a, const ManagedMethodReference& b) {
    return std::tie(a.token, a.definitionIndex, a.imageName, a.declaringType, a.name, a.isStatic) ==
        std::tie(b.token, b.definitionIndex, b.imageName, b.declaringType, b.name, b.isStatic);
}

std::optional<uint64_t> directAddress(const MetadataModel& metadata, const MethodModel& method) {
    if (method.address) return method.address;
    const auto found = metadata.methodPointersByImage.find(method.imageName);
    if (found == metadata.methodPointersByImage.end()) return {};
    int64_t index = -1;
    if (metadata.version > 0 && metadata.version < 24.2) index = method.methodIndex;
    else if ((method.token & 0xff000000U) == 0x06000000U && (method.token & 0x00ffffffU))
        index = static_cast<int64_t>(method.token & 0x00ffffffU) - 1;
    if (index < 0 || static_cast<size_t>(index) >= found->second.size()) return {};
    return found->second[static_cast<size_t>(index)];
}

} // namespace

bool VersionedDispatchLayout::hasSplitUnresolvedStubs() const noexcept {
    return unresolvedInstanceCallPointersOffset && unresolvedStaticCallPointersOffset;
}

bool VersionedUnresolvedStubs::empty() const noexcept {
    return virtualCalls.empty() && instanceCalls.empty() && staticCalls.empty();
}
bool VersionedUnresolvedStubs::containsVirtual(uint64_t address) const noexcept { return contains(virtualCalls, address); }
bool VersionedUnresolvedStubs::containsInstance(uint64_t address) const noexcept { return contains(instanceCalls, address); }
bool VersionedUnresolvedStubs::containsStatic(uint64_t address) const noexcept { return contains(staticCalls, address); }

VersionedDispatch::VersionedDispatch(double metadataVersion, size_t pointerSize)
    : layout_(layout(metadataVersion, pointerSize)) {}
VersionedDispatch::VersionedDispatch(VersionedDispatchLayout layout) : layout_(std::move(layout)) {}

bool VersionedDispatch::supports(double version) noexcept {
    return std::abs(version - 21.0) >= 0.001 && versions::ObjectLayouts::resolve(version, 8).supported;
}

VersionedDispatchLayout VersionedDispatch::layout(double version, size_t pointerSize) {
    VersionedDispatchLayout result;
    result.metadataVersion = version;
    result.pointerSize = pointerSize;
    if (pointerSize != 4 && pointerSize != 8) return result;
    const auto object = versions::ObjectLayouts::resolve(version, pointerSize);
    if (!object.supported) return result;
    // Metadata 21 spans both MethodInfo and VirtualInvokeData vtable ABIs.
    // Version alone cannot select one; callers may supply an observed layout explicitly.
    if (std::abs(version - 21.0) < 0.001) return result;
    result.confidence = object.confidence == versions::LayoutConfidence::Exact
        ? ManagedPatternConfidence::High : ManagedPatternConfidence::Low;
    const auto& klass = object.klass;
    result.vtableOffset = klass.vtable.offset;
    result.vtableEntrySize = klass.vtable.entrySize;
    if (klass.vtableCount.present) result.vtableCountOffset = klass.vtableCount.offset;
    if (klass.interfaceOffsets.present) result.classInterfaceOffsetsPointerOffset = klass.interfaceOffsets.offset;
    // The class offset count follows the interfaces count in these confirmed class forms.
    if (klass.vtableCount.present) result.classInterfaceOffsetsCountOffset = klass.vtableCount.offset + 4;
    result.interfaceOffsetEntrySize = pointerSize == 4 ? 8 : 16;
    result.interfaceOffsetValueOffset = pointerSize;
    if (klass.vtable.form == versions::VtableForm::MethodInfoPointerTable) {
        if (std::abs(version - 22.0) < 0.001) {
            // The v22 reader uses two-pointer VirtualInvokeData at the class vtable pointer.
            result.vtableForm = VersionedVtableForm::VirtualInvokeDataPointer;
            result.vtableEntrySize = 2 * pointerSize;
            result.methodInfoOffset = pointerSize;
            result.confidence = ManagedPatternConfidence::Medium;
        } else {
            result.vtableForm = VersionedVtableForm::MethodInfoPointers;
            result.methodInfoOffset = 0;
            result.methodInfoMethodPointerOffset = 0;
        }
    } else if (klass.vtable.form == versions::VtableForm::InlineVirtualInvokeData) {
        result.vtableForm = VersionedVtableForm::InlineVirtualInvokeData;
        result.methodPointerOffset = klass.vtable.methodPointer.offset;
        result.methodInfoOffset = klass.vtable.methodInfo.offset;
    } else {
        result.confidence = ManagedPatternConfidence::None;
    }
    // The modular CodeRegistration has a count/pointer pair at slots 9/10.
    if (version >= 24.0 && version <= 24.15) {
        result.unresolvedCallCountOffset = 10 * pointerSize;
        result.unresolvedVirtualCallPointersOffset = 11 * pointerSize;
    } else if (version >= 24.2 && version <= 29.3) {
        result.unresolvedCallCountOffset = 9 * pointerSize;
        result.unresolvedVirtualCallPointersOffset = 10 * pointerSize;
    }
    result.genericMethodRowSize = 3 * sizeof(int32_t);
    return result;
}

const VersionedDispatchLayout& VersionedDispatch::layout() const noexcept { return layout_; }

VersionedDispatchEntry VersionedDispatch::readVirtual(
    const BinaryImage& binary, uint64_t klassAddress, uint32_t slot) const {
    VersionedDispatchEntry result;
    result.klassAddress = klassAddress;
    result.slot = slot;
    result.confidence = layout_.confidence;
    const size_t p = layout_.pointerSize;
    if (!klassAddress || (p != 4 && p != 8) || layout_.confidence == ManagedPatternConfidence::None ||
        layout_.vtableEntrySize < p || !layout_.vtableCountOffset) {
        result.reason = "The class or vtable layout is unavailable.";
        return result;
    }
    const auto count = field(binary, klassAddress, *layout_.vtableCountOffset, 2);
    if (!count || slot >= *count) {
        result.reason = count ? "The virtual slot exceeds the class vtable count." : "The class vtable count is unreadable.";
        return result;
    }
    if (slot > std::numeric_limits<uint64_t>::max() / layout_.vtableEntrySize) {
        result.reason = "The virtual slot address overflows.";
        return result;
    }
    const auto table = layout_.vtableForm == VersionedVtableForm::InlineVirtualInvokeData
        ? add(klassAddress, layout_.vtableOffset)
        : field(binary, klassAddress, layout_.vtableOffset, p);
    if (!table || !*table) { result.reason = "The vtable address is unreadable."; return result; }
    result.vtableAddress = *table;
    const auto entry = add(*table, uint64_t(slot) * layout_.vtableEntrySize);
    if (!entry) { result.reason = "The vtable entry address overflows."; return result; }
    result.entryAddress = *entry;
    if (layout_.vtableForm == VersionedVtableForm::MethodInfoPointers) {
        const auto info = field(binary, *entry, layout_.methodInfoOffset.value_or(0), p);
        if (!info || !*info) { result.reason = "The MethodInfo vtable entry is unreadable."; return result; }
        result.methodInfo = *info;
        const auto pointer = field(binary, *info, layout_.methodInfoMethodPointerOffset, p);
        if (!pointer) { result.reason = "The MethodInfo target is unreadable."; return result; }
        result.methodPointer = *pointer;
    } else {
        const auto pointer = field(binary, *entry, layout_.methodPointerOffset, p);
        if (!pointer) { result.reason = "The virtual target is unreadable."; return result; }
        result.methodPointer = *pointer;
        if (layout_.methodInfoOffset) result.methodInfo = field(binary, *entry, *layout_.methodInfoOffset, p);
    }
    result.status = result.methodPointer ? ManagedPatternStatus::Placeholder : ManagedPatternStatus::Unresolved;
    result.reason = result.methodPointer ? "Native target recovered; managed identity requires resolution." : "The vtable target is null.";
    return result;
}

VersionedDispatchEntry VersionedDispatch::readInterface(
    const BinaryImage& binary, uint64_t klassAddress, uint64_t interfaceAddress, uint32_t slot) const {
    VersionedDispatchEntry result;
    result.klassAddress = klassAddress;
    result.interfaceAddress = interfaceAddress;
    result.slot = slot;
    result.confidence = layout_.confidence;
    if (!klassAddress || !interfaceAddress || !layout_.classInterfaceOffsetsPointerOffset ||
        !layout_.classInterfaceOffsetsCountOffset || (layout_.pointerSize != 4 && layout_.pointerSize != 8) ||
        layout_.interfaceOffsetEntrySize < layout_.pointerSize + 4) {
        result.reason = "The interface-offset layout is unavailable.";
        return result;
    }
    const auto count = field(binary, klassAddress, *layout_.classInterfaceOffsetsCountOffset,
                             layout_.interfaceOffsetsCountWidth);
    const auto table = field(binary, klassAddress, *layout_.classInterfaceOffsetsPointerOffset, layout_.pointerSize);
    if (!count || !table || !*table || *count > 65535) {
        result.reason = "The interface-offset table is unreadable.";
        return result;
    }
    std::optional<int32_t> match;
    for (uint64_t index = 0; index < *count; ++index) {
        const auto address = add(*table, index * layout_.interfaceOffsetEntrySize);
        if (!address) break;
        const auto type = read(binary, *address, layout_.pointerSize);
        const auto offset = field(binary, *address, layout_.interfaceOffsetValueOffset, 4);
        if (!type || !offset) { result.reason = "An interface-offset row is unreadable."; return result; }
        if (*type != interfaceAddress) continue;
        const auto value = std::bit_cast<int32_t>(static_cast<uint32_t>(*offset));
        if (match && *match != value) {
            result.status = ManagedPatternStatus::Ambiguous;
            result.reason = "Conflicting offsets match the interface.";
            return result;
        }
        match = value;
    }
    if (!match) { result.reason = "The interface has no offset in the class."; return result; }
    result.interfaceOffset = *match;
    result.hasInterfaceOffset = true;
    if (*match < 0 || uint64_t(slot) > std::numeric_limits<uint32_t>::max() - uint64_t(*match)) {
        result.reason = "The interface slot is invalid.";
        return result;
    }
    auto virtualEntry = readVirtual(binary, klassAddress, static_cast<uint32_t>(*match) + slot);
    virtualEntry.interfaceAddress = interfaceAddress;
    virtualEntry.interfaceOffset = *match;
    virtualEntry.hasInterfaceOffset = true;
    return virtualEntry;
}

VersionedUnresolvedStubs VersionedDispatch::readUnresolvedStubs(
    const BinaryImage& binary, uint64_t codeRegistrationAddress) const {
    VersionedUnresolvedStubs result;
    if (!codeRegistrationAddress || !layout_.unresolvedCallCountOffset ||
        !layout_.unresolvedVirtualCallPointersOffset) return result;
    const auto count = field(binary, codeRegistrationAddress, *layout_.unresolvedCallCountOffset, layout_.pointerSize);
    const auto table = field(binary, codeRegistrationAddress, *layout_.unresolvedVirtualCallPointersOffset, layout_.pointerSize);
    if (!count || !table || *count > 65536 || (*count && !*table)) return result;
    std::vector<uint64_t> values;
    for (uint64_t i = 0; i < *count; ++i) {
        if (i > std::numeric_limits<uint64_t>::max() / layout_.pointerSize) return {};
        const auto address = add(*table, i * layout_.pointerSize);
        const auto value = address ? read(binary, *address, layout_.pointerSize) : std::nullopt;
        if (!value) return {};
        if (*value) values.push_back(*value);
    }
    result.virtualCalls = std::move(values);
    return result;
}

VersionedDispatchTarget VersionedDispatch::resolveTarget(
    const MetadataModel& metadata, uint64_t targetAddress, const VersionedUnresolvedStubs& unresolved) const {
    VersionedDispatchTarget result;
    result.targetAddress = targetAddress;
    if (!targetAddress) { result.reason = "The native target is null."; return result; }
    if (unresolved.containsInstance(targetAddress) || unresolved.containsStatic(targetAddress) ||
        unresolved.containsVirtual(targetAddress) || contains(metadata.unresolvedVirtualCallPointers, targetAddress)) {
        result.kind = unresolved.containsInstance(targetAddress) ? VersionedDispatchTargetKind::UnresolvedInstance
            : unresolved.containsStatic(targetAddress) ? VersionedDispatchTargetKind::UnresolvedStatic
            : VersionedDispatchTargetKind::UnresolvedVirtual;
        result.unresolvedStub = true;
        result.confidence = ManagedPatternConfidence::High;
        result.reason = "The native address is a shared unresolved-call stub.";
        return result;
    }
    for (const auto& type : metadata.types) {
        for (const auto& method : type.methods) {
            if (directAddress(metadata, method) == targetAddress) {
                const auto candidate = reference(method, targetAddress);
                if (std::none_of(result.methodCandidates.begin(), result.methodCandidates.end(),
                    [&](const auto& prior) { return sameMethod(prior, candidate); })) result.methodCandidates.push_back(candidate);
            }
        }
    }
    for (const auto& mapping : metadata.genericMethodTable) {
        if (mapping.genericMethodIndex < 0 ||
            (mapping.methodPointer != targetAddress && mapping.adjustorThunk != targetAddress)) continue;
        ManagedGenericTarget candidate;
        candidate.present = true;
        candidate.adjustor = mapping.adjustorThunk == targetAddress;
        candidate.genericMethodIndex = mapping.genericMethodIndex;
        candidate.mapping = mapping;
        if (static_cast<size_t>(mapping.genericMethodIndex) < metadata.methodSpecs.size()) {
            const auto& spec = metadata.methodSpecs[static_cast<size_t>(mapping.genericMethodIndex)];
            candidate.classInstIndex = spec.classInstIndex;
            candidate.methodInstIndex = spec.methodInstIndex;
        }
        result.genericCandidates.push_back(candidate);
    }
    if (!result.genericCandidates.empty()) {
        result.kind = result.genericCandidates.front().adjustor
            ? VersionedDispatchTargetKind::GenericAdjustor : VersionedDispatchTargetKind::Generic;
        if (result.genericCandidates.size() != 1) {
            result.status = ManagedPatternStatus::Ambiguous;
            result.reason = "Multiple generic mappings share this target.";
            return result;
        }
        result.genericTarget = result.genericCandidates.front();
        const auto resolved = GenericMethodResolver(metadata).resolve(
            static_cast<uint32_t>(result.genericTarget.genericMethodIndex));
        if (resolved.status != MetadataUsageStatus::Resolved || !resolved.method) {
            result.status = resolved.status == MetadataUsageStatus::Ambiguous
                ? ManagedPatternStatus::Ambiguous : ManagedPatternStatus::Placeholder;
            result.confidence = ManagedPatternConfidence::Medium;
            result.reason = resolved.diagnostic;
            return result;
        }
        const auto resolvedReference = reference(*resolved.method, targetAddress);
        if (!result.methodCandidates.empty() &&
            (result.methodCandidates.size() != 1 || !sameMethod(result.methodCandidates.front(), resolvedReference))) {
            result.status = ManagedPatternStatus::Ambiguous;
            result.reason = "Direct and generic mappings disagree on the managed method.";
            return result;
        }
        result.method = resolvedReference;
        if (result.methodCandidates.empty()) result.methodCandidates.push_back(result.method);
        result.status = ManagedPatternStatus::Resolved;
        result.confidence = ManagedPatternConfidence::High;
        return result;
    }
    if (result.methodCandidates.size() == 1) {
        result.method = result.methodCandidates.front();
        result.status = ManagedPatternStatus::Resolved;
        result.confidence = ManagedPatternConfidence::High;
    } else if (result.methodCandidates.size() > 1) {
        result.status = ManagedPatternStatus::Ambiguous;
        result.reason = "Multiple managed methods share this native address.";
    } else {
        result.status = ManagedPatternStatus::Placeholder;
        result.confidence = ManagedPatternConfidence::Medium;
        result.reason = "Native target is available for fallback; managed identity is unknown.";
    }
    return result;
}

VersionedDispatchTarget VersionedDispatch::resolveTarget(
    const MetadataModel& metadata, const VersionedDispatchEntry& entry,
    const VersionedUnresolvedStubs& unresolved) const {
    auto result = resolveTarget(metadata, entry.methodPointer, unresolved);
    if (entry.status == ManagedPatternStatus::Unresolved || entry.status == ManagedPatternStatus::Ambiguous) {
        result.status = entry.status;
        result.confidence = entry.confidence;
        result.method = {};
        result.methodCandidates.clear();
        result.reason = entry.reason;
    } else if (static_cast<int>(result.confidence) > static_cast<int>(entry.confidence)) {
        result.confidence = entry.confidence;
    }
    return result;
}

} // namespace il2cpprec
