#include <il2cpprec/metadata/UnresolvedSignatures.hpp>

#include <algorithm>
#include <limits>
#include <map>
#include <tuple>
#include <utility>

namespace il2cpprec {
namespace {

const char* kindName(UnresolvedCallKind kind) {
    switch (kind) {
    case UnresolvedCallKind::Virtual: return "virtual";
    case UnresolvedCallKind::Instance: return "instance";
    case UnresolvedCallKind::Static: return "static";
    }
    return "unknown";
}

const std::vector<uint64_t>& pointersFor(
    const UnresolvedStubPointers& pointers,
    UnresolvedCallKind kind) {
    switch (kind) {
    case UnresolvedCallKind::Virtual: return pointers.virtualCalls;
    case UnresolvedCallKind::Instance: return pointers.instanceCalls;
    case UnresolvedCallKind::Static: return pointers.staticCalls;
    }
    return pointers.virtualCalls;
}

bool genericValueType(const TypeReferenceModel& type, const MetadataModel& metadata) {
    if (type.definitionIndex < 0) return false;
    const auto index = static_cast<size_t>(type.definitionIndex);
    return index < metadata.types.size() && (metadata.types[index].bitfield & 1U) != 0;
}

std::string rangeDiagnostic(size_t index, const char* reason) {
    return "Unresolved signature range " + std::to_string(index) + " " + reason;
}

} // namespace

bool supportsUnresolvedCallKind(double metadataVersion, UnresolvedCallKind kind) noexcept {
    switch (kind) {
    case UnresolvedCallKind::Virtual:
        return metadataVersion >= 22.0;
    case UnresolvedCallKind::Instance:
    case UnresolvedCallKind::Static:
        return metadataVersion >= 29.1 && metadataVersion != 31.0;
    }
    return false;
}

std::optional<Il2CppTypeCode> reduceUnityType(
    Il2CppTypeCode code,
    double metadataVersion,
    bool byRef,
    bool valueType) noexcept {
    if (metadataVersion < 27.0) return std::nullopt;
    if (byRef || code == Il2CppTypeCode::ByRef) return Il2CppTypeCode::Ptr;

    switch (code) {
    case Il2CppTypeCode::Boolean:
        return Il2CppTypeCode::U1;
    case Il2CppTypeCode::Char:
        return Il2CppTypeCode::U2;
    case Il2CppTypeCode::Enum:
        return Il2CppTypeCode::I4;
    case Il2CppTypeCode::GenericInst:
        if (metadataVersion >= 27.2 && valueType) return Il2CppTypeCode::ValueType;
        return Il2CppTypeCode::Class;
    default:
        return code;
    }
}

std::optional<Il2CppTypeCode> reduceUnityType(
    const ManagedType& type,
    double metadataVersion,
    bool valueType) noexcept {
    return reduceUnityType(type.code, metadataVersion, type.byRef, valueType);
}

std::optional<Il2CppTypeCode> reduceUnityType(
    const TypeReferenceModel& type,
    const MetadataModel& metadata,
    double metadataVersion) noexcept {
    const double version = metadataVersion != 0 ? metadataVersion : metadata.version;
    return reduceUnityType(
        static_cast<Il2CppTypeCode>(type.code),
        version,
        type.byRef,
        genericValueType(type, metadata));
}

UnresolvedSignatureSet UnresolvedSignatureSet::build(
    const MetadataModel& metadata,
    const UnresolvedStubPointers& pointers,
    double metadataVersion) {
    const double version = metadataVersion != 0 ? metadataVersion : metadata.version;
    UnresolvedSignatureSet result;
    result.signatures_.reserve(metadata.unresolvedSignatures.size());

    for (size_t index = 0; index < metadata.unresolvedSignatures.size(); ++index) {
        const auto& model = metadata.unresolvedSignatures[index];
        UnresolvedSignature signature;
        signature.index = index;
        signature.start = model.start;
        signature.count = model.count;
        signature.parameterTypeIndices = model.parameterTypeIndices;
        signature.reducedParameterTypes.reserve(model.parameterTypeIndices.size());

        bool valid = true;
        if (model.start < 0) {
            signature.diagnostic = rangeDiagnostic(index, "has a negative start");
            valid = false;
        } else if (model.count < 0) {
            signature.diagnostic = rangeDiagnostic(index, "has a negative parameter count");
            valid = false;
        } else if (model.start > std::numeric_limits<int32_t>::max() - model.count) {
            signature.diagnostic = rangeDiagnostic(index, "overflows the parameter type table");
            valid = false;
        } else if (model.parameterTypeIndices.size() != static_cast<size_t>(model.count)) {
            signature.diagnostic = rangeDiagnostic(index, "does not match its parameter type count");
            valid = false;
        }

        for (const int32_t typeIndex : model.parameterTypeIndices) {
            if (typeIndex < 0 || static_cast<size_t>(typeIndex) >= metadata.typeReferences.size()) {
                signature.reducedParameterTypes.push_back(std::nullopt);
                if (valid) signature.diagnostic = rangeDiagnostic(index, "contains an invalid parameter type index");
                valid = false;
                continue;
            }
            const auto& type = metadata.typeReferences[static_cast<size_t>(typeIndex)];
            auto reduced = reduceUnityType(type, metadata, version);
            if (!reduced) {
                if (valid) signature.diagnostic = rangeDiagnostic(index, "requires metadata version 27 or newer for reduced types");
                valid = false;
            }
            signature.reducedParameterTypes.push_back(reduced);
        }

        signature.valid = valid;
        result.signatures_.push_back(std::move(signature));
    }

    UnresolvedStubPointers effective = pointers;
    if (effective.virtualCalls.empty()) effective.virtualCalls = metadata.unresolvedVirtualCallPointers;

    constexpr UnresolvedCallKind kinds[] = {
        UnresolvedCallKind::Virtual,
        UnresolvedCallKind::Instance,
        UnresolvedCallKind::Static
    };
    std::map<uint64_t, unsigned> kindMasks;
    for (const auto kind : kinds) {
        const auto& addresses = pointersFor(effective, kind);
        if (!supportsUnresolvedCallKind(version, kind)) {
            if (!addresses.empty()) {
                result.diagnostics_.push_back(
                    std::string("Unresolved ") + kindName(kind) + " call pointers are not present in metadata version " +
                    std::to_string(version));
            }
            continue;
        }

        auto& addressSet = kind == UnresolvedCallKind::Virtual
            ? result.virtualStubs_
            : kind == UnresolvedCallKind::Instance ? result.instanceStubs_ : result.staticStubs_;
        for (size_t index = 0; index < addresses.size(); ++index) {
            const uint64_t address = addresses[index];
            if (address == 0) continue;
            UnresolvedStub stub;
            stub.address = address;
            stub.kind = kind;
            if (index < result.signatures_.size()) stub.signatureIndex = index;
            result.stubs_.push_back(stub);
            addressSet.insert(address);
            result.allStubs_.insert(address);
            kindMasks[address] |= 1U << static_cast<unsigned>(kind);
        }
        if (addresses.size() > result.signatures_.size()) {
            result.diagnostics_.push_back(
                std::string("Unresolved ") + kindName(kind) + " call pointer table has " +
                std::to_string(addresses.size() - result.signatures_.size()) + " entries without signature ranges");
        }
    }

    std::sort(result.stubs_.begin(), result.stubs_.end(), [](const auto& left, const auto& right) {
        return std::tie(left.address, left.kind, left.signatureIndex) <
            std::tie(right.address, right.kind, right.signatureIndex);
    });
    result.stubs_.erase(std::unique(result.stubs_.begin(), result.stubs_.end()), result.stubs_.end());

    for (const auto& [address, mask] : kindMasks) {
        if ((mask & (mask - 1)) != 0) result.sharedStubs_.insert(address);
    }
    return result;
}

const std::set<uint64_t>& UnresolvedSignatureSet::stubs(UnresolvedCallKind kind) const noexcept {
    switch (kind) {
    case UnresolvedCallKind::Virtual: return virtualStubs_;
    case UnresolvedCallKind::Instance: return instanceStubs_;
    case UnresolvedCallKind::Static: return staticStubs_;
    }
    return virtualStubs_;
}

bool UnresolvedSignatureSet::contains(uint64_t address, std::optional<UnresolvedCallKind> kind) const {
    if (address == 0) return false;
    return kind ? stubs(*kind).contains(address) : allStubs_.contains(address);
}

const UnresolvedSignature* UnresolvedSignatureSet::signature(size_t index) const noexcept {
    return index < signatures_.size() ? &signatures_[index] : nullptr;
}

UnresolvedCallsiteResolution UnresolvedSignatureSet::resolveCallsite(
    uint64_t address,
    std::optional<UnresolvedCallKind> kind) const {
    UnresolvedCallsiteResolution result;
    result.address = address;
    result.sharedStub = sharedStubs_.contains(address);

    for (const auto& stub : stubs_) {
        if (stub.address != address || (kind && stub.kind != *kind)) continue;
        result.candidates.push_back(stub);
    }
    if (result.candidates.empty()) return result;

    std::set<std::optional<size_t>> signatureIndices;
    for (const auto& candidate : result.candidates) signatureIndices.insert(candidate.signatureIndex);

    if (signatureIndices.size() != 1) {
        result.status = UnresolvedCallsiteStatus::AmbiguousSignature;
        result.confidence = CallsiteResolutionConfidence::Low;
        result.diagnostic = "The unresolved stub address is associated with multiple signature ranges";
        return result;
    }

    result.signatureIndex = *signatureIndices.begin();
    const UnresolvedSignature* resolved = result.signatureIndex ? signature(*result.signatureIndex) : nullptr;
    if (!resolved || !resolved->valid) {
        result.status = UnresolvedCallsiteStatus::InvalidSignature;
        result.confidence = CallsiteResolutionConfidence::Low;
        result.diagnostic = resolved ? resolved->diagnostic : "The unresolved stub has no signature range";
        return result;
    }

    result.status = UnresolvedCallsiteStatus::SignatureResolved;
    result.confidence = CallsiteResolutionConfidence::High;
    return result;
}

} // namespace il2cpprec
