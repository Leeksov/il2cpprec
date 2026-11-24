#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <il2cpprec/abi/AbiAdapter.hpp>
#include <il2cpprec/analysis/ManagedPatterns.hpp>
#include <il2cpprec/analysis/VirtualDispatch.hpp>

namespace il2cpprec {

class UniversalGenericResolver;

enum class ManagedEmittedMemberSyntax {
    Method,
    PropertyGet,
    PropertySet
};

struct ManagedEmittedMember {
    std::string imageName;
    std::string metadataDeclaringType;
    std::string metadataMethodName;
    std::string emittedDeclaringType;
    std::string emittedName;
    ManagedEmittedMemberSyntax syntax = ManagedEmittedMemberSyntax::Method;
    bool isStatic = false;
    // False for an omitted declaration or an emitted diagnostic stub.
    bool bodyAvailable = false;
};

struct ManagedEmissionSurface {
    const MetadataModel* source = nullptr;
    std::unordered_map<int, std::vector<ManagedEmittedMember>> byDefinitionIndex;
};

struct ManagedEmitterOptions {
    ManagedTargetProfile profile;
    ManagedPatternOptions patterns;
    VirtualDispatchOptions dispatch;
    AbiAdapterOptions abi;
    // Optional indexed adapter for exactly this MetadataModel and ABI policy.
    // A metadata clone or changed ABI policy uses a local adapter instead.
    const AbiAdapter* abiAdapter = nullptr;
    const MetadataModel* abiAdapterSource = nullptr;
    // When supplied, only uniquely matching, callable emitted members may
    // replace native calls. Null preserves standalone analyzer behavior.
    const ManagedEmissionSurface* emissionSurface = nullptr;
    // Optional resolver built for exactly this MetadataModel. An emitter that
    // clones metadata for discovery ignores it and builds a local resolver.
    const UniversalGenericResolver* universalGenerics = nullptr;
    const MetadataModel* universalGenericsSource = nullptr;
};

struct ManagedCallSite {
    CallSiteKind kind = CallSiteKind::Unknown;
    ManagedPatternStatus status = ManagedPatternStatus::Unresolved;
    ManagedPatternConfidence confidence = ManagedPatternConfidence::None;
    uint64_t address = 0;
    size_t blockIndex = 0;
    size_t statementIndex = 0;
    bool emitted = false;
    ManagedMethodReference method;
    ManagedGenericTarget genericTarget;
    bool unresolvedStub = false;
    CallSiteAbiModel abi;
    std::string reason;
    std::vector<Statement> nativeStatements;
};

struct ManagedEmitResult {
    std::string csharp;
    std::vector<ManagedCallSite> callSites;
    ManagedAnalysisResult managedAnalysis;
    VirtualDispatchAnalysisResult dispatchAnalysis;
};

class ManagedEmitter {
public:
    ManagedEmitResult emit(
        const RecoveredFunction& function,
        const MetadataModel& metadata,
        const ManagedEmitterOptions& options = {}) const;
};

} // namespace il2cpprec
