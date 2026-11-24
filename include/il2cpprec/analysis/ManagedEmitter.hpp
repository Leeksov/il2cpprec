#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/abi/AbiAdapter.hpp>
#include <il2cpprec/analysis/ManagedPatterns.hpp>
#include <il2cpprec/analysis/VirtualDispatch.hpp>

namespace il2cpprec {

struct ManagedEmitterOptions {
    ManagedTargetProfile profile;
    ManagedPatternOptions patterns;
    VirtualDispatchOptions dispatch;
    AbiAdapterOptions abi;
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
