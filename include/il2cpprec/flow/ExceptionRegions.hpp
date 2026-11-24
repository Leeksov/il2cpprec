#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/IR.hpp>

namespace il2cpprec::flow {

enum class ExceptionRegionDiagnosticKind {
    InvalidEvidence,
    UnresolvedLeaveTarget,
    UnresolvedJumpTable,
    MissingTryBoundary,
    MissingHandlerBoundary,
    UnmatchedEndFinally,
    UnmatchedCleanup,
    RethrowOutsideRegion,
    AmbiguousRegion
};

struct ExceptionRegionDiagnostic {
    ExceptionRegionDiagnosticKind kind = ExceptionRegionDiagnosticKind::InvalidEvidence;
    uint64_t address = 0;
    std::string message;
};

struct ExceptionRegionAnalysis {
    std::vector<ExceptionRegion> regions;
    std::vector<uint64_t> rethrows;
    std::vector<ExceptionRegionDiagnostic> diagnostics;
    bool partial = false;
};

class ExceptionRegions {
public:
    ExceptionRegionAnalysis analyze(
        const RecoveredFunction& function,
        const std::vector<NativeInstruction>& nativeInstructions = {}) const;
};

} // namespace il2cpprec::flow
