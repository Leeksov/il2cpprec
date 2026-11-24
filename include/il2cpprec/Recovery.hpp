#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/IR.hpp>
#include <il2cpprec/Model.hpp>
#include <il2cpprec/flow/ExceptionRegions.hpp>

namespace il2cpprec {

struct FunctionImage {
    Architecture architecture = Architecture::Arm64;
    uint64_t address = 0;
    const uint8_t* code = nullptr;
    size_t size = 0;
    std::string name;
    Arm32Mode arm32Mode = Arm32Mode::Arm;
};

enum class RecoveryDiagnosticKind {
    InvalidImage,
    OutsideExecutableSection,
    DecodeFailed,
    UnresolvedTarget,
    IndirectTarget,
    OverlappingStart,
    InstructionBudgetExceeded
};

struct RecoveryDiagnostic {
    RecoveryDiagnosticKind kind = RecoveryDiagnosticKind::InvalidImage;
    uint64_t address = 0;
    uint64_t target = 0;
};

struct RecoveryOutcome {
    RecoveredFunction function;
    std::vector<RecoveryDiagnostic> diagnostics;
    flow::ExceptionRegionAnalysis exceptionAnalysis;
};

class Recovery {
public:
    RecoveredFunction recover(const FunctionImage& image) const;
    RecoveredFunction recover(const FunctionImage& image, const std::vector<Section>& sections) const;
    RecoveryOutcome recoverWithDiagnostics(
        const FunctionImage& image,
        const std::vector<Section>& sections = {}) const;
};

} // namespace il2cpprec
