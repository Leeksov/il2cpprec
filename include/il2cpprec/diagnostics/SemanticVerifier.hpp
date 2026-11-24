#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/Recovery.hpp>

namespace il2cpprec {

// This is a structural audit, not a proof that recovered C# is equivalent to
// the original managed method. In particular, instructions removed by valid
// lowering passes are counted as unmapped until a rewrite ledger is available.
enum class VerificationStatus {
    NoFinding,
    Suspect,
    Unverifiable
};

struct VerificationFinding {
    std::string code;
    uint64_t address = 0;
    std::string message;
};

struct VerificationResult {
    VerificationStatus status = VerificationStatus::Unverifiable;
    size_t decodedInstructions = 0;
    size_t representedInstructions = 0;
    size_t unmappedInstructions = 0;
    std::vector<VerificationFinding> findings;
};

const char* toString(VerificationStatus status) noexcept;

class SemanticVerifier {
public:
    VerificationResult verify(const FunctionImage& image, const RecoveredFunction& function) const;
};

} // namespace il2cpprec
