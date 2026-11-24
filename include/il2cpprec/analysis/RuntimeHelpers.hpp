#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <il2cpprec/IR.hpp>

namespace il2cpprec {

enum class RuntimeHelperRole {
    ClassInit
};

// An observation at one call site, not a claim about every call to the target.
struct RuntimeHelperEvidence {
    RuntimeHelperRole role = RuntimeHelperRole::ClassInit;
    uint64_t targetAddress = 0;
    uint64_t callAddress = 0;
    uint64_t guardAddress = 0;
    uint64_t storeAddress = 0;
    size_t blockIndex = 0;
    size_t statementIndex = 0;
};

class RuntimeHelpers {
public:
    // Requires a zero-tested guard load, a call skipped by that branch, and a
    // write of one to the same guard slot after the call. No IR is rewritten.
    std::vector<RuntimeHelperEvidence> infer(const RecoveredFunction& function) const;
};

} // namespace il2cpprec
