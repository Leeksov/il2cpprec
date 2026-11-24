#pragma once

#include <il2cpprec/IR.hpp>

namespace il2cpprec::flow {

class SSA {
public:
    RecoveredFunction transform(const RecoveredFunction& function) const;
};

RecoveredFunction transform(const RecoveredFunction& function);

} // namespace il2cpprec::flow
