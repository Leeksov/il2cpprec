#pragma once

#include <memory>
#include <vector>

#include <il2cpprec/Recovery.hpp>

namespace il2cpprec {

class Arm32Lifter {
public:
    explicit Arm32Lifter(const FunctionImage& image);
    ~Arm32Lifter();

    Arm32Lifter(Arm32Lifter&&) noexcept;
    Arm32Lifter& operator=(Arm32Lifter&&) noexcept;

    Arm32Lifter(const Arm32Lifter&) = delete;
    Arm32Lifter& operator=(const Arm32Lifter&) = delete;

    RecoveredFunction run(std::vector<NativeInstruction> instructions);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace il2cpprec
