#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <il2cpprec/IR.hpp>

namespace il2cpprec {

struct FunctionImage;

class X86Lifter {
public:
    X86Lifter(Architecture architecture, uint64_t address = 0, std::string name = {});
    explicit X86Lifter(const FunctionImage& image);
    ~X86Lifter();

    X86Lifter(X86Lifter&&) noexcept;
    X86Lifter& operator=(X86Lifter&&) noexcept;

    X86Lifter(const X86Lifter&) = delete;
    X86Lifter& operator=(const X86Lifter&) = delete;

    RecoveredFunction run(std::vector<NativeInstruction> instructions);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace il2cpprec
