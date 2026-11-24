#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <il2cpprec/Model.hpp>
#include <il2cpprec/Recovery.hpp>

namespace il2cpprec::flow {

class InstructionDecoder {
public:
    virtual ~InstructionDecoder() = default;

    virtual std::optional<NativeInstruction> decodeOne(
        Architecture architecture,
        const uint8_t* code,
        size_t size,
        uint64_t address) const = 0;
};

class DisassemblerInstructionDecoder final : public InstructionDecoder {
public:
    std::optional<NativeInstruction> decodeOne(
        Architecture architecture,
        const uint8_t* code,
        size_t size,
        uint64_t address) const override;
};

enum class DecodeDiagnosticKind {
    InvalidImage,
    OutsideExecutableSection,
    DecodeFailed,
    UnresolvedTarget,
    IndirectTarget,
    OverlappingStart,
    InstructionBudgetExceeded
};

struct DecodeDiagnostic {
    DecodeDiagnosticKind kind = DecodeDiagnosticKind::InvalidImage;
    uint64_t address = 0;
    uint64_t target = 0;
};

struct DecodedBasicBlock {
    uint64_t address = 0;
    size_t instructionBegin = 0;
    size_t instructionEnd = 0;
    std::optional<uint64_t> directTarget;
    std::optional<uint64_t> fallthrough;
};

struct DecodeOptions {
    size_t maxInstructions = 100000;
};

struct DecodeResult {
    std::vector<NativeInstruction> instructions;
    std::vector<DecodedBasicBlock> blocks;
    std::vector<DecodeDiagnostic> diagnostics;
};

class RecursiveDecoder {
public:
    RecursiveDecoder();
    explicit RecursiveDecoder(std::shared_ptr<const InstructionDecoder> decoder);

    DecodeResult decode(
        const FunctionImage& image,
        const std::vector<Section>& sections = {},
        const DecodeOptions& options = {}) const;

private:
    std::shared_ptr<const InstructionDecoder> decoder_;
};

} // namespace il2cpprec::flow
