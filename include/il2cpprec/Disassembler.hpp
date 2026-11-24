#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace il2cpprec {

enum class Architecture {
    Arm32,
    Arm64,
    X86,
    X64
};

enum class OperandKind {
    Register,
    Immediate,
    Memory,
    FloatingPoint
};

struct Shift {
    uint32_t type = 0;
    uint32_t value = 0;
};

struct VectorArrangement {
    uint16_t elementSize = 0;
    uint16_t elementCount = 0;
    bool replicate = false;
};

struct Operand {
    OperandKind kind = OperandKind::Immediate;
    std::string reg;
    int64_t immediate = 0;
    double floatingPoint = 0.0;
    uint16_t size = 0;
    std::string memoryBase;
    std::string memoryIndex;
    int64_t displacement = 0;
    int32_t scale = 1;
    Shift shift;
    VectorArrangement arrangement;
    int32_t laneIndex = -1;
};

enum class WritebackMode {
    None,
    PreIndex,
    PostIndex
};

struct NativeInstruction {
    uint32_t id = 0;
    uint32_t conditionCode = 0;
    uint64_t address = 0;
    uint16_t size = 0;
    std::string mnemonic;
    std::string text;
    std::vector<Operand> operands;
    WritebackMode writeback = WritebackMode::None;
    int64_t writebackOffset = 0;
    std::string writebackRegister;
};

enum class Arm32Mode {
    Arm,
    Thumb
};

class RecursiveDecoder {
public:
    explicit RecursiveDecoder(
        Architecture architecture,
        Arm32Mode arm32Mode = Arm32Mode::Arm);

    std::optional<NativeInstruction> decodeInstruction(
        const uint8_t* code,
        size_t size,
        uint64_t address) const;

    std::vector<NativeInstruction> decodeRange(
        const uint8_t* code,
        size_t size,
        uint64_t address,
        size_t maxInstructions = 0) const;

private:
    Architecture architecture_;
    Arm32Mode arm32Mode_;
};

class Disassembler {
public:
    std::vector<NativeInstruction> disassemble(
        Architecture architecture,
        const uint8_t* code,
        size_t size,
        uint64_t address) const;
};

} // namespace il2cpprec
