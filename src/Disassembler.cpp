#include <il2cpprec/Disassembler.hpp>

#include <capstone/arm.h>
#include <capstone/arm64.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <array>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

namespace il2cpprec {
namespace {

struct CapstoneArchitecture {
    cs_arch arch;
    cs_mode mode;
    size_t poolIndex;
};

CapstoneArchitecture getCapstoneArchitecture(
    Architecture architecture,
    Arm32Mode arm32Mode = Arm32Mode::Arm) {
    if (architecture != Architecture::Arm32 && arm32Mode != Arm32Mode::Arm) {
        throw std::invalid_argument("ARM/Thumb mode selection is only valid for Arm32");
    }

    switch (architecture) {
    case Architecture::Arm32:
        switch (arm32Mode) {
        case Arm32Mode::Arm:
            return {CS_ARCH_ARM, CS_MODE_ARM, 0};
        case Arm32Mode::Thumb:
            return {CS_ARCH_ARM, CS_MODE_THUMB, 1};
        }
        throw std::invalid_argument("Unsupported Arm32 mode");
    case Architecture::Arm64:
        return {CS_ARCH_ARM64, CS_MODE_ARM, 2};
    case Architecture::X86:
        return {CS_ARCH_X86, CS_MODE_32, 3};
    case Architecture::X64:
        return {CS_ARCH_X86, CS_MODE_64, 4};
    }
    throw std::invalid_argument("Unsupported architecture");
}

class CapstoneHandle {
public:
    CapstoneHandle() = default;
    ~CapstoneHandle() {
        if (handle_ != 0) {
            cs_close(&handle_);
        }
    }

    CapstoneHandle(const CapstoneHandle&) = delete;
    CapstoneHandle& operator=(const CapstoneHandle&) = delete;

    csh acquire(const CapstoneArchitecture& target) {
        if (handle_ == 0) {
            csh opened = 0;
            const auto status = cs_open(target.arch, target.mode, &opened);
            if (status != CS_ERR_OK) {
                throw std::runtime_error("cs_open failed: " + std::string(cs_strerror(status)));
            }
            handle_ = opened;
        }

        if (!detailEnabled_) {
            const auto status = cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
            if (status != CS_ERR_OK) {
                throw std::runtime_error("cs_option failed: " + std::string(cs_strerror(status)));
            }
            detailEnabled_ = true;
        }
        return handle_;
    }

private:
    csh handle_ = 0;
    bool detailEnabled_ = false;
};

class CapstoneHandlePool {
public:
    csh acquire(const CapstoneArchitecture& target) {
        return handles_[target.poolIndex].acquire(target);
    }

private:
    std::array<CapstoneHandle, 5> handles_;
};

csh acquireCapstoneHandle(const CapstoneArchitecture& target) {
    thread_local CapstoneHandlePool pool;
    return pool.acquire(target);
}

class CapstoneInstruction {
public:
    explicit CapstoneInstruction(csh handle)
        : instruction_(cs_malloc(handle)) {
        if (instruction_ == nullptr) {
            throw std::bad_alloc();
        }
    }

    ~CapstoneInstruction() {
        cs_free(instruction_, 1);
    }

    CapstoneInstruction(const CapstoneInstruction&) = delete;
    CapstoneInstruction& operator=(const CapstoneInstruction&) = delete;

    cs_insn* get() const {
        return instruction_;
    }

private:
    cs_insn* instruction_;
};

std::string registerName(csh handle, uint32_t id) {
    const char* name = cs_reg_name(handle, id);
    return name == nullptr ? std::string() : std::string(name);
}

uint16_t arm64VectorElementSize(arm64_vas vas) {
    switch (vas) {
    case ARM64_VAS_16B:
    case ARM64_VAS_8B:
    case ARM64_VAS_4B:
    case ARM64_VAS_1B:
        return 1;
    case ARM64_VAS_8H:
    case ARM64_VAS_4H:
    case ARM64_VAS_2H:
    case ARM64_VAS_1H:
        return 2;
    case ARM64_VAS_4S:
    case ARM64_VAS_2S:
    case ARM64_VAS_1S:
        return 4;
    case ARM64_VAS_2D:
    case ARM64_VAS_1D:
        return 8;
    case ARM64_VAS_1Q:
        return 16;
    default:
        return 0;
    }
}

uint16_t arm64VectorSize(arm64_vas vas) {
    switch (vas) {
    case ARM64_VAS_16B:
    case ARM64_VAS_8H:
    case ARM64_VAS_4S:
    case ARM64_VAS_2D:
    case ARM64_VAS_1Q:
        return 16;
    case ARM64_VAS_8B:
    case ARM64_VAS_4H:
    case ARM64_VAS_2S:
    case ARM64_VAS_1D:
        return 8;
    case ARM64_VAS_4B:
    case ARM64_VAS_2H:
    case ARM64_VAS_1S:
        return 4;
    case ARM64_VAS_1H:
        return 2;
    case ARM64_VAS_1B:
        return 1;
    default:
        return 0;
    }
}

uint16_t arm64RegisterSize(const cs_arm64_op& input, const std::string& name) {
    if (input.vas != ARM64_VAS_INVALID) {
        return input.vector_index >= 0 ? arm64VectorElementSize(input.vas) : arm64VectorSize(input.vas);
    }
    if (name.empty()) return 0;
    switch (name[0]) {
    case 'b': return 1;
    case 'h': return 2;
    case 'w':
    case 's': return 4;
    case 'x':
    case 'd': return 8;
    case 'q':
    case 'v': return 16;
    default: return 0;
    }
}

bool isArm64ReplicateLoad(uint32_t id) {
    return id == ARM64_INS_LD1R || id == ARM64_INS_LD2R ||
        id == ARM64_INS_LD3R || id == ARM64_INS_LD4R;
}

VectorArrangement arm64Arrangement(
    const cs_arm64_op& input,
    const std::string& name,
    uint32_t instructionId,
    size_t operandIndex) {
    VectorArrangement arrangement;
    if (input.vas != ARM64_VAS_INVALID) {
        arrangement.elementSize = arm64VectorElementSize(input.vas);
        const auto vectorSize = arm64VectorSize(input.vas);
        if (arrangement.elementSize != 0) arrangement.elementCount = vectorSize / arrangement.elementSize;
        arrangement.replicate = isArm64ReplicateLoad(instructionId) ||
            (instructionId == ARM64_INS_DUP && operandIndex == 0);
        return arrangement;
    }
    if (name.empty()) return arrangement;
    if (name[0] == 'b' || name[0] == 'h' || name[0] == 's' || name[0] == 'd' || name[0] == 'q') {
        arrangement.elementSize = arm64RegisterSize(input, name);
        arrangement.elementCount = 1;
    }
    return arrangement;
}

uint16_t arm32LaneSize(int vectorSize, arm_vectordata_type vectorData) {
    if (vectorSize > 0) return static_cast<uint16_t>(vectorSize / 8);
    switch (vectorData) {
    case ARM_VECTORDATA_I8:
    case ARM_VECTORDATA_S8:
    case ARM_VECTORDATA_U8:
    case ARM_VECTORDATA_P8:
        return 1;
    case ARM_VECTORDATA_I16:
    case ARM_VECTORDATA_S16:
    case ARM_VECTORDATA_U16:
    case ARM_VECTORDATA_F16:
        return 2;
    case ARM_VECTORDATA_I32:
    case ARM_VECTORDATA_S32:
    case ARM_VECTORDATA_U32:
    case ARM_VECTORDATA_F32:
        return 4;
    case ARM_VECTORDATA_I64:
    case ARM_VECTORDATA_S64:
    case ARM_VECTORDATA_U64:
    case ARM_VECTORDATA_F64:
        return 8;
    default:
        return 0;
    }
}

uint16_t arm32OperandElementSize(
    uint32_t instructionId,
    size_t operandIndex,
    int vectorSize,
    arm_vectordata_type vectorData) {
    if (vectorSize > 0) return static_cast<uint16_t>(vectorSize / 8);
    const auto scalarSize = arm32LaneSize(0, vectorData);
    if (scalarSize != 0) {
        if ((instructionId == ARM_INS_VMULL || instructionId == ARM_INS_VQDMULL) && operandIndex == 0) {
            return static_cast<uint16_t>(scalarSize * 2);
        }
        return scalarSize;
    }

    const bool destination = operandIndex == 0;
    switch (vectorData) {
    case ARM_VECTORDATA_F16F64: return destination ? 2 : 8;
    case ARM_VECTORDATA_F64F16: return destination ? 8 : 2;
    case ARM_VECTORDATA_F32F16: return destination ? 4 : 2;
    case ARM_VECTORDATA_F16F32: return destination ? 2 : 4;
    case ARM_VECTORDATA_F64F32: return destination ? 8 : 4;
    case ARM_VECTORDATA_F32F64: return destination ? 4 : 8;
    case ARM_VECTORDATA_S32F32:
    case ARM_VECTORDATA_U32F32:
    case ARM_VECTORDATA_F32S32:
    case ARM_VECTORDATA_F32U32:
        return 4;
    case ARM_VECTORDATA_F64S16:
    case ARM_VECTORDATA_F64U16:
        return destination ? 8 : 2;
    case ARM_VECTORDATA_F32S16:
    case ARM_VECTORDATA_F32U16:
        return destination ? 4 : 2;
    case ARM_VECTORDATA_F64S32:
    case ARM_VECTORDATA_F64U32:
        return destination ? 8 : 4;
    case ARM_VECTORDATA_S16F64:
    case ARM_VECTORDATA_U16F64:
        return destination ? 2 : 8;
    case ARM_VECTORDATA_S16F32:
    case ARM_VECTORDATA_U16F32:
        return destination ? 2 : 4;
    case ARM_VECTORDATA_S32F64:
    case ARM_VECTORDATA_U32F64:
        return destination ? 4 : 8;
    case ARM_VECTORDATA_F16U16:
    case ARM_VECTORDATA_U16F16:
        return 2;
    case ARM_VECTORDATA_F16U32:
        return destination ? 2 : 4;
    case ARM_VECTORDATA_U32F16:
        return destination ? 4 : 2;
    default:
        return 0;
    }
}

uint16_t arm32PhysicalRegisterSize(int reg) {
    if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31) return 4;
    if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31) return 8;
    if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15) return 16;
    return 0;
}

VectorArrangement arm32Arrangement(
    const cs_arm_op& input,
    uint32_t instructionId,
    size_t operandIndex,
    int vectorSize,
    arm_vectordata_type vectorData,
    bool replicate) {
    VectorArrangement arrangement;
    const auto registerSize = arm32PhysicalRegisterSize(input.reg);
    if (registerSize == 0) return arrangement;
    arrangement.elementSize = arm32OperandElementSize(instructionId, operandIndex, vectorSize, vectorData);
    if (arrangement.elementSize == 0) arrangement.elementSize = registerSize;
    arrangement.elementCount = registerSize / arrangement.elementSize;
    arrangement.replicate = replicate;
    return arrangement;
}

uint16_t arm32RegisterSize(const cs_arm_op& input, int vectorSize, arm_vectordata_type vectorData) {
    if (input.neon_lane >= 0 || input.vector_index >= 0) {
        return arm32LaneSize(vectorSize, vectorData);
    }
    const auto size = arm32PhysicalRegisterSize(input.reg);
    return size == 0 ? uint16_t{4} : size;
}

Operand convertOperand(
    const cs_arm_op& input,
    csh handle,
    int vectorSize,
    arm_vectordata_type vectorData,
    uint32_t instructionId,
    size_t operandIndex,
    bool replicate) {
    Operand output;
    output.size = 4;
    output.shift = {static_cast<uint32_t>(input.shift.type), input.shift.value};
    switch (input.type) {
    case ARM_OP_REG:
        output.kind = OperandKind::Register;
        output.reg = registerName(handle, input.reg);
        output.size = arm32RegisterSize(input, vectorSize, vectorData);
        output.arrangement = arm32Arrangement(
            input, instructionId, operandIndex, vectorSize, vectorData, replicate);
        if (input.neon_lane >= 0) output.laneIndex = input.neon_lane;
        else if (input.vector_index >= 0) output.laneIndex = input.vector_index;
        break;
    case ARM_OP_IMM:
        output.kind = OperandKind::Immediate;
        output.immediate = input.imm;
        break;
    case ARM_OP_FP:
        output.kind = OperandKind::FloatingPoint;
        output.floatingPoint = input.fp;
        break;
    case ARM_OP_MEM:
        output.kind = OperandKind::Memory;
        output.size = 0;
        output.memoryBase = registerName(handle, input.mem.base);
        output.memoryIndex = registerName(handle, input.mem.index);
        output.displacement = input.mem.disp;
        output.scale = input.mem.scale;
        break;
    default:
        output.kind = OperandKind::Immediate;
        break;
    }
    return output;
}

Operand convertOperand(
    const cs_arm64_op& input,
    csh handle,
    uint32_t instructionId,
    size_t operandIndex) {
    Operand output;
    output.shift = {static_cast<uint32_t>(input.shift.type), input.shift.value};
    switch (input.type) {
    case ARM64_OP_REG:
        output.kind = OperandKind::Register;
        output.reg = registerName(handle, input.reg);
        output.size = arm64RegisterSize(input, output.reg);
        output.arrangement = arm64Arrangement(input, output.reg, instructionId, operandIndex);
        output.laneIndex = input.vector_index;
        break;
    case ARM64_OP_IMM:
    case ARM64_OP_CIMM:
        output.kind = OperandKind::Immediate;
        output.immediate = input.imm;
        break;
    case ARM64_OP_FP:
        output.kind = OperandKind::FloatingPoint;
        output.floatingPoint = input.fp;
        break;
    case ARM64_OP_MEM:
        output.kind = OperandKind::Memory;
        output.memoryBase = registerName(handle, input.mem.base);
        output.memoryIndex = registerName(handle, input.mem.index);
        output.displacement = input.mem.disp;
        output.scale = 1;
        break;
    default:
        output.kind = OperandKind::Immediate;
        output.immediate = 0;
        break;
    }
    return output;
}

uint16_t arm64MemorySize(const cs_insn& input, const std::vector<Operand>& operands) {
    const auto& detail = input.detail->arm64;
    const auto id = input.id;
    if (id == ARM64_INS_LDRAA || id == ARM64_INS_LDRAB) return 8;
    switch (id) {
    case ARM64_INS_LDRB:
    case ARM64_INS_LDURB:
    case ARM64_INS_LDTRB:
    case ARM64_INS_LDRSB:
    case ARM64_INS_LDURSB:
    case ARM64_INS_LDTRSB:
    case ARM64_INS_STRB:
    case ARM64_INS_STURB:
    case ARM64_INS_STTRB:
        return 1;
    case ARM64_INS_LDRH:
    case ARM64_INS_LDURH:
    case ARM64_INS_LDTRH:
    case ARM64_INS_LDRSH:
    case ARM64_INS_LDURSH:
    case ARM64_INS_LDTRSH:
    case ARM64_INS_STRH:
    case ARM64_INS_STURH:
    case ARM64_INS_STTRH:
        return 2;
    default:
        break;
    }
    if (id == ARM64_INS_LD64B || id == ARM64_INS_ST64B || id == ARM64_INS_ST64BV ||
        id == ARM64_INS_ST64BV0) return 64;
    const bool structure = id == ARM64_INS_LD1 || id == ARM64_INS_LD2 || id == ARM64_INS_LD3 ||
        id == ARM64_INS_LD4 || id == ARM64_INS_ST1 || id == ARM64_INS_ST2 ||
        id == ARM64_INS_ST3 || id == ARM64_INS_ST4 || id == ARM64_INS_LD1R ||
        id == ARM64_INS_LD2R || id == ARM64_INS_LD3R || id == ARM64_INS_LD4R;
    if (structure) {
        const bool replicate = id == ARM64_INS_LD1R || id == ARM64_INS_LD2R ||
            id == ARM64_INS_LD3R || id == ARM64_INS_LD4R;
        uint16_t size = 0;
        for (uint8_t i = 0; i < detail.op_count; ++i) {
            const auto& operand = detail.operands[i];
            if (operand.type != ARM64_OP_REG) continue;
            size += replicate || operand.vector_index >= 0
                ? arm64VectorElementSize(operand.vas)
                : arm64VectorSize(operand.vas);
        }
        return size;
    }

    if (id == ARM64_INS_LDPSW) return 8;
    if (id == ARM64_INS_LDP || id == ARM64_INS_LDNP || id == ARM64_INS_STP || id == ARM64_INS_STNP) {
        uint16_t size = 0;
        for (const auto& operand : operands) {
            if (operand.kind == OperandKind::Register) size += operand.size;
        }
        return size;
    }
    if (id == ARM64_INS_LDRSW || id == ARM64_INS_LDURSW || id == ARM64_INS_LDTRSW) return 4;

    bool scalar = true;
    bool hasRegister = false;
    uint16_t size = 0;
    for (const auto& operand : operands) {
        if (operand.kind != OperandKind::Register) continue;
        hasRegister = true;
        if (operand.size > size) size = operand.size;
        if (operand.size != 4 && operand.size != 8) scalar = false;
    }
    if (hasRegister && scalar) {
        const std::string mnemonic(input.mnemonic);
        if (!mnemonic.empty() && mnemonic.back() == 'b') return 1;
        if (!mnemonic.empty() && mnemonic.back() == 'h') return 2;
    }
    return size;
}

uint16_t arm32MemorySize(const cs_insn& input, const std::vector<Operand>& operands) {
    const auto& detail = input.detail->arm;
    switch (input.id) {
    case ARM_INS_LDRB:
    case ARM_INS_LDRBT:
    case ARM_INS_LDRSB:
    case ARM_INS_LDRSBT:
    case ARM_INS_LDREXB:
    case ARM_INS_LDAEXB:
    case ARM_INS_LDAB:
    case ARM_INS_STRB:
    case ARM_INS_STRBT:
    case ARM_INS_STREXB:
    case ARM_INS_STLEXB:
    case ARM_INS_STLB:
        return 1;
    case ARM_INS_LDRH:
    case ARM_INS_LDRHT:
    case ARM_INS_LDRSH:
    case ARM_INS_LDRSHT:
    case ARM_INS_LDREXH:
    case ARM_INS_LDAEXH:
    case ARM_INS_LDAH:
    case ARM_INS_STRH:
    case ARM_INS_STRHT:
    case ARM_INS_STREXH:
    case ARM_INS_STLEXH:
    case ARM_INS_STLH:
        return 2;
    case ARM_INS_LDRD:
    case ARM_INS_LDREXD:
    case ARM_INS_LDAEXD:
    case ARM_INS_STRD:
    case ARM_INS_STREXD:
    case ARM_INS_STLEXD:
        return 8;
    default:
        break;
    }

    const bool structure = input.id == ARM_INS_VLD1 || input.id == ARM_INS_VLD2 ||
        input.id == ARM_INS_VLD3 || input.id == ARM_INS_VLD4 || input.id == ARM_INS_VST1 ||
        input.id == ARM_INS_VST2 || input.id == ARM_INS_VST3 || input.id == ARM_INS_VST4;
    const bool multiple = input.id == ARM_INS_VLDMDB || input.id == ARM_INS_VLDMIA ||
        input.id == ARM_INS_VSTMDB || input.id == ARM_INS_VSTMIA;
    if (structure || multiple) {
        const bool replicate = structure && std::string(input.op_str).find("[]") != std::string::npos;
        uint16_t size = 0;
        for (uint8_t i = 0; i < detail.op_count; ++i) {
            const auto& operand = detail.operands[i];
            if (structure && operand.type == ARM_OP_MEM) break;
            if (operand.type != ARM_OP_REG) continue;
            if (multiple && i == 0) continue; // base register is not transferred
            if (structure && (replicate || operand.neon_lane >= 0 || operand.vector_index >= 0) && detail.vector_size > 0) {
                size += static_cast<uint16_t>(detail.vector_size / 8);
            } else {
                size += arm32RegisterSize(operand, detail.vector_size, detail.vector_data);
            }
        }
        return size;
    }

    uint16_t size = 0;
    for (const auto& operand : operands) {
        if (operand.kind == OperandKind::Register && operand.size > size) size = operand.size;
    }
    return size;
}

Operand convertOperand(const cs_x86_op& input, csh handle) {
    Operand output;
    output.size = input.size;
    switch (input.type) {
    case X86_OP_REG:
        output.kind = OperandKind::Register;
        output.reg = registerName(handle, input.reg);
        break;
    case X86_OP_IMM:
        output.kind = OperandKind::Immediate;
        output.immediate = input.imm;
        break;
    case X86_OP_MEM:
        output.kind = OperandKind::Memory;
        output.memoryBase = registerName(handle, input.mem.base);
        output.memoryIndex = registerName(handle, input.mem.index);
        output.displacement = input.mem.disp;
        output.scale = input.mem.scale;
        break;
    default:
        output.kind = OperandKind::Immediate;
        output.immediate = 0;
        break;
    }
    return output;
}

VectorArrangement makeArrangement(uint16_t elementSize, uint16_t elementCount, bool replicate = false) {
    return {elementSize, elementCount, replicate};
}

bool isX86VectorOperand(const Operand& operand) {
    if (operand.kind == OperandKind::Memory) return true;
    if (operand.kind != OperandKind::Register) return false;
    return operand.reg.rfind("xmm", 0) == 0 || operand.reg.rfind("ymm", 0) == 0 ||
        operand.reg.rfind("zmm", 0) == 0 || operand.reg.rfind("mm", 0) == 0;
}

VectorArrangement x86Arrangement(const cs_insn& input, size_t operandIndex, const Operand& operand) {
    if (!isX86VectorOperand(operand)) return {};
    const auto id = input.id;
    const auto& detail = input.detail->x86;

    uint16_t destinationElement = 0;
    uint16_t sourceElement = 0;
    bool packedConversion = false;
    switch (id) {
    case X86_INS_CVTSS2SD: destinationElement = 8; sourceElement = 4; break;
    case X86_INS_CVTSD2SS: destinationElement = 4; sourceElement = 8; break;
    case X86_INS_CVTDQ2PS:
    case X86_INS_CVTPS2DQ:
    case X86_INS_CVTTPS2DQ:
        destinationElement = 4; sourceElement = 4; packedConversion = true; break;
    case X86_INS_CVTDQ2PD: destinationElement = 8; sourceElement = 4; packedConversion = true; break;
    case X86_INS_CVTPD2DQ:
    case X86_INS_CVTTPD2DQ:
        destinationElement = 4; sourceElement = 8; packedConversion = true; break;
    case X86_INS_CVTPD2PS: destinationElement = 4; sourceElement = 8; packedConversion = true; break;
    case X86_INS_CVTPS2PD: destinationElement = 8; sourceElement = 4; packedConversion = true; break;
    default: break;
    }
    if (destinationElement != 0) {
        const auto elementSize = operandIndex == 0 ? destinationElement : sourceElement;
        if (!packedConversion) return makeArrangement(elementSize, 1);
        if (detail.op_count < 2) return {};
        const auto destinationCount = detail.operands[0].size / destinationElement;
        const auto sourceCount = detail.operands[1].size / sourceElement;
        return makeArrangement(elementSize, destinationCount < sourceCount ? destinationCount : sourceCount);
    }

    if (id == X86_INS_CVTSI2SS || id == X86_INS_CVTSI2SD) {
        const auto elementSize = operandIndex == 0 ? (id == X86_INS_CVTSI2SS ? 4 : 8) : operand.size;
        return makeArrangement(elementSize, 1);
    }
    if (id == X86_INS_CVTSS2SI || id == X86_INS_CVTTSS2SI) {
        return operandIndex == 0 ? VectorArrangement{} : makeArrangement(4, 1);
    }
    if (id == X86_INS_CVTSD2SI || id == X86_INS_CVTTSD2SI) {
        return operandIndex == 0 ? VectorArrangement{} : makeArrangement(8, 1);
    }

    uint16_t insertExtractWidth = 0;
    switch (id) {
    case X86_INS_PINSRB:
    case X86_INS_PEXTRB: insertExtractWidth = 1; break;
    case X86_INS_PINSRW:
    case X86_INS_PEXTRW: insertExtractWidth = 2; break;
    case X86_INS_PINSRD:
    case X86_INS_PEXTRD: insertExtractWidth = 4; break;
    case X86_INS_PINSRQ:
    case X86_INS_PEXTRQ: insertExtractWidth = 8; break;
    default: break;
    }
    if (insertExtractWidth != 0) {
        const bool vector = operand.kind == OperandKind::Register;
        return makeArrangement(
            insertExtractWidth,
            vector ? static_cast<uint16_t>(operand.size / insertExtractWidth) : uint16_t{1});
    }

    uint16_t elementSize = 0;
    bool packed = true;
    bool replicate = false;
    switch (id) {
    case X86_INS_MOVDDUP:
        elementSize = 8;
        replicate = operandIndex == 0;
        break;
    case X86_INS_MOVSHDUP:
    case X86_INS_MOVSLDUP:
        elementSize = 4;
        replicate = operandIndex == 0;
        break;
    case X86_INS_MOVSS:
    case X86_INS_ADDSS:
    case X86_INS_SUBSS:
    case X86_INS_MULSS:
    case X86_INS_DIVSS:
    case X86_INS_CMPSS:
    case X86_INS_UCOMISS:
    case X86_INS_COMISS:
        elementSize = 4;
        packed = false;
        break;
    case X86_INS_MOVSD:
    case X86_INS_ADDSD:
    case X86_INS_SUBSD:
    case X86_INS_MULSD:
    case X86_INS_DIVSD:
    case X86_INS_CMPSD:
    case X86_INS_UCOMISD:
    case X86_INS_COMISD:
        elementSize = 8;
        packed = false;
        break;
    case X86_INS_MOVAPS:
    case X86_INS_MOVUPS:
    case X86_INS_ADDPS:
    case X86_INS_SUBPS:
    case X86_INS_MULPS:
    case X86_INS_DIVPS:
    case X86_INS_CMPPS:
        elementSize = 4;
        break;
    case X86_INS_MOVAPD:
    case X86_INS_MOVUPD:
    case X86_INS_ADDPD:
    case X86_INS_SUBPD:
    case X86_INS_MULPD:
    case X86_INS_DIVPD:
    case X86_INS_CMPPD:
        elementSize = 8;
        break;
    case X86_INS_PMULHW:
    case X86_INS_PMULHUW:
    case X86_INS_PMULLW:
        elementSize = 2;
        break;
    case X86_INS_MOVDQA:
    case X86_INS_MOVDQU:
        elementSize = 1;
        break;
    case X86_INS_MOVD:
        elementSize = 4;
        packed = false;
        break;
    case X86_INS_MOVQ:
        elementSize = 8;
        packed = false;
        break;
    default:
        return {};
    }
    const auto elementCount = packed && elementSize != 0 ? operand.size / elementSize : 1;
    return makeArrangement(elementSize, elementCount, replicate);
}

VectorArrangement memoryArrangement(const std::vector<Operand>& operands, uint16_t memorySize) {
    for (const auto& operand : operands) {
        if (operand.kind != OperandKind::Register || operand.arrangement.elementSize == 0) continue;
        const auto elementSize = operand.arrangement.elementSize;
        if (memorySize % elementSize != 0) return {};
        return makeArrangement(elementSize, memorySize / elementSize);
    }
    return {};
}

std::optional<int64_t> postIndexImmediate(const cs_insn& input) {
    const std::string text(input.op_str);
    const auto bracket = text.rfind("],");
    if (bracket == std::string::npos) return std::nullopt;
    size_t position = bracket + 2;
    while (position < text.size() && text[position] == ' ') ++position;
    if (position >= text.size() || text[position] != '#') return std::nullopt;
    try {
        return std::stoll(text.c_str() + position + 1, nullptr, 0);
    } catch (const std::exception&) {
        throw std::runtime_error("Invalid Capstone post-index immediate: " + text);
    }
}

size_t memoryOperandIndex(const NativeInstruction& instruction) {
    for (size_t i = 0; i < instruction.operands.size(); ++i) {
        if (instruction.operands[i].kind == OperandKind::Memory) return i;
    }
    return instruction.operands.size();
}

void applyPostIndexOffset(const cs_insn& input, NativeInstruction& output, size_t memoryIndex) {
    if (memoryIndex + 1 < output.operands.size()) {
        const auto& offset = output.operands[memoryIndex + 1];
        if (offset.kind == OperandKind::Register) output.writebackRegister = offset.reg;
        else if (offset.kind == OperandKind::Immediate) output.writebackOffset = offset.immediate;
        return;
    }
    if (const auto offset = postIndexImmediate(input)) output.writebackOffset = *offset;
}

void applyArm64Writeback(const cs_insn& input, NativeInstruction& output) {
    const auto& detail = input.detail->arm64;
    if (!detail.writeback) return;
    const auto memoryIndex = memoryOperandIndex(output);
    if (memoryIndex == output.operands.size()) return;
    output.writeback = detail.post_index ? WritebackMode::PostIndex : WritebackMode::PreIndex;
    if (output.writeback == WritebackMode::PreIndex) {
        output.writebackOffset = output.operands[memoryIndex].displacement;
    } else {
        applyPostIndexOffset(input, output, memoryIndex);
    }
}

bool isArm32Structure(uint32_t id) {
    return id == ARM_INS_VLD1 || id == ARM_INS_VLD2 || id == ARM_INS_VLD3 || id == ARM_INS_VLD4 ||
        id == ARM_INS_VST1 || id == ARM_INS_VST2 || id == ARM_INS_VST3 || id == ARM_INS_VST4;
}

void applyArm32Writeback(const cs_insn& input, NativeInstruction& output) {
    const auto& detail = input.detail->arm;
    const auto memoryIndex = memoryOperandIndex(output);
    if (memoryIndex != output.operands.size()) {
        const bool explicitPostIndex = memoryIndex + 1 < output.operands.size();
        if (!detail.writeback && !explicitPostIndex) return;
        if (explicitPostIndex || isArm32Structure(input.id)) {
            output.writeback = WritebackMode::PostIndex;
            if (explicitPostIndex) applyPostIndexOffset(input, output, memoryIndex);
            else output.writebackOffset = output.operands[memoryIndex].size;
        } else {
            output.writeback = WritebackMode::PreIndex;
            output.writebackOffset = output.operands[memoryIndex].displacement;
        }
        return;
    }
    if (!detail.writeback) return;

    const bool decrement = input.id == ARM_INS_VLDMDB || input.id == ARM_INS_VSTMDB;
    const bool increment = input.id == ARM_INS_VLDMIA || input.id == ARM_INS_VSTMIA;
    if (!decrement && !increment) {
        output.writeback = detail.post_index ? WritebackMode::PostIndex : WritebackMode::PreIndex;
        return;
    }
    int64_t offset = 0;
    for (size_t i = 1; i < output.operands.size(); ++i) offset += output.operands[i].size;
    output.writeback = decrement ? WritebackMode::PreIndex : WritebackMode::PostIndex;
    output.writebackOffset = decrement ? -offset : offset;
}

NativeInstruction convertInstruction(const cs_insn& input, Architecture architecture, csh handle) {
    NativeInstruction output;
    output.id = input.id;
    output.address = input.address;
    output.size = input.size;
    output.mnemonic = input.mnemonic;
    output.text = std::string(input.mnemonic) + " " + input.op_str;

    if (input.detail == nullptr) {
        throw std::runtime_error("Capstone returned an instruction without details");
    }

    if (architecture == Architecture::Arm64) {
        const auto& detail = input.detail->arm64;
        output.conditionCode = detail.cc;
        output.operands.reserve(detail.op_count);
        for (uint8_t i = 0; i < detail.op_count; ++i) {
            auto operand = convertOperand(detail.operands[i], handle, input.id, i);
            if (operand.kind == OperandKind::Memory) {
                operand.size = arm64MemorySize(input, output.operands);
                operand.arrangement = memoryArrangement(output.operands, operand.size);
            } else if (operand.kind == OperandKind::FloatingPoint && !output.operands.empty() &&
                output.operands[0].kind == OperandKind::Register) {
                operand.size = output.operands[0].size;
                operand.arrangement = makeArrangement(operand.size, 1);
            } else if (operand.kind == OperandKind::Immediate && !output.operands.empty()) {
                const auto elementSize = output.operands[0].arrangement.elementSize;
                if ((input.id == ARM64_INS_MOVI || input.id == ARM64_INS_MVNI) && elementSize != 0) {
                    operand.size = elementSize;
                    operand.arrangement = makeArrangement(elementSize, 1);
                } else if (input.id == ARM64_INS_EXT ||
                    ((input.id == ARM64_INS_CCMP || input.id == ARM64_INS_CCMN ||
                      input.id == ARM64_INS_FCCMP || input.id == ARM64_INS_FCCMPE) && i == 2)) {
                    operand.size = 1;
                    operand.arrangement = makeArrangement(1, 1);
                } else if ((input.id == ARM64_INS_CCMP || input.id == ARM64_INS_CCMN) && i == 1) {
                    operand.size = output.operands[0].size;
                }
            }
            output.operands.push_back(std::move(operand));
        }
        applyArm64Writeback(input, output);
    } else if (architecture == Architecture::Arm32) {
        const auto& detail = input.detail->arm;
        output.conditionCode = detail.cc;
        output.operands.reserve(detail.op_count);
        const bool replicateLoad = std::string(input.op_str).find("[]") != std::string::npos;
        for (uint8_t i = 0; i < detail.op_count; ++i) {
            const auto& rawOperand = detail.operands[i];
            const bool replicate = rawOperand.type == ARM_OP_REG &&
                (replicateLoad || (input.id == ARM_INS_VDUP && i == 0));
            auto operand = convertOperand(
                rawOperand, handle, detail.vector_size, detail.vector_data, input.id, i, replicate);
            if (operand.kind == OperandKind::Memory) {
                operand.size = arm32MemorySize(input, output.operands);
                operand.arrangement = memoryArrangement(output.operands, operand.size);
            } else if (operand.kind == OperandKind::FloatingPoint && !output.operands.empty() &&
                output.operands[0].kind == OperandKind::Register) {
                operand.size = output.operands[0].size;
                operand.arrangement = makeArrangement(operand.size, 1);
            } else if (operand.kind == OperandKind::Immediate && !output.operands.empty()) {
                const auto elementSize = output.operands[0].arrangement.elementSize;
                if ((input.id == ARM_INS_VMOV || input.id == ARM_INS_VMVN) && elementSize != 0) {
                    operand.size = elementSize;
                    operand.arrangement = makeArrangement(elementSize, 1);
                } else if (input.id == ARM_INS_VEXT) {
                    operand.size = 1;
                    operand.arrangement = makeArrangement(1, 1);
                }
            }
            output.operands.push_back(std::move(operand));
        }
        applyArm32Writeback(input, output);
    } else {
        output.operands.reserve(input.detail->x86.op_count);
        for (uint8_t i = 0; i < input.detail->x86.op_count; ++i) {
            auto operand = convertOperand(input.detail->x86.operands[i], handle);
            operand.arrangement = x86Arrangement(input, i, operand);
            output.operands.push_back(std::move(operand));
        }
    }
    return output;
}

bool decodeNext(
    csh handle,
    cs_insn* instruction,
    const uint8_t** code,
    size_t* size,
    uint64_t* address) {
    if (cs_disasm_iter(handle, code, size, address, instruction)) {
        return true;
    }

    const auto error = cs_errno(handle);
    if (error != CS_ERR_OK) {
        throw std::runtime_error("cs_disasm_iter failed: " + std::string(cs_strerror(error)));
    }
    return false;
}

} // namespace

RecursiveDecoder::RecursiveDecoder(Architecture architecture, Arm32Mode arm32Mode)
    : architecture_(architecture),
      arm32Mode_(arm32Mode) {
    (void)getCapstoneArchitecture(architecture_, arm32Mode_);
}

std::optional<NativeInstruction> RecursiveDecoder::decodeInstruction(
    const uint8_t* code,
    size_t size,
    uint64_t address) const {
    if (code == nullptr && size != 0) {
        throw std::invalid_argument("Code pointer is null");
    }
    if (size == 0) {
        return std::nullopt;
    }

    const auto target = getCapstoneArchitecture(architecture_, arm32Mode_);
    const csh handle = acquireCapstoneHandle(target);
    CapstoneInstruction instruction(handle);
    const uint8_t* currentCode = code;
    size_t currentSize = size;
    uint64_t currentAddress = address;
    if (!decodeNext(handle, instruction.get(), &currentCode, &currentSize, &currentAddress)) {
        return std::nullopt;
    }
    return convertInstruction(*instruction.get(), architecture_, handle);
}

std::vector<NativeInstruction> RecursiveDecoder::decodeRange(
    const uint8_t* code,
    size_t size,
    uint64_t address,
    size_t maxInstructions) const {
    if (code == nullptr && size != 0) {
        throw std::invalid_argument("Code pointer is null");
    }

    std::vector<NativeInstruction> result;
    if (size == 0) {
        return result;
    }
    const auto target = getCapstoneArchitecture(architecture_, arm32Mode_);
    const csh handle = acquireCapstoneHandle(target);
    CapstoneInstruction instruction(handle);
    const uint8_t* currentCode = code;
    size_t currentSize = size;
    uint64_t currentAddress = address;
    while (currentSize != 0 && (maxInstructions == 0 || result.size() < maxInstructions)) {
        if (!decodeNext(handle, instruction.get(), &currentCode, &currentSize, &currentAddress)) {
            break;
        }
        result.push_back(convertInstruction(*instruction.get(), architecture_, handle));
    }
    return result;
}

std::vector<NativeInstruction> Disassembler::disassemble(
    Architecture architecture,
    const uint8_t* code,
    size_t size,
    uint64_t address) const {
    return RecursiveDecoder(architecture).decodeRange(code, size, address);
}

} // namespace il2cpprec
