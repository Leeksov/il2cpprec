#include <il2cpprec/flow/RecursiveDecoder.hpp>

#include <capstone/arm.h>
#include <capstone/arm64.h>
#include <capstone/x86.h>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace il2cpprec::flow {
namespace {

enum class FlowKind {
    Next,
    Conditional,
    Unconditional,
    Return
};

size_t maxInstructionSize(Architecture architecture) {
    switch (architecture) {
    case Architecture::Arm32:
    case Architecture::Arm64:
        return 4;
    case Architecture::X86:
    case Architecture::X64:
        return 15;
    }
    return 1;
}

bool hasRegister(const NativeInstruction& instruction, const char* name) {
    return std::any_of(instruction.operands.begin(), instruction.operands.end(), [&](const Operand& operand) {
        return operand.kind == OperandKind::Register && operand.reg == name;
    });
}

FlowKind flowKind(const NativeInstruction& instruction, Architecture architecture) {
    switch (architecture) {
    case Architecture::Arm64:
        if (instruction.id == ARM64_INS_RET || instruction.mnemonic == "retaa" || instruction.mnemonic == "retab") {
            return FlowKind::Return;
        }
        if (instruction.id == ARM64_INS_BR) {
            return hasRegister(instruction, "x30") || hasRegister(instruction, "lr")
                ? FlowKind::Return
                : FlowKind::Unconditional;
        }
        if (instruction.id == ARM64_INS_B) {
            return instruction.conditionCode == ARM64_CC_AL || instruction.conditionCode == ARM64_CC_INVALID
                ? FlowKind::Unconditional
                : FlowKind::Conditional;
        }
        if (instruction.id == ARM64_INS_CBZ || instruction.id == ARM64_INS_CBNZ ||
            instruction.id == ARM64_INS_TBZ || instruction.id == ARM64_INS_TBNZ) {
            return FlowKind::Conditional;
        }
        return FlowKind::Next;
    case Architecture::Arm32: {
        const bool conditional = instruction.conditionCode != ARM_CC_AL && instruction.conditionCode != ARM_CC_INVALID;
        if (instruction.id == ARM_INS_BX || instruction.id == ARM_INS_BXNS) {
            if (conditional) return FlowKind::Conditional;
            return instruction.id == ARM_INS_BX && hasRegister(instruction, "lr")
                ? FlowKind::Return
                : FlowKind::Unconditional;
        }
        if (instruction.id == ARM_INS_B) {
            return conditional ? FlowKind::Conditional : FlowKind::Unconditional;
        }
        if (instruction.id == ARM_INS_CBZ || instruction.id == ARM_INS_CBNZ) return FlowKind::Conditional;
        if (instruction.id == ARM_INS_POP && hasRegister(instruction, "pc")) {
            return conditional ? FlowKind::Conditional : FlowKind::Return;
        }
        if (instruction.id == ARM_INS_MOV && !instruction.operands.empty() &&
            instruction.operands.front().kind == OperandKind::Register && instruction.operands.front().reg == "pc") {
            if (conditional) return FlowKind::Conditional;
            return hasRegister(instruction, "lr") ? FlowKind::Return : FlowKind::Unconditional;
        }
        return FlowKind::Next;
    }
    case Architecture::X86:
    case Architecture::X64:
        if (instruction.id == X86_INS_RET || instruction.id == X86_INS_RETF || instruction.id == X86_INS_RETFQ ||
            instruction.mnemonic == "iret" || instruction.mnemonic == "iretd" || instruction.mnemonic == "iretq") {
            return FlowKind::Return;
        }
        if (instruction.id == X86_INS_JMP) return FlowKind::Unconditional;
        if ((instruction.id >= X86_INS_JAE && instruction.id <= X86_INS_JNS) ||
            instruction.id == X86_INS_JCXZ || instruction.id == X86_INS_JECXZ || instruction.id == X86_INS_JRCXZ ||
            instruction.id == X86_INS_LOOP || instruction.id == X86_INS_LOOPE || instruction.id == X86_INS_LOOPNE) {
            return FlowKind::Conditional;
        }
        return FlowKind::Next;
    }
    return FlowKind::Next;
}

bool decodeBounds(
    const FunctionImage& image,
    const std::vector<Section>& sections,
    uint64_t address,
    size_t& available) {
    if (address < image.address) return false;
    const uint64_t offset = address - image.address;
    if (offset >= image.size) return false;

    const size_t imageRemaining = image.size - static_cast<size_t>(offset);
    if (sections.empty()) {
        available = imageRemaining;
        return true;
    }

    size_t sectionRemaining = 0;
    for (const auto& section : sections) {
        if (!section.executable || address < section.virtualAddress) continue;
        const uint64_t sectionOffset = address - section.virtualAddress;
        const uint64_t sectionSize = section.virtualSize != 0 ? section.virtualSize : section.fileSize;
        if (sectionOffset >= sectionSize) continue;
        const uint64_t remaining = sectionSize - sectionOffset;
        const size_t bounded = remaining > std::numeric_limits<size_t>::max()
            ? std::numeric_limits<size_t>::max()
            : static_cast<size_t>(remaining);
        sectionRemaining = std::max(sectionRemaining, bounded);
    }
    if (sectionRemaining == 0) return false;
    available = std::min(imageRemaining, sectionRemaining);
    return true;
}

std::optional<uint64_t> directTarget(const NativeInstruction& instruction) {
    if (instruction.operands.empty()) return std::nullopt;
    const auto& operand = instruction.operands.back();
    if (operand.kind != OperandKind::Immediate) return std::nullopt;
    return static_cast<uint64_t>(operand.immediate);
}

} // namespace

std::optional<NativeInstruction> DisassemblerInstructionDecoder::decodeOne(
    Architecture architecture,
    const uint8_t* code,
    size_t size,
    uint64_t address) const {
    if (code == nullptr || size == 0) return std::nullopt;
    const il2cpprec::RecursiveDecoder decoder(architecture);
    return decoder.decodeInstruction(code, std::min(size, maxInstructionSize(architecture)), address);
}

RecursiveDecoder::RecursiveDecoder()
    : decoder_(std::make_shared<DisassemblerInstructionDecoder>()) {}

RecursiveDecoder::RecursiveDecoder(std::shared_ptr<const InstructionDecoder> decoder)
    : decoder_(std::move(decoder)) {
    if (!decoder_) decoder_ = std::make_shared<DisassemblerInstructionDecoder>();
}

DecodeResult RecursiveDecoder::decode(
    const FunctionImage& image,
    const std::vector<Section>& sections,
    const DecodeOptions& options) const {
    struct PendingBlock {
        DecodedBasicBlock block;
        uint64_t lastAddress = 0;
    };

    DecodeResult result;
    std::map<uint64_t, NativeInstruction> decoded;
    std::set<uint64_t> pending;
    std::set<uint64_t> started;
    std::vector<PendingBlock> decodedBlocks;
    std::set<std::tuple<uint64_t, DecodeDiagnosticKind, uint64_t>> diagnosticKeys;

    auto diagnostic = [&](DecodeDiagnosticKind kind, uint64_t address, uint64_t target = 0) {
        if (diagnosticKeys.emplace(address, kind, target).second) {
            result.diagnostics.push_back({kind, address, target});
        }
    };

    if (image.code == nullptr || image.size == 0) {
        diagnostic(DecodeDiagnosticKind::InvalidImage, image.address);
        return result;
    }

    const il2cpprec::RecursiveDecoder nativeDecoder(image.architecture, image.arm32Mode);
    const bool useNativeDecoder = dynamic_cast<const DisassemblerInstructionDecoder*>(decoder_.get()) != nullptr;

    size_t available = 0;
    if (!decodeBounds(image, sections, image.address, available)) {
        diagnostic(DecodeDiagnosticKind::OutsideExecutableSection, image.address);
        return result;
    }
    pending.insert(image.address);

    bool budgetExceeded = false;
    while (!pending.empty() && !budgetExceeded) {
        const uint64_t start = *pending.begin();
        pending.erase(pending.begin());
        if (!started.insert(start).second || decoded.contains(start)) continue;

        DecodedBasicBlock block;
        block.address = start;
        std::vector<uint64_t> addresses;
        uint64_t cursor = start;

        while (true) {
            const auto existing = decoded.find(cursor);
            if (existing != decoded.end()) {
                block.fallthrough = cursor;
                break;
            }

            const auto predecessor = decoded.upper_bound(cursor);
            if (predecessor != decoded.begin()) {
                const auto previous = std::prev(predecessor);
                if (cursor - previous->first < previous->second.size) {
                    diagnostic(DecodeDiagnosticKind::OverlappingStart, cursor, previous->first);
                    break;
                }
            }

            if (!decodeBounds(image, sections, cursor, available)) break;
            if (decoded.size() >= options.maxInstructions) {
                diagnostic(DecodeDiagnosticKind::InstructionBudgetExceeded, cursor);
                budgetExceeded = true;
                break;
            }

            const size_t offset = static_cast<size_t>(cursor - image.address);
            const auto nativeSize = std::min(available, maxInstructionSize(image.architecture));
            auto instruction = useNativeDecoder
                ? nativeDecoder.decodeInstruction(image.code + offset, nativeSize, cursor)
                : decoder_->decodeOne(image.architecture, image.code + offset, available, cursor);
            if (!instruction || instruction->address != cursor || instruction->size == 0 ||
                instruction->size > available ||
                static_cast<uint64_t>(instruction->size - 1) > std::numeric_limits<uint64_t>::max() - cursor) {
                diagnostic(DecodeDiagnosticKind::DecodeFailed, cursor);
                break;
            }

            if (cursor != std::numeric_limits<uint64_t>::max()) {
                const auto following = decoded.lower_bound(cursor + 1);
                if (following != decoded.end() && following->first - cursor < instruction->size) {
                    diagnostic(DecodeDiagnosticKind::OverlappingStart, cursor, following->first);
                    break;
                }
            }

            const FlowKind flow = flowKind(*instruction, image.architecture);
            const bool hasNext = instruction->size <= std::numeric_limits<uint64_t>::max() - cursor;
            const uint64_t next = hasNext ? cursor + instruction->size : 0;
            decoded.emplace(cursor, std::move(*instruction));
            addresses.push_back(cursor);

            if (flow == FlowKind::Return) break;
            if (flow == FlowKind::Conditional || flow == FlowKind::Unconditional) {
                const auto& branch = decoded.at(cursor);
                const auto target = directTarget(branch);
                if (target) {
                    block.directTarget = *target;
                    size_t targetAvailable = 0;
                    if (decodeBounds(image, sections, *target, targetAvailable)) {
                        pending.insert(*target);
                    } else {
                        diagnostic(DecodeDiagnosticKind::UnresolvedTarget, cursor, *target);
                    }
                } else {
                    diagnostic(
                        branch.operands.empty() ? DecodeDiagnosticKind::UnresolvedTarget : DecodeDiagnosticKind::IndirectTarget,
                        cursor);
                }

                if (flow == FlowKind::Unconditional) break;
                if (hasNext && decodeBounds(image, sections, next, available)) {
                    block.fallthrough = next;
                    pending.insert(next);
                }
                break;
            }

            if (!hasNext || !decodeBounds(image, sections, next, available)) break;
            cursor = next;
        }

        if (!addresses.empty()) {
            decodedBlocks.push_back({std::move(block), addresses.back()});
        }
    }

    result.instructions.reserve(decoded.size());
    std::map<uint64_t, size_t> indices;
    for (const auto& [address, instruction] : decoded) {
        indices.emplace(address, result.instructions.size());
        result.instructions.push_back(instruction);
    }

    std::sort(decodedBlocks.begin(), decodedBlocks.end(), [](const PendingBlock& left, const PendingBlock& right) {
        return left.block.address < right.block.address;
    });
    result.blocks.reserve(decodedBlocks.size());
    for (auto& pendingBlock : decodedBlocks) {
        const auto begin = indices.find(pendingBlock.block.address);
        const auto last = indices.find(pendingBlock.lastAddress);
        if (begin == indices.end() || last == indices.end()) continue;
        pendingBlock.block.instructionBegin = begin->second;
        pendingBlock.block.instructionEnd = last->second + 1;
        result.blocks.push_back(std::move(pendingBlock.block));
    }

    std::sort(result.diagnostics.begin(), result.diagnostics.end(), [](const DecodeDiagnostic& left, const DecodeDiagnostic& right) {
        return std::tie(left.address, left.kind, left.target) < std::tie(right.address, right.kind, right.target);
    });
    return result;
}

} // namespace il2cpprec::flow
