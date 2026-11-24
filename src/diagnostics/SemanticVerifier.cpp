#include <il2cpprec/diagnostics/SemanticVerifier.hpp>

#include <exception>
#include <limits>
#include <unordered_set>
#include <utility>

namespace il2cpprec {
namespace {

bool inside(const FunctionImage& image, uint64_t address) {
    return address >= image.address && address - image.address < image.size;
}

void finding(VerificationResult& result, std::string code, uint64_t address, std::string message) {
    if (result.findings.size() < 32) {
        result.findings.push_back({std::move(code), address, std::move(message)});
    }
}

void checkExpression(
    const ExpressionPtr& expression,
    uint64_t address,
    VerificationResult& result,
    std::unordered_set<const Expression*>& visited) {
    if (!expression || !visited.insert(expression.get()).second) return;
    if (expression->kind == Expression::Kind::Unknown) {
        finding(result, "unknown-expression", address, "final IR contains an unknown expression");
    }
    for (const auto& argument : expression->arguments) {
        checkExpression(argument, address, result, visited);
    }
}

} // namespace

const char* toString(VerificationStatus status) noexcept {
    switch (status) {
    case VerificationStatus::NoFinding: return "no-finding";
    case VerificationStatus::Suspect: return "suspect";
    case VerificationStatus::Unverifiable: return "unverifiable";
    }
    return "unverifiable";
}

VerificationResult SemanticVerifier::verify(
    const FunctionImage& image,
    const RecoveredFunction& function) const {
    VerificationResult result;
    if (!image.code || image.size == 0 || function.blocks.empty() ||
        image.address > std::numeric_limits<uint64_t>::max() - image.size ||
        image.architecture != function.architecture || image.address != function.address) {
        finding(result, "invalid-input", image.address, "native bytes or matching recovered function are unavailable");
        return result;
    }

    // Decode independently from the recovered CFG. Inline data and padding can
    // decode as instructions, so the unmapped count is diagnostic only.
    RecursiveDecoder decoder(image.architecture, image.arm32Mode);
    std::unordered_set<uint64_t> decoded;
    for (size_t offset = 0; offset < image.size;) {
        std::optional<NativeInstruction> instruction;
        try {
            instruction = decoder.decodeInstruction(
                image.code + offset, image.size - offset, image.address + offset);
        } catch (const std::exception& error) {
            finding(result, "decode-error", image.address + offset, error.what());
            return result;
        }
        if (!instruction || instruction->size == 0 || instruction->size > image.size - offset) {
            finding(result, "decode-gap", image.address + offset, "independent linear decode stopped here");
            break;
        }
        decoded.insert(instruction->address);
        ++result.decodedInstructions;
        offset += instruction->size;
    }

    std::unordered_set<uint64_t> blocks;
    std::unordered_set<uint64_t> represented;
    for (const auto& block : function.blocks) {
        if (!inside(image, block.address)) {
            finding(result, "block-outside-image", block.address, "IR block starts outside native method bytes");
        }
        if (!blocks.insert(block.address).second) {
            finding(result, "duplicate-block", block.address, "IR contains duplicate block starts");
        }
    }

    for (const auto& block : function.blocks) {
        for (const auto& statement : block.statements) {
            // Address zero marks a statement synthesized by an IR pass. It has
            // no native instruction to map and is not an out-of-bounds byte.
            if (statement.address != 0) {
                if (!inside(image, statement.address)) {
                    finding(result, "statement-outside-image", statement.address, "IR statement is outside native method bytes");
                } else if (!decoded.contains(statement.address)) {
                    finding(result, "statement-not-decoded", statement.address, "IR statement does not start at a decoded instruction");
                } else {
                    represented.insert(statement.address);
                }
            }
            std::unordered_set<const Expression*> visited;
            checkExpression(statement.destination, statement.address, result, visited);
            checkExpression(statement.value, statement.address, result, visited);
            checkExpression(statement.condition, statement.address, result, visited);
            checkExpression(statement.target, statement.address, result, visited);
            for (const auto& argument : statement.arguments) {
                checkExpression(argument, statement.address, result, visited);
            }
            if (statement.kind == Statement::Kind::ConditionalBranch && !statement.condition) {
                finding(result, "missing-condition", statement.address,
                    "conditional branch has no condition expression");
            }
            if ((statement.kind == Statement::Kind::Branch ||
                 statement.kind == Statement::Kind::ConditionalBranch ||
                 statement.kind == Statement::Kind::Call) && !statement.target) {
                finding(result, "missing-target", statement.address,
                    "control transfer has no target expression");
            }
            if ((statement.kind == Statement::Kind::Branch ||
                 statement.kind == Statement::Kind::ConditionalBranch) &&
                statement.target && statement.target->kind == Expression::Kind::Constant &&
                inside(image, statement.target->constant) && !blocks.contains(statement.target->constant)) {
                finding(result, "missing-branch-block", statement.address,
                    "direct branch targets an address with no recovered basic block");
            }
        }
    }

    result.representedInstructions = represented.size();
    result.unmappedInstructions = result.decodedInstructions - result.representedInstructions;
    result.status = result.findings.empty()
        ? VerificationStatus::NoFinding : VerificationStatus::Suspect;
    return result;
}

} // namespace il2cpprec
