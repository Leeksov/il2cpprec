#include <il2cpprec/diagnostics/SemanticVerifier.hpp>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <array>
#include <cassert>
#include <memory>
#include <string>

namespace {

using namespace il2cpprec;

bool hasFinding(const VerificationResult& result, const std::string& code) {
    for (const auto& finding : result.findings) {
        if (finding.code == code) return true;
    }
    return false;
}

RecoveredFunction function(uint64_t address) {
    RecoveredFunction recovered;
    recovered.architecture = Architecture::X64;
    recovered.address = address;
    recovered.blocks.push_back({address, {}});
    return recovered;
}

} // namespace

int main() {
    const std::array<uint8_t, 2> bytes{0x90, 0xC3}; // nop; ret
    FunctionImage image{Architecture::X64, 0x1000, bytes.data(), bytes.size(), "test"};
    auto recovered = function(image.address);
    Statement ret;
    ret.kind = Statement::Kind::Return;
    ret.address = 0x1001;
    recovered.blocks[0].statements.push_back(ret);

    const auto clean = SemanticVerifier{}.verify(image, recovered);
    assert(clean.status == VerificationStatus::NoFinding);
    assert(clean.decodedInstructions == 2);
    assert(clean.representedInstructions == 1);
    assert(clean.unmappedInstructions == 1); // NOP is not a semantic mismatch.

    auto synthesized = recovered;
    synthesized.blocks[0].statements[0].address = 0;
    const auto synthesizedResult = SemanticVerifier{}.verify(image, synthesized);
    assert(synthesizedResult.status == VerificationStatus::NoFinding);

    auto misplaced = recovered;
    misplaced.blocks[0].statements[0].address = 0x2000;
    assert(hasFinding(SemanticVerifier{}.verify(image, misplaced), "statement-outside-image"));

    auto duplicated = recovered;
    duplicated.blocks.push_back(duplicated.blocks.front());
    const auto duplicateResult = SemanticVerifier{}.verify(image, duplicated);
    assert(duplicateResult.status == VerificationStatus::Suspect);
    assert(hasFinding(duplicateResult, "duplicate-block"));

    auto unknownResultFunction = recovered;
    auto unknownValue = std::make_shared<Expression>();
    unknownValue->kind = Expression::Kind::Unknown;
    unknownResultFunction.blocks[0].statements[0].value = unknownValue;
    const auto unknownResult = SemanticVerifier{}.verify(image, unknownResultFunction);
    assert(hasFinding(unknownResult, "unknown-expression"));

    const std::array<uint8_t, 4> branchBytes{0xEB, 0x01, 0xC3, 0xC3};
    FunctionImage branchImage{Architecture::X64, 0x2000, branchBytes.data(), branchBytes.size(), "branch"};
    auto branchFunction = function(0x2000);
    Statement branch;
    branch.kind = Statement::Kind::Branch;
    branch.address = 0x2000;
    branch.target = std::make_shared<Expression>();
    branch.target->kind = Expression::Kind::Constant;
    branch.target->constant = 0x2003;
    branchFunction.blocks[0].statements.push_back(branch);
    const auto missingBlock = SemanticVerifier{}.verify(branchImage, branchFunction);
    assert(hasFinding(missingBlock, "missing-branch-block"));

    branchFunction.blocks[0].statements[0].kind = Statement::Kind::ConditionalBranch;
    const auto missingCondition = SemanticVerifier{}.verify(branchImage, branchFunction);
    assert(hasFinding(missingCondition, "missing-condition"));

    auto invalid = image;
    invalid.code = nullptr;
    const auto unavailable = SemanticVerifier{}.verify(invalid, recovered);
    assert(unavailable.status == VerificationStatus::Unverifiable);
}
