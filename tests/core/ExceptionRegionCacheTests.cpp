#include "TestSupport.hpp"

#include "../../src/pipeline/RecoveryPipeline.cpp"

#include <cstdint>
#include <string>
#include <vector>

namespace il2cpprec::tests {
namespace {

RecoveredFunction cacheFixture() {
    RecoveredFunction function;
    function.architecture = Architecture::Arm64;
    function.address = 0x1000;
    function.name = "ExceptionRegions";

    Statement assignment;
    assignment.kind = Statement::Kind::Assign;
    assignment.address = 0x1000;
    assignment.destination = reg("v0", ScalarType::vectorBits(128));
    assignment.value = load(reg("x0", ScalarType::pointer(64)), ScalarType::vectorBits(128));

    Statement result;
    result.kind = Statement::Kind::Return;
    result.address = 0x1004;
    result.value = reg("x0", ScalarType::pointer(64));
    function.blocks.push_back({0x1000, {assignment, result}});
    function.exceptionRegions = {
        {0x1000, 0x1010, 0x1020, 0x1030, ExceptionRegionKind::Catch},
        {0x1040, 0x1050, 0x1060, 0x1070, ExceptionRegionKind::Finally},
    };
    return function;
}

} // namespace

TEST_CASE("exceptionRegions and vector expressions survive disk cache roundtrip exactly") {
    const std::vector<uint8_t> code = {0xC0, 0x03, 0x5F, 0xD6};
    Job job;
    job.image = {Architecture::Arm64, 0x1000, code.data(), code.size(), "ExceptionRegions"};
    job.ownedCode = std::make_shared<const CodeBuffer>(code);

    RecoverySourceProfile profile;
    profile.unityMetadataVersion = "24.0";
    profile.binaryIdentity = "critical-regression-binary";
    profile.codeRegistrationIdentity = "critical-regression-code";
    profile.methodPointersIdentity = "critical-regression-methods";
    profile.lifterSemanticsVersion = 1;

    const auto before = cacheFixture();
    RecoveryOutcome outcome;
    outcome.function = before;
    const auto bytes = serializeDiskCache(job, outcome, profile);
    CHECK(!bytes.empty());
    const auto decoded = deserializeDiskCache(bytes, job, profile);
    CHECK(decoded.has_value());
    if (!decoded) return;

    const auto comparison = RecoveryPipeline::compareExact(before, decoded->function, true);
    if (!comparison.exact()) {
        std::string details;
        for (const auto& mismatch : comparison.mismatches) {
            details += mismatch.path + ": expected " + mismatch.expected + ", actual " + mismatch.actual + "\n";
        }
        fail(details, __FILE__, __LINE__);
    }
    CHECK_EQ(decoded->function.exceptionRegions.size(), 2);
    CHECK(decoded->function.exceptionRegions[0].kind == ExceptionRegionKind::Catch);
    CHECK_EQ(decoded->function.exceptionRegions[0].tryBegin, 0x1000);
    CHECK_EQ(decoded->function.exceptionRegions[0].tryEnd, 0x1010);
    CHECK_EQ(decoded->function.exceptionRegions[0].handler, 0x1020);
    CHECK_EQ(decoded->function.exceptionRegions[0].leaveTarget, 0x1030);
    CHECK(decoded->function.exceptionRegions[1].kind == ExceptionRegionKind::Finally);
    CHECK_EQ(decoded->function.exceptionRegions[1].tryBegin, 0x1040);
    CHECK_EQ(decoded->function.exceptionRegions[1].tryEnd, 0x1050);
    CHECK_EQ(decoded->function.exceptionRegions[1].handler, 0x1060);
    CHECK_EQ(decoded->function.exceptionRegions[1].leaveTarget, 0x1070);
}

} // namespace il2cpprec::tests
