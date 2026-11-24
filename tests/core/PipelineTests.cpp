#include "TestSupport.hpp"

#include <il2cpprec/pipeline/RecoveryPipeline.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace il2cpprec::tests {
namespace {

struct ImageBatch {
    std::vector<std::vector<uint8_t>> code;
    std::vector<FunctionImage> images;
};

ImageBatch makeBatch() {
    ImageBatch batch;
    batch.code = {
        {0xE0, 0x03, 0x01, 0xAA, 0x00, 0x00, 0x40, 0x91, 0xC0, 0x03, 0x5F, 0xD6},
        {0x80, 0x00, 0x80, 0xE0, 0x01, 0x00, 0x40, 0xE2, 0x1E, 0xFF, 0x2F, 0xE1},
        {0x89, 0xC8, 0x83, 0xC0, 0x01, 0xC3},
        {0x48, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x01, 0xC3},
    };
    const Architecture architectures[] = {
        Architecture::Arm64, Architecture::Arm32, Architecture::X86, Architecture::X64
    };
    for (size_t i = 0; i < 12; ++i) {
        const auto architecture = architectures[i % 4];
        batch.images.push_back({
            architecture,
            0x1000 + i * 0x100,
            batch.code[i % 4].data(),
            batch.code[i % 4].size(),
            "Function_" + std::to_string(i)
        });
    }
    return batch;
}

std::vector<std::string> resultSnapshots(const std::vector<RecoveryResult>& results) {
    std::vector<std::string> snapshots;
    snapshots.reserve(results.size());
    for (const auto& result : results) {
        std::string snapshot = std::to_string(static_cast<int>(result.status)) + ":" + result.error + ":";
        if (result.function) snapshot += serializeFunction(*result.function) + result.function->toCSharp();
        snapshots.push_back(std::move(snapshot));
    }
    return snapshots;
}

FunctionImage arm64Image(const std::vector<uint8_t>& code, std::string name = "Original", uint64_t address = 0x8000) {
    return {Architecture::Arm64, address, code.data(), code.size(), std::move(name)};
}

} // namespace

TEST_CASE("pipeline produces deterministic ordered results with 1, 2 and 4 workers") {
    auto batch = makeBatch();
    std::vector<std::string> baseline;
    for (const size_t workers : {size_t{1}, size_t{2}, size_t{4}}) {
        RecoveryPipeline pipeline({workers, 2, 0});
        CHECK_EQ(pipeline.workerCount(), workers);
        CHECK_EQ(pipeline.queueCapacity(), 2);
        const auto results = pipeline.recover(batch.images);
        CHECK_EQ(results.size(), batch.images.size());
        for (size_t i = 0; i < results.size(); ++i) {
            CHECK(results[i].succeeded());
            CHECK_EQ(static_cast<int>(results[i].status), static_cast<int>(RecoveryResultStatus::Success));
            CHECK(results[i].function.has_value());
            CHECK_EQ(results[i].function->name, batch.images[i].name);
            CHECK_EQ(results[i].function->address, batch.images[i].address);
        }
        const auto snapshots = resultSnapshots(results);
        if (workers == 1) baseline = snapshots;
        else CHECK(snapshots == baseline);

        const auto repeated = pipeline.recover(batch.images);
        CHECK(resultSnapshots(repeated) == snapshots);
    }
}

TEST_CASE("pipeline cache keys ignore names but return the requested name") {
    const std::vector<uint8_t> code = {
        0xE0, 0x03, 0x01, 0xAA, 0x00, 0x00, 0x40, 0x91, 0xC0, 0x03, 0x5F, 0xD6
    };
    RecoveryPipeline pipeline({2, 0, 8});
    const auto original = arm64Image(code);
    auto renamed = original;
    renamed.name = "Renamed";

    auto first = pipeline.recover({original});
    CHECK_EQ(static_cast<int>(first.at(0).status), static_cast<int>(RecoveryResultStatus::Success));
    CHECK_EQ(pipeline.cacheSize(), 1);
    auto pristine = serializeFunction(*first[0].function);
    first[0].function->blocks.at(0).statements.at(0).destination->name = "corrupted";

    auto second = pipeline.recover({renamed});
    CHECK_EQ(static_cast<int>(second.at(0).status), static_cast<int>(RecoveryResultStatus::CacheHit));
    CHECK_EQ(second.at(0).function->name, "Renamed");
    CHECK_EQ(second.at(0).function->blocks.at(0).statements.at(0).destination->name, "x0");
    CHECK_EQ(serializeFunction(*second[0].function), pristine.replace(pristine.find("Original"), 8, "Renamed"));
}

TEST_CASE("pipeline cache separates architectures addresses and code bytes") {
    const std::vector<uint8_t> code = {0x00, 0x00, 0x40, 0x91, 0xC0, 0x03, 0x5F, 0xD6};
    const std::vector<uint8_t> changed = {0x00, 0x00, 0x80, 0x91, 0xC0, 0x03, 0x5F, 0xD6};
    RecoveryPipeline pipeline({1, 1, 8});
    auto original = arm64Image(code);
    auto otherAddress = original;
    otherAddress.address += 0x100;
    auto otherArchitecture = original;
    otherArchitecture.architecture = Architecture::Arm32;
    auto otherCode = arm64Image(changed);

    const auto results = pipeline.recover({original, otherAddress, otherArchitecture, otherCode});
    for (const auto& result : results) CHECK_EQ(static_cast<int>(result.status), static_cast<int>(RecoveryResultStatus::Success));
    CHECK_EQ(pipeline.cacheSize(), 4);
    const auto cached = pipeline.recover({original, otherAddress, otherArchitecture, otherCode});
    for (const auto& result : cached) CHECK_EQ(static_cast<int>(result.status), static_cast<int>(RecoveryResultStatus::CacheHit));
}

TEST_CASE("pipeline cache LRU eviction and clear are observable") {
    const std::vector<uint8_t> code = {0x00, 0x00, 0x40, 0x91, 0xC0, 0x03, 0x5F, 0xD6};
    const auto a = arm64Image(code, "A", 0x9000);
    const auto b = arm64Image(code, "B", 0x9100);
    const auto c = arm64Image(code, "C", 0x9200);
    RecoveryPipeline pipeline({1, 1, 2});
    static_cast<void>(pipeline.recover({a, b}));
    CHECK_EQ(static_cast<int>(pipeline.recover({a})[0].status), static_cast<int>(RecoveryResultStatus::CacheHit));
    static_cast<void>(pipeline.recover({c}));
    CHECK_EQ(pipeline.cacheSize(), 2);
    CHECK_EQ(static_cast<int>(pipeline.recover({b})[0].status), static_cast<int>(RecoveryResultStatus::Success));
    pipeline.clearCache();
    CHECK_EQ(pipeline.cacheSize(), 0);
    CHECK_EQ(static_cast<int>(pipeline.recover({a})[0].status), static_cast<int>(RecoveryResultStatus::Success));
}

TEST_CASE("pipeline reports malformed images without affecting later jobs") {
    const std::vector<uint8_t> code = {0x00, 0x00, 0x40, 0x91, 0xC0, 0x03, 0x5F, 0xD6};
    const FunctionImage invalid{Architecture::Arm64, 0xA000, nullptr, 4, "Invalid"};
    RecoveryPipeline pipeline({4, 1, 4});
    const auto results = pipeline.recover({invalid, arm64Image(code, "Valid", 0xA100)});
    CHECK_EQ(results.size(), 2);
    CHECK_EQ(static_cast<int>(results[0].status), static_cast<int>(RecoveryResultStatus::Error));
    CHECK(!results[0].function.has_value());
    CHECK(results[0].error.find("null code pointer") != std::string::npos);
    CHECK(results[1].succeeded());
    CHECK_EQ(results[1].function->name, "Valid");
}

} // namespace il2cpprec::tests
