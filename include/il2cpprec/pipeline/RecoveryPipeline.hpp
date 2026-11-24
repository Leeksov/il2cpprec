#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

#include <il2cpprec/Recovery.hpp>

namespace il2cpprec {

enum class RecoveryCodeOwnership {
    Copy,
    // The caller must keep every code buffer alive and unchanged until recover returns.
    Borrow
};

struct RecoverySourceProfile {
    std::string unityMetadataVersion;
    std::string binaryIdentity;
    std::string codeRegistrationIdentity;
    std::string methodPointersIdentity;
    uint64_t lifterSemanticsVersion = 1;
    std::string profileIdentity;
    std::string layoutIdentity;
    int32_t rawMetadataVersion = 0;
    double preciseMetadataVersion = 0;
    double registrationVersion = 0;
    MetadataSectionModel generatedMethodTypeInfos;
    MetadataSectionModel generatedMethodTokens;
    uint64_t exceptionSemanticsVersion = 1;
    uint64_t vectorSemanticsVersion = 1;
};

struct RecoveryProfileStats {
    RecoverySourceProfile sourceProfile;
    uint64_t memoryCacheHits = 0;
    uint64_t persistentCacheHits = 0;
    uint64_t reusedCodeBytes = 0;
    uint64_t reusedExpressionNodes = 0;
    uint64_t reusedStatements = 0;
    uint64_t reusedPersistentBytes = 0;
};

enum class RecoveryErrorCategory {
    None,
    InvalidImage,
    QueueCapacity,
    Recovery
};

struct RecoveryPartialReasonCount {
    uint64_t address = 0;
    std::string message;
    uint64_t count = 0;
};

struct RecoveryPipelineDiagnostics {
    uint64_t exactFunctions = 0;
    uint64_t partialFunctions = 0;
    uint64_t partialReasonOccurrences = 0;
    uint64_t invalidImageErrors = 0;
    uint64_t queueCapacityErrors = 0;
    uint64_t recoveryErrors = 0;
    uint64_t persistentCacheErrors = 0;
    std::vector<RecoveryPartialReasonCount> partialReasons;
};

enum class RecoveryExactMismatchKind {
    Architecture,
    Address,
    Name,
    BlockCount,
    BlockAddress,
    StatementCount,
    StatementKind,
    StatementAddress,
    ExpressionPresence,
    ExpressionSharing,
    ExpressionKind,
    ScalarKind,
    ScalarWidth,
    ExpressionConstant,
    ExpressionName,
    ExpressionOperation,
    ExpressionArgumentCount,
    ExceptionRegionCount,
    ExceptionRegion,
    ProfileIdentity,
    LayoutIdentity,
    RawMetadataVersion,
    PreciseMetadataVersion,
    RegistrationVersion,
    GeneratedMethodTypeInfos,
    GeneratedMethodTokens,
    LifterSemanticsVersion,
    ExceptionSemanticsVersion,
    VectorSemanticsVersion
};

struct RecoveryExactMismatch {
    RecoveryExactMismatchKind kind = RecoveryExactMismatchKind::Architecture;
    std::string path;
    std::string expected;
    std::string actual;
};

struct RecoveryExactComparison {
    std::vector<RecoveryExactMismatch> mismatches;

    bool exact() const noexcept {
        return mismatches.empty();
    }
};

struct RecoveryPipelineOptions {
    size_t workerCount = 0;
    size_t queueCapacity = 0;
    size_t cacheCapacity = 256;
    size_t queueByteCapacity = 64 * 1024 * 1024;
    RecoveryCodeOwnership codeOwnership = RecoveryCodeOwnership::Copy;
    std::string cacheDirectory;
    RecoverySourceProfile sourceProfile;
};

struct RecoveryPipelineStats {
    uint64_t recoverCalls = 0;
    uint64_t images = 0;
    uint64_t succeeded = 0;
    uint64_t cacheHits = 0;
    uint64_t errors = 0;
    uint64_t cancelled = 0;

    uint64_t cacheLookups = 0;
    uint64_t cacheMisses = 0;
    uint64_t cacheStores = 0;
    uint64_t cacheEvictions = 0;

    uint64_t inputBytes = 0;
    uint64_t copiedCodeBytes = 0;
    uint64_t borrowedCodeBytes = 0;
    uint64_t currentQueueBytes = 0;
    uint64_t peakQueueBytes = 0;
    uint64_t cacheCodeBytes = 0;

    std::chrono::nanoseconds totalRecoverTime{0};
    std::chrono::nanoseconds queueWaitTime{0};
    std::chrono::nanoseconds recoveryTime{0};

    uint64_t diskCacheLookups = 0;
    uint64_t diskCacheHits = 0;
    uint64_t diskCacheMisses = 0;
    uint64_t diskCacheWrites = 0;
    uint64_t diskCacheErrors = 0;
    uint64_t diskCacheBytesRead = 0;
    uint64_t diskCacheBytesWritten = 0;
};

enum class RecoveryResultStatus {
    Success,
    CacheHit,
    Cancelled,
    Error
};

struct RecoveryResult {
    std::optional<RecoveredFunction> function;
    std::vector<RecoveryDiagnostic> recoveryDiagnostics;
    flow::ExceptionRegionAnalysis exceptionAnalysis;
    RecoveryResultStatus status = RecoveryResultStatus::Cancelled;
    std::string error;
    RecoveryErrorCategory errorCategory = RecoveryErrorCategory::None;
    std::vector<CSharpDiagnostic> partialReasons;

    bool succeeded() const noexcept {
        return status == RecoveryResultStatus::Success || status == RecoveryResultStatus::CacheHit;
    }

    bool exact() const noexcept {
        return succeeded() && function.has_value() && partialReasons.empty();
    }
};

class RecoveryPipeline {
public:
    explicit RecoveryPipeline(const RecoveryPipelineOptions& options = {});
    ~RecoveryPipeline();

    RecoveryPipeline(const RecoveryPipeline&) = delete;
    RecoveryPipeline& operator=(const RecoveryPipeline&) = delete;
    RecoveryPipeline(RecoveryPipeline&&) = delete;
    RecoveryPipeline& operator=(RecoveryPipeline&&) = delete;

    std::vector<RecoveryResult> recover(
        const std::vector<FunctionImage>& images,
        std::stop_token cancellation = {});

    void cancel();
    void clearCache();

    size_t workerCount() const noexcept;
    size_t queueCapacity() const noexcept;
    size_t queueByteCapacity() const noexcept;
    size_t cacheSize() const;
    RecoveryPipelineStats stats() const noexcept;
    RecoveryProfileStats profileStats() const;
    RecoveryPipelineDiagnostics diagnostics() const;

    static RecoveryExactComparison compareExact(
        const RecoveredFunction& before,
        const RecoveredFunction& after,
        bool ignoreName = false);

    static RecoveryExactComparison compareProfilesExact(
        const RecoverySourceProfile& before,
        const RecoverySourceProfile& after);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace il2cpprec
