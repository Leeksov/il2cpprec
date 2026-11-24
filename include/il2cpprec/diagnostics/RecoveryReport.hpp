#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace il2cpprec {

enum class RecoveryQuality {
    Exact,
    Partial,
    Unsupported,
    InvalidMetadata,
    Failed
};

enum class RecoveryIssueSeverity {
    Info,
    Warning,
    Error
};

enum class RecoveryPartialReasonCategory {
    ZeroBit,
    Vector128,
    TypeConflict,
    UnresolvedGeneric,
    VirtualDispatch,
    UnsupportedInstruction,
    Metadata,
    Unknown
};

enum class RecoveryConfidence {
    Unknown,
    Low,
    Medium,
    High
};

enum class RecoveryVersionProvenance {
    Unknown,
    RawHeader,
    InferredLayout,
    Registration,
    Explicit
};

enum class RecoveryCapability {
    MetadataSupported,
    Provisional,
    NativeVerified
};

const char* toString(RecoveryQuality quality) noexcept;
const char* toString(RecoveryIssueSeverity severity) noexcept;
const char* toString(RecoveryPartialReasonCategory category) noexcept;
const char* toString(RecoveryConfidence confidence) noexcept;
const char* toString(RecoveryVersionProvenance provenance) noexcept;
const char* toString(RecoveryCapability capability) noexcept;
RecoveryPartialReasonCategory normalizePartialReason(std::string_view reason);

struct RecoveryVersionInfo {
    int32_t rawVersion = 0;
    double effectiveVersion = 0;
    double registrationVersion = 0;
    RecoveryConfidence confidence = RecoveryConfidence::Unknown;
    RecoveryVersionProvenance provenance = RecoveryVersionProvenance::Unknown;

    std::string key() const;
    std::string toJson() const;
};

struct RecoveryIssue {
    using Severity = RecoveryIssueSeverity;

    std::string method;
    uint64_t address = 0;
    RecoveryIssueSeverity severity = RecoveryIssueSeverity::Error;
    std::string code;
    std::string message;
};

struct RecoveryMethod {
    RecoveryMethod() = default;
    RecoveryMethod(
        std::string methodName,
        uint64_t methodAddress = 0,
        RecoveryQuality methodQuality = RecoveryQuality::Failed,
        std::string imageName = {},
        std::vector<std::string> reasonList = {});

    std::string method;
    uint64_t address = 0;
    RecoveryQuality quality = RecoveryQuality::Failed;
    std::string image;
    std::vector<std::string> reasons;
    std::vector<RecoveryPartialReasonCategory> normalizedReasons;
};

struct RecoveryCounts {
    size_t exact = 0;
    size_t partial = 0;
    size_t unsupported = 0;
    size_t invalidMetadata = 0;
    size_t failed = 0;

    size_t count(RecoveryQuality quality) const noexcept;
    size_t errors() const noexcept;
    size_t total() const noexcept;
};

struct RecoveryReasonCounts {
    size_t zeroBit = 0;
    size_t vector128 = 0;
    size_t typeConflict = 0;
    size_t unresolvedGeneric = 0;
    size_t virtualDispatch = 0;
    size_t unsupportedInstruction = 0;
    size_t metadata = 0;
    size_t unknown = 0;

    size_t count(RecoveryPartialReasonCategory category) const noexcept;
    size_t total() const noexcept;
};

struct RecoveryDiffCounts {
    int64_t exact = 0;
    int64_t partial = 0;
    int64_t errors = 0;
};

struct RecoveryImageDiff {
    RecoveryCounts before;
    RecoveryCounts after;
    RecoveryDiffCounts delta;

    std::string toJson() const;
};

using RecoveryVersionDiff = RecoveryImageDiff;

struct RecoveryDiff {
    RecoveryCounts before;
    RecoveryCounts after;
    RecoveryDiffCounts delta;
    RecoveryVersionInfo beforeVersion;
    RecoveryVersionInfo afterVersion;
    RecoveryCapability beforeCapability = RecoveryCapability::Provisional;
    RecoveryCapability afterCapability = RecoveryCapability::Provisional;
    std::map<std::string, RecoveryImageDiff, std::less<>> images;
    std::map<std::string, RecoveryVersionDiff, std::less<>> versions;

    std::string toJson() const;
};

class RecoveryReportBuilder;

struct RecoveryReport {
    using Builder = RecoveryReportBuilder;

    RecoveryVersionInfo version;
    RecoveryCapability capability = RecoveryCapability::Provisional;
    RecoveryCounts counts;
    RecoveryReasonCounts reasonCounts;
    std::map<std::string, RecoveryCounts, std::less<>> imageCounts;
    std::map<std::string, RecoveryCounts, std::less<>> versionCounts;
    std::vector<RecoveryMethod> methods;
    std::vector<RecoveryIssue> issues;

    void finalize();
    RecoveryDiff diff(const RecoveryReport& after) const;
    std::string toJson() const;
};

RecoveryDiff diffRecoveryReports(const RecoveryReport& before, const RecoveryReport& after);

class RecoveryReportBuilder {
public:
    RecoveryReportBuilder() = default;

    RecoveryReportBuilder(const RecoveryReportBuilder&) = delete;
    RecoveryReportBuilder& operator=(const RecoveryReportBuilder&) = delete;
    RecoveryReportBuilder(RecoveryReportBuilder&&) = delete;
    RecoveryReportBuilder& operator=(RecoveryReportBuilder&&) = delete;

    void setVersion(RecoveryVersionInfo version);
    void setCapability(RecoveryCapability capability);
    void addMethod(RecoveryMethod method);
    void addMethod(std::string method, uint64_t address, RecoveryQuality quality);
    void addMethod(
        std::string image,
        std::string method,
        uint64_t address,
        RecoveryQuality quality,
        std::vector<std::string> reasons = {});
    void addIssue(RecoveryIssue issue);
    void add(RecoveryMethod method, std::vector<RecoveryIssue> issues = {});
    void clear();

    RecoveryReport build() const;

private:
    mutable std::mutex mutex_;
    RecoveryVersionInfo version_;
    RecoveryCapability capability_ = RecoveryCapability::Provisional;
    std::vector<RecoveryMethod> methods_;
    std::vector<RecoveryIssue> issues_;
};

} // namespace il2cpprec
