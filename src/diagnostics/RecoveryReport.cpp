#include <il2cpprec/diagnostics/RecoveryReport.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <iterator>
#include <tuple>
#include <utility>

namespace il2cpprec {
namespace {

std::string lowercaseAscii(std::string_view value) {
    std::string result(value);
    for (char& c : result) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return result;
}

bool contains(const std::string& value, std::string_view part) {
    return value.find(part) != std::string::npos;
}

bool preventsExact(const RecoveryIssue& issue) {
    const std::string code = lowercaseAscii(issue.code);
    const std::string message = lowercaseAscii(issue.message);
    return contains(code, "unsupported") || contains(code, "unresolved")
        || contains(message, "unsupported") || contains(message, "unresolved");
}

bool appliesTo(const RecoveryIssue& issue, const RecoveryMethod& method) {
    if (!issue.method.empty() && issue.method != method.method) return false;
    if (issue.address != 0 && method.address != 0 && issue.address != method.address) return false;
    return true;
}

void increment(RecoveryCounts& counts, RecoveryQuality quality) {
    switch (quality) {
    case RecoveryQuality::Exact: ++counts.exact; break;
    case RecoveryQuality::Partial: ++counts.partial; break;
    case RecoveryQuality::Unsupported: ++counts.unsupported; break;
    case RecoveryQuality::InvalidMetadata: ++counts.invalidMetadata; break;
    case RecoveryQuality::Failed: ++counts.failed; break;
    }
}

void increment(RecoveryReasonCounts& counts, RecoveryPartialReasonCategory category) {
    switch (category) {
    case RecoveryPartialReasonCategory::ZeroBit: ++counts.zeroBit; break;
    case RecoveryPartialReasonCategory::Vector128: ++counts.vector128; break;
    case RecoveryPartialReasonCategory::TypeConflict: ++counts.typeConflict; break;
    case RecoveryPartialReasonCategory::UnresolvedGeneric: ++counts.unresolvedGeneric; break;
    case RecoveryPartialReasonCategory::VirtualDispatch: ++counts.virtualDispatch; break;
    case RecoveryPartialReasonCategory::UnsupportedInstruction: ++counts.unsupportedInstruction; break;
    case RecoveryPartialReasonCategory::Metadata: ++counts.metadata; break;
    case RecoveryPartialReasonCategory::Unknown: ++counts.unknown; break;
    }
}

RecoveryDiffCounts difference(const RecoveryCounts& before, const RecoveryCounts& after) {
    return {
        static_cast<int64_t>(after.exact) - static_cast<int64_t>(before.exact),
        static_cast<int64_t>(after.partial) - static_cast<int64_t>(before.partial),
        static_cast<int64_t>(after.errors()) - static_cast<int64_t>(before.errors())
    };
}

void appendJsonString(std::string& output, std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
    output.push_back('"');
    for (const unsigned char c : value) {
        switch (c) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (c < 0x20) {
                output += "\\u00";
                output.push_back(hex[c >> 4]);
                output.push_back(hex[c & 0x0F]);
            } else {
                output.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    output.push_back('"');
}

std::string versionNumber(double version) {
    if (!std::isfinite(version)) return "null";
    char buffer[64];
    const auto result = std::to_chars(std::begin(buffer), std::end(buffer), version);
    if (result.ec != std::errc{}) return "null";
    std::string text(buffer, result.ptr);
    if (text.find_first_of(".eE") == std::string::npos) text += ".0";
    return text;
}

void appendAddress(std::string& output, uint64_t address) {
    constexpr char hex[] = "0123456789abcdef";
    char digits[16];
    size_t count = 0;
    do {
        digits[count++] = hex[address & 0x0F];
        address >>= 4;
    } while (address != 0);

    output += "\"0x";
    while (count != 0) output.push_back(digits[--count]);
    output.push_back('"');
}

void appendSummary(std::string& output, const RecoveryCounts& counts) {
    output += "{\"exact\":" + std::to_string(counts.exact);
    output += ",\"partial\":" + std::to_string(counts.partial);
    output += ",\"errors\":" + std::to_string(counts.errors());
    output.push_back('}');
}

void appendDelta(std::string& output, const RecoveryDiffCounts& delta) {
    output += "{\"exact\":" + std::to_string(delta.exact);
    output += ",\"partial\":" + std::to_string(delta.partial);
    output += ",\"errors\":" + std::to_string(delta.errors);
    output.push_back('}');
}

void appendReasonCounts(std::string& output, const RecoveryReasonCounts& counts) {
    output += "{\"0-bit\":" + std::to_string(counts.zeroBit);
    output += ",\"vector128\":" + std::to_string(counts.vector128);
    output += ",\"type-conflict\":" + std::to_string(counts.typeConflict);
    output += ",\"unresolved-generic\":" + std::to_string(counts.unresolvedGeneric);
    output += ",\"virtual-dispatch\":" + std::to_string(counts.virtualDispatch);
    output += ",\"unsupported-instruction\":" + std::to_string(counts.unsupportedInstruction);
    output += ",\"metadata\":" + std::to_string(counts.metadata);
    output += ",\"unknown\":" + std::to_string(counts.unknown);
    output.push_back('}');
}

} // namespace

const char* toString(RecoveryQuality quality) noexcept {
    switch (quality) {
    case RecoveryQuality::Exact: return "exact";
    case RecoveryQuality::Partial: return "partial";
    case RecoveryQuality::Unsupported: return "unsupported";
    case RecoveryQuality::InvalidMetadata: return "invalidMetadata";
    case RecoveryQuality::Failed: return "failed";
    }
    return "failed";
}

const char* toString(RecoveryIssueSeverity severity) noexcept {
    switch (severity) {
    case RecoveryIssueSeverity::Info: return "info";
    case RecoveryIssueSeverity::Warning: return "warning";
    case RecoveryIssueSeverity::Error: return "error";
    }
    return "error";
}

const char* toString(RecoveryPartialReasonCategory category) noexcept {
    switch (category) {
    case RecoveryPartialReasonCategory::ZeroBit: return "0-bit";
    case RecoveryPartialReasonCategory::Vector128: return "vector128";
    case RecoveryPartialReasonCategory::TypeConflict: return "type-conflict";
    case RecoveryPartialReasonCategory::UnresolvedGeneric: return "unresolved-generic";
    case RecoveryPartialReasonCategory::VirtualDispatch: return "virtual-dispatch";
    case RecoveryPartialReasonCategory::UnsupportedInstruction: return "unsupported-instruction";
    case RecoveryPartialReasonCategory::Metadata: return "metadata";
    case RecoveryPartialReasonCategory::Unknown: return "unknown";
    }
    return "unknown";
}

const char* toString(RecoveryConfidence confidence) noexcept {
    switch (confidence) {
    case RecoveryConfidence::Unknown: return "unknown";
    case RecoveryConfidence::Low: return "low";
    case RecoveryConfidence::Medium: return "medium";
    case RecoveryConfidence::High: return "high";
    }
    return "unknown";
}

const char* toString(RecoveryVersionProvenance provenance) noexcept {
    switch (provenance) {
    case RecoveryVersionProvenance::Unknown: return "unknown";
    case RecoveryVersionProvenance::RawHeader: return "raw-header";
    case RecoveryVersionProvenance::InferredLayout: return "inferred-layout";
    case RecoveryVersionProvenance::Registration: return "registration";
    case RecoveryVersionProvenance::Explicit: return "explicit";
    }
    return "unknown";
}

const char* toString(RecoveryCapability capability) noexcept {
    switch (capability) {
    case RecoveryCapability::MetadataSupported: return "metadata-supported";
    case RecoveryCapability::Provisional: return "provisional";
    case RecoveryCapability::NativeVerified: return "native-verified";
    }
    return "provisional";
}

std::string RecoveryVersionInfo::key() const {
    if (effectiveVersion != 0 && std::isfinite(effectiveVersion)) return versionNumber(effectiveVersion);
    if (registrationVersion != 0 && std::isfinite(registrationVersion)) {
        return versionNumber(registrationVersion);
    }
    if (rawVersion != 0) return versionNumber(rawVersion);
    return "unknown";
}

std::string RecoveryVersionInfo::toJson() const {
    std::string output = "{\"rawVersion\":" + std::to_string(rawVersion);
    output += ",\"effectiveVersion\":" + versionNumber(effectiveVersion);
    output += ",\"registrationVersion\":" + versionNumber(registrationVersion);
    output += ",\"confidence\":";
    appendJsonString(output, toString(confidence));
    output += ",\"provenance\":";
    appendJsonString(output, toString(provenance));
    output.push_back('}');
    return output;
}

RecoveryPartialReasonCategory normalizePartialReason(std::string_view reason) {
    const std::string normalized = lowercaseAscii(reason);
    if (contains(normalized, "0-bit") || contains(normalized, "0 bit")) {
        return RecoveryPartialReasonCategory::ZeroBit;
    }
    if (contains(normalized, "128-bit") || contains(normalized, "128 bit")
        || contains(normalized, "unsupportedvector128") || contains(normalized, "vector128")
        || contains(normalized, "vector 128")) {
        return RecoveryPartialReasonCategory::Vector128;
    }
    if (contains(normalized, "type-conflict") || contains(normalized, "type conflict")
        || contains(normalized, "conflicting types") || contains(normalized, "inconsistent types")
        || contains(normalized, "unsupportedvalue")) {
        return RecoveryPartialReasonCategory::TypeConflict;
    }
    if (contains(normalized, "unresolved-generic") || contains(normalized, "unresolved generic")
        || contains(normalized, "generic")) {
        return RecoveryPartialReasonCategory::UnresolvedGeneric;
    }
    if (contains(normalized, "virtual-dispatch") || contains(normalized, "virtual dispatch")
        || contains(normalized, "virtual call") || contains(normalized, "dispatch")) {
        return RecoveryPartialReasonCategory::VirtualDispatch;
    }
    if (contains(normalized, "metadata")) {
        return RecoveryPartialReasonCategory::Metadata;
    }
    if (contains(normalized, "unsupported-instruction") || contains(normalized, "unsupported instruction")
        || contains(normalized, "unsupported opcode") || contains(normalized, "unknown ir")
        || contains(normalized, "unsupported conversion") || contains(normalized, "unsupported")) {
        return RecoveryPartialReasonCategory::UnsupportedInstruction;
    }
    return RecoveryPartialReasonCategory::Unknown;
}

RecoveryMethod::RecoveryMethod(
    std::string methodName,
    uint64_t methodAddress,
    RecoveryQuality methodQuality,
    std::string imageName,
    std::vector<std::string> reasonList)
    : method(std::move(methodName)),
      address(methodAddress),
      quality(methodQuality),
      image(std::move(imageName)),
      reasons(std::move(reasonList)) {}

size_t RecoveryCounts::count(RecoveryQuality quality) const noexcept {
    switch (quality) {
    case RecoveryQuality::Exact: return exact;
    case RecoveryQuality::Partial: return partial;
    case RecoveryQuality::Unsupported: return unsupported;
    case RecoveryQuality::InvalidMetadata: return invalidMetadata;
    case RecoveryQuality::Failed: return failed;
    }
    return failed;
}

size_t RecoveryCounts::errors() const noexcept {
    return unsupported + invalidMetadata + failed;
}

size_t RecoveryCounts::total() const noexcept {
    return exact + partial + errors();
}

size_t RecoveryReasonCounts::count(RecoveryPartialReasonCategory category) const noexcept {
    switch (category) {
    case RecoveryPartialReasonCategory::ZeroBit: return zeroBit;
    case RecoveryPartialReasonCategory::Vector128: return vector128;
    case RecoveryPartialReasonCategory::TypeConflict: return typeConflict;
    case RecoveryPartialReasonCategory::UnresolvedGeneric: return unresolvedGeneric;
    case RecoveryPartialReasonCategory::VirtualDispatch: return virtualDispatch;
    case RecoveryPartialReasonCategory::UnsupportedInstruction: return unsupportedInstruction;
    case RecoveryPartialReasonCategory::Metadata: return metadata;
    case RecoveryPartialReasonCategory::Unknown: return unknown;
    }
    return unknown;
}

size_t RecoveryReasonCounts::total() const noexcept {
    return zeroBit + vector128 + typeConflict + unresolvedGeneric + virtualDispatch
        + unsupportedInstruction + metadata + unknown;
}

std::string RecoveryImageDiff::toJson() const {
    std::string output = "{\"before\":";
    appendSummary(output, before);
    output += ",\"after\":";
    appendSummary(output, after);
    output += ",\"delta\":";
    appendDelta(output, delta);
    output.push_back('}');
    return output;
}

std::string RecoveryDiff::toJson() const {
    std::string output = "{\"before\":";
    appendSummary(output, before);
    output += ",\"after\":";
    appendSummary(output, after);
    output += ",\"delta\":";
    appendDelta(output, delta);
    output += ",\"version\":{\"before\":" + beforeVersion.toJson();
    output += ",\"after\":" + afterVersion.toJson();
    output += "},\"capability\":{\"before\":";
    appendJsonString(output, toString(beforeCapability));
    output += ",\"after\":";
    appendJsonString(output, toString(afterCapability));
    output += "},\"images\":{";
    bool first = true;
    for (const auto& [image, diff] : images) {
        if (!first) output.push_back(',');
        first = false;
        appendJsonString(output, image);
        output.push_back(':');
        output += diff.toJson();
    }
    output += "},\"versions\":{";
    first = true;
    for (const auto& [version, diff] : versions) {
        if (!first) output.push_back(',');
        first = false;
        appendJsonString(output, version);
        output.push_back(':');
        output += diff.toJson();
    }
    output += "}}";
    return output;
}

void RecoveryReport::finalize() {
    for (auto& method : methods) {
        method.normalizedReasons.clear();
        method.normalizedReasons.reserve(method.reasons.size());
        for (const auto& reason : method.reasons) {
            method.normalizedReasons.push_back(normalizePartialReason(reason));
        }

        if (method.quality != RecoveryQuality::Exact) continue;
        const auto blocking = [&method](const RecoveryIssue& issue) {
            return appliesTo(issue, method) && preventsExact(issue);
        };
        if (!method.reasons.empty() || std::any_of(issues.begin(), issues.end(), blocking)) {
            method.quality = RecoveryQuality::Partial;
        }
    }

    std::sort(methods.begin(), methods.end(), [](const RecoveryMethod& left, const RecoveryMethod& right) {
        return std::tie(left.address, left.image, left.method, left.quality, left.reasons)
            < std::tie(right.address, right.image, right.method, right.quality, right.reasons);
    });
    std::sort(issues.begin(), issues.end(), [](const RecoveryIssue& left, const RecoveryIssue& right) {
        return std::tie(left.address, left.method, left.severity, left.code, left.message)
            < std::tie(right.address, right.method, right.severity, right.code, right.message);
    });

    counts = {};
    reasonCounts = {};
    imageCounts.clear();
    versionCounts.clear();
    for (const auto& method : methods) {
        increment(counts, method.quality);
        increment(imageCounts[method.image], method.quality);
        increment(versionCounts[version.key()], method.quality);
        if (method.quality != RecoveryQuality::Partial) continue;
        for (const auto category : method.normalizedReasons) {
            increment(reasonCounts, category);
        }
    }
}

RecoveryDiff RecoveryReport::diff(const RecoveryReport& after) const {
    return diffRecoveryReports(*this, after);
}

std::string RecoveryReport::toJson() const {
    RecoveryReport normalized = *this;
    normalized.finalize();

    std::string output = "{\"version\":" + normalized.version.toJson();
    output += ",\"capability\":";
    appendJsonString(output, toString(normalized.capability));
    output += ",\"counts\":{\"exact\":" + std::to_string(normalized.counts.exact);
    output += ",\"partial\":" + std::to_string(normalized.counts.partial);
    output += ",\"unsupported\":" + std::to_string(normalized.counts.unsupported);
    output += ",\"invalidMetadata\":" + std::to_string(normalized.counts.invalidMetadata);
    output += ",\"failed\":" + std::to_string(normalized.counts.failed);
    output += ",\"errors\":" + std::to_string(normalized.counts.errors());
    output += ",\"total\":" + std::to_string(normalized.counts.total());
    output += "},\"partialReasons\":";
    appendReasonCounts(output, normalized.reasonCounts);
    output += ",\"images\":{";
    bool first = true;
    for (const auto& [image, counts] : normalized.imageCounts) {
        if (!first) output.push_back(',');
        first = false;
        appendJsonString(output, image);
        output.push_back(':');
        appendSummary(output, counts);
    }
    output += "},\"versions\":{";
    first = true;
    for (const auto& [version, counts] : normalized.versionCounts) {
        if (!first) output.push_back(',');
        first = false;
        appendJsonString(output, version);
        output.push_back(':');
        appendSummary(output, counts);
    }
    output += "},\"methods\":[";

    first = true;
    for (const auto& method : normalized.methods) {
        if (!first) output.push_back(',');
        first = false;
        output += "{\"method\":";
        appendJsonString(output, method.method);
        output += ",\"address\":";
        appendAddress(output, method.address);
        output += ",\"quality\":";
        appendJsonString(output, toString(method.quality));
        output += ",\"image\":";
        appendJsonString(output, method.image);
        output += ",\"reasons\":[";
        for (size_t i = 0; i < method.reasons.size(); ++i) {
            if (i != 0) output.push_back(',');
            appendJsonString(output, method.reasons[i]);
        }
        output += "],\"normalizedReasons\":[";
        for (size_t i = 0; i < method.normalizedReasons.size(); ++i) {
            if (i != 0) output.push_back(',');
            appendJsonString(output, toString(method.normalizedReasons[i]));
        }
        output += "]}";
    }

    output += "],\"issues\":[";
    first = true;
    for (const auto& issue : normalized.issues) {
        if (!first) output.push_back(',');
        first = false;
        output += "{\"method\":";
        appendJsonString(output, issue.method);
        output += ",\"address\":";
        appendAddress(output, issue.address);
        output += ",\"severity\":";
        appendJsonString(output, toString(issue.severity));
        output += ",\"code\":";
        appendJsonString(output, issue.code);
        output += ",\"message\":";
        appendJsonString(output, issue.message);
        output.push_back('}');
    }
    output += "]}";
    return output;
}

RecoveryDiff diffRecoveryReports(const RecoveryReport& before, const RecoveryReport& after) {
    RecoveryReport normalizedBefore = before;
    RecoveryReport normalizedAfter = after;
    normalizedBefore.finalize();
    normalizedAfter.finalize();

    RecoveryDiff result;
    result.before = normalizedBefore.counts;
    result.after = normalizedAfter.counts;
    result.delta = difference(result.before, result.after);
    result.beforeVersion = normalizedBefore.version;
    result.afterVersion = normalizedAfter.version;
    result.beforeCapability = normalizedBefore.capability;
    result.afterCapability = normalizedAfter.capability;

    for (const auto& [image, counts] : normalizedBefore.imageCounts) {
        auto& diff = result.images[image];
        diff.before = counts;
    }
    for (const auto& [image, counts] : normalizedAfter.imageCounts) {
        auto& diff = result.images[image];
        diff.after = counts;
    }
    for (auto& [image, diff] : result.images) {
        (void)image;
        diff.delta = difference(diff.before, diff.after);
    }
    for (const auto& [version, counts] : normalizedBefore.versionCounts) {
        auto& diff = result.versions[version];
        diff.before = counts;
    }
    for (const auto& [version, counts] : normalizedAfter.versionCounts) {
        auto& diff = result.versions[version];
        diff.after = counts;
    }
    for (auto& [version, diff] : result.versions) {
        (void)version;
        diff.delta = difference(diff.before, diff.after);
    }
    return result;
}

void RecoveryReportBuilder::setVersion(RecoveryVersionInfo version) {
    std::lock_guard lock(mutex_);
    version_ = std::move(version);
}

void RecoveryReportBuilder::setCapability(RecoveryCapability capability) {
    std::lock_guard lock(mutex_);
    capability_ = capability;
}

void RecoveryReportBuilder::addMethod(RecoveryMethod method) {
    std::lock_guard lock(mutex_);
    methods_.push_back(std::move(method));
}

void RecoveryReportBuilder::addMethod(std::string method, uint64_t address, RecoveryQuality quality) {
    addMethod(RecoveryMethod{std::move(method), address, quality});
}

void RecoveryReportBuilder::addMethod(
    std::string image,
    std::string method,
    uint64_t address,
    RecoveryQuality quality,
    std::vector<std::string> reasons) {
    addMethod(RecoveryMethod{
        std::move(method), address, quality, std::move(image), std::move(reasons)});
}

void RecoveryReportBuilder::addIssue(RecoveryIssue issue) {
    std::lock_guard lock(mutex_);
    issues_.push_back(std::move(issue));
}

void RecoveryReportBuilder::add(RecoveryMethod method, std::vector<RecoveryIssue> issues) {
    std::lock_guard lock(mutex_);
    methods_.push_back(std::move(method));
    issues_.insert(
        issues_.end(),
        std::make_move_iterator(issues.begin()),
        std::make_move_iterator(issues.end()));
}

void RecoveryReportBuilder::clear() {
    std::lock_guard lock(mutex_);
    version_ = {};
    capability_ = RecoveryCapability::Provisional;
    methods_.clear();
    issues_.clear();
}

RecoveryReport RecoveryReportBuilder::build() const {
    RecoveryReport report;
    {
        std::lock_guard lock(mutex_);
        report.version = version_;
        report.capability = capability_;
        report.methods = methods_;
        report.issues = issues_;
    }
    report.finalize();
    return report;
}

} // namespace il2cpprec
