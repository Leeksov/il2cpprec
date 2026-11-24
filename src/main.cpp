#include <il2cpprec/Recovery.hpp>
#include <il2cpprec/diagnostics/SemanticVerifier.hpp>
#include <il2cpprec/emit/ProjectWriter.hpp>
#include <il2cpprec/formats/BinaryLoader.hpp>
#include <il2cpprec/ida/IdaRecovery.hpp>
#include <il2cpprec/ida/McpClient.hpp>
#include <il2cpprec/ida/SourceProfile.hpp>
#include <il2cpprec/metadata/GlobalMetadata.hpp>
#include <il2cpprec/metadata/CodeGenModules.hpp>
#include <il2cpprec/metadata/MetadataRegistration.hpp>
#include <il2cpprec/metadata/MethodResolver.hpp>
#include <il2cpprec/metadata/ProtectedMetadata.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>
#include <il2cpprec/pipeline/RecoveryPipeline.hpp>
#include <il2cpprec/versions/Version24Modular.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

struct Arguments {
    il2cpprec::Architecture architecture = il2cpprec::Architecture::Arm64;
    uint64_t address = 0x1000;
    std::string name;
    std::string hex;
    std::string inputPath;
    std::string inspectPath;
    std::string outputDirectory;
    std::string binaryPath;
    std::string metadataPath;
    std::string reportPath;
    std::vector<std::string> includedImages;
    std::string il2cppVersion;
    std::string layout;
    std::string gameFilter;
    std::string idaMcpHost = "127.0.0.1";
    std::string idaMcpInstance;
    uint16_t idaMcpPort = 13337;
    size_t workers = 0;
    size_t cacheCapacity = 256;
    size_t maxMethodSize = 0;
    bool inspectModules = false;
    bool failOnPartial = false;
    bool verify = false;
    bool protectedProfile = false;
    bool idaMcp = false;
    bool help = false;
};

enum class MethodStatus {
    Exact,
    Partial,
    Error
};

struct MethodReport {
    size_t index = 0;
    std::string name;
    std::string imageName;
    uint64_t address = 0;
    size_t size = 0;
    MethodStatus status = MethodStatus::Error;
    std::vector<std::string> reasons;
    std::optional<il2cpprec::VerificationResult> verification;
};

struct RecoveryOutcome {
    std::vector<MethodReport> methods;
    std::vector<std::optional<il2cpprec::RecoveredFunction>> functions;
    std::vector<il2cpprec::RecoveredFunction> exactFunctions;
    size_t exact = 0;
    size_t partial = 0;
    size_t errors = 0;
};

struct RegistrationSummary {
    std::optional<uint64_t> methodPointerCount;
    std::optional<uint64_t> reversePInvokeWrapperCount;
    std::optional<uint64_t> genericMethodCount;
    std::optional<uint64_t> invokerCount;
    std::optional<uint64_t> codeGenModuleCount;
    std::optional<uint64_t> metadataUsageCount;
    std::string countsProvenance;
    std::vector<std::string> reasons;
};

struct RegistrationFieldReport {
    size_t countOffset = 0;
    bool present = false;
};

struct SourceProfileReport {
    il2cpprec::RecoverySourceProfile recovery;
    std::string id;
    std::string unityVersion;
    std::string variant;
    std::string layoutHash;
    std::string selectionMode;
    std::string sourceSet;
    std::string confidence;
    std::string confidenceReason;
    std::string provenance;
    std::string methodMapping;
    il2cpprec::ida::NativeProfileCapabilities capabilities;
    double detectedMetadataVersion = 0;
    double selectedMetadataVersion = 0;
    bool supported = false;
    RegistrationFieldReport methodPointers;
    RegistrationFieldReport reversePInvokeWrappers;
    RegistrationFieldReport genericMethodPointers;
    RegistrationFieldReport invokerPointers;
    RegistrationFieldReport codeGenModules;
};

std::string versionConfidenceName(il2cpprec::MetadataVersionConfidence confidence) {
    using Confidence = il2cpprec::MetadataVersionConfidence;
    switch (confidence) {
    case Confidence::Unknown: return "unknown";
    case Confidence::RawHeader: return "raw-header";
    case Confidence::InferredLayout: return "inferred-layout";
    case Confidence::Registration: return "registration";
    case Confidence::Explicit: return "explicit";
    }
    return "unknown";
}

std::string invokerName(il2cpprec::ida::NativeInvokerSignature signature) {
    using Signature = il2cpprec::ida::NativeInvokerSignature;
    switch (signature) {
    case Signature::Unknown: return "unknown";
    case Signature::LegacyThreeArguments: return "legacy-three-arguments";
    case Signature::FourArguments: return "four-arguments";
    case Signature::FiveArguments: return "five-arguments";
    }
    return "unknown";
}

std::string profileConfidenceName(il2cpprec::ida::NativeProfileConfidence confidence) {
    using Confidence = il2cpprec::ida::NativeProfileConfidence;
    switch (confidence) {
    case Confidence::Exact: return "exact";
    case Confidence::High: return "high";
    case Confidence::Compatible: return "compatible";
    case Confidence::Override: return "override";
    case Confidence::Unsupported: return "unsupported";
    }
    return "unsupported";
}

struct IdaMcpSession {
    std::unique_ptr<il2cpprec::ida::McpClient> client;
    std::string instanceId;
};

std::string mcpErrorMessage(const il2cpprec::ida::McpError& error);

template <typename Metadata, typename ResolutionReport>
RegistrationSummary makeRegistrationSummary(const Metadata& metadata, const ResolutionReport& report) {
    RegistrationSummary summary;
    if constexpr (requires { metadata.genericMethodPointers.size(); }) {
        if (!metadata.genericMethodPointers.empty() || metadata.metadataRegistrationAddress != 0) {
            summary.genericMethodCount = metadata.genericMethodPointers.size();
        }
    } else if constexpr (requires { metadata.genericMethodPointersCount; }) {
        summary.genericMethodCount = metadata.genericMethodPointersCount;
    } else if constexpr (requires { report.genericMethodCount; }) {
        summary.genericMethodCount = report.genericMethodCount;
    }
    if constexpr (requires { metadata.invokerPointers.size(); }) {
        if (!metadata.invokerPointers.empty() || metadata.metadataRegistrationAddress != 0) {
            summary.invokerCount = metadata.invokerPointers.size();
        }
    } else if constexpr (requires { metadata.invokerPointersCount; }) {
        summary.invokerCount = metadata.invokerPointersCount;
    } else if constexpr (requires { report.invokerCount; }) {
        summary.invokerCount = report.invokerCount;
    }
    if constexpr (requires { metadata.metadataUsages.size(); }) {
        summary.metadataUsageCount = metadata.metadataUsages.size();
    } else if constexpr (requires { metadata.metadataUsagesCount; }) {
        if (metadata.metadataUsagesCount != 0 || metadata.metadataRegistrationAddress != 0) {
            summary.metadataUsageCount = metadata.metadataUsagesCount;
        } else if constexpr (requires { metadata.metadataUsagePairs; }) {
            if (!metadata.metadataUsagePairs.empty()) {
                uint64_t count = 0;
                for (const auto& pair : metadata.metadataUsagePairs) {
                    count = std::max(count, static_cast<uint64_t>(pair.destinationIndex) + 1);
                }
                summary.metadataUsageCount = count;
            }
        }
    } else if constexpr (requires { report.metadataUsageCount; }) {
        summary.metadataUsageCount = report.metadataUsageCount;
    }
    if constexpr (requires { metadata.registrationReasons; }) {
        for (const auto& reason : metadata.registrationReasons) summary.reasons.push_back(reason);
    }
    if constexpr (requires { report.registrationReasons; }) {
        for (const auto& reason : report.registrationReasons) summary.reasons.push_back(reason);
    }
    return summary;
}

void printHelp(std::ostream& output) {
    output << "Usage:\n"
           << "  il2cpprec_cli --arch arm64|arm32|x86|x64 [--address 0x1000] [--name Method]\n"
           << "                [--hex BYTES | --input FILE] [recovery options]\n"
           << "  il2cpprec_cli --inspect BINARY [--metadata global-metadata.dat] [--modules]\n"
           << "  il2cpprec_cli --binary BINARY --metadata global-metadata.dat [--output-dir DIR]\n"
           << "                [recovery options]\n\n"
           << "Recovery options:\n"
           << "  --workers N              Worker threads (0 = automatic, default: 0)\n"
           << "  --cache N                Recovery cache capacity (0 = disabled, default: 256)\n"
           << "  --max-method-size N      Maximum bytes lifted per method (0 = resolver default)\n"
           << "  --protected-profile      Enable the protected-binary recovery profile\n"
           << "  --fail-on-partial        Return a non-zero status when any method is partial\n"
           << "  --verify                 Audit decoded instruction addresses and final IR structure\n"
           << "  --report FILE            Write a JSON report with per-method statuses and reasons\n"
           << "  --idamcp HOST[:PORT]     Connect to IDA MCP (default port: 13337)\n"
           << "  --idamcp-host HOST       Set the IDA MCP host and enable IDA MCP\n"
           << "  --idamcp-port PORT       Set the IDA MCP port and enable IDA MCP\n"
           << "  --idamcp-instance ID     Select an IDA instance and enable IDA MCP\n\n"
           << "Other options:\n"
           << "  --output-dir DIR         Write a C# project containing exact methods\n"
           << "  --include-images LIST    Comma-separated image names to include in the project\n"
           << "  --game NAME              Image preset (criticalops or none)\n"
           << "  --il2cpp-version VALUE   Unity/profile or metadata version override\n"
           << "  --layout VALUE           Layout profile, 24.0-24.5, legacy, or modern\n"
           << "  --modules                List code generation modules in deterministic order\n"
           << "  --help, -h               Show this help\n";
}

il2cpprec::Architecture parseArchitecture(const std::string& value) {
    if (value == "arm32") return il2cpprec::Architecture::Arm32;
    if (value == "arm64") return il2cpprec::Architecture::Arm64;
    if (value == "x86") return il2cpprec::Architecture::X86;
    if (value == "x64") return il2cpprec::Architecture::X64;
    throw std::invalid_argument("Unknown architecture: " + value);
}

uint64_t parseUnsigned(const std::string& value, const std::string& option, uint64_t maximum) {
    if (value.empty() || value.front() == '-') {
        throw std::invalid_argument("Invalid non-negative integer for " + option + ": " + value);
    }
    size_t consumed = 0;
    unsigned long long parsed = 0;
    try {
        parsed = std::stoull(value, &consumed, 0);
    } catch (const std::exception&) {
        throw std::invalid_argument("Invalid integer for " + option + ": " + value);
    }
    if (consumed != value.size() || parsed > maximum) {
        throw std::invalid_argument("Invalid or out-of-range integer for " + option + ": " + value);
    }
    return static_cast<uint64_t>(parsed);
}

uint64_t parseNumber(const std::string& value, const std::string& option = "--address") {
    return parseUnsigned(value, option, std::numeric_limits<uint64_t>::max());
}

size_t parseSize(const std::string& value, const std::string& option) {
    return static_cast<size_t>(parseUnsigned(
        value,
        option,
        static_cast<uint64_t>(std::numeric_limits<size_t>::max())));
}

std::vector<std::string> parseIncludedImages(const std::string& value) {
    std::vector<std::string> images;
    size_t start = 0;
    while (start <= value.size()) {
        const auto end = value.find(',', start);
        const auto length = (end == std::string::npos ? value.size() : end) - start;
        auto image = value.substr(start, length);
        const auto first = std::find_if_not(image.begin(), image.end(), [](unsigned char c) {
            return std::isspace(c) != 0;
        });
        const auto last = std::find_if_not(image.rbegin(), image.rend(), [](unsigned char c) {
            return std::isspace(c) != 0;
        }).base();
        if (first >= last) throw std::invalid_argument("--include-images contains an empty image name");
        image = std::string(first, last);
        if (std::find(images.begin(), images.end(), image) == images.end()) images.push_back(std::move(image));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (images.empty()) throw std::invalid_argument("--include-images requires at least one image name");
    return images;
}

std::vector<uint8_t> parseHex(std::string value) {
    std::vector<uint8_t> result;
    std::string token;
    for (const char c : value) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            token.push_back(c);
            continue;
        }
        if (c == 'x' || c == 'X') {
            token.clear();
            continue;
        }
        if (!token.empty() && (c == ' ' || c == '_' || c == ',' || c == '\t' || c == '\n')) {
            if (token.size() % 2 != 0) throw std::invalid_argument("Incomplete byte in hex input");
            for (size_t i = 0; i < token.size(); i += 2) {
                result.push_back(static_cast<uint8_t>(std::stoul(token.substr(i, 2), nullptr, 16)));
            }
            token.clear();
        }
    }
    if (!token.empty()) {
        if (token.size() % 2 != 0) throw std::invalid_argument("Incomplete byte in hex input");
        for (size_t i = 0; i < token.size(); i += 2) {
            result.push_back(static_cast<uint8_t>(std::stoul(token.substr(i, 2), nullptr, 16)));
        }
    }
    return result;
}

std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open input file: " + path);
    const auto size = stream.tellg();
    if (size < 0) throw std::runtime_error("Cannot determine input file size: " + path);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    stream.seekg(0);
    if (!data.empty()) {
        stream.read(reinterpret_cast<char*>(data.data()), size);
        if (!stream) throw std::runtime_error("Cannot read input file: " + path);
    }
    return data;
}

void parseIdaMcpEndpoint(const std::string& value, Arguments& result) {
    if (value.empty()) throw std::invalid_argument("Missing host for --idamcp");
    result.idaMcp = true;
    if (value.front() == '[') {
        const auto closing = value.find(']');
        if (closing == std::string::npos) {
            throw std::invalid_argument("Invalid bracketed IDA MCP host: " + value);
        }
        result.idaMcpHost = value.substr(1, closing - 1);
        if (result.idaMcpHost.empty()) throw std::invalid_argument("Missing host for --idamcp");
        if (closing + 1 < value.size()) {
            if (value[closing + 1] != ':' || closing + 2 == value.size()) {
                throw std::invalid_argument("Invalid IDA MCP endpoint: " + value);
            }
            result.idaMcpPort = static_cast<uint16_t>(parseUnsigned(value.substr(closing + 2), "--idamcp", 65535));
        }
        if (result.idaMcpPort == 0) throw std::invalid_argument("IDA MCP port must be between 1 and 65535");
        return;
    }

    const auto firstColon = value.find(':');
    const auto lastColon = value.rfind(':');
    if (firstColon != std::string::npos && firstColon == lastColon) {
        result.idaMcpHost = value.substr(0, firstColon);
        if (firstColon + 1 == value.size()) {
            throw std::invalid_argument("Missing port in IDA MCP endpoint: " + value);
        }
        result.idaMcpPort = static_cast<uint16_t>(parseUnsigned(value.substr(firstColon + 1), "--idamcp", 65535));
    } else {
        result.idaMcpHost = value;
    }
    if (result.idaMcpHost.empty()) throw std::invalid_argument("Missing host for --idamcp");
    if (result.idaMcpPort == 0) throw std::invalid_argument("IDA MCP port must be between 1 and 65535");
}

Arguments parseArguments(int argc, char** argv) {
    Arguments result;
    for (int i = 1; i < argc; ++i) {
        std::string option = argv[i];
        std::string inlineValue;
        bool hasInlineValue = false;
        if (const auto equals = option.find('='); equals != std::string::npos) {
            inlineValue = option.substr(equals + 1);
            option.resize(equals);
            hasInlineValue = true;
        }

        if (option == "--help" || option == "-h") {
            if (hasInlineValue) throw std::invalid_argument("Unexpected value for " + option);
            result.help = true;
            continue;
        }
        if (option == "--modules" || option == "--fail-on-partial" ||
            option == "--protected-profile" || option == "--verify") {
            if (hasInlineValue) throw std::invalid_argument("Unexpected value for " + option);
            if (option == "--modules") result.inspectModules = true;
            else if (option == "--fail-on-partial") result.failOnPartial = true;
            else if (option == "--verify") result.verify = true;
            else result.protectedProfile = true;
            continue;
        }

        std::string value;
        if (hasInlineValue) {
            value = std::move(inlineValue);
        } else {
            if (i + 1 >= argc) throw std::invalid_argument("Missing value for " + option);
            value = argv[++i];
        }

        if (option == "--arch") result.architecture = parseArchitecture(value);
        else if (option == "--address") result.address = parseNumber(value);
        else if (option == "--name") result.name = value;
        else if (option == "--hex") result.hex = value;
        else if (option == "--input") result.inputPath = value;
        else if (option == "--inspect") result.inspectPath = value;
        else if (option == "--output-dir") result.outputDirectory = value;
        else if (option == "--include-images") {
            auto images = parseIncludedImages(value);
            result.includedImages.insert(result.includedImages.end(), images.begin(), images.end());
        }
        else if (option == "--il2cpp-version") result.il2cppVersion = value;
        else if (option == "--layout") result.layout = value;
        else if (option == "--game" || option == "--game-filter") result.gameFilter = value;
        else if (option == "--binary") result.binaryPath = value;
        else if (option == "--metadata") result.metadataPath = value;
        else if (option == "--workers") result.workers = parseSize(value, option);
        else if (option == "--cache") result.cacheCapacity = parseSize(value, option);
        else if (option == "--report") result.reportPath = value;
        else if (option == "--idamcp") parseIdaMcpEndpoint(value, result);
        else if (option == "--idamcp-host") {
            if (value.empty()) throw std::invalid_argument("Missing host for --idamcp-host");
            result.idaMcpHost = value;
            result.idaMcp = true;
        } else if (option == "--idamcp-port") {
            const auto port = parseUnsigned(value, option, 65535);
            if (port == 0) throw std::invalid_argument("IDA MCP port must be between 1 and 65535");
            result.idaMcpPort = static_cast<uint16_t>(port);
            result.idaMcp = true;
        } else if (option == "--idamcp-instance") {
            if (value.empty()) throw std::invalid_argument("Missing instance for --idamcp-instance");
            result.idaMcpInstance = value;
            result.idaMcp = true;
        } else if (option == "--max-method-size") {
            result.maxMethodSize = parseSize(value, option);
        } else {
            throw std::invalid_argument("Unknown option: " + option);
        }
    }
    if (!result.gameFilter.empty() && result.gameFilter != "none") {
        if (result.gameFilter != "criticalops" && result.gameFilter != "critical-ops") {
            throw std::invalid_argument("Unknown game filter: " + result.gameFilter);
        }
        for (const char* image : {"Assembly-CSharp.dll", "Assembly-CSharp-firstpass.dll", "Assembly-UnityScript-firstpass.dll"}) {
            if (std::find(result.includedImages.begin(), result.includedImages.end(), image) == result.includedImages.end()) {
                result.includedImages.emplace_back(image);
            }
        }
    }
    return result;
}

std::string hexAddress(uint64_t address) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result = "0x";
    bool started = false;
    for (int shift = 60; shift >= 0; shift -= 4) {
        const auto digit = static_cast<unsigned>((address >> shift) & 0x0f);
        if (digit != 0 || started || shift == 0) {
            started = true;
            result.push_back(digits[digit]);
        }
    }
    return result;
}

void fnvByte(uint64_t& hash, uint8_t byte) {
    hash ^= byte;
    hash *= 1099511628211ULL;
}

void fnvText(uint64_t& hash, std::string_view text) {
    for (const unsigned char byte : text) fnvByte(hash, byte);
}

void fnvInteger(uint64_t& hash, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        fnvByte(hash, static_cast<uint8_t>(value & 0xff));
        value >>= 8;
    }
}

std::string binaryIdentity(const il2cpprec::BinaryImage& binary) {
    uint64_t hash = 14695981039346656037ULL;
    if (binary.bytes) {
        for (const uint8_t byte : *binary.bytes) fnvByte(hash, byte);
    }
    return "fnv1a64:" + hexAddress(hash);
}

std::string methodPointersIdentity(const il2cpprec::MetadataModel& metadata) {
    uint64_t hash = 14695981039346656037ULL;
    std::vector<std::pair<std::string, const std::vector<uint64_t>*>> images;
    for (const auto& [name, pointers] : metadata.methodPointersByImage) images.emplace_back(name, &pointers);
    std::sort(images.begin(), images.end(), [](const auto& left, const auto& right) {
        return left.first < right.first;
    });
    for (const auto& [name, pointers] : images) {
        fnvText(hash, name);
        fnvInteger(hash, pointers->size());
        for (const auto pointer : *pointers) fnvInteger(hash, pointer);
    }
    return "fnv1a64:" + hexAddress(hash);
}

double parseMetadataVersion(const std::string& value, const std::string& option) {
    size_t consumed = 0;
    double version = 0;
    try {
        version = std::stod(value, &consumed);
    } catch (const std::exception&) {
        throw std::invalid_argument("Unknown IL2CPP metadata version for " + option + ": " + value);
    }
    if (consumed != value.size() || !std::isfinite(version) || version <= 0) {
        throw std::invalid_argument("Unknown IL2CPP metadata version for " + option + ": " + value);
    }
    return version;
}

RegistrationFieldReport registrationField(const il2cpprec::ida::NativeTableLayout& field) {
    return {field.count.offset, field.count.present && field.pointer.present};
}

std::string metadataVersionText(double version) {
    auto text = std::to_string(version);
    while (!text.empty() && text.back() == '0') text.pop_back();
    if (!text.empty() && text.back() == '.') text.pop_back();
    return text;
}

void populateRecoveryProfile(SourceProfileReport& report, const il2cpprec::MetadataModel& metadata) {
    auto& recovery = report.recovery;
    recovery.profileIdentity = report.id;
    recovery.layoutIdentity = report.layoutHash;
    recovery.rawMetadataVersion = metadata.versionInfo.rawVersion;
    recovery.preciseMetadataVersion = report.selectedMetadataVersion;
    recovery.registrationVersion = metadata.versionInfo.registrationVersion;
    recovery.versionConfidence = metadata.versionInfo.confidence;
    recovery.versionProvenance = metadata.versionInfo.provenance;
    recovery.methodSignatures = metadata.sections.methodSignatures;
    recovery.generatedMethodTypeInfos = metadata.sections.generatedMethodTypeInfos;
    recovery.generatedMethodTokens = metadata.sections.generatedMethodTokens;
    recovery.generatedMethodsStart = metadata.generatedMethodsStart;
}

void markVersionOverride(SourceProfileReport& report, const Arguments& arguments) {
    if (arguments.il2cppVersion.empty() && arguments.layout.empty()) return;
    report.recovery.versionConfidence = il2cpprec::MetadataVersionConfidence::Explicit;
    report.recovery.versionProvenance = "CLI override";
    if (!arguments.il2cppVersion.empty()) report.recovery.versionProvenance += " --il2cpp-version=" + arguments.il2cppVersion;
    if (!arguments.layout.empty()) report.recovery.versionProvenance += " --layout=" + arguments.layout;
}

SourceProfileReport makeVersion24ModularReport(
    const il2cpprec::BinaryImage& binary,
    const il2cpprec::MetadataModel& metadata,
    double version,
    const std::string& selectionMode) {
    const auto variant = il2cpprec::versions::Version24Modular::variantFor(version);
    if (!variant) throw std::invalid_argument("Unsupported modular IL2CPP version: " + metadataVersionText(version));
    const auto pointerSize = il2cpprec::ida::sourcePointerSize(binary);
    const auto layout = il2cpprec::versions::Version24ModularLayout::make(*variant, pointerSize);
    SourceProfileReport result;
    result.id = "il2cpp-24-modular";
    result.unityVersion = "24.2-24.3";
    result.variant = metadataVersionText(layout.version());
    result.selectionMode = selectionMode;
    result.sourceSet = "version-specific Version24Modular";
    result.detectedMetadataVersion = metadata.version;
    result.selectedMetadataVersion = layout.version();
    result.supported = true;
    result.confidence = "compatible";
    result.confidenceReason = "version-specific modular registration layout selected from metadata version";
    result.provenance = result.sourceSet;
    result.methodMapping = "per-image-token-row-id";
    const auto pair = [&](size_t index) {
        return RegistrationFieldReport{index * 2 * pointerSize, true};
    };
    result.reversePInvokeWrappers = pair(layout.reversePInvokeWrappersPair);
    result.genericMethodPointers = pair(layout.genericMethodPointersPair);
    result.invokerPointers = pair(layout.invokerPointersPair);
    result.codeGenModules = pair(layout.codeGenModulesPair);
    uint64_t hash = 14695981039346656037ULL;
    fnvText(hash, result.id);
    fnvInteger(hash, pointerSize);
    fnvInteger(hash, static_cast<uint64_t>(*variant));
    result.layoutHash = "fnv1a64:" + hexAddress(hash);
    result.recovery.unityMetadataVersion = result.variant;
    result.recovery.binaryIdentity = binaryIdentity(binary);
    result.recovery.codeRegistrationIdentity = result.layoutHash + "@" + hexAddress(metadata.codeRegistrationAddress);
    result.recovery.methodPointersIdentity = methodPointersIdentity(metadata);
    populateRecoveryProfile(result, metadata);
    return result;
}

SourceProfileReport makeSourceProfileReport(
    const il2cpprec::BinaryImage& binary,
    const il2cpprec::MetadataModel& metadata,
    const Arguments& arguments) {
    SourceProfileReport result;
    result.detectedMetadataVersion = metadata.version;
    il2cpprec::ida::SourceDetectionInput detection;
    detection.metadataVersion = metadata.version;
    detection.binary = &binary;
    if (metadata.codeRegistrationAddress != 0) {
        detection.registration.codeRegistrationAddress = metadata.codeRegistrationAddress;
    }
    if (metadata.metadataRegistrationAddress != 0) {
        detection.registration.metadataRegistrationAddress = metadata.metadataRegistrationAddress;
    }
    if (!arguments.protectedProfile) detection.rawMetadata = readFile(arguments.metadataPath);

    const auto setVersion = [&](double version, const char* option) {
        if (detection.overrides.metadataVersion && *detection.overrides.metadataVersion != version) {
            throw std::invalid_argument(std::string("Conflicting IL2CPP version overrides: ") + option);
        }
        detection.overrides.metadataVersion = version;
    };
    const auto setProfile = [&](const il2cpprec::ida::SourceProfile& profile, const char* option) {
        if (!detection.overrides.profileId.empty() && detection.overrides.profileId != profile.id) {
            throw std::invalid_argument(std::string("Conflicting IL2CPP profile overrides: ") + option);
        }
        detection.overrides.profileId = profile.id;
    };
    const auto profileFor = [](const std::string& value) {
        if (const auto* profile = il2cpprec::ida::Il2CppNativeProfileRegistry::find(value)) return profile;
        return il2cpprec::ida::findSourceProfile(value);
    };
    if (!arguments.il2cppVersion.empty()) {
        result.selectionMode = "il2cpp-version-override";
        if (const auto* profile = profileFor(arguments.il2cppVersion)) {
            setProfile(*profile, "--il2cpp-version");
        } else {
            setVersion(parseMetadataVersion(arguments.il2cppVersion, "--il2cpp-version"), "--il2cpp-version");
        }
    }
    if (!arguments.layout.empty()) {
        result.selectionMode = result.selectionMode.empty() ? "layout-override" : "combined-override";
        if (arguments.layout == "legacy" || arguments.layout == "modern") {
            setVersion(arguments.layout == "legacy" ? 24.1 : 24.5, "--layout");
        } else if (const auto* profile = profileFor(arguments.layout)) {
            setProfile(*profile, "--layout");
        } else {
            setVersion(parseMetadataVersion(arguments.layout, "--layout"), "--layout");
        }
    }
    if (result.selectionMode.empty()) result.selectionMode = arguments.protectedProfile ? "protected-researched" : "auto";
    const double selectedVersion = detection.overrides.metadataVersion.value_or(metadata.version);
    if (il2cpprec::versions::Version24Modular::supports(selectedVersion)) {
        if (!detection.overrides.profileId.empty()) {
            throw std::invalid_argument("Unsupported IL2CPP layout override for modular metadata " +
                metadataVersionText(selectedVersion) + ": no validated matching profile");
        }
        auto modular = makeVersion24ModularReport(binary, metadata, selectedVersion, result.selectionMode);
        markVersionOverride(modular, arguments);
        return modular;
    }

    const auto detected = il2cpprec::ida::Il2CppNativeProfileRegistry::detect(detection);
    if (!arguments.protectedProfile && !detected.supported()) {
        throw std::invalid_argument("Unsupported IL2CPP profile/layout for metadata " +
            metadataVersionText(selectedVersion) + ": " + detected.error);
    }
    const auto& selection = detected.selection;
    const auto validation = validateSourceLayout(selection);
    if (!arguments.protectedProfile &&
        (!selection.supported || !selection.nativeRuntimeAvailable || !validation.empty())) {
        const auto detail = !validation.empty() ? validation.front() : selection.diagnostics();
        throw std::invalid_argument(
            "Unsupported IL2CPP profile/layout for metadata " + std::to_string(selectedVersion) + ": " + detail);
    }

    result.id = selection.profile ? selection.profile->id : "unknown";
    result.unityVersion = selection.profile ? selection.profile->unityVersion : "";
    result.variant = selection.variant;
    result.layoutHash = selection.supported ? selection.layoutHash() : "";
    result.supported = selection.supported;
    result.sourceSet = selection.profile ? selection.profile->sourceSet : "";
    result.selectedMetadataVersion = selection.supported ? selection.metadataVersion : selectedVersion;
    result.methodMapping = !selection.supported ? "unknown" :
        (selection.methodMapping == il2cpprec::ida::MethodMapping::PerImageTokenRowId
            ? "per-image-token-row-id" : "global-method-index");
    result.confidence = profileConfidenceName(selection.confidence);
    result.confidenceReason = detected.error.empty() ? selection.diagnostics() : detected.error;
    result.provenance = selection.provenance;
    result.capabilities = selection.capabilities;
    result.methodPointers = registrationField(selection.codeRegistration.methodPointers);
    result.reversePInvokeWrappers = registrationField(selection.codeRegistration.reversePInvokeWrappers);
    result.genericMethodPointers = registrationField(selection.codeRegistration.genericMethodPointers);
    result.invokerPointers = registrationField(selection.codeRegistration.invokerPointers);
    result.codeGenModules = registrationField(selection.codeRegistration.codeGenModules);
    result.recovery.unityMetadataVersion = selection.variant.empty()
        ? std::to_string(selectedVersion)
        : selection.variant;
    result.recovery.binaryIdentity = binaryIdentity(binary);
    result.recovery.codeRegistrationIdentity = result.layoutHash + "@" +
        hexAddress(metadata.codeRegistrationAddress);
    result.recovery.methodPointersIdentity = methodPointersIdentity(metadata);
    populateRecoveryProfile(result, metadata);
    if (selection.rawVersion != 0) result.recovery.rawMetadataVersion = selection.rawVersion;
    if (selection.registrationVersion != 0) result.recovery.registrationVersion = selection.registrationVersion;
    markVersionOverride(result, arguments);
    return result;
}

size_t binaryPointerSize(const il2cpprec::BinaryImage& binary) {
    return binary.architecture == il2cpprec::Architecture::X86 ||
        binary.architecture == il2cpprec::Architecture::Arm32 ? 4 : 8;
}

uint32_t readLittle32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
        (static_cast<uint32_t>(data[1]) << 8) |
        (static_cast<uint32_t>(data[2]) << 16) |
        (static_cast<uint32_t>(data[3]) << 24);
}

uint64_t readLittle64(const uint8_t* data) {
    return static_cast<uint64_t>(readLittle32(data)) |
        (static_cast<uint64_t>(readLittle32(data + 4)) << 32);
}

uint64_t readBinaryPointer(const uint8_t* data, size_t pointerSize) {
    return pointerSize == 8 ? readLittle64(data) : readLittle32(data);
}

size_t binaryPointerOffset(const il2cpprec::BinaryImage& binary, uint64_t pointer, size_t size) {
    pointer &= 0x0000FFFFFFFFFFFFULL;
    if (binary.architecture == il2cpprec::Architecture::Arm32) pointer &= ~uint64_t{1};
    std::vector<uint64_t> candidates;
    if (binary.imageBase != 0 && pointer >= binary.imageBase) candidates.push_back(pointer - binary.imageBase);
    candidates.push_back(pointer);
    if (binary.imageBase != 0 && pointer <= std::numeric_limits<uint64_t>::max() - binary.imageBase) {
        candidates.push_back(pointer + binary.imageBase);
    }
    for (const auto candidate : candidates) {
        try {
            const auto offset = binary.mapVATR(candidate);
            if (offset <= std::numeric_limits<size_t>::max()) {
                binary.data(static_cast<size_t>(offset), size);
                return static_cast<size_t>(offset);
            }
        } catch (const std::exception&) {
        }
    }
    throw std::runtime_error("address is not backed by a file range: " + hexAddress(pointer));
}

struct GlobalRegistrationTable {
    uint64_t registrationAddress = 0;
    uint64_t tableAddress = 0;
    std::vector<uint64_t> methodPointers;
};

GlobalRegistrationTable readGlobalRegistrationTable(
    const il2cpprec::BinaryImage& binary,
    uint64_t registrationAddress) {
    const auto pointerSize = binaryPointerSize(binary);
    const auto registrationOffset = binaryPointerOffset(binary, registrationAddress, 2 * pointerSize);
    const auto* registration = binary.data(registrationOffset, 2 * pointerSize);
    const auto count = readLittle32(registration);
    if (pointerSize == 8 && readLittle32(registration + 4) != 0) {
        throw std::runtime_error("legacy global method pointer count exceeds 32 bits");
    }

    GlobalRegistrationTable table;
    table.registrationAddress = registrationAddress;
    table.tableAddress = readBinaryPointer(registration + pointerSize, pointerSize);
    if (count == 0) return table;
    if (table.tableAddress == 0) throw std::runtime_error("legacy global method pointer table is null");
    if (count > std::numeric_limits<size_t>::max() / pointerSize) {
        throw std::runtime_error("legacy global method pointer table size overflows");
    }
    const auto tableSize = static_cast<size_t>(count) * pointerSize;
    const auto tableOffset = binaryPointerOffset(binary, table.tableAddress, tableSize);
    const auto* addresses = binary.data(tableOffset, tableSize);
    table.methodPointers.reserve(count);
    for (uint32_t index = 0; index < count; ++index) {
        auto address = readBinaryPointer(addresses + static_cast<size_t>(index) * pointerSize, pointerSize);
        address &= 0x0000FFFFFFFFFFFFULL;
        if (binary.architecture == il2cpprec::Architecture::Arm32) address &= ~uint64_t{1};
        table.methodPointers.push_back(address);
    }
    return table;
}

GlobalRegistrationTable readLegacyCodeRegistrationTable(
    const il2cpprec::BinaryImage& binary,
    uint64_t codeRegistrationAddress,
    size_t pairIndex) {
    const auto pairSize = 2 * binaryPointerSize(binary);
    if (codeRegistrationAddress > std::numeric_limits<uint64_t>::max() - pairIndex * pairSize) {
        throw std::runtime_error("legacy code registration pair address overflows");
    }
    return readGlobalRegistrationTable(binary, codeRegistrationAddress + pairIndex * pairSize);
}

uint64_t readRegistrationTableCount(
    const il2cpprec::BinaryImage& binary,
    uint64_t codeRegistrationAddress,
    size_t countOffset) {
    const auto pointerSize = binaryPointerSize(binary);
    if (codeRegistrationAddress > std::numeric_limits<uint64_t>::max() - countOffset) {
        throw std::runtime_error("code registration table address overflows");
    }
    const auto address = codeRegistrationAddress + countOffset;
    const auto offset = binaryPointerOffset(binary, address, 2 * pointerSize);
    const auto* data = binary.data(offset, 2 * pointerSize);
    const auto count = readLittle32(data);
    if (pointerSize == 8 && readLittle32(data + 4) != 0) {
        throw std::runtime_error("registration table count exceeds 32 bits");
    }
    if (count != 0) {
        const auto table = readBinaryPointer(data + pointerSize, pointerSize);
        if (table == 0) throw std::runtime_error("registration table pointer is null");
        if (count > std::numeric_limits<size_t>::max() / pointerSize) {
            throw std::runtime_error("registration table size overflows");
        }
        binaryPointerOffset(binary, table, static_cast<size_t>(count) * pointerSize);
    }
    return count;
}

void printModules(
    const il2cpprec::BinaryImage& binary,
    const il2cpprec::MetadataModel& metadata,
    bool metadataLoaded) {
    const bool legacy = metadata.codeRegistrationAddress != 0 &&
        ((metadata.version > 0 && metadata.version <= 24.1) || metadata.methodPointersByImage.empty());
    if (legacy) {
        const auto global = readGlobalRegistrationTable(binary, metadata.codeRegistrationAddress);
        std::cout << "global registration=" << hexAddress(global.registrationAddress)
                  << " table=" << hexAddress(global.tableAddress)
                  << " methods=" << global.methodPointers.size() << '\n';
        for (size_t index = 0; index < global.methodPointers.size(); ++index) {
            std::cout << "global[" << index << "] address=" << hexAddress(global.methodPointers[index]) << '\n';
        }
        if (!metadataLoaded) return;

        std::vector<std::pair<std::string, const std::vector<uint64_t>*>> images;
        images.reserve(metadata.methodPointersByImage.size());
        for (const auto& [name, pointers] : metadata.methodPointersByImage) {
            images.emplace_back(name, &pointers);
        }
        std::sort(images.begin(), images.end(), [](const auto& left, const auto& right) {
            return left.first < right.first;
        });
        for (const auto& [name, pointers] : images) {
            const auto present = static_cast<size_t>(std::count_if(pointers->begin(), pointers->end(), [](uint64_t address) {
                return address != 0;
            }));
            std::cout << "image " << name << " slots=" << pointers->size()
                      << " methods=" << present << " view=sparse\n";
            for (size_t index = 0; index < pointers->size(); ++index) {
                if ((*pointers)[index] == 0) continue;
                std::cout << "image " << name << "[" << index << "] address="
                          << hexAddress((*pointers)[index]) << '\n';
            }
        }
        return;
    }

    std::vector<std::pair<std::string, size_t>> modules;
    modules.reserve(metadata.methodPointersByImage.size());
    for (const auto& [name, pointers] : metadata.methodPointersByImage) {
        modules.emplace_back(name, pointers.size());
    }
    std::sort(modules.begin(), modules.end(), [](const auto& left, const auto& right) {
        return left.first < right.first;
    });
    for (const auto& [name, count] : modules) {
        std::cout << name << " methods=" << count << '\n';
    }
}

std::string jsonString(std::string_view value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result = "\"";
    for (const unsigned char c : value) {
        switch (c) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (c < 0x20) {
                result += "\\u00";
                result.push_back(digits[c >> 4]);
                result.push_back(digits[c & 0x0f]);
            } else {
                result.push_back(static_cast<char>(c));
            }
        }
    }
    result.push_back('"');
    return result;
}

const char* statusName(MethodStatus status) {
    switch (status) {
    case MethodStatus::Exact: return "exact";
    case MethodStatus::Partial: return "partial";
    case MethodStatus::Error: return "error";
    }
    return "error";
}

std::vector<std::string> partialReasons(const il2cpprec::RecoveredFunction& function) {
    const auto emission = function.emitCSharp();
    std::vector<std::string> reasons;
    reasons.reserve(emission.diagnostics.size() + 1);
    for (const auto& diagnostic : emission.diagnostics) {
        reasons.push_back(diagnostic.message + " at " + hexAddress(diagnostic.address));
    }
    if (emission.partial && reasons.empty()) reasons.push_back("C# emission is incomplete");
    return reasons;
}

RecoveryOutcome recoverMethods(
    std::vector<il2cpprec::FunctionImage> images,
    const Arguments& arguments,
    IdaMcpSession* idaSession = nullptr,
    const std::string& binaryPath = {},
    const il2cpprec::RecoverySourceProfile& sourceProfile = {}) {
    il2cpprec::RecoveryPipelineOptions pipelineOptions;
    pipelineOptions.workerCount = arguments.workers;
    pipelineOptions.cacheCapacity = arguments.cacheCapacity;
    pipelineOptions.sourceProfile = sourceProfile;

    std::vector<std::vector<std::string>> inputReasons(images.size());
    if (arguments.maxMethodSize != 0) {
        for (size_t i = 0; i < images.size(); ++i) {
            if (images[i].size > arguments.maxMethodSize) {
                inputReasons[i].push_back(
                    "method size " + std::to_string(images[i].size) +
                    " exceeds --max-method-size " + std::to_string(arguments.maxMethodSize) +
                    "; input was truncated");
                images[i].size = arguments.maxMethodSize;
            }
        }
    }

    il2cpprec::RecoveryPipeline pipeline(pipelineOptions);
    const auto results = pipeline.recover(images);
    std::unique_ptr<il2cpprec::ida::IdaRecovery> idaRecovery;
    if (idaSession && idaSession->client) {
        idaRecovery = std::make_unique<il2cpprec::ida::IdaRecovery>(*idaSession->client);
    }

    RecoveryOutcome outcome;
    outcome.methods.reserve(results.size());
    outcome.functions.reserve(results.size());

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& result = results[i];
        MethodReport report;
        report.index = i;
        report.name = images[i].name;
        report.address = images[i].address;
        report.size = images[i].size;
        report.reasons = std::move(inputReasons[i]);

        std::optional<il2cpprec::RecoveredFunction> function;
        if (result.succeeded() && result.function) function = *result.function;
        if (function && function->blocks.empty()) {
            report.reasons.push_back("no native basic blocks were produced");
            function.reset();
        }
        if (!result.error.empty()) report.reasons.push_back(result.error);

        if (idaRecovery && (!function || !partialReasons(*function).empty())) {
            il2cpprec::ida::IdaRecoveryOptions options;
            options.name = images[i].name;
            auto fallback = idaRecovery->recover({binaryPath, {}, {}}, images[i], options);
            if (fallback.function) {
                function = std::move(fallback.function);
                if (fallback.status == il2cpprec::ida::IdaRecoveryStatus::ControlFlowOnly) {
                    report.reasons.push_back(fallback.artifact.reason);
                    for (const auto& warning : fallback.artifact.warnings) {
                        report.reasons.push_back("IDA: " + mcpErrorMessage(warning));
                    }
                }
            } else {
                const auto reason = !fallback.error.message.empty()
                    ? fallback.error.message
                    : fallback.artifact.reason;
                if (!reason.empty()) report.reasons.push_back("IDA: " + reason);
            }
        }

        if (function) {
            outcome.functions.push_back(*function);
            if (arguments.verify) {
                report.verification = il2cpprec::SemanticVerifier{}.verify(images[i], *function);
            }
            auto reasons = partialReasons(*function);
            for (auto& reason : reasons) {
                report.reasons.push_back(std::move(reason));
            }
            if (report.reasons.empty()) {
                report.status = MethodStatus::Exact;
                ++outcome.exact;
                outcome.exactFunctions.push_back(*function);
            } else {
                report.status = MethodStatus::Partial;
                ++outcome.partial;
            }
        } else {
            outcome.functions.push_back(std::nullopt);
            if (arguments.verify) {
                report.verification = il2cpprec::VerificationResult{};
            }
            report.status = MethodStatus::Error;
            ++outcome.errors;
            if (report.reasons.empty()) {
                report.reasons.push_back(
                    result.status == il2cpprec::RecoveryResultStatus::Cancelled
                        ? "recovery cancelled"
                        : "pipeline returned no function");
            }
        }
        outcome.methods.push_back(std::move(report));
    }
    return outcome;
}

std::string methodLabel(const MethodReport& method) {
    auto label = "[" + std::to_string(method.index) + "]";
    if (!method.name.empty()) label += " " + method.name;
    label += " at " + hexAddress(method.address);
    return label;
}

void printDiagnostics(const RecoveryOutcome& outcome, std::ostream& output) {
    for (const auto& method : outcome.methods) {
        if (method.status == MethodStatus::Exact) continue;
        output << statusName(method.status) << " " << methodLabel(method) << '\n';
        for (const auto& reason : method.reasons) {
            output << "  reason: " << reason << '\n';
        }
    }
}

void printSummary(const RecoveryOutcome& outcome, std::ostream& output) {
    output << "methods=" << outcome.methods.size()
           << " exact=" << outcome.exact
           << " partial=" << outcome.partial
           << " errors=" << outcome.errors << '\n';
}

void printVerificationSummary(const RecoveryOutcome& outcome, std::ostream& output) {
    size_t checked = 0;
    size_t suspect = 0;
    size_t unverifiable = 0;
    size_t unmapped = 0;
    for (const auto& method : outcome.methods) {
        if (!method.verification) continue;
        const auto& verification = *method.verification;
        if (verification.status == il2cpprec::VerificationStatus::Unverifiable) {
            ++unverifiable;
        } else {
            ++checked;
            if (verification.status == il2cpprec::VerificationStatus::Suspect) ++suspect;
            unmapped += verification.unmappedInstructions;
        }
    }
    output << "verification: checked=" << checked << " suspect=" << suspect
           << " unverifiable=" << unverifiable << " unmapped-instructions=" << unmapped
           << " (unmapped is informational; no semantic-equivalence claim)\n";
}

std::string partialReasonCategory(const std::string& reason) {
    if (reason.starts_with("Unsupported instruction")) return "unsupported-instruction";
    if (reason.starts_with("Unsupported") && reason.find("load") != std::string::npos) return "unsupported-load";
    if (reason.starts_with("Unsupported") && reason.find("conversion") != std::string::npos) {
        return "unsupported-conversion";
    }
    if (reason.starts_with("Unsupported")) return "unsupported-operation";
    if (reason.starts_with("method size")) return "method-size-limit";
    if (reason.starts_with("IDA:")) return "ida-recovery";
    if (reason.starts_with("no native basic blocks")) return "empty-recovery";
    return "other";
}

struct PartialReasonImage {
    size_t occurrences = 0;
    std::set<size_t> methods;
};

struct PartialReasonCategory {
    size_t occurrences = 0;
    std::set<size_t> methods;
    std::map<std::string, PartialReasonImage> images;
};

struct PartialReasonSummary {
    size_t occurrences = 0;
    std::set<size_t> methods;
    std::map<std::string, PartialReasonImage> images;
    std::map<std::string, PartialReasonCategory> categories;
};

PartialReasonSummary summarizePartialReasons(const RecoveryOutcome& outcome) {
    PartialReasonSummary summary;
    for (const auto& method : outcome.methods) {
        if (method.status != MethodStatus::Partial) continue;
        const auto image = method.imageName.empty() ? std::string("<unknown>") : method.imageName;
        summary.methods.insert(method.index);
        auto& imageSummary = summary.images[image];
        imageSummary.methods.insert(method.index);
        for (const auto& reason : method.reasons) {
            ++summary.occurrences;
            ++imageSummary.occurrences;
            auto& category = summary.categories[partialReasonCategory(reason)];
            ++category.occurrences;
            category.methods.insert(method.index);
            auto& categoryImage = category.images[image];
            ++categoryImage.occurrences;
            categoryImage.methods.insert(method.index);
        }
    }
    return summary;
}

void writePartialReasonImages(std::ostream& output, const std::map<std::string, PartialReasonImage>& images) {
    output << "[";
    bool first = true;
    for (const auto& [image, summary] : images) {
        if (!first) output << ", ";
        first = false;
        output << "{\"image\": " << jsonString(image)
               << ", \"methods\": " << summary.methods.size()
               << ", \"occurrences\": " << summary.occurrences << "}";
    }
    output << "]";
}

void writePartialReasonSummary(std::ostream& output, const RecoveryOutcome& outcome) {
    const auto summary = summarizePartialReasons(outcome);
    output << "{\"methods\": " << summary.methods.size()
           << ", \"occurrences\": " << summary.occurrences
           << ", \"images\": ";
    writePartialReasonImages(output, summary.images);
    output << ", \"categories\": [";
    bool first = true;
    for (const auto& [name, category] : summary.categories) {
        if (!first) output << ", ";
        first = false;
        output << "{\"category\": " << jsonString(name)
               << ", \"methods\": " << category.methods.size()
               << ", \"occurrences\": " << category.occurrences
               << ", \"images\": ";
        writePartialReasonImages(output, category.images);
        output << "}";
    }
    output << "]}";
}

il2cpprec::ProjectWriterOptions makeProjectWriterOptions(const Arguments& arguments) {
    il2cpprec::ProjectWriterOptions options;
    if constexpr (requires { options.includedImages = arguments.includedImages; }) {
        options.includedImages = arguments.includedImages;
    } else if (!arguments.includedImages.empty()) {
        throw std::invalid_argument("--include-images requires ProjectWriterOptions::includedImages support");
    }
    return options;
}

void writeJsonReport(
    const std::string& path,
    const RecoveryOutcome& outcome,
    const Arguments& arguments,
    const std::string& idaInstance,
    const RegistrationSummary& registration = {},
    const SourceProfileReport& sourceProfile = {}) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Cannot open JSON report: " + path);

    const auto countJson = [](const std::optional<uint64_t>& count) {
        return count ? std::to_string(*count) : "null";
    };
    output << "{\n"
           << "  \"total\": " << outcome.methods.size() << ",\n"
           << "  \"exact\": " << outcome.exact << ",\n"
           << "  \"partial\": " << outcome.partial << ",\n"
           << "  \"errors\": " << outcome.errors << ",\n"
           << "  \"methodPointerCount\": " << countJson(registration.methodPointerCount) << ",\n"
           << "  \"reversePInvokeWrapperCount\": " << countJson(registration.reversePInvokeWrapperCount) << ",\n"
           << "  \"genericMethodCount\": " << countJson(registration.genericMethodCount) << ",\n"
           << "  \"invokerCount\": " << countJson(registration.invokerCount) << ",\n"
           << "  \"codeGenModuleCount\": " << countJson(registration.codeGenModuleCount) << ",\n"
           << "  \"metadataUsageCount\": " << countJson(registration.metadataUsageCount) << ",\n"
           << "  \"registrationCountsProvenance\": " << jsonString(registration.countsProvenance) << ",\n"
           << "  \"registrationReasons\": [";
    for (size_t i = 0; i < registration.reasons.size(); ++i) {
        if (i != 0) output << ", ";
        output << jsonString(registration.reasons[i]);
    }
    output << "],\n"
           << "  \"outputPaths\": {\n"
           << "    \"binary\": " << jsonString(arguments.binaryPath) << ",\n"
           << "    \"metadata\": " << jsonString(arguments.metadataPath) << ",\n"
           << "    \"report\": " << jsonString(arguments.reportPath) << ",\n"
           << "    \"outputDirectory\": " << jsonString(arguments.outputDirectory) << "\n"
           << "  },\n"
           << "  \"idaMcpInstance\": " << jsonString(idaInstance) << ",\n"
           << "  \"sourceProfile\": {\n"
           << "    \"id\": " << jsonString(sourceProfile.id) << ",\n"
           << "    \"unityVersion\": " << jsonString(sourceProfile.unityVersion) << ",\n"
           << "    \"variant\": " << jsonString(sourceProfile.variant) << ",\n"
           << "    \"layoutHash\": " << jsonString(sourceProfile.layoutHash) << ",\n"
           << "    \"supported\": " << (sourceProfile.supported ? "true" : "false") << ",\n"
           << "    \"selectionMode\": " << jsonString(sourceProfile.selectionMode) << ",\n"
           << "    \"sourceSet\": " << jsonString(sourceProfile.sourceSet) << ",\n"
           << "    \"detectedMetadataVersion\": " << sourceProfile.detectedMetadataVersion << ",\n"
           << "    \"selectedMetadataVersion\": " << sourceProfile.selectedMetadataVersion << ",\n"
           << "    \"methodMapping\": " << jsonString(sourceProfile.methodMapping) << ",\n"
           << "    \"confidence\": " << jsonString(sourceProfile.confidence) << ",\n"
           << "    \"confidenceReason\": " << jsonString(sourceProfile.confidenceReason) << ",\n"
           << "    \"provenance\": " << jsonString(sourceProfile.provenance) << ",\n"
           << "    \"rawMetadataVersion\": " << sourceProfile.recovery.rawMetadataVersion << ",\n"
           << "    \"registrationVersion\": " << sourceProfile.recovery.registrationVersion << ",\n"
           << "    \"versionConfidence\": " << jsonString(versionConfidenceName(sourceProfile.recovery.versionConfidence)) << ",\n"
           << "    \"versionProvenance\": " << jsonString(sourceProfile.recovery.versionProvenance) << ",\n"
           << "    \"capabilities\": {\n"
           << "      \"invoker\": " << jsonString(invokerName(sourceProfile.capabilities.invoker)) << ",\n"
           << "      \"hiddenMethodInfo\": " << (sourceProfile.capabilities.hiddenMethodInfo ? "true" : "false") << ",\n"
           << "      \"virtualMethodPointer\": " << (sourceProfile.capabilities.virtualMethodPointer ? "true" : "false") << ",\n"
           << "      \"genericContexts\": " << (sourceProfile.capabilities.genericContexts ? "true" : "false") << ",\n"
           << "      \"adjustorThunks\": " << (sourceProfile.capabilities.adjustorThunks ? "true" : "false") << ",\n"
           << "      \"unresolvedReducedSignatures\": " << (sourceProfile.capabilities.unresolvedReducedSignatures ? "true" : "false") << ",\n"
           << "      \"generatedMethods\": " << (sourceProfile.capabilities.generatedMethods ? "true" : "false") << ",\n"
           << "      \"managedObjectLayout\": " << (sourceProfile.capabilities.managedObjectLayout ? "true" : "false") << "\n"
           << "    },\n"
           << "    \"unityMetadataVersion\": " << jsonString(sourceProfile.recovery.unityMetadataVersion) << ",\n"
           << "    \"binaryIdentity\": " << jsonString(sourceProfile.recovery.binaryIdentity) << ",\n"
           << "    \"codeRegistrationIdentity\": " << jsonString(sourceProfile.recovery.codeRegistrationIdentity) << ",\n"
           << "    \"methodPointersIdentity\": " << jsonString(sourceProfile.recovery.methodPointersIdentity) << ",\n"
           << "    \"lifterSemanticsVersion\": " << sourceProfile.recovery.lifterSemanticsVersion << "\n"
           << "  },\n"
           << "  \"options\": {\n"
           << "    \"workers\": " << arguments.workers << ",\n"
           << "    \"cache\": " << arguments.cacheCapacity << ",\n"
           << "    \"maxMethodSize\": " << arguments.maxMethodSize << ",\n"
           << "    \"protectedProfile\": " << (arguments.protectedProfile ? "true" : "false") << ",\n"
           << "    \"failOnPartial\": " << (arguments.failOnPartial ? "true" : "false") << ",\n"
           << "    \"verify\": " << (arguments.verify ? "true" : "false") << ",\n"
           << "    \"idaMcp\": " << (arguments.idaMcp ? "true" : "false") << ",\n"
           << "    \"idaInstance\": " << jsonString(idaInstance) << ",\n"
           << "    \"il2cppVersion\": " << jsonString(arguments.il2cppVersion) << ",\n"
           << "    \"layout\": " << jsonString(arguments.layout) << ",\n"
           << "    \"gameFilter\": " << jsonString(arguments.gameFilter) << ",\n"
           << "    \"includedImages\": [";
    for (size_t i = 0; i < arguments.includedImages.size(); ++i) {
        if (i != 0) output << ", ";
        output << jsonString(arguments.includedImages[i]);
    }
    output << "]\n"
           << "  },\n"
           << "  \"partialReasons\": ";
    writePartialReasonSummary(output, outcome);
    output << ",\n"
           << "  \"methods\": [\n";
    for (size_t i = 0; i < outcome.methods.size(); ++i) {
        const auto& method = outcome.methods[i];
        output << "    {\"index\": " << method.index
               << ", \"name\": " << jsonString(method.name)
               << ", \"image\": " << jsonString(method.imageName)
               << ", \"address\": " << jsonString(hexAddress(method.address))
               << ", \"size\": " << method.size
               << ", \"status\": " << jsonString(statusName(method.status))
               << ", \"reasons\": [";
        for (size_t j = 0; j < method.reasons.size(); ++j) {
            if (j != 0) output << ", ";
            output << jsonString(method.reasons[j]);
        }
        output << "]";
        if (method.verification) {
            const auto& audit = *method.verification;
            output << ", \"verification\": {\"status\": "
                   << jsonString(il2cpprec::toString(audit.status))
                   << ", \"decodedInstructions\": " << audit.decodedInstructions
                   << ", \"representedInstructions\": " << audit.representedInstructions
                   << ", \"unmappedInstructions\": " << audit.unmappedInstructions
                   << ", \"findings\": [";
            for (size_t j = 0; j < audit.findings.size(); ++j) {
                if (j != 0) output << ", ";
                const auto& finding = audit.findings[j];
                output << "{\"code\": " << jsonString(finding.code)
                       << ", \"address\": " << jsonString(hexAddress(finding.address))
                       << ", \"message\": " << jsonString(finding.message) << "}";
            }
            output << "]}";
        }
        output << "}" << (i + 1 == outcome.methods.size() ? "\n" : ",\n");
    }
    output << "  ]\n}\n";
    output.flush();
    if (!output) throw std::runtime_error("Cannot write JSON report: " + path);
}

std::string protectedDiagnosticText(const il2cpprec::ProtectedMetadataDiagnostic& diagnostic) {
    std::string text = diagnostic.code + ": " + diagnostic.message;
    if (diagnostic.table) text += " [table=" + std::string(il2cpprec::toString(*diagnostic.table));
    if (diagnostic.offset) text += (diagnostic.table ? ", offset=" : " [offset=") + hexAddress(*diagnostic.offset);
    if (diagnostic.size) text += (diagnostic.table || diagnostic.offset ? ", size=" : " [size=") + std::to_string(*diagnostic.size);
    if (diagnostic.table || diagnostic.offset || diagnostic.size) text += "]";
    return text;
}

int protectedMetadataFailure(
    const Arguments& arguments,
    const std::vector<il2cpprec::ProtectedMetadataDiagnostic>& diagnostics) {
    RecoveryOutcome outcome;
    if (diagnostics.empty()) {
        std::cerr << "protected metadata error: decoding failed without diagnostics\n";
        MethodReport report;
        report.name = "protected metadata";
        report.status = MethodStatus::Error;
        report.reasons.push_back("decoding failed without diagnostics");
        outcome.methods.push_back(std::move(report));
        outcome.functions.push_back(std::nullopt);
        outcome.errors = 1;
    } else {
        for (const auto& diagnostic : diagnostics) {
            const auto text = protectedDiagnosticText(diagnostic);
            std::cerr << "protected metadata error: " << text << '\n';
            MethodReport report;
            report.index = outcome.methods.size();
            report.name = "protected metadata";
            report.status = MethodStatus::Error;
            report.reasons.push_back(text);
            outcome.methods.push_back(std::move(report));
            outcome.functions.push_back(std::nullopt);
            ++outcome.errors;
        }
    }
    if (!arguments.reportPath.empty()) writeJsonReport(arguments.reportPath, outcome, arguments, {});
    printSummary(outcome, std::cerr);
    return 1;
}

bool selfContainedTypeReference(
    const il2cpprec::MetadataModel& metadata,
    int32_t index,
    std::vector<uint8_t>& state,
    size_t depth = 0) {
    if (index < 0 || static_cast<size_t>(index) >= metadata.typeReferences.size() || depth > 64) return false;
    const size_t position = static_cast<size_t>(index);
    if (state[position] == 2) return true;
    if (state[position] != 0) return false;
    state[position] = 1;

    const auto& reference = metadata.typeReferences[position];
    const auto code = static_cast<il2cpprec::Il2CppTypeCode>(reference.code);
    bool valid = false;
    if (il2cpprec::TypeSystem::primitiveType(code).has_value()) {
        valid = true;
    } else {
        switch (code) {
        case il2cpprec::Il2CppTypeCode::Var:
        case il2cpprec::Il2CppTypeCode::MVar:
            valid = !reference.name.empty();
            break;
        case il2cpprec::Il2CppTypeCode::Ptr:
        case il2cpprec::Il2CppTypeCode::ByRef:
        case il2cpprec::Il2CppTypeCode::SzArray:
        case il2cpprec::Il2CppTypeCode::CModReqD:
        case il2cpprec::Il2CppTypeCode::CModOpt:
        case il2cpprec::Il2CppTypeCode::Sentinel:
        case il2cpprec::Il2CppTypeCode::Pinned:
        case il2cpprec::Il2CppTypeCode::TypeIndex:
            valid = selfContainedTypeReference(metadata, reference.elementTypeIndex, state, depth + 1);
            break;
        case il2cpprec::Il2CppTypeCode::Array:
            valid = reference.rank <= 64 &&
                selfContainedTypeReference(metadata, reference.elementTypeIndex, state, depth + 1);
            break;
        default:
            break;
        }
    }
    state[position] = valid ? 2 : 3;
    return valid;
}

bool selfContainedTypeReferences(const il2cpprec::MetadataModel& metadata) {
    if (metadata.typeReferences.empty()) return false;
    std::vector<uint8_t> state(metadata.typeReferences.size());
    for (size_t index = 0; index < metadata.typeReferences.size(); ++index) {
        if (!selfContainedTypeReference(metadata, static_cast<int32_t>(index), state)) return false;
    }
    return true;
}

std::string mcpErrorMessage(const il2cpprec::ida::McpError& error) {
    auto message = error.message.empty() ? "unknown IDA MCP error" : error.message;
    if (error.code) message += " (code " + std::to_string(*error.code) + ")";
    return message;
}

IdaMcpSession connectIdaMcp(const Arguments& arguments) {
    IdaMcpSession session;
    if (!arguments.idaMcp) return session;

    il2cpprec::ida::McpClientConfig config;
    config.host = arguments.idaMcpHost;
    config.port = arguments.idaMcpPort;
    session.client = std::make_unique<il2cpprec::ida::McpClient>(config);
    auto instances = session.client->listInstances();
    if (!instances.ok()) {
        throw std::runtime_error(
            "IDA MCP connection to " + arguments.idaMcpHost + ":" +
            std::to_string(arguments.idaMcpPort) + " failed: " + mcpErrorMessage(instances.error));
    }

    std::sort(instances.value->begin(), instances.value->end(), [](const auto& left, const auto& right) {
        return left.id < right.id;
    });
    if (!arguments.idaMcpInstance.empty()) {
        const auto selected = std::find_if(instances.value->begin(), instances.value->end(), [&](const auto& instance) {
            return instance.id == arguments.idaMcpInstance;
        });
        if (selected == instances.value->end()) {
            throw std::runtime_error("IDA MCP instance not found: " + arguments.idaMcpInstance);
        }
        session.instanceId = selected->id;
    } else if (instances.value->size() == 1) {
        session.instanceId = instances.value->front().id;
    } else if (instances.value->empty()) {
        throw std::runtime_error("IDA MCP returned no instances");
    } else {
        throw std::invalid_argument("Multiple IDA MCP instances are available; use --idamcp-instance ID");
    }
    return session;
}

void validateArguments(const Arguments& arguments) {
    const bool moduleMetadata = arguments.inspectModules && arguments.binaryPath.empty() &&
        !arguments.inspectPath.empty() && !arguments.metadataPath.empty();
    if (arguments.binaryPath.empty() != arguments.metadataPath.empty() && !moduleMetadata) {
        throw std::invalid_argument("--binary and --metadata must be supplied together");
    }
    if (arguments.inspectModules && arguments.inspectPath.empty()) {
        throw std::invalid_argument("--modules requires --inspect BINARY");
    }
    if (!arguments.hex.empty() && !arguments.inputPath.empty()) {
        throw std::invalid_argument("--hex and --input are mutually exclusive");
    }
    if (!arguments.reportPath.empty() &&
        (!arguments.inspectPath.empty() || arguments.inspectModules) && arguments.binaryPath.empty()) {
        throw std::invalid_argument("--report is available for recovery modes, not --inspect/--modules");
    }
}

int recoveryExitCode(const RecoveryOutcome& outcome, bool failOnPartial) {
    if (outcome.errors != 0) return 1;
    if (failOnPartial && outcome.partial != 0) return 1;
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto arguments = parseArguments(argc, argv);
        if (arguments.help) {
            printHelp(std::cout);
            return 0;
        }
        validateArguments(arguments);

        if (arguments.inspectModules) {
            const auto binary = il2cpprec::loadBinary(arguments.inspectPath);
            il2cpprec::MetadataModel metadata;
            if (!arguments.metadataPath.empty()) {
                if (arguments.protectedProfile) {
                    throw std::invalid_argument("--protected-profile is not supported for --modules metadata views");
                }
                metadata = il2cpprec::GlobalMetadata().readFile(arguments.metadataPath);
            }
            il2cpprec::discoverCodeGenModules(binary, metadata);
            printModules(binary, metadata, !arguments.metadataPath.empty());
            return 0;
        }
        if (!arguments.binaryPath.empty()) {
            const auto binary = il2cpprec::loadBinary(arguments.binaryPath);
            il2cpprec::MetadataModel metadata;
            std::vector<std::string> registrationReasons;
            if (arguments.protectedProfile) {
                const auto protectedBytes = readFile(arguments.metadataPath);
                auto decoded = il2cpprec::ProtectedMetadata::researched().decode(protectedBytes);
                if (!decoded.ok()) return protectedMetadataFailure(arguments, decoded.diagnostics);

                il2cpprec::MetadataModel discovered;
                il2cpprec::discoverCodeGenModules(binary, discovered);
                if (discovered.metadataRegistrationAddress != 0) {
                    try {
                        il2cpprec::MetadataRegistrationReader{}.read(binary, discovered);
                    } catch (const std::exception& exception) {
                        const auto reason = std::string("malformed IL2CPP metadata registration: ") + exception.what();
                        registrationReasons.push_back(reason);
                        std::cerr << "warning: " << reason << '\n';
                    }
                }

                il2cpprec::ProtectedMetadataTypeResolver typeResolver;
                if (selfContainedTypeReferences(discovered)) {
                    typeResolver = [&discovered](int32_t index) -> std::optional<std::string> {
                        if (index < 0 || static_cast<size_t>(index) >= discovered.typeReferences.size()) {
                            return std::nullopt;
                        }
                        auto resolved = il2cpprec::TypeSystem::resolve(static_cast<size_t>(index), discovered);
                        if (resolved.empty()) return std::nullopt;
                        return resolved;
                    };
                }

                auto converted = decoded.toMetadataModel(typeResolver);
                if (!converted.ok()) return protectedMetadataFailure(arguments, converted.diagnostics);
                metadata = std::move(converted.metadata);
                metadata.methodPointersByImage = std::move(discovered.methodPointersByImage);
                metadata.typeReferences = std::move(discovered.typeReferences);
                metadata.genericClasses = std::move(discovered.genericClasses);
                metadata.genericInsts = std::move(discovered.genericInsts);
                metadata.genericMethodTable = std::move(discovered.genericMethodTable);
                metadata.methodSpecs = std::move(discovered.methodSpecs);
                metadata.genericMethodPointers = std::move(discovered.genericMethodPointers);
                metadata.invokerPointers = std::move(discovered.invokerPointers);
                metadata.metadataUsagesCount = discovered.metadataUsagesCount;
                metadata.metadataRegistrationAddress = discovered.metadataRegistrationAddress;
                metadata.codeRegistrationAddress = discovered.codeRegistrationAddress;
            } else {
                metadata = il2cpprec::GlobalMetadata().readFile(arguments.metadataPath);
            }
            auto sourceProfile = makeSourceProfileReport(binary, metadata, arguments);
            if (sourceProfile.selectedMetadataVersion > 0) metadata.version = sourceProfile.selectedMetadataVersion;
            il2cpprec::discoverCodeGenModules(binary, metadata);
            if (metadata.metadataRegistrationAddress != 0) {
                try {
                    il2cpprec::MetadataRegistrationReader{}.read(binary, metadata);
                } catch (const std::exception& exception) {
                    const auto reason = std::string("malformed IL2CPP metadata registration: ") + exception.what();
                    registrationReasons.push_back(reason);
                    std::cerr << "warning: " << reason << '\n';
                }
            }
            il2cpprec::MethodResolverOptions resolverOptions;
            resolverOptions.discoverModules = false;
            if (arguments.maxMethodSize != 0) resolverOptions.maxFunctionSize = 0;
            auto resolution = il2cpprec::MethodResolver(resolverOptions).resolveWithReport(metadata, binary);
            sourceProfile.recovery.codeRegistrationIdentity = sourceProfile.layoutHash + "@" +
                hexAddress(resolution.metadata.codeRegistrationAddress);
            sourceProfile.recovery.methodPointersIdentity = methodPointersIdentity(resolution.metadata);
            auto idaSession = connectIdaMcp(arguments);
            auto outcome = recoverMethods(
                std::move(resolution.functions), arguments, &idaSession, arguments.binaryPath,
                sourceProfile.recovery);
            std::map<std::pair<uint64_t, std::string>, std::string> imageByMethod;
            for (const auto& type : resolution.metadata.types) {
                for (const auto& method : type.methods) {
                    const auto name = method.declaringType.empty()
                        ? method.name
                        : method.declaringType + "__" + method.name;
                    imageByMethod.try_emplace({method.address, name}, method.imageName);
                }
            }
            for (auto& method : outcome.methods) {
                const auto image = imageByMethod.find({method.address, method.name});
                if (image != imageByMethod.end()) method.imageName = image->second;
            }
            for (const auto& unresolved : resolution.report.unresolved) {
                MethodReport report;
                report.index = outcome.methods.size();
                report.name = unresolved.declaringType.empty()
                    ? unresolved.name
                    : unresolved.declaringType + "__" + unresolved.name;
                report.imageName = unresolved.imageName;
                report.address = unresolved.pointer;
                report.status = MethodStatus::Error;
                report.reasons.push_back(unresolved.diagnostic);
                outcome.methods.push_back(std::move(report));
                outcome.functions.push_back(std::nullopt);
                ++outcome.errors;
            }
            if (!arguments.outputDirectory.empty()) {
                il2cpprec::ProjectWriter{makeProjectWriterOptions(arguments)}.write(
                    arguments.outputDirectory, resolution.metadata, outcome.exactFunctions);
            }
            if (!arguments.reportPath.empty()) {
                auto registration = makeRegistrationSummary(resolution.metadata, resolution.report);
                const bool legacy = resolution.metadata.version > 0 && resolution.metadata.version <= 24.1;
                if (sourceProfile.supported && resolution.metadata.codeRegistrationAddress != 0) {
                    const auto readCount = [&](std::optional<uint64_t>& count, const RegistrationFieldReport& field, const char* name) {
                        if (!field.present) return;
                        try {
                            count = readRegistrationTableCount(
                                binary, resolution.metadata.codeRegistrationAddress, field.countOffset);
                        } catch (const std::exception& exception) {
                            registration.reasons.push_back(
                                std::string(name) + " is unavailable: " + exception.what());
                        }
                    };
                    readCount(registration.methodPointerCount, sourceProfile.methodPointers, "methodPointerCount");
                    readCount(registration.reversePInvokeWrapperCount, sourceProfile.reversePInvokeWrappers, "reversePInvokeWrapperCount");
                    readCount(registration.genericMethodCount, sourceProfile.genericMethodPointers, "genericMethodCount");
                    readCount(registration.invokerCount, sourceProfile.invokerPointers, "invokerCount");
                    readCount(registration.codeGenModuleCount, sourceProfile.codeGenModules, "codeGenModuleCount");
                    registration.countsProvenance = "source-layout:" + sourceProfile.layoutHash;
                } else if (legacy && resolution.metadata.codeRegistrationAddress != 0) {
                    registration.genericMethodCount = readLegacyCodeRegistrationTable(
                        binary, resolution.metadata.codeRegistrationAddress, 2).methodPointers.size();
                    registration.invokerCount = readLegacyCodeRegistrationTable(
                        binary, resolution.metadata.codeRegistrationAddress, 3).methodPointers.size();
                    registration.countsProvenance = "legacy-code-registration";
                }
                if (!registration.methodPointerCount) {
                    uint64_t count = 0;
                    for (const auto& [name, pointers] : resolution.metadata.methodPointersByImage) {
                        (void)name;
                        count += pointers.size();
                    }
                    if (!resolution.metadata.methodPointersByImage.empty()) {
                        registration.methodPointerCount = count;
                        if (registration.countsProvenance.empty()) registration.countsProvenance = "resolved-image-tables";
                        else registration.countsProvenance += "+resolved-image-tables";
                    } else {
                        registration.reasons.push_back("methodPointerCount is unavailable: no registration count or resolved image pointer table");
                    }
                }
                if (resolution.metadata.codeRegistrationAddress == 0) {
                    registration.reasons.push_back("native code registration counts are unavailable: code registration address was not discovered");
                }
                if (!registration.codeGenModuleCount && sourceProfile.methodMapping == "per-image-token-row-id") {
                    registration.reasons.push_back("codeGenModuleCount is unavailable: no validated code registration count");
                }
                if (legacy && resolution.metadata.metadataRegistrationAddress == 0 &&
                    !registration.metadataUsageCount) {
                    registration.reasons.push_back(
                        "metadataUsageCount is unavailable: legacy metadata registration address was not discovered");
                }
                registration.reasons.insert(
                    registration.reasons.end(), registrationReasons.begin(), registrationReasons.end());
                std::sort(registration.reasons.begin(), registration.reasons.end());
                registration.reasons.erase(
                    std::unique(registration.reasons.begin(), registration.reasons.end()),
                    registration.reasons.end());
                writeJsonReport(
                    arguments.reportPath, outcome, arguments, idaSession.instanceId, registration, sourceProfile);
            }
            printDiagnostics(outcome, std::cout);
            printSummary(outcome, std::cout);
            if (arguments.verify) printVerificationSummary(outcome, std::cout);
            return recoveryExitCode(outcome, arguments.failOnPartial);
        }
        if (!arguments.inspectPath.empty()) {
            const auto binary = il2cpprec::loadBinary(arguments.inspectPath);
            std::cout << "format=" << static_cast<int>(binary.format)
                      << " arch=" << static_cast<int>(binary.architecture)
                      << " imageBase=0x" << std::hex << binary.imageBase << std::dec << '\n';
            for (const auto& section : binary.sections) {
                std::cout << section.name << " va=0x" << std::hex << section.virtualAddress
                          << " size=0x" << section.virtualSize
                          << " file=0x" << section.fileOffset
                          << " fileSize=0x" << section.fileSize
                          << " executable=" << section.executable << std::dec << '\n';
            }
            return 0;
        }

        const auto bytes = arguments.inputPath.empty() ? parseHex(arguments.hex) : readFile(arguments.inputPath);
        if (bytes.empty()) {
            std::cerr << "No code supplied. Use --hex or --input.\n";
            return 2;
        }

        il2cpprec::FunctionImage image;
        image.architecture = arguments.architecture;
        image.address = arguments.address;
        image.code = bytes.data();
        image.size = bytes.size();
        image.name = arguments.name;

        auto idaSession = connectIdaMcp(arguments);
        auto outcome = recoverMethods({image}, arguments);
        if (!arguments.outputDirectory.empty()) {
            il2cpprec::ProjectWriter{makeProjectWriterOptions(arguments)}.write(
                arguments.outputDirectory,
                il2cpprec::MetadataModel{},
                outcome.exactFunctions);
        }
        if (!arguments.reportPath.empty()) {
            writeJsonReport(arguments.reportPath, outcome, arguments, idaSession.instanceId);
        }
        printDiagnostics(outcome, std::cerr);
        printSummary(outcome, std::cerr);
        if (arguments.verify) printVerificationSummary(outcome, std::cerr);

        if (outcome.functions.size() == 1 && outcome.functions.front() && arguments.outputDirectory.empty()) {
            std::cout << outcome.functions.front()->toCSharp();
        }
        return recoveryExitCode(outcome, arguments.failOnPartial);
    } catch (const std::exception& exception) {
        std::cerr << "error: " << exception.what() << '\n';
        return 1;
    }
}
