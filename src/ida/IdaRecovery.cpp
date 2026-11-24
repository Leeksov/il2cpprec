#include <il2cpprec/ida/IdaRecovery.hpp>

#include <algorithm>
#include <cctype>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_set>
#include <utility>

namespace il2cpprec::ida {
namespace {

template <typename T>
McpResult<T> success(T value) {
    return McpResult<T>{std::move(value), {}};
}

template <typename T>
McpResult<T> failure(McpError error) {
    return McpResult<T>{std::nullopt, std::move(error)};
}

McpError recoveryError(std::string message, std::string rawJson = {}) {
    McpError error;
    error.kind = McpErrorKind::Analysis;
    error.message = std::move(message);
    error.rawJson = std::move(rawJson);
    return error;
}

std::string addressText(std::uint64_t address) {
    std::ostringstream output;
    output << "0x" << std::hex << address;
    return output.str();
}

std::string normalizedHash(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }).base();
    if (first >= last) return {};
    value = std::string(first, last);
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool validHash(const std::string& value, std::size_t digits) {
    return value.size() == digits && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

std::string normalizedPath(const std::string& value) {
    if (value.empty()) return {};
    std::filesystem::path path(value);
    std::error_code error;
    if (path.is_absolute()) {
        auto canonical = std::filesystem::weakly_canonical(path, error);
        if (!error) path = std::move(canonical);
    }
    return path.lexically_normal().string();
}

bool samePath(const std::string& left, const std::string& right) {
    return !left.empty() && !right.empty() &&
        (left == right || normalizedPath(left) == normalizedPath(right));
}

bool fingerprintMatches(
    const McpBinaryFingerprint& fingerprint,
    const std::string& sha256,
    const std::string& md5) {
    if (!sha256.empty() && normalizedHash(fingerprint.sha256) != sha256) return false;
    if (!md5.empty() && normalizedHash(fingerprint.md5) != md5) return false;
    return true;
}

std::uint16_t pointerBits(Architecture architecture) {
    return architecture == Architecture::Arm64 || architecture == Architecture::X64 ? 64 : 32;
}

RecoveredFunction controlFlowFunction(
    const McpBasicBlocksResult& controlFlow,
    const McpFunctionBounds& bounds,
    Architecture architecture,
    const std::string& name) {
    std::vector<const McpBasicBlock*> source;
    source.reserve(controlFlow.blocks.size());
    for (const McpBasicBlock& block : controlFlow.blocks) {
        if (!block.start || *block.start < bounds.start || *block.start >= bounds.end) continue;
        source.push_back(&block);
    }
    std::sort(source.begin(), source.end(), [](const McpBasicBlock* left, const McpBasicBlock* right) {
        return *left->start < *right->start;
    });
    source.erase(std::unique(source.begin(), source.end(), [](const McpBasicBlock* left, const McpBasicBlock* right) {
        return *left->start == *right->start;
    }), source.end());

    std::unordered_set<std::uint64_t> addresses;
    for (const McpBasicBlock* block : source) addresses.insert(*block->start);

    RecoveredFunction function;
    function.architecture = architecture;
    function.address = bounds.start;
    function.name = name;
    function.blocks.reserve(source.size());
    const ScalarType pointer = ScalarType::pointer(pointerBits(architecture));
    for (const McpBasicBlock* block : source) {
        BasicBlock output;
        output.address = *block->start;
        std::vector<std::uint64_t> successors;
        for (const std::uint64_t successor : block->successors) {
            if (addresses.contains(successor) &&
                std::find(successors.begin(), successors.end(), successor) == successors.end()) {
                successors.push_back(successor);
            }
        }
        for (std::size_t i = 0; i < successors.size(); ++i) {
            Statement branch;
            branch.address = output.address;
            branch.kind = i + 1 == successors.size()
                ? Statement::Kind::Branch
                : Statement::Kind::ConditionalBranch;
            if (branch.kind == Statement::Kind::ConditionalBranch) {
                branch.condition = unknown(ScalarType::boolean());
            }
            branch.target = constant(successors[i], pointer);
            output.statements.push_back(std::move(branch));
        }
        function.blocks.push_back(std::move(output));
    }
    return function;
}

} // namespace

IdaRecovery::IdaRecovery(McpClient& client) noexcept : client_(client) {}

McpResult<McpInstance> IdaRecovery::selectInstance(const IdaBinaryIdentity& binary) {
    const std::string sha256 = normalizedHash(binary.sha256);
    const std::string md5 = normalizedHash(binary.md5);
    if ((!binary.sha256.empty() && !validHash(sha256, 64)) ||
        (!binary.md5.empty() && !validHash(md5, 32))) {
        return failure<McpInstance>(recoveryError("Binary identity contains an invalid SHA-256 or MD5 hash"));
    }
    if (binary.binaryPath.empty() && sha256.empty() && md5.empty()) {
        return failure<McpInstance>(recoveryError("Binary identity requires an exact path, SHA-256, or MD5"));
    }

    auto listed = client_.listInstances();
    if (!listed) return failure<McpInstance>(std::move(listed.error));

    std::vector<McpInstance> candidates;
    for (const McpInstance& instance : *listed.value) {
        if (instance.id.empty()) continue;
        if (!binary.binaryPath.empty()) {
            if (samePath(binary.binaryPath, instance.binaryPath)) candidates.push_back(instance);
        } else {
            candidates.push_back(instance);
        }
    }
    if (candidates.empty()) {
        return failure<McpInstance>(recoveryError(
            binary.binaryPath.empty()
                ? "No IDA instance matches the requested binary hash"
                : "No IDA instance has the exact requested binary path"));
    }
    if (sha256.empty() && md5.empty()) {
        if (candidates.size() == 1) return success(std::move(candidates.front()));
        return failure<McpInstance>(recoveryError(
            "Multiple IDA instances have the exact binary path; provide SHA-256 or MD5"));
    }

    std::vector<McpInstance> matches;
    std::optional<McpError> fingerprintError;
    for (const McpInstance& candidate : candidates) {
        auto fingerprint = client_.binaryFingerprint(candidate.id);
        if (!fingerprint) {
            if (!fingerprintError) fingerprintError = std::move(fingerprint.error);
            continue;
        }
        if (fingerprintMatches(*fingerprint.value, sha256, md5)) {
            matches.push_back(candidate);
        }
    }
    if (matches.size() == 1) return success(std::move(matches.front()));
    if (matches.empty() && fingerprintError) {
        return failure<McpInstance>(std::move(*fingerprintError));
    }
    if (matches.empty()) {
        return failure<McpInstance>(recoveryError("No IDA instance matches the requested binary path and hash"));
    }
    return failure<McpInstance>(recoveryError("Multiple IDA instances match the requested binary identity"));
}

IdaRecoveryResult IdaRecovery::recover(
    const IdaBinaryIdentity& binary,
    std::uint64_t address,
    Architecture architecture,
    const IdaRecoveryOptions& options) {
    FunctionImage image;
    image.address = address;
    image.architecture = architecture;
    return recover(binary, image, options);
}

IdaRecoveryResult IdaRecovery::recover(
    const IdaBinaryIdentity& binary,
    const FunctionImage& image,
    const IdaRecoveryOptions& options) {
    IdaRecoveryResult result;
    result.artifact.binaryPath = binary.binaryPath;
    result.artifact.requestedAddress = image.address;

    auto selected = selectInstance(binary);
    if (!selected) {
        result.error = std::move(selected.error);
        result.artifact.reason = "IDA instance selection failed";
        return result;
    }
    result.artifact.instance = *selected.value;
    const std::string requested = addressText(image.address);

    auto bounds = client_.functionBounds(selected.value->id, requested);
    if (!bounds) {
        result.error = std::move(bounds.error);
        result.artifact.reason = "IDA function bounds are unavailable";
        return result;
    }
    result.artifact.bounds = *bounds.value;

    auto blocks = client_.basicBlocks(
        selected.value->id,
        {requested},
        std::max<std::size_t>(1, options.maxBlocks));
    if (blocks) {
        result.artifact.controlFlow = std::move(*blocks.value);
        if (!result.artifact.controlFlow.complete) {
            result.artifact.warnings.push_back(recoveryError(
                "IDA CFG is truncated at the configured block limit",
                result.artifact.controlFlow.rawJson));
        }
    } else {
        result.artifact.controlFlow.complete = false;
        result.artifact.warnings.push_back(std::move(blocks.error));
    }

    auto callees = client_.callees(selected.value->id, {requested}, options.calleeLimit);
    if (callees) {
        result.artifact.callees = std::move(*callees.value);
    } else {
        result.artifact.warnings.push_back(std::move(callees.error));
    }

    if (options.fetchPseudocode) {
        auto pseudocode = client_.decompile(selected.value->id, requested);
        if (pseudocode) {
            result.artifact.pseudocode = std::move(*pseudocode.value);
        } else {
            result.artifact.warnings.push_back(std::move(pseudocode.error));
        }
    }

    const std::string name = !options.name.empty()
        ? options.name
        : (!image.name.empty() ? image.name : bounds.value->name);
    if (image.code && image.size > 0) {
        if (bounds.value->start >= image.address) {
            const std::uint64_t delta = bounds.value->start - image.address;
            if (delta <= image.size && bounds.value->size() <= image.size - static_cast<std::size_t>(delta) &&
                bounds.value->size() <= std::numeric_limits<std::size_t>::max()) {
                FunctionImage bounded = image;
                bounded.address = bounds.value->start;
                bounded.code = image.code + static_cast<std::size_t>(delta);
                bounded.size = static_cast<std::size_t>(bounds.value->size());
                bounded.name = name;
                try {
                    RecoveredFunction function = Recovery{}.recover(bounded);
                    if (!function.blocks.empty()) {
                        result.function = std::move(function);
                        result.status = IdaRecoveryStatus::NativeFunction;
                        return result;
                    }
                    result.artifact.warnings.push_back(recoveryError(
                        "Native recovery produced no blocks inside IDA function bounds"));
                } catch (const std::exception& exception) {
                    result.artifact.warnings.push_back(recoveryError(
                        std::string("Native recovery failed: ") + exception.what()));
                } catch (...) {
                    result.artifact.warnings.push_back(recoveryError("Native recovery failed with an unknown error"));
                }
            } else {
                result.artifact.warnings.push_back(recoveryError(
                    "Native image does not cover the complete IDA function bounds"));
            }
        } else {
            result.artifact.warnings.push_back(recoveryError(
                "IDA function starts before the supplied native image"));
        }
    }

    if (options.buildControlFlowFunction) {
        RecoveredFunction function = controlFlowFunction(
            result.artifact.controlFlow,
            *bounds.value,
            image.architecture,
            name);
        if (!function.blocks.empty()) {
            result.function = std::move(function);
            result.status = IdaRecoveryStatus::ControlFlowOnly;
            result.artifact.reason =
                "Only IDA control-flow topology is present; native semantics and C# recovery are not guaranteed";
            return result;
        }
    }

    result.status = IdaRecoveryStatus::FallbackArtifact;
    result.artifact.reason = "No native function could be produced; raw IDA data is preserved in the fallback artifact";
    return result;
}

} // namespace il2cpprec::ida
