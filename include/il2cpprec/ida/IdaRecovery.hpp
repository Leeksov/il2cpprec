#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <il2cpprec/Recovery.hpp>
#include <il2cpprec/ida/McpClient.hpp>

namespace il2cpprec::ida {

struct IdaBinaryIdentity {
    std::string binaryPath;
    std::string sha256;
    std::string md5;
};

struct IdaRecoveryOptions {
    std::string name;
    std::size_t maxBlocks = 10000;
    std::size_t calleeLimit = 200;
    bool fetchPseudocode = true;
    bool buildControlFlowFunction = true;
};

struct IdaFallbackArtifact {
    std::string binaryPath;
    std::uint64_t requestedAddress = 0;
    std::optional<McpInstance> instance;
    std::optional<McpFunctionBounds> bounds;
    McpBasicBlocksResult controlFlow;
    McpCalleesResult callees;
    std::optional<McpDecompilation> pseudocode;
    std::vector<McpError> warnings;
    std::string reason;
};

enum class IdaRecoveryStatus {
    NativeFunction,
    ControlFlowOnly,
    FallbackArtifact,
    Error
};

struct IdaRecoveryResult {
    IdaRecoveryStatus status = IdaRecoveryStatus::Error;
    std::optional<RecoveredFunction> function;
    IdaFallbackArtifact artifact;
    McpError error;

    bool hasFunction() const noexcept {
        return function.has_value();
    }

    bool hasNativeFunction() const noexcept {
        return status == IdaRecoveryStatus::NativeFunction && function.has_value();
    }
};

class IdaRecovery {
public:
    explicit IdaRecovery(McpClient& client) noexcept;

    McpResult<McpInstance> selectInstance(const IdaBinaryIdentity& binary);

    IdaRecoveryResult recover(
        const IdaBinaryIdentity& binary,
        const FunctionImage& image,
        const IdaRecoveryOptions& options = {});

    IdaRecoveryResult recover(
        const IdaBinaryIdentity& binary,
        std::uint64_t address,
        Architecture architecture,
        const IdaRecoveryOptions& options = {});

private:
    McpClient& client_;
};

} // namespace il2cpprec::ida
