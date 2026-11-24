#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace il2cpprec::ida {

enum class McpErrorKind {
    None,
    Transport,
    Protocol,
    Analysis
};

struct McpError {
    McpErrorKind kind = McpErrorKind::None;
    std::string message;
    std::optional<int> code;
    std::string rawJson;

    bool isTransportError() const noexcept;
    bool isAnalysisError() const noexcept;
    explicit operator bool() const noexcept;
};

template <typename T>
struct McpResult {
    std::optional<T> value;
    McpError error;

    bool ok() const noexcept {
        return value.has_value() && error.kind == McpErrorKind::None;
    }

    explicit operator bool() const noexcept {
        return ok();
    }
};

struct McpInstance {
    std::string id;
    std::string type;
    std::string binaryName;
    std::string binaryPath;
    std::string architecture;
    std::string host;
    std::optional<uint16_t> port;
    std::optional<int64_t> pid;
    std::string rawJson;
};

struct McpBinaryFingerprint {
    std::string sha256;
    std::string md5;
    std::optional<std::size_t> functionCount;
    std::string architecture;
    std::string rawJson;
};

struct McpFunctionBounds {
    std::string query;
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::string name;
    std::string rawJson;

    bool valid() const noexcept {
        return end > start;
    }

    std::uint64_t size() const noexcept {
        return valid() ? end - start : 0;
    }
};

struct McpDecompilation {
    std::string code;
    std::string rawJson;
};

struct McpBasicBlock {
    std::string functionAddress;
    std::optional<uint64_t> start;
    std::optional<uint64_t> end;
    std::vector<uint64_t> successors;
    std::string rawJson;
};

struct McpBasicBlocksResult {
    std::vector<McpBasicBlock> blocks;
    std::optional<std::size_t> totalBlocks;
    bool complete = true;
    std::string rawJson;
};

struct McpCallee {
    std::string functionAddress;
    std::optional<uint64_t> address;
    std::string name;
    std::string rawJson;
};

struct McpCalleesResult {
    std::vector<McpCallee> callees;
    std::string rawJson;
};

struct McpClientConfig {
    std::string host = "127.0.0.1";
    uint16_t port = 13337;
    std::string endpointPath = "/mcp";
    std::chrono::milliseconds timeout = std::chrono::milliseconds(10000);
    std::chrono::milliseconds transportRetryDelay = std::chrono::milliseconds(100);
    std::chrono::milliseconds cacheTtl = std::chrono::milliseconds(30000);
    std::size_t maxResponseBytes = 16 * 1024 * 1024;
    std::size_t maxTransportRetries = 1;
    std::size_t cacheCapacity = 128;
    bool autoInitialize = true;
    bool directInstance = false;
};

class McpClient {
public:
    explicit McpClient(McpClientConfig config = {});
    ~McpClient();

    McpClient(McpClient&&) noexcept;
    McpClient& operator=(McpClient&&) noexcept;
    McpClient(const McpClient&) = delete;
    McpClient& operator=(const McpClient&) = delete;

    McpResult<std::vector<McpInstance>> listInstances();

    McpResult<McpBinaryFingerprint> binaryFingerprint(const std::string& instanceId);

    McpResult<McpFunctionBounds> functionBounds(
        const std::string& instanceId,
        const std::string& addressOrName);

    McpResult<McpDecompilation> decompile(
        const std::string& instanceId,
        const std::string& address);

    McpResult<McpBasicBlocksResult> basicBlocks(
        const std::string& instanceId,
        const std::vector<std::string>& addresses,
        std::size_t maxBlocks = 1000,
        std::size_t offset = 0);

    McpResult<McpCalleesResult> callees(
        const std::string& instanceId,
        const std::vector<std::string>& addresses,
        std::size_t limit = 200);

    void clearCache();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace il2cpprec::ida
