#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace il2cpprec::ida {

struct ManagedMethodName {
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::string fullName;
    std::string idaName;
};

struct IdaFunctionName {
    bool found = false;
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::string name;
};

struct IdaNameImportStatus {
    bool ok = false;
    std::string error;

    explicit operator bool() const noexcept {
        return ok;
    }
};

template <typename T>
struct IdaNameImportResult {
    std::optional<T> value;
    std::string error;

    bool ok() const noexcept {
        return value.has_value() && error.empty();
    }

    explicit operator bool() const noexcept {
        return ok();
    }
};

class IdaNameImportMcp {
public:
    virtual ~IdaNameImportMcp() = default;

    virtual IdaNameImportResult<std::vector<IdaFunctionName>> lookupFunctions(
        const std::vector<std::uint64_t>& addresses) = 0;
    virtual IdaNameImportResult<std::vector<std::uint8_t>> readBytes(
        std::uint64_t address,
        std::size_t size) = 0;
    virtual IdaNameImportStatus defineCode(std::uint64_t address) = 0;
    virtual IdaNameImportStatus defineFunction(std::uint64_t start, std::uint64_t end) = 0;
    virtual IdaNameImportStatus renameFunctions(
        const std::vector<std::pair<std::uint64_t, std::string>>& names) = 0;
    virtual IdaNameImportStatus setComments(
        const std::vector<std::pair<std::uint64_t, std::string>>& comments) = 0;
    virtual IdaNameImportStatus saveIdb() = 0;
};

struct IdaNameImportOptions {
    std::size_t batchSize = 128;
    bool createMissing = true;
    bool verifyBeforeSave = true;
    bool save = true;
};

struct IdaNameImportIssue {
    enum class Kind {
        Missing,
        Conflict,
        Failure
    };

    Kind kind = Kind::Failure;
    std::uint64_t address = 0;
    std::string message;
};

struct IdaNameImportReport {
    std::size_t total = 0;
    std::size_t existing = 0;
    std::size_t created = 0;
    std::size_t renamed = 0;
    std::size_t alreadyNamed = 0;
    std::size_t missing = 0;
    std::size_t conflicts = 0;
    std::size_t failed = 0;
    std::size_t comments = 0;
    std::size_t verified = 0;
    bool saved = false;
    std::vector<IdaNameImportIssue> issues;
};

std::string safeIdaName(std::string_view managedName, std::size_t maximumLength = 240);
std::vector<ManagedMethodName> parseIl2CppDumperReport(std::string_view json);

class IdaNameImport {
public:
    explicit IdaNameImport(IdaNameImportMcp& mcp, IdaNameImportOptions options = {}) noexcept;

    IdaNameImportReport apply(const std::vector<ManagedMethodName>& methods) const;

private:
    IdaNameImportMcp& mcp_;
    IdaNameImportOptions options_;
};

} // namespace il2cpprec::ida
