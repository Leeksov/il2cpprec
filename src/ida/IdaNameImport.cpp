#include <il2cpprec/ida/IdaNameImport.hpp>

#include <algorithm>
#include <charconv>
#include <iomanip>
#include <limits>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace il2cpprec::ida {
namespace {

std::string hexAddress(std::uint64_t address) {
    std::ostringstream output;
    output << "0x" << std::hex << address;
    return output.str();
}

void appendUtf8(std::string& output, std::uint32_t codePoint) {
    if (codePoint <= 0x7f) {
        output.push_back(static_cast<char>(codePoint));
    } else if (codePoint <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (codePoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    } else if (codePoint <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (codePoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    } else {
        output.push_back(static_cast<char>(0xf0 | (codePoint >> 18)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    }
}

int hexDigit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool parseHex4(std::string_view input, std::size_t position, std::uint32_t& value) {
    if (position + 4 > input.size()) return false;
    value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        const int digit = hexDigit(input[position + index]);
        if (digit < 0) return false;
        value = (value << 4) | static_cast<std::uint32_t>(digit);
    }
    return true;
}

std::string jsonString(std::string_view input) {
    std::string output;
    output.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        const char value = input[index];
        if (value != '\\') {
            output.push_back(value);
            continue;
        }
        if (++index >= input.size()) break;
        switch (input[index]) {
        case '"': output.push_back('"'); break;
        case '\\': output.push_back('\\'); break;
        case '/': output.push_back('/'); break;
        case 'b': output.push_back('\b'); break;
        case 'f': output.push_back('\f'); break;
        case 'n': output.push_back('\n'); break;
        case 'r': output.push_back('\r'); break;
        case 't': output.push_back('\t'); break;
        case 'u': {
            std::uint32_t codePoint = 0;
            if (!parseHex4(input, index + 1, codePoint)) return output;
            index += 4;
            if (codePoint >= 0xd800 && codePoint <= 0xdbff && index + 6 < input.size() &&
                input[index + 1] == '\\' && input[index + 2] == 'u') {
                std::uint32_t low = 0;
                if (parseHex4(input, index + 3, low) && low >= 0xdc00 && low <= 0xdfff) {
                    codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00);
                    index += 6;
                }
            }
            appendUtf8(output, codePoint);
            break;
        }
        default: output.push_back(input[index]); break;
        }
    }
    return output;
}

std::uint64_t unsignedValue(std::string_view input) {
    std::uint64_t value = 0;
    int base = 10;
    if (input.size() > 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        input.remove_prefix(2);
        base = 16;
    }
    const auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), value, base);
    return error == std::errc{} && end == input.data() + input.size() ? value : 0;
}

std::uint64_t fnv1a(std::string_view input) {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const unsigned char byte : input) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

void issue(
    IdaNameImportReport& report,
    IdaNameImportIssue::Kind kind,
    std::uint64_t address,
    std::string message) {
    if (kind == IdaNameImportIssue::Kind::Missing) ++report.missing;
    if (kind == IdaNameImportIssue::Kind::Conflict) ++report.conflicts;
    if (kind == IdaNameImportIssue::Kind::Failure) ++report.failed;
    report.issues.push_back({kind, address, std::move(message)});
}

} // namespace

std::string safeIdaName(std::string_view managedName, std::size_t maximumLength) {
    maximumLength = std::max<std::size_t>(maximumLength, 32);
    std::string result = "il2cpp_";
    bool underscore = false;
    for (const unsigned char value : managedName) {
        const bool alphaNumeric = (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9');
        if (alphaNumeric || value == '_') {
            result.push_back(static_cast<char>(value));
            underscore = false;
        } else if (!underscore && !result.empty() && result.back() != '_') {
            result.push_back('_');
            underscore = true;
        }
    }
    while (!result.empty() && result.back() == '_') result.pop_back();
    if (result == "il2cpp") result = "il2cpp_method";
    if (result.size() <= maximumLength) return result;

    std::ostringstream suffix;
    suffix << '_' << std::hex << std::setfill('0') << std::setw(8)
           << static_cast<std::uint32_t>(fnv1a(managedName) & 0xffffffffULL);
    result.resize(maximumLength - suffix.str().size());
    if (!result.empty() && result.back() == '_') result.pop_back();
    result += suffix.str();
    return result;
}

std::vector<ManagedMethodName> parseIl2CppDumperReport(std::string_view json) {
    static const std::regex pattern(
        R"re("name"\s*:\s*"((?:\\.|[^"\\])*)"\s*,\s*"address"\s*:\s*"(0x[0-9A-Fa-f]+)"(?:\s*,\s*"size"\s*:\s*([0-9]+))?)re",
        std::regex::optimize);
    std::vector<ManagedMethodName> methods;
    const auto begin = std::regex_iterator<std::string_view::const_iterator>(json.begin(), json.end(), pattern);
    const auto end = std::regex_iterator<std::string_view::const_iterator>();
    for (auto match = begin; match != end; ++match) {
        ManagedMethodName method;
        method.fullName = jsonString(match->str(1));
        method.address = unsignedValue(match->str(2));
        method.size = match->length(3) == 0 ? 0 : unsignedValue(match->str(3));
        method.idaName = safeIdaName(method.fullName);
        if (method.address != 0 && !method.fullName.empty()) methods.push_back(std::move(method));
    }
    return methods;
}

IdaNameImport::IdaNameImport(IdaNameImportMcp& mcp, IdaNameImportOptions options) noexcept
    : mcp_(mcp), options_(options) {
    if (options_.batchSize == 0) options_.batchSize = 128;
}

IdaNameImportReport IdaNameImport::apply(const std::vector<ManagedMethodName>& methods) const {
    IdaNameImportReport report;
    report.total = methods.size();
    std::unordered_map<std::string, std::uint64_t> usedNames;
    std::unordered_set<std::uint64_t> seenAddresses;
    std::vector<std::pair<std::uint64_t, std::string>> renamed;

    for (std::size_t batchBegin = 0; batchBegin < methods.size(); batchBegin += options_.batchSize) {
        const std::size_t batchEnd = std::min(methods.size(), batchBegin + options_.batchSize);
        std::vector<std::uint64_t> addresses;
        std::vector<const ManagedMethodName*> current;
        addresses.reserve(batchEnd - batchBegin);
        current.reserve(batchEnd - batchBegin);
        for (std::size_t index = batchBegin; index < batchEnd; ++index) {
            const auto& method = methods[index];
            if (method.address == 0 || method.fullName.empty()) {
                issue(report, IdaNameImportIssue::Kind::Conflict, method.address, "mapping entry has no native address or managed name");
                continue;
            }
            if (!seenAddresses.insert(method.address).second) {
                issue(report, IdaNameImportIssue::Kind::Conflict, method.address, "duplicate mapping address");
                continue;
            }
            addresses.push_back(method.address);
            current.push_back(&method);
        }
        if (addresses.empty()) continue;

        auto lookup = mcp_.lookupFunctions(addresses);
        if (!lookup) {
            for (const auto* method : current) {
                issue(report, IdaNameImportIssue::Kind::Failure, method->address, lookup.error);
            }
            continue;
        }
        if (lookup.value->size() != current.size()) {
            for (const auto* method : current) {
                issue(report, IdaNameImportIssue::Kind::Failure, method->address, "lookup_funcs returned an incomplete batch");
            }
            continue;
        }

        std::vector<std::pair<std::uint64_t, std::string>> names;
        std::vector<std::pair<std::uint64_t, std::string>> comments;
        for (std::size_t index = 0; index < current.size(); ++index) {
            const auto& method = *current[index];
            const auto& function = (*lookup.value)[index];
            if (function.found) {
                if (function.start != method.address) {
                    issue(report, IdaNameImportIssue::Kind::Conflict, method.address,
                        "native address belongs to function at " + hexAddress(function.start));
                    continue;
                }
                ++report.existing;
            } else {
                if (!options_.createMissing) {
                    issue(report, IdaNameImportIssue::Kind::Missing, method.address, "function is absent");
                    continue;
                }
                auto bytes = mcp_.readBytes(method.address, 16);
                if (!bytes || bytes.value->empty() ||
                    std::all_of(bytes.value->begin(), bytes.value->end(), [](std::uint8_t value) { return value == 0; })) {
                    issue(report, IdaNameImportIssue::Kind::Missing, method.address,
                        bytes ? "native address has no confirmed instruction bytes" : bytes.error);
                    continue;
                }
                const auto code = mcp_.defineCode(method.address);
                if (!code) {
                    issue(report, IdaNameImportIssue::Kind::Failure, method.address, code.error);
                    continue;
                }
                std::uint64_t end = 0;
                if (method.size != 0 && method.address <= std::numeric_limits<std::uint64_t>::max() - method.size) {
                    end = method.address + method.size;
                }
                const auto created = mcp_.defineFunction(method.address, end);
                if (!created) {
                    issue(report, IdaNameImportIssue::Kind::Failure, method.address, created.error);
                    continue;
                }
                ++report.created;
            }

            std::string idaName = method.idaName.empty() ? safeIdaName(method.fullName) : method.idaName;
            const auto used = usedNames.find(idaName);
            if (used != usedNames.end() && used->second != method.address) {
                idaName = safeIdaName(method.fullName + "_" + hexAddress(method.address));
            }
            usedNames[idaName] = method.address;
            if (function.found && function.name == idaName) {
                ++report.alreadyNamed;
            } else {
                names.emplace_back(method.address, idaName);
            }
            comments.emplace_back(method.address, "IL2CPP: " + method.fullName);
        }

        if (!names.empty()) {
            const auto renamedBatch = mcp_.renameFunctions(names);
            if (!renamedBatch) {
                for (const auto& [address, name] : names) {
                    issue(report, IdaNameImportIssue::Kind::Conflict, address,
                        "cannot rename to " + name + ": " + renamedBatch.error);
                }
                names.clear();
            } else {
                report.renamed += names.size();
                renamed.insert(renamed.end(), names.begin(), names.end());
            }
        }
        if (!comments.empty()) {
            const auto commentBatch = mcp_.setComments(comments);
            if (!commentBatch) {
                for (const auto& [address, text] : comments) {
                    (void)text;
                    issue(report, IdaNameImportIssue::Kind::Failure, address, commentBatch.error);
                }
            } else {
                report.comments += comments.size();
            }
        }
    }

    if (options_.verifyBeforeSave) {
        for (std::size_t begin = 0; begin < renamed.size(); begin += options_.batchSize) {
            const std::size_t end = std::min(renamed.size(), begin + options_.batchSize);
            std::vector<std::uint64_t> addresses;
            addresses.reserve(end - begin);
            for (std::size_t index = begin; index < end; ++index) addresses.push_back(renamed[index].first);
            auto lookup = mcp_.lookupFunctions(addresses);
            if (!lookup || lookup.value->size() != addresses.size()) {
                for (std::size_t index = begin; index < end; ++index) {
                    issue(report, IdaNameImportIssue::Kind::Failure, renamed[index].first,
                        lookup ? "verification returned an incomplete batch" : lookup.error);
                }
                continue;
            }
            for (std::size_t index = begin; index < end; ++index) {
                const auto& function = (*lookup.value)[index - begin];
                if (!function.found || function.start != renamed[index].first || function.name != renamed[index].second) {
                    issue(report, IdaNameImportIssue::Kind::Conflict, renamed[index].first,
                        "post-rename verification failed");
                } else {
                    ++report.verified;
                }
            }
        }
    }

    const bool verificationComplete = !options_.verifyBeforeSave || report.verified == report.renamed;
    if (options_.save && report.failed == 0 && verificationComplete) {
        const auto saved = mcp_.saveIdb();
        if (saved) {
            report.saved = true;
        } else {
            issue(report, IdaNameImportIssue::Kind::Failure, 0, saved.error);
        }
    }
    return report;
}

} // namespace il2cpprec::ida
