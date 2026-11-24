#include <il2cpprec/flow/ExceptionRegions.hpp>

#include <algorithm>
#include <cctype>
#include <limits>
#include <optional>
#include <set>
#include <string_view>
#include <tuple>
#include <utility>

namespace il2cpprec::flow {
namespace {

enum class EventKind {
    TryStart,
    TryEnd,
    Leave,
    EndFinally,
    Cleanup,
    JumpTable,
    Rethrow,
    Finally,
    Catch
};

struct Event {
    EventKind kind = EventKind::Leave;
    uint64_t address = 0;
    std::optional<uint64_t> first;
    std::optional<uint64_t> second;
    std::string label;
    std::string catchType;
};

struct RegionEvidence {
    ExceptionRegionKind kind = ExceptionRegionKind::Finally;
    std::optional<uint64_t> tryBegin;
    std::optional<uint64_t> tryEnd;
    std::optional<uint64_t> handlerBegin;
    std::optional<uint64_t> handlerEnd;
    std::optional<uint64_t> leaveTarget;
    std::optional<uint64_t> leaveDestination;
    std::string catchType;
    bool rethrow = false;
    bool partial = false;
};

struct Builder {
    RegionEvidence info;
    std::string handlerLabel;
    bool sawEndFinally = false;
    bool fromModel = false;
    bool requireLeaveDestination = false;
};

std::string normalized(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const unsigned char c : value) {
        if (std::isalnum(c)) result.push_back(static_cast<char>(std::tolower(c)));
    }
    return result;
}

std::string upper(std::string_view value) {
    std::string result(value);
    for (char& c : result) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return result;
}

std::string_view trim(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.remove_prefix(1);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.remove_suffix(1);
    return value;
}

std::optional<EventKind> macroKind(std::string_view name) {
    const auto value = normalized(name);
    const auto matches = [&](std::string_view suffix) {
        return value.size() >= suffix.size() && value.ends_with(suffix);
    };
    if (matches("il2cppleave")) return EventKind::Leave;
    if (matches("il2cppendfinally")) return EventKind::EndFinally;
    if (matches("il2cppcleanup")) return EventKind::Cleanup;
    if (matches("il2cppjumptbl")) return EventKind::JumpTable;
    if (matches("il2cpprethrow") || matches("il2cpprethrowifunhandled")) return EventKind::Rethrow;
    return std::nullopt;
}

ExpressionPtr stripCasts(ExpressionPtr expression) {
    while (expression && expression->kind == Expression::Kind::Cast && expression->arguments.size() == 1) {
        expression = expression->arguments.front();
    }
    return expression;
}

std::optional<uint64_t> constant(const ExpressionPtr& expression) {
    const auto value = stripCasts(expression);
    if (!value || value->kind != Expression::Kind::Constant) return std::nullopt;
    return value->constant;
}

std::string registerName(const ExpressionPtr& expression) {
    const auto value = stripCasts(expression);
    return value && value->kind == Expression::Kind::Register ? value->name : std::string{};
}

std::optional<uint64_t> hexadecimalSuffix(std::string_view value, std::string_view prefix) {
    const auto text = upper(trim(value));
    if (!text.starts_with(prefix) || text.size() == prefix.size()) return std::nullopt;
    uint64_t result = 0;
    for (size_t i = prefix.size(); i < text.size(); ++i) {
        const char c = text[i];
        unsigned digit = 0;
        if (c >= '0' && c <= '9') digit = static_cast<unsigned>(c - '0');
        else if (c >= 'A' && c <= 'F') digit = static_cast<unsigned>(c - 'A' + 10);
        else return std::nullopt;
        if (result > (std::numeric_limits<uint64_t>::max() - digit) / 16) return std::nullopt;
        result = result * 16 + digit;
    }
    return result;
}

std::optional<uint64_t> parseValue(std::string_view input) {
    auto text = trim(input);
    if (text.empty()) return std::nullopt;
    if (const auto il = hexadecimalSuffix(text, "IL_")) return il;
    if (const auto finally = hexadecimalSuffix(text, "FINALLY_")) return finally;
    if (const auto catchAddress = hexadecimalSuffix(text, "CATCH_")) return catchAddress;

    unsigned base = 10;
    if (text.size() > 2 && text.substr(0, 2) == "0x") {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return std::nullopt;
    uint64_t result = 0;
    for (const char c : text) {
        unsigned digit = 0;
        if (c >= '0' && c <= '9') digit = static_cast<unsigned>(c - '0');
        else if (base == 16 && c >= 'a' && c <= 'f') digit = static_cast<unsigned>(c - 'a' + 10);
        else if (base == 16 && c >= 'A' && c <= 'F') digit = static_cast<unsigned>(c - 'A' + 10);
        else return std::nullopt;
        if (result > (std::numeric_limits<uint64_t>::max() - digit) / base) return std::nullopt;
        result = result * base + digit;
    }
    return result;
}

std::vector<std::string_view> arguments(std::string_view text, size_t macroPosition) {
    const auto open = text.find('(', macroPosition);
    const auto close = open == std::string_view::npos ? std::string_view::npos : text.find(')', open + 1);
    if (open == std::string_view::npos || close == std::string_view::npos) return {};
    std::vector<std::string_view> result;
    size_t begin = open + 1;
    int depth = 0;
    for (size_t i = begin; i <= close; ++i) {
        if (i < close && text[i] == '(') ++depth;
        if (i < close && text[i] == ')') --depth;
        if (i == close || (text[i] == ',' && depth == 0)) {
            result.push_back(trim(text.substr(begin, i - begin)));
            begin = i + 1;
        }
    }
    return result;
}

bool isLeaveTarget(const ExpressionPtr& expression) {
    return normalized(registerName(expression)) == "leavetarget";
}

std::optional<uint64_t> leaveComparison(const ExpressionPtr& expression) {
    const auto condition = stripCasts(expression);
    if (!condition || condition->kind != Expression::Kind::Binary || condition->op != "==" ||
        condition->arguments.size() != 2) {
        return std::nullopt;
    }
    const auto& left = condition->arguments[0];
    const auto& right = condition->arguments[1];
    if (isLeaveTarget(left)) return constant(right);
    if (isLeaveTarget(right)) return constant(left);
    return std::nullopt;
}

class Collector {
public:
    Collector(const RecoveredFunction& function, const std::vector<NativeInstruction>& nativeInstructions) {
        for (const auto& block : function.blocks) blockAddresses_.insert(block.address);
        for (const auto& region : function.exceptionRegions) {
            Builder builder;
            builder.fromModel = true;
            builder.info.kind = region.kind;
            builder.info.tryBegin = region.tryBegin;
            builder.info.tryEnd = region.tryEnd;
            builder.info.handlerBegin = region.handler;
            if (region.leaveTarget != 0) builder.info.leaveTarget = region.leaveTarget;
            builders_.push_back(std::move(builder));
        }
        collectIR(function);
        collectNative(nativeInstructions);
        std::sort(events_.begin(), events_.end(), [](const Event& left, const Event& right) {
            return std::tie(left.address, left.kind, left.first, left.second, left.label, left.catchType) <
                std::tie(right.address, right.kind, right.first, right.second, right.label, right.catchType);
        });
    }

    ExceptionRegionAnalysis run() {
        for (const auto& event : events_) {
            switch (event.kind) {
            case EventKind::Leave:
                processLeave(event);
                break;
            case EventKind::Finally:
                processFinally(event);
                break;
            case EventKind::Catch:
                processCatch(event);
                break;
            case EventKind::EndFinally:
                processEndFinally(event);
                break;
            case EventKind::Cleanup:
                processCleanup(event);
                break;
            case EventKind::Rethrow:
                processRethrow(event);
                break;
            case EventKind::TryStart:
            case EventKind::TryEnd:
            case EventKind::JumpTable:
                break;
            }
        }
        processTryBoundaries();
        processJumpTables();
        finish();
        return std::move(result_);
    }

private:
    std::vector<Event> events_;
    std::set<uint64_t> blockAddresses_;
    std::vector<Builder> builders_;
    ExceptionRegionAnalysis result_;
    std::set<std::tuple<EventKind, uint64_t, std::optional<uint64_t>, std::optional<uint64_t>, std::string, std::string>> eventKeys_;
    std::set<std::tuple<ExceptionRegionDiagnosticKind, uint64_t, std::string>> diagnosticKeys_;

    void add(Event event) {
        const auto key = std::make_tuple(event.kind, event.address, event.first, event.second, event.label, event.catchType);
        if (eventKeys_.insert(key).second) events_.push_back(std::move(event));
    }

    void diagnostic(ExceptionRegionDiagnosticKind kind, uint64_t address, std::string message) {
        if (diagnosticKeys_.emplace(kind, address, message).second) {
            result_.diagnostics.push_back({kind, address, std::move(message)});
        }
    }

    std::optional<uint64_t> resolveAddress(const Event& event, bool second) const {
        const auto& value = second ? event.second : event.first;
        if (value && blockAddresses_.contains(*value)) return value;
        if (second && !event.label.empty()) {
            if (const auto parsed = parseValue(event.label); parsed && blockAddresses_.contains(*parsed)) return parsed;
        }
        return std::nullopt;
    }

    size_t createBuilder(ExceptionRegionKind kind) {
        Builder builder;
        builder.info.kind = kind;
        builders_.push_back(std::move(builder));
        return builders_.size() - 1;
    }

    std::optional<size_t> matchingFinally(const Event& event, const std::optional<uint64_t>& handler) {
        std::optional<size_t> match;
        for (size_t i = 0; i < builders_.size(); ++i) {
            auto& builder = builders_[i];
            if (builder.info.kind != ExceptionRegionKind::Finally) continue;
            const bool sameAddress = handler && builder.info.handlerBegin == handler;
            const bool sameLabel = !event.label.empty() && !builder.handlerLabel.empty() &&
                normalized(builder.handlerLabel) == normalized(event.label);
            if (!sameAddress && !sameLabel) continue;
            if (match) return match;
            match = i;
        }
        return match;
    }

    void closeCatch(uint64_t address) {
        std::optional<size_t> current;
        for (size_t i = 0; i < builders_.size(); ++i) {
            const auto& info = builders_[i].info;
            if (info.kind != ExceptionRegionKind::Catch || info.handlerEnd || !info.handlerBegin ||
                *info.handlerBegin > address) {
                continue;
            }
            if (!current || *builders_[*current].info.handlerBegin < *info.handlerBegin) current = i;
        }
        if (current) builders_[*current].info.handlerEnd = address;
    }

    void processLeave(const Event& event) {
        closeCatch(event.address);
        auto handler = resolveAddress(event, true);
        auto index = matchingFinally(event, handler);
        if (!index) {
            index = createBuilder(ExceptionRegionKind::Finally);
            builders_[*index].handlerLabel = event.label;
        }
        auto& builder = builders_[*index];
        auto& info = builder.info;
        if (handler) info.handlerBegin = handler;
        if ((event.second || !event.label.empty()) && !info.handlerBegin) {
            info.partial = true;
            diagnostic(ExceptionRegionDiagnosticKind::UnresolvedLeaveTarget, event.address,
                "Leave handler is not a basic block in the recovered function");
        }
        if (!builder.fromModel && (!info.tryEnd || *info.tryEnd < event.address)) info.tryEnd = event.address;
        if (event.first) {
            builder.requireLeaveDestination = true;
            if (info.leaveTarget && info.leaveTarget != event.first) {
                info.partial = true;
                diagnostic(ExceptionRegionDiagnosticKind::AmbiguousRegion, event.address,
                    "Conflicting leave targets for one finally region");
            } else {
                info.leaveTarget = event.first;
            }
        }
    }

    void processFinally(const Event& event) {
        auto index = matchingFinally(event, event.address);
        if (!index) index = createBuilder(ExceptionRegionKind::Finally);
        auto& builder = builders_[*index];
        builder.handlerLabel = event.label;
        if (builder.info.handlerBegin && builder.info.handlerBegin != event.address) {
            builder.info.partial = true;
            diagnostic(ExceptionRegionDiagnosticKind::AmbiguousRegion, event.address,
                "Conflicting finally handler boundaries");
        } else {
            builder.info.handlerBegin = event.address;
        }
    }

    void processCatch(const Event& event) {
        closeCatch(event.address);
        std::optional<size_t> index;
        for (size_t i = 0; i < builders_.size(); ++i) {
            if (builders_[i].info.kind == ExceptionRegionKind::Catch &&
                builders_[i].info.handlerBegin == event.address) {
                index = i;
                break;
            }
        }
        if (!index) index = createBuilder(ExceptionRegionKind::Catch);
        auto& info = builders_[*index].info;
        info.handlerBegin = event.address;
        info.catchType = event.catchType;
        builders_[*index].handlerLabel = event.label;
    }

    std::optional<size_t> openFinally(uint64_t address, bool requireEndFinally) {
        std::optional<size_t> current;
        for (size_t i = 0; i < builders_.size(); ++i) {
            const auto& builder = builders_[i];
            const auto& info = builder.info;
            if (info.kind != ExceptionRegionKind::Finally || info.handlerEnd ||
                (requireEndFinally && !builder.sawEndFinally) ||
                (info.handlerBegin && *info.handlerBegin > address)) {
                continue;
            }
            if (!current) {
                current = i;
                continue;
            }
            const auto& previous = builders_[*current].info.handlerBegin;
            if (!previous || (info.handlerBegin && *previous < *info.handlerBegin)) current = i;
        }
        return current;
    }

    void processEndFinally(const Event& event) {
        const auto index = openFinally(event.address, false);
        if (!index) {
            diagnostic(ExceptionRegionDiagnosticKind::UnmatchedEndFinally, event.address,
                "END_FINALLY has no matching finally handler");
            return;
        }
        builders_[*index].sawEndFinally = true;
    }

    void processCleanup(const Event& event) {
        const auto index = openFinally(event.address, true);
        if (!index) {
            diagnostic(ExceptionRegionDiagnosticKind::UnmatchedCleanup, event.address,
                "Cleanup has no matching END_FINALLY");
            return;
        }
        builders_[*index].info.handlerEnd = event.address;
    }

    void processRethrow(const Event& event) {
        result_.rethrows.push_back(event.address);
        std::optional<size_t> current;
        for (size_t i = 0; i < builders_.size(); ++i) {
            const auto& info = builders_[i].info;
            if (!info.handlerBegin || *info.handlerBegin > event.address ||
                (info.handlerEnd && event.address >= *info.handlerEnd)) {
                continue;
            }
            if (!current || *builders_[*current].info.handlerBegin < *info.handlerBegin) current = i;
        }
        if (!current) {
            diagnostic(ExceptionRegionDiagnosticKind::RethrowOutsideRegion, event.address,
                "Rethrow is outside every recognized handler");
            return;
        }
        builders_[*current].info.rethrow = true;
    }

    void processTryBoundaries() {
        for (auto& builder : builders_) {
            if (builder.fromModel) continue;
            auto& info = builder.info;
            const auto boundary = info.tryEnd ? info.tryEnd : info.handlerBegin;
            if (!boundary) continue;

            std::optional<uint64_t> start;
            std::optional<uint64_t> end;
            for (const auto& event : events_) {
                if (event.address >= *boundary) continue;
                if (event.kind == EventKind::TryStart && (!start || *start < event.address)) start = event.address;
            }
            if (!start) continue;
            info.tryBegin = start;
            if (!info.tryEnd) {
                for (const auto& event : events_) {
                    if (event.kind != EventKind::TryEnd || event.address <= *start || event.address > *boundary) continue;
                    if (!end || *end < event.address) end = event.address;
                }
                info.tryEnd = end;
            }
            if (info.tryEnd && *info.tryEnd <= *start) {
                info.partial = true;
                diagnostic(ExceptionRegionDiagnosticKind::AmbiguousRegion, *info.tryEnd,
                    "Try boundaries are inconsistent with cleanup evidence");
            }
        }
    }

    void processJumpTables() {
        std::vector<std::pair<uint64_t, std::pair<std::optional<uint64_t>, uint64_t>>> mappings;
        for (const auto& event : events_) {
            if (event.kind != EventKind::JumpTable || !event.first) continue;
            const auto destination = resolveAddress(event, true);
            if (!destination) {
                diagnostic(ExceptionRegionDiagnosticKind::UnresolvedJumpTable, event.address,
                    "Jump-table destination is not a basic block in the recovered function");
                continue;
            }
            mappings.push_back({*event.first, {destination, event.address}});
        }
        std::sort(mappings.begin(), mappings.end());

        for (auto& builder : builders_) {
            auto& info = builder.info;
            if (!info.leaveTarget || !builder.requireLeaveDestination) continue;
            const auto begin = std::lower_bound(mappings.begin(), mappings.end(), *info.leaveTarget,
                [](const auto& mapping, uint64_t target) { return mapping.first < target; });
            if (begin == mappings.end() || begin->first != *info.leaveTarget) {
                info.partial = true;
                diagnostic(ExceptionRegionDiagnosticKind::UnresolvedJumpTable,
                    info.tryEnd.value_or(info.handlerBegin.value_or(0)),
                    "Leave target has no resolved jump-table destination");
                continue;
            }
            info.leaveDestination = begin->second.first;
            const auto next = std::next(begin);
            if (next != mappings.end() && next->first == *info.leaveTarget && next->second.first != begin->second.first) {
                info.partial = true;
                diagnostic(ExceptionRegionDiagnosticKind::AmbiguousRegion, next->second.second,
                    "Conflicting jump-table destinations for one leave target");
            }
        }
    }

    void finish() {
        for (auto& builder : builders_) {
            auto& info = builder.info;
            const uint64_t address = info.handlerBegin.value_or(info.tryEnd.value_or(0));
            if (!builder.fromModel && (!info.tryBegin || !info.tryEnd)) {
                info.partial = true;
                diagnostic(ExceptionRegionDiagnosticKind::MissingTryBoundary, address,
                    "Protected-region boundaries are not proven by cleanup evidence");
            }
            if (!builder.fromModel && !info.handlerBegin) {
                info.partial = true;
                diagnostic(ExceptionRegionDiagnosticKind::MissingHandlerBoundary, address,
                    "Handler entry is not proven by cleanup evidence");
            }
            if (!builder.fromModel && !info.handlerEnd) {
                info.partial = true;
                diagnostic(ExceptionRegionDiagnosticKind::MissingHandlerBoundary, address,
                    "Handler exit is not proven by cleanup evidence");
            }
            if (!builder.fromModel && (!info.tryBegin || !info.tryEnd || !info.handlerBegin)) {
                result_.partial = true;
                continue;
            }

            ExceptionRegion region;
            region.tryBegin = info.tryBegin.value_or(0);
            region.tryEnd = info.tryEnd.value_or(0);
            region.handler = info.handlerBegin.value_or(0);
            region.leaveTarget = info.leaveTarget.value_or(0);
            region.kind = info.kind;
            result_.regions.push_back(region);
            result_.partial = result_.partial || info.partial;
        }

        std::sort(result_.regions.begin(), result_.regions.end(), [](const ExceptionRegion& left, const ExceptionRegion& right) {
            return std::tie(left.tryBegin, left.tryEnd, left.handler, left.leaveTarget, left.kind) <
                std::tie(right.tryBegin, right.tryEnd, right.handler, right.leaveTarget, right.kind);
        });
        std::sort(result_.rethrows.begin(), result_.rethrows.end());
        result_.rethrows.erase(std::unique(result_.rethrows.begin(), result_.rethrows.end()), result_.rethrows.end());
        std::sort(result_.diagnostics.begin(), result_.diagnostics.end(), [](const auto& left, const auto& right) {
            return std::tie(left.address, left.kind, left.message) < std::tie(right.address, right.kind, right.message);
        });
        result_.partial = result_.partial || !result_.diagnostics.empty();
    }

    void collectIR(const RecoveredFunction& function) {
        for (const auto& block : function.blocks) {
            std::optional<size_t> pendingLeave;
            for (const auto& statement : block.statements) {
                if (statement.kind == Statement::Kind::Assign && isLeaveTarget(statement.destination)) {
                    Event event;
                    event.kind = EventKind::Leave;
                    event.address = statement.address;
                    event.first = constant(statement.value);
                    add(std::move(event));
                    pendingLeave = events_.size() - 1;
                }

                if (statement.kind == Statement::Kind::Branch && pendingLeave) {
                    auto& event = events_[*pendingLeave];
                    event.second = constant(statement.target);
                    event.label = registerName(statement.target);
                    pendingLeave.reset();
                }

                if (statement.kind == Statement::Kind::ConditionalBranch) {
                    if (const auto target = leaveComparison(statement.condition)) {
                        Event event;
                        event.kind = EventKind::JumpTable;
                        event.address = statement.address;
                        event.first = target;
                        event.second = constant(statement.target);
                        event.label = registerName(statement.target);
                        add(std::move(event));
                    }
                }

                if (statement.kind != Statement::Kind::Call) continue;
                const auto kind = macroKind(registerName(statement.target));
                if (!kind) continue;
                Event event;
                event.kind = *kind;
                event.address = statement.address;
                if (!statement.arguments.empty()) {
                    event.first = constant(statement.arguments[0]);
                    if (event.label.empty()) event.label = registerName(statement.arguments[0]);
                }
                if (statement.arguments.size() > 1) {
                    event.second = constant(statement.arguments[1]);
                    event.label = registerName(statement.arguments[1]);
                }
                add(std::move(event));
            }
        }
    }

    void collectNative(const std::vector<NativeInstruction>& instructions) {
        for (const auto& instruction : instructions) {
            const std::string text = instruction.text.empty() ? instruction.mnemonic : instruction.text;
            const auto textUpper = upper(text);
            const auto label = trim(text);
            const auto labelEnd = label.find_first_of(": \t\r\n(");
            const auto labelToken = label.substr(0, labelEnd);
            if (textUpper.find("BEGIN TRY") != std::string::npos) {
                Event event;
                event.kind = EventKind::TryStart;
                event.address = instruction.address;
                event.label = std::string(labelToken);
                add(std::move(event));
            }
            if (textUpper.find("END TRY") != std::string::npos) {
                Event event;
                event.kind = EventKind::TryEnd;
                event.address = instruction.address;
                event.label = std::string(labelToken);
                add(std::move(event));
            }
            if (const auto value = hexadecimalSuffix(labelToken, "FINALLY_")) {
                Event event;
                event.kind = EventKind::Finally;
                event.address = instruction.address;
                event.first = value;
                event.label = std::string(labelToken);
                add(std::move(event));
            } else if (const auto value = hexadecimalSuffix(labelToken, "CATCH_")) {
                Event event;
                event.kind = EventKind::Catch;
                event.address = instruction.address;
                event.first = value;
                event.label = std::string(labelToken);
                const auto catchOpen = textUpper.find("CATCH(", labelToken.size());
                const auto catchClose = catchOpen == std::string::npos ? std::string::npos : text.find(')', catchOpen + 6);
                if (catchOpen != std::string::npos && catchClose != std::string::npos) {
                    event.catchType = std::string(trim(std::string_view(text).substr(catchOpen + 6, catchClose - catchOpen - 6)));
                }
                add(std::move(event));
            }

            const std::pair<std::string_view, EventKind> macros[] = {
                {"IL2CPP_LEAVE", EventKind::Leave},
                {"IL2CPP_END_FINALLY", EventKind::EndFinally},
                {"IL2CPP_CLEANUP", EventKind::Cleanup},
                {"IL2CPP_JUMP_TBL", EventKind::JumpTable},
                {"IL2CPP_RETHROW_IF_UNHANDLED", EventKind::Rethrow},
                {"IL2CPP_RETHROW", EventKind::Rethrow},
            };
            for (const auto& [name, kind] : macros) {
                const auto position = textUpper.find(name);
                if (position == std::string::npos) continue;
                Event event;
                event.kind = kind;
                event.address = instruction.address;
                const auto args = arguments(text, position);
                if (!args.empty()) {
                    event.first = parseValue(args[0]);
                    if (kind == EventKind::Rethrow) event.catchType = std::string(args[0]);
                }
                if (args.size() > 1) {
                    event.second = parseValue(args[1]);
                    event.label = std::string(args[1]);
                }
                add(std::move(event));
                break;
            }
        }
    }
};

} // namespace

ExceptionRegionAnalysis ExceptionRegions::analyze(
    const RecoveredFunction& function,
    const std::vector<NativeInstruction>& nativeInstructions) const {
    return Collector(function, nativeInstructions).run();
}

} // namespace il2cpprec::flow
