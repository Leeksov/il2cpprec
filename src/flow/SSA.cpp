#include <il2cpprec/flow/SSA.hpp>

#include <il2cpprec/flow/Structurer.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <numeric>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace il2cpprec::flow {
namespace {

constexpr size_t npos = ControlFlowGraph::npos;

using IdSet = std::vector<size_t>;

IdSet normalized(IdSet values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

void mergeInto(IdSet& destination, const IdSet& source) {
    if (source.empty()) return;
    IdSet merged;
    merged.reserve(destination.size() + source.size());
    std::set_union(
        destination.begin(), destination.end(), source.begin(), source.end(),
        std::back_inserter(merged));
    destination = std::move(merged);
}

IdSet subtract(const IdSet& values, const IdSet& removed) {
    IdSet result;
    result.reserve(values.size());
    std::set_difference(
        values.begin(), values.end(), removed.begin(), removed.end(),
        std::back_inserter(result));
    return result;
}

struct ReachingState;
using ReachingStatePtr = std::shared_ptr<const ReachingState>;

struct ReachingState {
    size_t variable = npos;
    std::vector<size_t> definitions;
    uint64_t priority = 0;
    ReachingStatePtr left;
    ReachingStatePtr right;
};

uint64_t reachingPriority(size_t variable) {
    uint64_t value = variable + 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

ReachingStatePtr makeReachingState(
    size_t variable,
    std::vector<size_t> definitions,
    ReachingStatePtr left,
    ReachingStatePtr right) {
    return std::make_shared<ReachingState>(ReachingState{
        variable, std::move(definitions), reachingPriority(variable), std::move(left), std::move(right)});
}

ReachingStatePtr insertReaching(
    ReachingStatePtr state,
    size_t variable,
    std::vector<size_t> definitions) {
    if (!state) return makeReachingState(variable, std::move(definitions), nullptr, nullptr);
    if (variable == state->variable) {
        if (state->definitions == definitions) return state;
        return makeReachingState(variable, std::move(definitions), state->left, state->right);
    }
    if (variable < state->variable) {
        auto child = insertReaching(state->left, variable, std::move(definitions));
        if (child == state->left) return state;
        if (child->priority > state->priority) {
            auto replacement = makeReachingState(
                state->variable, state->definitions, child->right, state->right);
            return makeReachingState(child->variable, child->definitions, child->left, std::move(replacement));
        }
        return makeReachingState(state->variable, state->definitions, std::move(child), state->right);
    }
    auto child = insertReaching(state->right, variable, std::move(definitions));
    if (child == state->right) return state;
    if (child->priority > state->priority) {
        auto replacement = makeReachingState(
            state->variable, state->definitions, state->left, child->left);
        return makeReachingState(child->variable, child->definitions, std::move(replacement), child->right);
    }
    return makeReachingState(state->variable, state->definitions, state->left, std::move(child));
}

const std::vector<size_t>* findReaching(const ReachingStatePtr& state, size_t variable) {
    auto current = state;
    while (current) {
        if (variable == current->variable) return &current->definitions;
        current = variable < current->variable ? current->left : current->right;
    }
    return nullptr;
}

bool sameReachingState(const ReachingStatePtr& left, const ReachingStatePtr& right) {
    if (left == right) return true;
    if (!left || !right || left->variable != right->variable || left->definitions != right->definitions) {
        return false;
    }
    return sameReachingState(left->left, right->left) && sameReachingState(left->right, right->right);
}

void mergeReachingStates(ReachingStatePtr& destination, const ReachingStatePtr& source) {
    if (!source || destination == source) return;
    if (!destination) {
        destination = source;
        return;
    }
    if (source->left) mergeReachingStates(destination, source->left);
    auto definitions = source->definitions;
    if (const auto* existing = findReaching(destination, source->variable)) {
        mergeInto(definitions, *existing);
    }
    destination = insertReaching(destination, source->variable, std::move(definitions));
    if (source->right) mergeReachingStates(destination, source->right);
}

bool sameType(ScalarType left, ScalarType right) {
    return left.kind == right.kind && left.bits == right.bits;
}

bool isComparison(const std::string& op) {
    return op == "==" || op == "!=" || op == "<" || op == "<=" || op == ">" || op == ">=" || op == "unordered";
}

bool isBooleanCondition(ScalarType type) {
    return type.kind == ScalarKind::Boolean ||
        (type.bits == 1 && type.kind != ScalarKind::FloatingPoint && type.kind != ScalarKind::Vector);
}

bool isUnresolvedCall(const Statement& statement) {
    return statement.kind == Statement::Kind::Call &&
        (!statement.target || statement.target->kind != Expression::Kind::Constant);
}

bool isExceptionStateRegister(const std::string& name) {
    return name == "__leave_target" || name == "__last_unhandled_exception" ||
        name == "__exception_local" || name == "__active_exceptions";
}

bool isPure(const ExpressionPtr& expression) {
    if (!expression) return false;
    switch (expression->kind) {
    case Expression::Kind::Unknown:
    case Expression::Kind::Load:
        return false;
    case Expression::Kind::Constant:
    case Expression::Kind::Register:
        return true;
    case Expression::Kind::Unary:
    case Expression::Kind::Binary:
    case Expression::Kind::Cast:
    case Expression::Kind::Select:
        return std::all_of(expression->arguments.begin(), expression->arguments.end(), isPure);
    }
    return false;
}

struct ValueKey {
    enum class Kind {
        Constant,
        Expression,
        Phi
    };

    Kind kind = Kind::Constant;
    Expression::Kind expressionKind = Expression::Kind::Unknown;
    ScalarKind scalarKind = ScalarKind::Unknown;
    uint16_t bits = 0;
    uint64_t constant = 0;
    std::string op;
    std::vector<uint32_t> arguments;
    size_t variable = npos;
    std::vector<size_t> definitions;

    bool operator==(const ValueKey&) const = default;
};

struct ValueKeyHash {
    size_t operator()(const ValueKey& key) const {
        size_t result = static_cast<size_t>(key.kind);
        auto combine = [&result](size_t value) {
            result ^= value + 0x9e3779b97f4a7c15ULL + (result << 6) + (result >> 2);
        };
        combine(static_cast<size_t>(key.expressionKind));
        combine(static_cast<size_t>(key.scalarKind));
        combine(key.bits);
        combine(static_cast<size_t>(key.constant));
        combine(std::hash<std::string>{}(key.op));
        for (const auto argument : key.arguments) combine(argument);
        combine(key.variable);
        for (const auto definition : key.definitions) combine(definition);
        return result;
    }
};

class ValueNumbers {
public:
    static bool isNumberableType(ScalarType type) {
        return type.kind != ScalarKind::Unknown && type.bits != 0;
    }

    ScalarType type(uint32_t number) const {
        return number < types_.size() ? types_[number] : ScalarType{};
    }

    uint32_t constant(const ExpressionPtr& expression) {
        if (!expression || !isNumberableType(expression->type)) return 0;
        ValueKey key;
        key.kind = ValueKey::Kind::Constant;
        key.scalarKind = expression->type.kind;
        key.bits = expression->type.bits;
        key.constant = expression->constant;
        return intern(std::move(key));
    }

    uint32_t registerValue(
        const ExpressionPtr& expression,
        const std::unordered_map<size_t, uint32_t>& environment) const {
        if (!expression || expression->kind != Expression::Kind::Register || !isNumberableType(expression->type)) return 0;
        const auto registerId = registerIds_.find(expression->name);
        if (registerId == registerIds_.end()) return 0;
        const auto found = environment.find(registerId->second);
        if (found == environment.end() || found->second == 0 || !sameType(type(found->second), expression->type)) return 0;
        return found->second;
    }

    uint32_t expression(const ExpressionPtr& value, const std::unordered_map<size_t, uint32_t>& environment) {
        if (!value || !isNumberableType(value->type)) return 0;
        if (value->kind == Expression::Kind::Register) return registerValue(value, environment);
        if (value->kind == Expression::Kind::Constant) return constant(value);
        if (!isPure(value)) return 0;

        size_t expectedArguments = 0;
        switch (value->kind) {
        case Expression::Kind::Unary:
        case Expression::Kind::Cast:
            expectedArguments = 1;
            break;
        case Expression::Kind::Binary:
            expectedArguments = 2;
            break;
        case Expression::Kind::Select:
            expectedArguments = 3;
            break;
        default:
            return 0;
        }
        if (value->arguments.size() != expectedArguments) return 0;
        if (value->kind == Expression::Kind::Binary && isComparison(value->op) &&
            (value->type.kind != ScalarKind::Boolean || !sameType(value->arguments[0]->type, value->arguments[1]->type))) {
            return 0;
        }
        if (value->kind == Expression::Kind::Select &&
            (!isBooleanCondition(value->arguments[0]->type) ||
             !sameType(value->type, value->arguments[1]->type) ||
             !sameType(value->type, value->arguments[2]->type))) {
            return 0;
        }

        ValueKey key;
        key.kind = ValueKey::Kind::Expression;
        key.expressionKind = value->kind;
        key.scalarKind = value->type.kind;
        key.bits = value->type.bits;
        key.op = value->op;
        key.arguments.reserve(value->arguments.size());
        for (const auto& argument : value->arguments) {
            uint32_t number = 0;
            if (argument && argument->kind == Expression::Kind::Register) {
                number = registerValue(argument, environment);
            } else {
                number = expression(argument, environment);
            }
            if (number == 0) return 0;
            key.arguments.push_back(number);
        }
        return intern(std::move(key));
    }

    uint32_t phi(
        size_t variable,
        const std::vector<size_t>& definitions,
        const std::vector<uint32_t>& definitionValues,
        const std::vector<ScalarType>& definitionTypes) {
        if (definitions.empty() || definitions.front() >= definitionTypes.size()) return 0;
        const auto mergedType = definitionTypes[definitions.front()];
        if (!isNumberableType(mergedType)) return 0;
        for (const auto definition : definitions) {
            if (definition >= definitionTypes.size() || definition >= definitionValues.size() ||
                !sameType(definitionTypes[definition], mergedType)) {
                return 0;
            }
        }

        const auto first = definitionValues[definitions.front()];
        const bool allEqual = std::all_of(definitions.begin(), definitions.end(), [&](size_t definition) {
            return definitionValues[definition] == first;
        });
        if (allEqual) return first != 0 && sameType(type(first), mergedType) ? first : 0;

        ValueKey key;
        key.kind = ValueKey::Kind::Phi;
        key.scalarKind = mergedType.kind;
        key.bits = mergedType.bits;
        key.variable = variable;
        key.definitions = definitions;
        return intern(std::move(key));
    }

    void setRegisterIds(const std::unordered_map<std::string, size_t>& ids) {
        registerIds_ = ids;
    }

private:
    std::unordered_map<ValueKey, uint32_t, ValueKeyHash> values_;
    std::unordered_map<std::string, size_t> registerIds_;
    std::vector<ScalarType> types_ = std::vector<ScalarType>(1);
    uint32_t next_ = 1;

    uint32_t intern(ValueKey key) {
        if (const auto found = values_.find(key); found != values_.end()) return found->second;
        const auto result = next_++;
        types_.push_back({key.scalarKind, key.bits});
        values_.emplace(std::move(key), result);
        return result;
    }
};

class Analyzer {
public:
    explicit Analyzer(const RecoveredFunction& function)
        : function_(function), cfg_(function) {
        buildStatements();
    }

    RecoveredFunction run() {
        if (unsupported_ || refs_.empty() || !function_.exceptionRegions.empty() || hasOpaqueCalls_) return function_;
        valueNumbers_.setRegisterIds(variableIds_);
        computeOrder();
        if (!hasCalls_) {
            computeReachingDefinitions();
            computeValueNumbers();
        }
        computeLiveness();
        eliminateDeadAssignments();

        RecoveredFunction result = function_;
        for (size_t sourceIndex = 0; sourceIndex < result.blocks.size(); ++sourceIndex) {
            auto& statements = result.blocks[sourceIndex].statements;
            std::vector<Statement> kept;
            kept.reserve(statements.size());
            for (size_t statementIndex = 0; statementIndex < statements.size(); ++statementIndex) {
                if (!removed_[sourceIndex][statementIndex]) kept.push_back(std::move(statements[statementIndex]));
            }
            statements = std::move(kept);
        }
        return result;
    }

private:
    struct StatementInfo {
        size_t sourceIndex = 0;
        size_t statementIndex = 0;
        size_t block = npos;
        const Statement* statement = nullptr;
        IdSet uses;
        size_t variable = npos;
        size_t definition = npos;
        bool pure = false;
        bool redundant = false;
        bool preserve = false;
    };

    struct Definition {
        size_t ref = npos;
        size_t variable = npos;
        size_t block = npos;
    };

    struct BlockSummary {
        IdSet uses;
        IdSet definitions;
        bool unknownExit = false;
    };

    const RecoveredFunction& function_;
    ControlFlowGraph cfg_;
    std::unordered_map<std::string, size_t> variableIds_;
    std::vector<std::string> variableNames_;
    std::vector<StatementInfo> refs_;
    std::vector<std::vector<size_t>> blockRefs_;
    std::vector<Definition> definitions_;
    std::vector<ScalarType> definitionTypes_;
    std::vector<ReachingStatePtr> reachingIn_;
    std::vector<std::vector<ReachingStatePtr>> reachingInputs_;
    std::vector<size_t> order_;
    std::vector<std::vector<bool>> covered_;
    std::vector<std::vector<bool>> removed_;
    std::vector<BlockSummary> summaries_;
    std::vector<IdSet> liveIn_;
    std::vector<IdSet> liveOut_;
    ValueNumbers valueNumbers_;
    bool unsupported_ = false;
    bool hasCalls_ = false;
    bool hasOpaqueCalls_ = false;

    size_t variable(const std::string& name) {
        if (const auto found = variableIds_.find(name); found != variableIds_.end()) return found->second;
        const auto id = variableNames_.size();
        variableIds_.emplace(name, id);
        variableNames_.push_back(name);
        return id;
    }

    void collectUses(const ExpressionPtr& expression, IdSet& uses) {
        if (!expression) return;
        if (expression->kind == Expression::Kind::Register) uses.push_back(variable(expression->name));
        for (const auto& argument : expression->arguments) collectUses(argument, uses);
    }

    void addStatement(size_t blockIndex, size_t sourceIndex, size_t statementIndex) {
        const auto& statement = function_.blocks[sourceIndex].statements[statementIndex];
        StatementInfo info;
        info.sourceIndex = sourceIndex;
        info.statementIndex = statementIndex;
        info.block = blockIndex;
        info.statement = &statement;
        hasOpaqueCalls_ = hasOpaqueCalls_ || isUnresolvedCall(statement);
        hasCalls_ = hasCalls_ || statement.kind == Statement::Kind::Call;

        const bool directDestination = statement.destination &&
            statement.destination->kind == Expression::Kind::Register &&
            (statement.kind == Statement::Kind::Assign || statement.kind == Statement::Kind::Call);
        info.preserve = statement.kind == Statement::Kind::Assign && directDestination &&
            isExceptionStateRegister(statement.destination->name);
        if (!directDestination) collectUses(statement.destination, info.uses);
        collectUses(statement.value, info.uses);
        collectUses(statement.condition, info.uses);
        collectUses(statement.target, info.uses);
        for (const auto& argument : statement.arguments) collectUses(argument, info.uses);
        info.uses = normalized(std::move(info.uses));

        if (directDestination) {
            info.variable = variable(statement.destination->name);
            info.definition = definitions_.size();
            info.pure = statement.kind == Statement::Kind::Assign && isPure(statement.value);
            definitions_.push_back({refs_.size(), info.variable, blockIndex});
            definitionTypes_.push_back(statement.destination->type);
        }

        covered_[sourceIndex][statementIndex] = true;
        blockRefs_[blockIndex].push_back(refs_.size());
        refs_.push_back(std::move(info));
    }

    void buildStatements() {
        blockRefs_.resize(cfg_.blocks.size());
        covered_.resize(function_.blocks.size());
        removed_.resize(function_.blocks.size());
        for (size_t i = 0; i < function_.blocks.size(); ++i) {
            covered_[i].assign(function_.blocks[i].statements.size(), false);
            removed_[i].assign(function_.blocks[i].statements.size(), false);
        }

        for (size_t blockIndex = 0; blockIndex < cfg_.blocks.size(); ++blockIndex) {
            const auto& block = cfg_.blocks[blockIndex];
            if (!block.source || block.sourceIndex >= function_.blocks.size()) {
                unsupported_ = true;
                return;
            }
            for (size_t i = block.statementBegin; i < block.statementEnd; ++i) {
                if (i >= block.source->statements.size()) {
                    unsupported_ = true;
                    return;
                }
                addStatement(blockIndex, block.sourceIndex, i);
            }
            if (block.terminatorIndex != npos) {
                if (block.terminatorIndex >= block.source->statements.size()) {
                    unsupported_ = true;
                    return;
                }
                addStatement(blockIndex, block.sourceIndex, block.terminatorIndex);
            }
        }

        for (const auto& block : covered_) {
            if (std::find(block.begin(), block.end(), false) != block.end()) {
                unsupported_ = true;
                return;
            }
        }
    }

    void computeOrder() {
        const auto count = cfg_.blocks.size();
        std::vector<unsigned char> state(count, 0);
        std::vector<size_t> postorder;
        postorder.reserve(count);
        auto visit = [&](size_t root) {
            if (root == npos || root >= count || state[root] != 0) return;
            std::vector<std::pair<size_t, size_t>> pending;
            pending.push_back({root, 0});
            state[root] = 1;
            while (!pending.empty()) {
                auto& [current, next] = pending.back();
                const auto& successors = cfg_.blocks[current].successors;
                if (next < successors.size()) {
                    const auto successor = successors[next++];
                    if (successor < count && state[successor] == 0) {
                        state[successor] = 1;
                        pending.push_back({successor, 0});
                    }
                    continue;
                }
                state[current] = 2;
                postorder.push_back(current);
                pending.pop_back();
            }
        };
        visit(cfg_.entry);
        for (size_t block = 0; block < count; ++block) visit(block);
        order_.assign(postorder.rbegin(), postorder.rend());
    }

    void computeReachingDefinitions() {
        const auto count = cfg_.blocks.size();
        std::vector<std::unordered_map<size_t, size_t>> generated(count);
        for (size_t block = 0; block < count; ++block) {
            for (const auto ref : blockRefs_[block]) {
                const auto& info = refs_[ref];
                if (info.definition != npos) generated[block][info.variable] = info.definition;
            }
        }

        reachingIn_.resize(count);
        reachingInputs_.assign(count, {});
        std::vector<ReachingStatePtr> reachingOut(count);
        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto current : order_) {
                std::vector<ReachingStatePtr> inputs;
                for (const auto predecessor : cfg_.blocks[current].predecessors) {
                    if (predecessor < count) inputs.push_back(reachingOut[predecessor]);
                }
                const auto& previous = reachingInputs_[current];
                const bool sameInputs = inputs.size() == previous.size() &&
                    std::equal(inputs.begin(), inputs.end(), previous.begin());
                if (sameInputs && (reachingOut[current] || generated[current].empty())) continue;

                ReachingStatePtr nextIn;
                for (const auto& input : inputs) mergeReachingStates(nextIn, input);
                auto nextOut = nextIn;
                for (const auto& [variableId, definition] : generated[current]) {
                    nextOut = insertReaching(nextOut, variableId, {definition});
                }
                const bool sameIn = sameReachingState(nextIn, reachingIn_[current]);
                const bool sameOut = sameReachingState(nextOut, reachingOut[current]);
                reachingInputs_[current] = std::move(inputs);
                if (sameIn && sameOut) continue;
                reachingIn_[current] = sameIn ? reachingIn_[current] : std::move(nextIn);
                reachingOut[current] = sameOut ? reachingOut[current] : std::move(nextOut);
                changed = true;
            }
        }
    }

    std::unordered_map<size_t, uint32_t> incomingValues(
        size_t block,
        const std::vector<uint32_t>& definitionValues) {
        IdSet used;
        for (const auto ref : blockRefs_[block]) {
            const auto& info = refs_[ref];
            used.insert(used.end(), info.uses.begin(), info.uses.end());
            if (info.variable != npos) used.push_back(info.variable);
        }
        used = normalized(std::move(used));

        std::unordered_map<size_t, uint32_t> environment;
        for (const auto variableId : used) {
            const auto* incoming = findReaching(reachingIn_[block], variableId);
            if (incoming) {
                environment.emplace(variableId, valueNumbers_.phi(
                    variableId, *incoming, definitionValues, definitionTypes_));
            }
        }
        return environment;
    }

    uint32_t expressionValue(
        const ExpressionPtr& expression,
        const std::unordered_map<size_t, uint32_t>& environment) {
        return valueNumbers_.expression(expression, environment);
    }

    uint32_t definitionValue(
        const StatementInfo& info,
        const std::unordered_map<size_t, uint32_t>& environment) {
        if (info.statement->kind != Statement::Kind::Assign || info.preserve) return 0;
        const auto& source = info.statement->value;
        const auto& destination = info.statement->destination;
        if (!source || !destination || !sameType(source->type, destination->type)) return 0;
        const auto value = expressionValue(source, environment);
        return value != 0 && sameType(valueNumbers_.type(value), destination->type) ? value : 0;
    }

    void computeValueNumbers() {
        std::vector<uint32_t> definitionValues(definitions_.size(), 0);
        bool changed = true;
        while (changed) {
            changed = false;
            std::vector<uint32_t> next(definitionValues.size(), 0);
            for (const auto block : order_) {
                auto environment = incomingValues(block, definitionValues);
                for (const auto ref : blockRefs_[block]) {
                    const auto& info = refs_[ref];
                    if (info.definition == npos) continue;
                    const auto value = definitionValue(info, environment);
                    next[info.definition] = value;
                    environment[info.variable] = value;
                }
            }
            if (next != definitionValues) {
                definitionValues = std::move(next);
                changed = true;
            }
        }

        for (const auto block : order_) {
            auto environment = incomingValues(block, definitionValues);
            for (const auto ref : blockRefs_[block]) {
                auto& info = refs_[ref];
                if (info.definition == npos) continue;
                const auto value = definitionValue(info, environment);
                const auto& source = info.statement->value;
                const auto& destination = info.statement->destination;
                const auto current = environment.find(info.variable);
                info.redundant = info.pure && source && destination &&
                    (source->kind == Expression::Kind::Constant || source->kind == Expression::Kind::Register) &&
                    value != 0 && current != environment.end() && current->second == value &&
                    sameType(source->type, destination->type) &&
                    sameType(valueNumbers_.type(current->second), source->type);
                environment[info.variable] = value;
            }
        }
    }

    void buildSummaries() {
        summaries_.assign(cfg_.blocks.size(), {});
        for (size_t block = 0; block < cfg_.blocks.size(); ++block) {
            std::unordered_set<size_t> defined;
            std::unordered_set<size_t> used;
            for (const auto ref : blockRefs_[block]) {
                const auto& info = refs_[ref];
                for (const auto use : info.uses) {
                    if (!defined.contains(use)) used.insert(use);
                }
                if (info.variable != npos && !info.redundant) defined.insert(info.variable);
            }
            auto& summary = summaries_[block];
            summary.uses = normalized(IdSet(used.begin(), used.end()));
            summary.definitions = normalized(IdSet(defined.begin(), defined.end()));
            const auto* terminator = cfg_.blocks[block].terminator();
            summary.unknownExit = terminator &&
                (terminator->kind == Statement::Kind::Branch || terminator->kind == Statement::Kind::ConditionalBranch) &&
                cfg_.blocks[block].takenSuccessor == npos;
        }
    }

    void computeLiveness() {
        buildSummaries();
        const auto count = cfg_.blocks.size();
        liveIn_.resize(count);
        liveOut_.resize(count);
        IdSet allVariables(variableNames_.size());
        std::iota(allVariables.begin(), allVariables.end(), 0);

        bool changed = true;
        while (changed) {
            changed = false;
            for (auto position = order_.rbegin(); position != order_.rend(); ++position) {
                const auto current = *position;
                IdSet nextOut;
                if (summaries_[current].unknownExit) nextOut = allVariables;
                for (const auto successor : cfg_.blocks[current].successors) {
                    if (successor < count) mergeInto(nextOut, liveIn_[successor]);
                }
                auto nextIn = subtract(nextOut, summaries_[current].definitions);
                mergeInto(nextIn, summaries_[current].uses);
                if (nextIn != liveIn_[current] || nextOut != liveOut_[current]) {
                    liveIn_[current] = std::move(nextIn);
                    liveOut_[current] = std::move(nextOut);
                    changed = true;
                }
            }
        }
    }

    void eliminateDeadAssignments() {
        for (size_t block = 0; block < cfg_.blocks.size(); ++block) {
            std::unordered_set<size_t> live(liveOut_[block].begin(), liveOut_[block].end());
            const auto& statements = blockRefs_[block];
            for (auto current = statements.rbegin(); current != statements.rend(); ++current) {
                auto& info = refs_[*current];
                if (info.redundant) {
                    removed_[info.sourceIndex][info.statementIndex] = true;
                    live.insert(info.uses.begin(), info.uses.end());
                    continue;
                }

                const bool dead = info.statement->kind == Statement::Kind::Assign &&
                    info.definition != npos && info.pure && !info.preserve && !live.contains(info.variable);
                if (dead) {
                    removed_[info.sourceIndex][info.statementIndex] = true;
                    live.erase(info.variable);
                    continue;
                }

                if (info.variable != npos) live.erase(info.variable);
                live.insert(info.uses.begin(), info.uses.end());
            }
        }
    }
};

} // namespace

RecoveredFunction SSA::transform(const RecoveredFunction& function) const {
    return Analyzer(function).run();
}

RecoveredFunction transform(const RecoveredFunction& function) {
    return SSA{}.transform(function);
}

} // namespace il2cpprec::flow
