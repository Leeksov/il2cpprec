#include <il2cpprec/analysis/RuntimeHelpers.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace il2cpprec {
namespace {

ExpressionPtr uncast(ExpressionPtr expression) {
    while (expression && expression->kind == Expression::Kind::Cast && expression->arguments.size() == 1) {
        expression = expression->arguments.front();
    }
    return expression;
}

bool sameExpression(ExpressionPtr left, ExpressionPtr right, unsigned depth = 0) {
    left = uncast(std::move(left));
    right = uncast(std::move(right));
    if (!left || !right || depth > 16 || left->kind == Expression::Kind::Unknown ||
        right->kind == Expression::Kind::Unknown || left->kind != right->kind ||
        left->arguments.size() != right->arguments.size()) return false;
    if (left->kind == Expression::Kind::Constant && left->constant != right->constant) return false;
    if (left->kind == Expression::Kind::Register && left->name != right->name) return false;
    if (left->op != right->op) return false;
    for (size_t i = 0; i < left->arguments.size(); ++i) {
        if (!sameExpression(left->arguments[i], right->arguments[i], depth + 1)) return false;
    }
    return true;
}

bool isConstant(ExpressionPtr expression, uint64_t value) {
    expression = uncast(std::move(expression));
    return expression && expression->kind == Expression::Kind::Constant && expression->constant == value;
}

ExpressionPtr definitionOf(const BasicBlock& block, size_t before, const std::string& name) {
    for (size_t i = before; i > 0; --i) {
        const auto& statement = block.statements[i - 1];
        if (statement.kind != Statement::Kind::Assign || !statement.destination ||
            statement.destination->kind != Expression::Kind::Register) continue;
        if (statement.destination->name == name) return statement.value;
    }
    return {};
}

ExpressionPtr resolve(const BasicBlock& block, size_t before, ExpressionPtr expression, std::set<std::string>& seen,
                      unsigned depth = 0) {
    expression = uncast(std::move(expression));
    if (!expression || depth > 16) return {};
    if (expression->kind == Expression::Kind::Register) {
        if (!seen.insert(expression->name).second) return expression;
        auto definition = definitionOf(block, before, expression->name);
        if (definition) {
            auto result = resolve(block, before, definition, seen, depth + 1);
            seen.erase(expression->name);
            return result;
        }
        seen.erase(expression->name);
        return expression;
    }
    if (expression->arguments.empty()) return expression;
    auto copy = std::make_shared<Expression>(*expression);
    for (auto& argument : copy->arguments) argument = resolve(block, before, argument, seen, depth + 1);
    return copy;
}

ExpressionPtr resolved(const BasicBlock& block, size_t before, ExpressionPtr expression) {
    std::set<std::string> seen;
    return resolve(block, before, std::move(expression), seen);
}

void loadSlots(ExpressionPtr expression, std::vector<ExpressionPtr>& slots, unsigned depth = 0) {
    expression = uncast(std::move(expression));
    if (!expression || depth > 16) return;
    if (expression->kind == Expression::Kind::Load && expression->arguments.size() == 1) {
        slots.push_back(expression->arguments.front());
        return;
    }
    for (const auto& argument : expression->arguments) loadSlots(argument, slots, depth + 1);
}

bool branchTestsZeroOnSlot(const BasicBlock& block, size_t branchIndex, const Statement& branch,
                           ExpressionPtr slot) {
    auto condition = uncast(resolved(block, branchIndex, branch.condition));
    if (!condition || condition->kind != Expression::Kind::Binary ||
        (condition->op != "==" && condition->op != "!=") || condition->arguments.size() != 2) return false;
    ExpressionPtr tested;
    if (isConstant(condition->arguments[0], 0)) tested = condition->arguments[1];
    else if (isConstant(condition->arguments[1], 0)) tested = condition->arguments[0];
    else return false;
    std::vector<ExpressionPtr> slots;
    loadSlots(tested, slots);
    return slots.size() == 1 && sameExpression(slots.front(), slot);
}

} // namespace

std::vector<RuntimeHelperEvidence> RuntimeHelpers::infer(const RecoveredFunction& function) const {
    std::vector<RuntimeHelperEvidence> evidence;
    for (size_t blockIndex = 0; blockIndex < function.blocks.size(); ++blockIndex) {
        const auto& block = function.blocks[blockIndex];
        for (size_t callIndex = 0; callIndex < block.statements.size(); ++callIndex) {
            const auto& call = block.statements[callIndex];
            const auto target = uncast(call.target);
            if (call.kind != Statement::Kind::Call || !target || target->kind != Expression::Kind::Constant ||
                target->constant == 0 || call.arguments.empty()) continue;

            // A second call or control transfer makes the store's relationship
            // to this call ambiguous. Assignments may prepare the guard write.
            for (size_t storeIndex = callIndex + 1; storeIndex < block.statements.size(); ++storeIndex) {
                const auto& store = block.statements[storeIndex];
                if (store.kind == Statement::Kind::Call || store.kind == Statement::Kind::Branch ||
                    store.kind == Statement::Kind::ConditionalBranch || store.kind == Statement::Kind::Return) break;
                if (store.kind != Statement::Kind::Store || !store.value ||
                    (store.value->type.bits != 8 && store.value->type.kind != ScalarKind::Boolean) ||
                    !isConstant(resolved(block, storeIndex, store.value), 1)) continue;
                auto slot = resolved(block, storeIndex, store.destination);
                if (!slot || slot->kind == Expression::Kind::Unknown) continue;

                for (size_t branchIndex = callIndex; branchIndex > 0; --branchIndex) {
                    const auto& branch = block.statements[branchIndex - 1];
                    if (branch.kind == Statement::Kind::Call || branch.kind == Statement::Kind::Store ||
                        branch.kind == Statement::Kind::Return || branch.kind == Statement::Kind::Branch) break;
                    if (branch.kind != Statement::Kind::ConditionalBranch || !branch.target ||
                        branch.target->kind != Expression::Kind::Constant ||
                        branch.target->constant <= store.address ||
                        std::none_of(function.blocks.begin(), function.blocks.end(), [&](const BasicBlock& candidate) {
                            return candidate.address == branch.target->constant;
                        }) ||
                        !branchTestsZeroOnSlot(block, branchIndex - 1, branch, slot)) continue;
                    evidence.push_back({RuntimeHelperRole::ClassInit, target->constant, call.address,
                                        branch.address, store.address, blockIndex, callIndex});
                    break;
                }
                break;
            }
        }
    }
    return evidence;
}

} // namespace il2cpprec
