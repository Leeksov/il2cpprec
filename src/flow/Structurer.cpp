#include <il2cpprec/flow/Structurer.hpp>

#include <algorithm>
#include <limits>
#include <queue>
#include <utility>

namespace il2cpprec::flow {
namespace {

bool isControlStatement(Statement::Kind kind) {
    return kind == Statement::Kind::Branch || kind == Statement::Kind::ConditionalBranch || kind == Statement::Kind::Return;
}

StructuredNodePtr makeNode(StructuredKind kind) {
    auto node = std::make_unique<StructuredNode>();
    node->kind = kind;
    return node;
}

StructuredNodePtr makeEmpty() {
    return makeNode(StructuredKind::Empty);
}

StructuredNodePtr makeBlock(const CFGBlock& block, bool isLabel = true) {
    auto node = makeNode(StructuredKind::Block);
    node->address = block.address;
    node->isLabel = isLabel;
    if (block.source) {
        node->statements.assign(
            block.source->statements.begin() + static_cast<std::ptrdiff_t>(block.statementBegin),
            block.source->statements.begin() + static_cast<std::ptrdiff_t>(block.statementEnd));
    }
    return node;
}

StructuredNodePtr makeSequence(std::vector<StructuredNodePtr> nodes) {
    std::vector<StructuredNodePtr> children;
    for (auto& node : nodes) {
        if (!node || node->kind == StructuredKind::Empty) continue;
        children.push_back(std::move(node));
    }
    if (children.empty()) return makeEmpty();
    if (children.size() == 1) return std::move(children.front());
    auto sequence = makeNode(StructuredKind::Sequence);
    sequence->children = std::move(children);
    return sequence;
}

template <typename... Nodes>
StructuredNodePtr makeSequence(Nodes&&... nodes) {
    std::vector<StructuredNodePtr> list;
    list.reserve(sizeof...(nodes));
    (list.push_back(std::forward<Nodes>(nodes)), ...);
    return makeSequence(std::move(list));
}

StructuredNodePtr makeReturn(const Statement& statement) {
    auto node = makeNode(StructuredKind::Return);
    node->address = statement.address;
    node->returnStatement = statement;
    return node;
}

StructuredNodePtr makeGoto(const Statement& statement) {
    if (!statement.target || statement.target->kind != Expression::Kind::Constant) {
        auto node = makeNode(StructuredKind::Block);
        node->address = statement.address;
        node->isLabel = false;
        Statement branch = statement;
        branch.kind = Statement::Kind::Branch;
        branch.condition = nullptr;
        node->statements.push_back(std::move(branch));
        return node;
    }
    auto node = makeNode(StructuredKind::Goto);
    node->address = statement.address;
    node->targetExpression = statement.target;
    node->target = statement.target->constant;
    return node;
}

StructuredNodePtr makeGoto(const CFGBlock& target) {
    auto node = makeNode(StructuredKind::Goto);
    node->target = target.address;
    return node;
}

ExpressionPtr negated(const ExpressionPtr& condition) {
    if (!condition) return nullptr;
    auto result = std::make_shared<Expression>();
    result->kind = Expression::Kind::Unary;
    result->type = ScalarType::boolean();
    result->op = "!";
    result->arguments = {condition};
    return result;
}

StructuredNodePtr flattenSequences(StructuredNodePtr root) {
    if (!root) return nullptr;
    std::vector<StructuredNode*> pending = {root.get()};
    while (!pending.empty()) {
        const auto current = pending.back();
        pending.pop_back();
        if (current->kind == StructuredKind::Sequence) {
            std::vector<StructuredNodePtr> nested;
            for (auto& child : current->children) nested.push_back(std::move(child));
            current->children.clear();
            std::vector<StructuredNodePtr> children;
            while (!nested.empty()) {
                auto child = std::move(nested.back());
                nested.pop_back();
                if (child && child->kind == StructuredKind::Sequence) {
                    for (auto& grandchild : child->children) nested.push_back(std::move(grandchild));
                    child->children.clear();
                } else if (child && child->kind != StructuredKind::Empty) {
                    children.push_back(std::move(child));
                }
            }
            std::reverse(children.begin(), children.end());
            current->children = std::move(children);
        }
        for (auto& child : current->children) {
            if (child) pending.push_back(child.get());
        }
        if (current->thenBranch) pending.push_back(current->thenBranch.get());
        if (current->elseBranch) pending.push_back(current->elseBranch.get());
        if (current->body) pending.push_back(current->body.get());
    }
    return root;
}

struct NaturalLoop {
    size_t header = ControlFlowGraph::npos;
    std::vector<size_t> nodes;
    std::vector<size_t> latches;
};

struct AllowedSet {
    const NaturalLoop* loop = nullptr;
    size_t excluded = ControlFlowGraph::npos;
};

class RegionStructurer {
public:
    explicit RegionStructurer(const ControlFlowGraph& cfg)
        : cfg_(cfg), reachable_(cfg.blocks.size(), false), consumed_(cfg.blocks.size(), false),
          loopHeaders_(cfg.blocks.size(), ControlFlowGraph::npos), budget_(initialBudget(cfg)) {
        discoverReachableBlocks();
        computeDominators();
        if (!failed_) findNaturalLoops();
    }

    StructuredNodePtr run() {
        if (cfg_.entry == npos) return makeEmpty();
        if (failed_ || std::find(reachable_.begin(), reachable_.end(), false) != reachable_.end()) {
            return makeFlatFallback();
        }

        std::vector<Frame> work;
        std::vector<StructuredNodePtr> results;
        work.push_back(makeParse(cfg_.entry, npos, AllowedSet{}, 0));
        while (!work.empty() && !failed_ && spend()) {
            auto frame = std::move(work.back());
            work.pop_back();
            process(std::move(frame), work, results);
        }
        for (size_t i = 0; i < cfg_.blocks.size(); ++i) {
            if (reachable_[i] && !consumed_[i]) failed_ = true;
        }
        if (failed_ || results.size() != 1) {
            disposePending(work, results);
            return makeFlatFallback();
        }
        auto result = std::move(results.back());
        results.pop_back();
        return flattenSequences(std::move(result));
    }

private:
    struct Reachability {
        std::vector<bool> visited;
        std::vector<size_t> distances;
        bool reachesStop = false;
    };

    enum class FrameKind {
        ParseBlock,
        ParseOrdinary,
        ParseLoop,
        AfterNext,
        AfterThen,
        AfterElse,
        AfterWhileBody,
        AfterDoBody
    };

    struct Frame {
        FrameKind kind = FrameKind::ParseBlock;
        size_t index = npos;
        size_t stop = npos;
        size_t join = npos;
        size_t exit = npos;
        size_t loopIndex = npos;
        size_t depth = 0;
        AllowedSet allowed;
        bool ordinaryOnly = false;
        bool taken = false;
        uint64_t address = 0;
        ExpressionPtr condition;
        StructuredNodePtr first;
        StructuredNodePtr second;
    };

    const ControlFlowGraph& cfg_;
    std::vector<bool> reachable_;
    std::vector<bool> consumed_;
    std::vector<size_t> immediateDominators_;
    std::vector<std::vector<size_t>> dominatorTree_;
    std::vector<size_t> dominatorBegin_;
    std::vector<size_t> dominatorEnd_;
    std::vector<NaturalLoop> loops_;
    std::vector<size_t> loopHeaders_;
    size_t budget_;
    bool failed_ = false;

    static constexpr size_t npos = ControlFlowGraph::npos;
    static constexpr size_t maxStructuredDepth = 256;

    static size_t initialBudget(const ControlFlowGraph& cfg) {
        size_t work = cfg.blocks.size() + 1;
        for (const auto& block : cfg.blocks) {
            if (work > std::numeric_limits<size_t>::max() - block.successors.size()) {
                work = std::numeric_limits<size_t>::max();
                break;
            }
            work += block.successors.size();
        }
        if (work > std::numeric_limits<size_t>::max() / 32) return std::numeric_limits<size_t>::max();
        return std::max<size_t>(1000000, work * 32);
    }

    bool spend(size_t amount = 1) {
        if (failed_) return false;
        if (amount > budget_) {
            budget_ = 0;
            failed_ = true;
            return false;
        }
        budget_ -= amount;
        return true;
    }

    StructuredNodePtr fail() {
        failed_ = true;
        return makeEmpty();
    }

    static Frame makeParse(size_t index, size_t stop, AllowedSet allowed, size_t depth, bool ordinaryOnly = false) {
        Frame frame;
        frame.kind = FrameKind::ParseBlock;
        frame.index = index;
        frame.stop = stop;
        frame.allowed = allowed;
        frame.depth = depth;
        frame.ordinaryOnly = ordinaryOnly;
        return frame;
    }

    static StructuredNodePtr takeResult(std::vector<StructuredNodePtr>& results) {
        auto result = std::move(results.back());
        results.pop_back();
        return result;
    }

    static void disposePending(std::vector<Frame>& work, std::vector<StructuredNodePtr>& results) {
        std::vector<StructuredNodePtr> pending;
        for (auto& frame : work) {
            if (frame.first) pending.push_back(std::move(frame.first));
            if (frame.second) pending.push_back(std::move(frame.second));
        }
        work.clear();
        for (auto& result : results) {
            if (result) pending.push_back(std::move(result));
        }
        results.clear();
        while (!pending.empty()) {
            auto current = std::move(pending.back());
            pending.pop_back();
            for (auto& child : current->children) {
                if (child) pending.push_back(std::move(child));
            }
            current->children.clear();
            if (current->thenBranch) pending.push_back(std::move(current->thenBranch));
            if (current->elseBranch) pending.push_back(std::move(current->elseBranch));
            if (current->body) pending.push_back(std::move(current->body));
        }
    }

    void discoverReachableBlocks() {
        if (cfg_.entry == npos) return;
        std::queue<size_t> pending;
        pending.push(cfg_.entry);
        reachable_[cfg_.entry] = true;
        while (!pending.empty()) {
            const auto current = pending.front();
            pending.pop();
            for (const auto successor : cfg_.blocks[current].successors) {
                if (successor >= cfg_.blocks.size() || reachable_[successor]) continue;
                reachable_[successor] = true;
                pending.push(successor);
            }
        }
    }

    void computeDominators() {
        const auto count = cfg_.blocks.size();
        immediateDominators_.assign(count, npos);
        dominatorTree_.assign(count, {});
        dominatorBegin_.assign(count, npos);
        dominatorEnd_.assign(count, npos);
        if (cfg_.entry == npos) return;

        std::vector<size_t> parent(count, npos);
        std::vector<size_t> dfsNumber(count, npos);
        std::vector<size_t> order;
        std::vector<size_t> nextSuccessor(count, 0);
        std::vector<size_t> stack = {cfg_.entry};
        order.reserve(count);
        dfsNumber[cfg_.entry] = 0;
        order.push_back(cfg_.entry);
        while (!stack.empty()) {
            if (!spend()) return;
            const auto current = stack.back();
            if (nextSuccessor[current] < cfg_.blocks[current].successors.size()) {
                const auto successor = cfg_.blocks[current].successors[nextSuccessor[current]++];
                if (successor >= count || dfsNumber[successor] != npos) continue;
                parent[successor] = current;
                dfsNumber[successor] = order.size();
                order.push_back(successor);
                stack.push_back(successor);
            } else {
                stack.pop_back();
            }
        }

        std::vector<size_t> semi(count, npos);
        std::vector<size_t> ancestor(count, npos);
        std::vector<size_t> label(count, npos);
        std::vector<std::vector<size_t>> bucket(count);
        for (const auto node : order) {
            semi[node] = node;
            label[node] = node;
        }

        auto compress = [&](size_t node) {
            std::vector<size_t> path;
            auto current = node;
            while (ancestor[current] != npos && ancestor[ancestor[current]] != npos) {
                path.push_back(current);
                current = ancestor[current];
            }
            for (auto it = path.rbegin(); it != path.rend(); ++it) {
                const auto item = *it;
                const auto itemAncestor = ancestor[item];
                if (dfsNumber[semi[label[itemAncestor]]] < dfsNumber[semi[label[item]]]) {
                    label[item] = label[itemAncestor];
                }
                ancestor[item] = ancestor[itemAncestor];
            }
            spend(path.size());
        };
        auto eval = [&](size_t node) {
            if (ancestor[node] == npos) return label[node];
            compress(node);
            return label[node];
        };
        auto semiNumber = [&](size_t node) { return dfsNumber[semi[node]]; };

        for (size_t i = order.size(); i-- > 1;) {
            if (failed_) return;
            const auto node = order[i];
            for (const auto predecessor : cfg_.blocks[node].predecessors) {
                if (predecessor >= count || dfsNumber[predecessor] == npos) continue;
                if (!spend()) return;
                const auto candidate = eval(predecessor);
                if (semiNumber(candidate) < semiNumber(node)) semi[node] = semi[candidate];
                if (failed_) return;
            }
            bucket[semi[node]].push_back(node);
            ancestor[node] = parent[node];
            auto& linked = bucket[parent[node]];
            for (const auto child : linked) {
                const auto candidate = eval(child);
                immediateDominators_[child] = semiNumber(candidate) < semiNumber(child) ? candidate : parent[node];
                if (failed_) return;
            }
            linked.clear();
        }
        for (size_t i = 1; i < order.size(); ++i) {
            const auto node = order[i];
            if (immediateDominators_[node] != semi[node]) {
                immediateDominators_[node] = immediateDominators_[immediateDominators_[node]];
            }
        }
        for (const auto node : order) {
            if (node == cfg_.entry) continue;
            const auto dominator = immediateDominators_[node];
            if (dominator != npos) dominatorTree_[dominator].push_back(node);
        }

        size_t timer = 0;
        std::vector<std::pair<size_t, size_t>> treeStack = {{cfg_.entry, 0}};
        dominatorBegin_[cfg_.entry] = timer++;
        while (!treeStack.empty()) {
            auto& [current, child] = treeStack.back();
            if (child < dominatorTree_[current].size()) {
                const auto next = dominatorTree_[current][child++];
                dominatorBegin_[next] = timer++;
                treeStack.emplace_back(next, 0);
            } else {
                dominatorEnd_[current] = timer;
                treeStack.pop_back();
            }
        }
    }

    bool dominates(size_t dominator, size_t node) const {
        return dominator < cfg_.blocks.size() && node < cfg_.blocks.size() &&
            dominatorBegin_[dominator] != npos && dominatorBegin_[node] != npos &&
            dominatorBegin_[dominator] <= dominatorBegin_[node] &&
            dominatorEnd_[node] <= dominatorEnd_[dominator];
    }

    void findNaturalLoops() {
        for (size_t latch = 0; latch < cfg_.blocks.size(); ++latch) {
            if (!reachable_[latch]) continue;
            for (const auto header : cfg_.blocks[latch].successors) {
                if (!dominates(header, latch)) continue;
                auto loopIndex = loopHeaders_[header];
                if (loopIndex == npos) {
                    NaturalLoop loop;
                    loop.header = header;
                    loops_.push_back(std::move(loop));
                    loopIndex = loops_.size() - 1;
                    loopHeaders_[header] = loopIndex;
                }
                loops_[loopIndex].latches.push_back(latch);
            }
        }

        std::vector<size_t> marks(cfg_.blocks.size(), 0);
        std::vector<size_t> pending;
        for (size_t loopIndex = 0; loopIndex < loops_.size(); ++loopIndex) {
            auto& loop = loops_[loopIndex];
            const auto generation = loopIndex + 1;
            auto add = [&](size_t node) {
                if (marks[node] == generation) return;
                if (!spend()) return;
                marks[node] = generation;
                loop.nodes.push_back(node);
            };
            add(loop.header);
            for (const auto latch : loop.latches) {
                if (failed_) return;
                if (marks[latch] != generation) {
                    add(latch);
                    pending.push_back(latch);
                }
                while (!pending.empty()) {
                    if (!spend()) {
                        pending.clear();
                        return;
                    }
                    const auto current = pending.back();
                    pending.pop_back();
                    for (const auto predecessor : cfg_.blocks[current].predecessors) {
                        if (predecessor >= cfg_.blocks.size() || !reachable_[predecessor] || marks[predecessor] == generation) {
                            continue;
                        }
                        add(predecessor);
                        if (failed_) {
                            pending.clear();
                            return;
                        }
                        pending.push_back(predecessor);
                    }
                }
            }
            std::sort(loop.nodes.begin(), loop.nodes.end());
        }
    }

    static bool contains(const NaturalLoop& loop, size_t index) {
        return std::binary_search(loop.nodes.begin(), loop.nodes.end(), index);
    }

    bool isAllowed(size_t index, const AllowedSet& allowed) const {
        if (index >= cfg_.blocks.size() || !reachable_[index]) return false;
        if (!allowed.loop) return true;
        return index != allowed.excluded && contains(*allowed.loop, index);
    }

    bool loopAllowed(const NaturalLoop& loop, const AllowedSet& allowed) const {
        for (const auto index : loop.nodes) {
            if (!isAllowed(index, allowed)) return false;
        }
        return true;
    }

    bool onlyExitsFrom(const NaturalLoop& loop, size_t source, size_t exit) const {
        for (const auto index : loop.nodes) {
            for (const auto successor : cfg_.blocks[index].successors) {
                if (contains(loop, successor)) continue;
                if (index != source || successor != exit) return false;
            }
        }
        return true;
    }

    Reachability reachableFrom(size_t start, size_t stop, const AllowedSet& allowed) {
        Reachability result;
        result.visited.assign(cfg_.blocks.size(), false);
        result.distances.assign(cfg_.blocks.size(), npos);
        if (start == stop) {
            result.reachesStop = true;
            return result;
        }
        if (!isAllowed(start, allowed)) return result;

        std::queue<size_t> pending;
        pending.push(start);
        result.visited[start] = true;
        result.distances[start] = 0;
        while (!pending.empty() && !failed_) {
            if (!spend()) break;
            const auto current = pending.front();
            pending.pop();
            for (const auto successor : cfg_.blocks[current].successors) {
                if (successor == stop) {
                    result.reachesStop = true;
                    continue;
                }
                if (!isAllowed(successor, allowed) || result.visited[successor]) continue;
                result.visited[successor] = true;
                result.distances[successor] = result.distances[current] + 1;
                pending.push(successor);
            }
        }
        return result;
    }

    bool reachesOnlyThrough(size_t start, size_t candidate, size_t stop, const AllowedSet& allowed) {
        if (start == candidate) return true;
        if (start == stop || !isAllowed(start, allowed)) return false;
        struct Visit {
            size_t node;
            size_t next = 0;
        };
        std::vector<unsigned char> state(cfg_.blocks.size(), 0);
        std::vector<Visit> pending = {{start, 0}};
        state[start] = 1;
        while (!pending.empty()) {
            if (!spend()) return false;
            auto& visit = pending.back();
            const auto current = visit.node;
            const auto& block = cfg_.blocks[current];
            const auto* terminator = block.terminator();
            if ((terminator && terminator->kind == Statement::Kind::Return) || block.successors.empty()) {
                state[current] = 2;
                pending.pop_back();
                continue;
            }
            if (visit.next == block.successors.size()) {
                state[current] = 2;
                pending.pop_back();
                continue;
            }
            const auto successor = block.successors[visit.next++];
            if (successor == candidate) continue;
            if (successor == stop || !isAllowed(successor, allowed) || state[successor] == 1) return false;
            if (state[successor] == 2) continue;
            state[successor] = 1;
            pending.push_back({successor, 0});
        }
        return true;
    }

    size_t findJoin(size_t taken, size_t fallthrough, size_t stop, const AllowedSet& allowed) {
        if (taken == fallthrough) return taken;
        if (taken == stop || fallthrough == stop) return stop;
        auto takenReach = reachableFrom(taken, stop, allowed);
        auto fallthroughReach = reachableFrom(fallthrough, stop, allowed);
        if (failed_) return npos;
        std::vector<size_t> candidates;
        for (size_t i = 0; i < cfg_.blocks.size(); ++i) {
            if (takenReach.visited[i] && fallthroughReach.visited[i] && !consumed_[i]) candidates.push_back(i);
        }
        std::sort(candidates.begin(), candidates.end(), [&](size_t left, size_t right) {
            const auto leftMax = std::max(takenReach.distances[left], fallthroughReach.distances[left]);
            const auto rightMax = std::max(takenReach.distances[right], fallthroughReach.distances[right]);
            if (leftMax != rightMax) return leftMax < rightMax;
            const auto leftSum = takenReach.distances[left] + fallthroughReach.distances[left];
            const auto rightSum = takenReach.distances[right] + fallthroughReach.distances[right];
            if (leftSum != rightSum) return leftSum < rightSum;
            return left < right;
        });
        for (const auto candidate : candidates) {
            if (reachesOnlyThrough(taken, candidate, stop, allowed) &&
                reachesOnlyThrough(fallthrough, candidate, stop, allowed)) {
                return candidate;
            }
            if (failed_) return npos;
        }
        if (stop != npos && takenReach.reachesStop && fallthroughReach.reachesStop) return stop;
        return npos;
    }

    bool pushNestedParse(
        std::vector<Frame>& work,
        size_t index,
        size_t stop,
        AllowedSet allowed,
        size_t depth,
        bool ordinaryOnly = false) {
        if (depth > maxStructuredDepth) {
            failed_ = true;
            return false;
        }
        work.push_back(makeParse(index, stop, allowed, depth, ordinaryOnly));
        return true;
    }

    void process(Frame frame, std::vector<Frame>& work, std::vector<StructuredNodePtr>& results) {
        switch (frame.kind) {
        case FrameKind::ParseBlock: {
            if (frame.index == npos || frame.index == frame.stop) {
                results.push_back(makeEmpty());
                return;
            }
            if (!isAllowed(frame.index, frame.allowed) || consumed_[frame.index]) {
                fail();
                return;
            }
            const auto loopIndex = loopHeaders_[frame.index];
            if (!frame.ordinaryOnly && loopIndex != npos && loopAllowed(loops_[loopIndex], frame.allowed)) {
                frame.kind = FrameKind::ParseLoop;
                frame.loopIndex = loopIndex;
            } else {
                frame.kind = FrameKind::ParseOrdinary;
            }
            work.push_back(std::move(frame));
            return;
        }
        case FrameKind::ParseOrdinary: {
            if (frame.index == npos || frame.index == frame.stop) {
                results.push_back(makeEmpty());
                return;
            }
            if (!isAllowed(frame.index, frame.allowed) || consumed_[frame.index]) {
                fail();
                return;
            }
            consumed_[frame.index] = true;
            const auto& block = cfg_.blocks[frame.index];
            auto prefix = makeBlock(block);
            const auto* terminator = block.terminator();
            if (!terminator) {
                if (block.fallthroughSuccessor == npos) {
                    results.push_back(std::move(prefix));
                    return;
                }
                Frame next;
                next.kind = FrameKind::AfterNext;
                next.first = std::move(prefix);
                work.push_back(std::move(next));
                work.push_back(makeParse(block.fallthroughSuccessor, frame.stop, frame.allowed, frame.depth));
                return;
            }
            if (terminator->kind == Statement::Kind::Return) {
                results.push_back(makeSequence(std::move(prefix), makeReturn(*terminator)));
                return;
            }
            if (terminator->kind == Statement::Kind::Branch) {
                if (block.takenSuccessor == npos || block.successors.size() != 1) {
                    fail();
                    return;
                }
                Frame next;
                next.kind = FrameKind::AfterNext;
                next.first = std::move(prefix);
                work.push_back(std::move(next));
                work.push_back(makeParse(block.takenSuccessor, frame.stop, frame.allowed, frame.depth));
                return;
            }

            const auto taken = block.takenSuccessor;
            const auto fallthrough = block.fallthroughSuccessor;
            if (taken == npos || fallthrough == npos) {
                fail();
                return;
            }
            if (taken == fallthrough) {
                auto branch = makeNode(StructuredKind::IfElse);
                branch->condition = terminator->condition;
                branch->thenBranch = makeEmpty();
                branch->elseBranch = makeEmpty();
                Frame next;
                next.kind = FrameKind::AfterNext;
                next.first = std::move(prefix);
                next.second = std::move(branch);
                work.push_back(std::move(next));
                work.push_back(makeParse(taken, frame.stop, frame.allowed, frame.depth));
                return;
            }

            const auto join = findJoin(taken, fallthrough, frame.stop, frame.allowed);
            if (failed_) return;
            Frame afterThen;
            afterThen.kind = FrameKind::AfterThen;
            afterThen.index = fallthrough;
            afterThen.stop = frame.stop;
            afterThen.join = join;
            afterThen.allowed = frame.allowed;
            afterThen.depth = frame.depth;
            afterThen.address = terminator->address;
            afterThen.condition = terminator->condition;
            afterThen.first = std::move(prefix);
            work.push_back(std::move(afterThen));
            pushNestedParse(work, taken, join, frame.allowed, frame.depth + 1);
            return;
        }
        case FrameKind::AfterThen: {
            Frame afterElse;
            afterElse.kind = FrameKind::AfterElse;
            afterElse.stop = frame.stop;
            afterElse.join = frame.join;
            afterElse.allowed = frame.allowed;
            afterElse.depth = frame.depth;
            afterElse.address = frame.address;
            afterElse.condition = std::move(frame.condition);
            afterElse.first = std::move(frame.first);
            afterElse.second = takeResult(results);
            work.push_back(std::move(afterElse));
            pushNestedParse(work, frame.index, frame.join, frame.allowed, frame.depth + 1);
            return;
        }
        case FrameKind::AfterElse: {
            auto elseBranch = takeResult(results);
            auto branch = makeNode(StructuredKind::IfElse);
            branch->address = frame.address;
            branch->condition = std::move(frame.condition);
            branch->thenBranch = std::move(frame.second);
            branch->elseBranch = std::move(elseBranch);
            if (frame.join == npos) {
                results.push_back(makeSequence(std::move(frame.first), std::move(branch)));
                return;
            }
            Frame next;
            next.kind = FrameKind::AfterNext;
            next.first = std::move(frame.first);
            next.second = std::move(branch);
            work.push_back(std::move(next));
            work.push_back(makeParse(frame.join, frame.stop, frame.allowed, frame.depth));
            return;
        }
        case FrameKind::AfterNext: {
            auto next = takeResult(results);
            results.push_back(makeSequence(std::move(frame.first), std::move(frame.second), std::move(next)));
            return;
        }
        case FrameKind::ParseLoop: {
            const auto& loop = loops_[frame.loopIndex];
            const auto& header = cfg_.blocks[loop.header];
            const auto* headerTerminator = header.terminator();
            if (headerTerminator && headerTerminator->kind == Statement::Kind::ConditionalBranch) {
                const bool takenContinues = contains(loop, header.takenSuccessor);
                const bool fallthroughContinues = contains(loop, header.fallthroughSuccessor);
                if (takenContinues != fallthroughContinues) {
                    const auto continueIndex = takenContinues ? header.takenSuccessor : header.fallthroughSuccessor;
                    const auto exit = takenContinues ? header.fallthroughSuccessor : header.takenSuccessor;
                    if (exit == npos || (exit != frame.stop && !isAllowed(exit, frame.allowed)) ||
                        !onlyExitsFrom(loop, loop.header, exit)) {
                        fail();
                        return;
                    }
                    consumed_[loop.header] = true;
                    AllowedSet bodyAllowed{&loop, loop.header};
                    Frame afterBody;
                    afterBody.kind = FrameKind::AfterWhileBody;
                    afterBody.stop = frame.stop;
                    afterBody.exit = exit;
                    afterBody.loopIndex = frame.loopIndex;
                    afterBody.depth = frame.depth;
                    afterBody.allowed = frame.allowed;
                    afterBody.taken = takenContinues;
                    afterBody.address = header.address;
                    afterBody.condition = headerTerminator->condition;
                    work.push_back(std::move(afterBody));
                    if (continueIndex == loop.header) {
                        results.push_back(makeEmpty());
                    } else {
                        pushNestedParse(work, continueIndex, loop.header, bodyAllowed, frame.depth + 1);
                    }
                    return;
                }
            }

            if (loop.latches.size() != 1 || header.successors.size() != 1) {
                fail();
                return;
            }
            const auto latchIndex = loop.latches.front();
            if (latchIndex == loop.header) {
                fail();
                return;
            }
            const auto& latch = cfg_.blocks[latchIndex];
            const auto* latchTerminator = latch.terminator();
            if (!latchTerminator || latchTerminator->kind != Statement::Kind::ConditionalBranch) {
                fail();
                return;
            }
            const bool takenRepeats = latch.takenSuccessor == loop.header;
            const bool fallthroughRepeats = latch.fallthroughSuccessor == loop.header;
            if (takenRepeats == fallthroughRepeats) {
                fail();
                return;
            }
            const auto exit = takenRepeats ? latch.fallthroughSuccessor : latch.takenSuccessor;
            if (exit == npos || (exit != frame.stop && !isAllowed(exit, frame.allowed)) ||
                !onlyExitsFrom(loop, latchIndex, exit)) {
                fail();
                return;
            }

            AllowedSet bodyAllowed{&loop, latchIndex};
            Frame afterBody;
            afterBody.kind = FrameKind::AfterDoBody;
            afterBody.stop = frame.stop;
            afterBody.exit = exit;
            afterBody.index = latchIndex;
            afterBody.loopIndex = frame.loopIndex;
            afterBody.depth = frame.depth;
            afterBody.allowed = frame.allowed;
            afterBody.taken = takenRepeats;
            afterBody.address = header.address;
            afterBody.condition = latchTerminator->condition;
            work.push_back(std::move(afterBody));
            pushNestedParse(work, loop.header, latchIndex, bodyAllowed, frame.depth + 1, true);
            return;
        }
        case FrameKind::AfterWhileBody: {
            const auto& loop = loops_[frame.loopIndex];
            auto body = takeResult(results);
            for (const auto index : loop.nodes) {
                if (!consumed_[index]) failed_ = true;
            }
            if (failed_) return;
            body = makeSequence(std::move(body), makeBlock(cfg_.blocks[loop.header], false));
            auto loopNode = makeNode(StructuredKind::While);
            loopNode->address = frame.address;
            loopNode->condition = frame.taken ? std::move(frame.condition) : negated(frame.condition);
            loopNode->body = std::move(body);
            Frame next;
            next.kind = FrameKind::AfterNext;
            next.first = makeBlock(cfg_.blocks[loop.header]);
            next.second = std::move(loopNode);
            work.push_back(std::move(next));
            work.push_back(makeParse(frame.exit, frame.stop, frame.allowed, frame.depth));
            return;
        }
        case FrameKind::AfterDoBody: {
            const auto& loop = loops_[frame.loopIndex];
            auto body = takeResult(results);
            for (const auto index : loop.nodes) {
                if (index != frame.index && !consumed_[index]) failed_ = true;
            }
            if (failed_) return;
            consumed_[frame.index] = true;
            auto loopNode = makeNode(StructuredKind::DoWhile);
            loopNode->address = frame.address;
            loopNode->condition = frame.taken ? std::move(frame.condition) : negated(frame.condition);
            loopNode->body = std::move(body);
            Frame next;
            next.kind = FrameKind::AfterNext;
            next.second = std::move(loopNode);
            work.push_back(std::move(next));
            work.push_back(makeParse(frame.exit, frame.stop, frame.allowed, frame.depth));
            return;
        }
        }
    }

    StructuredNodePtr makeFlatFallback() const {
        std::vector<StructuredNodePtr> nodes;
        for (size_t i = 0; i < cfg_.blocks.size(); ++i) {
            const auto& block = cfg_.blocks[i];
            nodes.push_back(makeBlock(block));
            const auto* terminator = block.terminator();
            if (!terminator) {
                if (block.fallthroughSuccessor != npos) {
                    nodes.push_back(makeGoto(cfg_.blocks[block.fallthroughSuccessor]));
                }
                continue;
            }
            if (terminator->kind == Statement::Kind::Return) {
                nodes.push_back(makeReturn(*terminator));
                continue;
            }
            if (terminator->kind == Statement::Kind::Branch) {
                nodes.push_back(makeGoto(*terminator));
                continue;
            }

            auto branch = makeNode(StructuredKind::IfElse);
            branch->address = terminator->address;
            branch->condition = terminator->condition;
            branch->thenBranch = makeGoto(*terminator);
            if (block.fallthroughSuccessor != npos) {
                branch->elseBranch = makeGoto(cfg_.blocks[block.fallthroughSuccessor]);
            }
            nodes.push_back(std::move(branch));
        }
        return makeSequence(std::move(nodes));
    }
};

} // namespace

const Statement* CFGBlock::terminator() const {
    if (!source || terminatorIndex == npos || terminatorIndex >= source->statements.size()) return nullptr;
    return &source->statements[terminatorIndex];
}

ControlFlowGraph::ControlFlowGraph(const RecoveredFunction& function) {
    const auto sourceCount = function.blocks.size();
    blocks.reserve(sourceCount);
    std::vector<size_t> first(sourceCount, npos);
    std::vector<size_t> openFallthrough(sourceCount, npos);

    auto appendBlock = [&](size_t sourceIndex, size_t begin, size_t end, size_t terminatorIndex) {
        const auto& source = function.blocks[sourceIndex];
        CFGBlock block;
        block.index = blocks.size();
        block.sourceIndex = sourceIndex;
        block.source = &source;
        block.address = begin == 0 ? source.address : source.statements[begin].address;
        block.statementBegin = begin;
        block.statementEnd = end;
        block.terminatorIndex = terminatorIndex;
        blocks.push_back(std::move(block));
        return blocks.size() - 1;
    };

    for (size_t sourceIndex = 0; sourceIndex < sourceCount; ++sourceIndex) {
        const auto& source = function.blocks[sourceIndex];
        if (source.statements.empty()) {
            const auto current = appendBlock(sourceIndex, 0, 0, npos);
            first[sourceIndex] = current;
            openFallthrough[sourceIndex] = current;
            continue;
        }

        size_t begin = 0;
        size_t previous = npos;
        while (begin < source.statements.size()) {
            size_t end = begin;
            while (end < source.statements.size() && !isControlStatement(source.statements[end].kind)) ++end;
            const bool hasTerminator = end < source.statements.size();
            const auto current = appendBlock(sourceIndex, begin, end, hasTerminator ? end : npos);
            if (first[sourceIndex] == npos) first[sourceIndex] = current;
            if (previous != npos) blocks[previous].fallthroughSuccessor = current;

            if (!hasTerminator) {
                previous = current;
                break;
            }
            const auto kind = source.statements[end].kind;
            if (kind == Statement::Kind::ConditionalBranch) {
                previous = current;
                if (end + 1 < source.statements.size()) {
                    begin = end + 1;
                    continue;
                }
                break;
            }
            previous = npos;
            break;
        }
        openFallthrough[sourceIndex] = previous;
    }

    for (size_t sourceIndex = 0; sourceIndex < sourceCount; ++sourceIndex) {
        blockIndices.emplace(function.blocks[sourceIndex].address, first[sourceIndex]);
        if (openFallthrough[sourceIndex] != npos && sourceIndex + 1 < sourceCount && first[sourceIndex + 1] != npos) {
            blocks[openFallthrough[sourceIndex]].fallthroughSuccessor = first[sourceIndex + 1];
        }
    }
    for (const auto& block : blocks) blockIndices.emplace(block.address, block.index);

    auto directSuccessor = [&](const Statement* statement) {
        if (!statement || !statement->target || statement->target->kind != Expression::Kind::Constant) return npos;
        const auto found = blockIndices.find(statement->target->constant);
        return found == blockIndices.end() ? npos : found->second;
    };
    auto addSuccessor = [&](size_t source, size_t successor) {
        if (successor == npos) return;
        auto& successors = blocks[source].successors;
        if (std::find(successors.begin(), successors.end(), successor) == successors.end()) {
            successors.push_back(successor);
        }
    };

    for (size_t i = 0; i < blocks.size(); ++i) {
        const auto* terminator = blocks[i].terminator();
        if (terminator && terminator->kind == Statement::Kind::Branch) {
            blocks[i].takenSuccessor = directSuccessor(terminator);
            blocks[i].fallthroughSuccessor = npos;
            addSuccessor(i, blocks[i].takenSuccessor);
        } else if (terminator && terminator->kind == Statement::Kind::ConditionalBranch) {
            blocks[i].takenSuccessor = directSuccessor(terminator);
            addSuccessor(i, blocks[i].takenSuccessor);
            addSuccessor(i, blocks[i].fallthroughSuccessor);
        } else if (terminator && terminator->kind == Statement::Kind::Return) {
            blocks[i].takenSuccessor = npos;
            blocks[i].fallthroughSuccessor = npos;
        } else {
            addSuccessor(i, blocks[i].fallthroughSuccessor);
        }
    }

    for (size_t i = 0; i < blocks.size(); ++i) {
        for (const auto successor : blocks[i].successors) blocks[successor].predecessors.push_back(i);
    }

    const auto entryByAddress = blockIndices.find(function.address);
    if (entryByAddress != blockIndices.end()) {
        entry = entryByAddress->second;
    } else if (!first.empty()) {
        entry = first.front();
    }
}

const CFGBlock* ControlFlowGraph::find(uint64_t address) const {
    const auto found = blockIndices.find(address);
    return found == blockIndices.end() ? nullptr : &blocks[found->second];
}

size_t ControlFlowGraph::indexOf(uint64_t address) const {
    const auto found = blockIndices.find(address);
    return found == blockIndices.end() ? npos : found->second;
}

StructuredFunction::StructuredFunction(const RecoveredFunction& function)
    : cfg(function) {}

StructuredFunction Structurer::structure(const RecoveredFunction& function) const {
    StructuredFunction result(function);
    result.root = RegionStructurer(result.cfg).run();
    return result;
}

} // namespace il2cpprec::flow
