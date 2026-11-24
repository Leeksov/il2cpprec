#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <unordered_map>
#include <vector>

#include <il2cpprec/IR.hpp>

namespace il2cpprec::flow {

struct CFGBlock {
    static constexpr size_t npos = std::numeric_limits<size_t>::max();

    size_t index = npos;
    size_t sourceIndex = npos;
    const BasicBlock* source = nullptr;
    uint64_t address = 0;
    size_t statementBegin = 0;
    size_t statementEnd = 0;
    size_t terminatorIndex = npos;
    size_t takenSuccessor = npos;
    size_t fallthroughSuccessor = npos;
    std::vector<size_t> successors;
    std::vector<size_t> predecessors;

    const Statement* terminator() const;
};

class ControlFlowGraph {
public:
    static constexpr size_t npos = CFGBlock::npos;

    explicit ControlFlowGraph(const RecoveredFunction& function);

    const CFGBlock* find(uint64_t address) const;
    size_t indexOf(uint64_t address) const;

    std::vector<CFGBlock> blocks;
    std::unordered_map<uint64_t, size_t> blockIndices;
    size_t entry = npos;
};

enum class StructuredKind {
    Empty,
    Block,
    Sequence,
    IfElse,
    While,
    DoWhile,
    Goto,
    Return
};

struct StructuredNode;
using StructuredNodePtr = std::unique_ptr<StructuredNode>;

struct StructuredNode {
    StructuredKind kind = StructuredKind::Empty;
    uint64_t address = 0;
    bool isLabel = false;
    std::vector<Statement> statements;
    std::vector<StructuredNodePtr> children;
    ExpressionPtr condition;
    StructuredNodePtr thenBranch;
    StructuredNodePtr elseBranch;
    StructuredNodePtr body;
    uint64_t target = 0;
    ExpressionPtr targetExpression;
    Statement returnStatement;
};

struct StructuredFunction {
    explicit StructuredFunction(const RecoveredFunction& function);

    ControlFlowGraph cfg;
    StructuredNodePtr root;
};

class Structurer {
public:
    StructuredFunction structure(const RecoveredFunction& function) const;
};

} // namespace il2cpprec::flow
