#include "TestSupport.hpp"

#include <il2cpprec/Recovery.hpp>
#include <il2cpprec/flow/SSA.hpp>
#include <il2cpprec/flow/Structurer.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace il2cpprec::tests {
namespace {

RecoveredFunction recover(
    Architecture architecture,
    uint64_t address,
    std::string name,
    const std::vector<uint8_t>& code) {
    return Recovery{}.recover({architecture, address, code.data(), code.size(), std::move(name)});
}

void checkArchitectureGolden(
    Architecture architecture,
    const std::string& slug,
    const std::string& name,
    uint64_t address,
    const std::vector<uint8_t>& code) {
    const auto function = recover(architecture, address, name, code);
    const auto repeated = recover(architecture, address, name, code);
    const auto ir = serializeFunction(function);
    CHECK_EQ(serializeFunction(repeated), ir);
    CHECK_EQ(repeated.toCSharp(), function.toCSharp());
    checkGolden("core/golden/" + slug + ".ir.txt", ir);
    checkGolden("core/golden/" + slug + ".cs", function.toCSharp());
}

Statement assign(uint64_t address, const std::string& destination, ExpressionPtr value) {
    Statement statement;
    statement.kind = Statement::Kind::Assign;
    statement.address = address;
    statement.destination = reg(destination, ScalarType::pointer(64));
    statement.value = std::move(value);
    return statement;
}

Statement typedAssign(uint64_t address, const std::string& destination, ScalarType type, ExpressionPtr value) {
    Statement statement;
    statement.kind = Statement::Kind::Assign;
    statement.address = address;
    statement.destination = reg(destination, type);
    statement.value = std::move(value);
    return statement;
}

Statement branch(uint64_t address, uint64_t target, ExpressionPtr condition = {}) {
    Statement statement;
    statement.kind = condition ? Statement::Kind::ConditionalBranch : Statement::Kind::Branch;
    statement.address = address;
    statement.condition = std::move(condition);
    statement.target = constant(target, ScalarType::pointer(64));
    return statement;
}

Statement returnValue(uint64_t address, ExpressionPtr value) {
    Statement statement;
    statement.kind = Statement::Kind::Return;
    statement.address = address;
    statement.value = std::move(value);
    return statement;
}

ExpressionPtr zero() {
    return constant(0, ScalarType::pointer(64));
}

ExpressionPtr one() {
    return constant(1, ScalarType::pointer(64));
}

ExpressionPtr x0() {
    return reg("x0", ScalarType::pointer(64));
}

ExpressionPtr x1() {
    return reg("x1", ScalarType::pointer(64));
}

ExpressionPtr lessThanTen() {
    return binary("<", x0(), constant(10, ScalarType::pointer(64)), ScalarType::boolean());
}

RecoveredFunction function(std::string name, uint64_t address, std::vector<BasicBlock> blocks) {
    RecoveredFunction result;
    result.architecture = Architecture::X64;
    result.address = address;
    result.name = std::move(name);
    result.blocks = std::move(blocks);
    return result;
}

RecoveredFunction ifElseFunction() {
    return function("IfElse", 0x1000, {
        {0x1000, {
            branch(0x1000, 0x1010, binary("==", x0(), zero(), ScalarType::boolean())),
            assign(0x1004, "x1", one()),
            branch(0x1008, 0x1020)
        }},
        {0x1010, {assign(0x1010, "x1", constant(2, ScalarType::pointer(64))), branch(0x1014, 0x1020)}},
        {0x1020, {returnValue(0x1020, x1())}},
    });
}

RecoveredFunction earlyReturnFunction() {
    return function("EarlyReturn", 0x2000, {
        {0x2000, {
            branch(0x2000, 0x2010, binary("==", x0(), zero(), ScalarType::boolean())),
            returnValue(0x2004, one())
        }},
        {0x2010, {returnValue(0x2010, constant(2, ScalarType::pointer(64)))}},
    });
}

RecoveredFunction whileFunction() {
    return function("WhileLoop", 0x3000, {
        {0x3000, {
            branch(0x3000, 0x3010, lessThanTen()),
            returnValue(0x3004, x0())
        }},
        {0x3010, {assign(0x3010, "x0", binary("+", x0(), one(), ScalarType::pointer(64))), branch(0x3014, 0x3000)}},
    });
}

RecoveredFunction doWhileFunction() {
    return function("DoWhileLoop", 0x4000, {
        {0x4000, {
            assign(0x4000, "x0", binary("+", x0(), one(), ScalarType::pointer(64))),
            branch(0x4004, 0x4004)
        }},
        {0x4004, {
            branch(0x4004, 0x4000, lessThanTen()),
            returnValue(0x4008, x0())
        }},
    });
}

RecoveredFunction sharedJoinFunction() {
    return function("SharedJoin", 0x5000, {
        {0x5000, {
            branch(0x5000, 0x5010, binary("==", x0(), zero(), ScalarType::boolean())),
            assign(0x5004, "x1", one()),
            branch(0x5008, 0x5020)
        }},
        {0x5010, {assign(0x5010, "x1", constant(2, ScalarType::pointer(64))), branch(0x5014, 0x5020)}},
        {0x5020, {
            branch(0x5020, 0x5030, binary("==", x1(), zero(), ScalarType::boolean())),
            assign(0x5024, "x0", constant(3, ScalarType::pointer(64))),
            branch(0x5028, 0x5040)
        }},
        {0x5030, {assign(0x5030, "x0", constant(4, ScalarType::pointer(64))), branch(0x5034, 0x5040)}},
        {0x5040, {returnValue(0x5040, x1())}},
    });
}

size_t countKind(const flow::StructuredNodePtr& node, flow::StructuredKind kind) {
    if (!node) return 0;
    size_t result = node->kind == kind ? 1 : 0;
    for (const auto& child : node->children) result += countKind(child, kind);
    result += countKind(node->thenBranch, kind);
    result += countKind(node->elseBranch, kind);
    result += countKind(node->body, kind);
    return result;
}

size_t countSubstring(const std::string& text, const std::string& needle) {
    size_t count = 0;
    size_t position = 0;
    while ((position = text.find(needle, position)) != std::string::npos) {
        ++count;
        position += needle.size();
    }
    return count;
}

void checkFlowGolden(
    const std::string& slug,
    const RecoveredFunction& function,
    flow::StructuredKind kind,
    size_t expectedKindCount) {
    const auto csharp = function.toCSharp();
    checkGolden("core/golden/" + slug + ".ir.txt", serializeFunction(function));
    checkGolden("core/golden/" + slug + ".cs", csharp);
    const auto structured = flow::Structurer{}.structure(function);
    CHECK(structured.root != nullptr);
    CHECK_EQ(countKind(structured.root, kind), expectedKindCount);
    CHECK_EQ(csharp.find("goto"), std::string::npos);
}

void checkExpressionTypes(
    const ExpressionPtr& expression,
    std::map<std::string, ScalarType>& registers) {
    if (!expression) return;
    if (expression->kind == Expression::Kind::Load) {
        CHECK(expression->type.bits != 0);
        CHECK(expression->type.bits <= 64);
    }
    if (expression->kind == Expression::Kind::Register) {
        auto [current, inserted] = registers.emplace(expression->name, expression->type);
        if (!inserted) {
            CHECK_EQ(static_cast<int>(current->second.kind), static_cast<int>(expression->type.kind));
            CHECK_EQ(current->second.bits, expression->type.bits);
        }
    }
    for (const auto& argument : expression->arguments) checkExpressionTypes(argument, registers);
}

void checkArm32Types(const std::vector<uint8_t>& code, Arm32Mode mode) {
    FunctionImage image;
    image.architecture = Architecture::Arm32;
    image.address = 0x1000;
    image.code = code.data();
    image.size = code.size();
    image.name = "Arm32TypeProbe";
    image.arm32Mode = mode;
    const auto function = Recovery{}.recover(image);
    std::map<std::string, ScalarType> registers;
    for (const auto& block : function.blocks) {
        for (const auto& statement : block.statements) {
            checkExpressionTypes(statement.destination, registers);
            checkExpressionTypes(statement.value, registers);
            checkExpressionTypes(statement.condition, registers);
            checkExpressionTypes(statement.target, registers);
            for (const auto& argument : statement.arguments) checkExpressionTypes(argument, registers);
        }
    }
    CHECK(!function.emitCSharp().partial);
}

void checkX86Types(Architecture architecture, const std::vector<uint8_t>& code) {
    const auto function = recover(architecture, 0x1000, "X86TypeProbe", code);
    std::map<std::string, ScalarType> registers;
    for (const auto& block : function.blocks) {
        for (const auto& statement : block.statements) {
            checkExpressionTypes(statement.destination, registers);
            checkExpressionTypes(statement.value, registers);
            checkExpressionTypes(statement.condition, registers);
            checkExpressionTypes(statement.target, registers);
            for (const auto& argument : statement.arguments) checkExpressionTypes(argument, registers);
        }
    }
    CHECK(!function.emitCSharp().partial);
}

} // namespace

TEST_CASE("golden ARM32 IR and C#") {
    checkArchitectureGolden(Architecture::Arm32, "add_one_arm32", "AddOneArm32", 0x4000,
        {0x80, 0x00, 0x80, 0xE0, 0x01, 0x00, 0x40, 0xE2, 0x1E, 0xFF, 0x2F, 0xE1});
}

TEST_CASE("golden ARM64 IR and C#") {
    checkArchitectureGolden(Architecture::Arm64, "add_one_arm64", "AddOneArm64", 0x1000,
        {0xE0, 0x03, 0x01, 0xAA, 0x00, 0x00, 0x40, 0x91, 0xC0, 0x03, 0x5F, 0xD6});
}

TEST_CASE("golden x86 IR and C#") {
    checkArchitectureGolden(Architecture::X86, "add_one_x86", "AddOneX86", 0x6000,
        {0x89, 0xC8, 0x83, 0xC0, 0x01, 0xC3});
}

TEST_CASE("golden x64 IR and C#") {
    checkArchitectureGolden(Architecture::X64, "add_one_x64", "AddOneX64", 0x2000,
        {0x48, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x01, 0xC3});
}

TEST_CASE("x86 scalar SSE keeps compatible raw XMM types") {
    const std::vector<uint8_t> code{
        0xF3, 0x0F, 0x2A, 0xC1, 0xF3, 0x0F, 0x2A, 0xCA,
        0xF3, 0x0F, 0x58, 0xC1, 0x66, 0x0F, 0x7E, 0xC0, 0xC3,
    };
    for (const auto architecture : {Architecture::X86, Architecture::X64}) {
        checkX86Types(architecture, code);
    }
}

TEST_CASE("x86 packed SSE splits memory and register lanes without conflicts") {
    const std::vector<std::vector<uint8_t>> probes{
        {
            0x0F, 0x28, 0x05, 0, 0, 0, 0, 0x0F, 0x58, 0xC1,
            0x0F, 0x29, 0x05, 0, 0, 0, 0, 0x66, 0x0F, 0x7E, 0xC0, 0xC3,
        },
        {0xF3, 0x0F, 0x2A, 0xC1, 0x0F, 0x58, 0xC1, 0x66, 0x0F, 0x7E, 0xC0, 0xC3},
        {0x0F, 0x57, 0x05, 0, 0, 0, 0, 0x66, 0x0F, 0x7E, 0xC0, 0xC3},
        {0xF3, 0x0F, 0xE6, 0xC1, 0xF2, 0x0F, 0xE6, 0xC0, 0x66, 0x0F, 0x7E, 0xC0, 0xC3},
    };
    for (const auto architecture : {Architecture::X86, Architecture::X64}) {
        for (const auto& probe : probes) checkX86Types(architecture, probe);
    }
}

TEST_CASE("if/else has one shared join") {
    const auto function = ifElseFunction();
    checkFlowGolden("if_else", function, flow::StructuredKind::IfElse, 1);
    CHECK_EQ(countSubstring(function.toCSharp(), "return x1;"), 1);
}

TEST_CASE("early returns remain in both branches") {
    checkFlowGolden("early_return", earlyReturnFunction(), flow::StructuredKind::Return, 2);
}

TEST_CASE("while loop is structured") {
    checkFlowGolden("while_loop", whileFunction(), flow::StructuredKind::While, 1);
}

TEST_CASE("do/while loop is structured") {
    const auto function = doWhileFunction();
    const flow::ControlFlowGraph cfg(function);
    CHECK_EQ(cfg.blocks.size(), 3);
    CHECK(cfg.blocks[0].terminator() != nullptr);
    CHECK(cfg.blocks[0].terminator()->kind == Statement::Kind::Branch);
    CHECK(cfg.blocks[1].terminator() != nullptr);
    CHECK(cfg.blocks[1].terminator()->kind == Statement::Kind::ConditionalBranch);
    CHECK_EQ(cfg.blocks[1].takenSuccessor, 0);
    CHECK_EQ(cfg.blocks[1].fallthroughSuccessor, 2);
    checkFlowGolden("do_while_loop", function, flow::StructuredKind::DoWhile, 1);
}

TEST_CASE("nested conditions share joins without duplication") {
    const auto function = sharedJoinFunction();
    checkFlowGolden("shared_join", function, flow::StructuredKind::IfElse, 2);
    CHECK_EQ(countSubstring(function.toCSharp(), "return x1;"), 1);
    CHECK_EQ(countSubstring(function.toCSharp(), "x1 = 0x2UL;"), 1);
}

TEST_CASE("ARM32 memory loads have explicit widths") {
    checkArm32Types({
        0x00, 0x00, 0xD1, 0xE5, 0x00, 0x00, 0xC1, 0xE5,
        0xB0, 0x20, 0xD1, 0xE1, 0xB0, 0x20, 0xC1, 0xE1,
        0xD0, 0x00, 0xD1, 0xE1, 0xF0, 0x00, 0xD1, 0xE1,
        0x1E, 0xFF, 0x2F, 0xE1,
    }, Arm32Mode::Arm);
}

TEST_CASE("Thumb memory loads have explicit widths") {
    checkArm32Types({
        0x08, 0x78, 0x08, 0x70, 0x0A, 0x88, 0x0A, 0x80,
        0x91, 0xF9, 0x00, 0x00, 0xB1, 0xF9, 0x00, 0x00, 0x70, 0x47,
    }, Arm32Mode::Thumb);
}

TEST_CASE("ARM32 VFP conversions keep typed register views") {
    checkArm32Types({
        0x10, 0x0A, 0x00, 0xEE, 0xC0, 0x0A, 0xB8, 0xEE,
        0x90, 0x1A, 0x00, 0xEE, 0xE0, 0x0A, 0xF8, 0xEE,
        0x20, 0x0A, 0x30, 0xEE, 0x10, 0x0A, 0x10, 0xEE,
        0x1E, 0xFF, 0x2F, 0xE1,
    }, Arm32Mode::Arm);
    checkArm32Types({
        0x10, 0x0A, 0x00, 0xEE, 0xC0, 0x0A, 0xB8, 0xEE,
        0x40, 0x0A, 0xBD, 0xEE, 0x10, 0x0A, 0x10, 0xEE,
        0x1E, 0xFF, 0x2F, 0xE1,
    }, Arm32Mode::Arm);
}

TEST_CASE("SSA preserves load widths across copies and DCE") {
    const auto pointer = ScalarType::pointer(64);
    const auto word = ScalarType::uintBits(32);
    auto original = function("SSALoadWidth", 0x6000, {{0x6000, {
        assign(0x6000, "v0", constant(0, pointer)),
        assign(0x6004, "v8", constant(0, pointer)),
        assign(0x6008, "v8", reg("v0", pointer)),
        typedAssign(0x600C, "x0", word, load(reg("v8", pointer), word)),
        returnValue(0x6010, reg("x0", word)),
    }}});
    const auto transformed = flow::SSA{}.transform(original);
    const auto snapshot = serializeFunction(transformed);
    CHECK(snapshot.find("load<u32>") != std::string::npos);
    CHECK(snapshot.find("load<unknown0>") == std::string::npos);
    CHECK_EQ(transformed.blocks.at(0).statements.size(), 4);
    const auto& loadAssignment = transformed.blocks.at(0).statements.at(2);
    CHECK(loadAssignment.value->kind == Expression::Kind::Load);
    CHECK_EQ(loadAssignment.value->type.bits, 32);
    CHECK(loadAssignment.value->type.kind == ScalarKind::UnsignedInteger);
    CHECK_EQ(serializeFunction(flow::transform(original)), snapshot);
}

TEST_CASE("SSA does not merge conflicting v0 and v8 definitions") {
    const auto single = ScalarType::floatBits(32);
    const auto vector = ScalarType::vectorBits(128);
    auto original = function("SSAVectorMerge", 0x7000, {
        {0x7000, {branch(0x7000, 0x7020, binary("==", x0(), zero(), ScalarType::boolean()))}},
        {0x7010, {typedAssign(0x7010, "v0", vector, constant(0, vector)), branch(0x7014, 0x7030)}},
        {0x7020, {typedAssign(0x7020, "v0", single, constant(0, single)), branch(0x7024, 0x7030)}},
        {0x7030, {branch(0x7030, 0x7050, binary("==", x0(), zero(), ScalarType::boolean()))}},
        {0x7040, {typedAssign(0x7040, "v8", vector, reg("v0", vector)), branch(0x7044, 0x7060)}},
        {0x7050, {typedAssign(0x7050, "v8", single, reg("v0", single)), branch(0x7054, 0x7060)}},
        {0x7060, {
            typedAssign(0x7060, "v8", single, reg("v0", single)),
            returnValue(0x7064, reg("v8", single)),
        }},
    });
    const auto transformed = flow::SSA{}.transform(original);
    CHECK_EQ(serializeFunction(transformed), serializeFunction(flow::transform(original)));
    CHECK_EQ(transformed.blocks.at(6).statements.size(), 2);
    const auto& mergeCopy = transformed.blocks.at(6).statements.at(0);
    CHECK(mergeCopy.value->kind == Expression::Kind::Register);
    CHECK(mergeCopy.destination->type.kind == ScalarKind::FloatingPoint);
    CHECK_EQ(mergeCopy.destination->type.bits, 32);
}

TEST_CASE("SSA keeps Unknown expressions and unresolved call inputs") {
    const auto pointer = ScalarType::pointer(64);
    Statement unresolved;
    unresolved.kind = Statement::Kind::Call;
    unresolved.address = 0x9008;
    unresolved.target = unknown(pointer);
    auto original = function("SSAUnknownCall", 0x9000, {{0x9000, {
        typedAssign(0x9000, "v0", pointer, select(
            reg("condition", ScalarType::boolean()), unknown(pointer), constant(1, pointer), pointer)),
        typedAssign(0x9004, "x1", pointer, constant(7, pointer)),
        unresolved,
        returnValue(0x900C, constant(0, pointer)),
    }}});
    const auto transformed = flow::SSA{}.transform(original);
    CHECK_EQ(transformed.blocks.at(0).statements.size(), 4);
    CHECK(transformed.blocks.at(0).statements.at(0).value->kind == Expression::Kind::Select);
    CHECK(transformed.blocks.at(0).statements.at(1).destination->name == "x1");
    CHECK(transformed.blocks.at(0).statements.at(2).kind == Statement::Kind::Call);
}

TEST_CASE("SSA does not carry value numbers across calls") {
    const auto pointer = ScalarType::pointer(64);
    Statement direct;
    direct.kind = Statement::Kind::Call;
    direct.address = 0xA004;
    direct.target = constant(0x5000, pointer);
    direct.destination = reg("x0", pointer);
    auto original = function("SSACallClobber", 0xA000, {{0xA000, {
        typedAssign(0xA000, "x1", pointer, constant(5, pointer)),
        direct,
        typedAssign(0xA008, "x1", pointer, constant(5, pointer)),
        returnValue(0xA00C, reg("x1", pointer)),
    }}});
    const auto transformed = flow::SSA{}.transform(original);
    CHECK_EQ(transformed.blocks.at(0).statements.size(), 3);
    CHECK(transformed.blocks.at(0).statements.at(0).kind == Statement::Kind::Call);
    CHECK_EQ(transformed.blocks.at(0).statements.at(1).address, 0xA008);
}

TEST_CASE("SSA preserves definitions used by exception handlers") {
    const auto pointer = ScalarType::pointer(64);
    auto original = function("SSAExceptionFlow", 0x8000, {
        {0x8000, {
            typedAssign(0x8000, "x1", pointer, constant(7, pointer)),
            branch(0x8004, 0x8030),
        }},
        {0x8020, {returnValue(0x8020, reg("x1", pointer))}},
        {0x8030, {returnValue(0x8030, constant(0, pointer))}},
    });
    original.exceptionRegions = {{0x8000, 0x8010, 0x8020, 0x8030, ExceptionRegionKind::Catch}};
    const auto transformed = flow::SSA{}.transform(original);
    CHECK_EQ(serializeFunction(transformed), serializeFunction(original));
    CHECK_EQ(transformed.exceptionRegions.size(), 1);
    CHECK_EQ(transformed.blocks.at(0).statements.size(), 2);

    auto exceptionState = function("SSAExceptionState", 0x8800, {{0x8800, {
        typedAssign(0x8800, "__leave_target", pointer, constant(0, pointer)),
        returnValue(0x8804, constant(0, pointer)),
    }}});
    CHECK_EQ(flow::SSA{}.transform(exceptionState).blocks.at(0).statements.size(), 2);
}

TEST_CASE("SSA validates FP comparisons and select arm types") {
    const auto single = ScalarType::floatBits(32);
    const auto vector = ScalarType::vectorBits(128);
    const auto boolean = ScalarType::boolean();
    auto valid = function("SSAFloatSelect", 0xB000, {{0xB000, {
        typedAssign(0xB000, "v0", boolean, binary("<", reg("v1", single), reg("v2", single), boolean)),
        typedAssign(0xB004, "v8", single, select(
            reg("v0", boolean), constant(1, single), constant(0, single), single)),
        returnValue(0xB008, reg("v8", single)),
    }}});
    const auto validResult = flow::SSA{}.transform(valid);
    CHECK_EQ(validResult.blocks.at(0).statements.size(), 3);
    CHECK(validResult.blocks.at(0).statements.at(0).value->type.kind == ScalarKind::Boolean);
    CHECK(validResult.blocks.at(0).statements.at(1).value->type.kind == ScalarKind::FloatingPoint);
    CHECK_EQ(validResult.blocks.at(0).statements.at(1).value->type.bits, 32);

    auto conflicting = function("SSAConflictingSelect", 0xB100, {{0xB100, {
        typedAssign(0xB100, "v0", single, select(
            reg("condition", boolean), constant(1, single), constant(0, vector), single)),
        typedAssign(0xB104, "v8", single, reg("v0", single)),
        typedAssign(0xB108, "v8", single, reg("v0", single)),
        returnValue(0xB10C, reg("v8", single)),
    }}});
    const auto conflictingResult = flow::SSA{}.transform(conflicting);
    CHECK_EQ(conflictingResult.blocks.at(0).statements.size(), 3);
    CHECK_EQ(conflictingResult.blocks.at(0).statements.at(1).address, 0xB108);
    CHECK(conflictingResult.blocks.at(0).statements.at(0).value->kind == Expression::Kind::Select);
    CHECK_EQ(conflictingResult.blocks.at(0).statements.at(0).value->arguments.at(1)->type.bits, 32);
    CHECK_EQ(conflictingResult.blocks.at(0).statements.at(0).value->arguments.at(2)->type.bits, 128);
}

} // namespace il2cpprec::tests
