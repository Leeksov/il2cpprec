#include "TestSupport.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <utility>

namespace il2cpprec::tests {
namespace {

std::string hex(uint64_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << std::uppercase << value;
    return output.str();
}

std::string architectureName(Architecture architecture) {
    switch (architecture) {
    case Architecture::Arm32: return "arm32";
    case Architecture::Arm64: return "arm64";
    case Architecture::X86: return "x86";
    case Architecture::X64: return "x64";
    }
    return "unknown";
}

std::string typeName(ScalarType type) {
    std::string prefix;
    switch (type.kind) {
    case ScalarKind::Unknown: prefix = "unknown"; break;
    case ScalarKind::Boolean: prefix = "bool"; break;
    case ScalarKind::UnsignedInteger: prefix = "u"; break;
    case ScalarKind::SignedInteger: prefix = "i"; break;
    case ScalarKind::FloatingPoint: prefix = "f"; break;
    case ScalarKind::Pointer: prefix = "p"; break;
    case ScalarKind::Vector: prefix = "v"; break;
    }
    return prefix + std::to_string(type.bits);
}

std::string expressionText(const ExpressionPtr& expression) {
    if (!expression) return "null";
    const auto type = typeName(expression->type);
    switch (expression->kind) {
    case Expression::Kind::Unknown:
        return "unknown<" + type + ">";
    case Expression::Kind::Constant:
        return "const<" + type + ">(" + hex(expression->constant) + ")";
    case Expression::Kind::Register:
        return "reg<" + type + ">(" + expression->name + ")";
    case Expression::Kind::Load:
        return "load<" + type + ">(" + expressionText(expression->arguments.at(0)) + ")";
    case Expression::Kind::Cast:
        return "cast<" + type + ">(" + expressionText(expression->arguments.at(0)) + ")";
    case Expression::Kind::Unary:
    case Expression::Kind::Binary:
    case Expression::Kind::Select: {
        std::string kind;
        if (expression->kind == Expression::Kind::Unary) kind = "unary";
        else if (expression->kind == Expression::Kind::Binary) kind = "binary";
        else kind = "select";
        std::string result = kind + "<" + type + ">(" + expression->op;
        for (const auto& argument : expression->arguments) result += "," + expressionText(argument);
        return result + ")";
    }
    }
    return "invalid";
}

std::string statementText(const Statement& statement) {
    std::string result = "@" + hex(statement.address) + " ";
    switch (statement.kind) {
    case Statement::Kind::Assign:
        return result + "assign " + expressionText(statement.destination) + " = " + expressionText(statement.value);
    case Statement::Kind::Store:
        return result + "store " + expressionText(statement.destination) + " = " + expressionText(statement.value);
    case Statement::Kind::Call: {
        result += "call ";
        if (statement.destination) result += expressionText(statement.destination) + " = ";
        result += expressionText(statement.target) + "(";
        for (size_t i = 0; i < statement.arguments.size(); ++i) {
            if (i != 0) result += ",";
            result += expressionText(statement.arguments[i]);
        }
        return result + ")";
    }
    case Statement::Kind::Branch:
        return result + "branch " + expressionText(statement.target);
    case Statement::Kind::ConditionalBranch:
        return result + "if " + expressionText(statement.condition) + " branch " + expressionText(statement.target);
    case Statement::Kind::Return:
        return result + "return " + expressionText(statement.value);
    }
    return result + "invalid";
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw TestFailure("Cannot open golden file: " + path.string());
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

} // namespace

std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

bool& updateGoldens() {
    static bool update = false;
    return update;
}

TestRegistrar::TestRegistrar(std::string_view name, TestFunction function) {
    registry().push_back({name, function});
}

void fail(std::string message, const char* file, int line) {
    throw TestFailure(std::string(file) + ":" + std::to_string(line) + ": " + std::move(message));
}

void check(bool condition, std::string_view expression, const char* file, int line) {
    if (!condition) fail("CHECK failed: " + std::string(expression), file, line);
}

void checkEqual(const std::string& actual, const std::string& expected, const char* file, int line) {
    if (actual == expected) return;
    fail("Strings differ\n--- expected ---\n" + expected + "\n--- actual ---\n" + actual, file, line);
}

void checkEqual(uint64_t actual, uint64_t expected, const char* file, int line) {
    if (actual != expected) {
        fail("Values differ: actual " + std::to_string(actual) + ", expected " + std::to_string(expected), file, line);
    }
}

void checkGolden(const std::string& relativePath, const std::string& actual) {
    const auto path = std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR) / relativePath;
    if (updateGoldens()) {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) throw TestFailure("Cannot write golden file: " + path.string());
        output << actual;
        if (!output) throw TestFailure("Cannot finish golden file: " + path.string());
        return;
    }
    checkEqual(actual, readFile(path), path.string().c_str(), 0);
}

std::string serializeFunction(const RecoveredFunction& function) {
    std::ostringstream output;
    output << "function " << architectureName(function.architecture) << " " << function.name
           << " @ " << hex(function.address) << "\n";
    for (const auto& block : function.blocks) {
        output << "block " << hex(block.address) << "\n";
        for (const auto& statement : block.statements) output << "  " << statementText(statement) << "\n";
        output << "end\n";
    }
    output << "end\n";
    return output.str();
}

} // namespace il2cpprec::tests
