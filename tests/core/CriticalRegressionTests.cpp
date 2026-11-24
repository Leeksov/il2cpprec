#include "TestSupport.hpp"

#include <il2cpprec/IR.hpp>
#include <il2cpprec/emit/ProjectWriter.hpp>
#include <il2cpprec/lifters/Arm64Lifter.hpp>

#include <capstone/arm64.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace il2cpprec::tests {
namespace {

Statement assignment(ExpressionPtr destination, ExpressionPtr value, uint64_t address = 0x1000) {
    Statement statement;
    statement.kind = Statement::Kind::Assign;
    statement.address = address;
    statement.destination = std::move(destination);
    statement.value = std::move(value);
    return statement;
}

Statement returnValue(ExpressionPtr value, uint64_t address = 0x1004) {
    Statement statement;
    statement.kind = Statement::Kind::Return;
    statement.address = address;
    statement.value = std::move(value);
    return statement;
}

RecoveredFunction functionWithStatements(std::string name, std::vector<Statement> statements) {
    RecoveredFunction function;
    function.architecture = Architecture::Arm64;
    function.address = 0x1000;
    function.name = std::move(name);
    function.blocks.push_back({0x1000, std::move(statements)});
    return function;
}

Operand registerOperand(const std::string& name, uint16_t size) {
    Operand operand;
    operand.kind = OperandKind::Register;
    operand.reg = name;
    operand.size = size;
    return operand;
}

Operand memoryOperand(const std::string& base, uint16_t size) {
    Operand operand;
    operand.kind = OperandKind::Memory;
    operand.size = size;
    operand.memoryBase = base;
    return operand;
}

NativeInstruction vectorMemoryInstruction(uint32_t id, uint64_t address, const std::string& mnemonic) {
    NativeInstruction instruction;
    instruction.id = id;
    instruction.address = address;
    instruction.size = 4;
    instruction.mnemonic = mnemonic;
    instruction.text = mnemonic == "ldr" ? "q0, [x1]" : "q0, [x2]";
    instruction.operands = {
        registerOperand("q0", 16),
        memoryOperand(mnemonic == "ldr" ? "x1" : "x2", 16)
    };
    return instruction;
}

struct OutputDirectory {
    explicit OutputDirectory(std::filesystem::path path) : path(std::move(path)) {
        std::filesystem::remove_all(this->path);
        std::filesystem::create_directories(this->path);
    }
    ~OutputDirectory() { std::filesystem::remove_all(path); }
    std::filesystem::path path;
};

std::string readSources(const std::filesystem::path& directory) {
    std::string result;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".cs") continue;
        std::ifstream input(entry.path(), std::ios::binary);
        result += std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }
    return result;
}

MetadataModel genericMetadata() {
    MetadataModel metadata;
    metadata.genericContainers = {
        {0, 1, 0, 0},
        {0, 1, 1, 1},
    };
    metadata.genericParameters = {
        {0, "T", -1, 0, 0, 0},
        {1, "TMethod", -1, 0, 1, 0},
    };

    TypeModel type;
    type.nameSpace = "Regression";
    type.name = "Box`1";
    type.imageName = "Assembly-CSharp.dll";
    type.genericContainerIndex = 0;
    type.flags = 1;
    type.bitfield = 0;

    MethodModel identity;
    identity.token = 0x06000001;
    identity.definitionIndex = 0;
    identity.address = 0x1000;
    identity.imageName = "Assembly-CSharp.dll";
    identity.declaringType = "Regression.Box`1";
    identity.name = "Identity";
    identity.returnType = "TMethod";
    identity.parameters = {{"value", "TMethod", -1}};
    identity.flags = 0x0006 | 0x0040 | 0x0100;
    identity.genericContainerIndex = 1;
    type.methods.push_back(identity);

    MethodModel run;
    run.token = 0x06000002;
    run.definitionIndex = 1;
    run.address = 0x2000;
    run.imageName = "Assembly-CSharp.dll";
    run.declaringType = "Regression.Box`1";
    run.name = "Run";
    run.returnType = "int";
    run.flags = 0x0006 | 0x0040;
    type.methods.push_back(run);

    metadata.types.push_back(type);
    return metadata;
}

RecoveredFunction namedBody(const std::string& name, uint64_t address) {
    auto function = functionWithStatements(name, {returnValue(reg("x0", ScalarType::pointer(64)), address)});
    function.address = address;
    function.blocks[0].address = address;
    return function;
}

} // namespace

TEST_CASE("zero-bit load uses native pointer width without partial emission") {
    const auto native = ScalarType::uintBits(64);
    const auto zeroWidth = ScalarType::uintBits(0);
    const auto function = functionWithStatements("ZeroBitLoad", {
        assignment(reg("x0", native), load(constant(0x2000, ScalarType::pointer(64)), zeroWidth)),
        returnValue(reg("x0", native))
    });
    const auto emitted = function.emitCSharp();
    CHECK(!emitted.partial);
    CHECK(emitted.diagnostics.empty());
    CHECK(emitted.source.find("RuntimeMemory.ReadU64(0x2000UL)") != std::string::npos);
    CHECK(emitted.source.find("Unsupported 0-bit load") == std::string::npos);
}

TEST_CASE("v0 and v8 type conflicts stay register-local and diagnosed") {
    const auto single = ScalarType::floatBits(32);
    const auto vector = ScalarType::vectorBits(128);
    const auto function = functionWithStatements("RegisterConflicts", {
        assignment(reg("v0", single), binary("+", reg("v8", single), reg("v0", single), single)),
        assignment(reg("v8", vector), load(reg("x0", ScalarType::pointer(64)), vector), 0x1004),
        returnValue(reg("v0", single), 0x1008)
    });
    const auto emitted = function.emitCSharp();
    CHECK(emitted.partial);
    CHECK(emitted.source.find("float v0 = default(float);") != std::string::npos);
    CHECK(emitted.source.find("__UnsupportedValue v8 = default(__UnsupportedValue);") != std::string::npos);
    bool sawV8Conflict = false;
    for (const auto& diagnostic : emitted.diagnostics) {
        CHECK(diagnostic.message.find("Register 'v0' has conflicting types") == std::string::npos);
        if (diagnostic.message.find("Register 'v8' has conflicting types") != std::string::npos) sawV8Conflict = true;
    }
    CHECK(sawV8Conflict);
}

TEST_CASE("ARM64 q0 load/store produces real vector128 IR and CSharp") {
    std::vector<Statement> statements;
    Arm64Lifter lifter;
    lifter.lift(vectorMemoryInstruction(ARM64_INS_LDR, 0x1000, "ldr"), statements);
    lifter.lift(vectorMemoryInstruction(ARM64_INS_STR, 0x1004, "str"), statements);
    CHECK_EQ(statements.size(), 2);
    CHECK(statements[0].kind == Statement::Kind::Assign);
    CHECK(statements[0].value != nullptr);
    CHECK(statements[0].value->kind == Expression::Kind::Load);
    CHECK_EQ(statements[0].value->type.bits, 128);
    CHECK(statements[1].kind == Statement::Kind::Store);
    CHECK(statements[1].value != nullptr);
    CHECK_EQ(statements[1].value->type.bits, 128);

    const auto emitted = functionWithStatements("VectorMemory", std::move(statements)).emitCSharp();
    CHECK(!emitted.partial);
    CHECK(emitted.diagnostics.empty());
    CHECK(emitted.source.find("RuntimeVector128 v0 = default(RuntimeVector128);") != std::string::npos);
    CHECK(emitted.source.find("RuntimeMemory.ReadVector128(x1)") != std::string::npos);
    CHECK(emitted.source.find("RuntimeMemory.WriteVector128(x2, v0);") != std::string::npos);
    CHECK(emitted.source.find("__Unsupported<") == std::string::npos);
}

TEST_CASE("generic and virtual methods emit declared type parameters and modifiers") {
    const auto metadata = genericMetadata();
    std::vector<RecoveredFunction> functions = {
        namedBody("Identity", 0x1000),
        namedBody("Run", 0x2000),
    };
    OutputDirectory output(
        std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() / "build/tests/generic-virtual-emission");
    ProjectWriter::write(output.path, metadata, functions, {"RegressionChecks", "net8.0", {}, {}});
    const auto source = readSources(output.path);
    if (source.find("unsafe partial class Box<T>") == std::string::npos ||
        source.find("public virtual TMethod Identity<TMethod>(TMethod value)") == std::string::npos ||
        source.find("public virtual int Run()") == std::string::npos ||
        source.find("public override int Run()") != std::string::npos) {
        fail("Generated sources:\n" + source, __FILE__, __LINE__);
    }
}

TEST_CASE("enum and static class declarations use legal CSharp modifiers") {
    MetadataModel metadata;
    TypeModel enumeration;
    enumeration.name = "Mode";
    enumeration.flags = 0x1 | 0x80 | 0x100;
    enumeration.bitfield = 0x2;
    enumeration.fields.push_back({"value__", "int", 0, false, 0, 0, -1});
    metadata.types.push_back(enumeration);

    TypeModel utility;
    utility.name = "Utility";
    utility.flags = 0x1 | 0x80 | 0x100;
    utility.fields.push_back({"Value", "int", 0, true, 0, 0x16, -1});
    metadata.types.push_back(utility);

    OutputDirectory output(
        std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() / "build/tests/type-modifier-emission");
    ProjectWriter::write(output.path, metadata, {}, {"RegressionChecks", "net8.0", {}, {}});
    const auto source = readSources(output.path);
    if (source.find("public enum Mode : int") == std::string::npos ||
        source.find("public static unsafe partial class Utility") == std::string::npos ||
        source.find("unsafe enum") != std::string::npos ||
        source.find("abstract sealed") != std::string::npos) {
        fail("Generated sources:\n" + source, __FILE__, __LINE__);
    }
}

TEST_CASE("optional defaults do not create invalid or duplicate CSharp signatures") {
    MetadataModel metadata;
    metadata.parameterDefaultValues.push_back({0, -1, -1});
    TypeModel type;
    type.name = "Factory";
    type.flags = 1;
    MethodModel optional;
    optional.name = "Create";
    optional.returnType = "object";
    optional.flags = 0x16;
    optional.isStatic = true;
    optional.address = 0x1000;
    optional.parameters = {{"value", "object", 0}};
    type.methods.push_back(optional);
    MethodModel required = optional;
    required.address = 0x2000;
    required.parameters = {{"value", "object", -1}};
    type.methods.push_back(required);
    MethodModel mixed = optional;
    mixed.name = "Mixed";
    mixed.address = 0x3000;
    mixed.parameters = {{"optional", "object", 0}, {"required", "int", -1}};
    type.methods.push_back(mixed);
    metadata.types.push_back(type);

    std::vector<RecoveredFunction> functions = {
        namedBody("Create", 0x1000), namedBody("Create", 0x2000), namedBody("Mixed", 0x3000)
    };
    OutputDirectory output(
        std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() / "build/tests/default-parameter-emission");
    ProjectWriter::write(output.path, metadata, functions, {"RegressionChecks", "net8.0", {}, {}});
    const auto source = readSources(output.path);
    if (source.find("Create(object value = null)") == std::string::npos ||
        source.find("Create_0x2000(object value)") == std::string::npos ||
        source.find("Mixed(object optional, int required)") == std::string::npos ||
        source.find("Mixed(object optional = null, int required)") != std::string::npos) {
        fail("Generated sources:\n" + source, __FILE__, __LINE__);
    }
}

} // namespace il2cpprec::tests
