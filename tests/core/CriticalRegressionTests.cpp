#include "TestSupport.hpp"

#include <il2cpprec/IR.hpp>
#include <il2cpprec/emit/ProjectWriter.hpp>
#include <il2cpprec/lifters/Arm64Lifter.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>

#include <capstone/arm64.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>
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

TEST_CASE("generic constraints use the constraint index table") {
    MetadataModel metadata;
    metadata.genericContainers.push_back({0, 1, 0, 0});
    metadata.genericParameters.push_back({0, "T", 1, 1, 0, 0});
    metadata.genericParameterConstraints = {99, 1};
    metadata.typeReferences.resize(2);
    metadata.typeReferences[1].code = static_cast<uint8_t>(Il2CppTypeCode::Class);
    metadata.typeReferences[1].name = "IRequirement";
    metadata.typeReferences[1].definitionIndex = 1;

    TypeModel holder;
    holder.name = "Holder`1";
    holder.flags = 1;
    holder.genericContainerIndex = 0;
    metadata.types.push_back(holder);
    TypeModel requirement;
    requirement.name = "IRequirement";
    requirement.flags = 0x21;
    metadata.types.push_back(requirement);

    OutputDirectory output(
        std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() / "build/tests/constraint-index-emission");
    ProjectWriter::write(output.path, metadata, {}, {"RegressionChecks", "net8.0", {}, {}});
    const auto source = readSources(output.path);
    if (source.find("Holder<T> where T : IRequirement") == std::string::npos) {
        fail("Generated sources:\n" + source, __FILE__, __LINE__);
    }
}

TEST_CASE("v111 generated method signature and token reach project emission") {
    MetadataModel metadata;
    metadata.version = 111;
    metadata.typeReferences.resize(2);
    metadata.typeReferences[0].code = static_cast<uint8_t>(Il2CppTypeCode::I4);
    metadata.typeReferences[1].code = static_cast<uint8_t>(Il2CppTypeCode::Boolean);
    metadata.methodSignatures.push_back({4, 0, {1}});
    metadata.generatedMethodsStart = 0;
    metadata.generatedMethodTokens.push_back({0x06000042});
    TypeModel type;
    type.name = "Modern";
    type.flags = 1;
    MethodModel method;
    method.name = "Generated";
    method.address = 0x1000;
    method.definitionIndex = 0;
    method.token = 0x06000042;
    method.flags = 0x16;
    method.isStatic = true;
    method.returnType = "type[0]";
    method.signatureOffset = 4;
    method.parameters.push_back({"flag", "type[1]", -1});
    type.methods.push_back(method);
    metadata.types.push_back(type);

    OutputDirectory output(
        std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() / "build/tests/v111-emission");
    ProjectWriter::write(output.path, metadata, {namedBody("Generated", 0x1000)},
                         {"RegressionChecks", "net8.0", {}, {}});
    const auto source = readSources(output.path);
    if (source.find("int Generated(bool flag)") == std::string::npos ||
        source.find("Generated method metadata token: 0x6000042") == std::string::npos) {
        fail("Generated sources:\n" + source, __FILE__, __LINE__);
    }
}

TEST_CASE("property and framework event metadata emit CSharp members") {
    MetadataModel metadata;
    metadata.typeReferences.resize(1);
    metadata.typeReferences[0].code = static_cast<uint8_t>(Il2CppTypeCode::Class);
    metadata.typeReferences[0].name = "System.Action";
    metadata.properties.push_back({"Name", 0, 1, 0, 0x17000001});
    metadata.events.push_back({"Changed", 0, 2, 3, -1, 0x14000001});
    TypeModel type;
    type.name = "Container";
    type.flags = 1;
    type.propertyStart = 0;
    type.propertyCount = 1;
    type.eventStart = 0;
    type.eventCount = 1;
    const auto addMethod = [&](std::string name, int definitionIndex, uint64_t address,
                               std::string returnType, std::vector<ParameterModel> parameters) {
        MethodModel method;
        method.name = std::move(name);
        method.definitionIndex = definitionIndex;
        method.address = address;
        method.returnType = std::move(returnType);
        method.parameters = std::move(parameters);
        method.flags = 0x6;
        type.methods.push_back(std::move(method));
    };
    addMethod("get_Name", 0, 0x1000, "string", {});
    addMethod("set_Name", 1, 0x2000, "void", {{"value", "string", -1}});
    addMethod("add_Changed", 2, 0x3000, "void", {{"value", "System.Action", -1}});
    addMethod("remove_Changed", 3, 0x4000, "void", {{"value", "System.Action", -1}});
    addMethod("get_Name", 4, 0x5000, "string", {});
    metadata.types.push_back(type);
    std::vector<RecoveredFunction> functions = {
        namedBody("get_Name", 0x1000), namedBody("set_Name", 0x2000),
        namedBody("add_Changed", 0x3000), namedBody("remove_Changed", 0x4000),
        namedBody("get_Name", 0x5000)
    };

    OutputDirectory output(
        std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() / "build/tests/property-event-emission");
    ProjectWriter::write(output.path, metadata, functions, {"RegressionChecks", "net8.0", {}, {}});
    const auto source = readSources(output.path);
    if (source.find("string Name") == std::string::npos ||
        source.find("event System.Action Changed") == std::string::npos ||
        source.find("get_Name_0x1000") == std::string::npos ||
        source.find("get_Name_0x5000") == std::string::npos ||
        source.find("add_Changed_0x3000") == std::string::npos) {
        fail("Generated sources:\n" + source, __FILE__, __LINE__);
    }
}

TEST_CASE("simple nested type is emitted inside its declaring type") {
    MetadataModel metadata;
    TypeModel outer;
    outer.nameSpace = "Regression";
    outer.name = "Outer";
    outer.flags = 1;
    metadata.types.push_back(outer);
    TypeModel inner;
    inner.nameSpace = "Regression";
    inner.name = "Inner";
    inner.flags = 2;
    inner.declaringTypeIndex = 0;
    metadata.types.push_back(inner);

    OutputDirectory output(
        std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() / "build/tests/nested-type-emission");
    ProjectWriter::write(output.path, metadata, {}, {"RegressionChecks", "net8.0", {}, {}});
    const auto source = readSources(output.path);
    if (source.find("public unsafe partial class Outer\n    {\n        public unsafe partial class Inner") == std::string::npos) {
        fail("Generated sources:\n" + source, __FILE__, __LINE__);
    }
}

} // namespace il2cpprec::tests
