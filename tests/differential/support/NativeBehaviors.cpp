#include <il2cpprec/analysis/ManagedPatterns.hpp>
#include <il2cpprec/emit/RuntimeSupport.hpp>

#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace il2cpprec;

int passed = 0;
int partial = 0;
int failed = 0;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void exact(const std::string& name, const std::function<void()>& test) {
    try {
        test();
        std::cout << "PASS exact " << name << '\n';
        ++passed;
    } catch (const std::exception& error) {
        std::cout << "FAIL " << name << ": " << error.what() << '\n';
        ++failed;
    }
}

void expectedPartial(const std::string& name, const std::function<std::string()>& test) {
    try {
        const auto detail = test();
        std::cout << "PARTIAL " << name << ": " << detail << '\n';
        ++partial;
    } catch (const std::exception& error) {
        std::cout << "FAIL " << name << ": " << error.what() << '\n';
        ++failed;
    }
}

ScalarType pointerType() {
    return ScalarType::pointer(64);
}

Statement assignment(const std::string& destination, ExpressionPtr value) {
    Statement statement;
    statement.kind = Statement::Kind::Assign;
    statement.destination = reg(destination, pointerType());
    statement.value = std::move(value);
    return statement;
}

Statement call(ExpressionPtr target) {
    Statement statement;
    statement.kind = Statement::Kind::Call;
    statement.destination = reg("x0", pointerType());
    statement.target = std::move(target);
    statement.arguments = {reg("x0", pointerType())};
    return statement;
}

RecoveredFunction functionWith(Statement statement, const std::string& name) {
    RecoveredFunction function;
    function.architecture = Architecture::X64;
    function.address = 0x1000;
    function.name = name;
    function.blocks.push_back({0x1000, {std::move(statement)}});
    return function;
}

MethodModel method(const std::string& name, uint32_t token, uint64_t address) {
    MethodModel result;
    result.name = name;
    result.token = token;
    result.definitionIndex = static_cast<int>(token);
    result.address = address;
    result.imageName = "tests.dll";
    result.isStatic = true;
    return result;
}

MetadataModel metadataWithMethods(const std::vector<MethodModel>& methods) {
    MetadataModel metadata;
    TypeModel type;
    type.nameSpace = "Behavior";
    type.name = "GenericTarget";
    type.methods = methods;
    metadata.types.push_back(std::move(type));
    TypeReferenceModel reference;
    reference.name = "GenericIdentity<System.Int32>";
    reference.genericArgumentIndices = {7};
    metadata.typeReferences.push_back(std::move(reference));
    return metadata;
}

const ManagedOperation& onlyOperation(const ManagedAnalysisResult& result) {
    require(result.operations.size() == 1,
        "expected exactly one managed operation, got " + std::to_string(result.operations.size()));
    return result.operations.front();
}

ManagedAnalysisResult analyzeCall(uint64_t target, const MetadataModel& metadata) {
    return ManagedPatterns{}.analyze(
        functionWith(call(constant(target, pointerType())), "ManagedCall"), metadata);
}

RecoveredFunction virtualCall(size_t slot, bool symbolicVtable) {
    RecoveredFunction function;
    function.architecture = Architecture::X64;
    function.address = 0x1000;
    function.name = symbolicVtable ? "InterfaceDispatch" : "VirtualDispatch";
    BasicBlock block;
    block.address = 0x1000;
    const auto vtable = load(reg("x0", pointerType()), pointerType());
    ExpressionPtr targetBase = vtable;
    if (symbolicVtable) {
        block.statements.push_back(assignment("x1", vtable));
        targetBase = reg("x1", pointerType());
    }
    const auto slotAddress = binary("+", targetBase, constant(slot, pointerType()), pointerType());
    block.statements.push_back(call(load(slotAddress, pointerType())));
    function.blocks.push_back(std::move(block));
    return function;
}

void requirePartialEmission(const std::string& operation) {
    auto function = functionWith(
        assignment("x0", unary(operation, reg("x0", pointerType()), pointerType())),
        "Unsupported_" + operation);
    const auto emitted = function.emitCSharp();
    require(emitted.partial, "emission did not set partial for " + operation);
    require(!emitted.diagnostics.empty(), "emission did not report a diagnostic for " + operation);
    require(emitted.source.find("__Unsupported") != std::string::npos,
        "emission lost the unsupported marker for " + operation);
}

std::string partialDetail(ManagedPatternStatus status, const std::string& reason) {
    return std::string("status=") + std::to_string(static_cast<int>(status)) + "; " + reason;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--runtime-support") {
        std::ofstream output(argv[2], std::ios::binary);
        output << il2cpprec::generateRuntimeSupport(il2cpprec::Architecture::X64);
        return output ? 0 : 2;
    }
    if (argc != 1) {
        std::cerr << "usage: NativeBehaviors [--runtime-support OUTPUT]\n";
        return 2;
    }

    exact("GenericMethodCallResolved", [] {
        const auto metadata = metadataWithMethods({method("GenericIdentity<System.Int32>", 1, 0x4000)});
        const auto result = analyzeCall(0x4000, metadata);
        const auto& operation = onlyOperation(result);
        require(operation.kind == ManagedOperationKind::DirectMethodCall, "wrong operation kind");
        require(operation.status == ManagedPatternStatus::Resolved, "generic call was not resolved");
        require(operation.method.name == "GenericIdentity<System.Int32>", "wrong generic method identity");
        require(metadata.typeReferences.at(0).genericArgumentIndices == std::vector<int32_t>{7},
            "generic argument metadata changed");
    });

    expectedPartial("GenericMethodCallAmbiguous", [] {
        const auto metadata = metadataWithMethods({
            method("GenericIdentity<System.Int32>", 1, 0x4000),
            method("GenericIdentity<System.UInt32>", 2, 0x4000),
        });
        const auto result = analyzeCall(0x4000, metadata);
        const auto& operation = onlyOperation(result);
        require(operation.status == ManagedPatternStatus::Ambiguous,
            "ambiguous generic methods were treated as exact");
        return partialDetail(operation.status, operation.reason);
    });

    expectedPartial("DirectMethodCallUnresolved", [] {
        const auto result = analyzeCall(0xDEAD, MetadataModel{});
        const auto& operation = onlyOperation(result);
        require(operation.status == ManagedPatternStatus::Unresolved,
            "unknown call target was treated as exact");
        return partialDetail(operation.status, operation.reason);
    });

    expectedPartial("VirtualDispatchNeedsMethodIdentity", [] {
        const auto result = ManagedPatterns{}.analyze(virtualCall(24, false), MetadataModel{});
        const auto& operation = onlyOperation(result);
        require(operation.kind == ManagedOperationKind::VirtualDispatch, "vtable pattern was not recognized");
        require(operation.status == ManagedPatternStatus::Placeholder, "vtable placeholder became exact");
        require(operation.offset == 24, "wrong vtable slot");
        return partialDetail(operation.status, operation.reason);
    });

    expectedPartial("InterfaceDispatchNeedsMethodIdentity", [] {
        const auto result = ManagedPatterns{}.analyze(virtualCall(40, false), MetadataModel{});
        const auto& operation = onlyOperation(result);
        require(operation.kind == ManagedOperationKind::VirtualDispatch, "interface pattern was not recognized");
        require(operation.status == ManagedPatternStatus::Placeholder, "interface placeholder became exact");
        require(operation.offset == 40, "wrong interface slot");
        return partialDetail(operation.status, operation.reason);
    });

    exact("StringLiteralResolved", [] {
        MetadataModel metadata;
        metadata.stringLiterals.emplace(42, "recovered literal");
        ManagedPatternOptions options;
        options.stringLiteralAddresses.emplace(42, 0x8000);
        const auto function = functionWith(assignment("x0", constant(0x8000, pointerType())), "StringLiteral");
        const auto result = ManagedPatterns{}.analyze(function, metadata, options);
        const auto& operation = onlyOperation(result);
        require(operation.kind == ManagedOperationKind::StringLiteralReference, "wrong string operation kind");
        require(operation.status == ManagedPatternStatus::Resolved, "string literal was not resolved");
        require(operation.stringLiteral == "recovered literal", "wrong string literal value");
    });

    expectedPartial("StringLiteralAmbiguous", [] {
        MetadataModel metadata;
        metadata.stringLiterals.emplace(42, "first");
        metadata.stringLiterals.emplace(43, "second");
        ManagedPatternOptions options;
        options.stringLiteralAddresses.emplace(42, 0x8000);
        options.stringLiteralAddresses.emplace(43, 0x8000);
        const auto function = functionWith(assignment("x0", constant(0x8000, pointerType())), "AmbiguousString");
        const auto result = ManagedPatterns{}.analyze(function, metadata, options);
        const auto& operation = onlyOperation(result);
        require(operation.status == ManagedPatternStatus::Ambiguous, "ambiguous string became exact");
        return partialDetail(operation.status, operation.reason);
    });

    expectedPartial("ArrayLayoutNeedsManagedType", [] {
        RecoveredFunction function;
        function.architecture = Architecture::X64;
        function.address = 0x1000;
        function.name = "ArrayAccess";
        BasicBlock block;
        block.address = 0x1000;
        block.statements.push_back(assignment("x1", load(
            binary("+", reg("x0", pointerType()), constant(24, pointerType()), pointerType()),
            ScalarType::uintBits(32))));
        const auto scaled = binary("*", reg("x1", ScalarType::uintBits(32)), constant(4, pointerType()), pointerType());
        const auto elements = binary("+", reg("x0", pointerType()), scaled, pointerType());
        block.statements.push_back(assignment("x2", load(
            binary("+", elements, constant(32, pointerType()), pointerType()), ScalarType::uintBits(32))));
        function.blocks.push_back(std::move(block));
        const auto result = ManagedPatterns{}.analyze(function, MetadataModel{});
        require(result.operations.size() == 2, "array length/element patterns were not recognized");
        require(result.operations[0].kind == ManagedOperationKind::ArrayLength, "missing array length");
        require(result.operations[1].kind == ManagedOperationKind::ArrayElementLoad, "missing array element");
        for (const auto& operation : result.operations) {
            require(operation.status == ManagedPatternStatus::Placeholder, "typed array access became exact");
        }
        return "array operations have placeholders until the managed element type is known";
    });

    expectedPartial("BoxingIRUnsupported", [] { requirePartialEmission("box"); return "boxing IR remains unsupported"; });
    expectedPartial("NullCheckIRUnsupported", [] { requirePartialEmission("nullcheck"); return "NullCheck IR remains unsupported"; });
    expectedPartial("TryRegionUnsupported", [] { requirePartialEmission("try_region"); return "try region remains unsupported"; });
    expectedPartial("CatchRegionUnsupported", [] { requirePartialEmission("catch_region"); return "catch region remains unsupported"; });
    expectedPartial("FinallyRegionUnsupported", [] { requirePartialEmission("finally_region"); return "finally region remains unsupported"; });

    std::cout << "BEHAVIOR_NATIVE SUMMARY passed=" << passed << " partial=" << partial
              << " failed=" << failed << '\n';
    return failed == 0 ? 0 : 1;
}
