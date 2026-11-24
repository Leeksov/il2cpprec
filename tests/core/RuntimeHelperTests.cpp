#include <il2cpprec/analysis/ManagedPatterns.hpp>
#include <il2cpprec/analysis/ManagedEmitter.hpp>
#include <il2cpprec/analysis/RuntimeHelpers.hpp>
#include <il2cpprec/metadata/GenericMethodResolver.hpp>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <chrono>
#include <iostream>
#include <string>

using namespace il2cpprec;

namespace {

RecoveredFunction guardedCall(uint64_t guardStoreAddress = 0x3000, uint64_t skipAddress = 0x1018) {
    const auto word = ScalarType::pointer(64);
    RecoveredFunction function;
    function.architecture = Architecture::Arm64;
    function.address = 0x1000;
    function.name = "GuardedCall";
    BasicBlock block;
    block.address = 0x1000;

    Statement guardLoad;
    guardLoad.kind = Statement::Kind::Assign;
    guardLoad.address = 0x1000;
    guardLoad.destination = reg("guard", word);
    guardLoad.value = load(constant(0x3000, word), ScalarType::uintBits(8));
    block.statements.push_back(guardLoad);

    Statement branch;
    branch.kind = Statement::Kind::ConditionalBranch;
    branch.address = 0x1004;
    branch.condition = binary("!=", reg("guard", word), constant(0, word), ScalarType::boolean());
    branch.target = constant(skipAddress, word);
    block.statements.push_back(branch);

    Statement call;
    call.kind = Statement::Kind::Call;
    call.address = 0x1008;
    call.target = constant(0x2000, word);
    call.destination = reg("x0", word);
    call.arguments = {constant(0x4000, word)};
    block.statements.push_back(call);

    Statement setOne;
    setOne.kind = Statement::Kind::Assign;
    setOne.address = 0x100c;
    setOne.destination = reg("one", word);
    setOne.value = constant(1, word);
    block.statements.push_back(setOne);

    Statement store;
    store.kind = Statement::Kind::Store;
    store.address = 0x1010;
    store.destination = constant(guardStoreAddress, word);
    store.value = cast(reg("one", word), ScalarType::uintBits(8));
    block.statements.push_back(store);
    function.blocks.push_back(block);

    BasicBlock exit;
    exit.address = 0x1018;
    Statement ret;
    ret.kind = Statement::Kind::Return;
    ret.address = 0x1018;
    ret.value = constant(0, word);
    exit.statements.push_back(ret);
    function.blocks.push_back(exit);
    return function;
}

} // namespace

int main() {
    auto function = guardedCall();
    const auto evidence = RuntimeHelpers{}.infer(function);
    assert(evidence.size() == 1);
    assert(evidence.front().role == RuntimeHelperRole::ClassInit);
    assert(evidence.front().targetAddress == 0x2000);
    assert(evidence.front().callAddress == 0x1008);

    const auto source = function.emitCSharp().source;
    assert(source.find("Likely IL2CPP class initialization helper") != std::string::npos);
    assert(source.find("InvokeDirect") != std::string::npos);

    const auto analysis = ManagedPatterns{}.analyze(function, MetadataModel{});
    bool found = false;
    for (const auto& operation : analysis.operations) {
        if (operation.kind == ManagedOperationKind::RuntimeClassInit) {
            assert(operation.status == ManagedPatternStatus::Resolved);
            assert(operation.confidence == ManagedPatternConfidence::Medium);
            found = true;
        }
    }
    assert(found);

    assert(RuntimeHelpers{}.infer(guardedCall(0x3001)).empty());
    assert(RuntimeHelpers{}.infer(guardedCall(0x100c)).empty());

    MetadataModel metadata;
    TypeModel type;
    MethodModel method;
    method.address = 0x2000;
    method.name = "ManagedMethod";
    type.methods.push_back(method);
    metadata.types.push_back(type);
    const auto managedAnalysis = ManagedPatterns{}.analyze(function, metadata);
    for (const auto& operation : managedAnalysis.operations) {
        assert(operation.kind != ManagedOperationKind::RuntimeClassInit);
    }

    // Keep many calls in one function: rebuilding a resolver for every call
    // makes this probe scale with calls times the metadata method count.
    MetadataModel genericMetadata;
    genericMetadata.version = 24.0;
    TypeModel genericType;
    genericType.name = "GenericOwner";
    for (int index = 0; index < 5000; ++index) {
        MethodModel definition;
        definition.definitionIndex = index;
        definition.name = "Method" + std::to_string(index);
        genericType.methods.push_back(std::move(definition));
        FieldModel field;
        field.name = "Field" + std::to_string(index);
        field.offset = 16;
        genericType.fields.push_back(std::move(field));
    }
    genericMetadata.types.push_back(std::move(genericType));
    genericMetadata.methodSpecs.push_back({0, -1, -1});
    GenericMethodPointerModel mapping;
    mapping.genericMethodIndex = 0;
    mapping.methodPointer = 0x9000;
    genericMetadata.genericMethodTable.push_back(mapping);

    RecoveredFunction genericCalls;
    genericCalls.architecture = Architecture::Arm64;
    BasicBlock calls;
    for (size_t index = 0; index < 100; ++index) {
        Statement call;
        call.kind = Statement::Kind::Call;
        call.address = 0x4000 + index * 4;
        call.target = constant(0x9000, ScalarType::pointer(64));
        calls.statements.push_back(std::move(call));
    }
    genericCalls.blocks.push_back(std::move(calls));
    const auto started = std::chrono::steady_clock::now();
    const auto fallback = ManagedPatterns{}.analyze(genericCalls, genericMetadata);
    const auto fallbackMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    GenericMethodResolver sharedResolver(genericMetadata);
    ManagedMetadataIndex sharedIndex(genericMetadata);
    ManagedPatternOptions sharedOptions;
    sharedOptions.genericResolver = &sharedResolver;
    sharedOptions.metadataIndex = &sharedIndex;
    const auto shared = ManagedPatterns{}.analyze(genericCalls, genericMetadata, sharedOptions);
    assert(fallback.operations.size() == 100);
    assert(shared.operations.size() == fallback.operations.size());
    for (size_t index = 0; index < shared.operations.size(); ++index) {
        assert(shared.operations[index].status == ManagedPatternStatus::Resolved);
        assert(shared.operations[index].method.definitionIndex == fallback.operations[index].method.definitionIndex);
    }
    const auto repeatedStart = std::chrono::steady_clock::now();
    for (size_t index = 0; index < 30; ++index) {
        assert(ManagedPatterns{}.analyze(genericCalls, genericMetadata, sharedOptions).operations.size() == 100);
    }
    const auto sharedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - repeatedStart).count();
    std::cerr << "managed index probe: 100 calls, 5000 methods/fields; fallback " << fallbackMs
              << " ms, 30 shared analyses " << sharedMs << " ms\n";

    ManagedEmitterOptions emitOptions;
    emitOptions.patterns.genericResolver = &sharedResolver;
    emitOptions.patterns.metadataIndex = &sharedIndex;
    const auto reused = ManagedEmitter{}.emit(genericCalls, genericMetadata, emitOptions);
    const auto owned = ManagedEmitter{}.emit(genericCalls, genericMetadata);
    assert(reused.csharp == owned.csharp);
    assert(reused.callSites.size() == owned.callSites.size());
    for (size_t index = 0; index < reused.callSites.size(); ++index) {
        assert(reused.callSites[index].status == owned.callSites[index].status);
        assert(reused.callSites[index].emitted == owned.callSites[index].emitted);
    }
    assert(genericMetadata.version == 24.0);
    assert(genericMetadata.genericMethodTable.size() == 1);

    auto versionOnly = genericMetadata;
    versionOnly.version = 0;
    versionOnly.versionInfo.preciseVersion = 24.0;
    const auto versionResult = ManagedEmitter{}.emit(genericCalls, versionOnly, emitOptions);
    assert(versionOnly.version == 0);
    assert(versionResult.csharp == owned.csharp);
}
