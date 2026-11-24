#include <il2cpprec/analysis/ManagedPatterns.hpp>
#include <il2cpprec/analysis/RuntimeHelpers.hpp>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
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
}
