#include <il2cpprec/analysis/ManagedPatterns.hpp>
#include <il2cpprec/analysis/ManagedEmitter.hpp>
#include <il2cpprec/analysis/RuntimeHelpers.hpp>
#include <il2cpprec/metadata/GenericMethodResolver.hpp>
#include <il2cpprec/metadata/UniversalGenericResolver.hpp>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <chrono>
#include <cstring>
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
        definition.address = 0x3000 + static_cast<uint64_t>(index) * 4;
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

    // A shared generic native body is not enough to identify its closed
    // instantiation. Explicit MethodInfo-slot evidence may select exactly one.
    MetadataModel sharedMetadata;
    sharedMetadata.version = 24.0;
    TypeModel sharedOwner;
    sharedOwner.name = "SharedOwner";
    MethodModel sharedDefinition;
    sharedDefinition.definitionIndex = 0;
    sharedDefinition.name = "Get";
    sharedDefinition.returnType = "void";
    sharedDefinition.isStatic = false;
    sharedOwner.methods.push_back(sharedDefinition);
    sharedMetadata.types.push_back(sharedOwner);
    for (int32_t index = 0; index < 2; ++index) {
        const uint64_t instAddress = 0xA000 + static_cast<uint64_t>(index) * 0x100;
        GenericInstModel inst;
        inst.address = instAddress;
        sharedMetadata.genericInsts.push_back(inst);
        GenericMethodSpecModel spec;
        spec.methodDefinitionIndex = 0;
        spec.classInstIndex = index;
        spec.classInstAddress = instAddress;
        sharedMetadata.methodSpecs.push_back(spec);
        GenericMethodPointerModel candidate;
        candidate.genericMethodIndex = index;
        candidate.methodPointer = 0x9000;
        candidate.classInstAddress = instAddress;
        sharedMetadata.genericMethodTable.push_back(candidate);
    }
    BinaryImage usageBinary;
    usageBinary.format = BinaryFormat::MachO;
    usageBinary.architecture = Architecture::Arm64;
    usageBinary.imageBase = 0x100000000ULL;
    usageBinary.bytes = std::make_shared<std::vector<uint8_t>>(0x500, 0);
    usageBinary.sections.push_back({"__DATA", usageBinary.imageBase, 0x500, 0, 0x500, false});
    usageBinary.sections.push_back({"__bss", usageBinary.imageBase + 0x1000, 0x100, 0, 0, false});
    const auto writeU64 = [&](size_t offset, uint64_t value) {
        std::memcpy(usageBinary.bytes->data() + offset, &value, sizeof(value));
    };
    sharedMetadata.metadataRegistrationAddress = usageBinary.imageBase + 0x100;
    sharedMetadata.metadataUsagesCount = 4;
    sharedMetadata.typeReferences.resize(2);
    writeU64(0x100 + 7 * 16, 4);
    writeU64(0x100 + 7 * 16 + 8, usageBinary.imageBase + 0x200);
    writeU64(0x100 + 3 * 16, 2);
    writeU64(0x100 + 3 * 16 + 8, usageBinary.imageBase + 0x280);
    const uint64_t firstTypeAddress = usageBinary.imageBase + 0x340;
    const uint64_t secondTypeAddress = usageBinary.imageBase + 0x350;
    writeU64(0x280, firstTypeAddress);
    writeU64(0x288, secondTypeAddress);
    (*usageBinary.bytes)[0x340 + 10] = 0x08;
    (*usageBinary.bytes)[0x350 + 10] = 0x08;
    const uint64_t methodInfoSlot = usageBinary.imageBase + 0x1010;
    writeU64(0x200 + 2 * 8, methodInfoSlot);
    MetadataUsageModel methodRefPair;
    methodRefPair.destinationIndex = 2;
    methodRefPair.encodedSourceIndex = (6U << 29) | 1U;
    sharedMetadata.metadataUsagePairs.push_back(methodRefPair);
    const auto derivedEvidence = deriveEarlyArm64MethodInfoEvidence(usageBinary, sharedMetadata);
    assert(derivedEvidence.bySlotAddress.size() == 1);
    assert(derivedEvidence.bySlotAddress.at(methodInfoSlot) == 1);
    assert(derivedEvidence.typeReferencesByAddress.size() == 2);
    assert(derivedEvidence.typeReferencesByAddress.at(firstTypeAddress) == 0);
    assert(derivedEvidence.typeReferencesByAddress.at(secondTypeAddress) == 1);
    assert(derivedEvidence.conflictingDestinations == 0 && derivedEvidence.unmappedSlots == 0);

    auto duplicateTypeBinary = usageBinary;
    duplicateTypeBinary.bytes = std::make_shared<std::vector<uint8_t>>(*usageBinary.bytes);
    std::memcpy(duplicateTypeBinary.bytes->data() + 0x288, &firstTypeAddress, sizeof(firstTypeAddress));
    const auto duplicateTypeEvidence = deriveEarlyArm64MethodInfoEvidence(duplicateTypeBinary, sharedMetadata);
    assert(duplicateTypeEvidence.typeReferencesByAddress.empty());
    assert(duplicateTypeEvidence.conflictingTypeAddresses == 1);

    auto missingTypeBinary = usageBinary;
    missingTypeBinary.bytes = std::make_shared<std::vector<uint8_t>>(*usageBinary.bytes);
    const uint64_t missingTypeAddress = usageBinary.imageBase + 0x3000;
    std::memcpy(missingTypeBinary.bytes->data() + 0x288, &missingTypeAddress, sizeof(missingTypeAddress));
    const auto missingTypeEvidence = deriveEarlyArm64MethodInfoEvidence(missingTypeBinary, sharedMetadata);
    assert(missingTypeEvidence.typeReferencesByAddress.size() == 1);
    assert(missingTypeEvidence.unmappedTypeDescriptors == 1);

    auto conflictingUsage = sharedMetadata;
    auto conflictingPair = methodRefPair;
    conflictingPair.encodedSourceIndex = (6U << 29);
    conflictingUsage.metadataUsagePairs.push_back(conflictingPair);
    const auto conflictingEvidence = deriveEarlyArm64MethodInfoEvidence(usageBinary, conflictingUsage);
    assert(conflictingEvidence.bySlotAddress.empty() && conflictingEvidence.conflictingDestinations == 1);

    auto unmappedUsageBinary = usageBinary;
    unmappedUsageBinary.bytes = std::make_shared<std::vector<uint8_t>>(*usageBinary.bytes);
    const uint64_t unmappedSlot = usageBinary.imageBase + 0x2000;
    std::memcpy(unmappedUsageBinary.bytes->data() + 0x200 + 2 * 8, &unmappedSlot, sizeof(unmappedSlot));
    const auto unmappedEvidence = deriveEarlyArm64MethodInfoEvidence(unmappedUsageBinary, sharedMetadata);
    assert(unmappedEvidence.bySlotAddress.empty() && unmappedEvidence.unmappedSlots == 1);

    auto unsupportedVersion = sharedMetadata;
    unsupportedVersion.version = 24.5;
    assert(deriveEarlyArm64MethodInfoEvidence(usageBinary, unsupportedVersion).bySlotAddress.empty());

    const auto pointer = ScalarType::pointer(64);
    RecoveredFunction sharedCalls;
    sharedCalls.architecture = Architecture::Arm64;
    BasicBlock sharedBlock;
    sharedBlock.address = 0x2000;
    Statement slotLoad;
    slotLoad.kind = Statement::Kind::Assign;
    slotLoad.address = 0x2000;
    slotLoad.destination = reg("x1", pointer);
    slotLoad.value = load(constant(methodInfoSlot, pointer), pointer);
    sharedBlock.statements.push_back(slotLoad);
    Statement sharedCall;
    sharedCall.kind = Statement::Kind::Call;
    sharedCall.address = 0x2004;
    sharedCall.target = constant(0x9000, pointer);
    sharedCall.arguments = {reg("x0", pointer), reg("x1", pointer)};
    sharedBlock.statements.push_back(sharedCall);
    sharedCalls.blocks.push_back(sharedBlock);
    const auto findSharedCall = [](const ManagedAnalysisResult& result) -> const ManagedOperation* {
        for (const auto& operation : result.operations) {
            if (operation.kind == ManagedOperationKind::DirectMethodCall && operation.targetAddress == 0x9000)
                return &operation;
        }
        return nullptr;
    };
    const auto withoutEvidence = ManagedPatterns{}.analyze(sharedCalls, sharedMetadata);
    const auto* unresolvedSharedCall = findSharedCall(withoutEvidence);
    assert(unresolvedSharedCall && unresolvedSharedCall->status == ManagedPatternStatus::Ambiguous);
    assert(unresolvedSharedCall->reason.find("2 generic instantiations") != std::string::npos);

    ManagedPatternOptions patternEvidence;
    patternEvidence.genericMethodInfoArgumentIndex = 1;
    patternEvidence.genericMethodInfoByAddress = derivedEvidence.bySlotAddress;
    const auto withEvidence = ManagedPatterns{}.analyze(sharedCalls, sharedMetadata, patternEvidence);
    const auto* resolvedSharedCall = findSharedCall(withEvidence);
    assert(resolvedSharedCall && resolvedSharedCall->status == ManagedPatternStatus::Resolved);
    assert(resolvedSharedCall->genericTarget.present && resolvedSharedCall->genericTarget.genericMethodIndex == 1);
    ManagedEmitterOptions sharedEmitOptions;
    sharedEmitOptions.patterns = patternEvidence;
    const auto emittedShared = ManagedEmitter{}.emit(sharedCalls, sharedMetadata, sharedEmitOptions);
    const auto* emitterAnalysis = findSharedCall(emittedShared.managedAnalysis);
    assert(emitterAnalysis && emitterAnalysis->status == ManagedPatternStatus::Resolved);
    assert(emitterAnalysis->genericTarget.genericMethodIndex == 1);
    UniversalGenericResolverOptions genericTypeOptions;
    genericTypeOptions.typeReferencesByAddress = derivedEvidence.typeReferencesByAddress;
    const UniversalGenericResolver universalEvidence(sharedMetadata, genericTypeOptions);
    sharedEmitOptions.universalGenerics = &universalEvidence;
    sharedEmitOptions.universalGenericsSource = &sharedMetadata;
    const auto emittedWithTypes = ManagedEmitter{}.emit(sharedCalls, sharedMetadata, sharedEmitOptions);
    const auto* typedAnalysis = findSharedCall(emittedWithTypes.managedAnalysis);
    assert(typedAnalysis && typedAnalysis->genericTarget.genericMethodIndex == 1);
    auto copiedMetadata = sharedMetadata;
    const auto mismatchedSource = ManagedEmitter{}.emit(sharedCalls, copiedMetadata, sharedEmitOptions);
    assert(mismatchedSource.callSites.size() == emittedWithTypes.callSites.size());

    patternEvidence.genericMethodInfoArgumentIndex.reset();
    const auto inferredArgument = ManagedPatterns{}.analyze(sharedCalls, sharedMetadata, patternEvidence);
    const auto* inferredSharedCall = findSharedCall(inferredArgument);
    assert(inferredSharedCall && inferredSharedCall->status == ManagedPatternStatus::Resolved);
    assert(inferredSharedCall->genericTarget.genericMethodIndex == 1);

    ManagedPatternOptions borrowedEvidence;
    borrowedEvidence.genericMethodInfoByAddressView = &derivedEvidence.bySlotAddress;
    borrowedEvidence.genericMethodInfoByAddress.emplace(methodInfoSlot, 99);
    const auto withBorrowedEvidence = ManagedPatterns{}.analyze(sharedCalls, sharedMetadata, borrowedEvidence);
    const auto* borrowedSharedCall = findSharedCall(withBorrowedEvidence);
    assert(borrowedSharedCall && borrowedSharedCall->status == ManagedPatternStatus::Resolved);
    assert(borrowedSharedCall->genericTarget.genericMethodIndex == inferredSharedCall->genericTarget.genericMethodIndex);

    auto wrongAbiMetadata = sharedMetadata;
    wrongAbiMetadata.types[0].methods[0].parameters.push_back({"value", "int", -1});
    const auto wrongAbi = ManagedPatterns{}.analyze(sharedCalls, wrongAbiMetadata, patternEvidence);
    const auto* wrongAbiCall = findSharedCall(wrongAbi);
    assert(wrongAbiCall && wrongAbiCall->status == ManagedPatternStatus::Ambiguous);

    wrongAbiMetadata = sharedMetadata;
    wrongAbiMetadata.version = 24.5;
    const auto wrongVersion = ManagedPatterns{}.analyze(sharedCalls, wrongAbiMetadata, patternEvidence);
    const auto* wrongVersionCall = findSharedCall(wrongVersion);
    assert(wrongVersionCall && wrongVersionCall->status == ManagedPatternStatus::Ambiguous);

    patternEvidence.genericMethodInfoByAddress.clear();
    patternEvidence.genericMethodInfoArgumentIndex = 1;
    patternEvidence.genericMethodInfoByAddress.emplace(methodInfoSlot, 99);
    const auto conflict = ManagedPatterns{}.analyze(sharedCalls, sharedMetadata, patternEvidence);
    const auto* conflictedSharedCall = findSharedCall(conflict);
    assert(conflictedSharedCall && conflictedSharedCall->status == ManagedPatternStatus::Unresolved);
    assert(conflictedSharedCall->reason.find("conflicts") != std::string::npos);

    patternEvidence.genericMethodInfoByAddress.clear();
    const auto unavailable = ManagedPatterns{}.analyze(sharedCalls, sharedMetadata, patternEvidence);
    const auto* unavailableSharedCall = findSharedCall(unavailable);
    assert(unavailableSharedCall && unavailableSharedCall->status == ManagedPatternStatus::Ambiguous);

    // The dispatch analyzer must give the same target with a borrowed
    // per-metadata index and with its local fallback index.
    MetadataModel dispatchMetadata;
    dispatchMetadata.version = 24.0;
    TypeModel dispatchOwner;
    dispatchOwner.nameSpace = "Synthetic";
    dispatchOwner.name = "Owner";
    MethodModel dispatchMethod;
    dispatchMethod.name = "Target";
    dispatchMethod.definitionIndex = 0;
    dispatchMethod.address = 0x1900;
    dispatchOwner.methods.push_back(dispatchMethod);
    dispatchMetadata.types.push_back(dispatchOwner);
    BinaryImage dispatchImage;
    dispatchImage.architecture = Architecture::Arm64;
    dispatchImage.format = BinaryFormat::MachO;
    dispatchImage.imageBase = 0x1000;
    dispatchImage.bytes = std::make_shared<std::vector<uint8_t>>(0x1000, 0);
    dispatchImage.sections.push_back({"__DATA", 0x1000, 0x1000, 0, 0x1000, false});
    const auto writeDispatchU64 = [&](size_t offset, uint64_t value) {
        std::memcpy(dispatchImage.bytes->data() + offset, &value, sizeof(value));
    };
    writeDispatchU64(0x100, 0x1200); // object.klass
    writeDispatchU64(0x340, 0x1900); // klass.vtable[3].methodPointer
    writeDispatchU64(0x348, 0x1A00); // klass.vtable[3].methodInfo
    RecoveredFunction dispatchFunction;
    dispatchFunction.architecture = Architecture::Arm64;
    dispatchFunction.address = 0x2000;
    BasicBlock dispatchBlock;
    dispatchBlock.address = 0x2000;
    Statement dispatchCall;
    dispatchCall.kind = Statement::Kind::Call;
    dispatchCall.address = 0x2000;
    const auto dispatchObject = constant(0x1100, pointer);
    const auto klass = load(dispatchObject, pointer);
    dispatchCall.target = load(binary("+", klass, constant(320, pointer), pointer), pointer);
    dispatchCall.arguments = {dispatchObject};
    dispatchBlock.statements.push_back(dispatchCall);
    dispatchFunction.blocks.push_back(dispatchBlock);
    VirtualDispatchOptions dispatchOptions;
    dispatchOptions.binary = &dispatchImage;
    const auto fallbackDispatch = VirtualDispatch{}.analyze(dispatchFunction, dispatchMetadata, dispatchOptions);
    assert(fallbackDispatch.operations.size() == 1);
    assert(fallbackDispatch.operations.front().status == ManagedPatternStatus::Resolved);
    assert(fallbackDispatch.operations.front().method.address == 0x1900);
    const ManagedMetadataIndex dispatchIndex(dispatchMetadata);
    dispatchOptions.metadataIndex = &dispatchIndex;
    const auto sharedDispatch = VirtualDispatch{}.analyze(dispatchFunction, dispatchMetadata, dispatchOptions);
    assert(sharedDispatch.operations.size() == fallbackDispatch.operations.size());
    assert(sharedDispatch.operations.front().status == fallbackDispatch.operations.front().status);
    assert(sharedDispatch.operations.front().method.address == fallbackDispatch.operations.front().method.address);
    auto copiedDispatchMetadata = dispatchMetadata;
    const auto sourceMismatch = VirtualDispatch{}.analyze(dispatchFunction, copiedDispatchMetadata, dispatchOptions);
    assert(sourceMismatch.operations.size() == fallbackDispatch.operations.size());
    assert(sourceMismatch.operations.front().method.address == fallbackDispatch.operations.front().method.address);

    VirtualDispatchOptions perfDispatchOptions;
    perfDispatchOptions.binary = &dispatchImage;
    const auto dispatchStarted = std::chrono::steady_clock::now();
    const auto fallbackLarge = VirtualDispatch{}.analyze(dispatchFunction, genericMetadata, perfDispatchOptions);
    assert(!fallbackLarge.operations.empty());
    const auto fallbackDispatchUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - dispatchStarted).count();
    perfDispatchOptions.metadataIndex = &sharedIndex;
    const auto sharedDispatchStarted = std::chrono::steady_clock::now();
    for (size_t index = 0; index < 30; ++index) {
        const auto reused = VirtualDispatch{}.analyze(dispatchFunction, genericMetadata, perfDispatchOptions);
        assert(reused.operations.size() == fallbackLarge.operations.size());
        assert(reused.operations.front().status == fallbackLarge.operations.front().status);
    }
    const auto sharedDispatchUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - sharedDispatchStarted).count();
    std::cerr << "dispatch index probe: 5000 methods; fallback " << fallbackDispatchUs
              << " us, 30 shared analyses " << sharedDispatchUs << " us\n";

    MetadataModel fieldMetadata;
    TypeModel fieldOwner;
    fieldOwner.name = "FieldOwner";
    for (const auto& name : {"First", "Second"}) {
        FieldModel field;
        field.name = name;
        field.offset = 16;
        fieldOwner.fields.push_back(field);
    }
    FieldModel uniqueField;
    uniqueField.name = "Unique";
    uniqueField.offset = 24;
    fieldOwner.fields.push_back(uniqueField);
    fieldMetadata.types.push_back(fieldOwner);
    RecoveredFunction fieldFunction;
    fieldFunction.architecture = Architecture::Arm64;
    BasicBlock fieldBlock;
    fieldBlock.address = 0x5000;
    for (const uint64_t offset : {16ULL, 24ULL}) {
        Statement read;
        read.kind = Statement::Kind::Assign;
        read.address = 0x5000 + offset;
        read.destination = reg("read" + std::to_string(offset), ScalarType::uintBits(32));
        read.value = load(binary("+", reg("object", pointer), constant(offset, pointer), pointer),
                          ScalarType::uintBits(32));
        fieldBlock.statements.push_back(read);
    }
    fieldFunction.blocks.push_back(fieldBlock);
    const auto fullFields = ManagedPatterns{}.analyze(fieldFunction, fieldMetadata);
    ManagedPatternOptions compactFields;
    compactFields.collectAmbiguousFieldCandidates = false;
    const auto compact = ManagedPatterns{}.analyze(fieldFunction, fieldMetadata, compactFields);
    assert(fullFields.operations.size() == 2 && compact.operations.size() == 2);
    for (size_t index = 0; index < 2; ++index) {
        assert(fullFields.operations[index].kind == ManagedOperationKind::FieldLoad);
        assert(compact.operations[index].status == fullFields.operations[index].status);
        assert(compact.operations[index].reason == fullFields.operations[index].reason);
        assert(compact.operations[index].fieldCandidateCount == fullFields.operations[index].fieldCandidateCount);
    }
    assert(fullFields.operations[0].fieldCandidates.size() == 2);
    assert(compact.operations[0].fieldCandidates.empty());
    assert(compact.operations[0].fieldCandidateCount == 2);
    assert(fullFields.operations[1].fieldCandidates.size() == 1);
    assert(compact.operations[1].fieldCandidates.size() == 1);
    assert(compact.operations[1].field.name == "Unique");

    MetadataModel abiCallMetadata;
    abiCallMetadata.version = 24.0;
    TypeModel abiCallOwner;
    abiCallOwner.name = "CallOwner";
    MethodModel abiCallee;
    abiCallee.name = "Ping";
    abiCallee.declaringType = "CallOwner";
    abiCallee.returnType = "void";
    abiCallee.isStatic = true;
    abiCallee.definitionIndex = 0;
    abiCallee.address = 0xA000;
    abiCallOwner.methods.push_back(abiCallee);
    abiCallMetadata.types.push_back(abiCallOwner);
    RecoveredFunction abiCaller;
    abiCaller.architecture = Architecture::Arm64;
    BasicBlock abiCallBlock;
    abiCallBlock.address = 0xB000;
    Statement abiCallStatement;
    abiCallStatement.kind = Statement::Kind::Call;
    abiCallStatement.address = 0xB000;
    abiCallStatement.target = constant(0xA000, pointer);
    abiCallBlock.statements.push_back(abiCallStatement);
    abiCaller.blocks.push_back(abiCallBlock);
    const auto localAbi = ManagedEmitter{}.emit(abiCaller, abiCallMetadata);
    assert(localAbi.callSites.size() == 1);
    const AbiAdapter indexedAbi({}, abiCallMetadata);
    ManagedEmitterOptions sharedAbiOptions;
    sharedAbiOptions.abiAdapter = &indexedAbi;
    sharedAbiOptions.abiAdapterSource = &abiCallMetadata;
    const auto sharedAbi = ManagedEmitter{}.emit(abiCaller, abiCallMetadata, sharedAbiOptions);
    assert(sharedAbi.callSites.size() == localAbi.callSites.size());
    assert(sharedAbi.csharp == localAbi.csharp);
    assert(sharedAbi.callSites[0].status == localAbi.callSites[0].status);
    assert(sharedAbi.callSites[0].emitted == localAbi.callSites[0].emitted);
    auto copiedAbiMetadata = abiCallMetadata;
    const auto sourceFallback = ManagedEmitter{}.emit(abiCaller, copiedAbiMetadata, sharedAbiOptions);
    assert(sourceFallback.csharp == localAbi.csharp);
    auto policyMismatch = sharedAbiOptions;
    policyMismatch.abi.methodInfo = MethodInfoArgumentPolicy::Omit;
    auto localPolicy = policyMismatch;
    localPolicy.abiAdapter = nullptr;
    localPolicy.abiAdapterSource = nullptr;
    const auto mismatchFallback = ManagedEmitter{}.emit(abiCaller, abiCallMetadata, policyMismatch);
    const auto mismatchExpected = ManagedEmitter{}.emit(abiCaller, abiCallMetadata, localPolicy);
    assert(mismatchFallback.csharp == mismatchExpected.csharp);
    assert(mismatchFallback.callSites.size() == mismatchExpected.callSites.size());
}
