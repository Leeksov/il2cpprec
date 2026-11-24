#include <il2cpprec/analysis/ManagedEmitter.hpp>

#include <il2cpprec/metadata/CodeGenModules.hpp>
#include <il2cpprec/metadata/MetadataRegistration.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>
#include <il2cpprec/metadata/UniversalGenericResolver.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <utility>

namespace il2cpprec {
namespace {

using StatementKey = std::pair<size_t, size_t>;

struct PendingCall {
    ManagedCallSite output;
    MethodModel method;
    CallSiteAbiSpec spec;
    uint64_t markerAddress = 0;
    std::string wrapperName;
    std::string wrapperBody;
    ExpressionPtr helperReceiver;
    size_t helperArgumentPrefix = 0;
    bool helperCall = false;
    bool prepare = false;
    std::vector<std::string> methodTypeArguments;
};

uint16_t pointerBits(Architecture architecture) {
    return architecture == Architecture::Arm64 || architecture == Architecture::X64 ? 64 : 32;
}

std::string nativeType(Architecture architecture) {
    return pointerBits(architecture) == 64 ? "ulong" : "uint";
}

std::string identifier(std::string value) {
    for (auto& character : value) {
        if (!std::isalnum(static_cast<unsigned char>(character)) && character != '_') character = '_';
    }
    return value;
}

std::string qualifiedTypeName(const TypeModel& type) {
    if (type.nameSpace.empty()) return type.name;
    if (type.name.empty()) return type.nameSpace;
    return type.nameSpace + "." + type.name;
}

std::optional<MethodModel> findMethod(const MetadataModel& metadata, const ManagedMethodReference& reference) {
    std::optional<MethodModel> result;
    size_t matches = 0;
    for (const auto& type : metadata.types) {
        const auto declaringType = qualifiedTypeName(type);
        for (const auto& method : type.methods) {
            if (reference.token != 0 && method.token != reference.token) continue;
            if (reference.definitionIndex >= 0 && method.definitionIndex != reference.definitionIndex) continue;
            if (!reference.name.empty() && method.name != reference.name) continue;
            if (!reference.imageName.empty() && method.imageName != reference.imageName) continue;
            if (!reference.declaringType.empty() && !method.declaringType.empty() && method.declaringType != reference.declaringType) continue;
            if (reference.token == 0 && reference.definitionIndex < 0 && method.address != reference.address) continue;
            result = method;
            if (result->declaringType.empty()) result->declaringType = declaringType;
            ++matches;
        }
    }
    if (matches != 1) return std::nullopt;
    return result;
}

std::string resolveTypeName(std::string type, const MetadataModel& metadata) {
    if (type.size() >= 7 && type.starts_with("type[") && type.back() == ']') {
        if (metadata.typeReferences.empty()) return {};
        return TypeSystem::resolve(type, &metadata);
    }
    return type;
}

std::string csharpType(std::string type, const MetadataModel& metadata) {
    static const std::set<std::string> primitives = {
        "void", "bool", "char", "sbyte", "byte", "short", "ushort", "int", "uint", "long", "ulong",
        "float", "double", "string", "object", "nint", "nuint"
    };
    if (type.empty()) return {};
    type = resolveTypeName(std::move(type), metadata);
    if (type.empty()) return {};
    if (primitives.contains(type)) return type;
    if (type.starts_with("global::")) type.erase(0, 8);
    // Match the metadata generic name to the declaration spelling used by ProjectWriter.
    for (size_t open = type.find('<'); open != std::string::npos; open = type.find('<', open + 1)) {
        size_t start = open;
        while (start != 0 && type[start - 1] != '<' && type[start - 1] != ',' && type[start - 1] != ' ') --start;
        const auto name = type.substr(start, open - start);
        std::optional<std::string> declaration;
        for (const auto& definition : metadata.types) {
            const auto tick = definition.name.rfind('`');
            if (tick == std::string::npos && definition.genericContainerIndex < 0) continue;
            const auto base = definition.nameSpace.empty()
                ? definition.name.substr(0, tick)
                : definition.nameSpace + "." + definition.name.substr(0, tick);
            if (base != name) continue;
            const auto candidate = tick == std::string::npos ? base : definition.nameSpace.empty()
                ? definition.name.substr(0, tick) + "_" + definition.name.substr(tick + 1)
                : definition.nameSpace + "." + definition.name.substr(0, tick) + "_" + definition.name.substr(tick + 1);
            if (declaration && *declaration != candidate) return {};
            declaration = candidate;
        }
        if (!declaration) return {};
        type.replace(start, open - start, *declaration);
        open = start + declaration->size();
    }
    int genericDepth = 0;
    for (const auto character : type) {
        if (character == '<') { ++genericDepth; continue; }
        if (character == '>') { if (--genericDepth < 0) return {}; continue; }
        if (!std::isalnum(static_cast<unsigned char>(character)) && character != '_' && character != '.' &&
            character != '[' && character != ']' && character != '*' && character != '&' &&
            character != ',' && character != ' ') {
            return {};
        }
    }
    if (genericDepth != 0 || type.find("<unresolved") != std::string::npos ||
        type.find('!') != std::string::npos || type.find('`') != std::string::npos) return {};
    return "global::" + type;
}

std::optional<std::string> csharpMethodName(const MethodModel& method, CallSiteKind kind) {
    auto name = method.name;
    if (name == ".ctor" || name == ".cctor" || name.find('`') != std::string::npos ||
        name.find('<') != std::string::npos || name.find('>') != std::string::npos) {
        return std::nullopt;
    }
    if (kind == CallSiteKind::Interface) {
        const auto separator = name.rfind('.');
        if (separator != std::string::npos) name = name.substr(separator + 1);
    }
    if (name.empty() || (!std::isalpha(static_cast<unsigned char>(name.front())) && name.front() != '_')) return std::nullopt;
    for (const auto character : name) {
        if (!std::isalnum(static_cast<unsigned char>(character)) && character != '_') return std::nullopt;
    }
    static const std::set<std::string> keywords = {
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked", "class", "const",
        "continue", "decimal", "default", "delegate", "do", "double", "else", "enum", "event", "explicit", "extern",
        "false", "finally", "fixed", "float", "for", "foreach", "goto", "if", "implicit", "in", "int", "interface",
        "internal", "is", "lock", "long", "namespace", "new", "null", "object", "operator", "out", "override", "params",
        "private", "protected", "public", "readonly", "ref", "return", "sbyte", "sealed", "short", "sizeof", "stackalloc",
        "static", "string", "struct", "switch", "this", "throw", "true", "try", "typeof", "uint", "ulong", "unchecked",
        "unsafe", "ushort", "using", "virtual", "void", "volatile", "while"
    };
    return keywords.contains(name) ? "@" + name : name;
}

std::string inputConversion(const AbiBinding& binding, const std::string& argument, const MetadataModel& metadata) {
    const auto type = csharpType(binding.managedType, metadata);
    if (type.empty()) return {};
    switch (binding.valueKind) {
    case AbiValueKind::ObjectReference:
        return "RuntimeCalls.NativePointerToObject<" + type + ">(" + argument + ")";
    case AbiValueKind::FloatingPoint:
        if (binding.scalarType.bits == 32) return "RuntimeCalls.UInt32BitsToSingle(unchecked((uint)" + argument + "))";
        if (binding.scalarType.bits == 64) return "RuntimeCalls.UInt64BitsToDouble(" + argument + ")";
        return {};
    case AbiValueKind::Integer:
        if (binding.scalarType.kind == ScalarKind::Boolean) return '(' + argument + " != 0)";
        return "unchecked((" + type + ')' + argument + ")";
    case AbiValueKind::Pointer:
        return "unchecked((" + type + ')' + argument + ")";
    default:
        return {};
    }
}

std::string returnConversion(const AbiReturnModel& value, const std::string& invocation, Architecture architecture, const MetadataModel& metadata) {
    const auto native = nativeType(architecture);
    const auto type = csharpType(value.managedType, metadata);
    if (type.empty()) return {};
    switch (value.valueKind) {
    case AbiValueKind::ObjectReference:
        return "RuntimeCalls.ObjectToNativePointer(" + invocation + ")";
    case AbiValueKind::FloatingPoint:
        if (value.scalarType.bits == 32) return "RuntimeCalls.SingleToUInt32Bits(" + invocation + ")";
        if (value.scalarType.bits == 64) return "RuntimeCalls.DoubleToUInt64Bits(" + invocation + ")";
        return {};
    case AbiValueKind::Integer:
        if (value.scalarType.kind == ScalarKind::Boolean) return '(' + invocation + " ? (" + native + ")1 : (" + native + ")0)";
        return "unchecked((" + native + ")(" + invocation + "))";
    case AbiValueKind::Pointer:
        return "unchecked((" + native + ")(" + invocation + "))";
    default:
        return {};
    }
}

ExpressionPtr helperArgument(
    const Statement& statement,
    Architecture architecture,
    size_t index) {
    if (index < statement.arguments.size()) return statement.arguments[index];
    const auto pointer = ScalarType::pointer(pointerBits(architecture));
    static constexpr const char* arm64Registers[] = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    static constexpr const char* arm32Registers[] = {"r0", "r1", "r2", "r3"};
    static constexpr const char* x64Registers[] = {"rcx", "rdx", "r8", "r9"};
    const char* name = nullptr;
    const char* stack = nullptr;
    size_t registerCount = 0;
    uint64_t stackOffset = 0;
    switch (architecture) {
    case Architecture::Arm64:
        if (index < 8) name = arm64Registers[index];
        registerCount = 8;
        stack = "sp";
        break;
    case Architecture::Arm32:
        if (index < 4) name = arm32Registers[index];
        registerCount = 4;
        stack = "sp";
        break;
    case Architecture::X64:
        if (index < 4) name = x64Registers[index];
        registerCount = 4;
        stack = "rsp";
        stackOffset = 40;
        break;
    case Architecture::X86:
        stack = "esp";
        stackOffset = 4;
        break;
    }
    if (name) return reg(name, pointer);
    if (!stack || index < registerCount) return {};
    const auto address = binary("+", reg(stack, pointer), constant(stackOffset + (index - registerCount) * (pointerBits(architecture) / 8), pointer), pointer);
    return load(address, pointer);
}

std::vector<ExpressionPtr> nativeArguments(const PendingCall& call, const Statement& statement, Architecture architecture) {
    std::vector<ExpressionPtr> result;
    for (const auto& binding : call.output.abi.signature.bindings) {
        if (binding.role != AbiValueRole::This && binding.role != AbiValueRole::Parameter) continue;
        if (call.helperCall && binding.role == AbiValueRole::This && call.helperReceiver) {
            result.push_back(call.helperReceiver);
            continue;
        }
        if (call.helperCall && binding.role == AbiValueRole::Parameter && binding.parameterIndex) {
            result.push_back(helperArgument(statement, architecture, call.helperArgumentPrefix + *binding.parameterIndex));
            continue;
        }
        if (binding.nativeValue) result.push_back(binding.nativeValue);
    }
    return result;
}

std::string returnRegister(Architecture architecture) {
    switch (architecture) {
    case Architecture::Arm64: return "x0";
    case Architecture::Arm32: return "r0";
    case Architecture::X64: return "rax";
    case Architecture::X86: return "eax";
    }
    return {};
}

bool buildWrapper(PendingCall& call, Architecture architecture, const MetadataModel& metadata) {
    const auto& model = call.output.abi;
    const auto& method = call.method;
    const auto methodName = csharpMethodName(method, model.kind);
    const auto declaringType = csharpType(method.declaringType, metadata);
    if (!methodName || declaringType.empty()) {
        call.output.reason = "The managed method or declaring type has no unambiguous C# representation.";
        return false;
    }

    std::vector<const AbiBinding*> inputs;
    for (const auto& binding : model.signature.bindings) {
        if (binding.role == AbiValueRole::This || binding.role == AbiValueRole::Parameter) inputs.push_back(&binding);
    }
    const AbiBinding* receiver = nullptr;
    std::vector<std::string> arguments;
    std::vector<std::string> parameters;
    for (size_t index = 0; index < inputs.size(); ++index) {
        const auto& binding = *inputs[index];
        const auto name = "arg" + std::to_string(index);
        parameters.push_back(nativeType(architecture) + " " + name);
        auto converted = inputConversion(binding, name, metadata);
        if (converted.empty()) {
            call.output.reason = "An ABI input has no managed conversion.";
            return false;
        }
        if (binding.role == AbiValueRole::This) receiver = &binding;
        else arguments.push_back(std::move(converted));
    }

    std::string invocation;
    if (method.isStatic && model.kind != CallSiteKind::Virtual && model.kind != CallSiteKind::Interface) {
        invocation = declaringType + "." + *methodName;
    } else {
        if (!receiver) {
            call.output.reason = "An instance call has no ABI receiver.";
            return false;
        }
        const size_t receiverIndex = static_cast<size_t>(std::find(inputs.begin(), inputs.end(), receiver) - inputs.begin());
        const auto receiverValue = inputConversion(*receiver, "arg" + std::to_string(receiverIndex), metadata);
        if (receiverValue.empty()) {
            call.output.reason = "The ABI receiver has no managed conversion.";
            return false;
        }
        invocation = model.kind == CallSiteKind::Interface
            ? "((" + declaringType + ")" + receiverValue + ")." + *methodName
            : receiverValue + "." + *methodName;
    }
    if (!call.methodTypeArguments.empty()) {
        invocation += '<';
        for (size_t index = 0; index < call.methodTypeArguments.size(); ++index) {
            if (index != 0) invocation += ", ";
            invocation += call.methodTypeArguments[index];
        }
        invocation += '>';
    }
    invocation += '(';
    for (size_t index = 0; index < arguments.size(); ++index) {
        if (index != 0) invocation += ", ";
        invocation += arguments[index];
    }
    invocation += ')';

    std::ostringstream output;
    output << "    public static " << nativeType(architecture) << ' ' << call.wrapperName << '(';
    for (size_t index = 0; index < parameters.size(); ++index) {
        if (index != 0) output << ", ";
        output << parameters[index];
    }
    output << ")\n    {\n";
    if (model.typedReturn().valueKind == AbiValueKind::Void) {
        output << "        " << invocation << ";\n        return 0;\n";
    } else {
        const auto converted = returnConversion(model.typedReturn(), invocation, architecture, metadata);
        if (converted.empty()) {
            call.output.reason = "The ABI return value has no managed conversion.";
            return false;
        }
        output << "        return " << converted << ";\n";
    }
    output << "    }\n";
    call.output.reason.clear();
    call.wrapperBody = output.str();
    return true;
}

bool replaceOnce(std::string& text, const std::string& source, const std::string& destination) {
    const auto position = text.find(source);
    if (position == std::string::npos || text.find(source, position + 1) != std::string::npos) return false;
    text.replace(position, source.size(), destination);
    return true;
}

std::string markerPrefix(const PendingCall& call, Architecture architecture) {
    std::ostringstream output;
    output << "RuntimeCalls.InvokeDirect(";
    if (pointerBits(architecture) == 32) output << "unchecked((uint)";
    output << "0x" << std::hex << std::uppercase << call.markerAddress << "UL";
    if (pointerBits(architecture) == 32) output << ')';
    return output.str();
}

} // namespace

ManagedEmitResult ManagedEmitter::emit(
    const RecoveredFunction& function,
    const MetadataModel& metadata,
    const ManagedEmitterOptions& options) const {
    ManagedEmitResult result;
    auto resolvedMetadata = metadata;
    if (resolvedMetadata.version == 0 && resolvedMetadata.versionInfo.preciseVersion != 0) {
        resolvedMetadata.version = resolvedMetadata.versionInfo.preciseVersion;
    }
    const auto* binary = options.patterns.binary ? options.patterns.binary : options.dispatch.binary;
    if (binary && resolvedMetadata.methodPointersByImage.empty()) discoverCodeGenModules(*binary, resolvedMetadata);
    if (binary && resolvedMetadata.typeReferences.empty() && resolvedMetadata.metadataRegistrationAddress != 0) {
        try {
            MetadataRegistrationReader{}.read(*binary, resolvedMetadata);
        } catch (const std::exception&) {
        }
    }
    auto patternOptions = options.patterns;
    auto dispatchOptions = options.dispatch;
    patternOptions.profile.genericAdjustorTargets.insert(options.profile.genericAdjustorTargets.begin(), options.profile.genericAdjustorTargets.end());
    patternOptions.profile.unresolvedVirtualCallStubs.insert(options.profile.unresolvedVirtualCallStubs.begin(), options.profile.unresolvedVirtualCallStubs.end());
    patternOptions.profile.genericTypeAddresses.insert(options.profile.genericTypeAddresses.begin(), options.profile.genericTypeAddresses.end());
    dispatchOptions.profile.genericAdjustorTargets.insert(options.profile.genericAdjustorTargets.begin(), options.profile.genericAdjustorTargets.end());
    dispatchOptions.profile.unresolvedVirtualCallStubs.insert(options.profile.unresolvedVirtualCallStubs.begin(), options.profile.unresolvedVirtualCallStubs.end());
    dispatchOptions.profile.genericTypeAddresses.insert(options.profile.genericTypeAddresses.begin(), options.profile.genericTypeAddresses.end());
    result.managedAnalysis = ManagedPatterns{}.analyze(function, resolvedMetadata, patternOptions);
    result.dispatchAnalysis = VirtualDispatch{}.analyze(function, resolvedMetadata, dispatchOptions);

    std::map<StatementKey, PendingCall> pending;
    std::vector<StatementKey> order;
    auto addCall = [&](ManagedCallSite call, bool replace) {
        const StatementKey key{call.blockIndex, call.statementIndex};
        if (pending.contains(key) && !replace) return;
        call.address = call.nativeStatements.empty() ? call.address : call.nativeStatements.back().address;
        if (!pending.contains(key)) order.push_back(key);
        PendingCall pendingCall;
        pendingCall.output = std::move(call);
        pending[key] = std::move(pendingCall);
    };

    for (const auto& operation : result.managedAnalysis.operations) {
        if (operation.kind != ManagedOperationKind::DirectMethodCall) continue;
        ManagedCallSite call;
        call.kind = CallSiteKind::GeneratedDirect;
        call.status = operation.status;
        call.confidence = operation.confidence;
        call.address = operation.address;
        call.blockIndex = operation.blockIndex;
        call.statementIndex = operation.statementIndex;
        call.method = operation.method;
        call.genericTarget = operation.genericTarget;
        call.unresolvedStub = operation.unresolvedStub;
        call.reason = operation.reason;
        call.nativeStatements = operation.nativeStatements;
        addCall(std::move(call), false);
    }
    for (const auto& operation : result.dispatchAnalysis.operations) {
        ManagedCallSite call;
        const bool interfaceCall = operation.kind == VirtualDispatchKind::Interface || operation.kind == VirtualDispatchKind::GenericInterface;
        call.kind = interfaceCall ? CallSiteKind::Interface : CallSiteKind::Virtual;
        call.status = operation.status;
        call.confidence = operation.confidence;
        call.address = operation.address;
        call.blockIndex = operation.blockIndex;
        call.statementIndex = operation.statementIndex;
        call.method = operation.method;
        call.genericTarget = operation.genericTarget;
        call.reason = operation.reason;
        call.nativeStatements = operation.nativeStatements;
        addCall(std::move(call), true);
    }

    AbiAdapter adapter(options.abi);
    auto copy = function;
    for (size_t index = 0; index < order.size(); ++index) {
        auto& call = pending.at(order[index]);
        if (call.output.unresolvedStub || call.output.status != ManagedPatternStatus::Resolved) {
            if (call.output.reason.empty()) call.output.reason = "The managed target is unresolved; native IR remains in use.";
            continue;
        }
        const auto method = findMethod(resolvedMetadata, call.output.method);
        if (!method) {
            call.output.status = ManagedPatternStatus::Placeholder;
            call.output.reason = "The resolved reference does not identify one complete MethodModel.";
            continue;
        }
        call.method = *method;
        if (call.output.genericTarget.present) {
            const auto genericIndex = call.output.genericTarget.genericMethodIndex;
            if (genericIndex < 0) {
                call.output.status = ManagedPatternStatus::Placeholder;
                call.output.reason = "The generic method index is invalid.";
                continue;
            }
            const auto inflated = UniversalGenericResolver(resolvedMetadata).resolve(static_cast<uint32_t>(genericIndex));
            if (!inflated.ok() || !inflated.method || inflated.methodPointer == 0 ||
                (call.output.genericTarget.adjustor && inflated.adjustorThunk != call.output.method.address)) {
                call.output.status = ManagedPatternStatus::Placeholder;
                call.output.reason = "The closed generic signature or native target is unresolved.";
                continue;
            }
            call.method = *inflated.method;
            for (const auto typeIndex : inflated.substitution.methodArguments) {
                const auto type = UniversalGenericResolver(resolvedMetadata).substitute(typeIndex);
                const auto syntax = type.ok() ? csharpType(type.name, resolvedMetadata) : std::string{};
                if (syntax.empty()) break;
                call.methodTypeArguments.push_back(syntax);
            }
            if (call.methodTypeArguments.size() != inflated.substitution.methodArguments.size()) {
                call.output.status = ManagedPatternStatus::Placeholder;
                call.output.reason = "A generic method argument has no C# type representation.";
                continue;
            }
            const auto arity = call.method.name.find('`');
            if (arity != std::string::npos) {
                const auto suffix = call.method.name.substr(arity + 1);
                unsigned parsedArity = 0;
                const auto parsed = std::from_chars(suffix.data(), suffix.data() + suffix.size(), parsedArity);
                if (suffix.empty() || parsed.ec != std::errc{} || parsed.ptr != suffix.data() + suffix.size() ||
                    parsedArity != call.methodTypeArguments.size()) {
                    call.output.status = ManagedPatternStatus::Placeholder;
                    call.output.reason = "The generic method name does not match its instantiation.";
                    continue;
                }
                // ProjectWriter spells metadata backticks as underscores in declarations.
                call.method.name[arity] = '_';
            }
        }
        if (call.method.name.empty() || call.method.declaringType.empty() || call.method.returnType.empty() ||
            std::any_of(call.method.parameters.begin(), call.method.parameters.end(),
                        [](const ParameterModel& parameter) { return parameter.type.empty(); })) {
            call.output.status = ManagedPatternStatus::Placeholder;
            call.output.reason = "The MethodModel has an incomplete managed signature.";
            continue;
        }
        call.spec.kind = call.output.kind;
        call.spec.methodPointer = constant(call.output.method.address, ScalarType::pointer(pointerBits(function.architecture)));
        if (call.output.genericTarget.present) {
            call.spec.genericInstance = true;
            const auto& target = call.output.genericTarget;
            if (target.mapping.methodPointer != 0) {
                call.spec.methodPointer = constant(target.mapping.methodPointer,
                    ScalarType::pointer(pointerBits(function.architecture)));
            }
            if (target.classInstIndex >= 0 && static_cast<size_t>(target.classInstIndex) < resolvedMetadata.genericInsts.size()) {
                call.spec.genericClassInstance = constant(resolvedMetadata.genericInsts[static_cast<size_t>(target.classInstIndex)].address,
                    ScalarType::pointer(pointerBits(function.architecture)));
            }
            if (target.methodInstIndex >= 0 && static_cast<size_t>(target.methodInstIndex) < resolvedMetadata.genericInsts.size()) {
                call.spec.genericMethodInstance = constant(resolvedMetadata.genericInsts[static_cast<size_t>(target.methodInstIndex)].address,
                    ScalarType::pointer(pointerBits(function.architecture)));
            }
            if (target.adjustor) {
                call.spec.adjustorThunk = constant(call.output.method.address, ScalarType::pointer(pointerBits(function.architecture)));
            }
        }
        const auto& native = call.output.nativeStatements;
        if (!native.empty()) {
            const auto& statement = native.back();
            if (statement.kind != Statement::Kind::Call && statement.kind != Statement::Kind::Branch) {
                call.output.status = ManagedPatternStatus::Placeholder;
                call.output.reason = "The resolved statement is not a call or tail call.";
                continue;
            }
            if (statement.kind == Statement::Kind::Branch && statement.condition) {
                call.output.status = ManagedPatternStatus::Placeholder;
                call.output.reason = "Conditional tail dispatch remains native.";
                continue;
            }
        }
        const auto& dispatch = result.dispatchAnalysis.operations;
        const auto operation = std::find_if(dispatch.begin(), dispatch.end(), [&](const auto& candidate) {
            return candidate.blockIndex == call.output.blockIndex && candidate.statementIndex == call.output.statementIndex;
        });
        if (operation != dispatch.end()) {
            call.spec.methodPointer = constant(operation->invokeData.methodPointer, ScalarType::pointer(pointerBits(function.architecture)));
            if (operation->hasMethodInfo) call.spec.methodInfo = constant(operation->invokeData.methodInfo, ScalarType::pointer(pointerBits(function.architecture)));
            else if (operation->methodInfoExpression) call.spec.methodInfo = operation->methodInfoExpression;
            call.spec.genericInstance = call.spec.genericInstance ||
                operation->kind == VirtualDispatchKind::GenericVirtual || operation->kind == VirtualDispatchKind::GenericInterface;
            if (!native.empty() && native.back().target && native.back().target->kind == Expression::Kind::Constant) {
                const auto target = native.back().target->constant;
                const bool interfaceHelper = options.dispatch.interfaceHelperAddresses.contains(target) ||
                    options.dispatch.genericInterfaceHelperAddresses.contains(target);
                const bool virtualHelper = options.dispatch.virtualHelperAddresses.contains(target) ||
                    options.dispatch.genericVirtualHelperAddresses.contains(target);
                if (interfaceHelper || virtualHelper) {
                    call.helperCall = true;
                    call.helperReceiver = operation->object;
                    call.helperArgumentPrefix = interfaceHelper
                        ? std::max({options.dispatch.interfaceSlotArgument, options.dispatch.interfaceTypeArgument, options.dispatch.interfaceObjectArgument}) + 1
                        : std::max(options.dispatch.virtualSlotArgument, options.dispatch.virtualObjectArgument) + 1;
                }
            }
        }
        call.output.abi = adapter.bindCallSite(call.method, resolvedMetadata, function.architecture, call.spec);
        if (!call.output.abi.supported()) {
            call.output.status = ManagedPatternStatus::Placeholder;
            call.output.reason = "CallSiteAbiModel rejected the managed signature.";
            continue;
        }
        if (call.output.abi.typedReturn().scalarType.bits > pointerBits(function.architecture)) {
            call.output.status = ManagedPatternStatus::Placeholder;
            call.output.reason = "The return value is wider than the native wrapper.";
            continue;
        }
        call.markerAddress = pointerBits(function.architecture) == 64
            ? uint64_t{0xFFFFFFFF00000000} + index
            : uint64_t{0xF0000000} + index;
        call.wrapperName = "Call_" + std::to_string(index);
        call.prepare = true;
        if (!buildWrapper(call, function.architecture, resolvedMetadata)) {
            call.output.status = ManagedPatternStatus::Placeholder;
            call.prepare = false;
            continue;
        }
        call.output.emitted = true;
    }

    for (size_t blockIndex = 0; blockIndex < copy.blocks.size(); ++blockIndex) {
        std::vector<Statement> statements;
        for (size_t statementIndex = 0; statementIndex < copy.blocks[blockIndex].statements.size(); ++statementIndex) {
            const auto& original = copy.blocks[blockIndex].statements[statementIndex];
            const auto found = pending.find({blockIndex, statementIndex});
            if (found == pending.end() || !found->second.prepare || !found->second.output.emitted) {
                statements.push_back(original);
                continue;
            }
            auto& call = found->second;
            auto statement = original;
            statement.address = 0;
            statement.kind = Statement::Kind::Call;
            statement.target = constant(call.markerAddress, ScalarType::pointer(pointerBits(function.architecture)));
            statement.arguments = nativeArguments(call, original, function.architecture);
            if (original.kind == Statement::Kind::Branch) {
                statement.destination = reg(returnRegister(function.architecture), ScalarType::pointer(pointerBits(function.architecture)));
                statements.push_back(std::move(statement));
                Statement tailReturn;
                tailReturn.kind = Statement::Kind::Return;
                tailReturn.address = original.address;
                tailReturn.value = reg(returnRegister(function.architecture), ScalarType::pointer(pointerBits(function.architecture)));
                statements.push_back(std::move(tailReturn));
            } else {
                statements.push_back(std::move(statement));
            }
        }
        copy.blocks[blockIndex].statements = std::move(statements);
    }

    auto nativeCSharp = copy.toCSharp();
    bool replacementsSucceeded = true;
    for (const auto& key : order) {
        auto& call = pending.at(key);
        if (!call.output.emitted) continue;
        const auto prefix = markerPrefix(call, function.architecture);
        const auto invocation = "ManagedCallSites_" + identifier(function.name) + "." + call.wrapperName;
        const auto replaced = replaceOnce(nativeCSharp, prefix + ")", invocation + "()") ||
            replaceOnce(nativeCSharp, prefix + ", ", invocation + "(");
        if (!replaced) {
            replacementsSucceeded = false;
            call.output.emitted = false;
            call.output.status = ManagedPatternStatus::Placeholder;
            call.output.reason = "The existing native emitter did not expose the resolved statement.";
        }
    }
    if (!replacementsSucceeded) {
        nativeCSharp = function.toCSharp();
        for (auto& [key, call] : pending) {
            if (call.output.emitted) {
                call.output.emitted = false;
                call.output.status = ManagedPatternStatus::Placeholder;
                call.output.reason = "Managed marker mapping failed; native output was restored.";
            }
        }
    }

    std::ostringstream wrappers;
    wrappers << "\npublic static unsafe class ManagedCallSites_" << identifier(function.name) << "\n{\n";
    for (const auto& key : order) {
        const auto& call = pending.at(key);
        if (call.prepare) wrappers << call.wrapperBody << '\n';
    }
    wrappers << "}\n";
    result.csharp = nativeCSharp + wrappers.str();
    for (const auto& key : order) result.callSites.push_back(std::move(pending.at(key).output));
    return result;
}

} // namespace il2cpprec
