#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <il2cpprec/IR.hpp>
#include <il2cpprec/Model.hpp>

namespace il2cpprec {
namespace ida {
struct SourceLayoutSelection;
}

enum class MethodInfoArgumentPolicy {
    Omit,
    Append
};

enum class AbiInvokerSignature {
    LegacyThreeArguments,
    FourArguments,
    FiveArguments
};

enum class AbiMethodInfoPointerLayout {
    MethodPointerOnly,
    MethodAndVirtualMethodPointer
};

struct AbiRuntimeProfile {
    std::string id = "auto";
    AbiInvokerSignature invoker = AbiInvokerSignature::FourArguments;
    AbiMethodInfoPointerLayout methodInfoPointers = AbiMethodInfoPointerLayout::MethodPointerOnly;
    bool adjustorThunks = false;
    bool unresolvedReducedSignatures = false;
    MethodInfoArgumentPolicy generatedMethodInfo = MethodInfoArgumentPolicy::Append;

    static AbiRuntimeProfile automatic();
    static AbiRuntimeProfile forMetadataVersion(double version);
    static AbiRuntimeProfile legacyThreeArgument();
    static AbiRuntimeProfile unity2017();
    static AbiRuntimeProfile modernFourArgument();
    static AbiRuntimeProfile modernFiveArgument();
    static AbiRuntimeProfile fromSourceLayout(const ida::SourceLayoutSelection& selection);
};

enum class X64CallingConvention {
    Microsoft,
    SystemV
};

enum class X86CallingConvention {
    Cdecl,
    ThisCall,
    FastCall,
    StdCall
};

enum class Arm32FloatAbi {
    Soft,
    Hard
};

struct AbiAdapterOptions {
    MethodInfoArgumentPolicy methodInfo = MethodInfoArgumentPolicy::Append;
    X64CallingConvention x64 = X64CallingConvention::Microsoft;
    X86CallingConvention x86 = X86CallingConvention::Cdecl;
    Arm32FloatAbi arm32Float = Arm32FloatAbi::Hard;
    AbiRuntimeProfile runtime;
};

enum class AbiDiagnosticSeverity {
    Warning,
    Error
};

enum class AbiDiagnosticCode {
    UnsupportedArchitecture,
    UnsupportedType,
    UnsupportedReturnType,
    UnknownCallingConvention,
    InvalidCallSignature,
    UnresolvedGenericType,
    UnsupportedMarshalling,
    ReducedSignature,
    ProfileConflict
};

struct AbiDiagnostic {
    AbiDiagnosticSeverity severity = AbiDiagnosticSeverity::Error;
    AbiDiagnosticCode code = AbiDiagnosticCode::UnsupportedType;
    std::string message;
    std::optional<size_t> parameterIndex;
};

enum class AbiValueRole {
    This,
    Parameter,
    MethodInfo,
    MethodPointer,
    Instance,
    Parameters,
    InvokerContext
};

enum class AbiValueKind {
    Void,
    Integer,
    FloatingPoint,
    Pointer,
    ObjectReference,
    Unsupported,
    Unknown
};

enum class AbiLocationKind {
    None,
    Register,
    RegisterPair,
    Stack,
    Unsupported
};

struct AbiLocation {
    AbiLocationKind kind = AbiLocationKind::None;
    std::string registerName;
    std::string secondRegisterName;
    uint64_t stackOffset = 0;
    uint16_t size = 0;
};

struct AbiRegisterView {
    std::string storageName;
    ScalarType storageType;
    std::string viewName;
    ScalarType viewType;
    uint16_t bitOffset = 0;
    ExpressionPtr expression;
};

enum class AbiConversion {
    None,
    ObjectToNativePointer,
    NativePointerToObject,
    RawBitsToFloat,
    Unsupported
};

enum class AbiGenericParameterKind {
    Class,
    Method
};

struct AbiGenericParameter {
    AbiGenericParameterKind kind = AbiGenericParameterKind::Class;
    std::string name;
    std::optional<size_t> index;
};

struct AbiBinding {
    AbiValueRole role = AbiValueRole::Parameter;
    std::optional<size_t> parameterIndex;
    std::string name;
    std::string managedName;
    std::string managedType;
    AbiValueKind valueKind = AbiValueKind::Unsupported;
    ScalarType scalarType;
    AbiLocation location;
    ExpressionPtr nativeValue;
    ExpressionPtr value;
    AbiConversion conversion = AbiConversion::Unsupported;
    std::string runtimeHelper;
    std::optional<AbiGenericParameter> genericParameter;
    std::optional<AbiRegisterView> registerView;
};

struct AbiReturnModel {
    std::string managedType;
    AbiValueKind valueKind = AbiValueKind::Void;
    ScalarType scalarType;
    AbiLocation location;
    ExpressionPtr nativeValue;
    ExpressionPtr value;
    AbiConversion conversion = AbiConversion::None;
    std::string runtimeHelper;
    std::optional<AbiGenericParameter> genericParameter;
    std::optional<AbiRegisterView> registerView;
};

struct AbiBindingModel {
    Architecture architecture = Architecture::Arm64;
    std::vector<AbiBinding> bindings;
    AbiReturnModel returnValue;
    std::vector<Statement> statements;
    std::vector<AbiDiagnostic> diagnostics;
    bool reducedSignature = false;
    size_t omittedParameterCount = 0;

    bool supported() const;
};

enum class CallSiteKind {
    Unknown,
    GeneratedDirect,
    Invoker,
    GenericInstance,
    Virtual,
    Interface,
    InternalCall,
    PInvoke,
    Delegate,
    DelegatePInvoke,
    Unresolved,
    AdjustorThunk
};

enum class CallTargetKind {
    Unknown,
    MethodPointer,
    InvokerMethod,
    VirtualMethodPointer,
    InterfaceMethodPointer,
    InternalCall,
    PInvoke,
    DelegateMethodPointer,
    DelegatePInvokeWrapper,
    UnresolvedMethodPointer,
    AdjustorThunk
};

struct GenericContextAbiModel {
    bool present = false;
    ExpressionPtr methodInfo;
    ExpressionPtr classInstance;
    ExpressionPtr methodInstance;
    std::string rgctxDataHelper;
    std::string classInstanceHelper;
    std::string methodInstanceHelper;
    std::string resolveTypeHelper;
};

struct CallSiteAbiSpec {
    CallSiteKind kind = CallSiteKind::Unknown;
    ExpressionPtr methodPointer;
    ExpressionPtr virtualMethodPointer;
    ExpressionPtr invokerMethod;
    ExpressionPtr invokerContext;
    ExpressionPtr methodInfo;
    ExpressionPtr genericClassInstance;
    ExpressionPtr genericMethodInstance;
    std::optional<std::string> returnType;
    std::vector<std::string> parameterTypes;
    bool genericInstance = false;
    ExpressionPtr adjustorThunk;
    ExpressionPtr adjustorThunkThis;
    std::optional<int64_t> adjustorThunkThisOffset;
    std::optional<X64CallingConvention> x64;
    std::optional<X86CallingConvention> x86;
    std::optional<Arm32FloatAbi> arm32Float;
};

struct AdjustorThunkAbiModel {
    bool present = false;
    ExpressionPtr thunk;
    ExpressionPtr methodPointer;
    ExpressionPtr thisValue;
    int64_t thisOffset = 0;
};

struct CallSiteAbiModel {
    CallSiteKind kind = CallSiteKind::Unknown;
    CallTargetKind targetKind = CallTargetKind::Unknown;
    MethodInfoArgumentPolicy methodInfoPolicy = MethodInfoArgumentPolicy::Omit;
    AbiRuntimeProfile runtimeProfile;
    AbiAdapterOptions targetOptions;
    ExpressionPtr target;
    ExpressionPtr methodPointer;
    ExpressionPtr virtualMethodPointer;
    ExpressionPtr invokerMethod;
    ExpressionPtr invokerContext;
    ExpressionPtr methodInfo;
    std::string targetRuntimeHelper;
    std::string methodInfoRuntimeHelper;
    GenericContextAbiModel genericContext;
    AdjustorThunkAbiModel adjustorThunk;
    AbiBindingModel signature;
    std::vector<AbiDiagnostic> diagnostics;

    bool supported() const;
    const AbiReturnModel& typedReturn() const { return signature.returnValue; }
};

class AbiAdapter {
public:
    explicit AbiAdapter(AbiAdapterOptions options = {});

    AbiBindingModel bind(
        const MethodModel& method,
        const MetadataModel& metadata,
        Architecture architecture) const;

    CallSiteAbiModel bindCallSite(
        const MethodModel& method,
        const MetadataModel& metadata,
        Architecture architecture,
        const CallSiteAbiSpec& spec) const;

    std::vector<Statement> bindingStatements(
        const MethodModel& method,
        const MetadataModel& metadata,
        Architecture architecture) const;

    std::vector<Statement> returnStatements(
        const AbiBindingModel& model,
        uint64_t address = 0) const;

    const AbiAdapterOptions& options() const { return options_; }

private:
    AbiAdapterOptions options_;
};

AbiBindingModel adaptMethodAbi(
    const MethodModel& method,
    const MetadataModel& metadata,
    Architecture architecture,
    AbiAdapterOptions options = {});

CallSiteAbiModel adaptCallSiteAbi(
    const MethodModel& method,
    const MetadataModel& metadata,
    Architecture architecture,
    const CallSiteAbiSpec& spec,
    AbiAdapterOptions options = {});

} // namespace il2cpprec
