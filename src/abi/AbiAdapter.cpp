#include <il2cpprec/abi/AbiAdapter.hpp>

#include <il2cpprec/ida/SourceProfile.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
struct AbiTypeNameIndex {
    std::unordered_map<std::string, size_t> qualified;
    std::unordered_map<std::string, std::optional<size_t>> unqualified;

    explicit AbiTypeNameIndex(const MetadataModel& metadata);
    const TypeModel* find(std::string_view name, const MetadataModel& metadata) const;
};

namespace {

constexpr const char* unsupportedAbiHelper = "RuntimeCalls.UnsupportedAbi";
constexpr const char* objectToNativeHelper = "RuntimeCalls.ObjectToNativePointer";
constexpr const char* nativeToObjectHelper = "RuntimeCalls.NativePointerToObject";
constexpr const char* bitsToSingleHelper = "RuntimeCalls.UInt32BitsToSingle";
constexpr const char* bitsToDoubleHelper = "RuntimeCalls.UInt64BitsToDouble";
constexpr const char* virtualTargetHelper = "RuntimeCalls.ResolveVirtualMethodPointer";
constexpr const char* interfaceTargetHelper = "RuntimeCalls.ResolveInterfaceMethodPointer";
constexpr const char* virtualMethodInfoHelper = "RuntimeCalls.ResolveVirtualMethodInfo";
constexpr const char* interfaceMethodInfoHelper = "RuntimeCalls.ResolveInterfaceMethodInfo";
constexpr const char* rgctxDataHelper = "RuntimeCalls.GetInflatedRgctxData";
constexpr const char* genericClassInstHelper = "RuntimeCalls.GetGenericClassInstance";
constexpr const char* genericMethodInstHelper = "RuntimeCalls.GetGenericMethodInstance";
constexpr const char* resolveGenericTypeHelper = "RuntimeCalls.ResolveGenericType";

struct ClassifiedType {
    ClassifiedType(AbiValueKind valueKind = AbiValueKind::Unsupported, ScalarType type = {}, uint16_t bits = 0)
        : kind(valueKind), scalar(type), storageBits(bits) {}

    AbiValueKind kind = AbiValueKind::Unsupported;
    ScalarType scalar;
    uint16_t storageBits = 0;
    std::optional<AbiGenericParameter> genericParameter;
};

struct ValueExpressions {
    ExpressionPtr native;
    ExpressionPtr value;
    AbiConversion conversion = AbiConversion::None;
    std::string runtimeHelper;
    std::optional<AbiRegisterView> registerView;
};

std::string trim(std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return std::string(value.substr(first, last - first + 1));
}

std::string qualifiedName(const TypeModel& type) {
    if (type.nameSpace.empty()) return type.name;
    if (type.name.empty()) return type.nameSpace;
    return type.nameSpace + '.' + type.name;
}

std::optional<size_t> typeReferenceIndex(std::string_view type) {
    if (type.size() < 7 || !type.starts_with("type[") || type.back() != ']') return std::nullopt;
    const auto digits = type.substr(5, type.size() - 6);
    size_t index = 0;
    const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), index);
    if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) return std::nullopt;
    return index;
}

std::string resolveTypeName(std::string type, const MetadataModel& metadata) {
    const auto index = typeReferenceIndex(type);
    if (!index || *index >= metadata.types.size()) return type;
    return qualifiedName(metadata.types[*index]);
}

std::string normalizedTypeName(std::string_view type) {
    auto result = trim(type);
    if (result.starts_with("global::")) result.erase(0, 8);
    const auto generic = result.find('<');
    if (generic != std::string::npos) result.erase(generic);
    std::replace(result.begin(), result.end(), '+', '.');
    std::replace(result.begin(), result.end(), '/', '.');
    for (size_t position = 0; position < result.size();) {
        if (result[position] != '`' || position + 1 == result.size() ||
            !std::isdigit(static_cast<unsigned char>(result[position + 1]))) {
            ++position;
            continue;
        }
        size_t end = position + 1;
        while (end < result.size() && std::isdigit(static_cast<unsigned char>(result[end]))) ++end;
        result.erase(position, end - position);
    }
    return trim(result);
}

const TypeModel* findTypeDefinition(
    std::string_view name, const MetadataModel& metadata, const AbiTypeNameIndex* index) {
    if (index) return index->find(name, metadata);
    const auto normalized = normalizedTypeName(name);
    const TypeModel* unqualifiedMatch = nullptr;
    bool ambiguous = false;
    for (const auto& type : metadata.types) {
        if (normalizedTypeName(qualifiedName(type)) == normalized) return &type;
        if (normalizedTypeName(type.name) == normalized) {
            if (unqualifiedMatch && unqualifiedMatch != &type) ambiguous = true;
            unqualifiedMatch = &type;
        }
    }
    return ambiguous ? nullptr : unqualifiedMatch;
}

ClassifiedType classifyType(
    std::string type,
    const MetadataModel& metadata,
    uint16_t pointerBits,
    bool emptyIsVoid,
    const AbiTypeNameIndex* typeIndex);

ClassifiedType classifyDefinition(const TypeModel& definition, const MetadataModel& metadata,
                                  uint16_t pointerBits) {
    const auto name = normalizedTypeName(qualifiedName(definition));
    if (name == "System.ValueType" || name == "System.Enum") {
        return {AbiValueKind::ObjectReference, ScalarType::pointer(pointerBits), pointerBits};
    }
    if ((definition.bitfield & 0x2) != 0) {
        const auto underlying = std::find_if(definition.fields.begin(), definition.fields.end(), [](const auto& field) {
            return field.name == "value__";
        });
        if (underlying == definition.fields.end()) return {};
        const auto type = TypeSystem::resolve(underlying->type, &metadata);
        if (type == "sbyte" || type == "System.SByte") return {AbiValueKind::Integer, ScalarType::intBits(8), 8};
        if (type == "byte" || type == "System.Byte") return {AbiValueKind::Integer, ScalarType::uintBits(8), 8};
        if (type == "short" || type == "System.Int16") return {AbiValueKind::Integer, ScalarType::intBits(16), 16};
        if (type == "ushort" || type == "System.UInt16") return {AbiValueKind::Integer, ScalarType::uintBits(16), 16};
        if (type == "int" || type == "System.Int32") return {AbiValueKind::Integer, ScalarType::intBits(32), 32};
        if (type == "uint" || type == "System.UInt32") return {AbiValueKind::Integer, ScalarType::uintBits(32), 32};
        if (type == "long" || type == "System.Int64") return {AbiValueKind::Integer, ScalarType::intBits(64), 64};
        if (type == "ulong" || type == "System.UInt64") return {AbiValueKind::Integer, ScalarType::uintBits(64), 64};
        return {};
    }
    if ((definition.bitfield & 0x1) != 0) return {};
    const auto base = normalizedTypeName(definition.baseType);
    if (base == "System.ValueType" || base == "System.Enum") return {};
    return {AbiValueKind::ObjectReference, ScalarType::pointer(pointerBits), pointerBits};
}

ClassifiedType classifyTypeReference(
    size_t index,
    const MetadataModel& metadata,
    uint16_t pointerBits,
    bool emptyIsVoid,
    const AbiTypeNameIndex* typeIndex,
    size_t depth = 0) {
    if (index >= metadata.typeReferences.size() || depth > 64) return {};
    const auto& reference = metadata.typeReferences[index];
    if (reference.byRef) return {AbiValueKind::Pointer, ScalarType::pointer(pointerBits), pointerBits};
    const auto code = static_cast<Il2CppTypeCode>(reference.code);
    if (auto primitive = TypeSystem::primitiveType(code)) {
        return classifyType(*primitive, metadata, pointerBits, emptyIsVoid, typeIndex);
    }

    const auto definition = [&]() -> const TypeModel* {
        if (reference.definitionIndex >= 0 && static_cast<size_t>(reference.definitionIndex) < metadata.types.size()) {
            return &metadata.types[static_cast<size_t>(reference.definitionIndex)];
        }
        return findTypeDefinition(reference.name, metadata, typeIndex);
    };
    switch (code) {
    case Il2CppTypeCode::Ptr:
    case Il2CppTypeCode::ByRef:
    case Il2CppTypeCode::FnPtr:
        return {AbiValueKind::Pointer, ScalarType::pointer(pointerBits), pointerBits};
    case Il2CppTypeCode::I:
        return {AbiValueKind::Integer, ScalarType::intBits(pointerBits), pointerBits};
    case Il2CppTypeCode::U:
        return {AbiValueKind::Integer, ScalarType::uintBits(pointerBits), pointerBits};
    case Il2CppTypeCode::Class:
    case Il2CppTypeCode::Array:
    case Il2CppTypeCode::SzArray:
    case Il2CppTypeCode::Internal:
        return {AbiValueKind::ObjectReference, ScalarType::pointer(pointerBits), pointerBits};
    case Il2CppTypeCode::GenericInst:
        if (const auto* type = definition()) return classifyDefinition(*type, metadata, pointerBits);
        return {};
    case Il2CppTypeCode::ValueType: {
        const auto* type = definition();
        return classifyType(type ? qualifiedName(*type) : reference.name, metadata, pointerBits, emptyIsVoid, typeIndex);
    }
    case Il2CppTypeCode::Enum: {
        const auto* type = definition();
        return type ? classifyDefinition(*type, metadata, pointerBits) : ClassifiedType{};
    }
    case Il2CppTypeCode::Var:
    case Il2CppTypeCode::MVar: {
        ClassifiedType result;
        const auto kind = code == Il2CppTypeCode::Var ? AbiGenericParameterKind::Class : AbiGenericParameterKind::Method;
        const auto fallback = code == Il2CppTypeCode::Var ? "T" : "TMethod";
        const auto name = reference.name.empty() ? std::string(fallback) : reference.name;
        const auto genericIndex = reference.definitionIndex < 0 ? std::optional<size_t>(std::nullopt) :
            std::optional<size_t>(static_cast<size_t>(reference.definitionIndex));
        result.genericParameter = AbiGenericParameter{kind, name, genericIndex};
        return result;
    }
    case Il2CppTypeCode::CModReqD:
    case Il2CppTypeCode::CModOpt:
    case Il2CppTypeCode::Modifier:
    case Il2CppTypeCode::Sentinel:
    case Il2CppTypeCode::Pinned:
    case Il2CppTypeCode::TypeIndex:
        if (reference.elementTypeIndex < 0) return {};
        return classifyTypeReference(static_cast<size_t>(reference.elementTypeIndex), metadata, pointerBits, emptyIsVoid, typeIndex, depth + 1);
    default:
        return {};
    }
}

std::optional<AbiGenericParameter> genericParameterFor(std::string_view type) {
    size_t prefixSize = 0;
    AbiGenericParameterKind kind = AbiGenericParameterKind::Class;
    if (type.starts_with("!!")) {
        prefixSize = 2;
        kind = AbiGenericParameterKind::Method;
    } else if (type.starts_with('!')) {
        prefixSize = 1;
    } else if (type.starts_with("TMethod")) {
        prefixSize = 7;
        kind = AbiGenericParameterKind::Method;
    } else if (type.starts_with('T')) {
        prefixSize = 1;
    } else {
        return std::nullopt;
    }

    const auto digits = type.substr(prefixSize);
    if (digits.empty()) return AbiGenericParameter{kind, std::string(type), std::nullopt};
    size_t index = 0;
    const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), index);
    if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) return std::nullopt;
    return AbiGenericParameter{kind, std::string(type), index};
}

ClassifiedType classifyType(
    std::string type,
    const MetadataModel& metadata,
    uint16_t pointerBits,
    bool emptyIsVoid,
    const AbiTypeNameIndex* typeIndex) {
    type = trim(type);
    if (type.empty()) {
        if (emptyIsVoid) return {AbiValueKind::Void, {}, 0};
        return {AbiValueKind::ObjectReference, ScalarType::pointer(pointerBits), pointerBits};
    }

    if (type.starts_with("global::")) type.erase(0, 8);
    if (const auto index = typeReferenceIndex(type); index && !metadata.typeReferences.empty()) {
        return classifyTypeReference(*index, metadata, pointerBits, emptyIsVoid, typeIndex);
    }
    for (const std::string_view prefix : {std::string_view("ref "), std::string_view("out "), std::string_view("in ")}) {
        if (type.starts_with(prefix)) {
            return {AbiValueKind::Pointer, ScalarType::pointer(pointerBits), pointerBits};
        }
    }
    if (type.back() == '&' || type.back() == '*') {
        return {AbiValueKind::Pointer, ScalarType::pointer(pointerBits), pointerBits};
    }
    if (type.back() == ']') {
        return {AbiValueKind::ObjectReference, ScalarType::pointer(pointerBits), pointerBits};
    }
    type = resolveTypeName(type, metadata);
    if (type.starts_with("global::")) type.erase(0, 8);
    if (auto generic = genericParameterFor(type)) {
        ClassifiedType result;
        result.genericParameter = std::move(*generic);
        return result;
    }

    if (type == "void" || type == "System.Void") {
        return emptyIsVoid ? ClassifiedType{AbiValueKind::Void, {}, 0} : ClassifiedType{};
    }
    if (type == "bool" || type == "System.Boolean") {
        return {AbiValueKind::Integer, ScalarType::boolean(), 8};
    }
    if (type == "char" || type == "System.Char") {
        return {AbiValueKind::Integer, ScalarType::uintBits(16), 16};
    }
    if (type == "sbyte" || type == "System.SByte") {
        return {AbiValueKind::Integer, ScalarType::intBits(8), 8};
    }
    if (type == "byte" || type == "System.Byte") {
        return {AbiValueKind::Integer, ScalarType::uintBits(8), 8};
    }
    if (type == "short" || type == "System.Int16") {
        return {AbiValueKind::Integer, ScalarType::intBits(16), 16};
    }
    if (type == "ushort" || type == "System.UInt16") {
        return {AbiValueKind::Integer, ScalarType::uintBits(16), 16};
    }
    if (type == "int" || type == "System.Int32") {
        return {AbiValueKind::Integer, ScalarType::intBits(32), 32};
    }
    if (type == "uint" || type == "System.UInt32") {
        return {AbiValueKind::Integer, ScalarType::uintBits(32), 32};
    }
    if (type == "long" || type == "System.Int64") {
        return {AbiValueKind::Integer, ScalarType::intBits(64), 64};
    }
    if (type == "ulong" || type == "System.UInt64") {
        return {AbiValueKind::Integer, ScalarType::uintBits(64), 64};
    }
    if (type == "float" || type == "System.Single") {
        return {AbiValueKind::FloatingPoint, ScalarType::floatBits(32), 32};
    }
    if (type == "double" || type == "System.Double") {
        return {AbiValueKind::FloatingPoint, ScalarType::floatBits(64), 64};
    }
    if (type == "nint") {
        return {AbiValueKind::Integer, ScalarType::intBits(pointerBits), pointerBits};
    }
    if (type == "nuint") {
        return {AbiValueKind::Integer, ScalarType::uintBits(pointerBits), pointerBits};
    }
    if (type == "System.IntPtr" || type == "System.UIntPtr") {
        return {AbiValueKind::Pointer, ScalarType::pointer(pointerBits), pointerBits};
    }
    if (type == "string" || type == "System.String" || type == "object" || type == "System.Object") {
        return {AbiValueKind::ObjectReference, ScalarType::pointer(pointerBits), pointerBits};
    }
    if (const auto* definition = findTypeDefinition(type, metadata, typeIndex)) {
        return classifyDefinition(*definition, metadata, pointerBits);
    }
    return {};
}

uint16_t pointerBitsFor(Architecture architecture) {
    switch (architecture) {
    case Architecture::Arm64:
    case Architecture::X64:
        return 64;
    case Architecture::Arm32:
    case Architecture::X86:
        return 32;
    }
    return 0;
}

ExpressionPtr coerce(ExpressionPtr value, const ScalarType& type) {
    if (!value) return nullptr;
    if (value->type.kind == type.kind && value->type.bits == type.bits) return value;
    return cast(std::move(value), type);
}

ExpressionPtr stackAddress(const ExpressionPtr& stackPointer, uint64_t offset, ScalarType pointerType) {
    if (offset == 0) return stackPointer;
    return binary("+", stackPointer, constant(offset, pointerType), pointerType);
}

uint64_t alignUp(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

class BindingBuilder {
public:
    BindingBuilder(
        const MethodModel& method,
        const MetadataModel& metadata,
        Architecture architecture,
        const AbiAdapterOptions& options,
        AbiBindingModel& output,
        bool requireBlittable = false,
        const AbiTypeNameIndex* typeIndex = nullptr)
        : method_(method), metadata_(metadata), architecture_(architecture), options_(options), output_(output),
          pointerBits_(pointerBitsFor(architecture)), pointerType_(ScalarType::pointer(pointerBits_)),
          requireBlittable_(requireBlittable), typeIndex_(typeIndex) {
        switch (architecture_) {
        case Architecture::Arm64:
        case Architecture::Arm32:
            stackOffset_ = 0;
            break;
        case Architecture::X86:
            stackOffset_ = 4;
            break;
        case Architecture::X64:
            stackOffset_ = 8 + (options_.x64 == X64CallingConvention::Microsoft ? 32 : 0);
            break;
        }
    }

    void addThis() {
        const ClassifiedType type{AbiValueKind::ObjectReference, pointerType_, pointerBits_};
        addBinding(AbiValueRole::This, "__abi_this", "this", method_.declaringType, type, std::nullopt);
    }

    void addParameter(size_t index) {
        const auto& parameter = method_.parameters[index];
        const auto type = classifyType(parameter.type, metadata_, pointerBits_, false, typeIndex_);
        const auto managedName = parameter.name.empty() ? "param" + std::to_string(index) : parameter.name;
        addBinding(
            AbiValueRole::Parameter,
            "__abi_param_" + std::to_string(index),
            managedName,
            parameter.type.empty() ? "object" : parameter.type,
            type,
            index);
    }

    void addMethodInfo() {
        const ClassifiedType type{AbiValueKind::Pointer, pointerType_, pointerBits_};
        addBinding(AbiValueRole::MethodInfo, "__abi_method_info", "method", "MethodInfo*", type, std::nullopt);
    }

    void addPointer(AbiValueRole role, std::string name, std::string managedName, std::string managedType) {
        const ClassifiedType type{AbiValueKind::Pointer, pointerType_, pointerBits_};
        addBinding(role, std::move(name), std::move(managedName), std::move(managedType), type, std::nullopt);
    }

    void setReturn() {
        auto& result = output_.returnValue;
        result.managedType = method_.returnType.empty() ? "void" : method_.returnType;
        const auto type = classifyType(method_.returnType, metadata_, pointerBits_, true, typeIndex_);
        result.valueKind = type.kind;
        result.scalarType = type.scalar;
        result.genericParameter = type.genericParameter;
        if (type.kind == AbiValueKind::Void) {
            result.location.kind = AbiLocationKind::None;
            result.conversion = AbiConversion::None;
            return;
        }
        if (type.kind == AbiValueKind::Unsupported || (requireBlittable_ && type.kind == AbiValueKind::ObjectReference)) {
            result.valueKind = AbiValueKind::Unsupported;
            result.location.kind = AbiLocationKind::Unsupported;
            result.conversion = AbiConversion::Unsupported;
            result.runtimeHelper = unsupportedAbiHelper;
            const auto code = type.genericParameter ? AbiDiagnosticCode::UnresolvedGenericType :
                requireBlittable_ && type.kind == AbiValueKind::ObjectReference ? AbiDiagnosticCode::UnsupportedMarshalling :
                AbiDiagnosticCode::UnsupportedReturnType;
            const auto message = code == AbiDiagnosticCode::UnresolvedGenericType ?
                "Return type '" + result.managedType + "' requires a concrete type from the generic context" :
                code == AbiDiagnosticCode::UnsupportedMarshalling ?
                "Return type '" + result.managedType + "' requires P/Invoke marshalling" :
                "Return type '" + result.managedType + "' is not supported by the scalar ABI adapter";
            addDiagnostic(code, message, std::nullopt);
            return;
        }

        result.location = returnLocation(type);
        auto expressions = expressionsFor(result.location, type, true);
        result.nativeValue = std::move(expressions.native);
        result.value = std::move(expressions.value);
        result.conversion = expressions.conversion;
        result.runtimeHelper = std::move(expressions.runtimeHelper);
        result.registerView = std::move(expressions.registerView);
    }

private:
    const MethodModel& method_;
    const MetadataModel& metadata_;
    Architecture architecture_;
    const AbiAdapterOptions& options_;
    AbiBindingModel& output_;
    uint16_t pointerBits_;
    ScalarType pointerType_;
    bool requireBlittable_ = false;
    const AbiTypeNameIndex* typeIndex_ = nullptr;
    size_t gpIndex_ = 0;
    size_t fpIndex_ = 0;
    size_t vfpIndex_ = 0;
    size_t argumentPosition_ = 0;
    uint64_t stackOffset_ = 0;

    void addDiagnostic(
        AbiDiagnosticCode code,
        std::string message,
        std::optional<size_t> parameterIndex) {
        output_.diagnostics.push_back({AbiDiagnosticSeverity::Error, code, std::move(message), parameterIndex});
    }

    AbiLocation stackLocation(const ClassifiedType& type) {
        AbiLocation result;
        result.kind = AbiLocationKind::Stack;
        result.size = type.storageBits;
        const uint64_t alignment = architecture_ == Architecture::Arm32 && type.storageBits == 64 ? 8 : pointerBits_ / 8;
        stackOffset_ = alignUp(stackOffset_, alignment);
        result.stackOffset = stackOffset_;
        stackOffset_ += std::max<uint64_t>(type.storageBits / 8, pointerBits_ / 8);
        return result;
    }

    AbiLocation registerLocation(std::string name, const ClassifiedType& type) {
        AbiLocation result;
        result.kind = AbiLocationKind::Register;
        result.registerName = std::move(name);
        result.size = type.storageBits;
        return result;
    }

    AbiLocation registerPairLocation(std::string low, std::string high, const ClassifiedType& type) {
        AbiLocation result;
        result.kind = AbiLocationKind::RegisterPair;
        result.registerName = std::move(low);
        result.secondRegisterName = std::move(high);
        result.size = type.storageBits;
        return result;
    }

    AbiLocation allocateArm64(const ClassifiedType& type) {
        if (type.kind == AbiValueKind::FloatingPoint) {
            if (fpIndex_ < 8) return registerLocation("v" + std::to_string(fpIndex_++), type);
            return stackLocation(type);
        }
        if (gpIndex_ < 8) return registerLocation("x" + std::to_string(gpIndex_++), type);
        return stackLocation(type);
    }

    AbiLocation allocateArm32(const ClassifiedType& type) {
        const bool hardFloat = type.kind == AbiValueKind::FloatingPoint && options_.arm32Float == Arm32FloatAbi::Hard;
        if (hardFloat) {
            if (type.storageBits == 32) {
                if (vfpIndex_ < 16) return registerLocation("s" + std::to_string(vfpIndex_++), type);
                return stackLocation(type);
            }
            vfpIndex_ = (vfpIndex_ + 1) & ~size_t{1};
            if (vfpIndex_ < 16) {
                const auto location = registerLocation("d" + std::to_string(vfpIndex_ / 2), type);
                vfpIndex_ += 2;
                return location;
            }
            return stackLocation(type);
        }

        if (type.storageBits == 64) {
            gpIndex_ = (gpIndex_ + 1) & ~size_t{1};
            if (gpIndex_ == 0 || gpIndex_ == 2) {
                const auto location = registerPairLocation(
                    "r" + std::to_string(gpIndex_),
                    "r" + std::to_string(gpIndex_ + 1),
                    type);
                gpIndex_ += 2;
                return location;
            }
            gpIndex_ = 4;
            return stackLocation(type);
        }
        if (gpIndex_ < 4) return registerLocation("r" + std::to_string(gpIndex_++), type);
        return stackLocation(type);
    }

    AbiLocation allocateX64(const ClassifiedType& type) {
        if (options_.x64 == X64CallingConvention::Microsoft) {
            const size_t position = argumentPosition_++;
            if (position >= 4) return stackLocation(type);
            if (type.kind == AbiValueKind::FloatingPoint) {
                return registerLocation("xmm" + std::to_string(position), type);
            }
            static constexpr const char* registers[] = {"rcx", "rdx", "r8", "r9"};
            return registerLocation(registers[position], type);
        }

        if (type.kind == AbiValueKind::FloatingPoint) {
            if (fpIndex_ < 8) return registerLocation("xmm" + std::to_string(fpIndex_++), type);
            return stackLocation(type);
        }
        static constexpr const char* registers[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
        if (gpIndex_ < 6) return registerLocation(registers[gpIndex_++], type);
        return stackLocation(type);
    }

    AbiLocation allocateX86(const ClassifiedType& type) {
        const size_t registerCount = options_.x86 == X86CallingConvention::FastCall ? 2 :
            options_.x86 == X86CallingConvention::ThisCall ? 1 : 0;
        if (type.kind != AbiValueKind::FloatingPoint && type.storageBits <= 32 && gpIndex_ < registerCount) {
            static constexpr const char* registers[] = {"ecx", "edx"};
            return registerLocation(registers[gpIndex_++], type);
        }
        return stackLocation(type);
    }

    AbiLocation allocate(const ClassifiedType& type) {
        switch (architecture_) {
        case Architecture::Arm64: return allocateArm64(type);
        case Architecture::Arm32: return allocateArm32(type);
        case Architecture::X64: return allocateX64(type);
        case Architecture::X86: return allocateX86(type);
        }
        AbiLocation result;
        result.kind = AbiLocationKind::Unsupported;
        return result;
    }

    ExpressionPtr rawRegister(const std::string& name) const {
        return reg(name, pointerType_);
    }

    ExpressionPtr rawPair(const AbiLocation& location) const {
        const auto wideType = ScalarType::uintBits(64);
        auto low = cast(rawRegister(location.registerName), wideType);
        auto high = cast(rawRegister(location.secondRegisterName), wideType);
        high = binary("<<", high, constant(32, wideType), wideType);
        return binary("|", std::move(low), std::move(high), wideType);
    }

    std::string x64WordView(const std::string& name) const {
        static const std::pair<std::string_view, std::string_view> views[] = {
            {"rax", "eax"}, {"rcx", "ecx"}, {"rdx", "edx"}, {"rsi", "esi"}, {"rdi", "edi"},
            {"r8", "r8d"}, {"r9", "r9d"}, {"r10", "r10d"}, {"r11", "r11d"}
        };
        for (const auto& [wide, narrow] : views) {
            if (name == wide) return std::string(narrow);
        }
        return name;
    }

    ExpressionPtr scalarRegister(
        const AbiLocation& location,
        const ClassifiedType& type,
        bool softFloat,
        ValueExpressions& result) const {
        const bool typedFloat = type.kind == AbiValueKind::FloatingPoint && !softFloat;
        if (typedFloat && (architecture_ == Architecture::Arm64 || architecture_ == Architecture::X64)) {
            AbiRegisterView view;
            view.storageName = location.registerName;
            view.storageType = ScalarType::vectorBits(128);
            view.viewType = type.scalar;
            if (architecture_ == Architecture::Arm64) {
                const auto suffix = location.registerName.size() > 1 ? location.registerName.substr(1) : "0";
                view.viewName = std::string(type.storageBits == 32 ? "s" : "d") + suffix;
            } else {
                view.viewName = location.registerName + (type.storageBits == 32 ? "_f32" : "_f64");
            }
            view.expression = reg(view.viewName, view.viewType);
            result.native = view.expression;
            result.registerView = std::move(view);
            return result.native;
        }
        if (typedFloat) return reg(location.registerName, type.scalar);

        if (type.kind == AbiValueKind::Integer && type.storageBits <= 32 && pointerBits_ == 64) {
            AbiRegisterView view;
            view.storageName = location.registerName;
            view.storageType = pointerType_;
            view.viewType = ScalarType::uintBits(32);
            view.viewName = architecture_ == Architecture::Arm64 ?
                'w' + location.registerName.substr(1) : x64WordView(location.registerName);
            view.expression = reg(view.viewName, view.viewType);
            result.native = view.expression;
            result.registerView = std::move(view);
            return result.native;
        }
        return rawRegister(location.registerName);
    }

    ValueExpressions expressionsFor(const AbiLocation& location, const ClassifiedType& type, bool forReturn) const {
        ValueExpressions result;
        const bool softFloat = architecture_ == Architecture::Arm32 &&
            type.kind == AbiValueKind::FloatingPoint && options_.arm32Float == Arm32FloatAbi::Soft &&
            location.kind != AbiLocationKind::Stack;

        if (location.kind == AbiLocationKind::Stack) {
            const char* stackPointer = architecture_ == Architecture::Arm64 || architecture_ == Architecture::Arm32 ? "sp" :
                architecture_ == Architecture::X64 ? "rsp" : "esp";
            const auto address = stackAddress(rawRegister(stackPointer), location.stackOffset, pointerType_);
            result.native = load(address, type.kind == AbiValueKind::ObjectReference ? pointerType_ : type.scalar);
        } else if (location.kind == AbiLocationKind::RegisterPair) {
            result.native = rawPair(location);
        } else if (location.kind == AbiLocationKind::Register) {
            result.native = scalarRegister(location, type, softFloat, result);
        } else {
            result.conversion = AbiConversion::Unsupported;
            result.runtimeHelper = unsupportedAbiHelper;
            return result;
        }

        if (type.kind == AbiValueKind::ObjectReference) {
            result.conversion = forReturn ? AbiConversion::NativePointerToObject : AbiConversion::ObjectToNativePointer;
            result.runtimeHelper = forReturn ? nativeToObjectHelper : objectToNativeHelper;
            return result;
        }
        if (softFloat) {
            result.conversion = AbiConversion::RawBitsToFloat;
            result.runtimeHelper = type.storageBits == 32 ? bitsToSingleHelper : bitsToDoubleHelper;
            return result;
        }

        result.native = coerce(std::move(result.native), type.scalar);
        result.value = result.native;
        result.conversion = AbiConversion::None;
        return result;
    }

    Statement unsupportedStatement(size_t bindingIndex) const {
        Statement statement;
        statement.address = method_.address;
        statement.kind = Statement::Kind::Call;
        statement.target = reg(unsupportedAbiHelper, pointerType_);
        statement.arguments = {
            constant(method_.address, pointerType_),
            constant(bindingIndex, ScalarType::uintBits(pointerBits_))
        };
        return statement;
    }

    void addBinding(
        AbiValueRole role,
        std::string name,
        std::string managedName,
        std::string managedType,
        const ClassifiedType& type,
        std::optional<size_t> parameterIndex) {
        const size_t bindingIndex = output_.bindings.size();
        AbiBinding binding;
        binding.role = role;
        binding.parameterIndex = parameterIndex;
        binding.name = std::move(name);
        binding.managedName = std::move(managedName);
        binding.managedType = std::move(managedType);
        binding.valueKind = type.kind;
        binding.scalarType = type.scalar;
        binding.genericParameter = type.genericParameter;

        if (type.kind == AbiValueKind::Unsupported || (requireBlittable_ && type.kind == AbiValueKind::ObjectReference)) {
            binding.valueKind = AbiValueKind::Unsupported;
            binding.location.kind = AbiLocationKind::Unsupported;
            binding.conversion = AbiConversion::Unsupported;
            binding.runtimeHelper = unsupportedAbiHelper;
            const auto code = type.genericParameter ? AbiDiagnosticCode::UnresolvedGenericType :
                requireBlittable_ && type.kind == AbiValueKind::ObjectReference ? AbiDiagnosticCode::UnsupportedMarshalling :
                AbiDiagnosticCode::UnsupportedType;
            const auto message = code == AbiDiagnosticCode::UnresolvedGenericType ?
                "Managed value '" + binding.managedName + "' requires concrete type '" + binding.managedType + "' from the generic context" :
                code == AbiDiagnosticCode::UnsupportedMarshalling ?
                "Managed value '" + binding.managedName + "' requires P/Invoke marshalling for type '" + binding.managedType + "'" :
                "Managed value '" + binding.managedName + "' has unsupported ABI type '" + binding.managedType + "'";
            addDiagnostic(code, message, parameterIndex);
            output_.statements.push_back(unsupportedStatement(bindingIndex));
            output_.bindings.push_back(std::move(binding));
            return;
        }

        binding.location = allocate(type);
        auto expressions = expressionsFor(binding.location, type, false);
        binding.nativeValue = std::move(expressions.native);
        binding.value = std::move(expressions.value);
        binding.conversion = expressions.conversion;
        binding.runtimeHelper = std::move(expressions.runtimeHelper);
        binding.registerView = std::move(expressions.registerView);

        Statement statement;
        statement.address = method_.address;
        statement.destination = reg(binding.name, binding.scalarType);
        if (binding.conversion == AbiConversion::None) {
            statement.kind = Statement::Kind::Assign;
            statement.value = binding.value;
        } else {
            statement.kind = Statement::Kind::Call;
            statement.target = reg(binding.runtimeHelper, pointerType_);
            statement.arguments = {binding.nativeValue};
        }
        output_.statements.push_back(std::move(statement));
        output_.bindings.push_back(std::move(binding));
    }

    AbiLocation returnLocation(const ClassifiedType& type) {
        switch (architecture_) {
        case Architecture::Arm64:
            return registerLocation(type.kind == AbiValueKind::FloatingPoint ? "v0" : "x0", type);
        case Architecture::Arm32:
            if (type.kind == AbiValueKind::FloatingPoint && options_.arm32Float == Arm32FloatAbi::Hard) {
                return registerLocation(type.storageBits == 32 ? "s0" : "d0", type);
            }
            if (type.storageBits == 64) return registerPairLocation("r0", "r1", type);
            return registerLocation("r0", type);
        case Architecture::X64:
            return registerLocation(type.kind == AbiValueKind::FloatingPoint ? "xmm0" : "rax", type);
        case Architecture::X86:
            if (type.kind == AbiValueKind::FloatingPoint) return registerLocation("st0", type);
            if (type.storageBits == 64) return registerPairLocation("eax", "edx", type);
            return registerLocation("eax", type);
        }
        AbiLocation result;
        result.kind = AbiLocationKind::Unsupported;
        return result;
    }
};

Statement unsupportedReturn(const AbiBindingModel& model, uint64_t address, ScalarType pointerType) {
    Statement statement;
    statement.address = address;
    statement.kind = Statement::Kind::Call;
    statement.target = reg(unsupportedAbiHelper, pointerType);
    statement.arguments = {
        constant(address, pointerType),
        constant(model.returnValue.managedType.size(), ScalarType::uintBits(pointerType.bits))
    };
    return statement;
}

std::optional<std::string> conventionError(Architecture architecture, const AbiAdapterOptions& options) {
    if (options.methodInfo != MethodInfoArgumentPolicy::Omit && options.methodInfo != MethodInfoArgumentPolicy::Append) {
        return "Unknown MethodInfo argument policy";
    }
    switch (architecture) {
    case Architecture::X64:
        if (options.x64 != X64CallingConvention::Microsoft && options.x64 != X64CallingConvention::SystemV) {
            return "Unknown x64 calling convention";
        }
        break;
    case Architecture::X86:
        if (options.x86 != X86CallingConvention::Cdecl && options.x86 != X86CallingConvention::ThisCall &&
            options.x86 != X86CallingConvention::FastCall && options.x86 != X86CallingConvention::StdCall) {
            return "Unknown x86 calling convention";
        }
        break;
    case Architecture::Arm32:
        if (options.arm32Float != Arm32FloatAbi::Soft && options.arm32Float != Arm32FloatAbi::Hard) {
            return "Unknown ARM32 floating-point ABI";
        }
        break;
    case Architecture::Arm64:
        break;
    }
    return std::nullopt;
}

std::optional<std::string> runtimeProfileError(const AbiRuntimeProfile& profile) {
    if (profile.invoker != AbiInvokerSignature::LegacyThreeArguments &&
        profile.invoker != AbiInvokerSignature::FourArguments &&
        profile.invoker != AbiInvokerSignature::FiveArguments) {
        return "Unknown invoker signature in ABI runtime profile";
    }
    if (profile.methodInfoPointers != AbiMethodInfoPointerLayout::MethodPointerOnly &&
        profile.methodInfoPointers != AbiMethodInfoPointerLayout::MethodAndVirtualMethodPointer) {
        return "Unknown MethodInfo pointer layout in ABI runtime profile";
    }
    if (profile.generatedMethodInfo != MethodInfoArgumentPolicy::Omit &&
        profile.generatedMethodInfo != MethodInfoArgumentPolicy::Append) {
        return "Unknown generated MethodInfo policy in ABI runtime profile";
    }
    return std::nullopt;
}

void setUnsupportedReturn(AbiBindingModel& model) {
    model.returnValue.valueKind = AbiValueKind::Unsupported;
    model.returnValue.location.kind = AbiLocationKind::Unsupported;
    model.returnValue.conversion = AbiConversion::Unsupported;
    model.returnValue.runtimeHelper = unsupportedAbiHelper;
}

} // namespace

AbiTypeNameIndex::AbiTypeNameIndex(const MetadataModel& metadata) {
    qualified.reserve(metadata.types.size());
    unqualified.reserve(metadata.types.size());
    for (size_t index = 0; index < metadata.types.size(); ++index) {
        const auto& type = metadata.types[index];
        qualified.try_emplace(normalizedTypeName(qualifiedName(type)), index);
        auto [entry, inserted] = unqualified.try_emplace(normalizedTypeName(type.name), index);
        if (!inserted) entry->second.reset();
    }
}

const TypeModel* AbiTypeNameIndex::find(std::string_view name, const MetadataModel& metadata) const {
    const auto normalized = normalizedTypeName(name);
    if (const auto found = qualified.find(normalized); found != qualified.end() &&
        found->second < metadata.types.size()) {
        const auto& type = metadata.types[found->second];
        if (normalizedTypeName(qualifiedName(type)) == normalized) return &type;
    }
    if (const auto found = unqualified.find(normalized); found != unqualified.end() &&
        found->second && *found->second < metadata.types.size()) {
        const auto& type = metadata.types[*found->second];
        if (normalizedTypeName(type.name) == normalized) return &type;
    }
    return nullptr;
}

AbiRuntimeProfile AbiRuntimeProfile::automatic() {
    return {};
}

AbiRuntimeProfile AbiRuntimeProfile::legacyThreeArgument() {
    AbiRuntimeProfile result;
    result.id = "il2cpp-legacy-three-arg-invoker";
    result.invoker = AbiInvokerSignature::LegacyThreeArguments;
    result.methodInfoPointers = AbiMethodInfoPointerLayout::MethodPointerOnly;
    result.adjustorThunks = false;
    result.unresolvedReducedSignatures = true;
    return result;
}

AbiRuntimeProfile AbiRuntimeProfile::unity2017() {
    AbiRuntimeProfile result;
    result.id = "unity-2017-four-arg-invoker";
    result.invoker = AbiInvokerSignature::FourArguments;
    result.methodInfoPointers = AbiMethodInfoPointerLayout::MethodPointerOnly;
    result.adjustorThunks = true;
    result.unresolvedReducedSignatures = false;
    return result;
}

AbiRuntimeProfile AbiRuntimeProfile::modernFourArgument() {
    AbiRuntimeProfile result;
    result.id = "il2cpp-modern-four-arg-invoker";
    result.invoker = AbiInvokerSignature::FourArguments;
    result.methodInfoPointers = AbiMethodInfoPointerLayout::MethodAndVirtualMethodPointer;
    result.adjustorThunks = true;
    result.unresolvedReducedSignatures = false;
    return result;
}

AbiRuntimeProfile AbiRuntimeProfile::modernFiveArgument() {
    auto result = modernFourArgument();
    result.id = "il2cpp-modern-five-arg-invoker";
    result.invoker = AbiInvokerSignature::FiveArguments;
    return result;
}

AbiRuntimeProfile AbiRuntimeProfile::forMetadataVersion(double version) {
    const auto unsupported = [] {
        AbiRuntimeProfile result;
        result.id = "unsupported-il2cpp-invoker-profile";
        result.invoker = static_cast<AbiInvokerSignature>(-1);
        return result;
    };
    if (!std::isfinite(version) || version <= 0) return unsupported();
    if (version == 16 || version == 18) {
        auto result = unity2017();
        result.id = "il2cpp-legacy-four-arg-invoker";
        result.adjustorThunks = false;
        return result;
    }
    if (version >= 19 && version <= 23 && std::floor(version) == version) return legacyThreeArgument();
    if (version == 24 || version == 24.1 || version == 24.2 || version == 24.3 ||
        version == 24.4 || version == 24.5) return unity2017();
    if (version == 27 || version == 27.1 || version == 27.2) return modernFourArgument();
    if (version == 29 || version == 29.1 || version == 31) {
        return modernFiveArgument();
    }
    return unsupported();
}

AbiRuntimeProfile AbiRuntimeProfile::fromSourceLayout(const ida::SourceLayoutSelection& selection) {
    if (!selection.supported) return forMetadataVersion(0);
    auto result = forMetadataVersion(selection.metadataVersion);
    if (selection.profile) result.id = selection.profile->id + "-abi";
    switch (selection.capabilities.invoker) {
    case ida::NativeInvokerSignature::LegacyThreeArguments:
        result.invoker = AbiInvokerSignature::LegacyThreeArguments;
        break;
    case ida::NativeInvokerSignature::FourArguments:
        result.invoker = AbiInvokerSignature::FourArguments;
        break;
    case ida::NativeInvokerSignature::FiveArguments:
        result.invoker = AbiInvokerSignature::FiveArguments;
        break;
    case ida::NativeInvokerSignature::Unknown:
        result.invoker = static_cast<AbiInvokerSignature>(-1);
        break;
    }
    result.generatedMethodInfo = selection.capabilities.hiddenMethodInfo ?
        MethodInfoArgumentPolicy::Append : MethodInfoArgumentPolicy::Omit;
    result.methodInfoPointers = selection.capabilities.virtualMethodPointer ?
        AbiMethodInfoPointerLayout::MethodAndVirtualMethodPointer : AbiMethodInfoPointerLayout::MethodPointerOnly;
    result.genericContexts = selection.capabilities.genericContexts;
    result.adjustorThunks = selection.capabilities.adjustorThunks;
    result.unresolvedReducedSignatures = selection.capabilities.unresolvedReducedSignatures;
    return result;
}

bool AbiBindingModel::supported() const {
    return std::none_of(diagnostics.begin(), diagnostics.end(), [](const AbiDiagnostic& diagnostic) {
        return diagnostic.severity == AbiDiagnosticSeverity::Error;
    });
}

bool CallSiteAbiModel::supported() const {
    return signature.supported() && std::none_of(diagnostics.begin(), diagnostics.end(), [](const AbiDiagnostic& diagnostic) {
        return diagnostic.severity == AbiDiagnosticSeverity::Error;
    });
}

AbiAdapter::AbiAdapter(AbiAdapterOptions options) : options_(options) {}

AbiAdapter::AbiAdapter(AbiAdapterOptions options, const MetadataModel& indexedMetadata)
    : options_(std::move(options)), typeNameIndex_(std::make_shared<AbiTypeNameIndex>(indexedMetadata)),
      indexedMetadata_(&indexedMetadata) {}

AbiBindingModel AbiAdapter::bind(
    const MethodModel& method,
    const MetadataModel& metadata,
    Architecture architecture) const {
    AbiBindingModel result;
    result.architecture = architecture;
    if (pointerBitsFor(architecture) == 0) {
        result.diagnostics.push_back({
            AbiDiagnosticSeverity::Error,
            AbiDiagnosticCode::UnsupportedArchitecture,
            "The requested architecture has no supported scalar calling convention",
            std::nullopt
        });
        result.returnValue.valueKind = AbiValueKind::Unsupported;
        result.returnValue.location.kind = AbiLocationKind::Unsupported;
        result.returnValue.conversion = AbiConversion::Unsupported;
        result.returnValue.runtimeHelper = unsupportedAbiHelper;
        return result;
    }
    if (const auto error = conventionError(architecture, options_)) {
        result.diagnostics.push_back({
            AbiDiagnosticSeverity::Error,
            AbiDiagnosticCode::UnknownCallingConvention,
            *error,
            std::nullopt
        });
        setUnsupportedReturn(result);
        return result;
    }

    const auto* typeIndex = indexedMetadata_ == &metadata ? typeNameIndex_.get() : nullptr;
    BindingBuilder builder(method, metadata, architecture, options_, result, false, typeIndex);
    if (!method.isStatic) builder.addThis();
    for (size_t index = 0; index < method.parameters.size(); ++index) builder.addParameter(index);
    if (options_.methodInfo == MethodInfoArgumentPolicy::Append) builder.addMethodInfo();
    builder.setReturn();
    return result;
}

CallSiteAbiModel AbiAdapter::bindCallSite(
    const MethodModel& method,
    const MetadataModel& metadata,
    Architecture architecture,
    const CallSiteAbiSpec& spec) const {
    CallSiteAbiModel result;
    result.kind = spec.kind;
    result.signature.architecture = architecture;
    const double version = metadata.versionInfo.preciseVersion > 0 ?
        metadata.versionInfo.preciseVersion : metadata.version;
    result.runtimeProfile = options_.runtime.id == "auto" ?
        AbiRuntimeProfile::forMetadataVersion(version) : options_.runtime;
    result.targetOptions = options_;
    result.targetOptions.runtime = result.runtimeProfile;
    if (spec.x64) result.targetOptions.x64 = *spec.x64;
    if (spec.x86) result.targetOptions.x86 = *spec.x86;
    if (spec.arm32Float) result.targetOptions.arm32Float = *spec.arm32Float;
    result.methodPointer = spec.methodPointer;
    result.virtualMethodPointer = spec.virtualMethodPointer;
    result.invokerMethod = spec.invokerMethod;
    result.invokerContext = spec.invokerContext;
    result.invokerReturnStorage = spec.invokerReturnStorage ? spec.invokerReturnStorage : spec.invokerContext;

    const auto addError = [&result](AbiDiagnosticCode code, std::string message) {
        result.diagnostics.push_back({AbiDiagnosticSeverity::Error, code, std::move(message), std::nullopt});
    };
    if (pointerBitsFor(architecture) == 0) {
        addError(AbiDiagnosticCode::UnsupportedArchitecture, "The requested architecture has no supported scalar calling convention");
        setUnsupportedReturn(result.signature);
        return result;
    }
    if (const auto error = conventionError(architecture, result.targetOptions)) {
        addError(AbiDiagnosticCode::UnknownCallingConvention, *error);
        setUnsupportedReturn(result.signature);
        return result;
    }
    if (const auto error = runtimeProfileError(result.runtimeProfile)) {
        addError(AbiDiagnosticCode::UnknownCallingConvention,
            result.runtimeProfile.id == "unsupported-il2cpp-invoker-profile" ?
                "No verified invocation ABI for IL2CPP metadata version " + std::to_string(version) : *error);
        setUnsupportedReturn(result.signature);
        return result;
    }

    bool invoker = false;
    bool requireBlittable = false;
    bool reduced = false;
    bool usesAdjustorThunk = spec.kind == CallSiteKind::AdjustorThunk || spec.adjustorThunk != nullptr;
    switch (spec.kind) {
    case CallSiteKind::GeneratedDirect:
        result.targetKind = CallTargetKind::MethodPointer;
        result.methodInfoPolicy = result.runtimeProfile.generatedMethodInfo;
        result.target = spec.methodPointer;
        break;
    case CallSiteKind::Invoker:
        result.targetKind = CallTargetKind::InvokerMethod;
        result.methodInfoPolicy = MethodInfoArgumentPolicy::Omit;
        result.target = spec.invokerMethod;
        invoker = true;
        break;
    case CallSiteKind::GenericInstance:
        result.targetKind = CallTargetKind::MethodPointer;
        result.methodInfoPolicy = result.runtimeProfile.generatedMethodInfo;
        result.target = spec.methodPointer;
        break;
    case CallSiteKind::Virtual:
        result.targetKind = CallTargetKind::VirtualMethodPointer;
        result.methodInfoPolicy = result.runtimeProfile.generatedMethodInfo;
        result.target = result.runtimeProfile.methodInfoPointers == AbiMethodInfoPointerLayout::MethodAndVirtualMethodPointer ?
            spec.virtualMethodPointer : spec.methodPointer;
        break;
    case CallSiteKind::Interface:
        result.targetKind = CallTargetKind::InterfaceMethodPointer;
        result.methodInfoPolicy = result.runtimeProfile.generatedMethodInfo;
        result.target = result.runtimeProfile.methodInfoPointers == AbiMethodInfoPointerLayout::MethodAndVirtualMethodPointer ?
            spec.virtualMethodPointer : spec.methodPointer;
        break;
    case CallSiteKind::InternalCall:
        result.targetKind = CallTargetKind::InternalCall;
        result.methodInfoPolicy = MethodInfoArgumentPolicy::Omit;
        result.target = spec.methodPointer;
        break;
    case CallSiteKind::PInvoke:
        result.targetKind = CallTargetKind::PInvoke;
        result.methodInfoPolicy = MethodInfoArgumentPolicy::Omit;
        result.target = spec.methodPointer;
        requireBlittable = true;
        break;
    case CallSiteKind::Delegate:
        result.targetKind = CallTargetKind::DelegateMethodPointer;
        result.methodInfoPolicy = result.runtimeProfile.generatedMethodInfo;
        result.target = spec.methodPointer;
        break;
    case CallSiteKind::DelegatePInvoke:
        result.targetKind = CallTargetKind::DelegatePInvokeWrapper;
        result.methodInfoPolicy = MethodInfoArgumentPolicy::Omit;
        result.target = spec.methodPointer;
        requireBlittable = true;
        break;
    case CallSiteKind::Unresolved:
        result.targetKind = CallTargetKind::UnresolvedMethodPointer;
        result.methodInfoPolicy = result.runtimeProfile.generatedMethodInfo;
        result.target = spec.methodPointer;
        // An unresolved stub may expose only a reduced signature. A full
        // invocation is safe only when the caller supplied every native type.
        reduced = !spec.returnType || spec.parameterTypes.size() != method.parameters.size();
        break;
    case CallSiteKind::AdjustorThunk:
        result.targetKind = CallTargetKind::AdjustorThunk;
        result.methodInfoPolicy = result.runtimeProfile.generatedMethodInfo;
        result.target = spec.adjustorThunk;
        break;
    case CallSiteKind::Unknown:
    default:
        addError(AbiDiagnosticCode::UnknownCallingConvention, "Unknown IL2CPP call-site convention");
        setUnsupportedReturn(result.signature);
        return result;
    }

    const bool virtualCall = spec.kind == CallSiteKind::Virtual || spec.kind == CallSiteKind::Interface;
    if (spec.virtualMethodPointer && !virtualCall) {
        addError(AbiDiagnosticCode::InvalidCallSignature, "virtualMethodPointer is only valid for virtual/interface call sites");
    }
    if (spec.virtualMethodPointer && virtualCall &&
        result.runtimeProfile.methodInfoPointers != AbiMethodInfoPointerLayout::MethodAndVirtualMethodPointer) {
        addError(AbiDiagnosticCode::ProfileConflict, "The runtime profile has no MethodInfo::virtualMethodPointer field");
    }
    if (usesAdjustorThunk && invoker) {
        addError(AbiDiagnosticCode::InvalidCallSignature, "An adjustor thunk is a method-pointer target, not an invoker signature");
    }
    if (usesAdjustorThunk && !result.runtimeProfile.adjustorThunks) {
        addError(AbiDiagnosticCode::ProfileConflict, "The runtime profile has no generic adjustor thunk table");
    }
    if (usesAdjustorThunk && !invoker) {
        result.targetKind = CallTargetKind::AdjustorThunk;
        result.target = spec.adjustorThunk;
        result.adjustorThunk.present = true;
        result.adjustorThunk.thunk = spec.adjustorThunk;
        result.adjustorThunk.methodPointer = spec.methodPointer;
        result.adjustorThunk.thisValue = spec.adjustorThunkThis;
        result.adjustorThunk.thisOffset = spec.adjustorThunkThisOffset.value_or(0);
    }
    if ((spec.kind == CallSiteKind::GenericInstance || spec.genericInstance ||
         spec.genericClassInstance || spec.genericMethodInstance) && !result.runtimeProfile.genericContexts) {
        addError(AbiDiagnosticCode::ProfileConflict,
            "The runtime profile does not establish a generic context calling convention");
    }
    if (invoker && result.runtimeProfile.invoker != AbiInvokerSignature::FiveArguments &&
        (spec.invokerContext || spec.invokerReturnStorage)) {
        addError(AbiDiagnosticCode::InvalidCallSignature,
            "This invoker profile has no fifth return-storage argument");
    }
    if (invoker && spec.invokerContext && spec.invokerReturnStorage &&
        spec.invokerContext != spec.invokerReturnStorage) {
        addError(AbiDiagnosticCode::InvalidCallSignature,
            "Conflicting fifth invoker argument values");
    }

    MethodModel signatureMethod = method;
    if (spec.returnType) signatureMethod.returnType = *spec.returnType;
    if (!spec.parameterTypes.empty()) {
        if (spec.parameterTypes.size() != signatureMethod.parameters.size()) {
            addError(AbiDiagnosticCode::InvalidCallSignature, "The typed parameter list does not match the managed method parameter count");
        } else {
            for (size_t index = 0; index < spec.parameterTypes.size(); ++index) {
                signatureMethod.parameters[index].type = spec.parameterTypes[index];
            }
        }
    }
    if (spec.kind == CallSiteKind::DelegatePInvoke) signatureMethod.isStatic = true;
    if (spec.kind == CallSiteKind::PInvoke && !signatureMethod.isStatic) {
        addError(AbiDiagnosticCode::InvalidCallSignature, "A P/Invoke target cannot have a managed this argument");
        signatureMethod.isStatic = true;
    }

    auto callOptions = result.targetOptions;
    callOptions.methodInfo = result.methodInfoPolicy;
    result.targetOptions.methodInfo = result.methodInfoPolicy;
    const auto* typeIndex = indexedMetadata_ == &metadata ? typeNameIndex_.get() : nullptr;
    if (reduced) {
        if (!result.runtimeProfile.unresolvedReducedSignatures) {
            addError(AbiDiagnosticCode::ProfileConflict, "The runtime profile does not permit reduced unresolved signatures");
            setUnsupportedReturn(result.signature);
            return result;
        }
        result.signature.reducedSignature = true;
        result.signature.omittedParameterCount = signatureMethod.parameters.size();
        BindingBuilder builder(signatureMethod, metadata, architecture, callOptions, result.signature, false, typeIndex);
        if (!signatureMethod.isStatic) builder.addThis();
        if (result.methodInfoPolicy == MethodInfoArgumentPolicy::Append) builder.addMethodInfo();
        if (spec.returnType) {
            builder.setReturn();
        } else {
            auto& returnValue = result.signature.returnValue;
            returnValue.managedType = signatureMethod.returnType.empty() ? "<unknown>" : signatureMethod.returnType;
            returnValue.valueKind = AbiValueKind::Unknown;
            returnValue.conversion = AbiConversion::Unsupported;
            returnValue.runtimeHelper = unsupportedAbiHelper;
        }
        result.diagnostics.push_back({
            AbiDiagnosticSeverity::Warning,
            AbiDiagnosticCode::ReducedSignature,
            "Unresolved target uses a reduced signature; omitted parameters and return type must be resolved separately",
            std::nullopt
        });
    } else if (invoker) {
        MethodModel invokerMethod;
        invokerMethod.address = method.address;
        invokerMethod.isStatic = true;
        invokerMethod.returnType = result.runtimeProfile.invoker == AbiInvokerSignature::FiveArguments ? "void" : "void*";
        BindingBuilder builder(invokerMethod, metadata, architecture, callOptions, result.signature, false, typeIndex);
        if (result.runtimeProfile.invoker != AbiInvokerSignature::LegacyThreeArguments) {
            builder.addPointer(AbiValueRole::MethodPointer, "__abi_method_pointer", "methodPointer", "Il2CppMethodPointer");
        }
        builder.addPointer(AbiValueRole::MethodInfo, "__abi_method_info", "method", "const MethodInfo*");
        builder.addPointer(AbiValueRole::Instance, "__abi_instance", "obj", "void*");
        builder.addPointer(AbiValueRole::Parameters, "__abi_parameters", "params", "void**");
        if (result.runtimeProfile.invoker == AbiInvokerSignature::FiveArguments) {
            builder.addPointer(AbiValueRole::InvokerReturnStorage, "__abi_invoker_return_storage", "ret", "void*");
        }
        builder.setReturn();
        if (!result.target) result.targetRuntimeHelper = "RuntimeCalls.GetInvokerMethod";
    } else {
        BindingBuilder builder(signatureMethod, metadata, architecture, callOptions, result.signature, requireBlittable, typeIndex);
        if (!signatureMethod.isStatic) builder.addThis();
        for (size_t index = 0; index < signatureMethod.parameters.size(); ++index) builder.addParameter(index);
        if (result.methodInfoPolicy == MethodInfoArgumentPolicy::Append) builder.addMethodInfo();
        builder.setReturn();
    }

    for (const auto& binding : result.signature.bindings) {
        if (binding.role == AbiValueRole::MethodInfo) {
            result.methodInfo = spec.methodInfo ? spec.methodInfo : binding.nativeValue;
            break;
        }
    }

    if (!result.target && result.targetRuntimeHelper.empty()) {
        switch (spec.kind) {
        case CallSiteKind::GeneratedDirect: result.targetRuntimeHelper = "RuntimeCalls.GetMethodPointer"; break;
        case CallSiteKind::GenericInstance: result.targetRuntimeHelper = "RuntimeCalls.GetGenericMethodPointer"; break;
        case CallSiteKind::Virtual:
            result.targetRuntimeHelper = spec.genericInstance ? "RuntimeCalls.ResolveGenericVirtualMethodPointer" : virtualTargetHelper;
            break;
        case CallSiteKind::Interface:
            result.targetRuntimeHelper = spec.genericInstance ? "RuntimeCalls.ResolveGenericInterfaceMethodPointer" : interfaceTargetHelper;
            break;
        case CallSiteKind::InternalCall: result.targetRuntimeHelper = "RuntimeCalls.ResolveInternalCall"; break;
        case CallSiteKind::PInvoke: result.targetRuntimeHelper = "RuntimeCalls.ResolvePInvoke"; break;
        case CallSiteKind::Delegate: result.targetRuntimeHelper = "RuntimeCalls.ResolveDelegateMethodPointer"; break;
        case CallSiteKind::DelegatePInvoke: result.targetRuntimeHelper = "RuntimeCalls.ResolveDelegatePInvokeWrapper"; break;
        case CallSiteKind::Unresolved: result.targetRuntimeHelper = "RuntimeCalls.ResolveUnresolvedMethodPointer"; break;
        case CallSiteKind::AdjustorThunk: result.targetRuntimeHelper = "RuntimeCalls.ResolveAdjustorThunk"; break;
        default: break;
        }
    }
    if (usesAdjustorThunk && !result.target && spec.kind != CallSiteKind::AdjustorThunk) {
        result.targetRuntimeHelper = "RuntimeCalls.ResolveAdjustorThunk";
    }
    if (spec.kind == CallSiteKind::GenericInstance && !spec.methodInfo) {
        result.methodInfoRuntimeHelper = "RuntimeCalls.GetInflatedMethodInfo";
    }
    if (spec.kind == CallSiteKind::Virtual && !spec.methodInfo) {
        result.methodInfoRuntimeHelper = spec.genericInstance ? "RuntimeCalls.ResolveGenericVirtualMethodInfo" : virtualMethodInfoHelper;
    }
    if (spec.kind == CallSiteKind::Interface && !spec.methodInfo) {
        result.methodInfoRuntimeHelper = spec.genericInstance ? "RuntimeCalls.ResolveGenericInterfaceMethodInfo" : interfaceMethodInfoHelper;
    }

    if (spec.kind == CallSiteKind::GenericInstance || spec.genericInstance) {
        result.genericContext.present = true;
        result.genericContext.methodInfo = result.methodInfo;
        result.genericContext.classInstance = spec.genericClassInstance;
        result.genericContext.methodInstance = spec.genericMethodInstance;
        result.genericContext.rgctxDataHelper = rgctxDataHelper;
        result.genericContext.resolveTypeHelper = resolveGenericTypeHelper;
        if (!result.genericContext.classInstance) result.genericContext.classInstanceHelper = genericClassInstHelper;
        if (!result.genericContext.methodInstance) result.genericContext.methodInstanceHelper = genericMethodInstHelper;
    }
    return result;
}

std::vector<Statement> AbiAdapter::bindingStatements(
    const MethodModel& method,
    const MetadataModel& metadata,
    Architecture architecture) const {
    auto result = bind(method, metadata, architecture);
    return std::move(result.statements);
}

std::vector<Statement> AbiAdapter::returnStatements(const AbiBindingModel& model, uint64_t address) const {
    const auto pointerBits = pointerBitsFor(model.architecture);
    const auto pointerType = ScalarType::pointer(pointerBits);
    const auto& returnValue = model.returnValue;
    if (returnValue.valueKind == AbiValueKind::Unsupported || returnValue.conversion == AbiConversion::Unsupported) {
        return {unsupportedReturn(model, address, pointerType)};
    }

    Statement result;
    result.address = address;
    if (returnValue.valueKind == AbiValueKind::Void) {
        result.kind = Statement::Kind::Return;
        return {result};
    }
    if (returnValue.conversion == AbiConversion::None) {
        result.kind = Statement::Kind::Return;
        result.value = returnValue.value;
        return {result};
    }

    auto converted = reg("__abi_return", returnValue.scalarType);
    Statement call;
    call.address = address;
    call.kind = Statement::Kind::Call;
    call.destination = converted;
    call.target = reg(returnValue.runtimeHelper, pointerType);
    call.arguments = {returnValue.nativeValue};
    result.kind = Statement::Kind::Return;
    result.value = std::move(converted);
    return {std::move(call), std::move(result)};
}

AbiBindingModel adaptMethodAbi(
    const MethodModel& method,
    const MetadataModel& metadata,
    Architecture architecture,
    AbiAdapterOptions options) {
    return AbiAdapter(options).bind(method, metadata, architecture);
}

CallSiteAbiModel adaptCallSiteAbi(
    const MethodModel& method,
    const MetadataModel& metadata,
    Architecture architecture,
    const CallSiteAbiSpec& spec,
    AbiAdapterOptions options) {
    return AbiAdapter(options).bindCallSite(method, metadata, architecture, spec);
}

} // namespace il2cpprec
