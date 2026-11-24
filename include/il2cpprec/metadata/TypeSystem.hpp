#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

namespace ida {
struct SourceProfile;
}

enum class Il2CppTypeCode : uint8_t {
    End = 0x00,
    Void = 0x01,
    Boolean = 0x02,
    Char = 0x03,
    I1 = 0x04,
    U1 = 0x05,
    I2 = 0x06,
    U2 = 0x07,
    I4 = 0x08,
    U4 = 0x09,
    I8 = 0x0a,
    U8 = 0x0b,
    R4 = 0x0c,
    R8 = 0x0d,
    String = 0x0e,
    Ptr = 0x0f,
    ByRef = 0x10,
    ValueType = 0x11,
    Class = 0x12,
    Var = 0x13,
    Array = 0x14,
    GenericInst = 0x15,
    TypedByRef = 0x16,
    I = 0x18,
    U = 0x19,
    FnPtr = 0x1b,
    Object = 0x1c,
    SzArray = 0x1d,
    MVar = 0x1e,
    CModReqD = 0x1f,
    CModOpt = 0x20,
    Internal = 0x21,
    Modifier = 0x40,
    Sentinel = 0x41,
    Pinned = 0x45,
    Enum = 0x55,
    TypeIndex = 0xff
};

using Il2CppTypeEnum = Il2CppTypeCode;

struct ManagedType {
    Il2CppTypeCode code = Il2CppTypeCode::Object;
    std::string name;
    std::shared_ptr<ManagedType> elementType;
    std::vector<ManagedType> genericArguments;
    uint32_t rank = 1;
    bool byRef = false;
};

struct TypeLayoutDiagnostic {
    std::string typeName;
    uint16_t pointerBits = 0;
    std::string message;
};

struct FieldLayout {
    FieldModel field;
    std::optional<size_t> size;
    std::optional<size_t> alignment;
    std::string accessExpression;
    std::optional<TypeLayoutDiagnostic> diagnostic;
};

struct TypeLayoutInfo {
    uint64_t instanceSize = 0;
    uint64_t actualInstanceSize = 0;
    uint64_t staticSize = 0;
    uint64_t threadStaticSize = 0;
    uint64_t parentInstanceSize = 0;
    uint64_t parentActualInstanceSize = 0;
    uint32_t minimumAlignment = 0;
    uint32_t naturalAlignment = 0;
    uint8_t packingSize = 0;
    bool valueType = false;
    bool generic = false;
    bool array = false;
    bool referenceType = false;
    std::vector<int32_t> fieldOffsets;
};

struct TypeLayoutContext {
    size_t pointerSize = 8;
    const MetadataModel* metadata = nullptr;
    const std::vector<TypeLayoutInfo>* typeLayouts = nullptr;
    const ida::SourceProfile* sourceProfile = nullptr;
    double metadataVersion = 0;
};

struct Il2CppTypeBitLayout {
    size_t size = 0;
    size_t dataOffset = 0;
    size_t bitsOffset = 0;
    size_t bitsSize = 0;
    size_t codeOffset = 0;
    size_t codeSize = 0;
    size_t byRefOffset = 0;
    size_t byRefSize = 0;
    size_t pinnedOffset = 0;
    size_t pinnedSize = 0;
    uint8_t byRefMask = 0;
    uint8_t pinnedMask = 0;
};

struct ObjectLayout {
    std::string typeName;
    uint64_t instanceSize = 0;
    uint64_t staticSize = 0;
    std::vector<FieldLayout> instanceFields;
    std::vector<FieldLayout> staticFields;
    uint64_t actualInstanceSize = 0;
    uint64_t valueSize = 0;
    uint64_t threadStaticSize = 0;
    uint32_t minimumAlignment = 0;
    uint32_t naturalAlignment = 0;
    bool valueType = false;
    std::vector<FieldLayout> threadStaticFields;
    std::vector<TypeLayoutDiagnostic> diagnostics;
};

class TypeSystem {
public:
    static std::optional<std::string> primitiveType(Il2CppTypeCode code);
    static std::string cSharpType(Il2CppTypeCode code);
    static std::string cSharpType(const ManagedType& type);
    static std::string resolve(std::string_view type, const MetadataModel* metadata = nullptr);
    static std::string resolve(size_t typeReferenceIndex, const MetadataModel& metadata);
    static std::string returnType(const MethodModel& method, const MetadataModel* metadata = nullptr);

    static std::string parameter(const ParameterModel& parameter, size_t index = 0, const MetadataModel* metadata = nullptr);
    static std::string parameterList(const MethodModel& method, const MetadataModel* metadata = nullptr);
    static std::string methodSignature(const MethodModel& method, const MetadataModel* metadata = nullptr);

    static std::optional<Il2CppTypeBitLayout> il2CppTypeLayout(const TypeLayoutContext& context = {});
    static std::optional<size_t> nativeSize(std::string_view type, const TypeLayoutContext& context = {});
    static std::optional<size_t> nativeAlignment(std::string_view type, const TypeLayoutContext& context = {});
    static std::optional<TypeLayoutDiagnostic> layoutDiagnostic(std::string_view type, const TypeLayoutContext& context = {});
    static std::optional<size_t> fieldSize(const FieldModel& field, size_t pointerSize = 8);
    static std::optional<size_t> fieldSize(const FieldModel& field, const TypeLayoutContext& context);
    static std::optional<size_t> fieldAlignment(const FieldModel& field, size_t pointerSize = 8);
    static std::optional<size_t> fieldAlignment(const FieldModel& field, const TypeLayoutContext& context);
    static FieldLayout fieldLayout(const TypeModel& declaringType, const FieldModel& field, size_t pointerSize = 8);
    static FieldLayout fieldLayout(const TypeModel& declaringType, const FieldModel& field, const TypeLayoutContext& context);
    static ObjectLayout objectLayout(
        const TypeModel& type,
        size_t pointerSize = 8,
        uint64_t declaredInstanceSize = 0,
        uint64_t declaredStaticSize = 0);
    static ObjectLayout objectLayout(
        const TypeModel& type,
        const TypeLayoutInfo& layout,
        const TypeLayoutContext& context = {});
    static ObjectLayout objectLayout(
        const TypeModel& type,
        const MetadataModel& metadata,
        size_t pointerSize = 8,
        const TypeLayoutInfo& layout = {},
        const std::vector<TypeLayoutInfo>* typeLayouts = nullptr);
    static std::string fieldAccess(
        const TypeModel& declaringType,
        const FieldModel& field,
        std::string_view instance = "this");
    static std::string describe(const ObjectLayout& layout);
};

} // namespace il2cpprec
