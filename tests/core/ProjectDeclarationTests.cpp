#include "TestSupport.hpp"

#include <il2cpprec/emit/ProjectWriter.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>

namespace il2cpprec::tests {
namespace {

struct OutputDirectory {
    explicit OutputDirectory(std::filesystem::path value) : path(std::move(value)) {
        std::filesystem::remove_all(path);
        std::filesystem::create_directories(path);
    }
    ~OutputDirectory() { std::filesystem::remove_all(path); }
    std::filesystem::path path;
};

std::string readFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

size_t countText(const std::string& text, const std::string& fragment) {
    size_t count = 0;
    for (size_t position = text.find(fragment); position != std::string::npos;
         position = text.find(fragment, position + fragment.size())) ++count;
    return count;
}

} // namespace

TEST_CASE("enum member defaults emit integral constants without enum casts") {
    MetadataModel metadata;
    TypeModel enumeration;
    enumeration.name = "Mode";
    enumeration.flags = 0x1 | 0x80 | 0x100;
    enumeration.bitfield = 0x2;
    FieldModel underlying;
    underlying.name = "value__";
    underlying.type = "int";
    enumeration.fields.push_back(underlying);
    FieldModel zero;
    zero.name = "Zero";
    zero.type = "Mode";
    zero.defaultValueIndex = 0;
    enumeration.fields.push_back(zero);
    FieldModel negative = zero;
    negative.name = "Negative";
    negative.defaultValueIndex = 1;
    enumeration.fields.push_back(negative);
    FieldModel invalid = zero;
    invalid.name = "Unknown";
    invalid.defaultValueIndex = 2;
    enumeration.fields.push_back(invalid);
    metadata.types.push_back(std::move(enumeration));
    metadata.fieldDefaultValues = {{1, -1, 0}, {2, -1, 4}, {3, -1, 99}};
    metadata.defaultValueData = {0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff};

    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/enum-integral-emission");
    ProjectWriter{}.write(output.path, metadata, {});
    const auto source = readFile(output.path / "Mode.cs");
    CHECK(source.find("public enum Mode : int") != std::string::npos);
    CHECK(source.find("Zero = unchecked((int)0x0UL),") != std::string::npos);
    CHECK(source.find("Negative = unchecked((int)0xFFFFFFFFUL),") != std::string::npos);
    CHECK(source.find("(Mode)") == std::string::npos);
    CHECK(source.find("Unknown =") == std::string::npos);
    CHECK(source.find("constant value for 'Unknown' is unavailable") != std::string::npos);
}

TEST_CASE("char constants use a single escaped Unicode code unit") {
    MetadataModel metadata;
    TypeModel type;
    type.name = "CharConstants";
    type.flags = 1;
    FieldModel field;
    field.name = "MaxValue";
    field.type = "char";
    field.flags = 6 | 0x10 | 0x40 | 0x80;
    field.defaultValueIndex = 0;
    type.fields.push_back(field);
    metadata.types.push_back(type);
    metadata.fieldDefaultValues = {{0, -1, 0}};
    metadata.defaultValueData = {0xff, 0xff};

    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/char-constant-emission");
    ProjectWriter{}.write(output.path, metadata, {});
    const auto source = readFile(output.path / "CharConstants.cs");
    CHECK(source.find("MaxValue = '\\uffff';") != std::string::npos);
}

TEST_CASE("full declarations retain metadata types while filtering native bodies") {
    MetadataModel metadata;
    TypeModel game;
    game.name = "GameType";
    game.imageName = "Assembly-CSharp.dll";
    game.flags = 1;
    FieldModel spriteField;
    spriteField.name = "SpriteField";
    spriteField.type = "UnityEngine.Sprite";
    game.fields.push_back(spriteField);
    MethodModel gameMethod;
    gameMethod.name = "Run";
    gameMethod.declaringType = "GameType";
    gameMethod.imageName = game.imageName;
    gameMethod.address = 0x1000;
    gameMethod.returnType = "void";
    gameMethod.isStatic = true;
    game.methods.push_back(gameMethod);
    metadata.types.push_back(game);

    TypeModel sprite;
    sprite.nameSpace = "UnityEngine";
    sprite.name = "Sprite";
    sprite.imageName = "UnityEngine.CoreModule.dll";
    sprite.flags = 1;
    MethodModel externalMethod;
    externalMethod.name = "Unused";
    externalMethod.declaringType = "UnityEngine.Sprite";
    externalMethod.imageName = sprite.imageName;
    externalMethod.address = 0x2000;
    externalMethod.returnType = "void";
    externalMethod.isStatic = true;
    sprite.methods.push_back(externalMethod);
    metadata.types.push_back(sprite);

    RecoveredFunction gameFunction;
    gameFunction.architecture = Architecture::Arm64;
    gameFunction.address = 0x1000;
    gameFunction.name = "GameType__Run";
    RecoveredFunction externalFunction = gameFunction;
    externalFunction.address = 0x2000;
    externalFunction.name = "UnityEngine.Sprite__Unused";

    ProjectWriterOptions options;
    options.includedImages = {"Assembly-CSharp.dll"};
    OutputDirectory filtered(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                             "build/tests/filtered-declarations");
    ProjectWriter{options}.write(filtered.path, metadata, {gameFunction, externalFunction});
    CHECK(std::filesystem::exists(filtered.path / "GameType.cs"));
    CHECK(!std::filesystem::exists(filtered.path / "UnityEngine/Sprite.cs"));

    options.includeExternalDeclarations = true;
    OutputDirectory full(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                         "build/tests/full-declarations");
    const auto report = ProjectWriter{options}.write(full.path, metadata, {gameFunction, externalFunction});
    CHECK(std::filesystem::exists(full.path / "GameType.cs"));
    CHECK(std::filesystem::exists(full.path / "UnityEngine/Sprite.cs"));
    CHECK(readFile(full.path / "GameType.cs").find("UnityEngine.Sprite SpriteField") != std::string::npos);
    CHECK(readFile(full.path / "UnityEngine/Sprite.cs").find("Unused(") == std::string::npos);
    CHECK_EQ(report.omitted, 1);
    CHECK_EQ(report.methods.size(), 2);
    CHECK(report.methods[0].imageName == "UnityEngine.CoreModule.dll");
    CHECK(report.methods[1].imageName == "Assembly-CSharp.dll");
}

TEST_CASE("full declarations narrow members exposing known internal types") {
    MetadataModel metadata;
    TypeModel internalType;
    internalType.name = "InternalValue";
    internalType.imageName = "Game.dll";
    internalType.flags = 0;
    internalType.declaringTypeIndex = 41953; // Invalid parent: emitted as a standalone internal type.
    metadata.types.push_back(internalType);
    TypeModel otherImageType = internalType;
    otherImageType.imageName = "Other.dll";
    otherImageType.flags = 1;
    metadata.types.push_back(otherImageType);

    TypeModel api;
    api.name = "Api";
    api.imageName = "Game.dll";
    api.flags = 1;
    FieldModel field;
    field.name = "Value";
    field.type = "InternalValue[]";
    field.flags = 6;
    api.fields.push_back(field);
    MethodModel method;
    method.name = "Get";
    method.declaringType = "Api";
    method.imageName = "Game.dll";
    method.address = 0x1000;
    method.returnType = "InternalValue[]";
    method.isStatic = true;
    method.flags = 6 | 0x10;
    api.methods.push_back(method);
    MethodModel getter = method;
    getter.name = "get_ValueProp";
    getter.address = 0x1004;
    api.methods.push_back(getter);
    api.propertyStart = 0;
    api.propertyCount = 1;
    metadata.types.push_back(api);
    PropertyModel property;
    property.name = "ValueProp";
    property.get = 1;
    metadata.properties.push_back(property);

    RecoveredFunction function;
    function.architecture = Architecture::Arm64;
    function.address = 0x1000;
    function.name = "Api__Get";
    ProjectWriterOptions options;
    options.includedImages = {"Game.dll"};
    options.includeExternalDeclarations = true;
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/internal-type-visibility");
    ProjectWriter{options}.write(output.path, metadata, {function});
    const auto source = readFile(output.path / "Api.cs");
    CHECK(source.find("internal InternalValue[] Value;") != std::string::npos);
    if (source.find("internal static InternalValue[] ValueProp") == std::string::npos) {
        fail("Generated source:\n" + source, __FILE__, __LINE__);
    }
    CHECK(source.find("internal static InternalValue[] Get_0x1000()") != std::string::npos);
    CHECK(source.find("C# visibility narrowed") != std::string::npos);
}

TEST_CASE("different method support variants share common CSharp helpers") {
    MetadataModel metadata;
    TypeModel type;
    type.name = "TwoMethods";
    type.flags = 1;
    for (const auto& [name, address] : {
             std::pair<const char*, uint64_t>{"First", 0x1000},
             {"Second", 0x2000}}) {
        MethodModel method;
        method.name = name;
        method.declaringType = type.name;
        method.address = address;
        method.returnType = "void";
        method.isStatic = true;
        method.flags = 6 | 0x10;
        type.methods.push_back(method);
    }
    metadata.types.push_back(type);

    RecoveredFunction first;
    first.architecture = Architecture::Arm64;
    first.address = 0x1000;
    first.name = "TwoMethods__First";
    Statement firstReturn;
    firstReturn.kind = Statement::Kind::Return;
    firstReturn.address = 0x1000;
    first.blocks.push_back({0x1000, {firstReturn}});

    RecoveredFunction second = first;
    second.address = 0x2000;
    second.name = "TwoMethods__Second";
    Statement vectorAssignment;
    vectorAssignment.kind = Statement::Kind::Assign;
    vectorAssignment.address = 0x2000;
    vectorAssignment.destination = reg("v8", ScalarType::vectorBits(128));
    vectorAssignment.value = constant(0, ScalarType::vectorBits(128));
    Statement secondReturn = firstReturn;
    secondReturn.address = 0x2004;
    second.blocks.front() = {0x2000, {vectorAssignment, secondReturn}};

    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/support-fragment-emission");
    ProjectWriter{}.write(output.path, metadata, {first, second});
    const auto source = readFile(output.path / "TwoMethods.cs");
    CHECK_EQ(countText(source, "struct __UnsupportedValue"), 1);
    CHECK_EQ(countText(source, "class __RecoveryUnsupportedException"), 1);
    CHECK_EQ(countText(source, "void __Discard<T>"), 1);
    CHECK_EQ(countText(source, "struct __UnsupportedVector128"), 1);
    CHECK_EQ(countText(source, "struct RuntimeVector128"), 1);
}

TEST_CASE("unbound generic member types are omitted without invented arguments") {
    MetadataModel metadata;
    GenericContainerModel container;
    container.typeArgumentCount = 2;
    container.genericParameterStart = 0;
    metadata.genericContainers.push_back(container);
    GenericParameterModel firstParameter;
    firstParameter.name = "TKey";
    GenericParameterModel secondParameter;
    secondParameter.name = "TValue";
    metadata.genericParameters = {firstParameter, secondParameter};

    TypeModel generic;
    generic.name = "Enumerator`2";
    generic.imageName = "Test.dll";
    generic.flags = 1;
    generic.genericContainerIndex = 0;
    metadata.types.push_back(generic);
    TypeModel externalGeneric = generic;
    externalGeneric.name = "OtherEnumerator`2";
    externalGeneric.imageName = "Other.dll";
    metadata.types.push_back(externalGeneric);
    TypeModel localNonGeneric = generic;
    localNonGeneric.name = "OtherEnumerator";
    localNonGeneric.genericContainerIndex = -1;
    metadata.types.push_back(localNonGeneric);

    TypeReferenceModel openReference;
    openReference.code = static_cast<uint8_t>(Il2CppTypeCode::ValueType);
    openReference.name = "Enumerator";
    openReference.definitionIndex = 0;
    metadata.typeReferences.push_back(openReference);

    TypeModel holder;
    holder.name = "Holder";
    holder.imageName = "Test.dll";
    holder.flags = 1;
    FieldModel raw;
    raw.name = "Raw";
    raw.type = "Enumerator";
    holder.fields.push_back(raw);
    FieldModel indirect = raw;
    indirect.name = "Indirect";
    indirect.type = "type[0]";
    holder.fields.push_back(indirect);
    FieldModel crossImage = raw;
    crossImage.name = "CrossImage";
    crossImage.type = "OtherEnumerator";
    holder.fields.push_back(crossImage);
    metadata.types.push_back(holder);

    ProjectWriterOptions options;
    options.includedImages = {"Test.dll"};
    options.includeExternalDeclarations = true;
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/unbound-generic-omission");
    ProjectWriter{options}.write(output.path, metadata, {});
    const auto source = readFile(output.path / "Holder.cs");
    CHECK(source.find("Raw;") == std::string::npos);
    CHECK(source.find("Indirect;") == std::string::npos);
    CHECK(source.find("CrossImage;") == std::string::npos);
    CHECK_EQ(countText(source, "has unresolved C# type syntax; member was not emitted"), 3);
}

TEST_CASE("full declarations use netstandard core types instead of mscorlib shells") {
    MetadataModel metadata;
    TypeModel framework;
    framework.nameSpace = "System";
    framework.name = "Attribute";
    framework.imageName = "mscorlib.dll";
    framework.flags = 1;
    MethodModel frameworkMethod;
    frameworkMethod.name = ".ctor";
    frameworkMethod.declaringType = "System.Attribute";
    frameworkMethod.imageName = framework.imageName;
    frameworkMethod.address = 0x2000;
    framework.methods.push_back(frameworkMethod);
    metadata.types.push_back(framework);

    TypeModel game;
    game.name = "Game";
    game.imageName = "Game.dll";
    game.flags = 1;
    FieldModel field;
    field.name = "KnownFrameworkType";
    field.type = "System.Attribute";
    field.flags = 6;
    game.fields.push_back(field);
    metadata.types.push_back(game);
    RecoveredFunction native;
    native.address = 0x2000;
    native.name = "System.Attribute__.ctor";

    ProjectWriterOptions options;
    options.includedImages = {"Game.dll"};
    options.includeExternalDeclarations = true;
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/framework-core-exclusion");
    const auto report = ProjectWriter{options}.write(output.path, metadata, {native});
    CHECK(std::filesystem::exists(output.path / "Game.cs"));
    CHECK(!std::filesystem::exists(output.path / "System/Attribute.cs"));
    CHECK(readFile(output.path / "Game.cs").find("System.Attribute KnownFrameworkType") != std::string::npos);
    CHECK_EQ(report.omitted, 1);
    CHECK(report.methods[0].imageName == "mscorlib.dll");
    CHECK(report.methods[0].reason.find("supplied by target framework") != std::string::npos);
}

TEST_CASE("static classes narrow invalid protected field visibility") {
    MetadataModel metadata;
    TypeModel type;
    type.name = "Interop";
    type.flags = 0x1 | 0x80 | 0x100;
    FieldModel field;
    field.name = "helper";
    field.type = "int";
    field.flags = 0x4 | 0x10;
    field.isStatic = true;
    type.fields.push_back(field);
    metadata.types.push_back(type);

    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/static-field-visibility");
    ProjectWriter{}.write(output.path, metadata, {});
    const auto source = readFile(output.path / "Interop.cs");
    CHECK(source.find("public static unsafe partial class Interop") != std::string::npos);
    CHECK(source.find("private static int helper;") != std::string::npos);
    CHECK(source.find("protected field visibility narrowed") != std::string::npos);
}

TEST_CASE("all-static members do not imply a static CSharp type") {
    MetadataModel metadata;
    TypeModel type;
    type.name = "SchemaType";
    type.flags = 1; // Native metadata does not mark the type abstract and sealed.
    FieldModel field;
    field.name = "StaticField";
    field.type = "int";
    field.flags = 6 | 0x10;
    field.isStatic = true;
    type.fields.push_back(field);
    metadata.types.push_back(type);
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/nonstatic-type-with-static-members");
    ProjectWriter{}.write(output.path, metadata, {});
    const auto source = readFile(output.path / "SchemaType.cs");
    CHECK(source.find("public unsafe partial class SchemaType") != std::string::npos);
    CHECK(source.find("static unsafe partial class SchemaType") == std::string::npos);
    CHECK(source.find("public static int StaticField;") != std::string::npos);
}

TEST_CASE("qualified field types bypass same-name namespace and class shadowing") {
    MetadataModel metadata;
    TypeModel implementation;
    implementation.nameSpace = "Fabric.Runtime.Internal";
    implementation.name = "Impl";
    implementation.imageName = "Game.dll";
    implementation.flags = 1;
    metadata.types.push_back(implementation);

    TypeModel fabric;
    fabric.nameSpace = "Fabric.Runtime";
    fabric.name = "Fabric";
    fabric.imageName = "Game.dll";
    fabric.flags = 1;
    FieldModel field;
    field.name = "impl";
    field.type = "Fabric.Runtime.Internal.Impl";
    field.flags = 1 | 0x10;
    fabric.fields.push_back(field);
    MethodModel make;
    make.name = "Make";
    make.declaringType = "Fabric.Runtime.Fabric";
    make.imageName = "Game.dll";
    make.address = 0x1000;
    make.returnType = "Fabric.Runtime.Internal.Impl";
    make.isStatic = true;
    make.flags = 6 | 0x10;
    fabric.methods.push_back(make);
    metadata.types.push_back(fabric);

    RecoveredFunction function;
    function.address = 0x1000;
    function.name = "Fabric.Runtime.Fabric__Make";

    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/namespace-type-shadowing");
    ProjectWriter{}.write(output.path, metadata, {function});
    const auto source = readFile(output.path / "Fabric/Runtime/Fabric.cs");
    CHECK(source.find("global::Fabric.Runtime.Internal.Impl impl;") != std::string::npos);
    CHECK(source.find("global::Fabric.Runtime.Internal.Impl Make()") != std::string::npos);
}

TEST_CASE("type references govern visibility and ambiguous raw names are omitted") {
    MetadataModel metadata;
    TypeModel internalType;
    internalType.name = "Reward";
    internalType.imageName = "Game.dll";
    internalType.flags = 0;
    metadata.types.push_back(internalType);
    TypeModel publicType = internalType;
    publicType.flags = 1;
    metadata.types.push_back(publicType);
    TypeReferenceModel reference;
    reference.code = static_cast<uint8_t>(Il2CppTypeCode::Class);
    reference.name = "Reward";
    reference.definitionIndex = 0;
    metadata.typeReferences.push_back(reference);

    TypeModel api;
    api.name = "Api";
    api.imageName = "Game.dll";
    api.flags = 1;
    FieldModel known;
    known.name = "Known";
    known.type = "type[0]";
    known.flags = 6;
    api.fields.push_back(known);
    FieldModel ambiguous = known;
    ambiguous.name = "Unknown";
    ambiguous.type = "Reward";
    api.fields.push_back(ambiguous);
    metadata.types.push_back(api);

    ProjectWriterOptions options;
    options.includedImages = {"Game.dll"};
    options.includeExternalDeclarations = true;
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/type-reference-visibility");
    ProjectWriter{options}.write(output.path, metadata, {});
    const auto source = readFile(output.path / "Api.cs");
    CHECK(source.find("internal Reward Known;") != std::string::npos);
    CHECK(source.find("Reward Unknown;") == std::string::npos);
    CHECK(source.find("field 'Unknown' has ambiguous metadata type identity") != std::string::npos);
}

TEST_CASE("emitted type names preserve cross-image and nested metadata identity") {
    MetadataModel metadata;
    auto makeType = [](std::string name, std::string image, uint32_t flags) {
        TypeModel type;
        type.name = std::move(name);
        type.imageName = std::move(image);
        type.flags = flags;
        return type;
    };
    metadata.types.push_back(makeType("ButtonState", "UI.dll", 0));
    metadata.types.push_back(makeType("ButtonState", "Game.dll", 1));
    metadata.types.push_back(makeType("OptionData", "UI.dll", 0));
    metadata.types.push_back(makeType("OptionData", "Game.dll", 1));

    TypeReferenceModel option;
    option.code = static_cast<uint8_t>(Il2CppTypeCode::Class);
    option.name = "OptionData";
    option.definitionIndex = 3;
    metadata.typeReferences.push_back(option);
    TypeReferenceModel optionArray;
    optionArray.code = static_cast<uint8_t>(Il2CppTypeCode::SzArray);
    optionArray.elementTypeIndex = 0;
    metadata.typeReferences.push_back(optionArray);

    TypeModel api = makeType("Api", "Game.dll", 1);
    FieldModel state;
    state.name = "State";
    state.type = "ButtonState";
    state.flags = 6;
    api.fields.push_back(state);
    FieldModel options = state;
    options.name = "Options";
    options.type = "type[1]";
    api.fields.push_back(options);
    MethodModel getter;
    getter.name = "Get";
    getter.declaringType = "Api";
    getter.imageName = "Game.dll";
    getter.address = 0x1000;
    getter.returnType = "type[1]";
    getter.isStatic = true;
    getter.flags = 6 | 0x10;
    api.methods.push_back(getter);
    metadata.types.push_back(api);

    metadata.types.push_back(makeType("RequestOpenCriticalPassSeasonEndCollected", "Other.dll", 1));
    TypeModel nested = makeType("ErrorType", "Fyber.dll", 2);
    nested.declaringTypeIndex = 5;
    metadata.types.push_back(nested);
    TypeModel response = makeType("ErrorResponse", "Fyber.dll", 1);
    FieldModel error;
    error.name = "Error";
    error.type = "ErrorType";
    error.flags = 6;
    response.fields.push_back(error);
    metadata.types.push_back(response);

    RecoveredFunction function;
    function.address = 0x1000;
    function.name = "Api__Get";
    ProjectWriterOptions writerOptions;
    writerOptions.includedImages = {"Game.dll", "Fyber.dll"};
    writerOptions.includeExternalDeclarations = true;
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/emitted-name-identity");
    ProjectWriter{writerOptions}.write(output.path, metadata, {function});
    const auto apiSource = readFile(output.path / "Api.cs");
    CHECK(apiSource.find("ButtonState_2 State;") != std::string::npos);
    CHECK(apiSource.find("OptionData_2[] Options;") != std::string::npos);
    CHECK(apiSource.find("OptionData_2[] Get()") != std::string::npos);
    const auto responseSource = readFile(output.path / "ErrorResponse.cs");
    CHECK(responseSource.find("global::RequestOpenCriticalPassSeasonEndCollected.ErrorType Error;") != std::string::npos);
}

TEST_CASE("renamed internal types narrow public signatures after identity mapping") {
    MetadataModel metadata;
    TypeModel first;
    first.name = "Mode";
    first.imageName = "UI.dll";
    first.flags = 1;
    metadata.types.push_back(first);
    TypeModel second = first;
    second.imageName = "Game.dll";
    second.flags = 0;
    metadata.types.push_back(second);
    TypeModel api;
    api.name = "Api";
    api.imageName = "Game.dll";
    api.flags = 1;
    FieldModel field;
    field.name = "State";
    field.type = "Mode";
    field.flags = 6;
    api.fields.push_back(field);
    MethodModel method;
    method.name = "Get";
    method.declaringType = "Api";
    method.imageName = "Game.dll";
    method.address = 0x1000;
    method.returnType = "Mode";
    method.isStatic = true;
    method.flags = 6 | 0x10;
    api.methods.push_back(method);
    MethodModel getter = method;
    getter.name = "get_ModeValue";
    getter.address = 0x1004;
    api.methods.push_back(getter);
    api.propertyStart = 0;
    api.propertyCount = 1;
    metadata.types.push_back(api);
    PropertyModel property;
    property.name = "ModeValue";
    property.get = 1;
    metadata.properties.push_back(property);

    RecoveredFunction function;
    function.address = 0x1000;
    function.name = "Api__Get";
    ProjectWriterOptions options;
    options.includedImages = {"Game.dll"};
    options.includeExternalDeclarations = true;
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/renamed-internal-visibility");
    ProjectWriter{options}.write(output.path, metadata, {function});
    const auto source = readFile(output.path / "Api.cs");
    CHECK(source.find("internal Mode_2 State;") != std::string::npos);
    CHECK(source.find("internal static Mode_2 ModeValue") != std::string::npos);
    if (source.find("internal static Mode_2 Get_0x1000()") == std::string::npos) {
        fail("Generated source:\n" + source, __FILE__, __LINE__);
    }
}

TEST_CASE("reference return body uses the planned cross-image type name") {
    MetadataModel metadata;
    TypeModel first;
    first.name = "ButtonState";
    first.imageName = "UI.dll";
    first.flags = 1;
    metadata.types.push_back(first);
    TypeModel second = first;
    second.imageName = "Game.dll";
    metadata.types.push_back(second);
    TypeReferenceModel reference;
    reference.code = static_cast<uint8_t>(Il2CppTypeCode::Class);
    reference.name = "ButtonState";
    reference.definitionIndex = 1;
    metadata.typeReferences.push_back(reference);
    TypeModel api;
    api.name = "Api";
    api.imageName = "Game.dll";
    api.flags = 1;
    MethodModel method;
    method.name = "Echo";
    method.declaringType = "Api";
    method.imageName = "Game.dll";
    method.address = 0x1000;
    method.returnType = "type[0]";
    method.parameters.push_back({"value", "type[0]", -1});
    method.isStatic = true;
    method.flags = 6 | 0x10;
    api.methods.push_back(method);
    metadata.types.push_back(api);
    RecoveredFunction function;
    function.address = 0x1000;
    function.name = "Api__Echo";
    function.architecture = Architecture::Arm64;
    BasicBlock block;
    block.address = 0x1000;
    Statement result;
    result.kind = Statement::Kind::Return;
    result.address = 0x1000;
    result.value = reg("x0", ScalarType::pointer(64));
    block.statements.push_back(result);
    function.blocks.push_back(block);
    ProjectWriterOptions options;
    options.includedImages = {"Game.dll"};
    options.includeExternalDeclarations = true;
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/reference-return-emitted-name");
    const auto report = ProjectWriter{options}.write(output.path, metadata, {function});
    const auto source = readFile(output.path / "Api.cs");
    CHECK(report.partial == 1);
    CHECK(source.find("ButtonState_2 Echo(") != std::string::npos);
    CHECK(source.find("FromNativeReturn<ButtonState_2>") != std::string::npos);
    CHECK(source.find("default(ButtonState_2)") != std::string::npos);
}

TEST_CASE("generic constraint with wrong emitted arity is omitted") {
    MetadataModel metadata;
    TypeModel plain;
    plain.name = "Settings";
    plain.imageName = "Game.dll";
    plain.flags = 1;
    metadata.types.push_back(plain);
    TypeModel holder;
    holder.name = "Settings`1";
    holder.imageName = "Game.dll";
    holder.flags = 1;
    holder.genericContainerIndex = 0;
    metadata.types.push_back(holder);
    metadata.genericContainers.push_back({1, 1, 0, 0});
    metadata.genericParameters.push_back({1, "T", 0, 1, 0, 0});
    metadata.genericParameterConstraints = {0};
    metadata.typeReferences.resize(2);
    metadata.typeReferences[0].code = static_cast<uint8_t>(Il2CppTypeCode::GenericInst);
    metadata.typeReferences[0].name = "Settings";
    metadata.typeReferences[0].definitionIndex = 0;
    metadata.typeReferences[0].genericArgumentIndices = {1};
    metadata.typeReferences[1].code = static_cast<uint8_t>(Il2CppTypeCode::Class);
    metadata.typeReferences[1].name = "T";
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/invalid-emitted-constraint");
    ProjectWriterOptions options;
    options.includedImages = {"Game.dll"};
    options.includeExternalDeclarations = true;
    ProjectWriter{options}.write(output.path, metadata, {});
    const auto source = readFile(output.path / "Settings_2.cs");
    CHECK(source.find("where T : Settings<T>") == std::string::npos);
    if (source.find("generic constraint omitted") == std::string::npos) {
        fail("Generated source:\n" + source, __FILE__, __LINE__);
    }
}

TEST_CASE("full declarations do not bind absent external managed members") {
    MetadataModel metadata;
    metadata.version = 24;
    TypeModel caller;
    caller.name = "Caller";
    caller.imageName = "Game.dll";
    caller.flags = 1;
    MethodModel run;
    run.name = "Run";
    run.declaringType = "Caller";
    run.imageName = "Game.dll";
    run.address = 0x1000;
    run.returnType = "void";
    run.isStatic = true;
    run.flags = 6 | 0x10;
    caller.methods.push_back(run);
    metadata.types.push_back(caller);
    TypeModel external;
    external.name = "Sprite";
    external.nameSpace = "UnityEngine";
    external.imageName = "UnityEngine.CoreModule.dll";
    external.flags = 1;
    MethodModel missing = run;
    missing.name = "Missing";
    missing.declaringType = "UnityEngine.Sprite";
    missing.imageName = external.imageName;
    missing.address = 0x2000;
    missing.definitionIndex = 1;
    external.methods.push_back(missing);
    metadata.types.push_back(external);
    RecoveredFunction function;
    function.name = "Caller__Run";
    function.address = 0x1000;
    function.architecture = Architecture::Arm64;
    BasicBlock block;
    block.address = 0x1000;
    Statement call;
    call.kind = Statement::Kind::Call;
    call.address = 0x1000;
    call.target = constant(0x2000, ScalarType::pointer(64));
    block.statements.push_back(call);
    function.blocks.push_back(block);
    ProjectWriterOptions options;
    options.includedImages = {"Game.dll"};
    options.includeExternalDeclarations = true;
    OutputDirectory output(std::filesystem::path(IL2CPPREC_TEST_SOURCE_DIR).parent_path() /
                           "build/tests/absent-managed-member");
    const auto report = ProjectWriter{options}.write(output.path, metadata, {function});
    const auto source = readFile(output.path / "Caller.cs");
    CHECK(source.find("Sprite.Missing") == std::string::npos);
    CHECK(source.find("Call_0") == std::string::npos);
    CHECK(report.supported == 0);
}

} // namespace il2cpprec::tests
