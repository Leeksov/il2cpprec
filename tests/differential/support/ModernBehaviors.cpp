#include <il2cpprec/ida/SourceProfile.hpp>
#include <il2cpprec/metadata/CodeGenModules.hpp>
#include <il2cpprec/metadata/GenericMethodResolver.hpp>
#include <il2cpprec/metadata/GlobalMetadata.hpp>
#include <il2cpprec/metadata/TypeSystem.hpp>

#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace il2cpprec;

constexpr uint64_t imageBase = 0x10000000;
constexpr size_t noField = std::numeric_limits<size_t>::max();
int passed = 0;
int partial = 0;
int provisional = 0;
int failed = 0;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void exact(const std::string& name, const std::function<void()>& test) {
    try {
        std::cout << "RUN " << name << '\n';
        test();
        ++passed;
        std::cout << "PASS exact " << name << '\n';
    } catch (const std::exception& error) {
        ++failed;
        std::cout << "FAIL " << name << ": " << error.what() << '\n';
    }
}

void expectedPartial(const std::string& name, const std::function<std::string()>& test) {
    try {
        const auto detail = test();
        ++partial;
        std::cout << "PARTIAL " << name << ": " << detail << '\n';
    } catch (const std::exception& error) {
        ++failed;
        std::cout << "FAIL " << name << ": " << error.what() << '\n';
    }
}

void provisionalCase(const std::string& name, const std::string& reason) {
    ++provisional;
    std::cout << "PROVISIONAL " << name << ": " << reason << '\n';
}

struct Version {
    double value;
    const char* label;
};

const Version versions[] = {
    {24.0, "24.0"}, {24.1, "24.1"}, {24.2, "24.2"}, {24.3, "24.3"}, {24.4, "24.4"}, {24.5, "24.5"},
    {27.0, "27.0"}, {27.1, "27.1"}, {27.2, "27.2"}, {29.0, "29.0"}, {29.1, "29.1"}, {31.0, "31"},
    {33.0, "33"}, {35.0, "35"}, {38.0, "38"}, {104.0, "104"}, {105.0, "105"}, {106.0, "106"},
    {107.0, "107"}, {108.0, "108"}, {109.0, "109"}, {110.0, "110"}, {111.0, "111"},
};

void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    for (size_t index = 0; index < 4; ++index) bytes[offset + index] = static_cast<uint8_t>(value >> (index * 8));
}

void put64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    for (size_t index = 0; index < 8; ++index) bytes[offset + index] = static_cast<uint8_t>(value >> (index * 8));
}

struct Layout {
    size_t registrationModules;
    size_t registrationSlots;
    std::vector<size_t> countTables;
    size_t globalMethods;
    size_t moduleSlots;
    size_t adjustor;
    size_t invoker;
    size_t reverse;
    size_t rgctxRanges;
    size_t rgctxs;
    size_t rgctxEntrySize;
    size_t metadataRegistration;
    size_t codeRegistration;
};

Layout module24(size_t registrationModules, size_t registrationSlots, std::vector<size_t> tables) {
    return {registrationModules, registrationSlots, std::move(tables), 0, 11, noField, 3, 4, 6, 8, 8, noField, noField};
}

Layout module24_5() {
    return {23, 25, {0, 2, 4, 6, 8, 10, 13, 15, 17, 19, 21}, 0, 13, 3, 5, 6, 8, 10, 8, noField, noField};
}

Layout module27_0() {
    return {12, 14, {0, 2, 4, 6, 8, 10}, noField, 16, noField, 3, 4, 6, 8, 8, 14, 15};
}

Layout module27_1(bool second) {
    return {13, 15, {0, 2, 5, 7, 9, 11}, noField, 18, 3, 5, 6, 8, 10, second ? size_t{16} : size_t{8}, 16, 17};
}

Layout module29(size_t registrationModules, std::vector<size_t> tables) {
    return {registrationModules, 17, std::move(tables), noField, 17, 3, 5, 6, 8, 10, 16, 15, 16};
}

Layout module108() {
    return {15, 17, {0, 2, 5, 7, 11, 13}, noField, 11, 3, noField, 5, noField, noField, 0, 9, 10};
}

Layout layoutFor(double version) {
    if (version == 24.2) return module24(20, 22, {0, 2, 4, 6, 8, 10, 12, 14, 16, 18});
    if (version == 24.3 || version == 24.4) return module24(22, 24, {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20});
    if (version == 24.5) return module24_5();
    if (version == 27.0) return module27_0();
    if (version == 27.1) return module27_1(false);
    if (version == 27.2) return module27_1(true);
    if (version == 29.0) {
        auto layout = module29(13, {0, 2, 5, 7, 9, 11});
        layout.registrationSlots = 15;
        return layout;
    }
    if (version == 29.1 || version == 31.0) return module29(15, {0, 2, 5, 7, 11, 13});
    if (version >= 33.0 && version < 35.0) {
        auto layout = module29(12, {0, 2, 5, 8, 10});
        layout.registrationSlots = 14;
        return layout;
    }
    if (version >= 35.0 && version < 108.0) return module29(15, {0, 2, 5, 7, 11, 13});
    if (version >= 108.0) return module108();
    throw std::runtime_error("no modern layout for version");
}

void table(std::vector<uint8_t>& bytes, size_t offset, uint32_t count, uint64_t pointer) {
    put32(bytes, offset, count);
    put64(bytes, offset + 8, pointer);
}

BinaryImage registrationFixture(double version) {
    const auto layout = layoutFor(version);
    BinaryImage binary;
    binary.architecture = Architecture::X64;
    binary.format = BinaryFormat::ELF;
    binary.imageBase = imageBase;
    binary.bytes = std::make_shared<std::vector<uint8_t>>(0x1800, 0);
    binary.sections.push_back({".text", 0, binary.bytes->size(), 0, binary.bytes->size(), true});
    auto& bytes = *binary.bytes;
    constexpr size_t registration = 0x100;
    constexpr size_t module = 0x800;
    constexpr size_t methodTable = 0x900;
    constexpr size_t modulesTable = 0x600;
    constexpr size_t payload = 0xA00;
    put64(bytes, methodTable, imageBase + 0x1200);
    put64(bytes, modulesTable, imageBase + module);

    for (const auto slot : layout.countTables) {
        const bool global = slot == layout.globalMethods;
        table(bytes, registration + slot * 8, global || slot == *layout.countTables.begin() ? 1 : 0,
              global || slot == *layout.countTables.begin() ? imageBase + methodTable : 0);
    }
    const auto second = std::find_if(layout.countTables.begin(), layout.countTables.end(), [&](size_t slot) {
        return slot != layout.globalMethods && slot != layout.registrationModules;
    });
    require(second != layout.countTables.end(), "layout has no secondary table");
    table(bytes, registration + *second * 8, 1, imageBase + payload);
    table(bytes, registration + layout.registrationModules * 8, 1, imageBase + modulesTable);

    put64(bytes, module, imageBase + 0x1000);
    put32(bytes, module + 8, 1);
    put64(bytes, module + 16, imageBase + methodTable);
    if (layout.adjustor != noField) table(bytes, module + layout.adjustor * 8, 1, imageBase + payload);
    if (layout.invoker != noField) put64(bytes, module + layout.invoker * 8, imageBase + payload);
    table(bytes, module + layout.reverse * 8, 0, 0);
    if (layout.rgctxRanges != noField) table(bytes, module + layout.rgctxRanges * 8, 0, 0);
    if (layout.rgctxs != noField) table(bytes, module + layout.rgctxs * 8, 0, 0);
    if (layout.metadataRegistration != noField) {
        put64(bytes, module + layout.metadataRegistration * 8, imageBase + 0x180);
        put64(bytes, module + layout.codeRegistration * 8, imageBase + registration);
    }
    const std::string name = "Assembly-CSharp.dll";
    std::memcpy(bytes.data() + 0x1000, name.c_str(), name.size() + 1);
    return binary;
}

MetadataModel genericMetadata(double version) {
    MetadataModel metadata;
    metadata.version = version;
    TypeModel type;
    type.nameSpace = "Modern";
    type.name = "GenericTarget";
    MethodModel method;
    method.name = "Identity";
    method.definitionIndex = 0;
    method.returnType = "int";
    method.isStatic = true;
    type.methods.push_back(method);
    metadata.types.push_back(type);
    metadata.methodSpecs.push_back({0, -1, -1, 0, 0});
    GenericMethodPointerModel mapping;
    mapping.genericMethodIndex = 0;
    mapping.methodIndex = 0;
    mapping.invokerIndex = 0;
    mapping.methodPointer = 0x5000;
    mapping.invokerPointer = 0x6000;
    mapping.adjustorThunkIndex = 0;
    mapping.adjustorThunk = 0x7000;
    metadata.genericMethodTable.push_back(mapping);
    return metadata;
}

size_t headerSize(int version) {
    size_t size = 168;
    if (version <= 24) size += 8;
    size += 16;
    if (version >= 19 && version <= 24) size += 16;
    if (version >= 19) size += 8;
    if (version >= 20) size += 8;
    if (version >= 21 && version <= 27) size += 16;
    if (version >= 29) size += 16;
    if (version >= 22) size += 16;
    if (version >= 23) size += 8;
    if (version >= 27) size += 8;
    if (version >= 24) size += 8;
    return size;
}

std::vector<uint8_t> headerFixture(int version) {
    std::vector<uint8_t> bytes(headerSize(version), 0);
    put32(bytes, 0, 0xFAB11BAF);
    put32(bytes, 4, static_cast<uint32_t>(version));
    put32(bytes, 8, static_cast<uint32_t>(bytes.size()));
    return bytes;
}

} // namespace

int main(int argc, char** argv) {
    std::cout.setf(std::ios::unitbuf);
    if (argc == 2 && std::string(argv[1]) == "--runtime-oracle") {
        const float left = 3.0F;
        const float right = 4.0F;
        const float result = left + right;
        uint32_t bits = 0;
        std::memcpy(&bits, &result, sizeof(bits));
        const uint64_t low = 0x402000003FA00000ULL;
        const uint64_t high = 0x40800000C0700000ULL;
        std::cout << std::hex << "float_result=0x" << bits << "\nvector_low=0x" << low
                  << "\nvector_high=0x" << high << "\nvector_equal=0x1\n";
        return 0;
    }
    if (argc != 1) {
        std::cerr << "usage: ModernBehaviors [--runtime-oracle]\n";
        return 2;
    }

    for (const auto& version : versions) {
        const std::string prefix = version.label;
        if (version.value <= 24.1) {
            exact(prefix + "/SourceLayout", [&] {
                const auto selection = ida::metadata24BaseProfile().resolve(version.value, 8);
                require(selection.supported, "legacy source layout was not selected");
                require(selection.methodInfo.customAttributeIndex.present, "legacy customAttributeIndex is absent");
                require(selection.object.klass.offset == 0 && selection.array.length.offset == 24,
                    "legacy managed layout changed");
            });
        } else {
            exact(prefix + "/CodeGenLayout", [&] {
                auto binary = registrationFixture(version.value);
                MetadataModel metadata;
                metadata.version = version.value;
                discoverCodeGenModules(binary, metadata);
                const auto& pointers = metadata.methodPointersByImage.at("Assembly-CSharp.dll");
                require(pointers.size() == 1 && pointers[0] == imageBase + 0x1200,
                    "module method pointer was not recovered");
                require(metadata.codeRegistrationAddress == imageBase + 0x100,
                    "code registration back-pointer was not recovered");
                if (version.value >= 27.0) {
                    require(metadata.metadataRegistrationAddress == imageBase + 0x180,
                        "metadata registration back-pointer was not recovered");
                }
            });
        }

        exact(prefix + "/GenericResolved", [&] {
            const auto metadata = genericMetadata(version.value);
            const auto resolved = GenericMethodResolver(metadata).resolve(0);
            require(resolved.status == MetadataUsageStatus::Resolved, resolved.diagnostic);
            require(resolved.mapping && resolved.mapping->methodPointer == 0x5000, "wrong generic method pointer");
            require(resolved.method && resolved.method->name == "Identity", "wrong generic method definition");
        });
        exact(prefix + "/AdjustorMappingPreserved", [&] {
            const auto metadata = genericMetadata(version.value);
            const auto resolved = GenericMethodResolver(metadata).resolve(0);
            require(resolved.mapping && resolved.mapping->adjustorThunk == 0x7000,
                "adjustor thunk address was not preserved");
        });
        expectedPartial(prefix + "/GenericUnresolved", [&] {
            const auto metadata = genericMetadata(version.value);
            const auto unresolved = GenericMethodResolver(metadata).resolve(99);
            require(unresolved.status == MetadataUsageStatus::Unresolved, "missing generic method became exact");
            require(!unresolved.diagnostic.empty(), "missing generic diagnostic");
            return unresolved.diagnostic;
        });
        exact(prefix + "/MethodSignatureLegacy", [&] {
            MethodModel method;
            method.name = "Generated";
            method.returnType = "float";
            method.isStatic = true;
            method.parameters = {{"value", "int", -1}, {"text", "string", -1}};
            const auto signature = TypeSystem::methodSignature(method);
            require(signature == "public static float Generated(int value, string text)",
                "wrong legacy method signature: " + signature);
        });
        provisionalCase(prefix + "/GeneratedMethods",
            "generatedMethodTypeInfos/generatedMethodTokens have no production resolver or emitter consumer");
        provisionalCase(prefix + "/MethodSignatureTable",
            "MethodModel.signatureOffset and MetadataModel.methodSignatures are not consumed by TypeSystem.methodSignature");
    }

    for (const int version : {24, 27, 29, 31}) {
        exact("MetadataHeader" + std::to_string(version), [&] {
            const auto metadata = GlobalMetadata{}.read(headerFixture(version));
            require(metadata.version == static_cast<double>(version), "wrong parsed metadata version");
        });
    }
    for (const auto& version : versions) {
        if (version.value <= 31.0) continue;
        expectedPartial(std::string(version.label) + "/MetadataHeaderUnsupported", [&] {
            try {
                static_cast<void>(GlobalMetadata{}.read(headerFixture(static_cast<int>(version.value))));
            } catch (const std::exception& error) {
                require(std::string(error.what()).find("Unsupported global metadata version") != std::string::npos,
                    "unexpected header parser failure");
                return std::string(error.what());
            }
            throw std::runtime_error("unsupported metadata header was accepted");
        });
    }

    std::cout << "MODERN_NATIVE SUMMARY passed=" << passed << " partial=" << partial
              << " provisional=" << provisional << " failed=" << failed << '\n';
    return failed == 0 ? 0 : 1;
}
