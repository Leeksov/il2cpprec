#include <il2cpprec/versions/Version24Adjustor.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <utility>

namespace il2cpprec::versions {
namespace {

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 24.4/24.5 data: " + message);
}

uint64_t checkedAdd(uint64_t value, uint64_t amount) {
    if (amount > std::numeric_limits<uint64_t>::max() - value) {
        invalid("virtual address overflow");
    }
    return value + amount;
}

size_t checkedTableSize(uint64_t count, size_t stride) {
    if (count > std::numeric_limits<size_t>::max() ||
        static_cast<size_t>(count) > std::numeric_limits<size_t>::max() / stride) {
        invalid("table size overflow");
    }
    return static_cast<size_t>(count) * stride;
}

class ImageReader {
public:
    ImageReader(const BinaryImage& binary, size_t pointerSize)
        : binary_(binary), pointerSize_(pointerSize) {
        if (!binary.bytes) invalid("binary image has no data");
    }

    uint32_t u32(uint64_t address) const {
        const auto* data = bytes(address, 4);
        return static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << 8) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 24);
    }

    int32_t i32(uint64_t address) const {
        return std::bit_cast<int32_t>(u32(address));
    }

    uint64_t u64(uint64_t address) const {
        const auto* data = bytes(address, 8);
        uint64_t value = 0;
        for (size_t index = 0; index < 8; ++index) {
            value |= static_cast<uint64_t>(data[index]) << (index * 8);
        }
        return value;
    }

    uint64_t pointer(uint64_t address) const {
        return pointerSize_ == 4 ? u32(address) : u64(address);
    }

    uint64_t count(uint64_t address) const {
        return pointer(address);
    }

    void require(uint64_t address, size_t size) const {
        static_cast<void>(bytes(address, size));
    }

    std::vector<uint64_t> pointerTable(uint64_t address, uint64_t count) const {
        const size_t size = checkedTableSize(count, pointerSize_);
        if (size != 0) require(address, size);
        std::vector<uint64_t> result;
        result.reserve(static_cast<size_t>(count));
        for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
            result.push_back(pointer(checkedAdd(address, index * pointerSize_)));
        }
        return result;
    }

    std::string string(uint64_t address) const {
        const size_t offset = fileOffset(address, 1);
        const auto& data = *binary_.bytes;
        constexpr size_t maximumLength = 1024 * 1024;
        const size_t limit = std::min(data.size() - offset, maximumLength + 1);
        size_t length = 0;
        while (length < limit && data[offset + length] != 0) ++length;
        if (length == limit || length > maximumLength) invalid("unterminated code-gen module name");
        return std::string(reinterpret_cast<const char*>(data.data() + offset), length);
    }

private:
    const uint8_t* bytes(uint64_t address, size_t size) const {
        return binary_.data(fileOffset(address, size), size);
    }

    size_t fileOffset(uint64_t address, size_t size) const {
        const auto map = [&](uint64_t candidate, uint64_t& mapped) {
            try {
                mapped = binary_.mapVATR(candidate);
                return true;
            } catch (const std::out_of_range&) {
                return false;
            } catch (const std::overflow_error&) {
                return false;
            }
        };

        uint64_t mapped = 0;
        if (!map(address, mapped)) {
            bool found = false;
            if (address >= binary_.imageBase) {
                found = map(address - binary_.imageBase, mapped);
            }
            if (!found && address <= std::numeric_limits<uint64_t>::max() - binary_.imageBase) {
                found = map(binary_.imageBase + address, mapped);
            }
            if (!found) invalid("virtual address is not backed by a file range");
        }
        if (mapped > std::numeric_limits<size_t>::max()) invalid("file offset exceeds the host size type");
        const size_t offset = static_cast<size_t>(mapped);
        if (!binary_.bytes || offset > binary_.bytes->size() || size > binary_.bytes->size() - offset) {
            invalid("read is outside the binary image");
        }
        return offset;
    }

    const BinaryImage& binary_;
    size_t pointerSize_;
};

Version24NativeTable readTable(const ImageReader& reader, uint64_t address, size_t pointerSize) {
    Version24NativeTable table;
    table.count = reader.count(address);
    table.address = reader.pointer(checkedAdd(address, pointerSize));
    return table;
}

uint64_t selectIndexed(const std::vector<uint64_t>& pointers, int32_t index) noexcept {
    if (index < 0 || static_cast<size_t>(index) >= pointers.size()) return 0;
    return pointers[static_cast<size_t>(index)];
}

uint16_t raw16(const uint8_t* data, size_t offset) {
    return static_cast<uint16_t>(data[offset]) |
        static_cast<uint16_t>(static_cast<uint16_t>(data[offset + 1]) << 8);
}

uint32_t raw32(const uint8_t* data, size_t offset) {
    return static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset + 1]) << 8) |
        (static_cast<uint32_t>(data[offset + 2]) << 16) |
        (static_cast<uint32_t>(data[offset + 3]) << 24);
}

int32_t rawI32(const uint8_t* data, size_t offset) {
    return std::bit_cast<int32_t>(raw32(data, offset));
}

void requireRaw(const uint8_t* data, size_t size, size_t expected) {
    if (data == nullptr || size < expected) {
        throw std::invalid_argument("IL2CPP definition requires at least " + std::to_string(expected) + " bytes");
    }
}

} // namespace

uint64_t Version24Registration::select(
    std::string_view imageName,
    uint32_t methodToken,
    Version24MethodPointerKind kind) const noexcept {
    const auto module = std::find_if(modules.begin(), modules.end(), [&](const auto& candidate) {
        return candidate.first == imageName;
    });
    if (module == modules.end()) return 0;

    if (kind == Version24MethodPointerKind::Adjustor) {
        const auto thunk = module->second.adjustorThunks.find(methodToken);
        return thunk == module->second.adjustorThunks.end() ? 0 : thunk->second;
    }

    if ((methodToken & 0xFF000000U) != 0x06000000U) return 0;
    const uint32_t rowId = methodToken & 0x00FFFFFFU;
    if (rowId == 0) return 0;
    const size_t index = static_cast<size_t>(rowId - 1);
    if (kind == Version24MethodPointerKind::Ordinary) {
        return index < module->second.methodPointers.size() ? module->second.methodPointers[index] : 0;
    }
    if (kind == Version24MethodPointerKind::Invoker) {
        if (index >= module->second.invokerIndices.size()) return 0;
        return selectIndexed(invokerPointers, module->second.invokerIndices[index]);
    }
    return 0;
}

uint64_t Version24Registration::select(
    const Version24GenericMethodFunctionsDefinition& method,
    Version24MethodPointerKind kind) const noexcept {
    switch (kind) {
    case Version24MethodPointerKind::Ordinary:
        return selectIndexed(genericMethodPointers, method.methodIndex);
    case Version24MethodPointerKind::Adjustor:
        return layout.version == 24.5 ? selectIndexed(genericAdjustorThunks, method.adjustorThunkIndex) : 0;
    case Version24MethodPointerKind::Invoker:
        return selectIndexed(invokerPointers, method.invokerIndex);
    }
    return 0;
}

Version24Adjustor::Version24Adjustor(double version, size_t pointerSize)
    : version_(version), pointerSize_(pointerSize) {
    if (!supports(version)) throw std::invalid_argument("Version24Adjustor supports only IL2CPP 24.4 and 24.5");
    if (pointerSize != 0 && pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
}

bool Version24Adjustor::supports(double version) noexcept {
    return version == 24.4 || version == 24.5;
}

size_t Version24Adjustor::pointerSize(const BinaryImage& binary) {
    switch (binary.architecture) {
    case Architecture::X86:
    case Architecture::Arm32:
        return 4;
    case Architecture::X64:
    case Architecture::Arm64:
        return 8;
    }
    throw std::invalid_argument("Unsupported IL2CPP binary architecture");
}

Version24Layout Version24Adjustor::makeLayout(double version, size_t pointerSize) {
    if (!supports(version)) throw std::invalid_argument("Version24Adjustor supports only IL2CPP 24.4 and 24.5");
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }

    Version24Layout layout;
    layout.version = version;
    layout.pointerSize = pointerSize;
    layout.codeRegistrationSize = (version == 24.5 ? 17 : 16) * pointerSize;
    layout.codeGenModuleSize = (version == 24.5 ? 13 : 11) * pointerSize;
    layout.genericMethodRowSize = version == 24.5 ? 16 : 12;
    layout.tokenAdjustorThunkPairSize = 2 * pointerSize;
    layout.genericMethodPointersCountOffset = 2 * pointerSize;
    layout.genericMethodPointersOffset = 3 * pointerSize;
    layout.methodPointerCountOffset = pointerSize;
    layout.methodPointersOffset = 2 * pointerSize;

    if (version == 24.5) {
        layout.genericAdjustorThunksOffset = 4 * pointerSize;
        layout.invokerPointersCountOffset = 5 * pointerSize;
        layout.invokerPointersOffset = 6 * pointerSize;
        layout.codeGenModulesCountOffset = 15 * pointerSize;
        layout.codeGenModulesOffset = 16 * pointerSize;
        layout.adjustorThunkCountOffset = 3 * pointerSize;
        layout.adjustorThunksOffset = 4 * pointerSize;
        layout.invokerIndicesOffset = 5 * pointerSize;
    } else {
        layout.invokerPointersCountOffset = 4 * pointerSize;
        layout.invokerPointersOffset = 5 * pointerSize;
        layout.codeGenModulesCountOffset = 14 * pointerSize;
        layout.codeGenModulesOffset = 15 * pointerSize;
        layout.invokerIndicesOffset = 3 * pointerSize;
    }
    return layout;
}

Version24Layout Version24Adjustor::layout() const {
    return makeLayout(version_, pointerSize_);
}

Version24Registration Version24Adjustor::read(
    const BinaryImage& binary,
    uint64_t codeRegistrationAddress,
    uint64_t genericMethodTableAddress,
    uint64_t genericMethodTableCount) const {
    const auto resolvedLayout = makeLayout(
        version_, pointerSize_ == 0 ? pointerSize(binary) : pointerSize_);
    const size_t nativePointerSize = resolvedLayout.pointerSize;
    ImageReader reader(binary, nativePointerSize);
    reader.require(codeRegistrationAddress, resolvedLayout.codeRegistrationSize);

    Version24Registration result;
    result.layout = resolvedLayout;
    result.codeRegistrationAddress = codeRegistrationAddress;
    result.genericMethodTableAddress = genericMethodTableAddress;

    auto& code = result.codeRegistration;
    code.reversePInvokeWrappers = readTable(reader, codeRegistrationAddress, nativePointerSize);
    code.genericMethodPointers = readTable(
        reader,
        checkedAdd(codeRegistrationAddress, resolvedLayout.genericMethodPointersCountOffset),
        nativePointerSize);
    if (resolvedLayout.genericAdjustorThunksOffset) {
        code.genericAdjustorThunks = reader.pointer(
            checkedAdd(codeRegistrationAddress, *resolvedLayout.genericAdjustorThunksOffset));
    }
    code.invokerPointers = readTable(
        reader,
        checkedAdd(codeRegistrationAddress, resolvedLayout.invokerPointersCountOffset),
        nativePointerSize);
    code.codeGenModules = readTable(
        reader,
        checkedAdd(codeRegistrationAddress, resolvedLayout.codeGenModulesCountOffset),
        nativePointerSize);

    const size_t customOffset = (version_ == 24.5 ? 7 : 6) * nativePointerSize;
    const size_t unresolvedOffset = (version_ == 24.5 ? 9 : 8) * nativePointerSize;
    const size_t interopOffset = (version_ == 24.5 ? 11 : 10) * nativePointerSize;
    const size_t windowsOffset = (version_ == 24.5 ? 13 : 12) * nativePointerSize;
    code.customAttributeGenerators = readTable(
        reader, checkedAdd(codeRegistrationAddress, customOffset), nativePointerSize);
    code.unresolvedVirtualCallPointers = readTable(
        reader, checkedAdd(codeRegistrationAddress, unresolvedOffset), nativePointerSize);
    code.interopData = readTable(
        reader, checkedAdd(codeRegistrationAddress, interopOffset), nativePointerSize);
    code.windowsRuntimeFactoryTable = readTable(
        reader, checkedAdd(codeRegistrationAddress, windowsOffset), nativePointerSize);

    result.genericMethodPointers = reader.pointerTable(
        code.genericMethodPointers.address, code.genericMethodPointers.count);
    result.invokerPointers = reader.pointerTable(code.invokerPointers.address, code.invokerPointers.count);
    if (version_ == 24.5) {
        result.genericAdjustorThunks = reader.pointerTable(
            code.genericAdjustorThunks, code.genericMethodPointers.count);
    }

    const auto modulePointers = reader.pointerTable(code.codeGenModules.address, code.codeGenModules.count);
    for (const uint64_t moduleAddress : modulePointers) {
        reader.require(moduleAddress, resolvedLayout.codeGenModuleSize);
        Version24AdjustorCodeGenModule module;
        module.address = moduleAddress;
        module.name = reader.string(reader.pointer(moduleAddress));
        const uint64_t methodCount = reader.count(
            checkedAdd(moduleAddress, resolvedLayout.methodPointerCountOffset));
        module.methodPointers = reader.pointerTable(
            reader.pointer(checkedAdd(moduleAddress, resolvedLayout.methodPointersOffset)), methodCount);

        const uint64_t invokerIndicesAddress = reader.pointer(
            checkedAdd(moduleAddress, resolvedLayout.invokerIndicesOffset));
        const size_t invokerIndicesSize = checkedTableSize(methodCount, sizeof(int32_t));
        if (invokerIndicesSize != 0) reader.require(invokerIndicesAddress, invokerIndicesSize);
        module.invokerIndices.reserve(static_cast<size_t>(methodCount));
        for (size_t index = 0; index < static_cast<size_t>(methodCount); ++index) {
            module.invokerIndices.push_back(reader.i32(
                checkedAdd(invokerIndicesAddress, index * sizeof(int32_t))));
        }

        if (resolvedLayout.adjustorThunkCountOffset) {
            const uint64_t adjustorCount = reader.count(
                checkedAdd(moduleAddress, *resolvedLayout.adjustorThunkCountOffset));
            const uint64_t adjustorAddress = reader.pointer(
                checkedAdd(moduleAddress, *resolvedLayout.adjustorThunksOffset));
            const size_t adjustorSize = checkedTableSize(
                adjustorCount, resolvedLayout.tokenAdjustorThunkPairSize);
            if (adjustorSize != 0) reader.require(adjustorAddress, adjustorSize);
            module.adjustorThunks.reserve(static_cast<size_t>(adjustorCount));
            for (size_t index = 0; index < static_cast<size_t>(adjustorCount); ++index) {
                const uint64_t pair = checkedAdd(
                    adjustorAddress, index * resolvedLayout.tokenAdjustorThunkPairSize);
                const uint32_t token = reader.u32(pair);
                const uint64_t thunk = reader.pointer(checkedAdd(pair, nativePointerSize));
                module.adjustorThunks.insert_or_assign(token, thunk);
            }
        }

        const auto [position, inserted] = result.modules.emplace(module.name, std::move(module));
        if (!inserted) invalid("duplicate code-gen module name: " + position->first);
    }

    const size_t genericTableSize = checkedTableSize(
        genericMethodTableCount, resolvedLayout.genericMethodRowSize);
    if (genericTableSize != 0) reader.require(genericMethodTableAddress, genericTableSize);
    result.genericMethodTable.reserve(static_cast<size_t>(genericMethodTableCount));
    for (size_t index = 0; index < static_cast<size_t>(genericMethodTableCount); ++index) {
        const uint64_t row = checkedAdd(
            genericMethodTableAddress, index * resolvedLayout.genericMethodRowSize);
        Version24GenericMethodFunctionsDefinition method;
        method.genericMethodIndex = reader.i32(row);
        method.methodIndex = reader.i32(checkedAdd(row, 4));
        method.invokerIndex = reader.i32(checkedAdd(row, 8));
        if (version_ == 24.5) method.adjustorThunkIndex = reader.i32(checkedAdd(row, 12));
        method.methodPointer = result.select(method, Version24MethodPointerKind::Ordinary);
        method.invokerPointer = result.select(method, Version24MethodPointerKind::Invoker);
        method.adjustorThunk = result.select(method, Version24MethodPointerKind::Adjustor);
        result.genericMethodTable.push_back(method);
    }
    return result;
}

Version24AssemblyDefinition Version24Adjustor::readAssemblyDefinition(const uint8_t* data, size_t size) {
    requireRaw(data, size, sizeof(Version24AssemblyDefinition));
    Version24AssemblyDefinition assembly;
    assembly.imageIndex = rawI32(data, 0);
    assembly.token = raw32(data, 4);
    assembly.referencedAssemblyStart = rawI32(data, 8);
    assembly.referencedAssemblyCount = rawI32(data, 12);
    assembly.nameIndex = raw32(data, 16);
    assembly.cultureIndex = raw32(data, 20);
    assembly.publicKeyIndex = raw32(data, 24);
    assembly.hashAlgorithm = raw32(data, 28);
    assembly.hashLength = rawI32(data, 32);
    assembly.flags = raw32(data, 36);
    assembly.major = rawI32(data, 40);
    assembly.minor = rawI32(data, 44);
    assembly.build = rawI32(data, 48);
    assembly.revision = rawI32(data, 52);
    for (size_t index = 0; index < 8; ++index) assembly.publicKeyToken[index] = data[56 + index];
    return assembly;
}

Version24TypeDefinition Version24Adjustor::readTypeDefinition(const uint8_t* data, size_t size) {
    requireRaw(data, size, sizeof(Version24TypeDefinition));
    Version24TypeDefinition type;
    type.nameIndex = raw32(data, 0);
    type.namespaceIndex = raw32(data, 4);
    type.byvalTypeIndex = rawI32(data, 8);
    type.byrefTypeIndex = rawI32(data, 12);
    type.declaringTypeIndex = rawI32(data, 16);
    type.parentIndex = rawI32(data, 20);
    type.elementTypeIndex = rawI32(data, 24);
    type.genericContainerIndex = rawI32(data, 28);
    type.flags = raw32(data, 32);
    type.fieldStart = rawI32(data, 36);
    type.methodStart = rawI32(data, 40);
    type.eventStart = rawI32(data, 44);
    type.propertyStart = rawI32(data, 48);
    type.nestedTypesStart = rawI32(data, 52);
    type.interfacesStart = rawI32(data, 56);
    type.vtableStart = rawI32(data, 60);
    type.interfaceOffsetsStart = rawI32(data, 64);
    type.methodCount = raw16(data, 68);
    type.propertyCount = raw16(data, 70);
    type.fieldCount = raw16(data, 72);
    type.eventCount = raw16(data, 74);
    type.nestedTypeCount = raw16(data, 76);
    type.vtableCount = raw16(data, 78);
    type.interfacesCount = raw16(data, 80);
    type.interfaceOffsetsCount = raw16(data, 82);
    type.bitfield = raw32(data, 84);
    type.token = raw32(data, 88);
    return type;
}

} // namespace il2cpprec::versions
