#include <il2cpprec/metadata/MetadataRegistration.hpp>

#include <il2cpprec/metadata/TypeSystem.hpp>

#include <algorithm>
#include <charconv>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace il2cpprec {
namespace {

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP metadata registration: " + message);
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
        if (pointerSize != 4 && pointerSize != 8) {
            throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
        }
        if (!binary.bytes) invalid("binary image has no data");
    }

    size_t pointerSize() const { return pointerSize_; }

    uint8_t u8(uint64_t address) const {
        return *bytes(address, 1);
    }

    uint16_t u16(uint64_t address) const {
        const auto* data = bytes(address, 2);
        return static_cast<uint16_t>(data[0]) |
            static_cast<uint16_t>(static_cast<uint16_t>(data[1]) << 8);
    }

    uint32_t u32(uint64_t address) const {
        const auto* data = bytes(address, 4);
        return static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << 8) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 24);
    }

    int32_t i32(uint64_t address) const {
        return static_cast<int32_t>(u32(address));
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

    void require(uint64_t address, size_t size) const {
        bytes(address, size);
    }

private:
    const uint8_t* bytes(uint64_t address, size_t size) const {
        if (address < binary_.imageBase) invalid("virtual address is below the image base");
        uint64_t fileOffset = 0;
        try {
            fileOffset = binary_.mapVATR(address - binary_.imageBase);
        } catch (const std::out_of_range&) {
            fileOffset = binary_.mapVATR(address);
        } catch (const std::overflow_error&) {
            fileOffset = binary_.mapVATR(address);
        }
        const auto& data = *binary_.bytes;
        if (fileOffset > data.size() || size > data.size() - static_cast<size_t>(fileOffset)) {
            invalid("read is outside the binary image");
        }
        return data.data() + static_cast<size_t>(fileOffset);
    }

    const BinaryImage& binary_;
    size_t pointerSize_;
};

std::string qualifiedName(const TypeModel& type) {
    if (type.nameSpace.empty()) return type.name;
    if (type.name.empty()) return type.nameSpace;
    return type.nameSpace + "." + type.name;
}

class TypeTableReader {
public:
    TypeTableReader(
        const ImageReader& reader,
        uint64_t typesAddress,
        uint64_t typesCount,
        const std::vector<TypeModel>& definitions)
        : reader_(reader), definitions_(definitions), addresses_(reader.pointerTable(typesAddress, typesCount)) {
        if (typesCount > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
            invalid("too many type references");
        }
        references_.resize(addresses_.size());
        state_.resize(addresses_.size());
        for (size_t index = 0; index < addresses_.size(); ++index) {
            if (addresses_[index] != 0) indices_.try_emplace(addresses_[index], index);
        }
    }

    std::vector<TypeReferenceModel> read() {
        for (size_t index = 0; index < addresses_.size(); ++index) {
            const uint64_t address = addresses_[index];
            if (address == 0) {
                state_[index] = State::Complete;
                continue;
            }
            const auto existing = indices_.find(address);
            if (existing != indices_.end() && existing->second != index) {
                readFixed(existing->second, address);
                references_[index] = references_[existing->second];
                state_[index] = State::Complete;
            } else {
                readFixed(index, address);
            }
        }
        return std::move(references_);
    }

private:
    enum class State {
        Unread,
        Reading,
        Complete
    };

    int32_t readPointer(uint64_t address) {
        if (address == 0) return -1;
        auto [position, inserted] = indices_.try_emplace(address, references_.size());
        if (inserted) {
            if (references_.size() >= static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
                invalid("too many nested type references");
            }
            references_.emplace_back();
            state_.push_back(State::Unread);
        }
        readFixed(position->second, address);
        return static_cast<int32_t>(position->second);
    }

    void readFixed(size_t index, uint64_t address) {
        if (state_[index] == State::Complete || state_[index] == State::Reading) return;
        state_[index] = State::Reading;
        TypeReferenceModel reference;
        readType(address, reference);
        references_[index] = std::move(reference);
        state_[index] = State::Complete;
    }

    void setDefinition(TypeReferenceModel& reference, int32_t definitionIndex) const {
        reference.definitionIndex = definitionIndex;
        if (definitionIndex >= 0 && static_cast<size_t>(definitionIndex) < definitions_.size()) {
            reference.name = qualifiedName(definitions_[static_cast<size_t>(definitionIndex)]);
        }
    }

    void readType(uint64_t address, TypeReferenceModel& reference) {
        const size_t pointerSize = reader_.pointerSize();
        reader_.require(address, pointerSize * 2);
        reference.attrs = reader_.u16(checkedAdd(address, pointerSize));
        reference.code = reader_.u8(checkedAdd(address, pointerSize + 2));
        const uint8_t flags = reader_.u8(checkedAdd(address, pointerSize + 3));
        reference.byRef = (flags & 0x40) != 0;

        const auto code = static_cast<Il2CppTypeCode>(reference.code);
        if (auto primitive = TypeSystem::primitiveType(code)) reference.name = std::move(*primitive);

        switch (code) {
        case Il2CppTypeCode::ValueType:
        case Il2CppTypeCode::Class:
        case Il2CppTypeCode::Enum:
            setDefinition(reference, reader_.i32(address));
            break;
        case Il2CppTypeCode::Ptr:
        case Il2CppTypeCode::ByRef:
        case Il2CppTypeCode::SzArray:
        case Il2CppTypeCode::CModReqD:
        case Il2CppTypeCode::CModOpt:
        case Il2CppTypeCode::Sentinel:
        case Il2CppTypeCode::Pinned:
            reference.elementTypeIndex = readPointer(reader_.pointer(address));
            if (code == Il2CppTypeCode::ByRef) reference.byRef = true;
            if (code == Il2CppTypeCode::SzArray) reference.rank = 1;
            break;
        case Il2CppTypeCode::Array: {
            const uint64_t array = reader_.pointer(address);
            if (array != 0) {
                reference.elementTypeIndex = readPointer(reader_.pointer(array));
                reference.rank = reader_.u8(checkedAdd(array, pointerSize));
            }
            break;
        }
        case Il2CppTypeCode::GenericInst: {
            const uint64_t genericClass = reader_.pointer(address);
            if (genericClass == 0) break;
            setDefinition(reference, reader_.i32(genericClass));
            const uint64_t genericInst = reader_.pointer(checkedAdd(genericClass, pointerSize));
            if (genericInst == 0) break;
            const uint32_t count = reader_.u32(genericInst);
            const uint64_t arguments = reader_.pointer(checkedAdd(genericInst, pointerSize));
            const auto argumentPointers = reader_.pointerTable(arguments, count);
            reference.genericArgumentIndices.reserve(argumentPointers.size());
            for (const uint64_t argument : argumentPointers) {
                reference.genericArgumentIndices.push_back(readPointer(argument));
            }
            break;
        }
        case Il2CppTypeCode::Var:
            reference.name = "!" + std::to_string(reader_.i32(address));
            break;
        case Il2CppTypeCode::MVar:
            reference.name = "!!" + std::to_string(reader_.i32(address));
            break;
        default:
            break;
        }
    }

    const ImageReader& reader_;
    const std::vector<TypeModel>& definitions_;
    std::vector<uint64_t> addresses_;
    std::vector<TypeReferenceModel> references_;
    std::vector<State> state_;
    std::unordered_map<uint64_t, size_t> indices_;
};

size_t inferredPointerSize(const BinaryImage& binary, size_t requested) {
    if (requested != 0) return requested;
    switch (binary.architecture) {
    case Architecture::Arm32:
    case Architecture::X86:
        return 4;
    case Architecture::Arm64:
    case Architecture::X64:
        return 8;
    }
    throw std::invalid_argument("Unsupported IL2CPP binary architecture");
}

// Unity 2017.4.11f1 stores method specs and generic method mappings as three int32 indices.
void readGenericTables(
    const BinaryImage& binary,
    MetadataModel& metadata,
    const MetadataRegistrationInfo& registration,
    size_t pointerSize) {
    ImageReader reader(binary, pointerSize);

    const auto methodPointers = reader.pointerTable(registration.methodPointersAddress, registration.methodPointersCount);
    if (!methodPointers.empty()) {
        for (auto& [name, pointers] : metadata.methodPointersByImage) {
            if (pointers.empty()) pointers = methodPointers;
        }
    }

    std::vector<GenericInstModel> genericInsts;
    const auto instPointers = reader.pointerTable(registration.genericInstsAddress, registration.genericInstsCount);
    genericInsts.reserve(instPointers.size());
    for (const uint64_t address : instPointers) {
        GenericInstModel inst;
        inst.address = address;
        if (address != 0) {
            reader.require(address, pointerSize * 2);
            const uint32_t count = reader.u32(address);
            const uint64_t arguments = reader.pointer(checkedAdd(address, pointerSize));
            inst.typeAddresses = reader.pointerTable(arguments, count);
        }
        genericInsts.push_back(std::move(inst));
    }

    std::vector<GenericClassModel> genericClasses;
    const auto classPointers = reader.pointerTable(registration.genericClassesAddress, registration.genericClassesCount);
    genericClasses.reserve(classPointers.size());
    for (const uint64_t address : classPointers) {
        GenericClassModel genericClass;
        genericClass.address = address;
        if (address != 0) {
            reader.require(address, pointerSize * 4);
            genericClass.definitionIndex = reader.i32(address);
            if (genericClass.definitionIndex < -1 ||
                (genericClass.definitionIndex >= 0 &&
                 static_cast<size_t>(genericClass.definitionIndex) >= metadata.types.size())) {
                invalid("generic class definition index is outside the type table");
            }
            genericClass.classInstAddress = reader.pointer(checkedAdd(address, pointerSize));
            genericClass.methodInstAddress = reader.pointer(checkedAdd(address, pointerSize * 2));
            genericClass.cachedClassAddress = reader.pointer(checkedAdd(address, pointerSize * 3));
        }
        genericClasses.push_back(genericClass);
    }

    size_t methodDefinitionCount = 0;
    for (const auto& type : metadata.types) {
        if (type.methods.size() > std::numeric_limits<size_t>::max() - methodDefinitionCount) {
            invalid("method definition count overflow");
        }
        methodDefinitionCount += type.methods.size();
    }

    std::vector<GenericMethodSpecModel> methodSpecs;
    const size_t specsSize = checkedTableSize(registration.methodSpecsCount, 12);
    if (specsSize != 0) reader.require(registration.methodSpecsAddress, specsSize);
    methodSpecs.reserve(static_cast<size_t>(registration.methodSpecsCount));
    for (size_t index = 0; index < static_cast<size_t>(registration.methodSpecsCount); ++index) {
        const uint64_t address = checkedAdd(registration.methodSpecsAddress, index * 12);
        GenericMethodSpecModel spec;
        spec.methodDefinitionIndex = reader.i32(address);
        spec.classInstIndex = reader.i32(checkedAdd(address, 4));
        spec.methodInstIndex = reader.i32(checkedAdd(address, 8));
        if (spec.methodDefinitionIndex < 0 ||
            static_cast<size_t>(spec.methodDefinitionIndex) >= methodDefinitionCount) {
            invalid("generic method spec definition index is outside the method table");
        }
        const auto instAddress = [&](int32_t instIndex) {
            if (instIndex == -1) return uint64_t{0};
            if (instIndex < -1 || static_cast<size_t>(instIndex) >= genericInsts.size()) {
                invalid("generic method spec instantiation index is outside the generic inst table");
            }
            return genericInsts[static_cast<size_t>(instIndex)].address;
        };
        spec.classInstAddress = instAddress(spec.classInstIndex);
        spec.methodInstAddress = instAddress(spec.methodInstIndex);
        methodSpecs.push_back(spec);
    }

    auto genericMethodPointers = reader.pointerTable(
        registration.genericMethodPointersAddress,
        registration.genericMethodPointersCount);
    auto invokerPointers = reader.pointerTable(
        registration.invokerPointersAddress,
        registration.invokerPointersCount);
    auto unresolvedVirtualCallPointers = reader.pointerTable(
        registration.unresolvedVirtualCallPointersAddress,
        registration.unresolvedVirtualCallPointersCount);
    std::vector<AdjustorThunkModel> adjustorThunks;
    const size_t adjustorSize = checkedTableSize(registration.adjustorThunksCount, pointerSize * 2);
    if (adjustorSize != 0) reader.require(registration.adjustorThunksAddress, adjustorSize);
    adjustorThunks.reserve(static_cast<size_t>(registration.adjustorThunksCount));
    for (size_t index = 0; index < static_cast<size_t>(registration.adjustorThunksCount); ++index) {
        const uint64_t address = checkedAdd(registration.adjustorThunksAddress, index * pointerSize * 2);
        adjustorThunks.push_back({reader.u32(address), reader.pointer(checkedAdd(address, pointerSize))});
    }

    const size_t entrySize = registration.genericMethodTableEntrySize == 0
        ? 12
        : registration.genericMethodTableEntrySize;
    if (entrySize != 12 && entrySize != 16) invalid("unsupported generic method table entry size");
    std::vector<GenericMethodPointerModel> genericMethodTable;
    const size_t genericTableSize = checkedTableSize(registration.genericMethodTableCount, entrySize);
    if (genericTableSize != 0) reader.require(registration.genericMethodTableAddress, genericTableSize);
    genericMethodTable.reserve(static_cast<size_t>(registration.genericMethodTableCount));
    for (size_t index = 0; index < static_cast<size_t>(registration.genericMethodTableCount); ++index) {
        const uint64_t address = checkedAdd(registration.genericMethodTableAddress, index * entrySize);
        GenericMethodPointerModel mapping;
        mapping.genericMethodIndex = reader.i32(address);
        mapping.methodIndex = reader.i32(checkedAdd(address, 4));
        mapping.invokerIndex = reader.i32(checkedAdd(address, 8));
        if (mapping.genericMethodIndex < 0 ||
            static_cast<size_t>(mapping.genericMethodIndex) >= methodSpecs.size()) {
            invalid("generic method table index is outside the method spec table");
        }
        const auto pointerAt = [](const std::vector<uint64_t>& pointers, int32_t pointerIndex, const char* message) {
            if (pointerIndex == -1) return uint64_t{0};
            if (pointerIndex < -1 || static_cast<size_t>(pointerIndex) >= pointers.size()) invalid(message);
            return pointers[static_cast<size_t>(pointerIndex)];
        };
        mapping.methodPointer = pointerAt(
            genericMethodPointers,
            mapping.methodIndex,
            "generic method pointer index is outside the pointer table");
        mapping.invokerPointer = pointerAt(
            invokerPointers,
            mapping.invokerIndex,
            "generic method invoker index is outside the pointer table");
        if (entrySize == 16) {
            mapping.adjustorThunkIndex = reader.i32(checkedAdd(address, 12));
            if (mapping.adjustorThunkIndex >= 0) {
                if (!adjustorThunks.empty() && static_cast<size_t>(mapping.adjustorThunkIndex) >= adjustorThunks.size()) {
                    invalid("generic method adjustor index is outside the adjustor table");
                }
                if (!adjustorThunks.empty()) {
                    mapping.adjustorThunk = adjustorThunks[static_cast<size_t>(mapping.adjustorThunkIndex)].address;
                }
            } else if (mapping.adjustorThunkIndex < -1) {
                invalid("negative generic method adjustor index");
            }
        }
        const auto& spec = methodSpecs[static_cast<size_t>(mapping.genericMethodIndex)];
        mapping.classInstAddress = spec.classInstAddress;
        mapping.methodInstAddress = spec.methodInstAddress;
        genericMethodTable.push_back(mapping);
    }

    metadata.genericClasses = std::move(genericClasses);
    metadata.genericInsts = std::move(genericInsts);
    metadata.genericMethodTable = std::move(genericMethodTable);
    metadata.methodSpecs = std::move(methodSpecs);
    metadata.genericMethodPointers = std::move(genericMethodPointers);
    metadata.invokerPointers = std::move(invokerPointers);
    metadata.unresolvedVirtualCallPointers = std::move(unresolvedVirtualCallPointers);
    metadata.adjustorThunks = std::move(adjustorThunks);
    metadata.metadataUsagesCount = registration.metadataUsagesCount;
}

size_t typeReferenceIndex(const std::string& type) {
    if (type.size() < 7 || !type.starts_with("type[") || type.back() != ']') {
        return std::numeric_limits<size_t>::max();
    }
    size_t index = 0;
    const char* begin = type.data() + 5;
    const char* end = type.data() + type.size() - 1;
    const auto parsed = std::from_chars(begin, end, index);
    if (parsed.ec != std::errc{} || parsed.ptr != end) return std::numeric_limits<size_t>::max();
    return index;
}

void applyTypeReferences(MetadataModel& metadata) {
    const auto resolve = [&](const std::string& type) {
        const size_t index = typeReferenceIndex(type);
        if (index >= metadata.typeReferences.size()) return type;
        const auto& name = metadata.typeReferences[index].name;
        return name.empty() ? type : name;
    };
    for (auto& type : metadata.types) {
        type.baseType = resolve(type.baseType);
        for (auto& field : type.fields) {
            const size_t referenceIndex = typeReferenceIndex(field.type);
            if (referenceIndex < metadata.typeReferences.size()) {
                const auto& reference = metadata.typeReferences[referenceIndex];
                field.flags = reference.attrs;
                field.isStatic = (reference.attrs & 0x0010) != 0;
            }
            field.type = resolve(field.type);
        }
        for (auto& method : type.methods) {
            method.returnType = resolve(method.returnType);
            for (auto& parameter : method.parameters) parameter.type = resolve(parameter.type);
        }
    }
}

} // namespace

MetadataRegistrationReader::MetadataRegistrationReader(size_t pointerSize)
    : pointerSize_(pointerSize) {
    if (pointerSize != 0 && pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }
}

std::vector<TypeReferenceModel> MetadataRegistrationReader::readTypes(
    const BinaryImage& binary,
    uint64_t typesAddress,
    uint64_t typesCount,
    const MetadataModel& metadata) const {
    ImageReader reader(binary, inferredPointerSize(binary, pointerSize_));
    return TypeTableReader(reader, typesAddress, typesCount, metadata.types).read();
}

void MetadataRegistrationReader::readFieldOffsets(
    const BinaryImage& binary,
    MetadataModel& metadata,
    uint64_t fieldOffsetsAddress,
    uint64_t fieldOffsetsCount) const {
    ImageReader reader(binary, inferredPointerSize(binary, pointerSize_));
    // IL2CPP 19/20 and early 21 store one flat int32 offset per field. Later
    // layouts store one pointer per type to an array of int32 offsets.
    const bool legacyFlat = metadata.version >= 19.0 && metadata.version < 21.0;
    bool flat = legacyFlat;
    if (metadata.version == 21.0 && fieldOffsetsCount != 0) {
        const auto candidates = reader.pointerTable(fieldOffsetsAddress, fieldOffsetsCount);
        flat = std::none_of(candidates.begin(), candidates.end(), [&](uint64_t candidate) {
            return candidate >= binary.imageBase;
        });
    }
    if (flat) {
        metadata.fieldOffsetsByToken.clear();
        size_t fieldIndex = 0;
        for (auto& type : metadata.types) {
            for (auto& field : type.fields) {
                if (fieldIndex >= fieldOffsetsCount) invalid("flat field offset table is shorter than metadata fields");
                field.offset = reader.i32(checkedAdd(fieldOffsetsAddress, fieldIndex * sizeof(int32_t)));
                ++fieldIndex;
                if (field.token != 0) metadata.fieldOffsetsByToken.insert_or_assign(field.token, field.offset);
            }
        }
        return;
    }
    const auto table = reader.pointerTable(fieldOffsetsAddress, fieldOffsetsCount);
    const size_t count = std::min(table.size(), metadata.types.size());
    std::vector<std::vector<int32_t>> offsets(count);
    for (size_t typeIndex = 0; typeIndex < count; ++typeIndex) {
        if (table[typeIndex] == 0) continue;
        const auto& fields = metadata.types[typeIndex].fields;
        const size_t size = checkedTableSize(fields.size(), sizeof(int32_t));
        if (size != 0) reader.require(table[typeIndex], size);
        offsets[typeIndex].reserve(fields.size());
        for (size_t fieldIndex = 0; fieldIndex < fields.size(); ++fieldIndex) {
            offsets[typeIndex].push_back(reader.i32(checkedAdd(table[typeIndex], fieldIndex * sizeof(int32_t))));
        }
    }

    metadata.fieldOffsetsByToken.clear();
    for (size_t typeIndex = 0; typeIndex < count; ++typeIndex) {
        auto& fields = metadata.types[typeIndex].fields;
        for (size_t fieldIndex = 0; fieldIndex < fields.size(); ++fieldIndex) {
            auto& field = fields[fieldIndex];
            field.offset = offsets[typeIndex][fieldIndex];
            if (field.token != 0) metadata.fieldOffsetsByToken.insert_or_assign(field.token, field.offset);
        }
    }
}

void MetadataRegistrationReader::read(const BinaryImage& binary, MetadataModel& metadata) const {
    if (metadata.metadataRegistrationAddress == 0) {
        throw std::invalid_argument("IL2CPP metadata registration address is zero");
    }
    read(binary, metadata, metadata.metadataRegistrationAddress, metadata.codeRegistrationAddress);
}

void MetadataRegistrationReader::read(
    const BinaryImage& binary,
    MetadataModel& metadata,
    const MetadataRegistrationInfo& registration) const {
    auto references = readTypes(binary, registration.typesAddress, registration.typesCount, metadata);
    metadata.typeReferences = std::move(references);
    metadata.fieldOffsetsByToken.clear();
    if (registration.fieldOffsetsCount != 0) {
        readFieldOffsets(binary, metadata, registration.fieldOffsetsAddress, registration.fieldOffsetsCount);
    }
    applyTypeReferences(metadata);
    readGenericTables(binary, metadata, registration, inferredPointerSize(binary, pointerSize_));
    auto& version = metadata.versionInfo;
    if (version.rawVersion == 0) version.rawVersion = static_cast<int32_t>(metadata.version);
    if (version.preciseVersion == 0) {
        version.preciseVersion = registration.registrationVersion != 0 ? registration.registrationVersion : metadata.version;
    }
    if (registration.registrationVersion != 0) {
        version.registrationVersion = registration.registrationVersion;
    }
    if (registration.versionConfidence != MetadataVersionConfidence::Unknown) {
        version.confidence = registration.versionConfidence;
    } else if (registration.registrationVersion != 0 &&
               version.confidence != MetadataVersionConfidence::Explicit) {
        version.confidence = MetadataVersionConfidence::Registration;
    }
    if (!registration.versionProvenance.empty()) {
        version.provenance = registration.versionProvenance;
    } else if (registration.registrationVersion != 0) {
        version.provenance = "metadata-registration:layout";
    }
    if (metadata.version == 0) metadata.version = version.preciseVersion;
    metadata.metadataRegistrationAddress = registration.metadataRegistrationAddress;
    metadata.codeRegistrationAddress = registration.codeRegistrationAddress;
}

void MetadataRegistrationReader::read(
    const BinaryImage& binary,
    MetadataModel& metadata,
    uint64_t metadataRegistrationAddress,
    uint64_t codeRegistrationAddress) const {
    ImageReader reader(binary, inferredPointerSize(binary, pointerSize_));
    const size_t pointerSize = reader.pointerSize();
    const auto pairAddress = [&](uint64_t index) {
        return checkedAdd(metadataRegistrationAddress, index * 2 * pointerSize);
    };
    const auto count = [&](uint64_t index) {
        const int32_t value = reader.i32(pairAddress(index));
        if (value < 0) invalid("negative table count");
        return static_cast<uint64_t>(static_cast<uint32_t>(value));
    };

    MetadataRegistrationInfo registration;
    registration.metadataRegistrationAddress = metadataRegistrationAddress;
    registration.codeRegistrationAddress = codeRegistrationAddress;
    registration.genericClassesCount = count(0);
    registration.genericClassesAddress = reader.pointer(checkedAdd(pairAddress(0), pointerSize));
    registration.genericInstsCount = count(1);
    registration.genericInstsAddress = reader.pointer(checkedAdd(pairAddress(1), pointerSize));
    registration.genericMethodTableCount = count(2);
    registration.genericMethodTableAddress = reader.pointer(checkedAdd(pairAddress(2), pointerSize));
    registration.typesCount = count(3);
    registration.typesAddress = reader.pointer(checkedAdd(pairAddress(3), pointerSize));
    registration.methodSpecsCount = count(4);
    registration.methodSpecsAddress = reader.pointer(checkedAdd(pairAddress(4), pointerSize));
    registration.fieldOffsetsCount = count(5);
    registration.fieldOffsetsAddress = reader.pointer(checkedAdd(pairAddress(5), pointerSize));
    registration.metadataUsagesCount = reader.pointer(pairAddress(7));
    if (codeRegistrationAddress != 0) {
        const auto codePairAddress = [&](uint64_t index) {
            return checkedAdd(codeRegistrationAddress, index * 2 * pointerSize);
        };
        const auto codeCount = [&](uint64_t index) {
            const int32_t value = reader.i32(codePairAddress(index));
            if (value < 0) invalid("negative code registration table count");
            return static_cast<uint64_t>(static_cast<uint32_t>(value));
        };
        registration.methodPointersCount = codeCount(0);
        registration.methodPointersAddress = reader.pointer(checkedAdd(codePairAddress(0), pointerSize));
        registration.genericMethodPointersCount = codeCount(2);
        registration.genericMethodPointersAddress = reader.pointer(checkedAdd(codePairAddress(2), pointerSize));
        registration.invokerPointersCount = codeCount(3);
        registration.invokerPointersAddress = reader.pointer(checkedAdd(codePairAddress(3), pointerSize));
        registration.unresolvedVirtualCallPointersCount = codeCount(5);
        registration.unresolvedVirtualCallPointersAddress = reader.pointer(checkedAdd(codePairAddress(5), pointerSize));
    }
    read(binary, metadata, registration);
}

} // namespace il2cpprec
