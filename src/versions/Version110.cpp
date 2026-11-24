#include <il2cpprec/versions/Version110.hpp>

#include <bit>
#include <limits>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace il2cpprec {
namespace {

constexpr uint32_t methodTokenType = 0x06000000U;
constexpr uint32_t tokenRowIdMask = 0x00FFFFFFU;
constexpr size_t generatedMethodTypeInfoSize = 12;
constexpr size_t generatedMethodTokenSize = 4;

struct GeneratedView {
    const std::vector<TypeModel>& types;
    const std::vector<GeneratedMethodTypeInfoModel>& typeInfos;
    const std::vector<GeneratedMethodTokenModel>& tokens;
    int32_t generatedMethodsStart;
};

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 110 generated methods: " + message);
}

GeneratedView view(const MetadataModel& metadata) {
    return {
        metadata.types,
        metadata.generatedMethodTypeInfos,
        metadata.generatedMethodTokens,
        metadata.generatedMethodsStart
    };
}

size_t totalMethodDefinitions(const GeneratedView& generated) {
    if (generated.generatedMethodsStart < 0) invalid("generatedMethodsStart is negative");
    const auto start = static_cast<uint64_t>(static_cast<uint32_t>(generated.generatedMethodsStart));
    const uint64_t total = start + generated.tokens.size();
    if (total > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
        invalid("method definition count exceeds the signed index range");
    }
    return static_cast<size_t>(total);
}

bool validMethodToken(uint32_t token) {
    return (token & ~tokenRowIdMask) == methodTokenType && (token & tokenRowIdMask) != 0;
}

void validateToken(uint32_t token) {
    if (!validMethodToken(token)) invalid("generated method has an invalid MethodDef token");
}

void validateTypeInfo(const GeneratedView& generated, const GeneratedMethodTypeInfoModel& info, size_t total) {
    if (info.typeIndex < 0) invalid("generated method type index is negative");
    if (info.generatedMethodStart < 0) invalid("generated method range has a negative start");
    if (info.generatedMethodCount < 0) invalid("generated method range has a negative count");

    const uint64_t start = static_cast<uint32_t>(info.generatedMethodStart);
    const uint64_t count = static_cast<uint32_t>(info.generatedMethodCount);
    const uint64_t end = start + count;
    if (end > total) invalid("generated method range exceeds the method definition table");
    if (count != 0 && start < static_cast<uint32_t>(generated.generatedMethodsStart)) {
        invalid("generated method range overlaps ordinary method definitions");
    }
}

const GeneratedMethodTypeInfoModel* findTypeInfo(const GeneratedView& generated, int32_t typeDefinitionIndex) {
    if (typeDefinitionIndex < 0 || static_cast<size_t>(typeDefinitionIndex) >= generated.types.size()) {
        invalid("type definition index is outside the type table");
    }

    const GeneratedMethodTypeInfoModel* result = nullptr;
    const size_t total = totalMethodDefinitions(generated);
    for (const auto& info : generated.typeInfos) {
        if (info.typeIndex != typeDefinitionIndex) continue;
        validateTypeInfo(generated, info, total);
        if (result != nullptr) invalid("type has duplicate generatedMethodTypeInfo entries");
        result = &info;
    }
    return result;
}

void validateTables(const GeneratedView& generated, size_t expectedTotal, bool validateTypes) {
    if (totalMethodDefinitions(generated) != expectedTotal) {
        invalid("generatedMethodsStart is inconsistent with the method and token table counts");
    }

    std::unordered_set<int32_t> typeIndices;
    for (const auto& info : generated.typeInfos) {
        validateTypeInfo(generated, info, expectedTotal);
        if (!typeIndices.insert(info.typeIndex).second) {
            invalid("type has duplicate generatedMethodTypeInfo entries");
        }
        if (validateTypes) {
            if (static_cast<size_t>(info.typeIndex) >= generated.types.size()) {
                invalid("generatedMethodTypeInfo references a type outside the type table");
            }
            const auto& type = generated.types[static_cast<size_t>(info.typeIndex)];
            if (info.generatedMethodCount > 0 && !Version110::hasGeneratedMethods(type)) {
                invalid("generatedMethodTypeInfo contradicts HasGeneratedMethods");
            }
        }
    }
    for (const auto& entry : generated.tokens) validateToken(entry.token);
}

struct TableLocation {
    size_t offset = 0;
    size_t count = 0;
};

TableLocation tableLocation(
    const MetadataSectionModel& section,
    size_t stride,
    const uint8_t* data,
    size_t size,
    const char* name) {
    if (data == nullptr && size != 0) invalid("null metadata data with nonzero size");
    if (section.offset < 0 || section.sectionSize < 0 || section.count < 0) {
        invalid(std::string(name) + " section has a negative offset, size, or count");
    }

    const auto count = static_cast<size_t>(section.count);
    if (count > std::numeric_limits<size_t>::max() / stride) {
        invalid(std::string(name) + " section size overflows");
    }
    const size_t expectedSize = count * stride;
    if (static_cast<size_t>(section.sectionSize) != expectedSize) {
        invalid(std::string(name) + " section size does not match its count and record size");
    }

    const auto offset = static_cast<size_t>(section.offset);
    if (offset > size || expectedSize > size - offset) {
        invalid(std::string(name) + " section is outside the metadata file");
    }
    return {offset, count};
}

uint32_t readU32(const uint8_t* data, size_t offset) {
    return static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset + 1]) << 8) |
        (static_cast<uint32_t>(data[offset + 2]) << 16) |
        (static_cast<uint32_t>(data[offset + 3]) << 24);
}

int32_t readI32(const uint8_t* data, size_t offset) {
    return std::bit_cast<int32_t>(readU32(data, offset));
}

uint32_t ordinaryMethodToken(const ImageModel& image, int32_t methodDefinitionIndex) {
    if (methodDefinitionIndex < 0) invalid("ordinary method definition index is negative");
    if (image.methodStart < 0) invalid("image has a negative ordinary method start");
    const int64_t rowId = static_cast<int64_t>(methodDefinitionIndex) - image.methodStart + 1;
    if (rowId <= 0 || rowId > tokenRowIdMask) invalid("ordinary MethodDef token row id is outside the 24-bit range");
    return methodTokenType | static_cast<uint32_t>(rowId);
}

} // namespace

bool Version110::hasGeneratedMethods(uint32_t bitfield) noexcept {
    return (bitfield & HasGeneratedMethods) != 0;
}

bool Version110::hasGeneratedMethods(const TypeModel& type) noexcept {
    return hasGeneratedMethods(type.bitfield);
}

int32_t Version110::generatedMethodsStart(size_t methodDefinitionCount, size_t generatedMethodTokenCount) {
    if (methodDefinitionCount > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
        invalid("method definition count exceeds the signed index range");
    }
    if (generatedMethodTokenCount > methodDefinitionCount) {
        invalid("generated token count exceeds the method definition count");
    }
    return static_cast<int32_t>(methodDefinitionCount - generatedMethodTokenCount);
}

void Version110::readGeneratedMethodTables(
    const uint8_t* data,
    size_t size,
    size_t methodDefinitionCount,
    MetadataModel& metadata) {
    const auto infoLocation = tableLocation(
        metadata.sections.generatedMethodTypeInfos,
        generatedMethodTypeInfoSize,
        data,
        size,
        "generatedMethodTypeInfos");
    const auto tokenLocation = tableLocation(
        metadata.sections.generatedMethodTokens,
        generatedMethodTokenSize,
        data,
        size,
        "generatedMethodTokens");

    const int32_t start = generatedMethodsStart(methodDefinitionCount, tokenLocation.count);
    std::vector<GeneratedMethodTypeInfoModel> typeInfos;
    typeInfos.reserve(infoLocation.count);
    for (size_t index = 0; index < infoLocation.count; ++index) {
        const size_t offset = infoLocation.offset + index * generatedMethodTypeInfoSize;
        typeInfos.push_back({
            readI32(data, offset),
            readI32(data, offset + 4),
            readI32(data, offset + 8)
        });
    }

    std::vector<GeneratedMethodTokenModel> tokens;
    tokens.reserve(tokenLocation.count);
    for (size_t index = 0; index < tokenLocation.count; ++index) {
        tokens.push_back({readU32(data, tokenLocation.offset + index * generatedMethodTokenSize)});
    }

    validateTables(GeneratedView{metadata.types, typeInfos, tokens, start}, methodDefinitionCount, false);
    metadata.generatedMethodTypeInfos = std::move(typeInfos);
    metadata.generatedMethodTokens = std::move(tokens);
    metadata.generatedMethodsStart = start;
}

void Version110::readGeneratedMethodTables(
    const std::vector<uint8_t>& data,
    size_t methodDefinitionCount,
    MetadataModel& metadata) {
    readGeneratedMethodTables(data.data(), data.size(), methodDefinitionCount, metadata);
}

Version110MethodRange Version110::methodRange(
    const MetadataModel& metadata,
    int32_t typeDefinitionIndex,
    int32_t ordinaryMethodStart,
    uint32_t methodCount) {
    const auto generated = view(metadata);
    const auto& type = generated.types.at(static_cast<size_t>(typeDefinitionIndex));
    const bool hasGenerated = hasGeneratedMethods(type);
    const auto* info = findTypeInfo(generated, typeDefinitionIndex);

    if (!hasGenerated && info != nullptr && info->generatedMethodCount > 0) {
        invalid("generatedMethodTypeInfo contradicts HasGeneratedMethods");
    }
    if (hasGenerated && info == nullptr && methodCount != 0) {
        invalid("HasGeneratedMethods is set without generatedMethodTypeInfo");
    }

    const uint32_t generatedCount = hasGenerated && info != nullptr
        ? static_cast<uint32_t>(info->generatedMethodCount)
        : 0;
    if (generatedCount > methodCount) invalid("generated method count exceeds the type method count");
    const uint32_t ordinaryCount = methodCount - generatedCount;
    const size_t generatedMethodsBegin = static_cast<size_t>(generated.generatedMethodsStart);

    if (ordinaryCount != 0) {
        if (ordinaryMethodStart < 0) invalid("ordinary method range has a negative start");
        const uint64_t end = static_cast<uint64_t>(static_cast<uint32_t>(ordinaryMethodStart)) + ordinaryCount;
        if (end > generatedMethodsBegin) invalid("ordinary method range overlaps generated method definitions");
    }

    Version110MethodRange result;
    result.ordinaryStart = ordinaryMethodStart;
    result.ordinaryCount = ordinaryCount;
    if (generatedCount != 0) result.generatedStart = info->generatedMethodStart;
    result.generatedCount = generatedCount;
    return result;
}

int32_t Version110::methodIndex(
    const MetadataModel& metadata,
    int32_t typeDefinitionIndex,
    int32_t ordinaryMethodStart,
    uint32_t methodCount,
    uint32_t methodIndexInType) {
    if (methodIndexInType >= methodCount) invalid("method index in type is outside the type method range");
    const auto range = methodRange(metadata, typeDefinitionIndex, ordinaryMethodStart, methodCount);
    const bool ordinary = methodIndexInType < range.ordinaryCount;
    const int64_t index = ordinary
        ? static_cast<int64_t>(range.ordinaryStart) + methodIndexInType
        : static_cast<int64_t>(range.generatedStart) + (methodIndexInType - range.ordinaryCount);
    if (index < 0 || index > std::numeric_limits<int32_t>::max()) {
        invalid("method definition index exceeds the signed index range");
    }
    return static_cast<int32_t>(index);
}

uint32_t Version110::methodToken(
    const MetadataModel& metadata,
    const ImageModel& image,
    int32_t typeDefinitionIndex,
    int32_t methodDefinitionIndex) {
    const auto generated = view(metadata);
    if (methodDefinitionIndex < 0) invalid("method definition index is negative");
    const auto& type = generated.types.at(static_cast<size_t>(typeDefinitionIndex));
    const auto* info = findTypeInfo(generated, typeDefinitionIndex);
    const bool hasGenerated = hasGeneratedMethods(type);

    if (!hasGenerated && info != nullptr && info->generatedMethodCount > 0) {
        invalid("generatedMethodTypeInfo contradicts HasGeneratedMethods");
    }
    if (hasGenerated && info == nullptr) invalid("HasGeneratedMethods is set without generatedMethodTypeInfo");

    if (hasGenerated && info != nullptr) {
        const int64_t generatedEnd = static_cast<int64_t>(info->generatedMethodStart) + info->generatedMethodCount;
        if (methodDefinitionIndex >= info->generatedMethodStart && methodDefinitionIndex < generatedEnd) {
            const int64_t tokenIndex = static_cast<int64_t>(methodDefinitionIndex) - generated.generatedMethodsStart;
            if (tokenIndex < 0 || static_cast<uint64_t>(tokenIndex) >= generated.tokens.size()) {
                invalid("generated method token index is outside the token table");
            }
            const uint32_t token = generated.tokens[static_cast<size_t>(tokenIndex)].token;
            validateToken(token);
            return token;
        }
    }

    if (methodDefinitionIndex >= generated.generatedMethodsStart) {
        invalid("generated method definition has no owning generated method range");
    }
    return ordinaryMethodToken(image, methodDefinitionIndex);
}

void Version110::reconstructMethodTokens(MetadataModel& metadata, size_t methodDefinitionCount) {
    const int32_t expectedStart = generatedMethodsStart(methodDefinitionCount, metadata.generatedMethodTokens.size());
    if (metadata.generatedMethodsStart != expectedStart) {
        invalid("generatedMethodsStart is inconsistent with the method and token table counts");
    }
    validateTables(view(metadata), methodDefinitionCount, true);

    std::vector<bool> visitedTypes(metadata.types.size(), false);
    std::vector<bool> visitedDefinitions(methodDefinitionCount, false);
    std::vector<std::pair<MethodModel*, uint32_t>> reconstructed;
    reconstructed.reserve(methodDefinitionCount);

    for (const auto& image : metadata.images) {
        if (image.typeCount != 0 && image.typeStart < 0) invalid("image has a negative type start");
        if (image.typeStart < 0 || static_cast<size_t>(image.typeStart) > metadata.types.size() ||
            image.typeCount > metadata.types.size() - static_cast<size_t>(image.typeStart)) {
            invalid("image type range is outside the type table");
        }

        std::unordered_set<uint32_t> imageTokens;
        for (uint32_t typeOffset = 0; typeOffset < image.typeCount; ++typeOffset) {
            const int64_t typeIndex64 = static_cast<int64_t>(image.typeStart) + typeOffset;
            if (typeIndex64 > std::numeric_limits<int32_t>::max()) invalid("type index exceeds the signed index range");
            const auto typeIndex = static_cast<int32_t>(typeIndex64);
            auto& type = metadata.types[static_cast<size_t>(typeIndex)];
            if (visitedTypes[static_cast<size_t>(typeIndex)]) invalid("type belongs to multiple image ranges");
            visitedTypes[static_cast<size_t>(typeIndex)] = true;

            if (type.methods.size() > std::numeric_limits<uint32_t>::max()) {
                invalid("type method count exceeds the unsigned 32-bit range");
            }
            const auto methodCount = static_cast<uint32_t>(type.methods.size());
            const auto* info = findTypeInfo(view(metadata), typeIndex);
            const uint32_t generatedCount = hasGeneratedMethods(type) && info != nullptr
                ? static_cast<uint32_t>(info->generatedMethodCount)
                : 0;
            if (generatedCount > methodCount) invalid("generated method count exceeds the type method count");
            const uint32_t ordinaryCount = methodCount - generatedCount;

            int32_t ordinaryStart = -1;
            if (ordinaryCount != 0) {
                ordinaryStart = type.methods.front().definitionIndex;
                if (ordinaryStart < 0) invalid("ordinary method has no definition index");
            }
            const auto range = methodRange(metadata, typeIndex, ordinaryStart, methodCount);

            for (uint32_t methodOffset = 0; methodOffset < methodCount; ++methodOffset) {
                auto& method = type.methods[methodOffset];
                const int32_t definitionIndex = methodIndex(
                    metadata,
                    typeIndex,
                    range.ordinaryStart,
                    methodCount,
                    methodOffset);
                if (method.definitionIndex != definitionIndex) {
                    invalid("method definition index does not match its ordinary/generated range");
                }
                if (static_cast<size_t>(definitionIndex) >= methodDefinitionCount) {
                    invalid("method definition index is outside the method definition table");
                }
                if (visitedDefinitions[static_cast<size_t>(definitionIndex)]) {
                    invalid("method definition is referenced by multiple type methods");
                }

                const uint32_t token = methodToken(metadata, image, typeIndex, definitionIndex);
                if (!imageTokens.insert(token).second) invalid("duplicate MethodDef token in image");
                visitedDefinitions[static_cast<size_t>(definitionIndex)] = true;
                reconstructed.emplace_back(&method, token);
            }
        }
    }

    for (size_t typeIndex = 0; typeIndex < metadata.types.size(); ++typeIndex) {
        if (!visitedTypes[typeIndex] && !metadata.types[typeIndex].methods.empty()) {
            invalid("type with methods is not covered by an image type range");
        }
    }
    for (size_t definitionIndex = 0; definitionIndex < visitedDefinitions.size(); ++definitionIndex) {
        if (!visitedDefinitions[definitionIndex]) invalid("method definition is not covered by a type method range");
    }

    for (const auto& [method, token] : reconstructed) method->token = token;
}

std::optional<size_t> Version110::methodPointerIndex(uint32_t token, size_t methodPointerCount) noexcept {
    if (!validMethodToken(token)) return std::nullopt;
    const size_t index = static_cast<size_t>((token & tokenRowIdMask) - 1);
    if (index >= methodPointerCount) return std::nullopt;
    return index;
}

std::optional<uint64_t> Version110::methodPointer(
    const MetadataModel& metadata,
    const std::string& imageName,
    uint32_t token) {
    const auto image = metadata.methodPointersByImage.find(imageName);
    if (image == metadata.methodPointersByImage.end()) return std::nullopt;
    const auto index = methodPointerIndex(token, image->second.size());
    if (!index) return std::nullopt;
    const uint64_t pointer = image->second[*index];
    if (pointer == 0) return std::nullopt;
    return pointer;
}

} // namespace il2cpprec
