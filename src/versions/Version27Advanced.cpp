#include <il2cpprec/versions/Version27Advanced.hpp>

#include <algorithm>
#include <bit>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <utility>

namespace il2cpprec {
namespace {

constexpr std::uint64_t maximumTableCount = 1ULL << 24;

[[noreturn]] void invalid(const std::string& message) {
    throw std::runtime_error("Invalid IL2CPP 27 registration: " + message);
}

std::uint64_t checkedAdd(std::uint64_t value, std::uint64_t amount) {
    if (amount > std::numeric_limits<std::uint64_t>::max() - value) {
        invalid("virtual address overflow");
    }
    return value + amount;
}

std::size_t checkedSize(std::uint64_t count, std::size_t stride) {
    if (count > maximumTableCount || count > std::numeric_limits<std::size_t>::max()) {
        invalid("table is too large");
    }
    const auto converted = static_cast<std::size_t>(count);
    if (converted > std::numeric_limits<std::size_t>::max() / stride) {
        invalid("table size overflow");
    }
    return converted * stride;
}

Version27Slot slot(std::size_t pointerSize, std::size_t index, std::size_t size) {
    return {index, index * pointerSize, size};
}

Version27TableLayout registrationTable(std::size_t pointerSize, std::size_t index) {
    return {
        slot(pointerSize, index, sizeof(std::uint32_t)),
        slot(pointerSize, index + 1, pointerSize)
    };
}

Version27TableLayout moduleTable(std::size_t pointerSize, std::size_t index) {
    return {
        slot(pointerSize, index, pointerSize),
        slot(pointerSize, index + 1, pointerSize)
    };
}

bool versionIs(double value, double expected) {
    return std::isfinite(value) && std::abs(value - expected) < 0.0001;
}

std::size_t inferredPointerSize(const BinaryImage& binary) {
    switch (binary.architecture) {
    case Architecture::Arm32:
    case Architecture::X86:
        return 4;
    case Architecture::Arm64:
    case Architecture::X64:
        return 8;
    }
    return 0;
}

class ImageReader {
public:
    ImageReader(const BinaryImage& binary, std::size_t pointerSize)
        : binary_(binary), pointerSize_(pointerSize) {
        if (pointerSize != 4 && pointerSize != 8) {
            throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
        }
        if (!binary.bytes) invalid("binary image has no data");
    }

    std::uint32_t u32(std::uint64_t address) const {
        const auto* data = bytes(address, 4);
        return static_cast<std::uint32_t>(data[0]) |
            (static_cast<std::uint32_t>(data[1]) << 8) |
            (static_cast<std::uint32_t>(data[2]) << 16) |
            (static_cast<std::uint32_t>(data[3]) << 24);
    }

    std::int32_t i32(std::uint64_t address) const {
        return std::bit_cast<std::int32_t>(u32(address));
    }

    std::uint64_t u64(std::uint64_t address) const {
        const auto* data = bytes(address, 8);
        std::uint64_t value = 0;
        for (std::size_t index = 0; index < 8; ++index) {
            value |= static_cast<std::uint64_t>(data[index]) << (index * 8);
        }
        return value;
    }

    std::uint64_t pointer(std::uint64_t address) const {
        return pointerSize_ == 4 ? u32(address) : u64(address);
    }

    std::uint32_t registrationCount(std::uint64_t address) const {
        const std::uint32_t value = u32(address);
        if (pointerSize_ == 8 && u32(checkedAdd(address, 4)) != 0) {
            invalid("registration count has nonzero padding");
        }
        return value;
    }

    std::uint64_t moduleCount(std::uint64_t address) const {
        return pointer(address);
    }

    void requireTable(std::uint64_t address, std::uint64_t count, std::size_t stride) const {
        const std::size_t size = checkedSize(count, stride);
        if (size == 0) return;
        if (address == 0) invalid("nonempty table has a null address");
        require(address, size);
    }

    void require(std::uint64_t address, std::size_t size) const {
        static_cast<void>(bytes(address, size));
    }

    bool mapped(std::uint64_t address, std::size_t size) const noexcept {
        try {
            require(address, size);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    std::vector<std::uint64_t> pointerTable(std::uint64_t address, std::uint64_t count) const {
        const std::size_t size = checkedSize(count, pointerSize_);
        if (size != 0) requireTable(address, count, pointerSize_);
        std::vector<std::uint64_t> result;
        result.reserve(static_cast<std::size_t>(count));
        for (std::size_t index = 0; index < static_cast<std::size_t>(count); ++index) {
            result.push_back(pointer(checkedAdd(address, index * pointerSize_)));
        }
        return result;
    }

private:
    const std::uint8_t* bytes(std::uint64_t address, std::size_t size) const {
        std::uint64_t fileOffset = 0;
        try {
            if (address >= binary_.imageBase && binary_.imageBase != 0) {
                fileOffset = binary_.mapVATR(address - binary_.imageBase);
            } else {
                fileOffset = binary_.mapVATR(address);
            }
        } catch (const std::out_of_range&) {
            fileOffset = binary_.mapVATR(address);
        } catch (const std::overflow_error&) {
            fileOffset = binary_.mapVATR(address);
        }
        return binary_.data(fileOffset, size);
    }

    const BinaryImage& binary_;
    std::size_t pointerSize_;
};

Version27Registration readRegistration(
    const ImageReader& reader,
    const Version27Layout& layout,
    std::uint64_t address) {
    reader.require(address, layout.registration.size);
    const auto& native = layout.registration;
    Version27Registration result;
    result.address = address;
    const auto readPair = [&](const Version27TableLayout& table, std::uint64_t& count,
                              std::uint64_t& pointer, std::size_t stride) {
        count = reader.registrationCount(checkedAdd(address, table.count.offset));
        pointer = reader.pointer(checkedAdd(address, table.pointer.offset));
        reader.requireTable(pointer, count, stride);
    };
    readPair(native.reversePInvokeWrappers, result.reversePInvokeWrapperCount,
             result.reversePInvokeWrappers, layout.pointerSize);
    readPair(native.genericMethodPointers, result.genericMethodPointersCount,
             result.genericMethodPointers, layout.pointerSize);
    result.genericAdjustorThunks = reader.pointer(checkedAdd(address, native.genericAdjustorThunks.offset));
    readPair(native.invokerPointers, result.invokerPointersCount,
             result.invokerPointers, layout.pointerSize);
    readPair(native.unresolvedVirtualCallPointers, result.unresolvedVirtualCallCount,
             result.unresolvedVirtualCallPointers, layout.pointerSize);
    readPair(native.interopData, result.interopDataCount, result.interopData, 1);
    readPair(native.windowsRuntimeFactoryTable, result.windowsRuntimeFactoryCount,
             result.windowsRuntimeFactoryTable, layout.pointerSize);
    readPair(native.codeGenModules, result.codeGenModulesCount,
             result.codeGenModules, layout.pointerSize);
    return result;
}

Version27CodeGenModule readModule(
    const ImageReader& reader,
    const Version27Layout& layout,
    std::uint64_t address,
    bool validateRgctx) {
    reader.require(address, layout.codeGenModule.size);
    const auto& native = layout.codeGenModule;
    Version27CodeGenModule result;
    result.address = address;
    const auto readPair = [&](const Version27TableLayout& table, std::uint64_t& count,
                              std::uint64_t& pointer, std::size_t stride) {
        count = reader.moduleCount(checkedAdd(address, table.count.offset));
        pointer = reader.pointer(checkedAdd(address, table.pointer.offset));
        reader.requireTable(pointer, count, stride);
    };
    result.moduleName = reader.pointer(checkedAdd(address, native.moduleName.offset));
    if (result.moduleName != 0) reader.require(result.moduleName, 1);
    readPair(native.methodPointers, result.methodPointerCount,
             result.methodPointers, layout.pointerSize);
    readPair(native.adjustorThunks, result.adjustorThunkCount,
             result.adjustorThunks, layout.pointerSize);
    result.invokerIndices = reader.pointer(checkedAdd(address, native.invokerIndices.offset));
    reader.requireTable(result.invokerIndices, result.methodPointerCount, sizeof(std::uint32_t));
    readPair(native.reversePInvokeWrapperIndices, result.reversePInvokeWrapperCount,
             result.reversePInvokeWrapperIndices, sizeof(std::uint32_t));
    readPair(native.rgctxRanges, result.rgctxRangesCount, result.rgctxRanges, 12);
    if (validateRgctx) {
        readPair(native.rgctxs, result.rgctxsCount, result.rgctxs, layout.rgctxEntrySize);
    } else {
        result.rgctxsCount = reader.moduleCount(checkedAdd(address, native.rgctxs.count.offset));
        result.rgctxs = reader.pointer(checkedAdd(address, native.rgctxs.pointer.offset));
        static_cast<void>(checkedSize(result.rgctxsCount, layout.pointerSize));
        if (result.rgctxsCount != 0 && result.rgctxs == 0) {
            invalid("nonempty RGCTX table has a null address");
        }
    }
    result.debuggerMetadata = reader.pointer(checkedAdd(address, native.debuggerMetadata.offset));
    result.customAttributeCacheGenerator =
        reader.pointer(checkedAdd(address, native.customAttributeCacheGenerator.offset));
    result.moduleInitializer = reader.pointer(checkedAdd(address, native.moduleInitializer.offset));
    result.staticConstructorTypeIndices =
        reader.pointer(checkedAdd(address, native.staticConstructorTypeIndices.offset));
    result.metadataRegistration = reader.pointer(checkedAdd(address, native.metadataRegistration.offset));
    result.codeRegistration = reader.pointer(checkedAdd(address, native.codeRegistration.offset));
    return result;
}

void addDiscriminator(
    std::vector<Version27Kind>& discriminators,
    std::vector<std::string>& diagnostics,
    Version27Kind kind,
    const std::string& source) {
    discriminators.push_back(kind);
    diagnostics.push_back(source + (kind == Version27Kind::V27_1 ? " indicates 27.1" : " indicates 27.2"));
}

} // namespace

bool Version27Detection::resolved() const noexcept {
    return kind.has_value() && !ambiguous;
}

Version27Layout makeVersion27Layout(Version27Kind kind, std::size_t pointerSize) {
    if (pointerSize != 4 && pointerSize != 8) {
        throw std::invalid_argument("IL2CPP pointer size must be 4 or 8 bytes");
    }

    Version27Layout result;
    result.kind = kind;
    result.pointerSize = pointerSize;
    auto& registration = result.registration;
    registration.size = version27CodeRegistrationSlots * pointerSize;
    registration.reversePInvokeWrappers = registrationTable(pointerSize, 0);
    registration.genericMethodPointers = registrationTable(pointerSize, 2);
    registration.genericAdjustorThunks = slot(pointerSize, 4, pointerSize);
    registration.invokerPointers = registrationTable(pointerSize, 5);
    registration.unresolvedVirtualCallPointers = registrationTable(pointerSize, 7);
    registration.interopData = registrationTable(pointerSize, 9);
    registration.windowsRuntimeFactoryTable = registrationTable(pointerSize, 11);
    registration.codeGenModules = registrationTable(pointerSize, 13);

    auto& module = result.codeGenModule;
    module.size = version27CodeGenModuleSlots * pointerSize;
    module.moduleName = slot(pointerSize, 0, pointerSize);
    module.methodPointers = moduleTable(pointerSize, 1);
    module.adjustorThunks = moduleTable(pointerSize, 3);
    module.invokerIndices = slot(pointerSize, 5, pointerSize);
    module.reversePInvokeWrapperIndices = moduleTable(pointerSize, 6);
    module.rgctxRanges = moduleTable(pointerSize, 8);
    module.rgctxs = moduleTable(pointerSize, 10);
    module.debuggerMetadata = slot(pointerSize, 12, pointerSize);
    module.customAttributeCacheGenerator = slot(pointerSize, 13, pointerSize);
    module.moduleInitializer = slot(pointerSize, 14, pointerSize);
    module.staticConstructorTypeIndices = slot(pointerSize, 15, pointerSize);
    module.metadataRegistration = slot(pointerSize, 16, pointerSize);
    module.codeRegistration = slot(pointerSize, 17, pointerSize);

    if (kind == Version27Kind::V27_1) {
        result.rgctxEntrySize = 8;
        result.rgctxEncoding = Version27RgctxEncoding::InlineKindAndIndex;
        result.invokerArgumentCount = 4;
    } else {
        result.rgctxEntrySize = pointerSize;
        result.rgctxEncoding = Version27RgctxEncoding::DataPointer;
        result.invokerArgumentCount = 5;
        result.invokerHasReturnValueArgument = true;
    }
    return result;
}

double version27Number(Version27Kind kind) noexcept {
    return kind == Version27Kind::V27_1 ? 27.1 : 27.2;
}

Version27TypeBits decodeVersion27TypeBits(Version27Kind kind, std::uint32_t bits) noexcept {
    Version27TypeBits result;
    result.attrs = static_cast<std::uint16_t>(bits & 0xffffU);
    result.type = static_cast<std::uint8_t>((bits >> 16) & 0xffU);
    if (kind == Version27Kind::V27_1) {
        result.numMods = static_cast<std::uint8_t>((bits >> 24) & 0x3fU);
        result.byRef = (bits & 0x40000000U) != 0;
        result.pinned = (bits & 0x80000000U) != 0;
    } else {
        result.numMods = static_cast<std::uint8_t>((bits >> 24) & 0x1fU);
        result.byRef = (bits & 0x20000000U) != 0;
        result.pinned = (bits & 0x40000000U) != 0;
        result.valueType = (bits & 0x80000000U) != 0;
    }
    return result;
}

Version27Detection detectVersion27(const Version27DetectionEvidence& evidence) {
    Version27Detection result;
    const bool declared27 = versionIs(evidence.declaredVersion, 27.0);
    const std::optional<Version27Kind> declaredKind = versionIs(evidence.declaredVersion, 27.1)
        ? std::optional<Version27Kind>(Version27Kind::V27_1)
        : versionIs(evidence.declaredVersion, 27.2)
            ? std::optional<Version27Kind>(Version27Kind::V27_2)
            : std::nullopt;
    if (evidence.declaredVersion != 0 && !declared27 && !declaredKind) {
        result.diagnostics.push_back("Declared metadata version is outside the 27.1/27.2 family");
        return result;
    }
    if (evidence.rawMetadataVersion != 0 && evidence.rawMetadataVersion != 27) {
        result.diagnostics.push_back("Raw metadata version is not 27");
        return result;
    }

    const bool familyEvidence = evidence.rawMetadataVersion == 27 || declared27 || declaredKind ||
        evidence.registration15Slots || evidence.module18Slots || evidence.genericMethodRows16;
    std::vector<Version27Kind> discriminators;
    if (evidence.rgctxEncoding) {
        addDiscriminator(discriminators, result.diagnostics,
                         *evidence.rgctxEncoding == Version27RgctxEncoding::DataPointer
                             ? Version27Kind::V27_2
                             : Version27Kind::V27_1,
                         "RGCTX entry encoding");
    }
    if (evidence.typeBitsHaveValueType) {
        addDiscriminator(discriminators, result.diagnostics,
                         *evidence.typeBitsHaveValueType ? Version27Kind::V27_2 : Version27Kind::V27_1,
                         "Il2CppType bit layout");
    }
    if (evidence.invokerArgumentCount) {
        if (*evidence.invokerArgumentCount == 4 || *evidence.invokerArgumentCount == 5) {
            addDiscriminator(discriminators, result.diagnostics,
                             *evidence.invokerArgumentCount == 5 ? Version27Kind::V27_2 : Version27Kind::V27_1,
                             "Invoker signature");
        } else {
            result.diagnostics.push_back("Invoker argument count is not valid for 27.1/27.2");
            return result;
        }
    }

    if (!familyEvidence && discriminators.empty()) {
        result.diagnostics.push_back("No IL2CPP 27.1/27.2 layout evidence is available");
        return result;
    }

    const bool conflictingDiscriminators = std::any_of(
        discriminators.begin(), discriminators.end(), [&](Version27Kind kind) {
            return kind != discriminators.front();
        });
    const bool declarationConflict = declaredKind && !discriminators.empty() &&
        std::any_of(discriminators.begin(), discriminators.end(), [&](Version27Kind kind) {
            return kind != *declaredKind;
        });
    if (conflictingDiscriminators || declarationConflict) {
        result.diagnostics.push_back("Conflicting 27.1/27.2 evidence; version was not selected");
        return result;
    }

    if (!discriminators.empty()) {
        result.kind = discriminators.front();
        result.preciseVersion = version27Number(*result.kind);
        result.ambiguous = false;
        result.confidence = declaredKind ? Version27DetectionConfidence::Explicit
            : discriminators.size() > 1 ? Version27DetectionConfidence::Corroborated
            : Version27DetectionConfidence::Inferred;
        return result;
    }

    if (declaredKind) {
        result.kind = declaredKind;
        result.preciseVersion = version27Number(*declaredKind);
        result.ambiguous = false;
        result.confidence = Version27DetectionConfidence::Explicit;
        result.diagnostics.push_back("Version selected only from the explicit declaration");
        return result;
    }

    result.confidence = Version27DetectionConfidence::LayoutOnly;
    result.diagnostics.push_back("Shared 27.1/27.2 layout is confirmed, but no discriminator is available");
    return result;
}

Version27Detection detectVersion27(
    const BinaryImage& binary,
    std::uint64_t codeRegistrationAddress,
    double declaredVersion,
    std::size_t pointerSize) {
    Version27DetectionEvidence evidence;
    evidence.rawMetadataVersion = 27;
    evidence.declaredVersion = declaredVersion;
    if (pointerSize == 0) pointerSize = inferredPointerSize(binary);

    try {
        const auto familyLayout = makeVersion27Layout(Version27Kind::V27_1, pointerSize);
        ImageReader reader(binary, pointerSize);
        const auto registration = readRegistration(reader, familyLayout, codeRegistrationAddress);
        evidence.registration15Slots = true;
        const auto moduleAddresses = reader.pointerTable(
            registration.codeGenModules, registration.codeGenModulesCount);
        std::vector<Version27CodeGenModule> modules;
        modules.reserve(moduleAddresses.size());
        for (const std::uint64_t address : moduleAddresses) {
            if (address == 0) invalid("code generation module table contains a null module");
            modules.push_back(readModule(reader, familyLayout, address, false));
        }
        if (!modules.empty()) evidence.module18Slots = true;

        std::optional<Version27Kind> rgctxVote;
        bool rgctxConflict = false;
        for (const auto& module : modules) {
            if (module.rgctxsCount == 0) continue;
            bool inlinePlausible = true;
            bool pointerPlausible = true;
            bool pointerShaped = true;
            for (std::uint64_t index = 0; index < module.rgctxsCount; ++index) {
                const std::uint64_t inlineAddress = checkedAdd(
                    module.rgctxs, index * familyLayout.rgctxEntrySize);
                const std::uint64_t pointerAddress = checkedAdd(
                    module.rgctxs, index * familyLayout.pointerSize);
                if (!reader.mapped(inlineAddress, sizeof(std::uint32_t))) {
                    inlinePlausible = false;
                } else if (reader.u32(inlineAddress) > 5) {
                    inlinePlausible = false;
                }
                if (!reader.mapped(pointerAddress, pointerSize)) {
                    pointerPlausible = false;
                    pointerShaped = false;
                    continue;
                }
                const std::uint64_t pointer = reader.pointer(pointerAddress);
                if (pointer == 0 || !reader.mapped(pointer, 1)) pointerPlausible = false;
                if (pointer <= 0xffffU) pointerShaped = false;
            }

            std::optional<Version27Kind> moduleVote;
            if (inlinePlausible != pointerPlausible) {
                moduleVote = inlinePlausible ? Version27Kind::V27_1 : Version27Kind::V27_2;
            } else if (!inlinePlausible && pointerShaped) {
                moduleVote = Version27Kind::V27_2;
            }
            if (!moduleVote) {
                rgctxConflict = true;
                break;
            }
            if (rgctxVote && *rgctxVote != *moduleVote) {
                rgctxConflict = true;
                break;
            }
            rgctxVote = moduleVote;
        }
        if (!rgctxConflict && rgctxVote) {
            evidence.rgctxEncoding = *rgctxVote == Version27Kind::V27_2
                ? Version27RgctxEncoding::DataPointer
                : Version27RgctxEncoding::InlineKindAndIndex;
        }
        auto result = detectVersion27(evidence);
        if (rgctxConflict) {
            result.diagnostics.push_back("RGCTX probe is inconclusive or disagrees between modules");
            if (!declaredVersion) {
                result.kind.reset();
                result.preciseVersion = 0;
                result.confidence = Version27DetectionConfidence::LayoutOnly;
                result.ambiguous = true;
            }
        }
        return result;
    } catch (const std::exception& error) {
        auto result = detectVersion27(evidence);
        result.diagnostics.push_back(std::string("Registration probe failed: ") + error.what());
        return result;
    }
}

Version27Advanced::Version27Advanced(Version27Kind kind, std::size_t pointerSize)
    : layout_(makeVersion27Layout(kind, pointerSize)) {}

Version27Advanced::Version27Advanced(Version27Layout layout)
    : layout_(std::move(layout)) {
    layout_ = makeVersion27Layout(layout_.kind, layout_.pointerSize);
}

Version27Registration Version27Advanced::readRegistration(
    const BinaryImage& binary,
    std::uint64_t address) const {
    return il2cpprec::readRegistration(ImageReader(binary, layout_.pointerSize), layout_, address);
}

Version27CodeGenModule Version27Advanced::readCodeGenModule(
    const BinaryImage& binary,
    std::uint64_t address) const {
    return readModule(ImageReader(binary, layout_.pointerSize), layout_, address, true);
}

std::vector<Version27GenericMethodRow> Version27Advanced::readGenericMethodRows(
    const BinaryImage& binary,
    std::uint64_t address,
    std::uint64_t count) const {
    ImageReader reader(binary, layout_.pointerSize);
    reader.requireTable(address, count, version27GenericMethodRowSize);
    std::vector<Version27GenericMethodRow> result;
    result.reserve(static_cast<std::size_t>(count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(count); ++index) {
        const std::uint64_t row = checkedAdd(address, index * version27GenericMethodRowSize);
        result.push_back({
            reader.i32(row),
            reader.i32(checkedAdd(row, 4)),
            reader.i32(checkedAdd(row, 8)),
            reader.i32(checkedAdd(row, 12))
        });
    }
    return result;
}

std::vector<Version27RgctxEntry> Version27Advanced::readRgctxEntries(
    const BinaryImage& binary,
    std::uint64_t address,
    std::uint64_t count) const {
    ImageReader reader(binary, layout_.pointerSize);
    reader.requireTable(address, count, layout_.rgctxEntrySize);
    std::vector<Version27RgctxEntry> result;
    result.reserve(static_cast<std::size_t>(count));
    for (std::size_t index = 0; index < static_cast<std::size_t>(count); ++index) {
        const std::uint64_t entry = checkedAdd(address, index * layout_.rgctxEntrySize);
        Version27RgctxEntry value;
        value.encoding = layout_.rgctxEncoding;
        if (layout_.rgctxEncoding == Version27RgctxEncoding::InlineKindAndIndex) {
            value.kind = reader.u32(entry);
            value.index = reader.i32(checkedAdd(entry, 4));
        } else {
            value.dataPointer = reader.pointer(entry);
        }
        result.push_back(value);
    }
    return result;
}

Version27TypeBits Version27Advanced::decodeTypeBits(std::uint32_t bits) const noexcept {
    return decodeVersion27TypeBits(layout_.kind, bits);
}

} // namespace il2cpprec
