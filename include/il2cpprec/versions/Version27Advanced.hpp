#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <il2cpprec/Model.hpp>

namespace il2cpprec {

inline constexpr std::size_t version27CodeRegistrationSlots = 15;
inline constexpr std::size_t version27CodeGenModuleSlots = 18;
inline constexpr std::size_t version27GenericMethodRowSize = 16;

enum class Version27Kind {
    V27_1,
    V27_2
};

enum class Version27RgctxEncoding {
    InlineKindAndIndex,
    DataPointer
};

enum class Version27DetectionConfidence {
    Unknown,
    LayoutOnly,
    Inferred,
    Corroborated,
    Explicit
};

struct Version27Slot {
    std::size_t index = 0;
    std::size_t offset = 0;
    std::size_t size = 0;
};

struct Version27TableLayout {
    Version27Slot count;
    Version27Slot pointer;
};

struct Version27RegistrationLayout {
    std::size_t size = 0;
    Version27TableLayout reversePInvokeWrappers;
    Version27TableLayout genericMethodPointers;
    Version27Slot genericAdjustorThunks;
    Version27TableLayout invokerPointers;
    Version27TableLayout unresolvedVirtualCallPointers;
    Version27TableLayout interopData;
    Version27TableLayout windowsRuntimeFactoryTable;
    Version27TableLayout codeGenModules;
};

struct Version27CodeGenModuleLayout {
    std::size_t size = 0;
    Version27Slot moduleName;
    Version27TableLayout methodPointers;
    Version27TableLayout adjustorThunks;
    Version27Slot invokerIndices;
    Version27TableLayout reversePInvokeWrapperIndices;
    Version27TableLayout rgctxRanges;
    Version27TableLayout rgctxs;
    Version27Slot debuggerMetadata;
    Version27Slot customAttributeCacheGenerator;
    Version27Slot moduleInitializer;
    Version27Slot staticConstructorTypeIndices;
    Version27Slot metadataRegistration;
    Version27Slot codeRegistration;
};

struct Version27Layout {
    Version27Kind kind = Version27Kind::V27_1;
    std::size_t pointerSize = 0;
    Version27RegistrationLayout registration;
    Version27CodeGenModuleLayout codeGenModule;
    std::size_t genericMethodRowSize = version27GenericMethodRowSize;
    std::size_t rgctxEntrySize = 0;
    Version27RgctxEncoding rgctxEncoding = Version27RgctxEncoding::InlineKindAndIndex;
    std::size_t invokerArgumentCount = 0;
    bool invokerHasReturnValueArgument = false;
};

struct Version27Registration {
    std::uint64_t address = 0;
    std::uint64_t reversePInvokeWrapperCount = 0;
    std::uint64_t reversePInvokeWrappers = 0;
    std::uint64_t genericMethodPointersCount = 0;
    std::uint64_t genericMethodPointers = 0;
    std::uint64_t genericAdjustorThunks = 0;
    std::uint64_t invokerPointersCount = 0;
    std::uint64_t invokerPointers = 0;
    std::uint64_t unresolvedVirtualCallCount = 0;
    std::uint64_t unresolvedVirtualCallPointers = 0;
    std::uint64_t interopDataCount = 0;
    std::uint64_t interopData = 0;
    std::uint64_t windowsRuntimeFactoryCount = 0;
    std::uint64_t windowsRuntimeFactoryTable = 0;
    std::uint64_t codeGenModulesCount = 0;
    std::uint64_t codeGenModules = 0;
};

struct Version27CodeGenModule {
    std::uint64_t address = 0;
    std::uint64_t moduleName = 0;
    std::uint64_t methodPointerCount = 0;
    std::uint64_t methodPointers = 0;
    std::uint64_t adjustorThunkCount = 0;
    std::uint64_t adjustorThunks = 0;
    std::uint64_t invokerIndices = 0;
    std::uint64_t reversePInvokeWrapperCount = 0;
    std::uint64_t reversePInvokeWrapperIndices = 0;
    std::uint64_t rgctxRangesCount = 0;
    std::uint64_t rgctxRanges = 0;
    std::uint64_t rgctxsCount = 0;
    std::uint64_t rgctxs = 0;
    std::uint64_t debuggerMetadata = 0;
    std::uint64_t customAttributeCacheGenerator = 0;
    std::uint64_t moduleInitializer = 0;
    std::uint64_t staticConstructorTypeIndices = 0;
    std::uint64_t metadataRegistration = 0;
    std::uint64_t codeRegistration = 0;
};

struct Version27GenericMethodRow {
    std::int32_t genericMethodIndex = -1;
    std::int32_t methodIndex = -1;
    std::int32_t invokerIndex = -1;
    std::int32_t adjustorThunkIndex = -1;
};

struct Version27RgctxEntry {
    Version27RgctxEncoding encoding = Version27RgctxEncoding::InlineKindAndIndex;
    std::uint32_t kind = 0;
    std::int32_t index = 0;
    std::uint64_t dataPointer = 0;
};

struct Version27TypeBits {
    std::uint16_t attrs = 0;
    std::uint8_t type = 0;
    std::uint8_t numMods = 0;
    bool byRef = false;
    bool pinned = false;
    bool valueType = false;
};

struct Version27DetectionEvidence {
    std::int32_t rawMetadataVersion = 0;
    double declaredVersion = 0;
    bool registration15Slots = false;
    bool module18Slots = false;
    bool genericMethodRows16 = false;
    std::optional<Version27RgctxEncoding> rgctxEncoding;
    std::optional<bool> typeBitsHaveValueType;
    std::optional<std::size_t> invokerArgumentCount;
};

struct Version27Detection {
    std::optional<Version27Kind> kind;
    double preciseVersion = 0;
    Version27DetectionConfidence confidence = Version27DetectionConfidence::Unknown;
    bool ambiguous = true;
    std::vector<std::string> diagnostics;

    bool resolved() const noexcept;
};

Version27Layout makeVersion27Layout(Version27Kind kind, std::size_t pointerSize);
double version27Number(Version27Kind kind) noexcept;
Version27TypeBits decodeVersion27TypeBits(Version27Kind kind, std::uint32_t bits) noexcept;
Version27Detection detectVersion27(const Version27DetectionEvidence& evidence);
Version27Detection detectVersion27(
    const BinaryImage& binary,
    std::uint64_t codeRegistrationAddress,
    double declaredVersion = 0,
    std::size_t pointerSize = 0);

class Version27Advanced {
public:
    Version27Advanced(Version27Kind kind, std::size_t pointerSize);
    explicit Version27Advanced(Version27Layout layout);

    const Version27Layout& layout() const noexcept { return layout_; }

    Version27Registration readRegistration(const BinaryImage& binary, std::uint64_t address) const;
    Version27CodeGenModule readCodeGenModule(const BinaryImage& binary, std::uint64_t address) const;
    std::vector<Version27GenericMethodRow> readGenericMethodRows(
        const BinaryImage& binary,
        std::uint64_t address,
        std::uint64_t count) const;
    std::vector<Version27RgctxEntry> readRgctxEntries(
        const BinaryImage& binary,
        std::uint64_t address,
        std::uint64_t count) const;
    Version27TypeBits decodeTypeBits(std::uint32_t bits) const noexcept;

private:
    Version27Layout layout_;
};

} // namespace il2cpprec
