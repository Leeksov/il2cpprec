#pragma once

#include <cstddef>
#include <string>

#include <il2cpprec/Disassembler.hpp>

namespace il2cpprec {
namespace ida {
struct SourceLayoutSelection;
}

struct RuntimeClassLayout {
    bool useLegacyDefaults = true;
    std::size_t elementClassOffset = 0;
    std::size_t staticFieldsOffset = 0;
    std::size_t threadStaticFieldsOffsetFieldOffset = 0;
    std::size_t cctorFinishedOffset = 0;
    std::size_t vtableOffset = 0;
    std::size_t vtableEntrySize = 0;
    std::size_t vtableMethodPointerOffset = 0;
    std::size_t vtableMethodInfoOffset = 0;
    std::size_t virtualMethodPointerOffset = 0;
    bool staticFieldsPresent = true;
    bool threadStaticFieldsPresent = true;
    bool vtablePresent = true;
    bool vtableInline = true;
    bool vtableMethodInfoPresent = true;
    bool virtualMethodPointerPresent = false;
};

struct RuntimeSupportOptions {
    RuntimeClassLayout classLayout;
    std::size_t methodVirtualMethodPointerOffset = 0;
    bool methodVirtualMethodPointerPresent = false;
};

class RuntimeSupportGenerator {
public:
    std::string generate(Architecture architecture) const;
    std::string generate(Architecture architecture, const RuntimeSupportOptions& options) const;
    std::string generate(const ida::SourceLayoutSelection& selection, const RuntimeSupportOptions& options = {}) const;
};

std::string generateRuntimeSupport(Architecture architecture);
std::string generateRuntimeSupport(Architecture architecture, const RuntimeSupportOptions& options);
std::string generateRuntimeSupport(const ida::SourceLayoutSelection& selection, const RuntimeSupportOptions& options = {});

} // namespace il2cpprec
