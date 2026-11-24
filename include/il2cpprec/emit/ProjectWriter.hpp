#pragma once

#include <cstddef>
#include <filesystem>
#include <cstdint>
#include <string>
#include <vector>

#include <il2cpprec/IR.hpp>
#include <il2cpprec/Model.hpp>

namespace il2cpprec {

struct ProjectWriterOptions {
    std::string projectName = "Il2CppRecovered";
    std::string targetFramework = "netstandard2.1";
    std::vector<std::string> assemblyReferences;
    // Empty means all images. Types without type or method image evidence are kept conservatively.
    std::vector<std::string> includedImages;
};

enum class ProjectMethodBodyStatus {
    Supported,
    Partial,
    Unsupported,
    DeclarationOnly,
    Omitted
};

struct ProjectMethodEmission {
    uint64_t address = 0;
    std::string name;
    ProjectMethodBodyStatus status = ProjectMethodBodyStatus::Unsupported;
    std::string reason;
    bool declarationPartial = false;
};

struct ProjectWriteReport {
    size_t supported = 0;
    size_t partial = 0;
    size_t unsupported = 0;
    size_t declarationOnly = 0;
    size_t omitted = 0;
    std::vector<ProjectMethodEmission> methods;
};

class ProjectWriter {
public:
    explicit ProjectWriter(ProjectWriterOptions options = {});

    ProjectWriteReport write(
        const std::filesystem::path& outputDirectory,
        const MetadataModel& metadata,
        const std::vector<RecoveredFunction>& functions) const;

    static ProjectWriteReport write(
        const std::filesystem::path& outputDirectory,
        const MetadataModel& metadata,
        const std::vector<RecoveredFunction>& functions,
        const ProjectWriterOptions& options);

private:
    ProjectWriterOptions options_;
};

} // namespace il2cpprec
