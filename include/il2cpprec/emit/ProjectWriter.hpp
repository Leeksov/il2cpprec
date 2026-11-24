#pragma once

#include <filesystem>
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

class ProjectWriter {
public:
    explicit ProjectWriter(ProjectWriterOptions options = {});

    void write(
        const std::filesystem::path& outputDirectory,
        const MetadataModel& metadata,
        const std::vector<RecoveredFunction>& functions) const;

    static void write(
        const std::filesystem::path& outputDirectory,
        const MetadataModel& metadata,
        const std::vector<RecoveredFunction>& functions,
        const ProjectWriterOptions& options);

private:
    ProjectWriterOptions options_;
};

} // namespace il2cpprec
