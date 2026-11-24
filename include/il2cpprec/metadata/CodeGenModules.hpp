#pragma once

#include <il2cpprec/Model.hpp>

#include <functional>
#include <optional>
#include <string>

namespace il2cpprec {

struct CodeGenAddressBounds {
    uint64_t start = 0;
    uint64_t end = 0;
    bool executable = false;
};

struct CodeGenModulesValidation {
    std::function<std::optional<CodeGenAddressBounds>(uint64_t address)> bounds;
    std::function<void(const std::string& message)> diagnostic;
};

void discoverCodeGenModules(const BinaryImage& binary, MetadataModel& metadata);
void discoverCodeGenModules(const BinaryImage& binary, MetadataModel& metadata,
                            const CodeGenModulesValidation& validation);

} // namespace il2cpprec
