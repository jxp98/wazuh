#pragma once

#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "json.hpp"

#include "logging_helper.h"

namespace RuntimeJavaInventory
{
    struct JarCandidate
    {
        std::string runtimePath;
        std::string discoverySource;
        bool isDirectRuntimeTarget {false};
    };

    class Discoverer final
    {
        public:
            using Logger = std::function<void(const modules_log_level_t, const std::string&)>;

            static std::vector<std::string> splitCmdlineBuffer(const std::string& rawBuffer);
            static std::vector<JarCandidate> extractCandidatesFromArgs(const std::vector<std::string>& args,
                                                                       const std::string& cwd);
            static std::pair<std::string, std::string> inferArtifactAndVersion(const std::string& jarPath);
            static std::string normalizeRuntimePath(const std::string& jarPath,
                                                    const std::string& cwd = {});
            static nlohmann::json inspectArchive(const JarCandidate& candidate);

            nlohmann::json collect(const Logger& logger) const;
    };
} // namespace RuntimeJavaInventory
