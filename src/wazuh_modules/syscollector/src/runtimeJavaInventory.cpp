#include "runtimeJavaInventory.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "cmdHelper.h"
#include "commonDefs.h"
#include "hashHelper.h"
#include "stringHelper.h"
#include "timeHelper.h"

namespace
{
    constexpr auto DELETED_SUFFIX {" (deleted)"};
    constexpr auto MANIFEST_ENTRY_PATH {"META-INF/MANIFEST.MF"};
    constexpr auto POM_PROPERTIES_SUFFIX {"/pom.properties"};
    constexpr auto NESTED_DISCOVERY_SOURCE {"nested_archive"};
    constexpr auto MAX_NESTED_DEPTH {1U};
    constexpr auto NORMALIZER_SCHEMA_VERSION {"1.0"};
    constexpr auto NORMALIZER_ENV_PATH {"WAZUH_RUNTIME_JAVA_NORMALIZER_PATH"};
    constexpr auto WAZUH_HOME_ENV_PATH {"WAZUH_HOME"};
    constexpr auto NORMALIZER_BINARY_NAME {"wazuh-runtime-java-normalizer"};
    constexpr auto DEFAULT_LINUX_NORMALIZER_PATH {"/var/ossec/bin/wazuh-runtime-java-normalizer"};

    struct ArchiveMetadata final
    {
        std::string groupId;
        std::string artifactId;
        std::string version;
        std::string purl;
        std::string sha1;
        std::string evidenceSource;
        std::string confidence;
        std::string packageType;
    };

    bool isArchivePath(const std::string& path)
    {
        const std::filesystem::path fsPath(path);
        const auto extension = Utils::toLowerCase(fsPath.extension().string());
        return extension == ".jar" || extension == ".war" || extension == ".ear";
    }

    bool isNumeric(const std::string& value)
    {
        return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch)
        {
            return std::isdigit(ch) != 0;
        });
    }

    std::string readFile(const std::filesystem::path& filePath, bool binary = false)
    {
        std::ifstream input(filePath, binary ? std::ios::binary : std::ios::in);

        if (!input.good())
        {
            return {};
        }

        std::ostringstream buffer;
        buffer << input.rdbuf();
        return buffer.str();
    }

    std::vector<std::string> splitLines(const std::string& value)
    {
        std::vector<std::string> lines;
        std::stringstream stream(value);
        std::string line;

        while (std::getline(stream, line))
        {
            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }

            lines.push_back(line);
        }

        return lines;
    }

    std::string shellEscape(const std::string& value)
    {
        std::string escaped;
        escaped.reserve(value.size() + 8);
        escaped.push_back('\'');

        for (const auto character : value)
        {
            if (character == '\'')
            {
                escaped.append("'\\''");
            }
            else
            {
                escaped.push_back(character);
            }
        }

        escaped.push_back('\'');
        return escaped;
    }

    bool hasUnzipSupport()
    {
#if defined(__linux__)
        static const bool available = !Utils::trim(Utils::exec("command -v unzip 2>/dev/null")).empty();
        return available;
#else
        return false;
#endif
    }

    bool isExecutableFile(const std::filesystem::path& filePath)
    {
        std::error_code errorCode;
        const auto status = std::filesystem::status(filePath, errorCode);

        if (errorCode || !std::filesystem::is_regular_file(status))
        {
            return false;
        }

        const auto permissions = status.permissions();
        return (permissions & (std::filesystem::perms::owner_exec |
                               std::filesystem::perms::group_exec |
                               std::filesystem::perms::others_exec)) != std::filesystem::perms::none;
    }

    std::string resolveNormalizerExecutable()
    {
#if defined(__linux__)
        if (const auto* envPath = std::getenv(NORMALIZER_ENV_PATH); envPath && *envPath)
        {
            const std::filesystem::path executablePath(envPath);
            if (isExecutableFile(executablePath))
            {
                return executablePath.lexically_normal().string();
            }
        }

        if (const auto* wazuhHome = std::getenv(WAZUH_HOME_ENV_PATH); wazuhHome && *wazuhHome)
        {
            const std::filesystem::path executablePath =
                std::filesystem::path(wazuhHome) / "bin" / NORMALIZER_BINARY_NAME;
            if (isExecutableFile(executablePath))
            {
                return executablePath.lexically_normal().string();
            }
        }

        const std::filesystem::path defaultExecutablePath {DEFAULT_LINUX_NORMALIZER_PATH};
        if (isExecutableFile(defaultExecutablePath))
        {
            return defaultExecutablePath.lexically_normal().string();
        }

        return Utils::trim(Utils::exec(std::string {"command -v "} + NORMALIZER_BINARY_NAME + " 2>/dev/null"));
#else
        return {};
#endif
    }

    std::vector<std::string> listArchiveEntries(const std::string& archivePath)
    {
        if (!hasUnzipSupport())
        {
            return {};
        }

        return splitLines(Utils::exec("unzip -Z1 " + shellEscape(archivePath) + " 2>/dev/null"));
    }

    std::string readArchiveEntry(const std::string& archivePath, const std::string& entryPath)
    {
        if (!hasUnzipSupport())
        {
            return {};
        }

        return Utils::exec("unzip -p " + shellEscape(archivePath) + " " + shellEscape(entryPath) + " 2>/dev/null");
    }

    std::pair<std::filesystem::path, std::filesystem::path> createTemporaryArchiveFile(const std::string& archiveEntryPath)
    {
        std::error_code errorCode;
        auto baseDirectory = std::filesystem::temp_directory_path(errorCode);

        if (errorCode)
        {
            errorCode.clear();
            baseDirectory = std::filesystem::current_path(errorCode);
        }

        if (errorCode)
        {
            return {};
        }

        for (size_t attempt = 0; attempt < 8; ++attempt)
        {
            const auto token = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" +
                               std::to_string(attempt);
            const auto tempDirectory = baseDirectory / ("wazuh-runtime-java-" + token);

            if (!std::filesystem::create_directories(tempDirectory, errorCode) && errorCode)
            {
                errorCode.clear();
                continue;
            }

            auto outputFile = tempDirectory / std::filesystem::path(archiveEntryPath).filename();
            if (outputFile.extension().empty())
            {
                outputFile += ".jar";
            }

            return {tempDirectory, outputFile};
        }

        return {};
    }

    bool extractArchiveEntryToFile(const std::string& archivePath,
                                   const std::string& entryPath,
                                   const std::filesystem::path& outputFile)
    {
        if (!hasUnzipSupport())
        {
            return false;
        }

        std::error_code errorCode;
        std::filesystem::create_directories(outputFile.parent_path(), errorCode);
        if (errorCode)
        {
            return false;
        }

        const auto status = Utils::exec("unzip -p " + shellEscape(archivePath) + " " + shellEscape(entryPath) +
                                        " > " + shellEscape(outputFile.string()) +
                                        " 2>/dev/null; printf '__STATUS__%d' $?");

        return status.find("__STATUS__0") != std::string::npos && std::filesystem::exists(outputFile);
    }

    std::string executeProcessWithInput(const std::string& executable, const std::string& input)
    {
#if defined(__linux__)
        std::array<int, 2> stdinPipe {-1, -1};
        std::array<int, 2> stdoutPipe {-1, -1};

        if (::pipe(stdinPipe.data()) != 0 || ::pipe(stdoutPipe.data()) != 0)
        {
            if (stdinPipe[0] != -1)
            {
                ::close(stdinPipe[0]);
                ::close(stdinPipe[1]);
            }
            if (stdoutPipe[0] != -1)
            {
                ::close(stdoutPipe[0]);
                ::close(stdoutPipe[1]);
            }
            return {};
        }

        const auto pid = ::fork();
        if (pid == -1)
        {
            ::close(stdinPipe[0]);
            ::close(stdinPipe[1]);
            ::close(stdoutPipe[0]);
            ::close(stdoutPipe[1]);
            return {};
        }

        if (pid == 0)
        {
            ::dup2(stdinPipe[0], STDIN_FILENO);
            ::dup2(stdoutPipe[1], STDOUT_FILENO);
            ::close(stdinPipe[0]);
            ::close(stdinPipe[1]);
            ::close(stdoutPipe[0]);
            ::close(stdoutPipe[1]);
            ::execl(executable.c_str(), executable.c_str(), static_cast<char*>(nullptr));
            _exit(127);
        }

        ::close(stdinPipe[0]);
        ::close(stdoutPipe[1]);

        ssize_t totalWritten {0};
        while (totalWritten < static_cast<ssize_t>(input.size()))
        {
            const auto written = ::write(stdinPipe[1], input.data() + totalWritten, input.size() - totalWritten);
            if (written <= 0)
            {
                break;
            }
            totalWritten += written;
        }
        ::close(stdinPipe[1]);

        std::string output;
        std::array<char, 4096> buffer {};
        while (true)
        {
            const auto bytesRead = ::read(stdoutPipe[0], buffer.data(), buffer.size());
            if (bytesRead <= 0)
            {
                break;
            }
            output.append(buffer.data(), static_cast<size_t>(bytesRead));
        }
        ::close(stdoutPipe[0]);

        int status {0};
        ::waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            return {};
        }

        return output;
#else
        (void)executable;
        (void)input;
        return {};
#endif
    }

    nlohmann::json runNormalizerHelper(const std::string& executable,
                                       const std::vector<RuntimeJavaInventory::JarCandidate>& candidates,
                                       const RuntimeJavaInventory::Discoverer::Logger& logger)
    {
        if (executable.empty() || candidates.empty())
        {
            return nlohmann::json::array();
        }

        auto request = nlohmann::json::object();
        request["schema_version"] = NORMALIZER_SCHEMA_VERSION;
        request["candidates"] = nlohmann::json::array();

        for (const auto& candidate : candidates)
        {
            request["candidates"].push_back({
                {"runtime_path", candidate.runtimePath},
                {"discovery_source", candidate.discoverySource},
                {"is_direct_runtime_target", candidate.isDirectRuntimeTarget}});
        }

        const auto output = executeProcessWithInput(executable, request.dump());

        if (output.empty())
        {
            if (logger)
            {
                logger(LOG_DEBUG, "运行态 Java helper 未返回有效数据，将回退到内置归一化逻辑。");
            }
            return nlohmann::json::array();
        }

        const auto response = nlohmann::json::parse(output, nullptr, false);
        if (response.is_discarded() || !response.contains("components") || !response.at("components").is_array())
        {
            if (logger)
            {
                logger(LOG_DEBUG, "运行态 Java helper 返回格式非法，将回退到内置归一化逻辑。");
            }
            return nlohmann::json::array();
        }

        return response.at("components");
    }

    std::map<std::string, std::string> parseProperties(const std::string& content)
    {
        std::map<std::string, std::string> values;

        for (const auto& rawLine : splitLines(content))
        {
            const auto line = Utils::trim(rawLine);
            if (line.empty() || line.front() == '#' || line.front() == '!')
            {
                continue;
            }

            const auto separator = line.find('=');
            if (separator == std::string::npos)
            {
                continue;
            }

            values[Utils::trim(line.substr(0, separator))] = Utils::trim(line.substr(separator + 1));
        }

        return values;
    }

    std::map<std::string, std::string> parseManifest(const std::string& content)
    {
        std::map<std::string, std::string> values;
        std::vector<std::string> unfoldedLines;
        std::string currentLine;

        for (const auto& line : splitLines(content))
        {
            if (!line.empty() && line.front() == ' ')
            {
                currentLine.append(line.substr(1));
                continue;
            }

            if (!currentLine.empty())
            {
                unfoldedLines.push_back(currentLine);
            }

            currentLine = line;
        }

        if (!currentLine.empty())
        {
            unfoldedLines.push_back(currentLine);
        }

        for (const auto& line : unfoldedLines)
        {
            const auto separator = line.find(':');
            if (separator == std::string::npos)
            {
                continue;
            }

            values[Utils::trim(line.substr(0, separator))] = Utils::trim(line.substr(separator + 1));
        }

        return values;
    }

    std::string buildMavenPurl(const std::string& groupId,
                               const std::string& artifactId,
                               const std::string& version)
    {
        if (groupId.empty() || artifactId.empty() || version.empty())
        {
            return {};
        }

        return "pkg:maven/" + groupId + "/" + artifactId + "@" + version;
    }

    std::string computeFileSha1(const std::string& filePath)
    {
        if (filePath.empty())
        {
            return {};
        }

        std::error_code errorCode;
        if (!std::filesystem::exists(filePath, errorCode) || errorCode)
        {
            return {};
        }

        try
        {
            return Utils::asciiToHex(Utils::hashFile(filePath));
        }
        catch (const std::exception&)
        {
            return {};
        }
    }

    std::string findPomPropertiesEntry(const std::vector<std::string>& entries)
    {
        for (const auto& entry : entries)
        {
            if (Utils::startsWith(entry, "META-INF/maven/") && Utils::endsWith(entry, POM_PROPERTIES_SUFFIX))
            {
                return entry;
            }
        }

        return {};
    }

    ArchiveMetadata resolveArchiveMetadata(const std::string& archivePath, const std::string& componentPathHint)
    {
        ArchiveMetadata metadata;
        const auto entries = archivePath.empty() ? std::vector<std::string> {} : listArchiveEntries(archivePath);

        const auto pomEntry = findPomPropertiesEntry(entries);
        if (!pomEntry.empty())
        {
            const auto properties = parseProperties(readArchiveEntry(archivePath, pomEntry));
            const auto groupIdIt = properties.find("groupId");
            const auto artifactIdIt = properties.find("artifactId");
            const auto versionIt = properties.find("version");

            if (groupIdIt != properties.end())
            {
                metadata.groupId = groupIdIt->second;
            }
            if (artifactIdIt != properties.end())
            {
                metadata.artifactId = artifactIdIt->second;
            }
            if (versionIt != properties.end())
            {
                metadata.version = versionIt->second;
            }

            if (!metadata.artifactId.empty() || !metadata.version.empty() || !metadata.groupId.empty())
            {
                metadata.evidenceSource = "pom.properties";
                metadata.confidence = "high";
            }
        }

        const auto manifest = archivePath.empty() ? std::map<std::string, std::string> {}
                                                  : parseManifest(readArchiveEntry(archivePath, MANIFEST_ENTRY_PATH));
        if (!manifest.empty())
        {
            if (metadata.artifactId.empty())
            {
                if (auto it = manifest.find("Implementation-Title"); it != manifest.end())
                {
                    metadata.artifactId = it->second;
                }
                else if (auto it = manifest.find("Bundle-Name"); it != manifest.end())
                {
                    metadata.artifactId = it->second;
                }
                else if (auto it = manifest.find("Bundle-SymbolicName"); it != manifest.end())
                {
                    auto symbolicName = it->second;
                    const auto directiveSeparator = symbolicName.find(';');
                    if (directiveSeparator != std::string::npos)
                    {
                        symbolicName = symbolicName.substr(0, directiveSeparator);
                    }

                    const auto lastDot = symbolicName.rfind('.');
                    metadata.artifactId = lastDot == std::string::npos ? symbolicName : symbolicName.substr(lastDot + 1);

                    if (metadata.groupId.empty() && lastDot != std::string::npos)
                    {
                        metadata.groupId = symbolicName.substr(0, lastDot);
                    }
                }
            }

            if (metadata.version.empty())
            {
                if (auto it = manifest.find("Implementation-Version"); it != manifest.end())
                {
                    metadata.version = it->second;
                }
                else if (auto it = manifest.find("Bundle-Version"); it != manifest.end())
                {
                    metadata.version = it->second;
                }
                else if (auto it = manifest.find("Specification-Version"); it != manifest.end())
                {
                    metadata.version = it->second;
                }
            }

            if (metadata.groupId.empty())
            {
                if (auto it = manifest.find("Implementation-Vendor-Id"); it != manifest.end())
                {
                    metadata.groupId = it->second;
                }
            }

            if (metadata.evidenceSource.empty() && (!metadata.artifactId.empty() || !metadata.version.empty()))
            {
                metadata.evidenceSource = "manifest";
                metadata.confidence = "medium";
            }
        }

        const auto [artifactIdFromName, versionFromName] =
            RuntimeJavaInventory::Discoverer::inferArtifactAndVersion(componentPathHint);

        if (metadata.artifactId.empty())
        {
            metadata.artifactId = artifactIdFromName;
        }
        if (metadata.version.empty())
        {
            metadata.version = versionFromName;
        }
        if (metadata.evidenceSource.empty())
        {
            metadata.evidenceSource = "filename";
            metadata.confidence = "low";
        }

        metadata.purl = buildMavenPurl(metadata.groupId, metadata.artifactId, metadata.version);
        metadata.sha1 = computeFileSha1(archivePath);
        metadata.packageType = metadata.purl.empty() ? "jar" : "maven";

        return metadata;
    }

    std::string readProcessComm(const int pid)
    {
        auto comm = readFile(std::filesystem::path("/proc") / std::to_string(pid) / "comm");

        while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r'))
        {
            comm.pop_back();
        }

        return comm;
    }

    std::string readProcessCwd(const int pid)
    {
        std::error_code errorCode;
        auto cwd = std::filesystem::read_symlink(std::filesystem::path("/proc") / std::to_string(pid) / "cwd", errorCode);
        return errorCode ? std::string {} : cwd.string();
    }

    std::string readProcessStartTime(const int pid)
    {
        const auto statContent = readFile(std::filesystem::path("/proc") / std::to_string(pid) / "stat");

        if (statContent.empty())
        {
            return {};
        }

        const auto processNameEnd = statContent.rfind(") ");

        if (processNameEnd == std::string::npos)
        {
            return {};
        }

        std::istringstream stream(statContent.substr(processNameEnd + 2));
        std::string token;

        for (size_t index = 0; index < 20 && stream >> token; ++index)
        {
            if (index == 19)
            {
                return token;
            }
        }

        return {};
    }

    std::vector<std::string> splitString(const std::string& value, const char separator)
    {
        std::vector<std::string> parts;
        std::stringstream stream(value);
        std::string item;

        while (std::getline(stream, item, separator))
        {
            if (!item.empty())
            {
                parts.push_back(item);
            }
        }

        return parts;
    }

    std::vector<std::string> expandClasspathEntry(const std::string& entry, const std::string& cwd)
    {
        std::vector<std::string> expandedPaths;
        auto normalizedEntry = RuntimeJavaInventory::Discoverer::normalizeRuntimePath(entry, cwd);

        if (normalizedEntry.empty())
        {
            return expandedPaths;
        }

        std::filesystem::path entryPath(normalizedEntry);

        const bool hasWildcard = !normalizedEntry.empty() && normalizedEntry.back() == '*';

        if (hasWildcard)
        {
            entryPath = entryPath.parent_path();
        }

        std::error_code errorCode;
        const auto status = std::filesystem::status(entryPath, errorCode);

        if (!errorCode && std::filesystem::is_directory(status))
        {
            for (const auto& item : std::filesystem::directory_iterator(entryPath, errorCode))
            {
                if (errorCode)
                {
                    break;
                }

                if (!item.is_regular_file(errorCode))
                {
                    continue;
                }

                const auto candidate = item.path().string();

                if (isArchivePath(candidate))
                {
                    expandedPaths.push_back(item.path().lexically_normal().string());
                }
            }

            return expandedPaths;
        }

        if (isArchivePath(normalizedEntry))
        {
            expandedPaths.push_back(normalizedEntry);
        }

        return expandedPaths;
    }

    bool isJavaProcess(const std::string& processName, const std::vector<std::string>& args)
    {
        const auto loweredProcessName = Utils::toLowerCase(processName);

        if (loweredProcessName == "java" || loweredProcessName == "java.exe")
        {
            return true;
        }

        if (!args.empty())
        {
            const auto executable = Utils::toLowerCase(std::filesystem::path(args.front()).filename().string());
            return executable == "java" || executable == "java.exe";
        }

        return false;
    }

    std::string mergeDiscoverySources(const std::string& currentSources, const std::string& newSource)
    {
        std::set<std::string> sources;

        for (const auto& source : splitString(currentSources, ','))
        {
            sources.insert(source);
        }

        if (!newSource.empty())
        {
            sources.insert(newSource);
        }

        std::ostringstream merged;

        for (auto it = sources.begin(); it != sources.end(); ++it)
        {
            if (it != sources.begin())
            {
                merged << ',';
            }

            merged << *it;
        }

        return merged.str();
    }

    void mergeCandidate(std::map<std::string, RuntimeJavaInventory::JarCandidate>& mergedCandidates,
                        const RuntimeJavaInventory::JarCandidate& candidate)
    {
        if (candidate.runtimePath.empty())
        {
            return;
        }

        auto& target = mergedCandidates[candidate.runtimePath];

        if (target.runtimePath.empty())
        {
            target.runtimePath = candidate.runtimePath;
        }

        target.discoverySource = mergeDiscoverySources(target.discoverySource, candidate.discoverySource);
        target.isDirectRuntimeTarget = target.isDirectRuntimeTarget || candidate.isDirectRuntimeTarget;
    }

    std::vector<RuntimeJavaInventory::JarCandidate> collectCandidatesFromFd(const int pid,
                                                                            const std::string& cwd)
    {
        std::vector<RuntimeJavaInventory::JarCandidate> candidates;
        std::error_code errorCode;
        const auto fdPath = std::filesystem::path("/proc") / std::to_string(pid) / "fd";

        for (const auto& item : std::filesystem::directory_iterator(fdPath, errorCode))
        {
            if (errorCode)
            {
                break;
            }

            const auto target = RuntimeJavaInventory::Discoverer::normalizeRuntimePath(
                                    std::filesystem::read_symlink(item.path(), errorCode).string(), cwd);

            if (errorCode)
            {
                errorCode.clear();
                continue;
            }

            if (isArchivePath(target))
            {
                candidates.push_back({target, "fd", false});
            }
        }

        return candidates;
    }

    std::string buildCommandLine(const std::vector<std::string>& args)
    {
        std::ostringstream commandLine;

        for (size_t index = 0; index < args.size(); ++index)
        {
            if (index > 0)
            {
                commandLine << ' ';
            }

            commandLine << args[index];
        }

        return commandLine.str();
    }

    nlohmann::json buildComponentRecord(const std::string& runtimePath,
                                        const std::string& archivePath,
                                        const std::string& pathInArchive,
                                        const std::string& discoverySource,
                                        const bool isDirectRuntimeTarget,
                                        const bool isNested,
                                        const ArchiveMetadata& metadata)
    {
        nlohmann::json record;
        record["runtime_path"] = runtimePath;
        record["archive_path"] = archivePath;
        record["path_in_archive"] = pathInArchive;
        record["package_type"] = metadata.packageType;
        record["group_id"] = metadata.groupId;
        record["artifact_id"] = metadata.artifactId;
        record["version_"] = metadata.version;
        record["purl"] = metadata.purl;
        record["sha1"] = metadata.sha1;
        record["evidence_source"] = metadata.evidenceSource;
        record["confidence"] = metadata.confidence;
        record["discovery_source"] = discoverySource;
        record["is_direct_runtime_target"] = isDirectRuntimeTarget ? 1 : 0;
        record["is_nested"] = isNested ? 1 : 0;
        record["discovered_at"] = Utils::getCurrentISO8601();
        return record;
    }

    void appendProcessContext(nlohmann::json& record,
                              const int pid,
                              const std::string& processName,
                              const std::string& processStartTime,
                              const std::vector<std::string>& args)
    {
        record["pid"] = std::to_string(pid);
        record["process_name"] = processName;
        record["process_cmdline"] = buildCommandLine(args);
        record["process_start"] = processStartTime;
    }
} // namespace

std::vector<std::string> RuntimeJavaInventory::Discoverer::splitCmdlineBuffer(const std::string& rawBuffer)
{
    std::vector<std::string> arguments;
    size_t start = 0;

    while (start < rawBuffer.size())
    {
        const auto end = rawBuffer.find('\0', start);
        const auto length = (end == std::string::npos) ? rawBuffer.size() - start : end - start;

        if (length > 0)
        {
            arguments.emplace_back(rawBuffer.substr(start, length));
        }

        if (end == std::string::npos)
        {
            break;
        }

        start = end + 1;
    }

    return arguments;
}

std::string RuntimeJavaInventory::Discoverer::normalizeRuntimePath(const std::string& jarPath,
                                                                   const std::string& cwd)
{
    if (jarPath.empty())
    {
        return {};
    }

    auto normalized = jarPath;

    if (normalized.size() > std::strlen(DELETED_SUFFIX) &&
        normalized.compare(normalized.size() - std::strlen(DELETED_SUFFIX), std::strlen(DELETED_SUFFIX), DELETED_SUFFIX) == 0)
    {
        normalized.erase(normalized.size() - std::strlen(DELETED_SUFFIX));
    }

    std::filesystem::path path(normalized);

    if (path.is_relative() && !cwd.empty())
    {
        path = std::filesystem::path(cwd) / path;
    }

    return path.lexically_normal().string();
}

std::vector<RuntimeJavaInventory::JarCandidate> RuntimeJavaInventory::Discoverer::extractCandidatesFromArgs(
    const std::vector<std::string>& args,
    const std::string& cwd)
{
    std::vector<JarCandidate> candidates;

    for (size_t index = 0; index < args.size(); ++index)
    {
        const auto& arg = args[index];

        if ((arg == "-jar") && (index + 1) < args.size())
        {
            const auto runtimePath = normalizeRuntimePath(args[index + 1], cwd);

            if (isArchivePath(runtimePath))
            {
                candidates.push_back({runtimePath, "jar", true});
            }

            ++index;
            continue;
        }

        if ((arg == "-cp" || arg == "-classpath") && (index + 1) < args.size())
        {
            for (const auto& entry : splitString(args[index + 1], ':'))
            {
                for (const auto& expanded : expandClasspathEntry(entry, cwd))
                {
                    candidates.push_back({expanded, "classpath", false});
                }
            }

            ++index;
            continue;
        }
    }

    return candidates;
}

std::pair<std::string, std::string> RuntimeJavaInventory::Discoverer::inferArtifactAndVersion(const std::string& jarPath)
{
    const auto filename = std::filesystem::path(jarPath).stem().string();
    static const std::regex artifactVersionPattern(R"(^(.+)-([0-9][A-Za-z0-9._-]*)$)");
    std::smatch matches;

    if (std::regex_match(filename, matches, artifactVersionPattern) && matches.size() == 3)
    {
        return {matches[1].str(), matches[2].str()};
    }

    return {filename, {}};
}

nlohmann::json RuntimeJavaInventory::Discoverer::inspectArchive(const JarCandidate& candidate)
{
    nlohmann::json components = nlohmann::json::array();

    if (candidate.runtimePath.empty())
    {
        return components;
    }

    const auto directMetadata = resolveArchiveMetadata(candidate.runtimePath, candidate.runtimePath);
    components.push_back(buildComponentRecord(candidate.runtimePath,
                                              std::string {},
                                              std::string {},
                                              candidate.discoverySource,
                                              candidate.isDirectRuntimeTarget,
                                              false,
                                              directMetadata));

    if (!candidate.isDirectRuntimeTarget || !hasUnzipSupport() || MAX_NESTED_DEPTH == 0)
    {
        return components;
    }

    const auto nestedDiscoverySource = mergeDiscoverySources(candidate.discoverySource, NESTED_DISCOVERY_SOURCE);

    for (const auto& entry : listArchiveEntries(candidate.runtimePath))
    {
        if (!isArchivePath(entry) || entry.find('/') == std::string::npos)
        {
            continue;
        }

        const auto [tempDirectory, tempArchiveFile] = createTemporaryArchiveFile(entry);
        if (tempArchiveFile.empty())
        {
            continue;
        }

        const auto cleanup = [&tempDirectory]()
        {
            std::error_code errorCode;
            std::filesystem::remove_all(tempDirectory, errorCode);
        };

        if (!extractArchiveEntryToFile(candidate.runtimePath, entry, tempArchiveFile))
        {
            const auto nestedMetadata = resolveArchiveMetadata(std::string {}, entry);
            components.push_back(buildComponentRecord(candidate.runtimePath,
                                                      candidate.runtimePath,
                                                      entry,
                                                      nestedDiscoverySource,
                                                      false,
                                                      true,
                                                      nestedMetadata));
            cleanup();
            continue;
        }

        const auto nestedMetadata = resolveArchiveMetadata(tempArchiveFile.string(), entry);
        components.push_back(buildComponentRecord(candidate.runtimePath,
                                                  candidate.runtimePath,
                                                  entry,
                                                  nestedDiscoverySource,
                                                  false,
                                                  true,
                                                  nestedMetadata));
        cleanup();
    }

    return components;
}

nlohmann::json RuntimeJavaInventory::Discoverer::collect(const Logger& logger) const
{
    nlohmann::json components = nlohmann::json::array();

#if defined(__linux__)
    const auto normalizerExecutable = resolveNormalizerExecutable();

    if (!normalizerExecutable.empty())
    {
        if (logger)
        {
            logger(LOG_DEBUG,
                   std::string {"运行态 Java 组件采集将优先使用本地 helper 归一化："} + normalizerExecutable);
        }
    }
    else if (!hasUnzipSupport() && logger)
    {
        logger(LOG_DEBUG,
               "未检测到 runtime-java helper 且系统没有 unzip，运行态 Java 组件采集将退化为文件名版本推断。");
    }

    std::error_code errorCode;

    for (const auto& processEntry : std::filesystem::directory_iterator("/proc", errorCode))
    {
        if (errorCode)
        {
            break;
        }

        if (!processEntry.is_directory(errorCode))
        {
            continue;
        }

        const auto pidString = processEntry.path().filename().string();

        if (!isNumeric(pidString))
        {
            continue;
        }

        const auto cmdlineBuffer = readFile(processEntry.path() / "cmdline", true);
        const auto args = splitCmdlineBuffer(cmdlineBuffer);
        const auto pid = std::stoi(pidString);
        const auto processName = readProcessComm(pid);

        if (!isJavaProcess(processName, args))
        {
            continue;
        }

        const auto cwd = readProcessCwd(pid);
        std::map<std::string, JarCandidate> mergedCandidates;

        for (const auto& candidate : extractCandidatesFromArgs(args, cwd))
        {
            mergeCandidate(mergedCandidates, candidate);
        }

        for (const auto& candidate : collectCandidatesFromFd(pid, cwd))
        {
            mergeCandidate(mergedCandidates, candidate);
        }

        if (mergedCandidates.empty())
        {
            continue;
        }

        const auto processStartTime = readProcessStartTime(pid);
        nlohmann::json normalizedComponents = nlohmann::json::array();

        if (!normalizerExecutable.empty())
        {
            std::vector<JarCandidate> batchCandidates;
            batchCandidates.reserve(mergedCandidates.size());

            for (const auto& [_, candidate] : mergedCandidates)
            {
                batchCandidates.push_back(candidate);
            }

            normalizedComponents = runNormalizerHelper(normalizerExecutable, batchCandidates, logger);
        }

        if (normalizedComponents.is_array() && !normalizedComponents.empty())
        {
            for (auto& component : normalizedComponents)
            {
                appendProcessContext(component, pid, processName, processStartTime, args);
                components.push_back(std::move(component));
            }

            continue;
        }

        for (const auto& [_, candidate] : mergedCandidates)
        {
            for (auto& component : inspectArchive(candidate))
            {
                appendProcessContext(component, pid, processName, processStartTime, args);
                components.push_back(std::move(component));
            }
        }
    }
#else
    if (logger)
    {
        logger(LOG_DEBUG, "运行态 Java 组件采集当前仅在 Linux 上启用。当前平台将跳过该采集器。");
    }
#endif

    return components;
}
