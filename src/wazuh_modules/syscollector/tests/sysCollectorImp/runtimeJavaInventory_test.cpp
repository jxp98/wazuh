#include <gtest/gtest.h>

#include "runtimeJavaInventory.hpp"

TEST(RuntimeJavaInventoryTest, splitCmdlineBufferParsesNullSeparatedArguments)
{
    const std::string rawBuffer {std::string("java\0-jar\0app.jar\0", 18)};
    const auto arguments = RuntimeJavaInventory::Discoverer::splitCmdlineBuffer(rawBuffer);

    ASSERT_EQ(arguments.size(), 3U);
    EXPECT_EQ(arguments[0], "java");
    EXPECT_EQ(arguments[1], "-jar");
    EXPECT_EQ(arguments[2], "app.jar");
}

TEST(RuntimeJavaInventoryTest, extractCandidatesFromArgsCollectsJarAndClasspathEntries)
{
    const std::vector<std::string> arguments
    {
        "/usr/bin/java",
        "-jar",
        "app/demo-app-1.2.3.jar",
        "-cp",
        "lib/alpha-1.0.jar:lib/beta.jar"
    };

    const auto candidates = RuntimeJavaInventory::Discoverer::extractCandidatesFromArgs(arguments, "/srv/runtime");

    ASSERT_EQ(candidates.size(), 3U);
    EXPECT_EQ(candidates[0].runtimePath, "/srv/runtime/app/demo-app-1.2.3.jar");
    EXPECT_TRUE(candidates[0].isDirectRuntimeTarget);
    EXPECT_EQ(candidates[0].discoverySource, "jar");
    EXPECT_EQ(candidates[1].runtimePath, "/srv/runtime/lib/alpha-1.0.jar");
    EXPECT_FALSE(candidates[1].isDirectRuntimeTarget);
    EXPECT_EQ(candidates[2].runtimePath, "/srv/runtime/lib/beta.jar");
}

TEST(RuntimeJavaInventoryTest, inferArtifactAndVersionParsesCommonJarName)
{
    const auto [artifactId, version] = RuntimeJavaInventory::Discoverer::inferArtifactAndVersion(
                                          "/opt/app/lib/spring-core-5.3.30.jar");

    EXPECT_EQ(artifactId, "spring-core");
    EXPECT_EQ(version, "5.3.30");
}

TEST(RuntimeJavaInventoryTest, normalizeRuntimePathStripsDeletedSuffix)
{
    const auto normalizedPath = RuntimeJavaInventory::Discoverer::normalizeRuntimePath(
                                    "/opt/app/lib/log4j-core-2.17.2.jar (deleted)");

    EXPECT_EQ(normalizedPath, "/opt/app/lib/log4j-core-2.17.2.jar");
}

TEST(RuntimeJavaInventoryTest, inspectArchiveUsesPomPropertiesWhenAvailable)
{
    const RuntimeJavaInventory::JarCandidate candidate {
        .runtimePath = "src/wazuh_modules/syscollector/tests/sysCollectorImp/data/log4j-core-2.17.2.jar",
        .discoverySource = "classpath",
        .isDirectRuntimeTarget = false};

    const auto components = RuntimeJavaInventory::Discoverer::inspectArchive(candidate);

    ASSERT_EQ(components.size(), 1U);
    EXPECT_EQ(components[0]["group_id"], "org.apache.logging.log4j");
    EXPECT_EQ(components[0]["artifact_id"], "log4j-core");
    EXPECT_EQ(components[0]["version_"], "2.17.2");
    EXPECT_EQ(components[0]["purl"], "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.2");
    EXPECT_EQ(components[0]["sha1"], "52fdcc7402c7b5c82f32a17b11f4d5874b560e38");
    EXPECT_EQ(components[0]["evidence_source"], "pom.properties");
    EXPECT_EQ(components[0]["confidence"], "high");
    EXPECT_EQ(components[0]["package_type"], "maven");
}

TEST(RuntimeJavaInventoryTest, inspectArchiveFallsBackToManifestWhenPomMissing)
{
    const RuntimeJavaInventory::JarCandidate candidate {
        .runtimePath = "src/wazuh_modules/syscollector/tests/sysCollectorImp/data/custom-app.jar",
        .discoverySource = "jar",
        .isDirectRuntimeTarget = true};

    const auto components = RuntimeJavaInventory::Discoverer::inspectArchive(candidate);

    ASSERT_EQ(components.size(), 1U);
    EXPECT_EQ(components[0]["artifact_id"], "custom-app");
    EXPECT_EQ(components[0]["version_"], "1.4.7");
    EXPECT_EQ(components[0]["sha1"], "c82fe3eaf49fe05c30d93f1f7a0ed4aa1acbe207");
    EXPECT_EQ(components[0]["evidence_source"], "manifest");
    EXPECT_EQ(components[0]["confidence"], "medium");
    EXPECT_EQ(components[0]["package_type"], "jar");
}

TEST(RuntimeJavaInventoryTest, inspectArchiveCollectsNestedSpringBootLibraries)
{
    const RuntimeJavaInventory::JarCandidate candidate {
        .runtimePath = "src/wazuh_modules/syscollector/tests/sysCollectorImp/data/demo-app-1.0.0.jar",
        .discoverySource = "jar",
        .isDirectRuntimeTarget = true};

    const auto components = RuntimeJavaInventory::Discoverer::inspectArchive(candidate);

    ASSERT_EQ(components.size(), 3U);
    EXPECT_EQ(components[0]["group_id"], "com.example");
    EXPECT_EQ(components[0]["artifact_id"], "demo-app");
    EXPECT_EQ(components[0]["version_"], "1.0.0");
    EXPECT_EQ(components[0]["sha1"], "42b9080d73f6714d8185e4174251d95087e7d326");

    ASSERT_EQ(components[1]["archive_path"], candidate.runtimePath);
    EXPECT_EQ(components[1]["path_in_archive"], "BOOT-INF/lib/log4j-core-2.14.1.jar");
    EXPECT_EQ(components[1]["group_id"], "org.apache.logging.log4j");
    EXPECT_EQ(components[1]["artifact_id"], "log4j-core");
    EXPECT_EQ(components[1]["version_"], "2.14.1");
    EXPECT_EQ(components[1]["sha1"], "c5a52d75b03c4d197b35446d5cd0e7f85a8e986b");
    EXPECT_EQ(components[1]["is_nested"], 1);
    EXPECT_NE(components[1]["discovery_source"].get<std::string>().find("nested_archive"), std::string::npos);

    ASSERT_EQ(components[2]["archive_path"], candidate.runtimePath);
    EXPECT_EQ(components[2]["path_in_archive"], "BOOT-INF/lib/spring-core-5.3.17.jar");
    EXPECT_EQ(components[2]["group_id"], "org.springframework");
    EXPECT_EQ(components[2]["artifact_id"], "spring-core");
    EXPECT_EQ(components[2]["version_"], "5.3.17");
    EXPECT_EQ(components[2]["sha1"], "50a151700885104778a7712d2488efeb77f9908b");
    EXPECT_EQ(components[2]["is_nested"], 1);
}
