// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mojo_service_manager/daemon/service_policy_loader.h"
#include "mojo_service_manager/daemon/service_policy_test_util.h"

namespace chromeos {
namespace mojo_service_manager {
namespace {

class ServicePolicyLoaderTest : public ::testing::Test {
 public:
  void SetUp() override { EXPECT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  const base::FilePath& root_dir() { return temp_dir_.GetPath(); }

  base::FilePath CreateTestFile(const std::string& content) {
    return CreateTestFileInDirectory(root_dir(), content);
  }

  base::FilePath CreateTestFileInDirectory(const base::FilePath& dir,
                                           const std::string& content) {
    base::FilePath file;
    CHECK(CreateDirectory(dir));
    CHECK(CreateTemporaryFileInDir(dir, &file));
    CHECK(base::WriteFile(file, content));
    return file;
  }

 private:
  base::ScopedTempDir temp_dir_;
};

TEST_F(ServicePolicyLoaderTest, Parse) {
  {
    // Test a general policy file.
    auto policy_map = ParseServicePolicyFromString(R"JSON(
        [
          // Comment
          {
            "identity": "user_a",
            "request": [
              "FooService",
              "BarService",
            ]
          },
          {
            "identity": "user_b",
            "own": [
              "FooService",
            ],
          }
        ]
      )JSON");
    EXPECT_TRUE(policy_map);
    EXPECT_EQ(policy_map.value(), CreateServicePolicyMapForTest(
                                      {{"FooService", {"user_b", {"user_a"}}},
                                       {"BarService", {"", {"user_a"}}}}));
  }
  {
    // Test multiple rules can be merged.
    auto policy_map = ParseServicePolicyFromString(R"JSON(
        [
          {"identity": "user_a", "request": [ "FooService" ]},
          {"identity": "user_a", "own": [ "FooService" ]},
          {"identity": "user_b", "request": [ "FooService" ]},
        ]
      )JSON");
    EXPECT_TRUE(policy_map);
    EXPECT_EQ(policy_map.value(),
              CreateServicePolicyMapForTest(
                  {{"FooService", {"user_a", {"user_a", "user_b"}}}}));
  }
}

TEST_F(ServicePolicyLoaderTest, Invalid) {
  // Policy list should be a list, not dict.
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      {}
    )JSON"));
  // Policy should be a dict, not int.
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [42]
    )JSON"));
  // Found an unexpected field.
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [{"identity": "user_a", "own":["ServiceA"], "unexpected":[]}]
    )JSON"));
  // Identity should be a string, not dict.
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [{"identity":{}, "own":["ServiceA"], "request":["ServiceA"]}]
    )JSON"));
  // No identity.
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [{"own":["ServiceA"], "request":["ServiceA"]}]
    )JSON"));
  // Own/request should be a list, not dict.
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [{"identity":"user_a", "own":{}, "request":["ServiceA"]}]
    )JSON"));
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [{"identity":"user_a", "own":["ServiceA"], "request":{}}]
    )JSON"));
  // Service name should be a string, not dict.
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [{"identity":"user_a", "own":[{}], "request":["ServiceA"]}]
    )JSON"));
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [{"identity":"user_a", "own":["ServiceA"], "request":[{}]}]
    )JSON"));
  // Cannot own "ServiceA" twice.
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [{"identity":"user_a", "own":["ServiceA", "ServiceA"]}]
    )JSON"));
  EXPECT_FALSE(ParseServicePolicyFromString(R"JSON(
      [
        {"identity":"user_a", "own":["ServiceA"]},
        {"identity":"user_b", "own":["ServiceA"]}
      ]
    )JSON"));
}

TEST_F(ServicePolicyLoaderTest, LoadFile) {
  // The last rule should fail(no identity field) and the whole file should not
  // be loaded.
  EXPECT_FALSE(LoadServicePolicyFile(CreateTestFile(R"JSON(
      [
        {"identity":"user_a","own":["ServiceA"],"request":["ServiceA"]},
        {"identity":"user_b","own":["ServiceB"],"request":["ServiceB"]},
        {}
      ]
    )JSON")));
  auto policy_map = LoadServicePolicyFile(CreateTestFile(R"JSON(
      [
        {"identity":"user_c","own":["ServiceC"],"request":["ServiceC"]},
        {"identity":"user_d","own":["ServiceD"],"request":["ServiceD"]},
      ]
    )JSON"));
  EXPECT_TRUE(policy_map);
  EXPECT_EQ(policy_map.value(), CreateServicePolicyMapForTest({
                                    {"ServiceC", {"user_c", {"user_c"}}},
                                    {"ServiceD", {"user_d", {"user_d"}}},
                                }));
}

TEST_F(ServicePolicyLoaderTest, LoadDirectory) {
  CreateTestFile(R"JSON(
      [
        {"identity":"user_a","own":["ServiceA"],"request":["ServiceA"]},
        {"identity":"user_b","own":["ServiceB"],"request":["ServiceB"]},
      ]
    )JSON");
  CreateTestFile(R"JSON(
      [
        {"identity":"user_c","request":["ServiceA"]},
        {"identity":"user_b","own":["ServiceC"],"request":["ServiceC"]},
      ]
    )JSON");

  ServicePolicyMap policy_map;
  EXPECT_TRUE(LoadAllServicePolicyFileFromDirectory(root_dir(), &policy_map));
  EXPECT_EQ(policy_map, CreateServicePolicyMapForTest({
                            {"ServiceA", {"user_a", {"user_a", "user_c"}}},
                            {"ServiceB", {"user_b", {"user_b"}}},
                            {"ServiceC", {"user_b", {"user_b"}}},
                        }));

  // Won't be loaded because the last rule doesn't have identity field.
  CreateTestFile(R"JSON(
      [
        {"identity":"user_d","own":["ServiceD"],"request":["ServiceD"]},
        {}
      ]
    )JSON");
  // False because a file cannot be loaded.
  EXPECT_FALSE(LoadAllServicePolicyFileFromDirectory(root_dir(), &policy_map));
  EXPECT_EQ(policy_map, CreateServicePolicyMapForTest({
                            {"ServiceA", {"user_a", {"user_a", "user_c"}}},
                            {"ServiceB", {"user_b", {"user_b"}}},
                            {"ServiceC", {"user_b", {"user_b"}}},
                        }));

  // Test load one more file and merge into current policy map.
  CreateTestFile(R"JSON(
      [
        {"identity":"user_e","own":["ServiceE"],"request":["ServiceE"]},
      ]
    )JSON");
  // False because a file cannot be loaded.
  EXPECT_FALSE(LoadAllServicePolicyFileFromDirectory(root_dir(), &policy_map));
  EXPECT_EQ(policy_map, CreateServicePolicyMapForTest({
                            {"ServiceA", {"user_a", {"user_a", "user_c"}}},
                            {"ServiceB", {"user_b", {"user_b"}}},
                            {"ServiceC", {"user_b", {"user_b"}}},
                            {"ServiceE", {"user_e", {"user_e"}}},
                        }));
}

TEST_F(ServicePolicyLoaderTest, LoadDirectoryMergeFail) {
  // Load will fail because "ServiceA" is owned twice.
  CreateTestFile(R"JSON(
      [
        {"identity":"user_a","own":["ServiceA"],"request":["ServiceA"]},
      ]
    )JSON");
  CreateTestFile(R"JSON(
      [
        {"identity":"user_a","own":["ServiceA"],"request":["ServiceA"]},
      ]
    )JSON");

  ServicePolicyMap policy_map;
  EXPECT_FALSE(LoadAllServicePolicyFileFromDirectory(root_dir(), &policy_map));
}

TEST_F(ServicePolicyLoaderTest, LoadDirectories) {
  const auto dir_a = root_dir().Append("a");
  const auto dir_b = root_dir().Append("b");
  CreateTestFileInDirectory(dir_a, R"JSON(
      [
        {"identity":"user_a","own":["ServiceA"],"request":["ServiceA"]},
      ]
    )JSON");
  CreateTestFileInDirectory(dir_b, R"JSON(
      [
        {"identity":"user_b","own":["ServiceB"],"request":["ServiceB"]},
      ]
    )JSON");
  ServicePolicyMap policy_map;
  EXPECT_TRUE(
      LoadAllServicePolicyFileFromDirectories({dir_a, dir_b}, &policy_map));
  EXPECT_EQ(policy_map, CreateServicePolicyMapForTest({
                            {"ServiceA", {"user_a", {"user_a"}}},
                            {"ServiceB", {"user_b", {"user_b"}}},
                        }));
}

TEST_F(ServicePolicyLoaderTest, LoadDirectoriesMergeFail) {
  // Load will fail because "ServiceA" is owned twice.
  const auto dir_a = root_dir().Append("a");
  const auto dir_b = root_dir().Append("b");
  CreateTestFileInDirectory(dir_a, R"JSON(
      [
        {"identity":"user_a","own":["ServiceA"],"request":["ServiceA"]},
      ]
    )JSON");
  CreateTestFileInDirectory(dir_b, R"JSON(
      [
        {"identity":"user_b","own":["ServiceA"],"request":["ServiceA"]},
      ]
    )JSON");

  ServicePolicyMap policy_map;
  EXPECT_FALSE(
      LoadAllServicePolicyFileFromDirectories({dir_a, dir_b}, &policy_map));
}

TEST_F(ServicePolicyLoaderTest, LoadDirectoriesKeepLoadingWhenFail) {
  const auto dir_a = root_dir().Append("a");
  const auto dir_b = root_dir().Append("b");
  // Will fail because it is not a list.
  CreateTestFileInDirectory(dir_a, R"JSON(
      {}
    )JSON");
  // Loads "b" even if fails to load "a".
  CreateTestFileInDirectory(dir_b, R"JSON(
      [
        {"identity":"user_b","own":["ServiceB"],"request":["ServiceB"]},
      ]
    )JSON");

  ServicePolicyMap policy_map;
  EXPECT_FALSE(
      LoadAllServicePolicyFileFromDirectories({dir_a, dir_b}, &policy_map));
  EXPECT_EQ(policy_map, CreateServicePolicyMapForTest({
                            {"ServiceB", {"user_b", {"user_b"}}},
                        }));
}

}  // namespace
}  // namespace mojo_service_manager
}  // namespace chromeos
