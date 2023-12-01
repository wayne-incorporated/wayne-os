// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <brillo/map_utils.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/json/json_reader.h>
#include <base/strings/stringprintf.h>
#include <base/values.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "runtime_probe/component_category.h"
#include "runtime_probe/functions/sysfs.h"
#include "runtime_probe/probe_config.h"

namespace runtime_probe {

namespace {

using ::testing::NiceMock;

constexpr char kConfigName[] = "probe_config.json";
constexpr char kConfigHash[] = "14127A36F3A2509343AF7F19387537F608B07EE1";

base::FilePath GetTestDataPath() {
  char* src_env = std::getenv("SRC");
  CHECK(src_env != nullptr)
      << "Expect to have the envvar |SRC| set when testing.";
  return base::FilePath(src_env).Append("testdata");
}

class MockComponentCategory : public ComponentCategory {
 public:
  MOCK_METHOD(base::Value::List, Eval, (), (const, override));
};

class ProbeConfigTest : public ::testing::Test {
 protected:
  // Set a mocked category that would return |category_eval_result| on
  // calling ComponentCategory::Eval() for |probe_config|.
  void SetProbeConfigCategory(ProbeConfig& probe_config,
                              const std::string& category_name,
                              const std::string& category_eval_result) {
    auto eval_result = base::JSONReader::Read(category_eval_result);
    auto category = std::make_unique<NiceMock<MockComponentCategory>>();
    ON_CALL(*category, Eval).WillByDefault([&category_eval_result]() {
      auto eval_result = base::JSONReader::Read(category_eval_result);
      return std::move(eval_result->GetList());
    });
    probe_config.SetCategoryForTesting(category_name, std::move(category));
  }
};

}  // namespace

TEST_F(ProbeConfigTest, LoadConfig) {
  const char* config_content = R"({
    "sysfs_battery": {
      "generic": {
        "eval": {
          "sysfs": {
            "dir_path": "/sys/class/power_supply/BAT0",
            "keys": ["model_name", "charge_full_design", "cycle_count"]
          }
        },
        "keys": [],
        "expect": {},
        "information": {}
      }
    }
  })";
  auto dict_value = base::JSONReader::Read(config_content);

  EXPECT_TRUE(dict_value.has_value());

  auto probe_config = ProbeConfig::FromValue(*dict_value);

  EXPECT_TRUE(probe_config);

  EXPECT_THAT(brillo::GetMapKeys(probe_config->category_),
              ::testing::UnorderedElementsAre("sysfs_battery"));

  const auto& category = probe_config->category_["sysfs_battery"];

  EXPECT_EQ(category->category_name_, "sysfs_battery");
  EXPECT_THAT(brillo::GetMapKeys(category->component_),
              ::testing::UnorderedElementsAre("generic"));

  const auto& probe_statement = category->component_["generic"];

  EXPECT_EQ(probe_statement->component_name_, "generic");
  EXPECT_EQ(probe_statement->key_.size(), 0);
  EXPECT_NE(probe_statement->expect_, nullptr);
  EXPECT_EQ(probe_statement->information_->GetDict().size(), 0);
  EXPECT_NE(probe_statement->probe_function_, nullptr);

  const SysfsFunction* probe_function =
      dynamic_cast<SysfsFunction*>(probe_statement->probe_function_.get());

  EXPECT_NE(probe_function, nullptr);
}

TEST_F(ProbeConfigTest, FromFileWithRelativePath) {
  const auto rel_file_path = GetTestDataPath().Append(kConfigName);
  const auto abs_file_path = base::MakeAbsoluteFilePath(rel_file_path);

  const auto probe_config = ProbeConfig::FromFile(rel_file_path);
  EXPECT_TRUE(probe_config);
  EXPECT_EQ(probe_config->path(), abs_file_path);
  EXPECT_EQ(probe_config->checksum(), kConfigHash);
}

TEST_F(ProbeConfigTest, FromFileWithAbsolutePath) {
  const auto rel_file_path = GetTestDataPath().Append(kConfigName);
  const auto abs_file_path = base::MakeAbsoluteFilePath(rel_file_path);

  const auto probe_config = ProbeConfig::FromFile(abs_file_path);
  EXPECT_TRUE(probe_config);
  EXPECT_EQ(probe_config->path(), abs_file_path);
  EXPECT_EQ(probe_config->checksum(), kConfigHash);
}

TEST_F(ProbeConfigTest, FromFileWithMissingFile) {
  const auto probe_config =
      ProbeConfig::FromFile(base::FilePath{"missing_file.json"});
  EXPECT_FALSE(probe_config);
}

TEST_F(ProbeConfigTest, FromFileWithInvalidFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  const base::FilePath rel_path{"invalid_config.json"};
  const char invalid_probe_config[] = "foo\nbar";
  PCHECK(WriteFile(temp_dir.GetPath().Append(rel_path), invalid_probe_config));

  const auto probe_config = ProbeConfig::FromFile(rel_path);
  EXPECT_FALSE(probe_config);
}

TEST_F(ProbeConfigTest, FromFileWithSymbolicLink) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  const auto rel_file_path = GetTestDataPath().Append(kConfigName);
  const auto abs_file_path = base::MakeAbsoluteFilePath(rel_file_path);
  const auto symlink_config_path = temp_dir.GetPath().Append("config.json");
  PCHECK(base::CreateSymbolicLink(abs_file_path, symlink_config_path));

  const auto probe_config = ProbeConfig::FromFile(symlink_config_path);
  EXPECT_TRUE(probe_config);
  EXPECT_EQ(probe_config->path(), abs_file_path);
  EXPECT_EQ(probe_config->checksum(), kConfigHash);
}

TEST_F(ProbeConfigTest, Eval) {
  auto dict_value = base::JSONReader::Read("{}");
  auto probe_config = ProbeConfig::FromValue(*dict_value);
  EXPECT_TRUE(probe_config);

  const std::string eval_content_1 = R"([
    {
      "name": "component_1",
      "values": {
        "field_1": "value_1"
      }
    }
  ])";
  const std::string eval_content_2 = R"([
    {
      "name": "component_2",
      "values": {
        "field_2": "value_2"
      }
    }
  ])";
  SetProbeConfigCategory(*probe_config, "category_1", eval_content_1);
  SetProbeConfigCategory(*probe_config, "category_2", eval_content_2);

  auto ans = base::JSONReader::Read(base::StringPrintf(R"({
    "category_1": %s,
    "category_2": %s
  })",
                                                       eval_content_1.c_str(),
                                                       eval_content_2.c_str()));
  auto res = probe_config->Eval();
  EXPECT_EQ(res, ans);
}

TEST_F(ProbeConfigTest, EvalWithDefinedCategory) {
  auto dict_value = base::JSONReader::Read("{}");
  auto probe_config = ProbeConfig::FromValue(*dict_value);
  EXPECT_TRUE(probe_config);

  const std::string eval_content_1 = R"([
    {
      "name": "component_1",
      "values": {
        "field_1": "value_1"
      }
    }
  ])";
  const std::string eval_content_2 = R"([
    {
      "name": "component_2",
      "values": {
        "field_2": "value_2"
      }
    }
  ])";
  SetProbeConfigCategory(*probe_config, "category_1", eval_content_1);
  SetProbeConfigCategory(*probe_config, "category_2", eval_content_2);

  std::vector<std::string> categories{"category_1"};
  // The result should contain only given categories.
  auto ans = base::JSONReader::Read(base::StringPrintf(R"({
    "category_1": %s
  })",
                                                       eval_content_1.c_str()));
  auto res = probe_config->Eval(categories);
  EXPECT_EQ(res, ans);
}

TEST_F(ProbeConfigTest, EvalWithUndefinedCategory) {
  auto dict_value = base::JSONReader::Read("{}");
  auto probe_config = ProbeConfig::FromValue(*dict_value);
  EXPECT_TRUE(probe_config);

  const std::string eval_content_1 = R"([
    {
      "name": "component_1",
      "values": {
        "field_1": "value_1"
      }
    }
  ])";
  SetProbeConfigCategory(*probe_config, "category_1", eval_content_1);

  std::vector<std::string> categories{"category_1", "undefined_category"};
  // The result should not contain "undefined_category".
  auto ans = base::JSONReader::Read(base::StringPrintf(R"({
    "category_1": %s
  })",
                                                       eval_content_1.c_str()));
  auto res = probe_config->Eval(categories);
  EXPECT_EQ(res, ans);
}

TEST_F(ProbeConfigTest, GetComponentCategory) {
  auto dict_value = base::JSONReader::Read("{}");
  auto probe_config = ProbeConfig::FromValue(*dict_value);
  EXPECT_TRUE(probe_config);

  const std::string eval_content_1 = R"([
    {
      "name": "component_1",
      "values": {
        "field_1": "value_1"
      }
    }
  ])";
  SetProbeConfigCategory(*probe_config, "category_1", eval_content_1);

  auto ans = base::JSONReader::Read(eval_content_1);
  auto category = probe_config->GetComponentCategory("category_1");
  EXPECT_NE(category, nullptr);
  EXPECT_EQ(category->Eval(), ans);
}

TEST_F(ProbeConfigTest, GetComponentCategoryWithUndefinedCategory) {
  auto dict_value = base::JSONReader::Read("{}");
  auto probe_config = ProbeConfig::FromValue(*dict_value);
  EXPECT_TRUE(probe_config);

  const std::string eval_content_1 = R"([
    {
      "name": "component_1",
      "values": {
        "field_1": "value_1"
      }
    }
  ])";
  SetProbeConfigCategory(*probe_config, "category_1", eval_content_1);

  auto undefined_category =
      probe_config->GetComponentCategory("undefined_category");
  EXPECT_EQ(undefined_category, nullptr);
}

}  // namespace runtime_probe
