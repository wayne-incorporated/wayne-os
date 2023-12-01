// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/config.h"

#include <utility>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "arc/setup/arc_setup_util.h"  // for WriteToFile()

namespace arc {

namespace {

constexpr char kValidJsonFile[] =
    "{\n"
    "  \"ARC_TEST_INT\":42,\n"
    "  \"ARC_TEST_STR\":\"42\",\n"
    "  \"ARC_TEST_BOOL\":true\n"
    "}\n";

constexpr char kInvalidJsonFile[] =
    "{\n"
    "  \"ARC_TEST_INT\":42,\n"
    "}\n";

TEST(Config, TestGetInt) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_TRUE(env->SetVar("ARC_TEST_INT", "43"));

  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath file(temp_directory.GetPath().Append("file"));

  // Try to parse a valid env file.
  ASSERT_TRUE(WriteToFile(file, 0700, kValidJsonFile));
  Config config(file, std::move(env));
  int var = 0;
  EXPECT_TRUE(config.GetInt("ARC_TEST_INT", &var));
  EXPECT_EQ(42, var);  // not 43. The variable in |env| should be ignored.
  // Does the same with -OrDie().
  EXPECT_EQ(42, config.GetIntOrDie("ARC_TEST_INT"));

  // Verify that type mismatches are caught.
  EXPECT_FALSE(config.GetInt("ARC_TEST_STR", &var));
  EXPECT_FALSE(config.GetInt("ARC_TEST_BOOL", &var));
  EXPECT_FALSE(config.GetInt("ARC_NONEXISTENT", &var));

  EXPECT_DEATH(config.GetIntOrDie("ARC_TEST_STR"), ".*");
  EXPECT_DEATH(config.GetIntOrDie("ARC_TEST_BOOL"), ".*");
  EXPECT_DEATH(config.GetIntOrDie("ARC_NONEXISTENT"), ".*");
}

TEST(Config, TestGetIntFallback) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_TRUE(env->SetVar("ARC_TEST_INT_FALLBACK_1", "42"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_INT_FALLBACK_2", "0"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_INT_FALLBACK_3", "-42"));
  // Invalid values.
  ASSERT_TRUE(env->SetVar("ARC_TEST_INT_FALLBACK_4", "1a"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_INT_FALLBACK_5", "a1"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_INT_FALLBACK_6", "0xff"));

  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath file(temp_directory.GetPath().Append("file"));

  // Try to parse a valid env file.
  ASSERT_TRUE(WriteToFile(file, 0700, kValidJsonFile));
  Config config(file, std::move(env));
  int var;
  // Since JSON does not define ARC_TEST_INT_FALLBACK_*, |env| should be read.
  EXPECT_TRUE(config.GetInt("ARC_TEST_INT_FALLBACK_1", &var));
  EXPECT_EQ(42, var);
  EXPECT_TRUE(config.GetInt("ARC_TEST_INT_FALLBACK_2", &var));
  EXPECT_EQ(0, var);
  EXPECT_TRUE(config.GetInt("ARC_TEST_INT_FALLBACK_3", &var));
  EXPECT_EQ(-42, var);

  EXPECT_FALSE(config.GetInt("ARC_TEST_INT_FALLBACK_4", &var));
  EXPECT_FALSE(config.GetInt("ARC_TEST_INT_FALLBACK_5", &var));
  EXPECT_FALSE(config.GetInt("ARC_TEST_INT_FALLBACK_6", &var));
}

TEST(Config, TestGetBool) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL", "false"));

  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath file(temp_directory.GetPath().Append("file"));

  // Try to parse a valid env file.
  ASSERT_TRUE(WriteToFile(file, 0700, kValidJsonFile));
  Config config(file, std::move(env));
  bool var = false;
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL", &var));
  EXPECT_TRUE(var);  // The variable in |env| should be ignored.
  // Does the same with -OrDie().
  EXPECT_TRUE(config.GetBoolOrDie("ARC_TEST_BOOL"));

  // Verify that type mismatches are caught.
  EXPECT_FALSE(config.GetBool("ARC_TEST_INT", &var));
  EXPECT_FALSE(config.GetBool("ARC_TEST_STR", &var));
  EXPECT_FALSE(config.GetBool("ARC_NONEXISTENT", &var));

  EXPECT_DEATH(config.GetBoolOrDie("ARC_TEST_INT"), ".*");
  EXPECT_DEATH(config.GetBoolOrDie("ARC_TEST_STR"), ".*");
  EXPECT_DEATH(config.GetBoolOrDie("ARC_NONEXISTENT"), ".*");
}

TEST(Config, TestGetBoolFallback) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_1", "false"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_2", "False"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_3", "FALSE"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_4", "FalsE"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_5", "0"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_6", "true"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_7", "True"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_8", "TRUE"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_9", "TruE"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_10", "1"));
  // Invalid values.
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_11", "F"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_BOOL_FALLBACK_12", "11"));

  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath file(temp_directory.GetPath().Append("file"));

  // Try to parse a valid env file.
  ASSERT_TRUE(WriteToFile(file, 0700, kValidJsonFile));
  Config config(file, std::move(env));
  bool var;
  // Since JSON does not define ARC_TEST_BOOL_FALLBACK_*, |env| should be read.
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_1", &var));
  EXPECT_FALSE(var);
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_2", &var));
  EXPECT_FALSE(var);
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_3", &var));
  EXPECT_FALSE(var);
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_4", &var));
  EXPECT_FALSE(var);
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_5", &var));
  EXPECT_FALSE(var);
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_6", &var));
  EXPECT_TRUE(var);
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_7", &var));
  EXPECT_TRUE(var);
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_8", &var));
  EXPECT_TRUE(var);
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_9", &var));
  EXPECT_TRUE(var);
  EXPECT_TRUE(config.GetBool("ARC_TEST_BOOL_FALLBACK_10", &var));
  EXPECT_TRUE(var);

  EXPECT_FALSE(config.GetBool("ARC_TEST_BOOL_FALLBACK_11", &var));
  EXPECT_FALSE(config.GetBool("ARC_TEST_BOOL_FALLBACK_12", &var));
}

TEST(Config, TestGetString) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  ASSERT_TRUE(env->SetVar("ARC_TEST_STR", "str1"));
  ASSERT_TRUE(env->SetVar("ARC_TEST_STR_ENVONLY", "str2"));

  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath file(temp_directory.GetPath().Append("file"));

  // Try to parse a valid env file.
  ASSERT_TRUE(WriteToFile(file, 0700, kValidJsonFile));
  Config config(file, std::move(env));
  std::string var;
  EXPECT_TRUE(config.GetString("ARC_TEST_STR", &var));
  // Confirm that the JSON file is searched first.
  EXPECT_EQ("42", var);  // not "str1"
  // Does the same with -OrDie().
  EXPECT_EQ("42", config.GetStringOrDie("ARC_TEST_STR"));

  // Confirm that the env variables are also searched after JSON.
  EXPECT_TRUE(config.GetString("ARC_TEST_STR_ENVONLY", &var));
  // Confirm that the JSON file is searched first.
  EXPECT_EQ("str2", var);
  EXPECT_EQ("str2", config.GetStringOrDie("ARC_TEST_STR_ENVONLY"));

  // Verify that type mismatches are caught.
  EXPECT_FALSE(config.GetString("ARC_TEST_INT", &var));
  EXPECT_FALSE(config.GetString("ARC_TEST_BOOL", &var));
  EXPECT_FALSE(config.GetString("ARC_NONEXISTENT", &var));

  EXPECT_DEATH(config.GetStringOrDie("ARC_TEST_INT"), ".*");
  EXPECT_DEATH(config.GetStringOrDie("ARC_TEST_BOOL"), ".*");
  EXPECT_DEATH(config.GetStringOrDie("ARC_NONEXISTENT"), ".*");
}

TEST(Config, TestJsonParseFailure) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());

  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath invalid_file(temp_directory.GetPath().Append("file"));

  ASSERT_TRUE(WriteToFile(invalid_file, 0700, kInvalidJsonFile));
  EXPECT_DEATH(Config(invalid_file, std::move(env)), ".*");
}

}  // namespace
}  // namespace arc
