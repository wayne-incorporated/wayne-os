// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <set>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/json/json_string_value_serializer.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "debugd/src/probe_tool.h"

namespace debugd {
namespace {

using ::testing::ByMove;
using ::testing::Return;

constexpr char kDefaultRunAs[] = "runtime_probe";

class ProbeToolForTesting : public ProbeTool {
 public:
  using ProbeTool::GetValidMinijailArguments;
  using ProbeTool::ProbeTool;

  MOCK_METHOD(std::optional<base::Value::Dict>,
              LoadMinijailArguments,
              (brillo::ErrorPtr*),
              (override));

  void SetMinijailArgumentsForTesting(const std::string& minijail_args_json) {
    JSONStringValueDeserializer deserializer(minijail_args_json);
    auto dict = deserializer.Deserialize(nullptr, nullptr);
    EXPECT_CALL(*this, LoadMinijailArguments)
        .WillOnce(Return(ByMove(std::move(*dict).TakeDict())));
  }
};

std::set<std::vector<std::string>> GroupArguments(
    const std::vector<std::string>& args) {
  // These are minijail flags with exactly one string argument.
  static const std::set<std::string> kMinijailStringArgFlags{"-u", "-g", "-c",
                                                             "-S", "-b"};
  std::set<std::vector<std::string>> rv;
  for (auto it = args.begin(); it != args.end(); ++it) {
    if (kMinijailStringArgFlags.count(*it)) {
      rv.insert({*it, *std::next(it)});
      ++it;
    } else {
      rv.insert({*it});
    }
  }

  return rv;
}

}  // namespace

TEST(ProbeToolTest, GetValidMinijailArguments_Success) {
  auto kMinijailArgs = R"({
    "func1": {
      "other_args": ["-A", "-B", "args"]
    }
  })";
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, kDefaultRunAs);
  EXPECT_EQ(group, kDefaultRunAs);
  EXPECT_EQ(GroupArguments(args),
            std::set<std::vector<std::string>>({{"-A"}, {"-B"}, {"args"}}));
}

TEST(ProbeToolTest, GetValidMinijailArguments_Failure) {
  auto kMinijailArgs = R"({
    "func1": {
      "other_args": ["-A", "-B", "args"]
    }
  })";
  auto kProbeStatement = R"({"func2":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_FALSE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_TRUE(function_name.empty());
  EXPECT_TRUE(user.empty());
  EXPECT_TRUE(group.empty());
  EXPECT_EQ(args.size(), 0);
}

TEST(ProbeToolTest, GetValidMinijailArguments_BindDirectoryExists) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto dir = temp_dir.GetPath().Append("dir");
  ASSERT_TRUE(base::CreateDirectory(dir));

  auto kMinijailArgs = base::StringPrintf(
      R"({
        "func1": {
          "binds": ["%s"],
          "other_args": ["-A"]
        }
      })",
      dir.value().c_str());
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, kDefaultRunAs);
  EXPECT_EQ(group, kDefaultRunAs);
  EXPECT_EQ(GroupArguments(args),
            std::set<std::vector<std::string>>({{"-A"}, {"-b", dir.value()}}));
}

TEST(ProbeToolTest, GetValidMinijailArguments_SkipBindingDirectoryNotExist) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto not_exist_dir = temp_dir.GetPath().Append("not_exist_dir");
  auto kMinijailArgs = base::StringPrintf(
      R"({
        "func1": {
          "binds": ["%s"],
          "other_args": ["-A"]
        }
      })",
      not_exist_dir.value().c_str());
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, kDefaultRunAs);
  EXPECT_EQ(group, kDefaultRunAs);
  EXPECT_EQ(GroupArguments(args), std::set<std::vector<std::string>>({{"-A"}}));
}

TEST(ProbeToolTest, GetValidMinijailArguments_BindSymbolicLink) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto dir = temp_dir.GetPath().Append("dir");
  ASSERT_TRUE(base::CreateDirectory(dir));
  auto symlink_dir = temp_dir.GetPath().Append("symlink_dir");
  ASSERT_TRUE(base::CreateSymbolicLink(dir, symlink_dir));
  auto kMinijailArgs = base::StringPrintf(
      R"({
        "func1": {
          "binds": ["%s"],
          "other_args": ["-A"]
        }
      })",
      symlink_dir.value().c_str());
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, kDefaultRunAs);
  EXPECT_EQ(group, kDefaultRunAs);
  EXPECT_EQ(GroupArguments(args), std::set<std::vector<std::string>>(
                                      {{"-A"}, {"-b", symlink_dir.value()}}));
}

TEST(ProbeToolTest, GetValidMinijailArguments_BindNormalFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto file = temp_dir.GetPath().Append("file");
  ASSERT_EQ(base::WriteFile(file, "", 0), 0);
  auto kMinijailArgs = base::StringPrintf(
      R"({
        "func1": {
          "binds": ["%s"],
          "other_args": ["-A"]
        }
      })",
      file.value().c_str());
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, kDefaultRunAs);
  EXPECT_EQ(group, kDefaultRunAs);
  EXPECT_EQ(GroupArguments(args),
            std::set<std::vector<std::string>>({{"-A"}, {"-b", file.value()}}));
}

TEST(ProbeToolTest, GetValidMinijailArguments_BindWithArguments) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto dir = temp_dir.GetPath().Append("dir");
  ASSERT_TRUE(base::CreateDirectory(dir));
  auto kMinijailArgs = base::StringPrintf(
      R"({
        "func1": {
          "binds": ["%s,,1"],
          "other_args": ["-A"]
        }
      })",
      dir.value().c_str());
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  // Writeable binding.
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, kDefaultRunAs);
  EXPECT_EQ(group, kDefaultRunAs);
  const auto kExpectedBindArg =
      base::StringPrintf("%s,,1", dir.value().c_str());
  EXPECT_EQ(GroupArguments(args), std::set<std::vector<std::string>>(
                                      {{"-A"}, {"-b", kExpectedBindArg}}));
}

TEST(ProbeToolTest, GetValidMinijailArguments_BindPathDict) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto dir1 = temp_dir.GetPath().Append("dir-1");
  ASSERT_TRUE(base::CreateDirectory(dir1));
  auto dir2 = temp_dir.GetPath().Append("dir-2");
  ASSERT_TRUE(base::CreateDirectory(dir2));
  auto dir3 = temp_dir.GetPath().Append("dir-foo");
  ASSERT_TRUE(base::CreateDirectory(dir3));

  auto kMinijailArgs = base::StringPrintf(
      R"({
        "func1": {
          "binds": [{"dirname": "%s", "basename": "dir-\\d+"}],
          "other_args": ["-A"]
        }
      })",
      temp_dir.GetPath().value().c_str());
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, kDefaultRunAs);
  EXPECT_EQ(group, kDefaultRunAs);
  EXPECT_EQ(GroupArguments(args),
            std::set<std::vector<std::string>>(
                {{"-A"}, {"-b", dir1.value()}, {"-b", dir2.value()}}));
}

TEST(ProbeToolTest, GetValidMinijailArguments_BindPathDictWithArgs) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto dir1 = temp_dir.GetPath().Append("dir-1");
  ASSERT_TRUE(base::CreateDirectory(dir1));
  auto dir2 = temp_dir.GetPath().Append("dir-2");
  ASSERT_TRUE(base::CreateDirectory(dir2));
  auto dir3 = temp_dir.GetPath().Append("dir-foo");
  ASSERT_TRUE(base::CreateDirectory(dir3));

  auto kMinijailArgs = base::StringPrintf(
      R"({
        "func1": {
          "binds": [{"dirname": "%s", "basename": "dir-\\d+", "args": ",,1"}],
          "other_args": ["-A"]
        }
      })",
      temp_dir.GetPath().value().c_str());
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, kDefaultRunAs);
  EXPECT_EQ(group, kDefaultRunAs);
  const auto kExpectedBindArg1 =
      base::StringPrintf("%s,,1", dir1.value().c_str());
  const auto kExpectedBindArg2 =
      base::StringPrintf("%s,,1", dir2.value().c_str());
  EXPECT_EQ(
      GroupArguments(args),
      std::set<std::vector<std::string>>(
          {{"-A"}, {"-b", kExpectedBindArg1}, {"-b", kExpectedBindArg2}}));
}

TEST(ProbeToolTest, GetValidMinijailArguments_SpecifyUser) {
  auto kMinijailArgs = R"({
    "func1": {
      "user": "abc",
      "other_args": ["-A", "-B", "args"]
    }
  })";
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, "abc");
  EXPECT_EQ(group, kDefaultRunAs);
  EXPECT_EQ(GroupArguments(args),
            std::set<std::vector<std::string>>({{"-A"}, {"-B"}, {"args"}}));
}

TEST(ProbeToolTest, GetValidMinijailArguments_SpecifyGroup) {
  auto kMinijailArgs = R"({
    "func1": {
      "group": "abc",
      "other_args": ["-A", "-B", "args"]
    }
  })";
  auto kProbeStatement = R"({"func1":{}})";
  ProbeToolForTesting probe_tool;
  probe_tool.SetMinijailArgumentsForTesting(kMinijailArgs);
  std::vector<std::string> args;
  std::string function_name, user, group;
  EXPECT_TRUE(probe_tool.GetValidMinijailArguments(
      nullptr, kProbeStatement, &function_name, &user, &group, &args));
  EXPECT_EQ(function_name, "func1");
  EXPECT_EQ(user, kDefaultRunAs);
  EXPECT_EQ(group, "abc");
  EXPECT_EQ(GroupArguments(args),
            std::set<std::vector<std::string>>({{"-A"}, {"-B"}, {"args"}}));
}

}  // namespace debugd
