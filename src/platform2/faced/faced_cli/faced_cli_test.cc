// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/faced_cli/faced_cli.h"

#include <absl/strings/match.h>
#include <base/command_line.h>
#include <brillo/flag_helper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "faced/util/status.h"

namespace faced {
namespace {

absl::StatusOr<CommandLineArgs> ParseCommandLine(
    const std::vector<std::string>& args) {
  std::vector<const char*> char_args;
  for (const std::string& s : args) {
    char_args.push_back(s.c_str());
  }
  return ::faced::ParseCommandLine(char_args.size(), char_args.data());
}

MATCHER_P(IsErrorContainingString, s, "is an error containing a string") {
  return !arg.ok() &&
         absl::StrContains(/*haystack=*/arg.status().message(), /*needle=*/s);
}

class ParseCommandLineTest : public ::testing::Test {
 public:
  ParseCommandLineTest() { base::CommandLine::Reset(); }
  ~ParseCommandLineTest() override { brillo::FlagHelper::ResetForTesting(); }
};

TEST_F(ParseCommandLineTest, ConnectToFaced) {
  CommandLineArgs args =
      faced::ValueOrDie(ParseCommandLine({"faced_cli", "connect"}));
  EXPECT_EQ(args.command, Command::kConnectToFaced);
}

TEST_F(ParseCommandLineTest, EnrollCommandIsParsedCorrectly) {
  CommandLineArgs args = faced::ValueOrDie(
      ParseCommandLine({"faced_cli", "enroll", "--user=someone"}));
  EXPECT_EQ(args.command, Command::kEnroll);
  EXPECT_EQ(args.user, "someone");
}

TEST_F(ParseCommandLineTest, IsEnrolledCommandIsParsedCorrectly) {
  CommandLineArgs args = faced::ValueOrDie(
      ParseCommandLine({"faced_cli", "is-enrolled", "--user=someone"}));
  EXPECT_EQ(args.command, Command::kIsEnrolled);
  EXPECT_EQ(args.user, "someone");
}

TEST_F(ParseCommandLineTest, RemoveCommandIsParsedCorrectly) {
  CommandLineArgs args = faced::ValueOrDie(
      ParseCommandLine({"faced_cli", "remove", "--user=someone"}));
  EXPECT_EQ(args.command, Command::kRemoveEnrollment);
  EXPECT_EQ(args.user, "someone");
}

TEST_F(ParseCommandLineTest, ListCommandIsParsedCorrectly) {
  CommandLineArgs args =
      faced::ValueOrDie(ParseCommandLine({"faced_cli", "list"}));
  EXPECT_EQ(args.command, Command::kListEnrollments);
}

TEST_F(ParseCommandLineTest, ClearCommandIsParsedCorrectly) {
  CommandLineArgs args =
      faced::ValueOrDie(ParseCommandLine({"faced_cli", "clear"}));
  EXPECT_EQ(args.command, Command::kClearEnrollments);
}

TEST_F(ParseCommandLineTest, NoArgs) {
  EXPECT_THAT(ParseCommandLine({"faced_cli"}),
              IsErrorContainingString("Expected exactly one command"));
}

TEST_F(ParseCommandLineTest, BadCommand) {
  EXPECT_THAT(ParseCommandLine({"faced_cli", "bad-command"}),
              IsErrorContainingString("Unknown command"));
}

TEST_F(ParseCommandLineTest, BadOption) {
  // Bad option
  EXPECT_THAT(ParseCommandLine({"faced_cli", "start", "--bad-option=3"}),
              IsErrorContainingString("Invalid option"));
}

}  // namespace
}  // namespace faced
