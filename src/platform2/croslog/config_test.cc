// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/config.h"

#include <vector>

#include <base/files/file_path.h>
#include <brillo/flag_helper.h>
#include <gtest/gtest.h>

#include "croslog/test_util.h"

namespace croslog {

namespace {
constexpr char kCrosLogPath[] = "croslog";
}

class ParseCommandLineTest : public ::testing::Test {
 private:
  void TearDown() override {
    brillo::FlagHelper::GetInstance()->ResetForTesting();
    base::CommandLine::Reset();
  }
};

TEST_F(ParseCommandLineTest, SourceModeNoArg) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath};
  EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
  EXPECT_EQ(SourceMode::PLAINTEXT_LOG, config.source);
}

TEST_F(ParseCommandLineTest, SourceModeJournalArg) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath, "--source=journal"};
  EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
  EXPECT_EQ(SourceMode::JOURNAL_LOG, config.source);
}

TEST_F(ParseCommandLineTest, SourceModePlainTextArg) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath, "--source=plaintext"};
  EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
  EXPECT_EQ(SourceMode::PLAINTEXT_LOG, config.source);
}

TEST_F(ParseCommandLineTest, SourceModeWithoutEqual) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath, "--source", "journal"};
  // Fails to parse.
  EXPECT_FALSE(config.ParseCommandLineArgs(args.size(), args.data()));
  // Falls back to the default.
  EXPECT_EQ(SourceMode::PLAINTEXT_LOG, config.source);
}

TEST_F(ParseCommandLineTest, SourceModeInvalidValue) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath, "--source=invalid"};
  // Fails to parse.
  EXPECT_FALSE(config.ParseCommandLineArgs(args.size(), args.data()));
  // Falls back to the default.
  EXPECT_EQ(SourceMode::PLAINTEXT_LOG, config.source);
}

TEST_F(ParseCommandLineTest, PagerModeNoArg) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath};
  EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
  EXPECT_TRUE(config.no_pager);
}

TEST_F(ParseCommandLineTest, PagerModeWithArg) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath, "--pager"};
  EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
  EXPECT_FALSE(config.no_pager);
}

TEST_F(ParseCommandLineTest, PagerModeWithNoArg) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath, "--no-pager"};
  EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
  EXPECT_TRUE(config.no_pager);
}

TEST_F(ParseCommandLineTest, BootModeNoArg) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath};
  EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
  // |boot| doesn't have value.
  EXPECT_FALSE(config.boot.has_value());
}

TEST_F(ParseCommandLineTest, BootModeWithoutSpecifiedID) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath, "--boot"};
  EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
  // |boot| has an empty value.
  EXPECT_TRUE(config.boot.has_value());
  EXPECT_TRUE(config.boot->empty());
}

TEST_F(ParseCommandLineTest, BootModeWithSpecifiedID) {
  Config config;
  std::vector<const char*> args = {kCrosLogPath, "--boot=BOOTID"};
  EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
  // |boot| has a value of the specified BOOT ID.
  EXPECT_TRUE(config.boot.has_value());
  EXPECT_EQ("BOOTID", *(config.boot));
}

TEST_F(ParseCommandLineTest, ParseUntil) {
  {
    Config config;
    std::vector<const char*> args = {kCrosLogPath, "--until=2020-10-12"};
    EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
    EXPECT_FALSE(config.until.is_null());
    EXPECT_EQ(config.until, TimeFromExploded(2020, 10, 12, 0, 0, 0));
  }

  {
    Config config;
    std::vector<const char*> args = {kCrosLogPath, "--until=20201012"};
    EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
    EXPECT_FALSE(config.until.is_null());
    EXPECT_EQ(config.until, TimeFromExploded(2020, 10, 12, 0, 0, 0));
  }
}

TEST_F(ParseCommandLineTest, ParseSince) {
  {
    Config config;
    std::vector<const char*> args = {kCrosLogPath, "--since=2020-10-12"};
    EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
    EXPECT_FALSE(config.since.is_null());
    EXPECT_EQ(config.since, TimeFromExploded(2020, 10, 12, 0, 0, 0));
  }

  {
    Config config;
    std::vector<const char*> args = {kCrosLogPath, "--since=20201012"};
    EXPECT_TRUE(config.ParseCommandLineArgs(args.size(), args.data()));
    EXPECT_FALSE(config.since.is_null());
    EXPECT_EQ(config.since, TimeFromExploded(2020, 10, 12, 0, 0, 0));
  }
}

}  // namespace croslog
