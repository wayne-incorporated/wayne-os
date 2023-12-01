// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/multiplexer.h"

#include <base/files/file_path.h>
#include <gtest/gtest.h>

#include "croslog/log_parser_syslog.h"

namespace croslog {

class MultiplexerTest : public ::testing::Test {
 public:
  MultiplexerTest() = default;
  MultiplexerTest(const MultiplexerTest&) = delete;
  MultiplexerTest& operator=(const MultiplexerTest&) = delete;
};

TEST_F(MultiplexerTest, Forward) {
  Multiplexer Multiplexer;
  Multiplexer.AddSource(base::FilePath("./testdata/TEST_NORMAL_LOG1"),
                        std::make_unique<LogParserSyslog>(), false);
  Multiplexer.AddSource(base::FilePath("./testdata/TEST_NORMAL_LOG2"),
                        std::make_unique<LogParserSyslog>(), false);

  {
    MaybeLogEntry e = Multiplexer.Forward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5963, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Forward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5964, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Forward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5965, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Forward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5966, e->pid());
  }

  EXPECT_FALSE(Multiplexer.Forward().has_value());
}

TEST_F(MultiplexerTest, BackwardFromLast) {
  Multiplexer Multiplexer;
  Multiplexer.AddSource(base::FilePath("./testdata/TEST_NORMAL_LOG1"),
                        std::make_unique<LogParserSyslog>(), false);
  Multiplexer.AddSource(base::FilePath("./testdata/TEST_NORMAL_LOG2"),
                        std::make_unique<LogParserSyslog>(), false);
  Multiplexer.SetLinesFromLast(0);

  {
    MaybeLogEntry e = Multiplexer.Backward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5966, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Backward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5965, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Backward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5964, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Backward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5963, e->pid());
  }

  EXPECT_FALSE(Multiplexer.Backward().has_value());
}

TEST_F(MultiplexerTest, InterleaveForwardAndBackward1) {
  Multiplexer Multiplexer;
  Multiplexer.AddSource(base::FilePath("./testdata/TEST_NORMAL_LOG1"),
                        std::make_unique<LogParserSyslog>(), false);
  Multiplexer.AddSource(base::FilePath("./testdata/TEST_NORMAL_LOG2"),
                        std::make_unique<LogParserSyslog>(), false);

  {
    MaybeLogEntry e = Multiplexer.Forward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5963, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Backward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5963, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Forward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5963, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Backward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5963, e->pid());
  }
}

TEST_F(MultiplexerTest, InterleaveForwardAndBackward2) {
  Multiplexer Multiplexer;
  Multiplexer.AddSource(base::FilePath("./testdata/TEST_NORMAL_LOG1"),
                        std::make_unique<LogParserSyslog>(), false);
  Multiplexer.AddSource(base::FilePath("./testdata/TEST_NORMAL_LOG2"),
                        std::make_unique<LogParserSyslog>(), false);
  Multiplexer.SetLinesFromLast(0);

  {
    MaybeLogEntry e = Multiplexer.Backward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5966, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Forward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5966, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Backward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5966, e->pid());
  }

  {
    MaybeLogEntry e = Multiplexer.Forward();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(5966, e->pid());
  }
}

}  // namespace croslog
