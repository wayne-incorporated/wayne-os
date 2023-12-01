// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#define G_LOG_USE_STRUCTURED
#include <glib.h>

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "glib-bridge/glib_logger.h"

namespace glib_bridge {

extern uint64_t g_num_logs;

class GlibStructuredLoggerTest : public ::testing::Test {
 public:
  GlibStructuredLoggerTest() {
    g_num_logs = 0;
    ForwardLogs();
  }
  ~GlibStructuredLoggerTest() override = default;
};

TEST_F(GlibStructuredLoggerTest, TestLogging) {
  g_message("foo");
  EXPECT_EQ(g_num_logs, 1);
}

}  // namespace glib_bridge
