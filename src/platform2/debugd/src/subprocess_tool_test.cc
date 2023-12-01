// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <tuple>

#include <brillo/errors/error.h>

#include "debugd/src/process_with_id.h"
#include "debugd/src/subprocess_tool.h"

namespace debugd {
namespace {

using SubprocessToolTestParam = std::tuple<bool,   // sandboxed
                                           bool>;  // allow_root_mount_ns

class SubprocessToolTest
    : public testing::TestWithParam<SubprocessToolTestParam> {
 protected:
  SubprocessTool tool_;
};

TEST_P(SubprocessToolTest, CreateProcessAndStop) {
  bool sandboxed;
  bool allow_root_mount_ns;
  std::tie(sandboxed, allow_root_mount_ns) = GetParam();

  ProcessWithId* process = tool_.CreateProcess(sandboxed, allow_root_mount_ns);
  EXPECT_NE(nullptr, process);
  EXPECT_FALSE(process->id().empty());

  std::string handle = process->id();

  EXPECT_TRUE(tool_.Stop(handle, nullptr));
  // |process| is now destroyed by SubprocessTool::Stop().

  brillo::ErrorPtr error;
  EXPECT_FALSE(tool_.Stop(handle, &error));
  EXPECT_EQ(handle, error->GetMessage());
}

INSTANTIATE_TEST_SUITE_P(SubprocessToolCreateProcess,
                         SubprocessToolTest,
                         testing::Combine(testing::Bool(), testing::Bool()));

TEST_F(SubprocessToolTest, StopInvalidProcessHandle) {
  std::string invalid_handle = "some_invalid_handle";
  brillo::ErrorPtr error;
  EXPECT_FALSE(tool_.Stop(invalid_handle, &error));
  EXPECT_EQ(invalid_handle, error->GetMessage());
}

}  // namespace
}  // namespace debugd
