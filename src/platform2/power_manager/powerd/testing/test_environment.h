// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_TESTING_TEST_ENVIRONMENT_H_
#define POWER_MANAGER_POWERD_TESTING_TEST_ENVIRONMENT_H_

#include <base/test/task_environment.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include <gtest/gtest.h>

namespace power_manager {

// A test fixture that provides a simple test environment setup with
// a base::test::SingleThreadTaskEnvironment using MOCK_TIME.
class TestEnvironment : public ::testing::Test {
 public:
  TestEnvironment();

  // Return the task environment.
  //
  // This class retains ownership.
  base::test::SingleThreadTaskEnvironment* task_env() {
    return &task_environment_;
  }

 private:
  base::test::SingleThreadTaskEnvironment task_environment_;
};

// A test fixture that provides a task environment and support for Mojo.
class MojoTestEnvironment : public TestEnvironment {
 public:
  MojoTestEnvironment();

 private:
  std::optional<mojo::core::ScopedIPCSupport> ipc_support_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_TESTING_TEST_ENVIRONMENT_H_
