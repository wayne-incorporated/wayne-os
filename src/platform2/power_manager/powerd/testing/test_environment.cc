// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/testing/test_environment.h"

#include <gtest/gtest.h>

#include <base/test/task_environment.h>
#include <mojo/core/embedder/embedder.h>

namespace power_manager {

namespace {

// Initialise Mojo global state.
//
// May be called multiple times, but only the first call will actually
// perform initialization.
void InitMojo() {
  // Static variables initialized by lambdas are only called once.
  //
  // We don't actually need the value of the variable (the compiler will ensure
  // the lambda is only called once), but do need to create one.
  static bool init_complete = []() {
    mojo::core::Init();
    return true;
  }();
  (void)init_complete;  // avoid warning about unused variable
}

}  // namespace

TestEnvironment::TestEnvironment()
    : task_environment_(base::test::TaskEnvironment::MainThreadType::IO,
                        base::test::TaskEnvironment::TimeSource::SYSTEM_TIME) {}

MojoTestEnvironment::MojoTestEnvironment() {
  InitMojo();
  ipc_support_.emplace(task_env()->GetMainThreadTaskRunner(),
                       mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);
}

}  // namespace power_manager
