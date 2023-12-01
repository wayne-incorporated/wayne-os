// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <common-mk/testrunner.h>
#include <mojo/core/embedder/embedder.h>

// This test runner creates the platform2::TestRunner and initializes mojo for
// tests that require it. This make sure the mojo is initialized once for the
// test process.
int main(int argc, char** argv) {
  auto runner = platform2::TestRunner(argc, argv);
  mojo::core::Init();
  return runner.Run();
}
