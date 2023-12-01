// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/test/test_timeouts.h>
#include <mojo/core/embedder/embedder.h>

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  TestTimeouts::Initialize();

  ::testing::InitGoogleTest(&argc, argv);
  base::AtExitManager at_exit;

  mojo::core::Init();

  return RUN_ALL_TESTS();
}
