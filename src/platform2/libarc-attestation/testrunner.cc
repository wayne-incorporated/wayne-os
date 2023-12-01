// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// based on libbrillo's testrunner.cc

#include <gtest/gtest.h>

#include <base/at_exit.h>
#include <brillo/test_helpers.h>

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  SetUpTests(&argc, argv, true);
  return RUN_ALL_TESTS();
}
