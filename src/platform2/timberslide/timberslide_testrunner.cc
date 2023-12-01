// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "common-mk/testrunner.h"

int main(int argc, char** argv) {
  platform2::TestRunner::Options opts;
  // Only a single ExitManager should be created (and debug builds assert
  // that this is the case). MockTimberslide is a libbrillo::Daemon, which
  // already creates one, so we don't want the TestRunner to create another.
  opts.instantiate_exit_manager = false;
  auto runner = platform2::TestRunner(argc, argv, opts);
  return runner.Run();
}
