// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "common-mk/testrunner.h"

int main(int argc, char** argv) {
  auto runner = platform2::TestRunner(argc, argv);
  return runner.Run();
}
