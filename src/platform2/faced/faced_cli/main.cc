// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/faced_cli/faced_cli.h"

// Entry point.
//
// We split "main" into its own file to allow it to be excluded from the test
// build, which has its own main.
int main(int argc, char* argv[]) {
  return faced::Main(argc, argv);
}
