// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Runs mount-passthrough with minijail0 as chronos.
// mount-passthrough-jailed is in the process of being ported from shell
// to C++.

#include <stdlib.h>
#include <unistd.h>

#include <base/logging.h>

#include "arc/mount-passthrough/mount-passthrough-util.h"

int main(int argc, char* argv[]) {
  arc::CommandLineFlags flags;
  arc::ParseCommandLine(argc, argv, &flags);

  auto minijail_args = arc::CreateMinijailCommandLineArgs(flags);
  std::vector<const char*> minijail_argv;
  for (const auto& arg : minijail_args) {
    minijail_argv.push_back(arg.c_str());
  }
  minijail_argv.push_back(nullptr);  // argv should be terminated with nullptr.

  execv(minijail_argv[0], const_cast<char* const*>(minijail_argv.data()));
  PLOG(ERROR) << "execve failed with " << minijail_argv[0];
  return EXIT_FAILURE;  // execve() failed.
}
