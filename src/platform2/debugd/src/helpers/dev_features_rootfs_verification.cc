// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <array>
#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/flag_helper.h>
#include <rootdev/rootdev.h>

#include "debugd/src/process_with_output.h"

namespace {

const char kUsageMessage[] =
    "\n"
    "Removes rootfs verification for the current partition or queries whether\n"
    "rootfs verification has already been removed.\n"
    "\n";

// Checks if rootfs verification has been removed by testing if / is writable.
// Must be called as root since / is never writable by the debugd user.
bool IsRootfsVerificationRemoved() {
  base::ScopedFD init_ns_fd(open("/proc/1/ns/mnt", O_CLOEXEC));
  // Since debugd is running in a sandboxed envrionment, the check
  // whether '/' is writable needs to be done in the init namespace,
  // instead of the debugd sandboxed namespace.
  setns(init_ns_fd.get(), CLONE_NEWNS);
  return base::PathIsWritable(base::FilePath("/"));
}

// Uses rootdev to get the partition we can safely use with make_dev_ssd.sh.
// Returns -1 and prints to stderr on failure.
int GetModifiablePartition() {
  // Use the same logic as make_dev_ssd.sh: query rootdev, get the number at
  // the end of the rootdev path, then subtract 1.
  std::array<char, PATH_MAX> path;
  int rootdev_result = rootdev(path.data(), path.size(), true, false);
  if (rootdev_result != 0) {
    LOG(WARNING) << "rootdev failed with error code " << rootdev_result;
    return -1;
  }
  size_t path_length = strlen(path.data());
  // There must be at least 1 numeric digit at the end of the path.
  if (!base::IsAsciiDigit(path[path_length - 1])) {
    LOG(WARNING) << "Couldn't determine partition from rootdev path \""
                 << path.data() << '"';
    return -1;
  }
  int partition = -1;
  for (int i = path_length - 1; i > 0; --i) {
    if (!base::IsAsciiDigit(path[i - 1])) {
      partition = atoi(&path[i]) - 1;
      break;
    }
  }
  return partition;
}

// Removes rootfs verification.
bool RemoveRootfsVerification() {
  int partition = GetModifiablePartition();
  if (partition == -1) {
    LOG(WARNING) << "No modifiable partition";
    return false;
  }
  std::string error;
  int result = debugd::ProcessWithOutput::RunProcessFromHelper(
      "/usr/share/vboot/bin/make_dev_ssd.sh",
      {"--remove_rootfs_verification", "--partitions",
       base::NumberToString(partition)},
      nullptr,  // stdin.
      nullptr,  // stdout.
      &error);  // stderr.
  if (result != EXIT_SUCCESS) {
    LOG(WARNING) << "\"make_dev_ssd.sh\" failed with exit code " << result
                 << ": " << error;
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_bool(q, false, "Query whether verification has been removed");
  brillo::FlagHelper::Init(argc, argv, kUsageMessage);

  if (FLAGS_q) {
    return IsRootfsVerificationRemoved() ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  return RemoveRootfsVerification() ? EXIT_SUCCESS : EXIT_FAILURE;
}
