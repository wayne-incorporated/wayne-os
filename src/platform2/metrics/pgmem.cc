// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// chromeos-pgmem - reports memory usage by process group.
//
// This utility uses the ProcessInfo class to gather information about process
// memory usage from /proc, and compute and print total usage split by process
// groups.  The groups are: chrome browser + helpers, chrome gpu process, chrome
// renderers, ARC++ processes, VMs, and daemons (user-level processes only, not
// including kernel daemons).  For each group, this reports total RSS and its
// separate components (anon, file, and shmem).  It also reports swap usage.

#include "metrics/process_meter.h"

#include <cinttypes>
#include <iostream>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <brillo/flag_helper.h>

namespace chromeos_metrics {

namespace {

const char* kGroupNames[] = {"browser", "gpu", "renderers",
                             "arc",     "vms", "daemons"};

static_assert(std::size(kGroupNames) == PG_KINDS_COUNT,
              "wrong number of kGroupNames");

}  // namespace

int PrintProcessGroupStats() {
  auto procfs_path = base::FilePath("/proc");
  ProcessInfo info(procfs_path, base::FilePath("/run"));
  info.Collect();
  info.Classify();

  std::cout << base::StringPrintf("group     total  anon  file shmem  swap\n");
  const int MiB = 1 << 20;
  for (int i = 0; i < PG_KINDS_COUNT; i++) {
    ProcessMemoryStats stats;
    ProcessGroupKind kind = static_cast<ProcessGroupKind>(i);
    AccumulateProcessGroupStats(procfs_path, info.GetGroup(kind), &stats);
    std::cout << base::StringPrintf("%-9s %5" PRIu64 " %5" PRIu64 " %5" PRIu64
                                    " %5" PRIu64 " %5" PRIu64,
                                    kGroupNames[i],
                                    stats.rss_sizes[MEM_TOTAL] / MiB,
                                    stats.rss_sizes[MEM_ANON] / MiB,
                                    stats.rss_sizes[MEM_FILE] / MiB,
                                    stats.rss_sizes[MEM_SHMEM] / MiB,
                                    stats.rss_sizes[MEM_SWAP] / MiB)
              << std::endl;
  }
  return 0;
}

}  // namespace chromeos_metrics

int main(int argc, const char* argv[]) {
  brillo::FlagHelper::Init(
      argc, argv, "chromeos-pgmem - reports memory usage by process group");
  return chromeos_metrics::PrintProcessGroupStats();
}
