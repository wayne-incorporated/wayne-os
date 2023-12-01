// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/process_meter.h"

#include <memory>
#include <optional>

#include <gtest/gtest.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

namespace chromeos_metrics {

class ProcessMeterTest : public testing::Test {};

void CreateFile(const base::FilePath& path, std::string content) {
  if (base::WriteFile(path, content.c_str(), content.length()) !=
      content.length()) {
    LOG(FATAL) << "cannot write to " << path.MaybeAsASCII();
  }
}

void CreateProcEntry(const base::FilePath& procfs_path,
                     int pid,
                     std::optional<int> ppid,
                     const char* name,
                     const char* cmdline,
                     int total_mib,
                     int anon_mib,
                     int file_mib,
                     int shmem_mib,
                     int swap_mib) {
  base::FilePath proc_pid_path(
      procfs_path.Append(base::StringPrintf("%d", pid)));
  CHECK(CreateDirectory(proc_pid_path));
  if (cmdline != nullptr) {
    base::FilePath cmdline_path(proc_pid_path.Append("cmdline"));
    CreateFile(cmdline_path, std::string(cmdline));
  }
  if (name != nullptr) {
    base::FilePath stat_path(proc_pid_path.Append("stat"));
    std::string stat_content;
    if (ppid) {
      stat_content = base::StringPrintf("%d (%s) R %d 33 44 blah blah \n", pid,
                                        name, *ppid);
    } else {
      stat_content =
          base::StringPrintf("%d (%s) R Q 33 44 blah blah \n", pid, name);
    }
    CreateFile(stat_path, stat_content);
  }
  base::FilePath totmaps_path(proc_pid_path.Append("totmaps"));
  bool is_kdaemon = total_mib == 0;
  std::string totmaps_content =
      is_kdaemon ? "blah\nblah\nblah"
                 : base::StringPrintf(
                       "blah\nblah\nblah\n"
                       "Pss:         %d kB\n"
                       "Pss_Anon:    %d kB\n"
                       "Pss_File:    %d kB\n"
                       "Pss_Shmem:   %d kB\n"
                       "blah\nblah\nblah\n"
                       "Swap:        %d kB\n"
                       "blah\nblah\nblah\n",
                       total_mib * 1024, anon_mib * 1024, file_mib * 1024,
                       shmem_mib * 1024, swap_mib * 1024);
  CreateFile(totmaps_path, totmaps_content);
}

// Test that we're classifying processes and adding up their sizes correctly.
TEST_F(ProcessMeterTest, ReportProcessStats) {
  base::FilePath temp_dir;
  EXPECT_TRUE(base::CreateNewTempDirectory("", &temp_dir));
  base::FilePath run_path = temp_dir.Append("run");
  base::FilePath procfs_path = temp_dir.Append("proc");

  // Create arc init PID file in mock /run.
  const int arc_init_pid = 22;
  base::FilePath arc_init_path = run_path.Append(kMetricsARCInitPIDFile);
  CHECK(CreateDirectory(arc_init_path.DirName()));
  const std::string arc_init_pid_string =
      base::StringPrintf("%d", arc_init_pid);
  const char* s = arc_init_pid_string.c_str();
  CreateFile(arc_init_path, s);

  // Create mock /proc.
  CHECK(CreateDirectory(procfs_path));

  // Fill /proc with entries for a few processes.
  // clang-format off

  // init.
  CreateProcEntry(procfs_path, 1, 0, "init", "/sbin/init",
                  10, 5, 5, 0, 7);
  // ARC init.
  CreateProcEntry(procfs_path, arc_init_pid, 1, "arc-init", "/blah/arc/init",
                  10, 5, 5, 0, 1);
  // kthreadd (kernel daemon)
  CreateProcEntry(procfs_path, 2, 0, "kthreadd", "",
                  0, 0, 0, 0, 0);
  // kworker with a space in its name
  CreateProcEntry(procfs_path, 2, 0, "kworker/0:0-My worker", "",
                  0, 0, 0, 0, 0);
  // Browser processes.
  CreateProcEntry(procfs_path, 100, 1, "chrome",
                  "/opt/google/chrome/chrome blah",
                  300, 200, 90, 10, 2);
  CreateProcEntry(procfs_path, 101, 100, "chrome",
                  "/opt/google/chrome/chrome --type=broker",
                  5, 4, 3, 2, 1);
  // Other spawned-from-chrome processes with a ) in the name. The Regular
  // Expression parser will backtrack and find the correct ) to match on.
  // Anything spawned from the Chrome browser process will count under browser
  // if it doesn't count under one of the other categories.
  CreateProcEntry(procfs_path, 102, 100, "bash (stuff)",
                  "/bin/bash /usr/bin/somescript",
                  400, 50, 245, 100, 5);
  CreateProcEntry(procfs_path, 103, 100, "corrupt )))) R Q",
                  "/bin/bash /usr/bin/somescript",
                  100, 33, 33, 33, 1);
  // GPU.
  CreateProcEntry(procfs_path, 110, 100, "chrome",
                  "/opt/google/chrome/chrome --type=gpu-process",
                  400, 70, 30, 300, 3);
  // Renderers.
  CreateProcEntry(procfs_path, 120, 100, "chrome",
                  "/opt/google/chrome/chrome --type=renderer",
                  500, 450, 30, 20, 13);
  CreateProcEntry(procfs_path, 121, 100, "chrome",
                  "/opt/google/chrome/chrome --type=renderer",
                  500, 450, 30, 20,  13);
  // Daemons.
  CreateProcEntry(procfs_path, 200, 1, "shill", "/usr/bin/shill",
                  100, 30, 70, 0, 0);
  // 4 bad entries. Since they cannot be parsed, they'll be put in the
  // "daemons" category, which is really a catch-all for non-Chrome, despite
  // looking a bit like a Chrome process:
  // Name not UTF-8.
  CreateProcEntry(procfs_path, 213, 100, "p\xb9Q\xc8",
                  "/opt/google/chrome/chrome --type=renderer",
                  113, 33, 80, 0, 0);
  // Unparsable ppid
  CreateProcEntry(procfs_path, 214, std::nullopt, "chrome",
                  "/opt/google/chrome/chrome --type=renderer",
                  213, 133, 80, 0, 0);
  // Missing cmdline.
  CreateProcEntry(procfs_path, 215, 100, "chrome", nullptr,
                  313, 133, 180, 0, 0);
  // Missing stat.
  CreateProcEntry(procfs_path, 216, 100, nullptr,
                  "/opt/google/chrome/chrome --type=renderer",
                  413, 183, 180, 50, 0);
  // clang-format on

  // Get process info from mocked /proc.
  ProcessInfo info(procfs_path, run_path);
  info.Collect();
  info.Classify();
  const uint64_t mib = 1 << 20;
  // clang-format off
  const ProcessMemoryStats expected_stats[PG_KINDS_COUNT] = {
      // browser
      {{ 805 * mib, 287 * mib, 371 * mib, 145 * mib,  9 * mib}},
      // gpu
      {{ 400 * mib,  70 * mib,  30 * mib, 300 * mib,  3 * mib}},
      // renderers
      {{1000 * mib, 900 * mib,  60 * mib,  40 * mib, 26 * mib}},
      // arc
      {{  10 * mib,   5 * mib,   5 * mib,         0,  1 * mib}},
      // vms
      {{         0,         0,         0,         0,        0}},
      // daemons
      {{1162 * mib, 517 * mib, 595 * mib,  50 * mib,  7 * mib}},
  };
  // clang-format on
  for (int i = 0; i < PG_KINDS_COUNT; i++) {
    ProcessMemoryStats stats;
    ProcessGroupKind kind = static_cast<ProcessGroupKind>(i);
    AccumulateProcessGroupStats(procfs_path, info.GetGroup(kind), &stats);
    for (int j = 0; j < MEM_KINDS_COUNT; j++) {
      EXPECT_EQ(stats.rss_sizes[j], expected_stats[i].rss_sizes[j])
          << "for expected_stats[" << i << "].rss_sizes[" << j << "]";
    }
  }
}

// Test that we're classifying VM processes and adding up their sizes correctly.
TEST_F(ProcessMeterTest, ReportProcessStats_VM) {
  base::FilePath temp_dir;
  EXPECT_TRUE(base::CreateNewTempDirectory("", &temp_dir));
  base::FilePath run_path = temp_dir.Append("run");
  base::FilePath procfs_path = temp_dir.Append("proc");

  // Create mock /proc.
  CHECK(CreateDirectory(procfs_path));

  // Fill /proc with entries for a few processes.
  // clang-format off

  // init.
  CreateProcEntry(procfs_path, 1, 0, "init", "/sbin/init",
                  10, 5, 5, 0, 7);

  // vm_concierge
  CreateProcEntry(procfs_path, 100, 1, "vm_concierge", "/usr/bin/vm_concierge",
                  10, 5, 5, 0, 1);

  // ARCVM
  CreateProcEntry(procfs_path, 200, 100, "crosvm",
                  "/usr/bin/crosvm androidboot.hardware=bertha vmlinux",
                  100, 50, 50, 10, 10);
  CreateProcEntry(procfs_path, 201, 100, "crosvm",
                  "/usr/bin/crosvm androidboot.hardware=bertha vmlinux",
                  100, 50, 50, 10, 10);

  // Other VMs
  CreateProcEntry(procfs_path, 300, 100, "crosvm", "/usr/bin/crosvm vmlinux",
                  10, 5, 5, 0, 1);
  CreateProcEntry(procfs_path, 301, 100, "crosvm", "/usr/bin/crosvm vmlinux",
                  10, 5, 5, 0, 1);
  // clang-format on

  // Get process info from mocked /proc.
  ProcessInfo info(procfs_path, run_path);
  info.Collect();
  info.Classify();
  const uint64_t mib = 1 << 20;
  // clang-format off
  const ProcessMemoryStats expected_stats[PG_KINDS_COUNT] = {
      // browser
      {{    0,          0,         0,         0,        0}},
      // gpu
      {{    0,          0,         0,         0,        0}},
      // renderers
      {{    0,          0,         0,         0,        0}},
      // arc
      {{  200 * mib,  100 * mib, 100 * mib,  20 * mib, 20 * mib}},
      // vms
      {{   30 * mib,   15 * mib,  15 * mib,   0 * mib,  3 * mib}},
      // daemons
      {{   10 * mib,    5 * mib,   5 * mib,   0 * mib,  7 * mib}},
  };
  // clang-format on
  for (int i = 0; i < PG_KINDS_COUNT; i++) {
    ProcessMemoryStats stats;
    ProcessGroupKind kind = static_cast<ProcessGroupKind>(i);
    AccumulateProcessGroupStats(procfs_path, info.GetGroup(kind), &stats);
    for (int j = 0; j < MEM_KINDS_COUNT; j++) {
      EXPECT_EQ(stats.rss_sizes[j], expected_stats[i].rss_sizes[j]);
    }
  }
}

void CheckPG(int pg, const char* field) {
  for (int i = 0; i < MEM_KINDS_COUNT; i++) {
    CHECK(strcasestr(kProcessMemoryUMANames[pg][i], field) != NULL);
  }
}

void CheckMem(int mem, const char* field) {
  for (int i = 0; i < PG_KINDS_COUNT; i++) {
    CHECK(strcasestr(kProcessMemoryUMANames[i][mem], field) != NULL);
  }
}

// Test that the enum constants for process kind and memory kind match the UMA
// histogram names.
TEST_F(ProcessMeterTest, CheckUMANames) {
  CheckPG(PG_BROWSER, "browser");
  CheckPG(PG_GPU, "gpu");
  CheckPG(PG_RENDERERS, "renderers");
  CheckPG(PG_ARC, "arc");
  CheckPG(PG_VMS, "vms");
  CheckPG(PG_DAEMONS, "daemons");

  CheckMem(MEM_TOTAL, "total");
  CheckMem(MEM_ANON, "anon");
  CheckMem(MEM_FILE, "file");
  CheckMem(MEM_SHMEM, "shmem");
  CheckMem(MEM_SWAP, "swap");

  // Extra consistency checks.
  ProcessMemoryStats stats;
  CHECK_EQ(std::size(stats.rss_sizes), std::size(kProcessMemoryUMANames[0]));
  CHECK_EQ(std::size(kProcessMemoryUMANames), PG_KINDS_COUNT);
}

}  // namespace chromeos_metrics
