// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_PROCESS_METER_H_
#define METRICS_PROCESS_METER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>

namespace chromeos_metrics {

static constexpr char kMetricsARCInitPIDFile[] =
    "containers/android-run_oci/container.pid";
static const int kPageSize = 4096;

enum MemoryStatKind {
  MEM_TOTAL = 0,
  MEM_ANON,
  MEM_FILE,
  MEM_SHMEM,
  MEM_SWAP,
  MEM_KINDS_COUNT
};

// Memory usage stats for processes.  Units are bytes.
struct ProcessMemoryStats {
  uint64_t rss_sizes[MEM_KINDS_COUNT] = {};
};

// Process group kinds, representing disjoint sets of processes.
enum ProcessGroupKind {
  PG_BROWSER = 0,
  PG_GPU,
  PG_RENDERERS,
  PG_ARC,
  PG_VMS,      // Except for ARCVM
  PG_DAEMONS,  // Everything that's not in one of the other categories.
  PG_KINDS_COUNT
};

// Names of process memory UMA histograms.
extern const char* const kProcessMemoryUMANames[PG_KINDS_COUNT]
                                               [MEM_KINDS_COUNT];

// Types of chrome processes.
enum ChromeProcessKind {
  CHROME_NOT_CHROME,
  CHROME_BROWSER,
  CHROME_BROWSER_HELPER,
  CHROME_RENDERER,
  CHROME_GPU,
  CHROME_OTHER,
};

// ProcessNode represents a process, and is used in building a process tree,
// where each node has pointers to nodes representing the parent and children of
// its process.
class ProcessNode {
 public:
  explicit ProcessNode(int pid)
      : pid_(pid), cmdline_(base::CommandLine::NO_PROGRAM) {}
  ProcessNode(const ProcessNode&) = delete;
  ProcessNode& operator=(const ProcessNode&) = delete;

  ~ProcessNode() {}

  // GetPID returns the PID of the process.
  const int GetPID() const { return pid_; }

  // Returns the command line of the process.
  const base::CommandLine GetCmdline() const { return cmdline_; }

  // Returns the command line of the process as a string.
  const std::string GetCmdlineString() const { return cmdline_string_; }

  // Adds to |processes| this node and all its descendants.
  void CollectSubtree(std::vector<ProcessNode*>* processes);

  // Does the same as CollectSubtree, but only when the |filter| returns true.
  using CollectSubtreeFilter =
      base::RepeatingCallback<bool(const ProcessNode&)>;
  void CollectSubtree(std::vector<ProcessNode*>* processes,
                      const CollectSubtreeFilter& filter);

  // Fills the process node with data from /proc.
  bool RetrieveProcessData(const base::FilePath& procfs_root);

  // Links this process node to its parent based on the node PID,
  // and adds the node to the parent's children list.
  void LinkToParent(
      const std::unordered_map<int, std::unique_ptr<ProcessNode>>& processes);

  // Finds the type of chrome process from its command line.
  const ChromeProcessKind GetChromeKind(std::string cmdline) const;

  // Returns true if the process name starts with |prefix|.
  const bool HasPrefix(const std::string& prefix) const;

 private:
  const int pid_;
  int ppid_ = 0;
  std::string name_;
  base::CommandLine cmdline_;
  std::string cmdline_string_;
  // All ProcessNode instances are owned by process_map_ in ProcessInfo.
  ProcessNode* parent_ = nullptr;
  std::vector<ProcessNode*> children_;
};

// If ARC is running, returns true and places the ARC init PID in |pid_out|.
bool GetARCInitPID(const base::FilePath& run_root, int* pid_out);

// Looks in |processes| for a process whose cmdline starts with |prefix|.
// Returns true if found, and stores the process into |process|.
bool FindProcessWithPrefix(
    const std::string& prefix,
    const std::unordered_map<int, std::unique_ptr<ProcessNode>>& processes,
    ProcessNode** process);

// Class for collecting information about all processes.
class ProcessInfo {
 public:
  ProcessInfo(const base::FilePath& procfs_root, const base::FilePath& run_root)
      : procfs_root_(procfs_root), run_root_(run_root) {}
  ProcessInfo(const ProcessInfo&) = delete;
  ProcessInfo& operator=(const ProcessInfo&) = delete;

  ~ProcessInfo() {}

  // Takes a snapshot of existing processes and builds the process tree.
  void Collect();

  // Classifies processes in process_map_ into groups.
  void Classify();

  // Returns process group |g| (for instance, g = PG_RENDERERS).
  const std::vector<ProcessNode*>& GetGroup(ProcessGroupKind group_kind);

 private:
  // Maps PIDs to nodes in the process tree.  This is the owner of all process
  // nodes.
  std::unordered_map<int, std::unique_ptr<ProcessNode>> process_map_;
  // Disjoint groups of processes.
  std::vector<ProcessNode*> groups_[PG_KINDS_COUNT];

  // Paths to /proc and /run, or mocks for testing.
  base::FilePath procfs_root_;
  base::FilePath run_root_;
};

// Accumulates memory usage stats for a group of processes.  |procfs_path|
// contains /proc or the path of a mock /proc filesystem.  Processes that no
// longer exist are ignored.
void AccumulateProcessGroupStats(const base::FilePath& procfs_path,
                                 const std::vector<ProcessNode*>& processes,
                                 ProcessMemoryStats* stats);

// GetMemoryUsage fills |stats| with memory usage stats for |pid|.  The
// information is from /proc/<pid>/totmaps or /proc/<pid>/smaps_rollup,
// depending on which is available.  These files are expected to contain some
// chromiumos-specific kernel changes (the smaps_rollup changes have been
// upstreamed).  If some fields are missing, only some of the stats wil be
// valid.
void GetMemoryUsage(const base::FilePath& procfs_path,
                    int pid,
                    ProcessMemoryStats* stats);

}  // namespace chromeos_metrics

#endif  // METRICS_PROCESS_METER_H_
