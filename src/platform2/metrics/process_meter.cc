// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/process_meter.h"

#include <errno.h>

#include <string>
#include <unordered_map>
#include <vector>

#include <base/check_op.h>
#include <base/command_line.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <re2/re2.h>

#include "metrics/metrics_library.h"

namespace chromeos_metrics {

namespace {

// A string which crosvm's command line for ARCVM always has.
constexpr char const* kArcVmCommandLine = "androidboot.hardware=bertha";

bool IsArcVmProcess(const ProcessNode& node) {
  return node.GetCmdlineString().find(kArcVmCommandLine) != std::string::npos;
}

bool IsNotArcVmProcess(const ProcessNode& node) {
  return !IsArcVmProcess(node);
}

}  // namespace

// UMA histogram names for process memory usage, split by process groups and
// types of memory.  They must match MemoryStatKind and ProcessGroupKind in
// process_meter.h.  C++ doesn't have C-style static array initializers, so the
// unit test checks this.
constexpr char const* kProcessMemoryUMANames[PG_KINDS_COUNT][MEM_KINDS_COUNT] =
    {{
         "Platform.Memory.Browser.Total",
         "Platform.Memory.Browser.Anon",
         "Platform.Memory.Browser.File",
         "Platform.Memory.Browser.Shmem",
         "Platform.Memory.Browser.Swap",
     },
     {
         "Platform.Memory.Gpu.Total",
         "Platform.Memory.Gpu.Anon",
         "Platform.Memory.Gpu.File",
         "Platform.Memory.Gpu.Shmem",
         "Platform.Memory.Gpu.Swap",
     },
     {
         "Platform.Memory.Renderers.Total",
         "Platform.Memory.Renderers.Anon",
         "Platform.Memory.Renderers.File",
         "Platform.Memory.Renderers.Shmem",
         "Platform.Memory.Renderers.Swap",
     },
     {
         "Platform.Memory.ARC.Total",
         "Platform.Memory.ARC.Anon",
         "Platform.Memory.ARC.File",
         "Platform.Memory.ARC.Shmem",
         "Platform.Memory.ARC.Swap",
     },
     {
         "Platform.Memory.VMs.Total",
         "Platform.Memory.VMs.Anon",
         "Platform.Memory.VMs.File",
         "Platform.Memory.VMs.Shmem",
         "Platform.Memory.VMs.Swap",
     },
     {
         "Platform.Memory.Daemons.Total",
         "Platform.Memory.Daemons.Anon",
         "Platform.Memory.Daemons.File",
         "Platform.Memory.Daemons.Shmem",
         "Platform.Memory.Daemons.Swap",
     }};

// Chrome process classification.  We rely on the "--type=xyz" command line flag
// to processes.  A partial list of types is in
// content/public/common/content_switches.cc.  We classify them as shown:
//
// const char kGpuProcess[]                    = "gpu-process";    // GPU
// const char kPpapiBrokerProcess[]            = "ppapi-broker";   // browser
// const char kPpapiPluginProcess[]            = "ppapi";          // renderer
// const char kRendererProcess[]               = "renderer";       // renderer
// const char kUtilityProcess[]                = "utility";        // renderer
//
// (PPAPI stands for "pepper plugin API", which includes Flash).  Additionally
// there is "zygote" and "broker", which we classify as browser.
//
// The browser process does not have a --type==xyz flag.

ChromeProcessKind GetChromeKind(const base::CommandLine& cmdline) {
  // Assume all Chrome binaries are in /opt/google/chrome.
  auto program = cmdline.GetProgram().MaybeAsASCII();

  // Chrome execs a bunch of other binaries (for instance, crossystem) so we
  // can't have a complete list.
  if (!base::StartsWith(program, "/opt/google/chrome",
                        base::CompareCase::SENSITIVE)) {
    return CHROME_OTHER;
  }

  if (program.find("/opt/google/chrome/nacl_helper") == 0)
    return CHROME_BROWSER_HELPER;

  // The Browser process needs to be identified as a binary named "chrome"
  // in addition to not having a "type" because there are other binaries
  // in that directory which may be running.
  if (!cmdline.HasSwitch("type") && (program == "/opt/google/chrome/chrome"))
    return CHROME_BROWSER;

  auto type = cmdline.GetSwitchValueASCII("type");
  // TODO(chromium:963210): remove the following "if" and let the next one
  // handle the "broker" case.
  if (strcmp(type.c_str(), "broker") == 0)
    return CHROME_BROWSER_HELPER;

  if (type == "broker" || type == "ppapi-broker" || type == "zygote") {
    return CHROME_BROWSER_HELPER;
  }

  // clang-format off
  if (type == "renderer" ||
      type == "ppapi" ||
      type == "sandbox" ||
      type == "utility") {
    return CHROME_RENDERER;
  }
  // clang-format on

  if (type == "gpu-process")
    return CHROME_GPU;

  return CHROME_OTHER;
}

bool GetARCInitPID(const base::FilePath& run_root, int* pid_out) {
  // ARC init may have stopped and restarted, so look up its PID.
  std::string file_content;
  const base::FilePath pid_file = run_root.Append(kMetricsARCInitPIDFile);
  if (!base::ReadFileToString(pid_file, &file_content)) {
    // ARC is not running or failed to read the file.
    PLOG_IF(ERROR, errno != ENOENT) << "Failed to read " << pid_file;
    return false;
  }

  base::TrimWhitespaceASCII(file_content, base::TRIM_TRAILING, &file_content);
  if (!base::StringToInt(file_content, pid_out)) {
    LOG(FATAL) << "invalid integer in ARC init pid file: " << file_content;
  }
  return true;
}

bool FindProcessWithPrefix(
    const std::string& prefix,
    const std::unordered_map<int, std::unique_ptr<ProcessNode>>& processes,
    ProcessNode** process) {
  for (const auto& pit : processes) {
    if (pit.second->HasPrefix(prefix)) {
      *process = pit.second.get();
      return true;
    }
  }
  return false;
}

const bool ProcessNode::HasPrefix(const std::string& prefix) const {
  return cmdline_.GetProgram().MaybeAsASCII().find(prefix) == 0;
}

void ProcessNode::CollectSubtree(std::vector<ProcessNode*>* processes) {
  CollectSubtree(processes, CollectSubtreeFilter());
}

void ProcessNode::CollectSubtree(std::vector<ProcessNode*>* processes,
                                 const CollectSubtreeFilter& filter) {
  if (!filter || filter.Run(*this))
    processes->push_back(this);
  for (const auto& child : children_) {
    child->CollectSubtree(processes, filter);
  }
}

void ProcessInfo::Classify() {
  // Find all ARC processes starting from ARC init.
  int arc_init_pid;
  if (GetARCInitPID(run_root_, &arc_init_pid)) {
    if (process_map_.find(arc_init_pid) == process_map_.end()) {
      LOG(WARNING) << "ARC init disappeared";
    } else {
      process_map_[arc_init_pid]->CollectSubtree(&groups_[PG_ARC]);
    }
  }

  // Find VM processes starting from vm_concierge and seneschal processes.
  ProcessNode* concierge;
  if (FindProcessWithPrefix("/usr/bin/vm_concierge", process_map_,
                            &concierge)) {
    concierge->CollectSubtree(&groups_[PG_ARC],
                              base::BindRepeating(&IsArcVmProcess));
    concierge->CollectSubtree(&groups_[PG_VMS],
                              base::BindRepeating(&IsNotArcVmProcess));
  }

  ProcessNode* seneschal;
  if (FindProcessWithPrefix("/usr/bin/seneschal", process_map_, &seneschal)) {
    seneschal->CollectSubtree(&groups_[PG_VMS]);
  }

  // Find the browser process.
  ProcessNode* browser_process = nullptr;
  for (const auto& pit : process_map_) {
    if (GetChromeKind(pit.second->GetCmdline()) == CHROME_BROWSER) {
      browser_process = pit.second.get();
    }
  }

  // Find all descendants of the chrome browser.
  std::vector<ProcessNode*> chrome_processes;
  if (browser_process != nullptr)
    browser_process->CollectSubtree(&chrome_processes);

  // Classify the chrome processes.
  for (const auto& process : chrome_processes) {
    switch (GetChromeKind(process->GetCmdline())) {
      case CHROME_RENDERER:
        groups_[PG_RENDERERS].push_back(process);
        break;
      case CHROME_GPU:
        groups_[PG_GPU].push_back(process);
        break;
      case CHROME_BROWSER:
      case CHROME_BROWSER_HELPER:
        groups_[PG_BROWSER].push_back(process);
        break;
      case CHROME_OTHER:
        // Treat other as a browser process.
        LOG(WARNING) << "Unknown chrome process type in "
                     << process->GetCmdlineString();
        groups_[PG_BROWSER].push_back(process);
        break;
      case CHROME_NOT_CHROME:
        LOG(FATAL) << "Unexpected chrome process: "
                   << process->GetCmdlineString();
        break;
    }
  }

  // Compute daemon processes.  Start by making a copy of the map of all
  // processes.  Then remove ARC, VMs, and Chrome processes.
  std::unordered_map<int, ProcessNode*> daemon_processes_map;
  for (const auto& pit : process_map_) {
    daemon_processes_map[pit.first] = pit.second.get();
  }

  for (const auto& process : groups_[PG_ARC]) {
    daemon_processes_map.erase(process->GetPID());
  }
  for (const auto& process : groups_[PG_VMS]) {
    daemon_processes_map.erase(process->GetPID());
  }
  for (const auto& process : chrome_processes) {
    daemon_processes_map.erase(process->GetPID());
  }

  for (const auto& pit : daemon_processes_map) {
    groups_[PG_DAEMONS].push_back(pit.second);
  }
}

bool ProcessNode::RetrieveProcessData(const base::FilePath& procfs_root) {
  std::string file_content;
  // Get PPID and name from /proc/#/stat.
  const std::string stat_name = base::StringPrintf("%d/stat", pid_);
  const base::FilePath stat_path = procfs_root.Append(stat_name);
  if (!base::ReadFileToString(stat_path, &file_content)) {
    // Assume process has exited.
    return false;
  }
  // stat: pid (comm) run_state ppid etc. The only parentheses in the file
  // are around <comm>.
  RE2 re(R"(.*\((.*)\) \w+ (\d+)(.|\n)*)");
  if (!RE2::FullMatch(file_content, re, &name_, &ppid_)) {
    // Since there's no guarantees about a processes name -- it might not
    // be UTF-8, for example -- this is just a warning.
    LOG(WARNING) << "cannot parse /proc/pid/stat: " << file_content;
    return false;
  }

  // Get command line from /proc/#/cmdline and parse it.
  const std::string cmdline_name = base::StringPrintf("%d/cmdline", pid_);
  const base::FilePath cmdline_path = procfs_root.Append(cmdline_name);
  if (!base::ReadFileToString(cmdline_path, &file_content)) {
    // Assume process has exited.
    return false;
  }
  cmdline_string_ = file_content;
  cmdline_ = base::CommandLine(base::SplitString(
      file_content, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY));

  return true;
}

void ProcessNode::LinkToParent(
    const std::unordered_map<int, std::unique_ptr<ProcessNode>>& processes) {
  if (ppid_ == 0) {
    // Not every process has a parent.
    return;
  }
  auto pit = processes.find(ppid_);
  if (pit == processes.end()) {
    // Parent process does not exist.  This might happen on a race, before the
    // orphan is reparented to init.  At worst, this should be rare.  We do the
    // reparenting for consistency.
    LOG(WARNING) << "PID " << pid_ << ": parent " << ppid_ << " not found";
    ppid_ = 1;
    pit = processes.find(ppid_);
  }
  // |pit| is now guaranteed to be valid.
  parent_ = pit->second.get();
  parent_->children_.push_back(this);
}

void ProcessInfo::Collect() {
  // Collect all processes.
  base::FileEnumerator proc_enum(procfs_root_, false,
                                 base::FileEnumerator::DIRECTORIES);
  for (base::FilePath path = proc_enum.Next(); !path.empty();
       path = proc_enum.Next()) {
    std::string pid_string = path.BaseName().MaybeAsASCII();
    // Skip directories that do not represent processes.
    int pid;
    if (!base::StringToInt(pid_string, &pid))
      continue;
    if (process_map_.find(pid) == process_map_.end()) {
      process_map_.emplace(pid, std::make_unique<ProcessNode>(pid));
    } else {
      // This seems rather unlikely, but just in case.
      LOG(WARNING) << "duplicate PID: " << pid;
    }
  }

  // Sanity check.
  if (process_map_.find(1) == process_map_.end())
    LOG(FATAL) << "cannot find init process";

  // Construct process tree.
  for (const auto& pit : process_map_) {
    ProcessNode* process = pit.second.get();
    if (!process->RetrieveProcessData(procfs_root_)) {
      // Process went away, so ignore it.
      continue;
    }
    // Set up parent/children links.
    process->LinkToParent(process_map_);
  }
}

const std::vector<ProcessNode*>& ProcessInfo::GetGroup(
    ProcessGroupKind group_kind) {
  return groups_[group_kind];
}

void GetMemoryUsage(const base::FilePath& procfs_path,
                    int pid,
                    ProcessMemoryStats* stats) {
  std::string file_content;
  const std::string file_name = base::StringPrintf("%d/totmaps", pid);
  const base::FilePath file_path = procfs_path.Append(file_name);
  if (!base::ReadFileToString(file_path, &file_content))
    return;
  const std::vector<std::string> lines = base::SplitString(
      file_content, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  struct NameValuePair {
    const std::string name;
    uint64_t value;
  };
  std::vector<NameValuePair> pairs = {{"Pss:", 0},
                                      {"Pss_Anon:", 0},
                                      {"Pss_File:", 0},
                                      {"Pss_Shmem:", 0},
                                      {"Swap:", 0}};
  int index = 0;
  for (const auto& line : lines) {
    if (base::StartsWith(line, pairs[index].name,
                         base::CompareCase::SENSITIVE)) {
      std::vector<std::string> fields = base::SplitString(
          line, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
      if (fields.size() != 3)
        LOG(FATAL) << "bad rollup line: " << line;
      if (!base::StringToUint64(fields[1], &pairs[index].value))
        LOG(FATAL) << "bad integer in rollup line: " << line;
      index++;
      if (index == pairs.size())
        break;
    }
  }
  if (index < pairs.size() && index != 0) {
    // If some fields aren't present, return zeros instead of crashing.
    return;
  }

  stats->rss_sizes[MEM_TOTAL] = pairs[0].value * 1024;
  stats->rss_sizes[MEM_ANON] = pairs[1].value * 1024;
  stats->rss_sizes[MEM_FILE] = pairs[2].value * 1024;
  stats->rss_sizes[MEM_SHMEM] = pairs[3].value * 1024;
  stats->rss_sizes[MEM_SWAP] = pairs[4].value * 1024;
}

void AccumulateProcessGroupStats(const base::FilePath& procfs_path,
                                 const std::vector<ProcessNode*>& processes,
                                 ProcessMemoryStats* stats) {
  for (const auto& process : processes) {
    ProcessMemoryStats process_stats;
    GetMemoryUsage(procfs_path, process->GetPID(), &process_stats);
    // If GetMemoryUsage fails (which will happen if the process has
    // exited), process_stats are all 0 and the accumulation is a no-op.
    for (int i = 0; i < MEM_KINDS_COUNT; i++) {
      stats->rss_sizes[i] += process_stats.rss_sizes[i];
    }
  }
}

}  // namespace chromeos_metrics
