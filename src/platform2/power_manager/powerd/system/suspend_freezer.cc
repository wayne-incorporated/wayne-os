// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <list>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/suspend_freezer.h"

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>

namespace power_manager::system {

const base::FilePath kBasePath("/sys/fs/cgroup/freezer");
const base::FilePath kWakeupCountPath("/sys/power/wakeup_count");

namespace {
static constexpr base::TimeDelta kFreezerTimeout = base::Seconds(10);
static constexpr base::TimeDelta kFreezerSampleTime = base::Milliseconds(10);
}  // namespace

SuspendFreezer::SuspendFreezer()
    : sys_utils_(std::make_unique<SystemUtilsInterface>()),
      clock_(std::make_unique<Clock>()) {}

void SuspendFreezer::Init(PrefsInterface* prefs) {
  DCHECK(prefs);
  prefs_ = prefs;
  // Just in case powerd crashed and respawned after freezing userspace.
  ThawUserspace();
}

bool SuspendFreezer::GetCgroups(std::vector<base::FilePath>* cgroups) {
  sys_utils_->GetSubDirs(kBasePath, cgroups);
  if (cgroups->empty()) {
    LOG(ERROR) << "No children cgroups found in " << kBasePath;
    return false;
  }
  return true;
}

bool SuspendFreezer::SetCgroupState(const base::FilePath& cgroup_path,
                                    const std::string& state) {
  base::FilePath state_path = cgroup_path.Append(kStateFile);

  if (!sys_utils_->PathExists(state_path)) {
    LOG(ERROR) << "File " << state_path
               << " does not exist. Suspend may not succeed as a result";
    return false;
  }

  if (sys_utils_->WriteFile(state_path, state.c_str(), state.size()) !=
      state.size()) {
    LOG(ERROR) << "Failed to set " << state_path.value() << " to " << state
               << ".  Suspend may not succeed as a result";
    return false;
  }

  DVLOG(1) << "Processes in cgroup " << state_path.DirName() << " set to "
           << state;
  return true;
}

bool SuspendFreezer::GetCgroupState(const base::FilePath& cgroup_path,
                                    std::string* state) {
  base::FilePath state_path = cgroup_path.Append(kStateFile);
  std::string str;

  if (!sys_utils_->PathExists(state_path)) {
    LOG(ERROR) << "File " << state_path
               << " does not exist. Suspend may not succeed as a result";
    return false;
  }

  if (!sys_utils_->ReadFileToString(state_path, &str)) {
    LOG(ERROR) << "Failed to read state of file: " << state_path;
    return false;
  }

  base::TrimWhitespaceASCII(str, base::TRIM_ALL, state);
  return true;
}

void SuspendFreezer::PopulateCgroupDepsFromPref(
    const base::FilePath& path,
    std::unordered_map<base::FilePath, struct CgroupNode>* graph) {
  std::string deps_name = kSuspendFreezerDepsPrefix + path.BaseName().value();
  std::string deps_value;

  // A freezer cgroup may have no dependencies. This can happen when a freezer
  // cgroup is setup for reasons other than freeze ordering on suspend, and no
  // processes depend on any processes in that cgroup to freeze successfully. It
  // may also be one of the last cgroups that we want frozen before handing off
  // to the kernel.
  if (!prefs_->GetString(deps_name, &deps_value)) {
    return;
  }

  auto lines = base::SplitString(deps_value, "\n", base::TRIM_WHITESPACE,
                                 base::SPLIT_WANT_ALL);
  for (const std::string& line : lines) {
    base::FilePath dep = kBasePath.Append(line);
    // If the dependency doesn't exist, that's fine. Everything that a cgroup
    // depends on directly should be listed in its own dependencies, so we don't
    // need to add the missing cgroup's dependencies.
    if (!sys_utils_->PathExists(dep.Append(kStateFile))) {
      continue;
    }

    (*graph)[path].deps.insert(dep);
    (*graph)[dep].rdep_count++;
  }
}

bool SuspendFreezer::ProcessFreezingCgroups(
    std::unordered_map<base::FilePath, struct CgroupNode>* graph,
    std::list<base::FilePath>* freezing,
    std::vector<base::FilePath>* frozen) {
  auto it = freezing->begin();
  while (it != freezing->end()) {
    auto cur = it++;
    base::FilePath cgroup = *cur;
    std::string state;
    if (!GetCgroupState(cgroup, &state)) {
      return false;
    } else if (state != kFreezerStateFrozen) {
      continue;
    }

    DVLOG(1) << "Cgroup " << cgroup << " is now frozen";
    freezing->erase(cur);
    frozen->push_back(cgroup);
    for (const auto& dep : (*graph)[cgroup].deps) {
      (*graph)[dep].rdep_count--;
      if ((*graph)[dep].rdep_count == 0) {
        if (!SetCgroupState(dep, kFreezerStateFrozen)) {
          return false;
        }
        freezing->push_back(dep);
      }

      CHECK((*graph)[dep].rdep_count >= 0)
          << "Negative reverse dependency count for " << dep.BaseName();
    }
  }

  return true;
}

FreezeResult SuspendFreezer::TopologicalFreeze(
    uint64_t wakeup_count,
    bool wakeup_count_valid,
    std::unordered_map<base::FilePath, struct CgroupNode>* graph) {
  // |freezing| is a list since we remove all elements from it one at a time
  // (assuming no timeout, etc.).
  std::list<base::FilePath> freezing;
  std::vector<base::FilePath> frozen;
  base::TimeTicks deadline = clock_->GetCurrentTime() + kFreezerTimeout;

  for (const auto& cgroup : *graph) {
    if (cgroup.second.rdep_count == 0) {
      if (!SetCgroupState(cgroup.first, kFreezerStateFrozen)) {
        return FreezeResult::FAILURE;
      }
      freezing.push_back(cgroup.first);
    }
  }

  // This performs a freeze on the cgroups with a topological ordering. This is
  // done since cgroups may take a while to freeze, so we may as well freeze
  // them in parallel when possible. Cgroups have deps (dependencies) that must
  // be frozen after the cgroup is frozen.
  if (!ProcessFreezingCgroups(graph, &freezing, &frozen)) {
    return FreezeResult::FAILURE;
  }
  while (!freezing.empty()) {
    if (clock_->GetCurrentTime() > deadline) {
      std::string str;
      for (const auto& cgroup : freezing) {
        str += cgroup.BaseName().value() + " ";
      }
      LOG(ERROR) << "Timeout waiting for cgroups to freeze. Cgroups still "
                    "freezing: "
                 << str;
      return FreezeResult::FAILURE;
    }

    if (wakeup_count_valid) {
      std::string wakeup_string;
      uint64_t read_wakeup;
      if (!sys_utils_->ReadFileToString(kWakeupCountPath, &wakeup_string)) {
        LOG(ERROR) << "Error reading wakeup_count from " << kWakeupCountPath;
        return FreezeResult::FAILURE;
      }

      if (!base::StringToUint64(
              base::TrimWhitespaceASCII(wakeup_string, base::TRIM_ALL),
              &read_wakeup)) {
        LOG(ERROR) << "Error converting wakeup_string |" << wakeup_string
                   << "| to uint64";
        return FreezeResult::FAILURE;
      }

      if (read_wakeup != wakeup_count) {
        LOG(INFO) << "Wakeup before system finished freezing cgroups";
        return FreezeResult::CANCELED;
      }
    }

    base::PlatformThread::Sleep(kFreezerSampleTime);
    if (!ProcessFreezingCgroups(graph, &freezing, &frozen)) {
      return FreezeResult::FAILURE;
    }
  }

  if (frozen.size() != graph->size()) {
    std::string frozen_str, cgroups_str;
    for (const auto& cgroup : frozen) {
      frozen_str += cgroup.BaseName().value() + " ";
    }
    for (const auto& cgroup : *graph) {
      cgroups_str += cgroup.first.BaseName().value() + " ";
    }
    LOG(ERROR) << "Number of frozen cgroups is not correct. Check for circular "
                  "dependencies, etc. in suspend_freezer_deps_* files.\n"
                  "Frozen freezer cgroups: "
               << frozen_str << "\nAll freezer cgroups: " << cgroups_str;
    return FreezeResult::FAILURE;
  }

  return FreezeResult::SUCCESS;
}

FreezeResult SuspendFreezer::FreezeUserspace(uint64_t wakeup_count,
                                             bool wakeup_count_valid) {
  std::vector<base::FilePath> cgroup_paths;
  std::unordered_map<base::FilePath, struct CgroupNode> cgroup_graph;

  if (!GetCgroups(&cgroup_paths)) {
    return FreezeResult::FAILURE;
  }

  for (const auto& path : cgroup_paths) {
    base::FilePath state_file = path.Append(kStateFile);
    // We only operate on cgroups that are children of the root freezer cgroup.
    // This means that we don't need to worry about frozen cgroups that are not
    // self-frozen.
    if (!sys_utils_->PathExists(state_file)) {
      LOG(ERROR) << "File " << kStateFile << " for cgroup freezer directory "
                 << path << " does not exist. All directories in " << kBasePath
                 << " should be a cgroup with this file";
      return FreezeResult::FAILURE;
    }

    std::string state;
    if (!sys_utils_->ReadFileToString(state_file, &state)) {
      LOG(ERROR) << "Could not read state of cgroup " << path;
      return FreezeResult::FAILURE;
    }

    base::TrimWhitespaceASCII(state, base::TRIM_ALL, &state);
    if (state != kFreezerStateThawed) {
      LOG(ERROR) << "State of freezer cgroup " << path.BaseName() << " is "
                 << state << " when it should be " << kFreezerStateThawed;
      return FreezeResult::FAILURE;
    }
    cgroup_graph[path] = {
        .deps = {},
        .rdep_count = 0,
    };
  }

  for (auto& cgroup : cgroup_graph) {
    PopulateCgroupDepsFromPref(cgroup.first, &cgroup_graph);
  }

  return TopologicalFreeze(wakeup_count, wakeup_count_valid, &cgroup_graph);
}

bool SuspendFreezer::ThawUserspace() {
  std::vector<base::FilePath> cgroups;
  bool ret = true;

  if (!GetCgroups(&cgroups)) {
    return false;
  }

  for (const auto& cgroup : cgroups) {
    if (!SetCgroupState(cgroup, kFreezerStateThawed)) {
      ret = false;
    }
  }

  return ret;
}

bool SuspendFreezer::SystemUtilsInterface::PathExists(
    const base::FilePath& path) {
  return base::PathExists(path);
}

bool SuspendFreezer::SystemUtilsInterface::ReadFileToString(
    const base::FilePath& path, std::string* contents) {
  return base::ReadFileToString(path, contents);
}

int SuspendFreezer::SystemUtilsInterface::WriteFile(const base::FilePath& path,
                                                    const char* data,
                                                    int size) {
  return base::WriteFile(path, data, size);
}

void SuspendFreezer::SystemUtilsInterface::GetSubDirs(
    const base::FilePath& root_path, std::vector<base::FilePath>* dirs) {
  base::FileEnumerator dir(root_path, false, base::FileEnumerator::DIRECTORIES);

  for (base::FilePath path = dir.Next(); !path.empty(); path = dir.Next()) {
    dirs->push_back(path);
  }
}

}  // namespace power_manager::system
