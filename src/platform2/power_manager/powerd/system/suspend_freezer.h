// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_SUSPEND_FREEZER_H_
#define POWER_MANAGER_POWERD_SYSTEM_SUSPEND_FREEZER_H_

#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "power_manager/common/clock.h"
#include "power_manager/common/prefs.h"

#include <base/files/file_path.h>
#include <base/time/time.h>

namespace power_manager::system {

static constexpr char kFreezerStateFrozen[] = "FROZEN";
static constexpr char kFreezerStateThawed[] = "THAWED";
static constexpr char kStateFile[] = "freezer.state";
extern const base::FilePath kBasePath;
extern const base::FilePath kWakeupCountPath;

enum class FreezeResult {
  SUCCESS = 0,
  FAILURE,
  CANCELED,
};

class SuspendFreezerInterface {
 public:
  SuspendFreezerInterface() = default;
  SuspendFreezerInterface(const SuspendFreezerInterface&) = delete;
  SuspendFreezerInterface& operator=(const SuspendFreezerInterface&) = delete;
  virtual ~SuspendFreezerInterface() = default;

  // Freeze a subset of userspace processes.
  virtual FreezeResult FreezeUserspace(uint64_t wakeup_count,
                                       bool wakeup_count_valid) = 0;
  // Thaw a subset of userspace processes.
  virtual bool ThawUserspace() = 0;
};

class SuspendFreezer : public SuspendFreezerInterface {
 public:
  // Abstract the IO functions into virtual functions for Mock testing.
  class SystemUtilsInterface {
   public:
    SystemUtilsInterface() = default;
    virtual ~SystemUtilsInterface() = default;
    // Return true if |path| exists, and false if it does not.
    virtual bool PathExists(const base::FilePath& path);
    // Returns true on success and false on error.
    virtual bool ReadFileToString(const base::FilePath& path,
                                  std::string* contents);
    // Returns the number of bytes written, or -1 on error.
    virtual int WriteFile(const base::FilePath& path,
                          const char* data,
                          int size);
    // Wrapper around base::FileEnumerator for testing purposes. Populates
    // |dirs| with the directories in |root_path|.
    virtual void GetSubDirs(const base::FilePath& root_path,
                            std::vector<base::FilePath>* dirs);
  };

  SuspendFreezer();
  SuspendFreezer(const SuspendFreezer&) = delete;
  SuspendFreezer& operator=(const SuspendFreezer&) = delete;
  ~SuspendFreezer() override = default;

  void set_sys_utils_for_testing(SystemUtilsInterface* utils) {
    sys_utils_ = std::unique_ptr<SystemUtilsInterface>(utils);
  }

  Clock* clock() { return clock_.get(); }

  // Initializes the SuspendFreezer by making sure the processes are in the
  // THAWED state.
  void Init(PrefsInterface* prefs);

  // SuspendFreezerInterface implementation via the child cgroups of
  // /sys/fs/group/freezer
  FreezeResult FreezeUserspace(uint64_t wakeup_count,
                               bool wakeup_count_valid) override;
  bool ThawUserspace() override;

 private:
  struct CgroupNode {
    // The set of cgroup dependencies that must freeze after the cgroup for this
    // CgroupNode.
    std::unordered_set<base::FilePath> deps;
    // The count of unfrozen cgroups that must freeze before the cgroup for this
    // CgroupNode.
    int rdep_count;
  };

  // Populate |cgroups| with the children of the root freezer (all subdirs of
  // /sys/fs/cgroup/freezer).
  bool GetCgroups(std::vector<base::FilePath>* cgroups);

  // Set the |state_path| cgroup state.
  bool SetCgroupState(const base::FilePath& cgroup_path,
                      const std::string& state);

  bool GetCgroupState(const base::FilePath& cgroup_path, std::string* state);

  // Populate the dependencies for the cgroup, |path|, in the dependency graph
  // representation, |graph|, from the suspend_freezer_deps pref for |path|.
  void PopulateCgroupDepsFromPref(
      const base::FilePath& path,
      std::unordered_map<base::FilePath, struct CgroupNode>* graph);

  // This is intended to be run multiple times until all cgroups in |graph| are
  // FROZEN. Some cgroups in |freezing| may not be FROZEN upon completion.
  bool ProcessFreezingCgroups(
      std::unordered_map<base::FilePath, struct CgroupNode>* graph,
      std::list<base::FilePath>* freezing,
      std::vector<base::FilePath>* frozen);

  // Freeze all non-root freezer cgroups via setting |freezer.state| for each
  // child of the root freezer. A return value of |FreezeResult::SUCCESS|
  // indicates that all of these cgroups are frozen. Otherwise, all cgroups are
  // thawed before return.
  FreezeResult TopologicalFreeze(
      uint64_t wakeup_count,
      bool wakeup_count_valid,
      std::unordered_map<base::FilePath, struct CgroupNode>* graph);

  std::unique_ptr<SystemUtilsInterface> sys_utils_;

  std::unique_ptr<Clock> clock_;

  PrefsInterface* prefs_;  // non-owned
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_SUSPEND_FREEZER_H_
