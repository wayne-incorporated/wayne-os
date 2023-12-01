// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_PROCESS_KILLER_PROCESS_KILLER_H_
#define INIT_PROCESS_KILLER_PROCESS_KILLER_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <init/process_killer/process.h>
#include <init/process_killer/process_manager.h>

namespace init {

// ProcessKiller searches for processes of interest that can live beyond the
// boundary of a mount and can potentially keep a device open.
class ProcessKiller {
 public:
  ProcessKiller(bool session, bool boot);
  ~ProcessKiller() = default;
  void KillProcesses(bool files, bool devices);
  void LogProcesses();

  void SetProcessManagerForTesting(std::unique_ptr<ProcessManager> pm) {
    pm_ = std::move(pm);
  }

 private:
  void UpdateProcessList(bool files, bool devices);

  const re2::RE2 mount_regex_;
  const re2::RE2 device_regex_;

  std::vector<ActiveProcess> process_list_;
  std::unique_ptr<ProcessManager> pm_;
};

}  // namespace init

#endif  // INIT_PROCESS_KILLER_PROCESS_KILLER_H_
