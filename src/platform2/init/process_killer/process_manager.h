// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_PROCESS_KILLER_PROCESS_MANAGER_H_
#define INIT_PROCESS_KILLER_PROCESS_MANAGER_H_

#include <sys/types.h>

#include <string>
#include <vector>

#include <base/files/file_path.h>

#include <init/process_killer/process.h>

namespace init {

// ProcessManager acts as the source of truth for processes still running at
// boundary conditions (session, system shutdown).
class ProcessManager {
 public:
  explicit ProcessManager(const base::FilePath& proc);
  virtual ~ProcessManager() = default;
  virtual std::vector<ActiveProcess> GetProcessList(bool need_files,
                                                    bool need_mounts);
  virtual bool SendSignalToProcess(const ActiveProcess& p, int signal);

 private:
  std::vector<ActiveMount> GetMountsForProcess(pid_t pid);
  std::vector<OpenFileDescriptor> GetFileDescriptorsForProcess(pid_t pid);
  std::string GetMountNamespaceForProcess(pid_t pid);

  base::FilePath proc_path_;
};

}  // namespace init
#endif  // INIT_PROCESS_KILLER_PROCESS_MANAGER_H_
