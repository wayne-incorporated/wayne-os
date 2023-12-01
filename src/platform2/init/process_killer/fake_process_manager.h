// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_PROCESS_KILLER_FAKE_PROCESS_MANAGER_H_
#define INIT_PROCESS_KILLER_FAKE_PROCESS_MANAGER_H_

#include <sys/types.h>
#include <vector>

#include <base/files/file_path.h>

#include <init/process_killer/process.h>

namespace init {

class FakeProcessManager : public ProcessManager {
 public:
  FakeProcessManager() : ProcessManager(base::FilePath("/foo")) {}
  ~FakeProcessManager() override = default;

  std::vector<ActiveProcess> GetProcessList(bool need_files,
                                            bool need_mounts) override {
    return process_list_;
  }
  bool SendSignalToProcess(const ActiveProcess& p, int signal) override {
    if (signal == SIGTERM || signal == SIGKILL) {
      auto iter = std::find_if(process_list_.begin(), process_list_.end(),
                               [&p](const ActiveProcess& process) {
                                 return p.GetPid() == process.GetPid();
                               });
      if (iter != process_list_.end())
        process_list_.erase(iter);
    }

    return true;
  }

  void SetProcessListForTesting(
      const std::vector<ActiveProcess>& process_list) {
    process_list_ = process_list;
  }

 private:
  std::vector<ActiveProcess> process_list_;
};

}  // namespace init
#endif  // INIT_PROCESS_KILLER_FAKE_PROCESS_MANAGER_H_
