// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_SIMULATOR_SIMULATOR_H_
#define TPM2_SIMULATOR_SIMULATOR_H_

#include <memory>
#include <string>

#include <base/files/file_path_watcher.h>
#include <base/files/file.h>
#include <brillo/daemons/daemon.h>

#include "tpm2-simulator/tpm_executor.h"

namespace tpm2_simulator {

class SimulatorDaemon final : public brillo::Daemon {
 public:
  explicit SimulatorDaemon(TpmExecutor* tpm_executor);
  SimulatorDaemon(const SimulatorDaemon&) = delete;
  SimulatorDaemon& operator=(const SimulatorDaemon&) = delete;
  ~SimulatorDaemon() = default;

  inline void set_sigstop_on_initialized(bool value) {
    sigstop_on_initialized_ = value;
  }

 protected:
  int OnInit() override;
  void OnCommand();
  void OnTpmPathChange(const base::FilePath& path, bool error);

  TpmExecutor* const tpm_executor_;
  bool initialized_{false};
  bool sigstop_on_initialized_{true};
  std::string remain_request_;
  std::unique_ptr<base::FilePathWatcher> tpm_watcher_;
  base::ScopedFD command_fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> command_fd_watcher_;
};

}  // namespace tpm2_simulator

#endif  // TPM2_SIMULATOR_SIMULATOR_H_
