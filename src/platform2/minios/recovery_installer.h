// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_RECOVERY_INSTALLER_H_
#define MINIOS_RECOVERY_INSTALLER_H_

#include <string>

#include "minios/process_manager.h"
#include "minios/recovery_installer_interface.h"

namespace minios {

class RecoveryInstaller : public RecoveryInstallerInterface {
 public:
  explicit RecoveryInstaller(ProcessManagerInterface* process_manager)
      : repartition_completed_(false), process_manager_(process_manager) {}
  virtual ~RecoveryInstaller() = default;

  RecoveryInstaller(const RecoveryInstaller&) = delete;
  RecoveryInstaller& operator=(const RecoveryInstaller&) = delete;

  bool RepartitionDisk() override;

 private:
  // Only repartition the disk once per recovery attempt.
  bool repartition_completed_;

  ProcessManagerInterface* process_manager_;
};

}  // namespace minios

#endif  // MINIOS_RECOVERY_INSTALLER_H_
