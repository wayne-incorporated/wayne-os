// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_RECOVERY_INSTALLER_H_
#define MINIOS_MOCK_RECOVERY_INSTALLER_H_

#include <gmock/gmock.h>

#include "minios/recovery_installer_interface.h"

namespace minios {

class MockRecoveryInstaller : public RecoveryInstallerInterface {
 public:
  MockRecoveryInstaller() = default;
  ~MockRecoveryInstaller() = default;

  MockRecoveryInstaller(const MockRecoveryInstaller&) = delete;
  MockRecoveryInstaller& operator=(const MockRecoveryInstaller&) = delete;

  MOCK_METHOD(bool, RepartitionDisk, (), (override));
};

}  // namespace minios

#endif  // MINIOS_MOCK_RECOVERY_INSTALLER_H_
