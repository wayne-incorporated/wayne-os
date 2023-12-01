// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_RECOVERY_INSTALLER_INTERFACE_H_
#define MINIOS_RECOVERY_INSTALLER_INTERFACE_H_

namespace minios {

class RecoveryInstallerInterface {
 public:
  virtual ~RecoveryInstallerInterface() = default;

  virtual bool RepartitionDisk() = 0;
};

}  // namespace minios

#endif  // MINIOS_RECOVERY_INSTALLER_INTERFACE_H_
