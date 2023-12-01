// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOOTLOCKBOX_BOOT_LOCKBOX_SERVICE_H_
#define BOOTLOCKBOX_BOOT_LOCKBOX_SERVICE_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>
#include <libhwsec/factory/factory_impl.h>

#include "bootlockbox/boot_lockbox_dbus_adaptor.h"
#include "bootlockbox/metrics.h"
#include "bootlockbox/nvram_boot_lockbox.h"

namespace bootlockbox {

// BootLockboxService that implements the top level setups of bootlockboxd.
class BootLockboxService : public brillo::DBusServiceDaemon {
 public:
  BootLockboxService();
  BootLockboxService(const BootLockboxService&) = delete;
  BootLockboxService& operator=(const BootLockboxService&) = delete;

  ~BootLockboxService();

 protected:
  int OnInit() override;
  void OnShutdown(int* exit_code) override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

 private:
  hwsec::FactoryImpl hwsec_factory_;
  std::unique_ptr<Metrics> metrics_;
  std::unique_ptr<HwsecSpace> nvspace_utility_;
  std::unique_ptr<NVRamBootLockbox> boot_lockbox_;
  std::unique_ptr<BootLockboxDBusAdaptor> boot_lockbox_dbus_adaptor_;
  base::WeakPtrFactory<BootLockboxService> weak_factory_{this};
};

}  // namespace bootlockbox

#endif  // BOOTLOCKBOX_BOOT_LOCKBOX_SERVICE_H_
