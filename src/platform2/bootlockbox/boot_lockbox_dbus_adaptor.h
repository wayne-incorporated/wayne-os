// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOOTLOCKBOX_BOOT_LOCKBOX_DBUS_ADAPTOR_H_
#define BOOTLOCKBOX_BOOT_LOCKBOX_DBUS_ADAPTOR_H_

#include <memory>
#include <vector>

#include "bootlockbox/nvram_boot_lockbox.h"
#include "bootlockbox/proto_bindings/boot_lockbox_rpc.pb.h"

#include "dbus_adaptors/org.chromium.BootLockboxInterface.h"

namespace bootlockbox {
// Implements DBus BootLockboxInterface.
class BootLockboxDBusAdaptor
    : public org::chromium::BootLockboxInterfaceInterface,
      public org::chromium::BootLockboxInterfaceAdaptor {
 public:
  // Don't own boot_lockbox, it is managed by BootLockboxService.
  explicit BootLockboxDBusAdaptor(scoped_refptr<dbus::Bus> bus,
                                  NVRamBootLockbox* boot_lockbox);
  BootLockboxDBusAdaptor(const BootLockboxDBusAdaptor&) = delete;
  BootLockboxDBusAdaptor& operator=(const BootLockboxDBusAdaptor&) = delete;

  // Registers dbus objects.
  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  // Stores a digest in bootlockbox.
  void StoreBootLockbox(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          bootlockbox::StoreBootLockboxReply>> response,
      const bootlockbox::StoreBootLockboxRequest& in_request) override;

  // Reads a digest from bootlockbox.
  void ReadBootLockbox(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          bootlockbox::ReadBootLockboxReply>> response,
      const bootlockbox::ReadBootLockboxRequest& in_request) override;

  // Finalizes the BootLockbox and locks the signing key. |response| is of type
  // BaseReply.
  void FinalizeBootLockbox(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          bootlockbox::FinalizeBootLockboxReply>> response,
      const bootlockbox::FinalizeNVRamBootLockboxRequest& in_request) override;

 private:
  NVRamBootLockbox* boot_lockbox_;
  brillo::dbus_utils::DBusObject dbus_object_;
};

}  // namespace bootlockbox

#endif  // BOOTLOCKBOX_BOOT_LOCKBOX_DBUS_ADAPTOR_H_
