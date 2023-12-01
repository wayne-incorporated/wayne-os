// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootlockbox/boot_lockbox_client.h"

#include <utility>
#include <vector>

#include <base/logging.h>
#include <base/timer/elapsed_timer.h>
#include <dbus/cryptohome/dbus-constants.h>
#include <dbus/dbus.h>

// Note that boot_lockbox_rpc.pb.h have to be included before
// dbus_adaptors/org.chromium.BootLockboxInterface.h because it is used in
// there.
#include "bootlockbox/proto_bindings/boot_lockbox_rpc.pb.h"

#include "bootlockbox/dbus-proxies.h"

namespace bootlockbox {

std::unique_ptr<BootLockboxClient>
BootLockboxClient::CreateBootLockboxClient() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);
  if (!bus->Connect()) {
    LOG(ERROR) << "D-Bus system bus is not ready";
    return nullptr;
  }

  auto bootlockbox_proxy =
      std::make_unique<org::chromium::BootLockboxInterfaceProxy>(bus);

  return std::unique_ptr<BootLockboxClient>(
      new BootLockboxClient(std::move(bootlockbox_proxy), bus));
}

BootLockboxClient::BootLockboxClient(
    std::unique_ptr<org::chromium::BootLockboxInterfaceProxy> bootlockbox,
    scoped_refptr<dbus::Bus> bus)
    : bootlockbox_(std::move(bootlockbox)), bus_(bus) {}

BootLockboxClient::~BootLockboxClient() {
  bus_->ShutdownAndBlock();
}

bool BootLockboxClient::Store(const std::string& key,
                              const std::string& digest) {
  base::ElapsedTimer timer;
  bootlockbox::StoreBootLockboxRequest request;
  request.set_key(key);
  request.set_data(digest);

  bootlockbox::StoreBootLockboxReply reply;
  brillo::ErrorPtr error;
  if (!bootlockbox_->StoreBootLockbox(request, &reply, &error)) {
    LOG(ERROR) << "Failed to call StoreBootLockbox, error: "
               << error->GetMessage();
    return false;
  }

  if (reply.has_error()) {
    LOG(ERROR) << "Failed to call Store, error code: " << reply.error();
    return false;
  }

  VLOG(1) << "BootLockboxClient::Store took "
          << timer.Elapsed().InMillisecondsRoundedUp() << "ms";
  return true;
}

bool BootLockboxClient::Read(const std::string& key, std::string* digest) {
  base::ElapsedTimer timer;
  bootlockbox::ReadBootLockboxRequest request;
  request.set_key(key);

  bootlockbox::ReadBootLockboxReply reply;
  brillo::ErrorPtr error;
  if (!bootlockbox_->ReadBootLockbox(request, &reply, &error)) {
    LOG(ERROR) << "Failed to call ReadBootLockbox, error: "
               << error->GetMessage();
    return false;
  }

  if (reply.has_error()) {
    LOG(ERROR) << "Failed to call ReadBootLockbox, error code: "
               << reply.error();
    return false;
  }
  if (!reply.has_data()) {
    LOG(ERROR) << "Missing data field in ReadBootLockboxReply";
    return false;
  }
  *digest = reply.data();
  return true;
}

bool BootLockboxClient::Finalize() {
  base::ElapsedTimer timer;
  bootlockbox::FinalizeNVRamBootLockboxRequest request;

  bootlockbox::FinalizeBootLockboxReply reply;
  brillo::ErrorPtr error;
  if (!bootlockbox_->FinalizeBootLockbox(request, &reply, &error)) {
    LOG(ERROR) << "Failed to call FinalizeBootLockbox";
    return false;
  }

  if (reply.has_error()) {
    LOG(ERROR) << "Error calling FinalizeBootLockbox, error code: "
               << reply.error();
    return false;
  }
  VLOG(1) << "BootLockboxClient::Finalize took "
          << timer.Elapsed().InMillisecondsRoundedUp() << "ms";
  return true;
}

}  // namespace bootlockbox
