// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootlockbox/boot_lockbox_dbus_adaptor.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <brillo/errors/error.h>
#include <brillo/errors/error_codes.h>
#include <brillo/secure_blob.h>
#include <dbus/dbus-protocol.h>

#include "bootlockbox/proto_bindings/boot_lockbox_rpc.pb.h"

namespace {
// Creates a dbus error message.
brillo::ErrorPtr CreateError(const std::string& code,
                             const std::string& message) {
  return brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain, code,
                               message);
}

}  // namespace

namespace bootlockbox {

BootLockboxDBusAdaptor::BootLockboxDBusAdaptor(scoped_refptr<dbus::Bus> bus,
                                               NVRamBootLockbox* boot_lockbox)
    : org::chromium::BootLockboxInterfaceAdaptor(this),
      boot_lockbox_(boot_lockbox),
      dbus_object_(
          nullptr,
          bus,
          org::chromium::BootLockboxInterfaceAdaptor::GetObjectPath()) {}

void BootLockboxDBusAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

void BootLockboxDBusAdaptor::StoreBootLockbox(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        bootlockbox::StoreBootLockboxReply>> response,
    const bootlockbox::StoreBootLockboxRequest& in_request) {
  if (!in_request.has_key() || !in_request.has_data()) {
    brillo::ErrorPtr error =
        CreateError(DBUS_ERROR_INVALID_ARGS,
                    "StoreBootLockboxRequest has invalid argument(s).");
    response->ReplyWithError(error.get());
    return;
  }

  bootlockbox::StoreBootLockboxReply reply;
  bootlockbox::BootLockboxErrorCode boot_lockbox_error;
  if (!boot_lockbox_->Store(in_request.key(), in_request.data(),
                            &boot_lockbox_error)) {
    reply.set_error(boot_lockbox_error);
  }
  response->Return(reply);
}

void BootLockboxDBusAdaptor::ReadBootLockbox(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        bootlockbox::ReadBootLockboxReply>> response,
    const bootlockbox::ReadBootLockboxRequest& in_request) {
  if (!in_request.has_key()) {
    brillo::ErrorPtr error =
        CreateError(DBUS_ERROR_INVALID_ARGS,
                    "ReadBootLockboxRequest has invalid argument(s).");
    response->ReplyWithError(error.get());
    return;
  }
  bootlockbox::ReadBootLockboxReply reply;
  std::string data;
  bootlockbox::BootLockboxErrorCode boot_lockbox_error;
  if (!boot_lockbox_->Read(in_request.key(), &data, &boot_lockbox_error)) {
    reply.set_error(boot_lockbox_error);
  } else {
    reply.set_data(data);
  }
  response->Return(reply);
}

void BootLockboxDBusAdaptor::FinalizeBootLockbox(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        bootlockbox::FinalizeBootLockboxReply>> response,
    const bootlockbox::FinalizeNVRamBootLockboxRequest& in_request) {
  bootlockbox::FinalizeBootLockboxReply reply;
  if (!boot_lockbox_->Finalize()) {
    // Failed to finalize, could be communication error or other error.
    reply.set_error(bootlockbox::BOOTLOCKBOX_ERROR_NVSPACE_OTHER);
  }
  response->Return(reply);
}

}  // namespace bootlockbox
