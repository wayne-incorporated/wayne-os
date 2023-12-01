// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/da_reset/da_resetter.h"

#include <memory>
#include <utility>

#include <base/logging.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

// This has to go after tpm_manager.pb.h.
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

namespace hwsec_foundation {

namespace {

std::unique_ptr<org::chromium::TpmManagerProxyInterface>
CreateTpmManagerProxy() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus = base::MakeRefCounted<dbus::Bus>(options);
  CHECK(bus->Connect()) << __func__ << "Failed to connect to system D-Bus";
  return std::unique_ptr<org::chromium::TpmManagerProxyInterface>(
      new org::chromium::TpmManagerProxy(bus));
}

}  // namespace

DAResetter::DAResetter() : DAResetter(CreateTpmManagerProxy()) {}

DAResetter::DAResetter(
    std::unique_ptr<org::chromium::TpmManagerProxyInterface> proxy)
    : proxy_(std::move(proxy)) {}

bool DAResetter::ResetDictionaryAttackLock() {
  brillo::ErrorPtr err;
  tpm_manager::ResetDictionaryAttackLockRequest request;
  request.set_is_async(true);
  tpm_manager::ResetDictionaryAttackLockReply reply;

  if (!proxy_->ResetDictionaryAttackLock(request, &reply, &err)) {
    LOG(ERROR) << __func__
               << "Error calling `ResetDictionaryAttackLock()` D-Bus method: "
               << err->GetMessage();
    return false;
  }
  if (reply.status() != tpm_manager::STATUS_SUCCESS) {
    LOG(ERROR) << __func__ << " Failed to reset DA: " << reply.status();
    return false;
  }
  return true;
}

}  // namespace hwsec_foundation
