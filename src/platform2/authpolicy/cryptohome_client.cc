// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/cryptohome_client.h"

#include <memory>

#include <base/logging.h>
#include <brillo/dbus/dbus_object.h>

#include <dbus/cryptohome/dbus-constants.h>
#include <dbus/object_proxy.h>

namespace authpolicy {

CryptohomeClient::CryptohomeClient(
    brillo::dbus_utils::DBusObject* dbus_object) {
  cryptohome_misc_proxy_.reset(
      new org::chromium::CryptohomeMiscInterfaceProxy(dbus_object->GetBus()));
}

CryptohomeClient::~CryptohomeClient() = default;

std::string CryptohomeClient::GetSanitizedUsername(
    const std::string& account_id_key) {
  user_data_auth::GetSanitizedUsernameReply reply;
  user_data_auth::GetSanitizedUsernameRequest request;
  request.set_username(account_id_key);
  brillo::ErrorPtr error;

  bool success = cryptohome_misc_proxy_->GetSanitizedUsername(
      request, &reply, &error, user_data_auth::kUserDataAuthServiceTimeoutInMs);
  if (!success || error) {
    // Error is logged when it is created, so we don't need to log it again.
    LOG(ERROR) << "Failed to get sanitized username from cryptohomed.";
    return std::string();
  }

  return reply.sanitized_username();
}

}  // namespace authpolicy
