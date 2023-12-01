// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/context_adaptor.h"

#include <memory>
#include <optional>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/dbus/dbus_object.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/object_proxy.h>
#include <session_manager/dbus-proxies.h>

namespace arc {
namespace keymaster {
namespace context {

namespace {

scoped_refptr<::dbus::Bus> InitDBusInCurrentTaskRunner() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<::dbus::Bus> bus = new dbus::Bus(options);
  CHECK(bus->Connect()) << "Failed to initialize adaptor DBus connection";
  return bus;
}

}  // namespace

ContextAdaptor::ContextAdaptor() : weak_ptr_factory_(this) {}

ContextAdaptor::~ContextAdaptor() = default;

scoped_refptr<::dbus::Bus> ContextAdaptor::GetBus() {
  // Ensure |bus_| is initialized before usages.
  if (!bus_)
    bus_ = InitDBusInCurrentTaskRunner();
  return bus_;
}

std::optional<std::string> ContextAdaptor::FetchPrimaryUserEmail() {
  // Short circuit if the results is already cached.
  if (cached_email_.has_value())
    return cached_email_.value();

  // Prepare output variables.
  std::string user_email;
  std::string sanitized_username;
  brillo::ErrorPtr error;

  // Make dbus call.
  org::chromium::SessionManagerInterfaceProxy session_manager_proxy(GetBus());
  if (!session_manager_proxy.RetrievePrimarySession(
          &user_email, &sanitized_username, &error)) {
    std::string error_message = error ? error->GetMessage() : "Unknown error.";
    LOG(INFO) << "Failed to get primary session: " << error_message;
    return std::nullopt;
  }

  // Cache and return result.
  cached_email_ = user_email;
  return user_email;
}

std::optional<CK_SLOT_ID> ContextAdaptor::FetchSlotId(Slot slot) {
  switch (slot) {
    case Slot::kUser:
      return FetchPrimaryUserSlotId();
    case Slot::kSystem:
      return FetchSystemSlotId();
    default:
      LOG(ERROR) << "Unknown chaps slot=" << static_cast<int>(slot);
      return std::nullopt;
  }
}

std::optional<CK_SLOT_ID> ContextAdaptor::FetchPrimaryUserSlotId() {
  // Short circuit if the result is already cached.
  if (cached_user_slot_.has_value())
    return cached_user_slot_;

  // Fetch email of the primary signed in user.
  std::optional<std::string> user_email = FetchPrimaryUserEmail();
  if (!user_email.has_value())
    return std::nullopt;

  // Cache and return result.
  cached_user_slot_ = FetchSlotIdFromTpmTokenInfo(user_email);
  return cached_user_slot_;
}

std::optional<CK_SLOT_ID> ContextAdaptor::FetchSystemSlotId() {
  // Initialize |cached_system_slot_| if result is not already cached.
  if (!cached_system_slot_.has_value()) {
    cached_system_slot_ =
        FetchSlotIdFromTpmTokenInfo(/*user_email=*/std::nullopt);
  }
  return cached_system_slot_;
}

std::optional<CK_SLOT_ID> ContextAdaptor::FetchSlotIdFromTpmTokenInfo(
    std::optional<std::string> user_email) {
  // Create the dbus proxy if it's not created.
  if (!pkcs11_proxy_) {
    pkcs11_proxy_.reset(
        new org::chromium::CryptohomePkcs11InterfaceProxy(GetBus()));
  }

  user_data_auth::Pkcs11GetTpmTokenInfoRequest request;
  // Setting a username retrieves the token info for that user. Leaving it empty
  // retrieves token info for the system.
  if (user_email.has_value())
    request.set_username(user_email.value());
  user_data_auth::Pkcs11GetTpmTokenInfoReply reply;
  brillo::ErrorPtr error;
  bool success = pkcs11_proxy_->Pkcs11GetTpmTokenInfo(
      request, &reply, &error, user_data_auth::kUserDataAuthServiceTimeoutInMs);
  if (!success || error) {
    // Error is logged when it is created, so we don't need to log it again.
    LOG(ERROR) << "Could not fetch slot information from cryptohome.";
    return std::nullopt;
  }

  // Return resulting slot.
  return reply.token_info().slot();
}

}  // namespace context
}  // namespace keymaster
}  // namespace arc
