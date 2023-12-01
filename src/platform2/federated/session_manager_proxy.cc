// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/session_manager_proxy.h"

#include <utility>

#include <base/functional/bind.h>
#include <dbus/login_manager/dbus-constants.h>

#include "federated/utils.h"

namespace federated {

namespace {

constexpr char kUnknownErrorMsg[] = "Unknown error";

void OnSignalConnected(const std::string& interface,
                       const std::string& signal,
                       bool success) {
  if (!success) {
    LOG(ERROR) << "Could not connect to signal " << signal << " on interface "
               << interface;
  }
}

}  // namespace

SessionManagerProxy::SessionManagerProxy(
    std::unique_ptr<org::chromium::SessionManagerInterfaceProxyInterface> proxy)
    : proxy_(std::move(proxy)), weak_ptr_factory_(this) {
  proxy_->RegisterSessionStateChangedSignalHandler(
      base::BindRepeating(&SessionManagerProxy::OnSessionStateChanged,
                          weak_ptr_factory_.GetMutableWeakPtr()),
      base::BindOnce(&OnSignalConnected));
}

SessionManagerProxy::~SessionManagerProxy() = default;

void SessionManagerProxy::AddObserver(
    SessionManagerObserverInterface* const observer) {
  CHECK(observer) << "Invalid observer object";
  observer_list_.AddObserver(observer);
}

void SessionManagerProxy::OnSessionStateChanged(const std::string& state) {
  if (state == kSessionStartedState) {
    for (SessionManagerObserverInterface& observer : observer_list_)
      observer.OnSessionStarted();
  } else if (state == kSessionStoppedState) {
    for (SessionManagerObserverInterface& observer : observer_list_)
      observer.OnSessionStopped();
  }
}

std::string SessionManagerProxy::RetrieveSessionState() {
  dbus::MethodCall method_call(
      login_manager::kSessionManagerInterface,
      login_manager::kSessionManagerRetrieveSessionState);
  std::string state;
  brillo::ErrorPtr error;
  if (!proxy_->RetrieveSessionState(&state, &error)) {
    const char* const error_msg =
        error ? error->GetMessage().c_str() : kUnknownErrorMsg;
    LOG(ERROR) << "Call to RetrieveSessionState failed. " << error_msg;
    return std::string();
  }
  return state;
}

std::string SessionManagerProxy::GetSanitizedUsername() {
  std::string username;
  std::string sanitized_username;
  brillo::ErrorPtr error;
  if (!proxy_->RetrievePrimarySession(&username, &sanitized_username, &error)) {
    const char* error_msg =
        error ? error->GetMessage().c_str() : kUnknownErrorMsg;
    LOG(ERROR) << "Call to RetrievePrimarySession failed. " << error_msg;
    return std::string();
  }
  return sanitized_username;
}

}  // namespace federated
