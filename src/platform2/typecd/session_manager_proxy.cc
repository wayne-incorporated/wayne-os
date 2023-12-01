// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/session_manager_proxy.h"

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace typecd {

namespace {

void OnSignalConnected(const std::string& interface,
                       const std::string& signal,
                       bool success) {
  if (!success) {
    LOG(ERROR) << "Could not connect to signal " << signal << " on interface "
               << interface;
  }
}

}  // namespace

SessionManagerProxy::SessionManagerProxy(scoped_refptr<dbus::Bus> bus)
    : proxy_(bus), weak_ptr_factory_(this) {
  proxy_.RegisterScreenIsLockedSignalHandler(
      base::BindRepeating(&SessionManagerProxy::OnScreenIsLocked,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));
  proxy_.RegisterScreenIsUnlockedSignalHandler(
      base::BindRepeating(&SessionManagerProxy::OnScreenIsUnlocked,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));
  proxy_.RegisterSessionStateChangedSignalHandler(
      base::BindRepeating(&SessionManagerProxy::OnSessionStateChanged,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));
}

void SessionManagerProxy::AddObserver(
    SessionManagerObserverInterface* observer) {
  CHECK(observer) << "Invalid observer object";
  observer_list_.AddObserver(observer);
}

bool SessionManagerProxy::IsScreenLocked() {
  brillo::ErrorPtr error;
  bool locked;
  if (!proxy_.IsScreenLocked(&locked, &error)) {
    LOG(ERROR) << "Failed to get lockscreen state: " << error->GetMessage();
    return false;
  }

  return locked;
}

bool SessionManagerProxy::IsSessionStarted() {
  brillo::ErrorPtr error;
  std::string state;
  if (!proxy_.RetrieveSessionState(&state, &error)) {
    LOG(ERROR) << "Failed to get session state: " << error->GetMessage();
    return false;
  }

  return state == "started";
}

void SessionManagerProxy::OnScreenIsLocked() {
  for (SessionManagerObserverInterface& observer : observer_list_)
    observer.OnScreenIsLocked();
}

void SessionManagerProxy::OnScreenIsUnlocked() {
  for (SessionManagerObserverInterface& observer : observer_list_)
    observer.OnScreenIsUnlocked();
}

void SessionManagerProxy::OnSessionStateChanged(const std::string& state) {
  if (state == "started") {
    // Guest sessions are treated the same as login screens.
    bool guest_active;
    brillo::ErrorPtr error;
    if (!proxy_.IsGuestSessionActive(&guest_active, &error)) {
      LOG(ERROR) << "Failed to check guest session state: "
                 << error->GetMessage();
      return;
    }

    if (guest_active) {
      LOG(INFO) << "Guest session started.";
      return;
    }

    // If it's not a guest session, proceed with notifying the observers (they
    // can then change alt modes if appropriate).
    for (SessionManagerObserverInterface& observer : observer_list_)
      observer.OnSessionStarted();
  } else if (state == "stopped") {
    for (SessionManagerObserverInterface& observer : observer_list_)
      observer.OnSessionStopped();
  }
}

}  // namespace typecd
