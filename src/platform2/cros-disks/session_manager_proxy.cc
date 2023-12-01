// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/session_manager_proxy.h"

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace cros_disks {

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
    for (SessionManagerObserverInterface& observer : observer_list_)
      observer.OnSessionStarted();
  } else if (state == "stopped") {
    for (SessionManagerObserverInterface& observer : observer_list_)
      observer.OnSessionStopped();
  }
}

}  // namespace cros_disks
