// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_SESSION_MANAGER_PROXY_H_
#define FEDERATED_SESSION_MANAGER_PROXY_H_

#include <memory>
#include <string>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <dbus/bus.h>
#include <session_manager/dbus-proxies.h>

#include "federated/session_manager_observer_interface.h"

namespace federated {

// A proxy class that listens to DBus signals from the session manager and
// notifies a list of registered observers for events.
class SessionManagerProxy {
 public:
  explicit SessionManagerProxy(
      std::unique_ptr<org::chromium::SessionManagerInterfaceProxyInterface>
          proxy);
  SessionManagerProxy(const SessionManagerProxy&) = delete;
  SessionManagerProxy& operator=(const SessionManagerProxy&) = delete;
  ~SessionManagerProxy();

  void AddObserver(SessionManagerObserverInterface* observer);

  // Retrieves the session state immediately. Returns an empty string on error.
  std::string RetrieveSessionState();
  // Retrieves the sanitized username of the primary session.
  std::string GetSanitizedUsername();

 private:
  // Handles the ScreenIsLocked DBus signal.
  void OnScreenIsLocked();

  // Handles the ScreenIsUnlocked DBus signal.
  void OnScreenIsUnlocked();

  // Handles the SessionStateChanged DBus signal.
  void OnSessionStateChanged(const std::string& state);

  const std::unique_ptr<org::chromium::SessionManagerInterfaceProxyInterface>
      proxy_;
  base::ObserverList<SessionManagerObserverInterface> observer_list_;

  const base::WeakPtrFactory<SessionManagerProxy> weak_ptr_factory_;
};

}  // namespace federated

#endif  // FEDERATED_SESSION_MANAGER_PROXY_H_
