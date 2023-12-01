// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_SESSION_STATE_MANAGER_H_
#define BIOD_SESSION_STATE_MANAGER_H_

#include <optional>
#include <string>

#include <base/observer_list.h>
#include <dbus/object_proxy.h>

#include "biod/biod_constants.h"
#include "biod/biod_metrics.h"

namespace biod {

namespace dbus_constants {
inline constexpr char kSessionStateStarted[] = "started";
inline constexpr char kSessionStateStopped[] = "stopped";
inline constexpr char kDBusErrorNoReply[] =
    "org.freedesktop.DBus.Error.NoReply";
inline constexpr char kDBusErrorServiceUnknown[] =
    "org.freedesktop.DBus.Error.ServiceUnknown";
}  // namespace dbus_constants

class SessionStateManagerInterface {
 public:
  virtual std::string GetPrimaryUser() const = 0;
  virtual bool RefreshPrimaryUser() = 0;

  // Interface for observing session state changes
  class Observer {
   public:
    // Called when user was logged in. |sanitized_username| argument contains
    // unique user hash, |is_new_login| indicates if it was actual user login.
    virtual void OnUserLoggedIn(const std::string& sanitized_username,
                                bool is_new_login) = 0;

    // Called when user was logged out.
    virtual void OnUserLoggedOut() = 0;

    virtual ~Observer() = default;
  };

  // Adds and removes the observer.
  virtual void AddObserver(Observer* observer) = 0;
  virtual void RemoveObserver(Observer* observer) = 0;

  virtual ~SessionStateManagerInterface() = default;
};

class SessionStateManager : public SessionStateManagerInterface {
 public:
  explicit SessionStateManager(dbus::Bus* bus,
                               BiodMetricsInterface* biod_metrics);
  explicit SessionStateManager(const SessionStateManager&) = delete;
  SessionStateManager& operator=(const SessionStateManager&) = delete;
  ~SessionStateManager() override = default;

  std::string GetPrimaryUser() const override;

  // Query session manager for current primary user. Returns true when
  // primary user exists, otherwise returns false.
  bool RefreshPrimaryUser() override;
  void AddObserver(Observer* observer) override;
  void RemoveObserver(Observer* observer) override;

 private:
  // Query session manager for the current primary user. Returns std::nullopt
  // when there was an error while getting primary user.
  std::optional<std::string> RetrievePrimaryUser();

  // Updates primary user internally.
  bool UpdatePrimaryUser();

  // Read or delete records in memory when users log in or out.
  void OnSessionStateChanged(dbus::Signal* signal);

  // Called when org.chromium.SessionManager name changes owner.
  void OnSessionManagerNameOwnerChanged(const std::string& old_owner,
                                        const std::string& new_owner);

  // Proxy for dbus communication with session manager / login.
  scoped_refptr<dbus::ObjectProxy> session_manager_proxy_;

  // Sanitized username of the primary user. Empty if no primary user present.
  std::string primary_user_;

  // List of SessionStateManager observers
  base::ObserverList<Observer>::Unchecked observers_;

  BiodMetricsInterface* biod_metrics_ = nullptr;  // Not owned.
};
}  // namespace biod

#endif  // BIOD_SESSION_STATE_MANAGER_H_
