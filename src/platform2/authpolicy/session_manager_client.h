// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_SESSION_MANAGER_CLIENT_H_
#define AUTHPOLICY_SESSION_MANAGER_CLIENT_H_

#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback_forward.h>
#include <base/memory/weak_ptr.h>

namespace org {
namespace chromium {
class SessionManagerInterfaceProxy;
}
}  // namespace org

namespace brillo {
namespace dbus_utils {
class DBusObject;
}
class Error;
}  // namespace brillo

namespace authpolicy {

// Exposes methods from the Session Manager daemon.
class SessionManagerClient {
 public:
  explicit SessionManagerClient(brillo::dbus_utils::DBusObject* dbus_object);
  SessionManagerClient(const SessionManagerClient&) = delete;
  SessionManagerClient& operator=(const SessionManagerClient&) = delete;

  virtual ~SessionManagerClient();

  // Exposed Session Manager methods.
  // See Session Manager for a description of the arguments.

  // Blocking for convenience / code simplicity.
  bool ListStoredComponentPolicies(const std::vector<uint8_t>& descriptor_blob,
                                   std::vector<std::string>* component_ids);

  // Connect to the signal invoked when the session state changes. See
  // session_manager_impl.cc for a list of possible states.
  void ConnectToSessionStateChangedSignal(
      const base::RepeatingCallback<void(const std::string& state)>& callback);

  // Retrieves the session state immediately. Returns an empty string on error.
  std::string RetrieveSessionState();

 private:
  // Callback called on SessionStateChanged signal. Calls callback with the new
  // session state.
  void OnSessionStateChanged(
      const base::RepeatingCallback<void(const std::string& state)>& callback,
      const std::string& state);

  std::unique_ptr<org::chromium::SessionManagerInterfaceProxy> proxy_;
  base::WeakPtrFactory<SessionManagerClient> weak_ptr_factory_;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_SESSION_MANAGER_CLIENT_H_
