// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_SESSION_MANAGER_INTERFACE_H_
#define LOGIN_MANAGER_SESSION_MANAGER_INTERFACE_H_

#include <string>
#include <vector>

namespace login_manager {

class SessionManagerInterface {
 public:
  SessionManagerInterface() {}
  virtual ~SessionManagerInterface() {}

  // Intializes policy subsystems.  Failure to initialize must be fatal.
  // Note: Initialize() does not start D-Bus service, yet.
  virtual bool Initialize() = 0;
  virtual void Finalize() = 0;

  // Starts SessionManagerInterface D-Bus service.
  // Returns true on success. Failure to start must be fatal.
  virtual bool StartDBusService() = 0;

  // Gets feature flags specified in device settings to pass to Chrome on
  // startup.
  virtual std::vector<std::string> GetFeatureFlags() = 0;

  // Emits state change signals.
  virtual void AnnounceSessionStoppingIfNeeded() = 0;
  virtual void AnnounceSessionStopped() = 0;

  // Returns true if the user's session should be ended (rather than the browser
  // being restarted) if the browser crashes right now. This is performed as a
  // security measure (e.g. if the screen is currently locked). If |reason_out|
  // is non-null, a human-readable explanation is saved to it if true is
  // returned.
  virtual bool ShouldEndSession(std::string* reason_out) = 0;

  // Starts a 'Powerwash' of the device.  |reason| is persisted to clobber.log
  // to annotate the cause of the powerwash.  |reason| must not exceed 50 bytes
  // in length and may only contain alphanumeric characters and underscores.
  virtual void InitiateDeviceWipe(const std::string& reason) = 0;
};

}  // namespace login_manager
#endif  // LOGIN_MANAGER_SESSION_MANAGER_INTERFACE_H_
