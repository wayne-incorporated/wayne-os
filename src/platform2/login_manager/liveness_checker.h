// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_LIVENESS_CHECKER_H_
#define LOGIN_MANAGER_LIVENESS_CHECKER_H_

#include <base/macros.h>

namespace login_manager {

// Provides an interface for classes that ping the browser to see if it's
// alive.
class LivenessChecker {
 public:
  LivenessChecker() {}
  LivenessChecker(const LivenessChecker&) = delete;
  LivenessChecker& operator=(const LivenessChecker&) = delete;

  virtual ~LivenessChecker() {}

  // Begin sending periodic liveness pings to the browser.
  virtual void Start() = 0;

  // Stop sending periodic liveness pings to the browser.
  // Must be idempotent.
  virtual void Stop() = 0;

  // Returns true if this instance has been started and not yet stopped.
  virtual bool IsRunning() = 0;

  // Turn off aborting of the browser even if a hang has been detected, to allow
  // HangWatcher to be the sole detector of hangs.
  virtual void DisableAborting() = 0;
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_LIVENESS_CHECKER_H_
