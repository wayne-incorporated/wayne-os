// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_SESSION_MANAGER_OBSERVER_INTERFACE_H_
#define FEDERATED_SESSION_MANAGER_OBSERVER_INTERFACE_H_

#include "base/observer_list_types.h"

namespace federated {

// An interface class for observing events from the session manager.
// A derived class of this class should override the event methods
// that it would like to observe.
class SessionManagerObserverInterface : public base::CheckedObserver {
 public:
  virtual ~SessionManagerObserverInterface() = default;

  // This method is called when a session has started.
  virtual void OnSessionStarted() = 0;

  // This method is called when a session has stopped.
  virtual void OnSessionStopped() = 0;
};

}  // namespace federated

#endif  // FEDERATED_SESSION_MANAGER_OBSERVER_INTERFACE_H_
