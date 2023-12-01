// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_EVENT_DISPATCHER_H_
#define SHILL_EVENT_DISPATCHER_H_

#include <stdint.h>

#include <base/functional/callback.h>
#include <base/location.h>
#include <base/time/time.h>

namespace shill {

// This is the main event dispatcher.  It contains a central instance, and is
// the entity responsible for dispatching events out of all queues to their
// listeners during the idle loop.
class EventDispatcher {
 public:
  EventDispatcher();
  EventDispatcher(const EventDispatcher&) = delete;
  EventDispatcher& operator=(const EventDispatcher&) = delete;

  virtual ~EventDispatcher();

  virtual void DispatchForever();

  // Processes all pending events that can run and returns.
  virtual void DispatchPendingEvents();

  // These are thin wrappers around calls of the same name in
  // <base/task_runner.h>
  void PostTask(const base::Location& location, base::OnceClosure task);
  virtual void PostDelayedTask(const base::Location& location,
                               base::OnceClosure task,
                               base::TimeDelta delay);

  virtual void QuitDispatchForever();

 private:
  base::RepeatingClosure quit_closure_;
};

}  // namespace shill

#endif  // SHILL_EVENT_DISPATCHER_H_
