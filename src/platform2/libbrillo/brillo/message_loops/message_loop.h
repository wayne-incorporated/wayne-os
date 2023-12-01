// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_MESSAGE_LOOPS_MESSAGE_LOOP_H_
#define LIBBRILLO_BRILLO_MESSAGE_LOOPS_MESSAGE_LOOP_H_

#include <string>
#include <utility>

#include <base/functional/callback.h>
#include <base/location.h>
#include <base/time/time.h>
#include <brillo/brillo_export.h>

namespace brillo {

class BRILLO_EXPORT MessageLoop {
 public:
  virtual ~MessageLoop();

  // A unique task identifier used to refer to scheduled callbacks.
  using TaskId = uint64_t;

  // The kNullEventId is reserved for an invalid task and will never be used
  // to refer to a real task.
  static const TaskId kTaskIdNull;

  // Return the MessageLoop for the current thread. It is a fatal error to
  // request the current MessageLoop if SetAsCurrent() was not called on the
  // current thread. If you really need to, use ThreadHasCurrent() to check if
  // there is a current thread.
  static MessageLoop* current();

  // Return whether there is a MessageLoop in the current thread.
  static bool ThreadHasCurrent();

  // Set this message loop as the current thread main loop. Only one message
  // loop can be set at a time. Use ReleaseFromCurrent() to release it.
  void SetAsCurrent();

  // Release this instance from the current thread. This instance must have
  // been previously set with SetAsCurrent().
  void ReleaseFromCurrent();

  // Schedule a Closure |task| to be executed after a |delay|. Returns a task
  // identifier for the scheduled task that can be used to cancel the task
  // before it is fired by passing it to CancelTask().
  // In case of an error scheduling the task, the kTaskIdNull is returned.
  // Note that once the call is executed or canceled, the TaskId could be reused
  // at a later point.
  // This method can only be called from the same thread running the main loop.
  virtual TaskId PostDelayedTask(const base::Location& from_here,
                                 base::OnceClosure task,
                                 base::TimeDelta delay) = 0;
  // Variant without the Location for easier usage.
  TaskId PostDelayedTask(base::OnceClosure task, base::TimeDelta delay) {
    return PostDelayedTask(base::Location(), std::move(task), delay);
  }

  // A convenience method to schedule a call with no delay.
  // This method can only be called from the same thread running the main loop.
  TaskId PostTask(base::OnceClosure task) {
    return PostDelayedTask(std::move(task), base::TimeDelta());
  }
  TaskId PostTask(const base::Location& from_here, base::OnceClosure task) {
    return PostDelayedTask(from_here, std::move(task), base::TimeDelta());
  }

  // Cancel a scheduled task. Returns whether the task was canceled. For
  // example, if the callback was already executed (or is being executed) or was
  // already canceled this method will fail. Note that the TaskId can be reused
  // after it was executed or cancelled.
  virtual bool CancelTask(TaskId task_id) = 0;

  // ---------------------------------------------------------------------------
  // Methods used to run and stop the message loop.

  // Run one iteration of the message loop, dispatching up to one task. The
  // |may_block| tells whether this method is allowed to block waiting for a
  // task to be ready to run. Returns whether it ran a task. Note that even
  // if |may_block| is true, this method can return false immediately if there
  // are no more tasks registered.
  virtual bool RunOnce(bool may_block) = 0;

  // Run the main loop until there are no more registered tasks.
  virtual void Run();

  // Quit the running main loop immediately. This method will make the current
  // running Run() method to return right after the current task returns back
  // to the message loop without processing any other task.
  virtual void BreakLoop();

 protected:
  MessageLoop() = default;
  MessageLoop(const MessageLoop&) = delete;
  MessageLoop& operator=(const MessageLoop&) = delete;

 private:
  // Tells whether Run() should quit the message loop in the default
  // implementation.
  bool should_exit_ = false;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_MESSAGE_LOOPS_MESSAGE_LOOP_H_
