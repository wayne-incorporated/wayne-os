// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_PUBLIC_DPSL_THREAD_CONTEXT_H_
#define DIAGNOSTICS_DPSL_PUBLIC_DPSL_THREAD_CONTEXT_H_

#include <cstdint>
#include <functional>
#include <memory>

namespace diagnostics {

class DpslGlobalContext;

// Interface of the class that performs the per-thread DPSL initialization and
// holds any thread-local resources it needs.
//
// It also manages the current thread's asynchronous task queue and provides the
// RunEventLoop() method that runs a loop running scheduled tasks and waiting
// for new ones. Normally, each thread that creates an instance of
// DpslThreadContext is expected to eventually call into RunEventLoop().
//
// EXAMPLE USAGE:
//
//   void ThreadMain() {
//     auto thread_context = DpslThreadContext::Create(...);
//     ...
//     thread_context->RunEventLoop();
//
// NOTE ON THREADING MODEL: Only the BelongsToCurrentThread() and the Post*()
// methods are allowed to be called from any thread. All other methods
// (including the destructor) must be called on the same thread on which the
// object was created.
//
// NOTE ON LIFETIME: At most one instance of this class must be created on any
// given thread.
//
// PRECONDITIONS:
// 1. An instance of DpslGlobalContext must exist during the whole lifetime of
//    this object.
class DpslThreadContext {
 public:
  // Factory method that returns an instance of the real implementation of this
  // interface.
  //
  // This method must be called no more than once for any given thread.
  //
  // The return value is guaranteed to be non-null.
  static std::unique_ptr<DpslThreadContext> Create(
      DpslGlobalContext* global_context);

  virtual ~DpslThreadContext() = default;

  // Returns whether the current thread is the one on which this instance was
  // created.
  //
  // This method is thread-safe: it's allowed to be called from any thread
  // (as long as the object isn't created/destroyed concurrently).
  virtual bool BelongsToCurrentThread() = 0;

  // Runs an event loop in a blocking manner: processing the already scheduled
  // tasks and waiting for new ones. This call blocks until the started event
  // loop quits - either due to |QuitEventLoop| or due to some internal DPSL
  // error.
  //
  // NOTE: It's forbidden to use nested message loops, i.e., call this method
  // while another invocation of it is running.
  virtual void RunEventLoop() = 0;

  // Returns whether an invocation of RunEventLoop() is currently running.
  virtual bool IsEventLoopRunning() = 0;

  // Schedules the given function to be executed on the thread with which the
  // object is associated.
  //
  // This method is thread-safe: it's allowed to be called from any thread
  // (as long as the object isn't created/destroyed concurrently).
  virtual void PostTask(std::function<void()> task) = 0;

  // Sames as PostTask(), but the callback is scheduled to be executed to be
  // executed approximately after the given timeout.
  //
  // |delay_milliseconds| must be non-negative.
  //
  // This method is thread-safe: it's allowed to be called from any thread
  // (as long as the object isn't created/destroyed concurrently).
  virtual void PostDelayedTask(std::function<void()> task,
                               int64_t delay_milliseconds) = 0;

  // Quits the current event loop that is run via RunEventLoop(). The event loop
  // will stop immediately after the currently running task completes.
  //
  // When no event loop is currently running, this method has no effect.
  //
  // NOTE: This method must only be called from the thread on which
  // DpslThreadContext was created. In case the event loop is needed to be
  // stopped from a different thread, employ the PostTask() method (with the
  // callback that calls QuitEventLoop()).
  virtual void QuitEventLoop() = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_PUBLIC_DPSL_THREAD_CONTEXT_H_
