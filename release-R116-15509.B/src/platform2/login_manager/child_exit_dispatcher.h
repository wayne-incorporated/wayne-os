// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_CHILD_EXIT_DISPATCHER_H_
#define LOGIN_MANAGER_CHILD_EXIT_DISPATCHER_H_

#include <signal.h>

#include <vector>

#include <base/memory/weak_ptr.h>

struct signalfd_siginfo;

namespace brillo {
class AsynchronousSignalHandler;
}

namespace login_manager {
class ChildExitHandler;

// Listen for SIGCHLD and informs the appropriate object that manages that
// child.
// TODO(crbug.com/1053782): Replace this class by libbrillo.
// Along with the change:
// - ChildExitDispatcher (or libbrillo equivalent) will be kept alive
//   during signal dispatching. I.e., the instance should not be destroyed
//   from the callback (or its descendant calls).
// - The registration will require a PID to be tracked.
// - It will register base::OnceCallback, so binding with WeakPtr could
//   help to maintain callee's lifetime, as common practice in Chrome.
class ChildExitDispatcher {
 public:
  ChildExitDispatcher(brillo::AsynchronousSignalHandler* signal_handler,
                      const std::vector<ChildExitHandler*>& managers);
  ~ChildExitDispatcher();

  ChildExitDispatcher(const ChildExitDispatcher&) = delete;
  ChildExitDispatcher& operator=(const ChildExitDispatcher&) = delete;

 private:
  // Called by the |AsynchronousSignalHandler| when a new SIGCHLD is received.
  bool OnSigChld(const struct signalfd_siginfo& info);

  // Notifies ChildExitHandlers one at a time about the child exiting until
  // one reports that it's handled the exit.
  void Dispatch(const siginfo_t& info);

  // Handler that notifies of signals. Owned by the caller.
  brillo::AsynchronousSignalHandler* const signal_handler_;

  // Handlers that will be notified about child exit events.
  const std::vector<ChildExitHandler*> handlers_;

  // This should be the last member of this class, so that the weakptr is
  // destroyed before everything above.
  base::WeakPtrFactory<ChildExitDispatcher> weak_factory_{this};
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_CHILD_EXIT_DISPATCHER_H_
