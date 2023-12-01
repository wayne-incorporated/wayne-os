// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_CLI_ASYNC_HANDLER_H_
#define LORGNETTE_CLI_ASYNC_HANDLER_H_

#include <string>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/synchronization/condition_variable.h>
#include <base/synchronization/lock.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

#include "lorgnette/dbus-proxies.h"

namespace lorgnette::cli {

// TODO(b/248023651): Add tests for this class when a fake Manager is available.
class AsyncHandler {
 public:
  using ManagerProxy = org::chromium::lorgnette::ManagerProxy;

  AsyncHandler(base::RepeatingClosure quit_closure, ManagerProxy* manager);
  AsyncHandler(const AsyncHandler& rhs) = delete;
  AsyncHandler& operator=(const AsyncHandler& rhs) = delete;
  virtual ~AsyncHandler();

  bool WaitUntilConnected();

 protected:
  virtual void ConnectSignal() = 0;

  void OnConnectedCallback(const std::string& interface_name,
                           const std::string& signal_name,
                           bool signal_connected);

  base::RepeatingClosure quit_closure_;
  ManagerProxy* manager_;  // Not owned.

 private:
  base::Lock lock_;
  base::ConditionVariable cvar_;
  bool connected_callback_called_{false};
  bool connection_status_{false};

  // Keep as the last member variable.
  base::WeakPtrFactory<AsyncHandler> weak_factory_{this};
};

}  // namespace lorgnette::cli

#endif  // LORGNETTE_CLI_ASYNC_HANDLER_H_
