// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/cli/async_handler.h"

#include <base/check.h>
#include <base/logging.h>

namespace lorgnette::cli {

AsyncHandler::AsyncHandler(base::RepeatingClosure quit_closure,
                           ManagerProxy* manager)
    : quit_closure_(quit_closure), manager_(manager), cvar_(&lock_) {
  DCHECK(manager_);
}

AsyncHandler::~AsyncHandler() = default;

bool AsyncHandler::WaitUntilConnected() {
  ConnectSignal();

  base::AutoLock auto_lock(lock_);
  while (!connected_callback_called_) {
    cvar_.Wait();
  }
  return connection_status_;
}

void AsyncHandler::OnConnectedCallback(const std::string& interface_name,
                                       const std::string& signal_name,
                                       bool signal_connected) {
  base::AutoLock auto_lock(lock_);
  connected_callback_called_ = true;
  connection_status_ = signal_connected;
  if (!signal_connected) {
    LOG(ERROR) << "Failed to connect to " << signal_name << " signal";
  }
  cvar_.Signal();
}

}  // namespace lorgnette::cli
