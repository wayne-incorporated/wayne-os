// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_STATE_HANDLER_MANAGER_H_
#define RMAD_STATE_HANDLER_STATE_HANDLER_MANAGER_H_

#include <map>

#include <base/memory/scoped_refptr.h>

#include "rmad/daemon/daemon_callback.h"
#include "rmad/state_handler/base_state_handler.h"

namespace rmad {

class JsonStore;

class StateHandlerManager {
 public:
  explicit StateHandlerManager(scoped_refptr<JsonStore> json_store);
  ~StateHandlerManager() = default;

  void RegisterStateHandler(scoped_refptr<BaseStateHandler> handler);
  void RegisterStateHandlers(scoped_refptr<DaemonCallback> daemon_callback);

  scoped_refptr<BaseStateHandler> GetStateHandler(
      RmadState::StateCase state) const;

 private:
  std::map<RmadState::StateCase, scoped_refptr<BaseStateHandler>>
      state_handler_map_;
  scoped_refptr<JsonStore> json_store_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_STATE_HANDLER_MANAGER_H_
