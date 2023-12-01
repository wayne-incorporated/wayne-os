// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/bindings/connectivity/context.h"

#include <utility>

#include "diagnostics/bindings/connectivity/local_state.h"
#include "diagnostics/bindings/connectivity/remote_state.h"

namespace ash::cros_healthd::connectivity {

class ContextImpl : public Context {
 public:
  ContextImpl(std::unique_ptr<LocalState> local_state,
              std::unique_ptr<RemoteState> remote_state)
      : local_state_(std::move(local_state)),
        remote_state_(std::move(remote_state)) {}
  ContextImpl(const ContextImpl&) = delete;
  ContextImpl& operator=(const ContextImpl&) = delete;
  virtual ~ContextImpl() = default;

 public:
  LocalState* local_state() override { return local_state_.get(); }
  RemoteState* remote_state() override { return remote_state_.get(); }

 private:
  std::unique_ptr<LocalState> local_state_;
  std::unique_ptr<RemoteState> remote_state_;
};

std::unique_ptr<Context> Context::Create(
    std::unique_ptr<LocalState> local_state,
    std::unique_ptr<RemoteState> remote_state) {
  return std::make_unique<ContextImpl>(std::move(local_state),
                                       std::move(remote_state));
}

}  // namespace ash::cros_healthd::connectivity
