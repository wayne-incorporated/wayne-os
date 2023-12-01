// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_STATE_H_
#define LIBHWSEC_BACKEND_TPM1_STATE_H_

#include <optional>
#include <vector>

#include "libhwsec/backend/state.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"

namespace hwsec {

class StateTpm1 : public State {
 public:
  explicit StateTpm1(org::chromium::TpmManagerProxyInterface& tpm_manager)
      : tpm_manager_(tpm_manager) {}

  StatusOr<bool> IsEnabled() override;
  StatusOr<bool> IsReady() override;
  Status Prepare() override;
  void WaitUntilReady(base::OnceCallback<void(Status)> callback) override;

 private:
  void OnReady();

  // Receive the ready signal or not, this will be std::nullopt if we didn't
  // register the signal.
  std::optional<bool> received_ready_signal_;

  std::vector<base::OnceCallback<void(Status)>> ready_callbacks_;

  org::chromium::TpmManagerProxyInterface& tpm_manager_;

  // Member variables should appear before the WeakPtrFactory, to ensure
  // that any WeakPtrs to Controller are invalidated before its members
  // variable's destructors are executed, rendering them invalid.
  base::WeakPtrFactory<StateTpm1> weak_factory_{this};
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_STATE_H_
