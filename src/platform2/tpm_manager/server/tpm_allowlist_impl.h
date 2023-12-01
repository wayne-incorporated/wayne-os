// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_ALLOWLIST_IMPL_H_
#define TPM_MANAGER_SERVER_TPM_ALLOWLIST_IMPL_H_

#include "tpm_manager/server/tpm_allowlist.h"
#include "tpm_manager/server/tpm_status.h"

namespace tpm_manager {

class TpmAllowlistImpl : public TpmAllowlist {
 public:
  explicit TpmAllowlistImpl(TpmStatus* tpm_status);
  ~TpmAllowlistImpl() override = default;
  bool IsAllowed() override;

 private:
  TpmStatus* tpm_status_ = nullptr;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_ALLOWLIST_IMPL_H_
