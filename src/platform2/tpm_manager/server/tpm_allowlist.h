// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_ALLOWLIST_H_
#define TPM_MANAGER_SERVER_TPM_ALLOWLIST_H_

namespace tpm_manager {

class TpmAllowlist {
 public:
  TpmAllowlist() = default;
  virtual ~TpmAllowlist() = default;
  virtual bool IsAllowed() = 0;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_ALLOWLIST_H_
