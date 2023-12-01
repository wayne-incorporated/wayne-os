// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_TPM_MANAGER_CLIENT_H_
#define RMAD_SYSTEM_TPM_MANAGER_CLIENT_H_

#include "rmad/proto_bindings/rmad.pb.h"

namespace rmad {

class TpmManagerClient {
 public:
  TpmManagerClient() = default;
  virtual ~TpmManagerClient() = default;

  virtual bool GetRoVerificationStatus(
      RoVerificationStatus* ro_verification_status) = 0;
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_TPM_MANAGER_CLIENT_H_
