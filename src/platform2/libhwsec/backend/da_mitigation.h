// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_DA_MITIGATION_H_
#define LIBHWSEC_BACKEND_DA_MITIGATION_H_

#include <base/time/time.h>

#include "libhwsec/status.h"

namespace hwsec {

// DAMitigation provide the functions related to the DA counter mitigation.
class DAMitigation {
 public:
  struct DAMitigationStatus {
    bool lockout;
    base::TimeDelta remaining;
  };

  // Is DA counter can be mitigated or not.
  virtual StatusOr<bool> IsReady() = 0;

  // Is DA mitigation status.
  virtual StatusOr<DAMitigationStatus> GetStatus() = 0;

  // Tries to mitigate the DA counter.
  virtual Status Mitigate() = 0;

 protected:
  DAMitigation() = default;
  ~DAMitigation() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_DA_MITIGATION_H_
