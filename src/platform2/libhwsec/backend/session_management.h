// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_SESSION_MANAGEMENT_H_
#define LIBHWSEC_BACKEND_SESSION_MANAGEMENT_H_

#include <cstdint>

#include "libhwsec/status.h"
#include "libhwsec/structures/operation_policy.h"
#include "libhwsec/structures/session.h"

namespace hwsec {

class BackendTpm2;

// SessionManagement provide the functions to manager session.
class SessionManagement {
 public:
  // Flushes all invalid sessions to reclaim the resource.
  virtual Status FlushInvalidSessions() = 0;

 protected:
  SessionManagement() = default;
  ~SessionManagement() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_SESSION_MANAGEMENT_H_
