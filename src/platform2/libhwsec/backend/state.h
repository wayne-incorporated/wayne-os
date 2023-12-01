// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_STATE_H_
#define LIBHWSEC_BACKEND_STATE_H_

#include <base/functional/callback.h>

#include "libhwsec/status.h"

namespace hwsec {

// State provide the basic state of the security module.
class State {
 public:
  // Is the security module enabled or not.
  virtual StatusOr<bool> IsEnabled() = 0;

  // Is the security module ready to use or not.
  virtual StatusOr<bool> IsReady() = 0;

  // Tries to make the security module become ready.
  virtual Status Prepare() = 0;

  // Waits until the security module is ready.
  virtual void WaitUntilReady(base::OnceCallback<void(Status)> callback) = 0;

 protected:
  State() = default;
  ~State() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_STATE_H_
