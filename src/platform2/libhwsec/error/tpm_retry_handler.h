// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_ERROR_TPM_RETRY_HANDLER_H_
#define LIBHWSEC_ERROR_TPM_RETRY_HANDLER_H_

#include <utility>

#include <base/logging.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/error/tpm_error.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

#ifndef BUILD_LIBHWSEC
#error "Don't include this file outside libhwsec!"
#endif

namespace hwsec {

class TPMRetryHandler {
 public:
  TPMRetryHandler();

  // Does the generic error handling for the Status/StatusOr result.
  // Returns true when there is no need to retry anymore (the result is success
  // or there is no way to recover from this error).
  template <typename Result, typename... Args>
  bool HandleResult(Result& result, Backend& backend, const Args&... args) {
    using hwsec_foundation::status::MakeStatus;
    if (result.ok()) {
      return true;
    }

    if (remaining_try_count_ <= 0) {
      result = MakeStatus<TPMError>("Retry failed", TPMRetryAction::kReboot)
                   .Wrap(std::move(result).err_status());
      return true;
    }

    bool retry = false;

    TPMRetryAction action = result.err_status()->ToTPMRetryAction();

    switch (action) {
      case TPMRetryAction::kSession:
      case TPMRetryAction::kLater:
        // Flush the invalid sessions.
        retry |= FlushInvalidSessions(backend);

        if (action == TPMRetryAction::kLater) {
          // fold expression with , operator.
          ((retry |= ReloadObject(backend, args)), ...);
        }
        break;

      case TPMRetryAction::kCommunication:
        retry = true;
        break;

      default:  // Unsupported retry action.
        // There is no way to recover from this error.
        return true;
    }

    if (retry) {
      LOG(WARNING) << "Retry libhwsec error: " << result.err_status();
      DelayAndUpdate();
    }

    return !retry;
  }

 private:
  void DelayAndUpdate();

  // Don't do anything by default.
  template <typename Arg>
  bool ReloadObject(hwsec::Backend& backend, const Arg& key) {
    return false;
  }

  // If the argument type is Key, use the specialization.
  template <>
  bool ReloadObject(hwsec::Backend& backend, const Key& key);

  bool FlushInvalidSessions(hwsec::Backend& backend);

  int remaining_try_count_;
  base::TimeDelta current_delay_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_ERROR_TPM_RETRY_HANDLER_H_
