// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ERROR_REAP_H_
#define CRYPTOHOME_ERROR_REAP_H_

#include <string>

#include <base/containers/span.h>

#include "cryptohome/error/cryptohome_error.h"

namespace cryptohome {

namespace error {

// This function should be called when there's an error but the code wants to
// perform some fallback action instead of surfacing the error. The error's
// ownership should be transferred into this function to be disposed of. Those
// disposed error will be reported to the Cryptohome.|error_bucket_name|.*
// metrics.
void ReapAndReportError(CryptohomeStatus status, std::string error_bucket_name);

// Override of ReapAndReportError that takes several error bucket paths and
// join them into the error bucket name.
void ReapAndReportError(CryptohomeStatus status,
                        base::span<const std::string> error_bucket_paths);

// This function should be called when there's an error that is deemed to be
// working as intended. The error's ownership should be transferred into this
// function to be disposed of.
void ReapWorkingAsIntendedError(CryptohomeStatus status);

// This function should be called when there's an error that triggered a retry,
// and thus will not be propagated up the dbus stack. The error's ownership
// should be transferred into this function to be disposed of.
void ReapRetryError(CryptohomeStatus status);

}  // namespace error

}  // namespace cryptohome

#endif  // CRYPTOHOME_ERROR_REAP_H_
