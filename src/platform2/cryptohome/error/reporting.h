// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ERROR_REPORTING_H_
#define CRYPTOHOME_ERROR_REPORTING_H_

#include <string>

#include <base/containers/span.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/error/cryptohome_error.h"

namespace cryptohome {

namespace error {

// Report an instance of CryptohomeError status chain to UMA, it'll
// automatically disect the status chain and figure out which UMAs need to be
// reported. It is expected that the caller have already called
// CryptohomeErrorToUserDataAuthError before calling this, and |info| is the
// result from it. If |info| doesn't match |err|, the behaviour is undefined.
void ReportCryptohomeError(
    const hwsec_foundation::status::StatusChain<CryptohomeError>& err,
    const user_data_auth::CryptohomeErrorInfo& info,
    const std::string& error_bucket_name);

// Report a Cryptohome Ok status. For each error bucket, if the error bucket
// represents the error results of a logical operation (like a dbus request),
// where each operation reports exactly 1 error to the bucket when failing, then
// when the operation succeeds, it can report an Ok status using this function.
// This can make the error bucket show meaningful results of error/success
// percentage for each operation. The override takes several error bucket paths
// and join them into the error bucket name.
void ReportCryptohomeOk(const std::string& error_bucket_name);
void ReportCryptohomeOk(base::span<const std::string> error_bucket_paths);

// Report an instance of CryptohomeStatus to UMA. Unlike ReportCryptohomeError
// that is used before the error is just being returned on dbus, this method is
// normally used half way in processing the request and for specific operation
// so as to facilitate tailored issue discovery for that operation. For
// instance, when we try to authenticate a specific AuthFactor. |err| can be
// either an error status or an ok value, both will be reported. The override
// takes several error bucket paths and join them into the error bucket name.
void ReportOperationStatus(
    const hwsec_foundation::status::StatusChain<CryptohomeError>& err,
    const std::string& error_bucket_name);
void ReportOperationStatus(
    const hwsec_foundation::status::StatusChain<CryptohomeError>& err,
    base::span<const std::string> error_bucket_paths);

}  // namespace error

}  // namespace cryptohome

#endif  // CRYPTOHOME_ERROR_REPORTING_H_
