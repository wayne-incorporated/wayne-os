// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ERROR_CONVERTER_H_
#define CRYPTOHOME_ERROR_CONVERTER_H_

#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/crypto_error.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/reporting.h"

namespace cryptohome {

namespace error {

// This file hosts utilities that converts the CryptohomeError class into the
// error format on the dbus.

// Retrieves the final ErrorActions from the stack of errors.
template <typename ErrorType>
void ActionsFromStack(
    const hwsec_foundation::status::StatusChain<ErrorType>& stack,
    std::optional<PrimaryAction>& primary,
    PossibleActions& possible);

// Retrieves the legacy CryptohomeErrorCode from the stack of errors.
user_data_auth::CryptohomeErrorCode LegacyErrorCodeFromStack(
    const hwsec_foundation::status::StatusChain<CryptohomeError>& stack);

// CryptohomeErrorToUserDataAuthError converts the CryptohomeError class into
// the error protobuf that is used by the dbus API (userdataauth).
user_data_auth::CryptohomeErrorInfo CryptohomeErrorToUserDataAuthError(
    const hwsec_foundation::status::StatusChain<CryptohomeError>& err,
    user_data_auth::CryptohomeErrorCode* legacy_ec);

// PopulateReplyWithError() is a helper utility that takes the information in
// CryptohomeERror and populates the relevant fields in the reply, with the
// assumption that it is for responding to dbus calls. As in, it'll report the
// relevant UMAs as well. This is usually used for responding to a sync dbus
// call.
//
// The ReplyType can be any reply message which has a CryptohomeErrorCode error
// field and a CryptohomeErrorInfo error_info field.
template <typename ReplyType>
void PopulateReplyWithError(
    const hwsec_foundation::status::StatusChain<CryptohomeError>& err,
    ReplyType* reply) {
  constexpr char kErrorBucketName[] = "Error";
  bool success = err.ok();
  if (!success) {
    user_data_auth::CryptohomeErrorCode legacy_ec;
    auto info = CryptohomeErrorToUserDataAuthError(err, &legacy_ec);
    // Cryptohome errors populated in dbus replies are reported to the default
    // bucket name, such that it will appear as Cryptohome.Error.AllLocations
    // etc.
    ReportCryptohomeError(err, info, kErrorBucketName);

    *reply->mutable_error_info() = std::move(info);
    reply->set_error(legacy_ec);
  } else {
    ReportCryptohomeOk(kErrorBucketName);
    reply->clear_error_info();
    reply->set_error(
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET);
  }
}

// ReplyWithError() is a helper utility that takes the information in
// CryptohomeError and populates the relevant fields in the reply then call the
// on_done helper function. This is usually used for responding to an async dbus
// call.
//
// This works with the same ReplyType types as PopulateReplyWithError.
template <typename ReplyType>
void ReplyWithError(
    base::OnceCallback<void(const ReplyType&)> on_done,
    ReplyType reply,
    const hwsec_foundation::status::StatusChain<CryptohomeError>& err) {
  PopulateReplyWithError(err, &reply);
  std::move(on_done).Run(reply);
}

}  // namespace error

}  // namespace cryptohome

#endif  // CRYPTOHOME_ERROR_CONVERTER_H_
