// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_U2F_H_
#define LIBHWSEC_BACKEND_MOCK_U2F_H_

#include <cstdint>
#include <optional>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/u2f.h"
#include "libhwsec/status.h"

namespace hwsec {

class MockU2f : public U2f {
 public:
  MockU2f() = default;
  explicit MockU2f(U2f* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, IsEnabled).WillByDefault(Invoke(default_, &U2f::IsEnabled));
    ON_CALL(*this, GenerateUserPresenceOnly)
        .WillByDefault(Invoke(default_, &U2f::GenerateUserPresenceOnly));
    ON_CALL(*this, Generate).WillByDefault(Invoke(default_, &U2f::Generate));
    ON_CALL(*this, SignUserPresenceOnly)
        .WillByDefault(Invoke(default_, &U2f::SignUserPresenceOnly));
    ON_CALL(*this, Sign).WillByDefault(Invoke(default_, &U2f::Sign));
    ON_CALL(*this, CheckUserPresenceOnly)
        .WillByDefault(Invoke(default_, &U2f::CheckUserPresenceOnly));
    ON_CALL(*this, Check).WillByDefault(Invoke(default_, &U2f::Check));
    ON_CALL(*this, G2fAttest).WillByDefault(Invoke(default_, &U2f::G2fAttest));
    ON_CALL(*this, CorpAttest)
        .WillByDefault(Invoke(default_, &U2f::CorpAttest));
    ON_CALL(*this, GetG2fAttestData)
        .WillByDefault(Invoke(default_, &U2f::GetG2fAttestData));
    ON_CALL(*this, GetConfig).WillByDefault(Invoke(default_, &U2f::GetConfig));
  }

  MOCK_METHOD(StatusOr<bool>, IsEnabled, (), (override));
  MOCK_METHOD(StatusOr<u2f::GenerateResult>,
              GenerateUserPresenceOnly,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               u2f::ConsumeMode,
               u2f::UserPresenceMode),
              (override));
  MOCK_METHOD(StatusOr<u2f::GenerateResult>,
              Generate,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               u2f::ConsumeMode,
               u2f::UserPresenceMode,
               const brillo::Blob&),
              (override));
  MOCK_METHOD(StatusOr<u2f::Signature>,
              SignUserPresenceOnly,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&,
               u2f::ConsumeMode,
               u2f::UserPresenceMode,
               const brillo::Blob&),
              (override));
  MOCK_METHOD(StatusOr<u2f::Signature>,
              Sign,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const std::optional<brillo::SecureBlob>&,
               const brillo::Blob&,
               u2f::ConsumeMode,
               u2f::UserPresenceMode,
               const brillo::Blob&),
              (override));
  MOCK_METHOD(Status,
              CheckUserPresenceOnly,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&),
              (override));
  MOCK_METHOD(Status,
              Check,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&),
              (override));
  MOCK_METHOD(StatusOr<u2f::Signature>,
              G2fAttest,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&,
               const brillo::Blob&,
               const brillo::Blob&),
              (override));
  MOCK_METHOD(StatusOr<u2f::Signature>,
              CorpAttest,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&,
               const brillo::Blob&,
               const brillo::Blob&,
               const brillo::Blob&),
              (override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              GetG2fAttestData,
              (const brillo::Blob&,
               const brillo::Blob&,
               const brillo::Blob&,
               const brillo::Blob&),
              (override));
  MOCK_METHOD(StatusOr<u2f::Config>, GetConfig, (), (override));

 private:
  U2f* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_U2F_H_
