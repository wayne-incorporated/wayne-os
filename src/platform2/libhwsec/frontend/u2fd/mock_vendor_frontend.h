// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_U2FD_MOCK_VENDOR_FRONTEND_H_
#define LIBHWSEC_FRONTEND_U2FD_MOCK_VENDOR_FRONTEND_H_

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "libhwsec/frontend/mock_frontend.h"
#include "libhwsec/frontend/u2fd/vendor_frontend.h"

namespace hwsec {

class MockU2fVendorFrontend : public MockFrontend, public U2fVendorFrontend {
 public:
  MockU2fVendorFrontend() = default;
  ~MockU2fVendorFrontend() override = default;

  MOCK_METHOD(StatusOr<bool>, IsEnabled, (), (const override));
  MOCK_METHOD(StatusOr<u2f::GenerateResult>,
              GenerateUserPresenceOnly,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               u2f::ConsumeMode,
               u2f::UserPresenceMode),
              (const override));
  MOCK_METHOD(StatusOr<u2f::GenerateResult>,
              Generate,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               u2f::ConsumeMode,
               u2f::UserPresenceMode,
               const brillo::Blob&),
              (const override));
  MOCK_METHOD(StatusOr<u2f::Signature>,
              SignUserPresenceOnly,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&,
               u2f::ConsumeMode,
               u2f::UserPresenceMode,
               const brillo::Blob&),
              (const override));
  MOCK_METHOD(StatusOr<u2f::Signature>,
              Sign,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const std::optional<brillo::SecureBlob>&,
               const brillo::Blob&,
               u2f::ConsumeMode,
               u2f::UserPresenceMode,
               const brillo::Blob&),
              (const override));
  MOCK_METHOD(Status,
              CheckUserPresenceOnly,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&),
              (const override));
  MOCK_METHOD(Status,
              Check,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&),
              (const override));
  MOCK_METHOD(StatusOr<u2f::Signature>,
              G2fAttest,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&,
               const brillo::Blob&,
               const brillo::Blob&),
              (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              GetG2fAttestData,
              (const brillo::Blob& app_id,
               const brillo::Blob& challenge,
               const brillo::Blob& key_handle,
               const brillo::Blob& public_key),
              (const override));
  MOCK_METHOD(StatusOr<u2f::Signature>,
              CorpAttest,
              (const brillo::Blob&,
               const brillo::SecureBlob&,
               const brillo::Blob&,
               const brillo::Blob&,
               const brillo::Blob&,
               const brillo::Blob&),
              (const override));
  MOCK_METHOD(StatusOr<RwVersion>, GetRwVersion, (), (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>, GetG2fCert, (), (const override));
  MOCK_METHOD(StatusOr<u2f::Config>, GetConfig, (), (const override));
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_U2FD_MOCK_VENDOR_FRONTEND_H_
