// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_MOCK_WEBAUTHN_STORAGE_H_
#define U2FD_MOCK_WEBAUTHN_STORAGE_H_

#include "u2fd/webauthn_storage.h"

#include <optional>
#include <string>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

namespace u2f {

class MockWebAuthnStorage : public WebAuthnStorage {
 public:
  MockWebAuthnStorage() = default;
  ~MockWebAuthnStorage() override = default;

  MOCK_METHOD(bool, WriteRecord, (const WebAuthnRecord& record), (override));

  MOCK_METHOD(bool, LoadRecords, (), (override));

  MOCK_METHOD(bool,
              SendRecordCountToUMA,
              (MetricsLibraryInterface*),
              (override));

  MOCK_METHOD(void, Reset, (), (override));

  MOCK_METHOD(std::optional<brillo::SecureBlob>,
              GetSecretByCredentialId,
              (const std::string& credential_id),
              (override));

  MOCK_METHOD(bool,
              GetSecretAndKeyBlobByCredentialId,
              (const std::string& credential_id,
               brillo::SecureBlob* secret,
               brillo::Blob* key_blob),
              (override));

  MOCK_METHOD(std::optional<WebAuthnRecord>,
              GetRecordByCredentialId,
              (const std::string& credential_id),
              (override));

  MOCK_METHOD(int,
              CountRecordsInTimeRange,
              (int64_t timestamp_min, int64_t timestamp_max),
              (override));

  MOCK_METHOD(int,
              DeleteRecordsInTimeRange,
              (int64_t timestamp_min, int64_t timestamp_max),
              (override));
};

}  // namespace u2f

#endif  // U2FD_MOCK_WEBAUTHN_STORAGE_H_
