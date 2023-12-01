// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/webauthn_storage.h"

#include <memory>
#include <optional>
#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace u2f {
namespace {

constexpr char kSanitizedUser[] = "SanitizedUser";

constexpr char kCredentialId[] = "CredentialId";
constexpr char kCredentialSecret[65] = {[0 ... 63] = 'E', '\0'};
constexpr char kCredentialKeyBlob[65] = {[0 ... 63] = 'F', '\0'};
constexpr char kRpId[] = "example.com";
constexpr char kRpDisplayName[] = "Example Site";
constexpr char kUserId[] = "deadbeef";
constexpr char kUserDisplayName[] = "example_user";
constexpr double kCreatedTime = 12345;

brillo::Blob HexArrayToBlob(const char* array) {
  brillo::Blob blob;
  CHECK(base::HexStringToBytes(array, &blob));
  return blob;
}

using ::testing::_;
using ::testing::Return;

// TODO(b/205813697): Add tests for record structure backward compatibility.
class WebAuthnStorageTest : public ::testing::Test {
 public:
  WebAuthnStorageTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    root_path_ =
        temp_dir_.GetPath().AppendASCII("webauthn_storage_unittest_root");
    webauthn_storage_ = std::make_unique<WebAuthnStorage>();
    // Since there is no session manager, allow accesses by default.
    webauthn_storage_->set_allow_access(true);
    webauthn_storage_->set_sanitized_user(kSanitizedUser);
    webauthn_storage_->SetRootPathForTesting(root_path_);
  }

  ~WebAuthnStorageTest() override {
    EXPECT_TRUE(base::DeletePathRecursively(temp_dir_.GetPath()));
  }

 protected:
  base::ScopedTempDir temp_dir_;
  base::FilePath root_path_;
  std::unique_ptr<WebAuthnStorage> webauthn_storage_;
};

TEST_F(WebAuthnStorageTest, WriteAndReadRecord) {
  const WebAuthnRecord record{.credential_id = kCredentialId,
                              .secret = HexArrayToBlob(kCredentialSecret),
                              .key_blob = HexArrayToBlob(kCredentialKeyBlob),
                              .rp_id = kRpId,
                              .rp_display_name = kRpDisplayName,
                              .user_id = kUserId,
                              .user_display_name = kUserDisplayName,
                              .timestamp = kCreatedTime,
                              .is_resident_key = true};

  EXPECT_TRUE(webauthn_storage_->WriteRecord(record));

  webauthn_storage_->Reset();
  webauthn_storage_->set_allow_access(true);
  webauthn_storage_->set_sanitized_user(kSanitizedUser);

  EXPECT_TRUE(webauthn_storage_->LoadRecords());

  std::optional<WebAuthnRecord> record_loaded =
      webauthn_storage_->GetRecordByCredentialId(kCredentialId);
  EXPECT_TRUE(record_loaded);
  EXPECT_EQ(record.secret, record_loaded->secret);
  EXPECT_EQ(record.key_blob, record_loaded->key_blob);
  EXPECT_EQ(record.rp_id, record_loaded->rp_id);
  EXPECT_EQ(record.rp_display_name, record_loaded->rp_display_name);
  EXPECT_EQ(record.user_id, record_loaded->user_id);
  EXPECT_EQ(record.user_display_name, record_loaded->user_display_name);
  EXPECT_EQ(record.timestamp, record_loaded->timestamp);
  EXPECT_TRUE(record.is_resident_key);
}

TEST_F(WebAuthnStorageTest, WriteAndReadRecordWithEmptyUserIdAndDisplayName) {
  const WebAuthnRecord record{.credential_id = kCredentialId,
                              .secret = HexArrayToBlob(kCredentialSecret),
                              .key_blob = HexArrayToBlob(kCredentialKeyBlob),
                              .rp_id = kRpId,
                              .rp_display_name = kRpDisplayName,
                              .user_id = std::string(),
                              .user_display_name = std::string(),
                              .timestamp = kCreatedTime,
                              .is_resident_key = false};

  EXPECT_TRUE(webauthn_storage_->WriteRecord(record));

  webauthn_storage_->Reset();
  webauthn_storage_->set_allow_access(true);
  webauthn_storage_->set_sanitized_user(kSanitizedUser);

  EXPECT_TRUE(webauthn_storage_->LoadRecords());

  std::optional<WebAuthnRecord> record_loaded =
      webauthn_storage_->GetRecordByCredentialId(kCredentialId);
  EXPECT_TRUE(record_loaded);
  EXPECT_EQ(record.secret, record_loaded->secret);
  EXPECT_EQ(record.key_blob, record_loaded->key_blob);
  EXPECT_EQ(record.rp_id, record_loaded->rp_id);
  EXPECT_EQ(record.rp_display_name, record_loaded->rp_display_name);
  EXPECT_TRUE(record_loaded->user_id.empty());
  EXPECT_TRUE(record_loaded->user_display_name.empty());
  EXPECT_EQ(record.timestamp, record_loaded->timestamp);
  EXPECT_FALSE(record.is_resident_key);
}

TEST_F(WebAuthnStorageTest, LoadManyRecords) {
  for (int i = 0; i < 30; i++) {
    const WebAuthnRecord record{
        .credential_id = std::string(kCredentialId) + std::to_string(i),
        .secret = HexArrayToBlob(kCredentialSecret),
        .key_blob = HexArrayToBlob(kCredentialKeyBlob),
        .rp_id = kRpId,
        .rp_display_name = kRpDisplayName,
        .user_id = kUserId,
        .user_display_name = kUserDisplayName,
        .timestamp = kCreatedTime,
        .is_resident_key = false};

    EXPECT_TRUE(webauthn_storage_->WriteRecord(record));
  }

  webauthn_storage_->Reset();
  webauthn_storage_->set_allow_access(true);
  webauthn_storage_->set_sanitized_user(kSanitizedUser);

  EXPECT_TRUE(webauthn_storage_->LoadRecords());
}

TEST_F(WebAuthnStorageTest, CountAndDeleteRecords) {
  double timestamp_base = 10000;
  for (int i = 0; i < 10; i++) {
    const WebAuthnRecord record{
        .credential_id = std::string(kCredentialId) + std::to_string(i),
        .secret = HexArrayToBlob(kCredentialSecret),
        .rp_id = kRpId,
        .rp_display_name = kRpDisplayName,
        .user_id = kUserId,
        .user_display_name = kUserDisplayName,
        .timestamp = timestamp_base + i * 100,
        .is_resident_key = true};

    EXPECT_TRUE(webauthn_storage_->WriteRecord(record));
  }

  // The time range of min_timestamp~max_timestamp is inclusive.
  EXPECT_EQ(webauthn_storage_->CountRecordsInTimeRange(10100, 10300), 3);
  // Test counting all records.
  EXPECT_EQ(webauthn_storage_->CountRecordsInTimeRange(0, 100000), 10);

  // Delete some records.
  EXPECT_EQ(webauthn_storage_->DeleteRecordsInTimeRange(10100, 10200), 2);
  EXPECT_EQ(webauthn_storage_->DeleteRecordsInTimeRange(10400, 10700), 4);

  // See if remaining amount of records is correct.
  EXPECT_EQ(webauthn_storage_->CountRecordsInTimeRange(10150, 10800), 2);
  EXPECT_EQ(webauthn_storage_->CountRecordsInTimeRange(0, 100000), 4);

  // Delete all records.
  EXPECT_EQ(webauthn_storage_->DeleteRecordsInTimeRange(0, 100000), 4);
  EXPECT_EQ(webauthn_storage_->CountRecordsInTimeRange(0, 100000), 0);
}

}  // namespace
}  // namespace u2f
