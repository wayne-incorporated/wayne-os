// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/webauthn_storage.h"

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <base/base64.h>
#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/json/json_reader.h>
#include <base/json/json_string_value_serializer.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/values.h>
#include <brillo/scoped_umask.h>
#include <brillo/secure_blob.h>
#include <brillo/secure_string.h>

#include "u2fd/client/util.h"

namespace u2f {

using base::FilePath;

namespace {

constexpr const char kDaemonStorePath[] = "/run/daemon-store/u2f";
constexpr const char kWebAuthnDirName[] = "webauthn";
constexpr const char kRecordFileNamePrefix[] = "Record_";

// Members of the JSON file
constexpr const char kCredentialIdKey[] = "credential_id";
constexpr const char kSecretKey[] = "secret";
constexpr const char kKeyBlobKey[] = "key_blob";
constexpr const char kRpIdKey[] = "rp_id";
constexpr const char kRpDisplayNameKey[] = "rp_display_name";
constexpr const char kUserIdKey[] = "user_id";
constexpr const char kUserDisplayNameKey[] = "user_display_name";
constexpr const char kCreatedTimestampKey[] = "created";
constexpr const char kIsResidentKeyKey[] = "is_resident_key";

constexpr char kWebAuthnRecordCountMetric[] =
    "WebAuthentication.ChromeOS.StartupRecordCount";
constexpr int kMinRecordCount = 0;
constexpr int kMaxRecordCount = 50;
constexpr int kRecordCountBuckets = 50;

}  // namespace

WebAuthnStorage::WebAuthnStorage() : root_path_(kDaemonStorePath) {}
WebAuthnStorage::~WebAuthnStorage() = default;

bool WebAuthnStorage::WriteRecord(const WebAuthnRecord& record) {
  DCHECK(allow_access_ && !sanitized_user_.empty());

  const std::string credential_id_hex =
      base::HexEncode(record.credential_id.data(), record.credential_id.size());

  if (record.secret.size() != kCredentialSecretSize) {
    LOG(ERROR) << "Wrong secret size in record with id " << credential_id_hex;
    return false;
  }

  base::Value::Dict record_value =
      base::Value::Dict()
          .Set(kCredentialIdKey, credential_id_hex)
          .Set(kSecretKey, base::Base64Encode(brillo::Blob(
                               record.secret.begin(), record.secret.end())))
          .Set(kKeyBlobKey, base::Base64Encode(record.key_blob))
          .Set(kRpIdKey, record.rp_id)
          .Set(kRpDisplayNameKey, record.rp_display_name)
          .Set(kUserIdKey,
               base::HexEncode(record.user_id.data(), record.user_id.size()))
          .Set(kUserDisplayNameKey, record.user_display_name)
          .Set(kCreatedTimestampKey, record.timestamp)
          .Set(kIsResidentKeyKey, record.is_resident_key);

  std::string json_string;
  JSONStringValueSerializer json_serializer(&json_string);
  if (!json_serializer.Serialize(record_value)) {
    LOG(ERROR) << "Failed to serialize record with id " << credential_id_hex
               << " to JSON.";
    return false;
  }

  // Use the hash of credential_id for the filename because the hex encode of
  // credential_id itself is too long and would cause ENAMETOOLONG.
  const std::vector<uint8_t> credential_id_hash =
      util::Sha256(record.credential_id);
  std::vector<FilePath> paths = {
      FilePath(sanitized_user_), FilePath(kWebAuthnDirName),
      FilePath(kRecordFileNamePrefix +
               base::HexEncode(credential_id_hash.data(),
                               credential_id_hash.size()))};

  FilePath record_storage_filename = root_path_;
  for (const auto& path : paths) {
    DCHECK(!path.IsAbsolute());
    record_storage_filename = record_storage_filename.Append(path);
  }

  {
    brillo::ScopedUmask owner_only_umask(~(0700));

    if (!base::CreateDirectory(record_storage_filename.DirName())) {
      PLOG(ERROR) << "Cannot create directory: "
                  << record_storage_filename.DirName().value() << ".";
      return false;
    }
  }

  {
    brillo::ScopedUmask owner_only_umask(~(0600));

    if (!base::ImportantFileWriter::WriteFileAtomically(record_storage_filename,
                                                        json_string)) {
      LOG(ERROR) << "Failed to write JSON file: "
                 << record_storage_filename.value() << ".";
      return false;
    }
  }

  VLOG(1) << "Done writing record with id " << credential_id_hex
          << " to file successfully. ";

  records_.emplace_back(record);
  return true;
}

bool WebAuthnStorage::LoadRecords() {
  DCHECK(allow_access_ && !sanitized_user_.empty());

  FilePath webauthn_path =
      root_path_.Append(sanitized_user_).Append(kWebAuthnDirName);
  base::FileEnumerator enum_records(webauthn_path, false,
                                    base::FileEnumerator::FILES,
                                    std::string(kRecordFileNamePrefix) + "*");
  bool read_all_records_successfully = true;
  for (FilePath record_path = enum_records.Next(); !record_path.empty();
       record_path = enum_records.Next()) {
    std::string json_string;
    if (!base::ReadFileToString(record_path, &json_string)) {
      LOG(ERROR) << "Failed to read the string from " << record_path.value()
                 << ".";
      read_all_records_successfully = false;
      continue;
    }

    auto record_value = base::JSONReader::ReadAndReturnValueWithError(
        json_string, base::JSON_ALLOW_TRAILING_COMMAS);

    if (!record_value.has_value()) {
      LOG(ERROR) << "Error in deserializing JSON from path "
                 << record_path.value();
      LOG_IF(ERROR, !record_value.error().message.empty())
          << "JSON error message: " << record_value.error().message << ".";
      read_all_records_successfully = false;
      continue;
    }

    if (!record_value->is_dict()) {
      LOG(ERROR) << "Value " << record_path.value() << " is not a dictionary.";
      read_all_records_successfully = false;
      continue;
    }
    base::Value::Dict record_dictionary = std::move(*record_value).TakeDict();

    const std::string* credential_id_hex =
        record_dictionary.FindString(kCredentialIdKey);
    std::string credential_id;
    if (!credential_id_hex ||
        !base::HexStringToString(*credential_id_hex, &credential_id)) {
      LOG(ERROR) << "Cannot read credential_id from " << record_path.value()
                 << ".";
      read_all_records_successfully = false;
      continue;
    }

    const std::string* secret_base64 = record_dictionary.FindString(kSecretKey);
    std::string secret;
    if (!secret_base64 || !base::Base64Decode(*secret_base64, &secret)) {
      LOG(ERROR) << "Cannot read credential secret from " << record_path.value()
                 << ".";
      read_all_records_successfully = false;
      continue;
    }

    const std::string* key_blob_base64 =
        record_dictionary.FindString(kKeyBlobKey);
    std::string key_blob;
    // key blob can be empty for backward compatibility. New key blobs generated
    // in gsc case are empty strings.
    if (key_blob_base64 && !base::Base64Decode(*key_blob_base64, &key_blob)) {
      LOG(ERROR) << "Failed to decode credential secret from "
                 << record_path.value() << ".";
      read_all_records_successfully = false;
      continue;
    }

    const std::string* rp_id = record_dictionary.FindString(kRpIdKey);
    if (!rp_id) {
      LOG(ERROR) << "Cannot read rp_id from " << record_path.value() << ".";
      read_all_records_successfully = false;
      continue;
    }

    const std::string* rp_display_name =
        record_dictionary.FindString(kRpDisplayNameKey);
    if (!rp_display_name) {
      LOG(ERROR) << "Cannot read rp_display_name from " << record_path.value()
                 << ".";
      read_all_records_successfully = false;
      continue;
    }

    const std::string* user_id_hex = record_dictionary.FindString(kUserIdKey);
    std::string user_id;
    if (!user_id_hex) {
      LOG(ERROR) << "Cannot read user_id from " << record_path.value() << ".";
      read_all_records_successfully = false;
      continue;
    }
    // Empty user_id is allowed:
    // https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id
    if (!user_id_hex->empty() &&
        !base::HexStringToString(*user_id_hex, &user_id)) {
      LOG(ERROR) << "Cannot parse user_id from " << record_path.value() << ".";
      read_all_records_successfully = false;
      continue;
    }

    const std::string* user_display_name =
        record_dictionary.FindString(kUserDisplayNameKey);
    if (!user_display_name) {
      LOG(ERROR) << "Cannot read user_display_name from " << record_path.value()
                 << ".";
      read_all_records_successfully = false;
      continue;
    }

    const std::optional<double> timestamp =
        record_dictionary.FindDouble(kCreatedTimestampKey);
    if (!timestamp) {
      LOG(ERROR) << "Cannot read timestamp from " << record_path.value() << ".";
      read_all_records_successfully = false;
      continue;
    }

    const std::optional<bool> is_resident_key =
        record_dictionary.FindBool(kIsResidentKeyKey);
    if (!is_resident_key.has_value()) {
      LOG(ERROR) << "Cannot read is_resident_key from " << record_path.value()
                 << ".";
      read_all_records_successfully = false;
      continue;
    }

    records_.emplace_back(WebAuthnRecord{
        .credential_id = credential_id,
        .secret = brillo::BlobFromString(secret),
        .key_blob = brillo::Blob(key_blob.begin(), key_blob.end()),
        .rp_id = *rp_id,
        .rp_display_name = *rp_display_name,
        .user_id = user_id,
        .user_display_name = *user_display_name,
        .timestamp = *timestamp,
        .is_resident_key = *is_resident_key});
    brillo::SecureClearContainer(secret);
  }
  VLOG(1) << "Loaded " << records_.size() << " WebAuthn records to memory.";
  return read_all_records_successfully;
}

bool WebAuthnStorage::SendRecordCountToUMA(MetricsLibraryInterface* metrics) {
  return metrics->SendToUMA(kWebAuthnRecordCountMetric, records_.size(),
                            kMinRecordCount, kMaxRecordCount,
                            kRecordCountBuckets);
}

std::optional<brillo::SecureBlob> WebAuthnStorage::GetSecretByCredentialId(
    const std::string& credential_id) {
  for (const WebAuthnRecord& record : records_) {
    if (record.credential_id == credential_id) {
      return brillo::SecureBlob(record.secret);
    }
  }
  return std::nullopt;
}

bool WebAuthnStorage::GetSecretAndKeyBlobByCredentialId(
    const std::string& credential_id,
    brillo::SecureBlob* secret,
    brillo::Blob* key_blob) {
  for (const WebAuthnRecord& record : records_) {
    if (record.credential_id == credential_id) {
      if (secret) {
        *secret = brillo::SecureBlob(record.secret);
      }
      if (key_blob) {
        *key_blob = record.key_blob;
      }
      return true;
    }
  }
  return false;
}

std::optional<WebAuthnRecord> WebAuthnStorage::GetRecordByCredentialId(
    const std::string& credential_id) {
  for (const WebAuthnRecord& record : records_) {
    if (record.credential_id == credential_id) {
      return record;
    }
  }
  return std::nullopt;
}

int WebAuthnStorage::CountRecordsInTimeRange(int64_t timestamp_min,
                                             int64_t timestamp_max) {
  int num_records = 0;
  for (const WebAuthnRecord& record : records_) {
    if (timestamp_min <= record.timestamp &&
        record.timestamp <= timestamp_max) {
      num_records++;
    }
  }
  return num_records;
}

int WebAuthnStorage::DeleteRecordsInTimeRange(int64_t timestamp_min,
                                              int64_t timestamp_max) {
  size_t original_size = records_.size();
  auto remove_begin =
      std::remove_if(records_.begin(), records_.end(),
                     [timestamp_min, timestamp_max](const auto& record) {
                       return timestamp_min <= record.timestamp &&
                              record.timestamp <= timestamp_max;
                     });
  for (auto record = remove_begin; record != records_.end(); record++) {
    DeleteRecordWithCredentialId(record->credential_id);
  }
  records_.erase(remove_begin, records_.end());
  size_t updated_size = records_.size();
  return original_size - updated_size;
}

void WebAuthnStorage::Reset() {
  allow_access_ = false;
  sanitized_user_.clear();
  records_.clear();
}

void WebAuthnStorage::SetRootPathForTesting(const base::FilePath& root_path) {
  root_path_ = root_path;
}

bool WebAuthnStorage::DeleteRecordWithCredentialId(
    const std::string& credential_id) {
  // Use the hash of credential_id for the filename because the hex encode of
  // credential_id itself is too long and would cause ENAMETOOLONG.
  const std::vector<uint8_t> credential_id_hash = util::Sha256(credential_id);
  std::vector<FilePath> paths = {
      FilePath(sanitized_user_), FilePath(kWebAuthnDirName),
      FilePath(kRecordFileNamePrefix +
               base::HexEncode(credential_id_hash.data(),
                               credential_id_hash.size()))};

  FilePath record_storage_filename = root_path_;
  for (const auto& path : paths) {
    DCHECK(!path.IsAbsolute());
    record_storage_filename = record_storage_filename.Append(path);
  }

  if (!base::DeleteFile(record_storage_filename)) {
    LOG(ERROR) << "Failed to delete file: " << record_storage_filename.value()
               << ".";
    return false;
  }
  VLOG(1) << "Successfully deleted file: " << record_storage_filename.value()
          << ".";
  return true;
}

}  // namespace u2f
