// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_STORAGE_H_
#define BIOD_BIOD_STORAGE_H_

#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include <base/base64.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/secure_blob.h>
#include <brillo/scoped_umask.h>

#include "biod/biometrics_manager.h"
#include "biod/biometrics_manager_record.h"

namespace biod {

// Version of the record format.
inline constexpr int kRecordFormatVersion = 2;
inline constexpr int kRecordFormatVersionNoValidationValue = 1;

class BiodStorageInterface {
 public:
  struct RecordMetadata {
    /** Record file's scheme version. */
    int record_format_version;
    /** Record/fingerprint-template's UUID. */
    std::string record_id;
    /** Sanitized user session ID. */
    std::string user_id;
    /** User supplied description of finger. */
    std::string label;
    /** Positive match secrect validation value. */
    std::vector<uint8_t> validation_val;

    bool operator==(const RecordMetadata& rhs) const {
      return std::tie(this->record_format_version, this->validation_val,
                      this->record_id, this->user_id, this->label) ==
             std::tie(rhs.record_format_version, rhs.validation_val,
                      rhs.record_id, rhs.user_id, rhs.label);
    }

    bool operator!=(const RecordMetadata& rhs) const { return !(*this == rhs); }

    const std::string GetValidationValBase64() const {
      std::string validation_val_base64(validation_val.begin(),
                                        validation_val.end());
      base::Base64Encode(validation_val_base64, &validation_val_base64);
      return validation_val_base64;
    }

    bool IsValidUTF8() const {
      if (!base::IsStringUTF8(label)) {
        LOG(ERROR) << "Label is not valid UTF8";
        return false;
      }

      if (!base::IsStringUTF8(record_id)) {
        LOG(ERROR) << "Record ID is not valid UTF8";
        return false;
      }

      if (!base::IsStringUTF8(GetValidationValBase64())) {
        LOG(ERROR) << "Validation value is not valid UTF8";
        return false;
      }

      if (!base::IsStringUTF8(user_id)) {
        LOG(ERROR) << "User ID is not valid UTF8";
        return false;
      }

      return true;
    }
  };

  struct Record {
    RecordMetadata metadata;
    // "data" is base64 encoded.
    std::string data;
    bool valid = true;

    bool operator==(const Record& rhs) const {
      // Please note that |valid| is not taken into account when comparing
      // Record structures.
      return std::tie(this->metadata, this->data) ==
             std::tie(rhs.metadata, rhs.data);
    }

    bool operator!=(const Record& rhs) const { return !(*this == rhs); }
  };

  virtual ~BiodStorageInterface() = default;

  virtual void SetRootPathForTesting(const base::FilePath& root_path) = 0;
  virtual base::FilePath GetRecordFilename(
      const BiodStorageInterface::RecordMetadata& record_metadata) = 0;
  virtual bool WriteRecord(
      const BiodStorageInterface::RecordMetadata& record_metadata,
      base::Value data) = 0;
  virtual std::vector<Record> ReadRecords(
      const std::unordered_set<std::string>& user_ids) = 0;
  virtual std::vector<Record> ReadRecordsForSingleUser(
      const std::string& user_id) = 0;
  virtual std::optional<Record> ReadSingleRecord(
      const std::string& user_id, const std::string& record_id) = 0;
  virtual bool DeleteRecord(const std::string& user_id,
                            const std::string& record_id) = 0;
  virtual void set_allow_access(bool allow_access) = 0;
};

class BiodStorage : public BiodStorageInterface {
 public:
  // Constructor sets the file path to be
  // /run/daemon-store/biod/<user_id>/<biometrics_manager_name>/<record_id>,
  // which is bound to
  // /home/root/<user_id>/biod/<biometrics_manager_name>/<record_id>.
  explicit BiodStorage(const std::string& biometrics_manager_name);

  // Set root path to a different path for testing purpose only.
  void SetRootPathForTesting(const base::FilePath& root_path) override;

  /**
   * Get the file name for a given record. Intended to be used for testing.
   *
   * @param record
   * @return Full path on success. Empty path on failure.
   */
  base::FilePath GetRecordFilename(
      const BiodStorageInterface::RecordMetadata& record_metadata) override;

  // Write one record to file in per user stateful. This is called whenever
  // we enroll a new record.
  bool WriteRecord(const BiodStorageInterface::RecordMetadata& record_metadata,
                   base::Value data) override;

  // Read validation value from |record_dictionary| and store in |output|.
  static std::unique_ptr<std::vector<uint8_t>> ReadValidationValueFromRecord(
      const base::Value::Dict& record_dictionary,
      const base::FilePath& record_path);

  // Read all records from file for all users in the set. Called whenever biod
  // starts or when a new user logs in.
  std::vector<Record> ReadRecords(
      const std::unordered_set<std::string>& user_ids) override;

  // Read all records from disk for a single user. Uses a file enumerator to
  // enumerate through all record files. Called whenever biod starts or when
  // a new user logs in.
  std::vector<Record> ReadRecordsForSingleUser(
      const std::string& user_id) override;

  // Read a single record from disk and return it. If record doesn't exist
  // then std::nullopt is returned.
  std::optional<Record> ReadSingleRecord(const std::string& user_id,
                                         const std::string& record_id) override;

  // Delete one record file. User will be able to do this via UI. True if
  // this record does not exist on disk.
  bool DeleteRecord(const std::string& user_id,
                    const std::string& record_id) override;

  // Generate a uuid with guid.h for each record. Uuid is 128 bit number,
  // which is then turned into a string of format
  // xxxxxxxx_xxxx_xxxx_xxxx_xxxxxxxxxxxx, where x is a lowercase hex number.
  static std::string GenerateNewRecordId();

  // Set the |allow_access_| which determines whether the backing storage
  // location can be accessed or not. Depending on the mounting mechanism and
  // namespace restrictions, the mounts might not be visible until after
  // certain points of the user flow (like successful login) are complete.
  void set_allow_access(bool allow_access) override {
    allow_access_ = allow_access;
  }

 private:
  // It reads single record from provided path. If record doesn't exist then
  // std::nullopt is returned. If record is invalid then |valid| field in the
  // Record structure will be set to false.
  std::optional<Record> ReadRecordFromPath(const base::FilePath& record_path);
  base::FilePath root_path_;
  std::string biometrics_manager_name_;
  bool allow_access_;
};
}  // namespace biod

#endif  // BIOD_BIOD_STORAGE_H_
