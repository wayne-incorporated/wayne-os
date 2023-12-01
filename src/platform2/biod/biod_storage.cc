// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/biod_storage.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <optional>
#include <sstream>
#include <utility>

#include <base/base64.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/json/json_reader.h>
#include <base/json/json_string_value_serializer.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/uuid.h>
#include <base/values.h>
#include <brillo/scoped_umask.h>

#include "biod/biometrics_manager_record.h"
#include "biod/utils.h"

namespace biod {

using base::FilePath;

namespace {
constexpr char kDaemonStorePath[] = "/run/daemon-store";
constexpr char kRecordFileName[] = "Record";
constexpr char kBiod[] = "biod";

// Members of the JSON file.
constexpr char kBioManagerMember[] = "biomanager";
constexpr char kData[] = "data";
constexpr char kLabel[] = "label";
constexpr char kRecordId[] = "record_id";
constexpr char kValidationVal[] = "match_validation_value";
constexpr char kVersionMember[] = "version";
}  // namespace

BiodStorage::BiodStorage(const std::string& biometrics_manager_name)
    : root_path_(kDaemonStorePath),
      biometrics_manager_name_(biometrics_manager_name),
      allow_access_(false) {}

void BiodStorage::SetRootPathForTesting(const base::FilePath& root_path) {
  root_path_ = root_path;
}

bool BiodStorage::WriteRecord(
    const BiodStorageInterface::RecordMetadata& record_metadata,
    base::Value data) {
  if (!allow_access_) {
    LOG(ERROR) << "Access to the storage mounts not allowed.";
    return false;
  }

  if (!record_metadata.IsValidUTF8()) {
    LOG(ERROR) << "Record contains invalid UTF8.";
    return false;
  }

  const std::string& record_id(record_metadata.record_id);
  base::Value::Dict record_value;
  record_value.Set(kLabel, record_metadata.label);
  record_value.Set(kRecordId, record_id);
  record_value.Set(kValidationVal, record_metadata.GetValidationValBase64());
  record_value.Set(kVersionMember, kRecordFormatVersion);
  record_value.Set(kData, std::move(data));
  record_value.Set(kBioManagerMember, biometrics_manager_name_);

  std::string json_string;
  JSONStringValueSerializer json_serializer(&json_string);
  if (!json_serializer.Serialize(record_value)) {
    LOG(ERROR) << "Failed to serialize record " << LogSafeID(record_id)
               << " to JSON.";
    return false;
  }

  FilePath record_storage_filename = GetRecordFilename(record_metadata);
  if (record_storage_filename.empty()) {
    LOG(ERROR) << "Unable to get filename for record.";
    return false;
  }

  {
    brillo::ScopedUmask owner_only_umask(~(0700));

    if (!base::CreateDirectory(record_storage_filename.DirName())) {
      PLOG(ERROR) << "Cannot create directory for user "
                  << LogSafeID(record_metadata.user_id) << ".";
      return false;
    }
  }

  {
    brillo::ScopedUmask owner_only_umask(~(0600));

    if (!base::ImportantFileWriter::WriteFileAtomically(record_storage_filename,
                                                        json_string)) {
      LOG(ERROR) << "Failed to write JSON file for record "
                 << LogSafeID(record_metadata.record_id) << ".";
      return false;
    }
  }

  LOG(INFO) << "Done writing record " << LogSafeID(record_id)
            << " to file successfully. ";
  return true;
}

std::unique_ptr<std::vector<uint8_t>>
BiodStorage::ReadValidationValueFromRecord(
    const base::Value::Dict& record_dictionary, const FilePath& record_path) {
  std::string validation_val_str;

  const std::string* validation_val_str_ptr =
      record_dictionary.FindString(kValidationVal);
  if (!validation_val_str_ptr) {
    LOG(WARNING) << "Cannot read validation value from " << record_path.value()
                 << ".";
    return nullptr;
  }
  validation_val_str = *validation_val_str_ptr;
  if (!base::Base64Decode(validation_val_str, &validation_val_str)) {
    LOG(ERROR) << "Unable to base64 decode validation value from "
               << record_path.value() << ".";
    return nullptr;
  }

  return std::make_unique<std::vector<uint8_t>>(validation_val_str.begin(),
                                                validation_val_str.end());
}

std::vector<BiodStorageInterface::Record> BiodStorage::ReadRecords(
    const std::unordered_set<std::string>& user_ids) {
  std::vector<BiodStorageInterface::Record> ret;
  for (const auto& user_id : user_ids) {
    auto result = ReadRecordsForSingleUser(user_id);
    ret.insert(ret.end(), std::make_move_iterator(result.begin()),
               std::make_move_iterator(result.end()));
  }
  return ret;
}

std::vector<BiodStorageInterface::Record> BiodStorage::ReadRecordsForSingleUser(
    const std::string& user_id) {
  std::vector<BiodStorageInterface::Record> ret;

  if (!allow_access_) {
    LOG(ERROR) << "Access to the storage mounts not yet allowed.";
    return ret;
  }

  FilePath biod_path =
      root_path_.Append(kBiod).Append(user_id).Append(biometrics_manager_name_);
  base::FileEnumerator enum_records(biod_path, false,
                                    base::FileEnumerator::FILES, "Record*");
  for (FilePath record_path = enum_records.Next(); !record_path.empty();
       record_path = enum_records.Next()) {
    auto record = ReadRecordFromPath(record_path);
    // In this function we are enumerating files, so if Optional returned
    // by ReadRecordFromPath is empty, then there is something wrong with biod.
    CHECK(record);
    record->metadata.user_id = user_id;

    ret.emplace_back(std::move(*record));
  }
  return ret;
}

std::optional<BiodStorageInterface::Record> BiodStorage::ReadSingleRecord(
    const std::string& user_id, const std::string& record_id) {
  if (!allow_access_) {
    LOG(ERROR) << "Access to the storage mounts not yet allowed.";
    return std::nullopt;
  }

  base::FilePath record_path = root_path_.Append(kBiod)
                                   .Append(user_id)
                                   .Append(biometrics_manager_name_)
                                   .Append(kRecordFileName + record_id);

  auto record = ReadRecordFromPath(record_path);
  if (record) {
    record->metadata.user_id = user_id;
  }

  return record;
}

std::optional<BiodStorageInterface::Record> BiodStorage::ReadRecordFromPath(
    const base::FilePath& record_path) {
  std::string json_string;

  if (!base::ReadFileToString(record_path, &json_string)) {
    LOG(ERROR) << "Failed to read the string from " << record_path.value()
               << ".";
    // Biod can't find this file.
    return std::nullopt;
  }

  // File was found. Return Record (valid or invalid) to indicate that it
  // exists.
  BiodStorageInterface::Record record;
  record.valid = false;

  // Get RecordId from path. In case of mismatch this RecordId is more
  // important because it allows upper layers to remove invalid record
  // properly.
  std::string record_id_path = record_path.BaseName().value();
  record_id_path.erase(0, sizeof(kRecordFileName) - 1);
  record.metadata.record_id = record_id_path;

  auto record_value = base::JSONReader::ReadAndReturnValueWithError(
      json_string, base::JSON_ALLOW_TRAILING_COMMAS);

  if (!record_value.has_value()) {
    LOG_IF(ERROR, !record_value.error().message.empty())
        << "JSON error message: " << record_value.error().message << ".";
    return record;
  }

  if (!record_value->is_dict()) {
    LOG(ERROR) << "Value " << record_path.value() << " is not a dictionary.";
    return record;
  }
  base::Value::Dict record_dictionary = std::move(record_value->GetDict());

  const std::string* record_id = record_dictionary.FindString(kRecordId);

  if (!record_id) {
    LOG(ERROR) << "Cannot read record id from " << record_path.value() << ".";
    return record;
  }
  // If RecordId from path is different than stored in the file then
  // record is not valid.
  if (record.metadata.record_id != *record_id) {
    LOG(ERROR) << "RecordId from path " << LogSafeID(record.metadata.record_id)
               << " is different than RecordId stored in file "
               << LogSafeID(*record_id);
    return record;
  }

  const std::string* label = record_dictionary.FindString(kLabel);

  if (!label) {
    LOG(ERROR) << "Cannot read label from " << record_path.value() << ".";
    return record;
  }
  record.metadata.label = *label;

  std::optional<int> record_format_version =
      record_dictionary.FindInt(kVersionMember);
  if (!record_format_version.has_value()) {
    LOG(ERROR) << "Cannot read record format version from "
               << record_path.value() << ".";
    return record;
  }
  record.metadata.record_format_version = *record_format_version;

  if (*record_format_version < 0 ||
      *record_format_version > kRecordFormatVersion) {
    LOG(ERROR) << "Invalid format version from record " << record_path.value()
               << ".";
    return record;
  }

  std::unique_ptr<std::vector<uint8_t>> validation_val =
      ReadValidationValueFromRecord(record_dictionary, record_path);
  // Validation value was introduced in format version 2, so it might not be
  // present in older records.
  if (!validation_val) {
    if (*record_format_version >= kRecordFormatVersion) {
      return record;
    }
    // If format version is older than 2, then it is valid old record (without
    // validation value).
    validation_val = std::make_unique<std::vector<uint8_t>>();
  }
  record.metadata.validation_val = *validation_val;

  const std::string* data = record_dictionary.FindString(kData);

  if (!data) {
    LOG(ERROR) << "Cannot read data from " << record_path.value() << ".";
    return record;
  }
  record.data = *data;

  record.valid = true;
  return record;
}

bool BiodStorage::DeleteRecord(const std::string& user_id,
                               const std::string& record_id) {
  if (!allow_access_) {
    LOG(ERROR) << "Access to the storage mounts not yet allowed.";
    return false;
  }

  FilePath record_storage_filename = root_path_.Append(kBiod)
                                         .Append(user_id)
                                         .Append(biometrics_manager_name_)
                                         .Append(kRecordFileName + record_id);

  if (!base::PathExists(record_storage_filename)) {
    LOG(INFO) << "Trying to delete record " << LogSafeID(record_id)
              << " which does not exist on disk.";
    return true;
  }
  if (!base::DeleteFile(record_storage_filename)) {
    LOG(ERROR) << "Fail to delete record " << LogSafeID(record_id)
               << " from disk.";
    return false;
  }
  LOG(INFO) << "Done deleting record " << LogSafeID(record_id) << " from disk.";
  return true;
}

std::string BiodStorage::GenerateNewRecordId() {
  std::string record_id(base::Uuid::GenerateRandomV4().AsLowercaseString());
  // dbus member names only allow '_'
  std::replace(record_id.begin(), record_id.end(), '-', '_');
  return record_id;
}

base::FilePath BiodStorage::GetRecordFilename(
    const BiodStorageInterface::RecordMetadata& record_metadata) {
  std::vector<FilePath> paths = {
      FilePath(kBiod), FilePath(record_metadata.user_id),
      FilePath(biometrics_manager_name_),
      FilePath(kRecordFileName + record_metadata.record_id)};

  FilePath record_storage_filename = root_path_;
  for (const auto& path : paths) {
    if (path.IsAbsolute()) {
      LOG(ERROR) << "Path component must not be absolute: '" << path << "'";
      return base::FilePath();
    }
    record_storage_filename = record_storage_filename.Append(path);
  }

  return record_storage_filename;
}

}  // namespace biod
