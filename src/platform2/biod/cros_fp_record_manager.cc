// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <optional>
#include <utility>

#include "biod/cros_fp_record_manager.h"
#include "biod/utils.h"

namespace biod {

CrosFpRecordManager::CrosFpRecordManager(
    std::unique_ptr<BiodStorageInterface> biod_storage)
    : biod_storage_(std::move(biod_storage)) {
  CHECK(biod_storage_);
}

void CrosFpRecordManager::SetAllowAccess(bool allow) {
  biod_storage_->set_allow_access(allow);
}

std::optional<RecordMetadata> CrosFpRecordManager::GetRecordMetadata(
    const std::string& record_id) {
  auto entry = records_metadata_.find(record_id);
  if (entry == records_metadata_.end())
    return std::nullopt;

  return entry->second.metadata;
}

void CrosFpRecordManager::MakeRecordsWithoutValidationValInvalid(
    std::vector<Record>* records) {
  for (auto& record : *records) {
    if (record.valid && record.metadata.validation_val.empty()) {
      LOG(INFO) << "Marking record " << LogSafeID(record.metadata.record_id)
                << " as invalid because it doesn't contain"
                << " validation value.";
      record.valid = false;
    }
  }
}

std::vector<Record> CrosFpRecordManager::GetRecordsForUser(
    const std::string& user_id) {
  std::vector<Record> result = biod_storage_->ReadRecordsForSingleUser(user_id);

  // We don't support records without validation value, so mark them as invalid.
  MakeRecordsWithoutValidationValInvalid(&result);

  // Add records that are not present in records_metadata_.
  // Please note that try_emplace changes the map only when no element with
  // record_id key exists.
  // Invalid records are added too, so they can be deleted when
  // DeleteInvalidRecords or DeleteAllRecords is called (assuming that record
  // metadata contains correct user_id and record_id).
  for (const auto& record : result) {
    records_metadata_.try_emplace(
        record.metadata.record_id,
        CrosFpRecordMetadata{record.metadata, record.valid});
  }

  // Remove invalid records from result before returning vector.
  result.erase(std::remove_if(result.begin(), result.end(),
                              [](const auto& record) { return !record.valid; }),
               result.end());

  return result;
}

bool CrosFpRecordManager::UserHasInvalidRecords(const std::string& user_id) {
  return std::any_of(records_metadata_.begin(), records_metadata_.end(),
                     [&user_id](const auto& p) {
                       const auto& [id, record] = p;
                       return record.valid == false &&
                              record.metadata.user_id == user_id;
                     });
}

bool CrosFpRecordManager::CreateRecord(
    const BiodStorageInterface::RecordMetadata& record,
    std::unique_ptr<VendorTemplate> templ) {
  auto entry = records_metadata_.find(record.record_id);
  if (entry != records_metadata_.end()) {
    LOG(ERROR) << "Attempted to create record with existing RecordID "
               << LogSafeID(record.record_id) << ".";
    return false;
  }

  std::string tmpl_base64 = TemplateToBase64(std::move(templ));
  if (!biod_storage_->WriteRecord(record,
                                  base::Value(std::move(tmpl_base64)))) {
    return false;
  }

  std::string record_id = record.record_id;
  records_metadata_.emplace(std::move(record_id), CrosFpRecordMetadata{record});

  return true;
}

bool CrosFpRecordManager::UpdateRecord(const RecordMetadata& record_metadata,
                                       std::unique_ptr<VendorTemplate> templ) {
  const auto& record_id = record_metadata.record_id;
  const auto& user_id = record_metadata.user_id;

  // Updated record must exist.
  CHECK(records_metadata_.find(record_id) != records_metadata_.end());
  const auto& current_user_id = records_metadata_[record_id].metadata.user_id;

  // Must be valid.
  if (!records_metadata_[record_id].valid) {
    LOG(WARNING) << "Attempt to update invalid record " << LogSafeID(record_id)
                 << " for user " << LogSafeID(current_user_id);
    return false;
  }

  // And UserId must match.
  if (current_user_id != user_id) {
    LOG(ERROR) << "UserID mismatch (current: " << LogSafeID(current_user_id)
               << ", update: " << LogSafeID(user_id) << ") during attempt"
               << " to update record " << LogSafeID(record_id);
    return false;
  }

  std::string tmpl_base64 = TemplateToBase64(std::move(templ));
  if (!biod_storage_->WriteRecord(record_metadata,
                                  base::Value(std::move(tmpl_base64)))) {
    return false;
  }

  // Update metadata stored in this record manager.
  records_metadata_[record_id].metadata = record_metadata;

  return true;
}

bool CrosFpRecordManager::UpdateRecordMetadata(
    const RecordMetadata& record_metadata) {
  const auto& record_id = record_metadata.record_id;
  const auto& user_id = record_metadata.user_id;

  // Updated record must exist.
  CHECK(records_metadata_.find(record_id) != records_metadata_.end());
  const auto& current_user_id = records_metadata_[record_id].metadata.user_id;

  // Must be valid.
  if (!records_metadata_[record_id].valid) {
    LOG(WARNING) << "Attempt to update invalid record " << LogSafeID(record_id)
                 << " for user " << LogSafeID(current_user_id);
    return false;
  }

  // And UserId must match.
  if (current_user_id != user_id) {
    LOG(ERROR) << "UserID mismatch (current: " << LogSafeID(current_user_id)
               << ", update: " << LogSafeID(user_id) << ") during attempt"
               << " to update record " << LogSafeID(record_id);
    return false;
  }

  // Read existing record from storage. A complete record consists of both
  // the metadata and the FPMCU template. We currently only have the metadata.
  const auto record = biod_storage_->ReadSingleRecord(user_id, record_id);
  if (!record || !record->valid) {
    return false;
  }

  if (!biod_storage_->WriteRecord(record_metadata,
                                  base::Value(std::move(record->data)))) {
    return false;
  }

  // Update metadata stored in this record manager.
  records_metadata_[record_id].metadata = record_metadata;

  return true;
}

void CrosFpRecordManager::DeleteInvalidRecords() {
  for (auto it = records_metadata_.cbegin(); it != records_metadata_.cend();) {
    const auto record = it->second;
    if (!record.valid) {
      LOG(INFO) << "Deleting invalid record "
                << LogSafeID(record.metadata.record_id) << " for user "
                << LogSafeID(record.metadata.user_id);
      biod_storage_->DeleteRecord(record.metadata.user_id,
                                  record.metadata.record_id);
      it = records_metadata_.erase(it);
    } else {
      it = std::next(it);
    }
  }
}

bool CrosFpRecordManager::DeleteRecord(const std::string& record_id) {
  auto entry = records_metadata_.find(record_id);
  CHECK(entry != records_metadata_.end());

  const std::string user_id = entry->second.metadata.user_id;
  // Delete record from storage.
  if (!biod_storage_->DeleteRecord(user_id, record_id)) {
    return false;
  }

  // Remove record metadata.
  records_metadata_.erase(record_id);

  return true;
}

bool CrosFpRecordManager::DeleteAllRecords() {
  // Enumerate through records_metadata_ and delete each record.
  bool delete_all_records = true;
  for (const auto& [id, record] : records_metadata_) {
    delete_all_records &= biod_storage_->DeleteRecord(
        record.metadata.user_id, record.metadata.record_id);
  }
  RemoveRecordsFromMemory();
  return delete_all_records;
}

void CrosFpRecordManager::RemoveRecordsFromMemory() {
  records_metadata_.clear();
}

std::string CrosFpRecordManager::TemplateToBase64(
    std::unique_ptr<VendorTemplate> templ) {
  std::string tmpl_base64;

  base::StringPiece tmpl_sp(reinterpret_cast<char*>(templ->data()),
                            templ->size());
  base::Base64Encode(tmpl_sp, &tmpl_base64);

  return tmpl_base64;
}

}  // namespace biod
