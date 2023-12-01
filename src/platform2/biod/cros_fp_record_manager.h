// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_CROS_FP_RECORD_MANAGER_H_
#define BIOD_CROS_FP_RECORD_MANAGER_H_

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <libec/fingerprint/cros_fp_device_interface.h>

#include "biod/biod_storage.h"
#include "biod/biometrics_manager.h"

namespace biod {

using RecordMetadata = BiodStorageInterface::RecordMetadata;
using Record = BiodStorage::Record;

class CrosFpRecordManagerInterface {
 public:
  virtual ~CrosFpRecordManagerInterface() = default;

  virtual void SetAllowAccess(bool allow) = 0;
  virtual std::optional<RecordMetadata> GetRecordMetadata(
      const std::string& record_id) = 0;
  virtual std::vector<Record> GetRecordsForUser(const std::string& user_id) = 0;
  virtual bool UserHasInvalidRecords(const std::string& user_id) = 0;
  virtual bool CreateRecord(const RecordMetadata& record,
                            std::unique_ptr<VendorTemplate> templ) = 0;
  virtual bool UpdateRecord(const RecordMetadata& record_metadata,
                            std::unique_ptr<VendorTemplate> templ) = 0;
  virtual bool UpdateRecordMetadata(const RecordMetadata& record_metadata) = 0;

  virtual bool DeleteRecord(const std::string& record_id) = 0;
  virtual bool DeleteAllRecords() = 0;
  virtual void DeleteInvalidRecords() = 0;
  virtual void RemoveRecordsFromMemory() = 0;
};

class CrosFpRecordManager : public CrosFpRecordManagerInterface {
 public:
  explicit CrosFpRecordManager(
      std::unique_ptr<BiodStorageInterface> biod_storage);
  explicit CrosFpRecordManager(const CrosFpRecordManager&) = delete;
  CrosFpRecordManager& operator=(const CrosFpRecordManager&) = delete;

  void SetAllowAccess(bool allow) override;

  // Returns RecordMetadata for given record.
  std::optional<RecordMetadata> GetRecordMetadata(
      const std::string& record_id) override;
  std::vector<Record> GetRecordsForUser(const std::string& user_id) override;
  bool UserHasInvalidRecords(const std::string& user_id) override;
  bool CreateRecord(const RecordMetadata& record,
                    std::unique_ptr<VendorTemplate> templ) override;
  bool UpdateRecord(const RecordMetadata& record_metadata,
                    std::unique_ptr<VendorTemplate> templ) override;
  bool UpdateRecordMetadata(const RecordMetadata& record_metadata) override;

  bool DeleteRecord(const std::string& record_id) override;
  bool DeleteAllRecords() override;
  void DeleteInvalidRecords() override;
  void RemoveRecordsFromMemory() override;

 private:
  std::string TemplateToBase64(std::unique_ptr<VendorTemplate> templ);
  void MakeRecordsWithoutValidationValInvalid(std::vector<Record>* records);
  std::unique_ptr<BiodStorageInterface> biod_storage_;

  struct CrosFpRecordMetadata {
    BiodStorageInterface::RecordMetadata metadata;
    bool valid = true;
  };

  // Map in which the key is Record ID and the value is record metadata.
  std::unordered_map<std::string, CrosFpRecordMetadata> records_metadata_;
};
}  // namespace biod

#endif  // BIOD_CROS_FP_RECORD_MANAGER_H_
