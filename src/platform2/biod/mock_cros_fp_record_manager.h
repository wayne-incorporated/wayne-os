// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_MOCK_CROS_FP_RECORD_MANAGER_H_
#define BIOD_MOCK_CROS_FP_RECORD_MANAGER_H_

#include <gmock/gmock.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "biod/cros_fp_record_manager.h"

namespace biod {

class MockCrosFpRecordManager : public CrosFpRecordManagerInterface {
 public:
  MockCrosFpRecordManager() = default;
  explicit MockCrosFpRecordManager(const MockCrosFpRecordManager&) = delete;
  MockCrosFpRecordManager& operator=(const MockCrosFpRecordManager&) = delete;

  MOCK_METHOD(void, SetAllowAccess, (bool allow));
  MOCK_METHOD(std::optional<RecordMetadata>,
              GetRecordMetadata,
              (const std::string& record_id));
  MOCK_METHOD(std::vector<Record>,
              GetRecordsForUser,
              (const std::string& user_id));
  MOCK_METHOD(bool, UserHasInvalidRecords, (const std::string& user_id));
  MOCK_METHOD(bool,
              CreateRecord,
              (const RecordMetadata& record,
               std::unique_ptr<VendorTemplate> templ));
  MOCK_METHOD(bool,
              UpdateRecord,
              (const RecordMetadata& record_metadata,
               std::unique_ptr<VendorTemplate> templ));
  MOCK_METHOD(bool,
              UpdateRecordMetadata,
              (const RecordMetadata& record_metadata));

  MOCK_METHOD(bool, DeleteRecord, (const std::string& record_id));
  MOCK_METHOD(bool, DeleteAllRecords, ());
  MOCK_METHOD(void, DeleteInvalidRecords, ());
  MOCK_METHOD(void, RemoveRecordsFromMemory, ());
};

}  // namespace biod

#endif  // BIOD_MOCK_CROS_FP_RECORD_MANAGER_H_
