// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_MOCK_BIOD_STORAGE_H_
#define BIOD_MOCK_BIOD_STORAGE_H_

#include <gmock/gmock.h>

#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "biod/biod_storage.h"

namespace biod {
namespace storage {

class MockBiodStorage : public BiodStorageInterface {
 public:
  MockBiodStorage() = default;
  ~MockBiodStorage() override = default;

  MOCK_METHOD(void,
              SetRootPathForTesting,
              (const base::FilePath& root_path),
              (override));
  MOCK_METHOD(base::FilePath,
              GetRecordFilename,
              (const BiodStorageInterface::RecordMetadata& record_metadata),
              (override));
  MOCK_METHOD(bool,
              WriteRecord,
              (const BiodStorageInterface::RecordMetadata& record_metadata,
               base::Value data),
              (override));
  MOCK_METHOD(std::vector<BiodStorageInterface::Record>,
              ReadRecords,
              (const std::unordered_set<std::string>& user_ids),
              (override));
  MOCK_METHOD(std::vector<BiodStorageInterface::Record>,
              ReadRecordsForSingleUser,
              (const std::string& user_id),
              (override));
  MOCK_METHOD(std::optional<Record>,
              ReadSingleRecord,
              (const std::string& user_id, const std::string& record_id),
              (override));
  MOCK_METHOD(bool,
              DeleteRecord,
              (const std::string& user_id, const std::string& record_id),
              (override));
  MOCK_METHOD(void, set_allow_access, (bool allow_access), (override));
};

}  // namespace storage
}  // namespace biod

#endif  // BIOD_MOCK_BIOD_STORAGE_H_
