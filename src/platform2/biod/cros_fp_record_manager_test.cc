// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <optional>
#include <utility>

#include "biod/biod_crypto_test_data.h"
#include "biod/cros_fp_record_manager.h"
#include "biod/mock_biod_storage.h"

namespace biod {

using Record = BiodStorageInterface::Record;
using RecordMetadata = BiodStorageInterface::RecordMetadata;

namespace {
constexpr char kRecordID1[] = "record1";
constexpr char kRecordID2[] = "record2";
constexpr char kData1[] = "some_super_interesting_data1";
constexpr char kData2[] = "some_super_interesting_data2";
constexpr char kLabel[] = "label0";
constexpr char kUserID1[] = "User1";
constexpr char kUserID2[] = "User2";

using crypto_test_data::kFakePositiveMatchSecret1;
using crypto_test_data::kFakePositiveMatchSecret2;
using crypto_test_data::kFakeValidationValue1;
using crypto_test_data::kFakeValidationValue2;
using crypto_test_data::kUserID;

using testing::_;
using testing::DoAll;
using testing::Return;

class CrosFpRecordManagerTest : public ::testing::Test {
 public:
  CrosFpRecordManagerTest() {
    auto mock_biod_storage = std::make_unique<storage::MockBiodStorage>();
    mock_biod_storage_ = mock_biod_storage.get();

    record_manager_.emplace(std::move(mock_biod_storage));
  }

 protected:
  std::optional<CrosFpRecordManager> record_manager_;
  storage::MockBiodStorage* mock_biod_storage_;
};

TEST_F(CrosFpRecordManagerTest, TestSetAllowAccessTrue) {
  EXPECT_CALL(*mock_biod_storage_, set_allow_access(true)).Times(1);
  EXPECT_CALL(*mock_biod_storage_, set_allow_access(false)).Times(0);

  record_manager_->SetAllowAccess(true);
}

TEST_F(CrosFpRecordManagerTest, TestSetAllowAccessFalse) {
  EXPECT_CALL(*mock_biod_storage_, set_allow_access(true)).Times(0);
  EXPECT_CALL(*mock_biod_storage_, set_allow_access(false)).Times(1);

  record_manager_->SetAllowAccess(false);
}

TEST_F(CrosFpRecordManagerTest, TestGetRecordsForUser) {
  std::vector<Record> user_records({{{kRecordFormatVersion, kRecordID1,
                                      kUserID1, kLabel, kFakeValidationValue1},
                                     kData1},
                                    {{kRecordFormatVersion, kRecordID2,
                                      kUserID1, kLabel, std::vector<uint8_t>()},
                                     kData2}});

  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser)
      .WillOnce(Return(user_records));

  std::vector<Record> result = record_manager_->GetRecordsForUser(kUserID1);

  // Expect that only valid records were returned
  EXPECT_EQ(result.size(), 1);
  EXPECT_EQ(result[0], user_records[0]);
}

TEST_F(CrosFpRecordManagerTest, TestGetRecordsForUserNoValidationValue) {
  RecordMetadata record_metadata1{kRecordFormatVersionNoValidationValue,
                                  kRecordID1, kUserID1, kLabel,
                                  std::vector<uint8_t>()};

  std::vector<Record> test_record({Record{record_metadata1, kData1}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));

  EXPECT_TRUE(record_manager_->GetRecordsForUser(kUserID1).empty());
  EXPECT_TRUE(record_manager_->UserHasInvalidRecords(kUserID1));
}

TEST_F(CrosFpRecordManagerTest, TestGetRecordMetadataValidInvalid) {
  RecordMetadata valid_record_metadata{kRecordFormatVersion, kRecordID1,
                                       kUserID1, kLabel, kFakeValidationValue1};
  RecordMetadata invalid_record_metadata{kRecordFormatVersion, kRecordID2,
                                         kUserID1, kLabel,
                                         std::vector<uint8_t>()};

  std::vector<Record> test_records = {
      Record{valid_record_metadata, kData1},
      Record{invalid_record_metadata, kData2, /* valid= */ false}};
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser)
      .WillOnce(Return(test_records));

  record_manager_->GetRecordsForUser(kUserID1);
  auto metadata1 = record_manager_->GetRecordMetadata(kRecordID1);
  auto metadata2 = record_manager_->GetRecordMetadata(kRecordID2);
  EXPECT_TRUE(metadata1);
  EXPECT_TRUE(metadata2);
  EXPECT_EQ(valid_record_metadata, *metadata1);
  EXPECT_EQ(invalid_record_metadata, *metadata2);
}

TEST_F(CrosFpRecordManagerTest, TestGetRecordMetadataManyUsers) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2{kRecordFormatVersion, kRecordID2, kUserID2,
                                  kLabel, kFakeValidationValue2};

  std::vector<Record> test_record1({Record{record_metadata1, kData1}});
  std::vector<Record> test_record2({Record{record_metadata2, kData2}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record1));
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID2))
      .WillOnce(Return(test_record2));

  record_manager_->GetRecordsForUser(kUserID1);
  record_manager_->GetRecordsForUser(kUserID2);
  auto metadata1 = record_manager_->GetRecordMetadata(kRecordID1);
  auto metadata2 = record_manager_->GetRecordMetadata(kRecordID2);
  EXPECT_TRUE(metadata1);
  EXPECT_TRUE(metadata2);
  EXPECT_EQ(record_metadata1, *metadata1);
  EXPECT_EQ(record_metadata2, *metadata2);
}

TEST_F(CrosFpRecordManagerTest, TestUserHasInvalidRecordsTrue) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};

  std::vector<Record> test_record1(
      {Record{record_metadata1, kData1, /* valid= */ false}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record1));

  record_manager_->GetRecordsForUser(kUserID1);
  EXPECT_TRUE(record_manager_->UserHasInvalidRecords(kUserID1));
}

TEST_F(CrosFpRecordManagerTest, TestUserHasInvalidRecordsFalse) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};

  std::vector<Record> test_record({Record{record_metadata1, kData1}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));

  record_manager_->GetRecordsForUser(kUserID1);
  EXPECT_FALSE(record_manager_->UserHasInvalidRecords(kUserID1));
}

TEST_F(CrosFpRecordManagerTest, TestUserHasInvalidRecordsNoRecords) {
  // Check if function reports false when we haven't attempted to load records.
  EXPECT_FALSE(record_manager_->UserHasInvalidRecords(kUserID1));

  std::vector<Record> test_record;
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));

  record_manager_->GetRecordsForUser(kUserID1);
  // Function should report false also when we attempted to load records,
  // but user doesn't have any.
  EXPECT_FALSE(record_manager_->UserHasInvalidRecords(kUserID2));
}

TEST_F(CrosFpRecordManagerTest, TestCreateRecord) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};

  EXPECT_CALL(*mock_biod_storage_, WriteRecord(record_metadata1, _))
      .WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->CreateRecord(
      record_metadata1, std::make_unique<VendorTemplate>()));
  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestCreateRecordWhenOtherRecordsExists) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2{kRecordFormatVersion, kRecordID2, kUserID1,
                                  kLabel, kFakeValidationValue2};

  std::vector<Record> test_record({Record{record_metadata1, kData1}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, WriteRecord(record_metadata2, _))
      .WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->CreateRecord(
      record_metadata2, std::make_unique<VendorTemplate>()));
  auto metadata1 = record_manager_->GetRecordMetadata(kRecordID1);
  auto metadata2 = record_manager_->GetRecordMetadata(kRecordID2);
  EXPECT_TRUE(metadata1);
  EXPECT_TRUE(metadata2);
  EXPECT_EQ(record_metadata1, *metadata1);
  EXPECT_EQ(record_metadata2, *metadata2);
}

TEST_F(CrosFpRecordManagerTest, TestCreateRecordWriteFailed) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};

  EXPECT_CALL(*mock_biod_storage_, WriteRecord(record_metadata1, _))
      .WillOnce(Return(false));
  EXPECT_FALSE(record_manager_->CreateRecord(
      record_metadata1, std::make_unique<VendorTemplate>()));
}

/*
 * Check if running CreateRecord with the same RecordID twice causes the latter
 * to fail. No records are loaded from disk in this test.
 */
TEST_F(CrosFpRecordManagerTest, TestCreateTheSameRecordTwice) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2{kRecordFormatVersion, kRecordID1, kUserID2,
                                  kLabel, kFakeValidationValue2};

  EXPECT_CALL(*mock_biod_storage_, WriteRecord(record_metadata1, _))
      .WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->CreateRecord(
      record_metadata1, std::make_unique<VendorTemplate>()));
  EXPECT_FALSE(record_manager_->CreateRecord(
      record_metadata2, std::make_unique<VendorTemplate>()));
  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

/*
 * Check if CreateRecord refuses to add record if provided RecordID already
 * exists. Existing record is loaded from disk, not created like in
 * TestCreateTheSameRecordTwice.
 */
TEST_F(CrosFpRecordManagerTest, TestCreateRecordWithExistingID) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2{kRecordFormatVersion, kRecordID1, kUserID2,
                                  kLabel, kFakeValidationValue2};

  std::vector<Record> test_record({Record{record_metadata1, kData1}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));

  record_manager_->GetRecordsForUser(kUserID1);
  EXPECT_CALL(*mock_biod_storage_, WriteRecord).Times(0);
  EXPECT_FALSE(record_manager_->CreateRecord(
      record_metadata2, std::make_unique<VendorTemplate>()));
  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestUpdateValidRecord) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  // Final metadata with different validation value.
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.validation_val = kFakeValidationValue2;

  std::vector<Record> test_record({Record{record_metadata1, kData1}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, WriteRecord(record_metadata2, _))
      .WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->UpdateRecord(
      record_metadata2, std::make_unique<VendorTemplate>()));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata2, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestUpdateInvalidRecord) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  // Final metadata with different validation value.
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.validation_val = kFakeValidationValue2;

  std::vector<Record> test_record(
      {Record{record_metadata1, kData1, /* valid= */ false}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, WriteRecord).Times(0);
  EXPECT_FALSE(record_manager_->UpdateRecord(
      record_metadata2, std::make_unique<VendorTemplate>()));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestUpdateRecordWriteFailed) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  // Final metadata with different validation value.
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.validation_val = kFakeValidationValue2;

  std::vector<Record> test_record({Record{record_metadata1, kData1}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, WriteRecord).WillOnce(Return(false));
  EXPECT_FALSE(record_manager_->UpdateRecord(
      record_metadata2, std::make_unique<VendorTemplate>()));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestUpdateRecordDifferentUserId) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  // Final metadata with different UserId.
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.user_id = kUserID2;

  std::vector<Record> test_record({Record{record_metadata1, kData1}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, WriteRecord).Times(0);
  EXPECT_FALSE(record_manager_->UpdateRecord(
      record_metadata2, std::make_unique<VendorTemplate>()));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestUpdateMetadataValidRecord) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  // Final metadata with different validation value.
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.validation_val = kFakeValidationValue2;
  Record record1{record_metadata1, kData1};

  std::vector<Record> test_record({record1});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, ReadSingleRecord(kUserID1, kRecordID1))
      .WillOnce(Return(record1));
  EXPECT_CALL(*mock_biod_storage_, WriteRecord(record_metadata2, _))
      .WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->UpdateRecordMetadata(record_metadata2));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata2, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestUpdateMetadataInvalidRecord) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  // Final metadata with different validation value.
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.validation_val = kFakeValidationValue2;
  Record record1{record_metadata1, kData1, /* valid= */ false};

  std::vector<Record> test_record({record1});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, WriteRecord).Times(0);
  EXPECT_FALSE(record_manager_->UpdateRecordMetadata(record_metadata2));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestUpdateMetadataRecordReadFailed) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  // Final metadata with different validation value.
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.validation_val = kFakeValidationValue2;
  Record record1{record_metadata1, kData1};

  std::vector<Record> test_record({record1});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, ReadSingleRecord(kUserID1, kRecordID1))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*mock_biod_storage_, WriteRecord).Times(0);
  EXPECT_FALSE(record_manager_->UpdateRecordMetadata(record_metadata2));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestUpdateMetadataRecordWriteFailed) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  // Final metadata with different validation value.
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.validation_val = kFakeValidationValue2;
  Record record1{record_metadata1, kData1};

  std::vector<Record> test_record({record1});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, ReadSingleRecord(kUserID1, kRecordID1))
      .WillOnce(Return(record1));
  EXPECT_CALL(*mock_biod_storage_, WriteRecord).WillOnce(Return(false));
  EXPECT_FALSE(record_manager_->UpdateRecordMetadata(record_metadata2));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestUpdateMetadataDifferentUserId) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  // Final metadata with different UserId.
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.user_id = kUserID2;
  Record record1{record_metadata1, kData1};

  std::vector<Record> test_record({record1});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, ReadSingleRecord(kUserID1, kRecordID1))
      .Times(0);
  EXPECT_CALL(*mock_biod_storage_, WriteRecord).Times(0);
  EXPECT_FALSE(record_manager_->UpdateRecordMetadata(record_metadata2));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestDeleteValidRecord) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.validation_val = kFakeValidationValue2;

  std::vector<Record> test_record({Record{record_metadata1, kData1}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID1, kRecordID1))
      .WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->DeleteRecord(kRecordID1));

  // Creating record with the same RecordID should succeed.
  EXPECT_CALL(*mock_biod_storage_, WriteRecord).WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->CreateRecord(
      record_metadata2, std::make_unique<VendorTemplate>()));
  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata2, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestDeleteInvalidRecord) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2 = record_metadata1;
  record_metadata2.validation_val = kFakeValidationValue2;

  std::vector<Record> test_record(
      {Record{record_metadata1, kData1, /* valid= */ false}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);
  EXPECT_TRUE(record_manager_->UserHasInvalidRecords(kUserID1));

  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID1, kRecordID1))
      .WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->DeleteRecord(kRecordID1));
  EXPECT_FALSE(record_manager_->UserHasInvalidRecords(kUserID1));

  // Creating record with the same RecordID should succeed.
  EXPECT_CALL(*mock_biod_storage_, WriteRecord).WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->CreateRecord(
      record_metadata2, std::make_unique<VendorTemplate>()));
  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata2, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestDeleteAllInvalidRecords) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2{kRecordFormatVersion, kRecordID2, kUserID2,
                                  kLabel, kFakeValidationValue2};

  std::vector<Record> test_record1(
      {Record{record_metadata1, kData1, /* valid= */ false}});
  std::vector<Record> test_record2(
      {Record{record_metadata2, kData2, /* valid= */ false}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record1));
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID2))
      .WillOnce(Return(test_record2));

  record_manager_->GetRecordsForUser(kUserID1);
  record_manager_->GetRecordsForUser(kUserID2);

  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID1, kRecordID1))
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID2, kRecordID2))
      .WillOnce(Return(true));

  record_manager_->DeleteInvalidRecords();
  EXPECT_FALSE(record_manager_->UserHasInvalidRecords(kUserID1));
  EXPECT_FALSE(record_manager_->UserHasInvalidRecords(kUserID2));
}

TEST_F(CrosFpRecordManagerTest, TestDeleteOnlyOneRecord) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2{kRecordFormatVersion, kRecordID2, kUserID1,
                                  kLabel, kFakeValidationValue2};

  std::vector<Record> test_record = {Record{record_metadata1, kData1},
                                     Record{record_metadata2, kData2}};
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID1, kRecordID1))
      .WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->DeleteRecord(kRecordID1));

  auto metadata = record_manager_->GetRecordMetadata(kRecordID2);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata2, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestDeleteRecordFailed) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};

  std::vector<Record> test_record({Record{record_metadata1, kData1}});
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID1, kRecordID1))
      .WillOnce(Return(false));
  EXPECT_FALSE(record_manager_->DeleteRecord(kRecordID1));
  auto metadata = record_manager_->GetRecordMetadata(kRecordID1);
  EXPECT_TRUE(metadata);
  EXPECT_EQ(record_metadata1, *metadata);
}

TEST_F(CrosFpRecordManagerTest, TestDeleteAllRecordsSuccess) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2{kRecordFormatVersion, kRecordID2, kUserID1,
                                  kLabel, kFakeValidationValue2};

  std::vector<Record> test_record = {
      Record{record_metadata1, kData1},
      Record{record_metadata2, kData2, /* valid= */ false}};
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID1, kRecordID1))
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID1, kRecordID2))
      .WillOnce(Return(true));
  EXPECT_TRUE(record_manager_->DeleteAllRecords());
  EXPECT_FALSE(record_manager_->UserHasInvalidRecords(kUserID1));
}

TEST_F(CrosFpRecordManagerTest, TestDeleteAllRecordsOneFailed) {
  RecordMetadata record_metadata1{kRecordFormatVersion, kRecordID1, kUserID1,
                                  kLabel, kFakeValidationValue1};
  RecordMetadata record_metadata2{kRecordFormatVersion, kRecordID2, kUserID1,
                                  kLabel, kFakeValidationValue2};

  std::vector<Record> test_record = {
      Record{record_metadata1, kData1},
      Record{record_metadata2, kData2, /* valid= */ false}};
  EXPECT_CALL(*mock_biod_storage_, ReadRecordsForSingleUser(kUserID1))
      .WillOnce(Return(test_record));
  record_manager_->GetRecordsForUser(kUserID1);

  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID1, kRecordID1))
      .WillOnce(Return(false));
  EXPECT_CALL(*mock_biod_storage_, DeleteRecord(kUserID1, kRecordID2))
      .WillOnce(Return(true));
  EXPECT_FALSE(record_manager_->DeleteAllRecords());
  EXPECT_FALSE(record_manager_->UserHasInvalidRecords(kUserID1));
}

}  // namespace
}  // namespace biod
