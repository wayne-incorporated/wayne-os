// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/biod_storage.h"

#include <sys/resource.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <unordered_set>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <testing/gtest/include/gtest/gtest.h>
#include <base/strings/string_util.h>
#include <base/files/important_file_writer.h>
#include <base/json/json_string_value_serializer.h>

namespace biod {

using Record = BiodStorageInterface::Record;
using RecordMetadata = BiodStorageInterface::RecordMetadata;

namespace {

const char kBiometricsManagerName[] = "BiometricsManager";

const base::FilePath kFilePath("TestFile");

const char kRecordId1[] = "00000000_0000_0000_0000_000000000001";
const char kUserId1[] = "0000000000000000000000000000000000000001";
const char kLabel1[] = "record1";
const std::vector<uint8_t> kValidationVal1 = {0x00, 0x01};
const char kData1[] = "Hello, world1!";

const char kRecordId2[] = "00000000_0000_0000_0000_000000000002";
const char kUserId2[] = "0000000000000000000000000000000000000002";
const char kLabel2[] = "record2";
const std::vector<uint8_t> kValidationVal2 = {0x00, 0x02};
const char kData2[] = "Hello, world2!";

const char kRecordId3[] = "00000000_0000_0000_0000_000000000003";
const char kLabel3[] = "record3";
const std::vector<uint8_t> kValidationVal3 = {0x00, 0x03};
const char kData3[] = "Hello, world3!";

constexpr int kPermissions600 =
    base::FILE_PERMISSION_READ_BY_USER | base::FILE_PERMISSION_WRITE_BY_USER;
constexpr int kPermissions700 = base::FILE_PERMISSION_USER_MASK;

const char kInvalidUTF8[] = "\xed\xa0\x80\xed\xbf\xbf";

constexpr int kFpc1145TemplateSizeBytes = 47616;
constexpr int kFpc1025TemplateSizeBytes = 5156;
constexpr int kElan80TemplateSizeBytes = 41024;
constexpr int kElan515TemplateSizeBytes = 67064;

/**
 * "Max locked memory" value from reading /proc/<PID>/limits on DUT
 *
 * This matches the default value in the kernel:
 * https://chromium.googlesource.com/chromiumos/third_party/kernel/+/a5746cdefaed35de0a85ede48a47e9a340a6f7e6/include/uapi/linux/resource.h#72
 *
 * The default can be overridden in /etc/security/limits.conf:
 * https://access.redhat.com/solutions/61334
 *
 * or in the upstart script http://upstart.ubuntu.com/cookbook/#limit:
 *
 * limit memlock <soft> <hard>
 */
constexpr int kRlimitMemlockBytes = 65536;

struct MemlockTestParams {
  int rlimit_bytes;
  int template_size_bytes;
};

}  // namespace

class BiodStorageBaseTest : public ::testing::Test {
 public:
  BiodStorageBaseTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    root_path_ = temp_dir_.GetPath().AppendASCII("biod_storage_unittest_root");
    biod_storage_ = std::make_unique<BiodStorage>(kBiometricsManagerName);
    // Since there is no session manager, allow accesses by default.
    biod_storage_->set_allow_access(true);
    biod_storage_->SetRootPathForTesting(root_path_);
  }
  BiodStorageBaseTest(const BiodStorageBaseTest&) = delete;
  BiodStorageBaseTest& operator=(const BiodStorageBaseTest&) = delete;

  ~BiodStorageBaseTest() override {
    EXPECT_TRUE(base::DeletePathRecursively(temp_dir_.GetPath()));
  }

  base::Value::Dict CreateRecordDictionary(
      const std::vector<uint8_t>& validation_val) {
    base::Value::Dict record_dictionary;
    std::string validation_value_str(validation_val.begin(),
                                     validation_val.end());
    base::Base64Encode(validation_value_str, &validation_value_str);
    record_dictionary.Set("match_validation_value", validation_value_str);
    return record_dictionary;
  }

 protected:
  base::ScopedTempDir temp_dir_;
  base::FilePath root_path_;
  std::unique_ptr<BiodStorage> biod_storage_;
};

TEST_F(BiodStorageBaseTest, WriteAndReadRecords) {
  const std::vector<uint8_t> kEmpty;
  const std::vector<Record> kRecords(
      {{{kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
        kData1},
       {{kRecordFormatVersion, kRecordId2, kUserId2, kLabel2, kValidationVal2},
        kData2},
       {{kRecordFormatVersion, kRecordId3, kUserId2, kLabel3, kValidationVal3},
        kData3}});

  // Write the record.
  for (auto const& record : kRecords) {
    EXPECT_TRUE(
        biod_storage_->WriteRecord(record.metadata, base::Value(record.data)));
  }

  // Read the record.
  std::unordered_set<std::string> user_ids({kUserId1, kUserId2});
  auto read_result = biod_storage_->ReadRecords(user_ids);

  EXPECT_EQ(read_result.size(), kRecords.size());

  // Check if all records returned by ReadRecords have "valid" flag set.
  EXPECT_TRUE(std::all_of(read_result.begin(), read_result.end(),
                          [](auto const& record) { return record.valid; }));

  EXPECT_TRUE(std::is_permutation(kRecords.begin(), kRecords.end(),
                                  read_result.begin()));
}

TEST_F(BiodStorageBaseTest, WriteAndReadSingleRecord) {
  const std::vector<Record> kRecords(
      {{{kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
        kData1},
       {{kRecordFormatVersion, kRecordId2, kUserId2, kLabel2, kValidationVal2},
        kData2},
       {{kRecordFormatVersion, kRecordId3, kUserId2, kLabel3, kValidationVal3},
        kData3}});

  // Write the record.
  for (auto const& record : kRecords) {
    EXPECT_TRUE(
        biod_storage_->WriteRecord(record.metadata, base::Value(record.data)));
  }

  // Read the records.
  EXPECT_EQ(kRecords[0],
            *biod_storage_->ReadSingleRecord(kUserId1, kRecordId1));
  EXPECT_EQ(kRecords[1],
            *biod_storage_->ReadSingleRecord(kUserId2, kRecordId2));
  EXPECT_EQ(kRecords[2],
            *biod_storage_->ReadSingleRecord(kUserId2, kRecordId3));
}

TEST_F(BiodStorageBaseTest, ReadSingleRecord) {
  const std::vector<Record> kRecords(
      {{{kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
        kData1},
       {{kRecordFormatVersion, kRecordId2, kUserId2, kLabel2, kValidationVal2},
        kData2}});

  // Write the record.
  for (auto const& record : kRecords) {
    EXPECT_TRUE(
        biod_storage_->WriteRecord(record.metadata, base::Value(record.data)));
  }

  // Check if ReadSingleRecord returns empty std::optional on RecordId,
  // UserId mismatch.
  EXPECT_FALSE(biod_storage_->ReadSingleRecord(kUserId1, kRecordId2));
  EXPECT_FALSE(biod_storage_->ReadSingleRecord(kUserId2, kRecordId1));
}

TEST_F(BiodStorageBaseTest, WriteRecord_InvalidAbsolutePath) {
  Record record = {{kRecordFormatVersion, kRecordId1, "/absolutepath", kLabel1,
                    kValidationVal1},
                   kData1};

  EXPECT_FALSE(
      biod_storage_->WriteRecord(record.metadata, base::Value(record.data)));
}

TEST_F(BiodStorageBaseTest, WriteRecord_RecordIdNotUTF8) {
  EXPECT_FALSE(base::IsStringUTF8(kInvalidUTF8));

  Record record = {
      {kRecordFormatVersion, kInvalidUTF8, kUserId1, kLabel1, kValidationVal1},
      kData1};

  EXPECT_FALSE(record.metadata.IsValidUTF8());
  EXPECT_FALSE(
      biod_storage_->WriteRecord(record.metadata, base::Value(record.data)));
}

TEST_F(BiodStorageBaseTest, WriteRecord_UserIdNotUTF8) {
  EXPECT_FALSE(base::IsStringUTF8(kInvalidUTF8));

  Record record = {{kRecordFormatVersion, kRecordId1, kInvalidUTF8, kLabel1,
                    kValidationVal1},
                   kData1};

  EXPECT_FALSE(record.metadata.IsValidUTF8());
  EXPECT_FALSE(
      biod_storage_->WriteRecord(record.metadata, base::Value(record.data)));
}

TEST_F(BiodStorageBaseTest, WriteRecord_LabelNotUTF8) {
  EXPECT_FALSE(base::IsStringUTF8(kInvalidUTF8));

  Record record = {{kRecordFormatVersion, kRecordId1, kUserId1, kInvalidUTF8,
                    kValidationVal1},
                   kData1};

  EXPECT_FALSE(record.metadata.IsValidUTF8());
  EXPECT_FALSE(
      biod_storage_->WriteRecord(record.metadata, base::Value(record.data)));
}

TEST_F(BiodStorageBaseTest, WriteRecord_CheckUmask) {
  Record record = {
      {kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
      kData1};

  const base::FilePath kRecordStorageFilename =
      root_path_.Append("biod")
          .Append(record.metadata.user_id)
          .Append(kBiometricsManagerName)
          .Append("Record" + record.metadata.record_id);

  ASSERT_FALSE(base::PathExists(kRecordStorageFilename));
  ASSERT_FALSE(base::PathExists(kRecordStorageFilename.DirName()));

  EXPECT_TRUE(
      biod_storage_->WriteRecord(record.metadata, base::Value(record.data)));

  // Check permissions of directory
  int actual_permissions;
  EXPECT_TRUE(base::GetPosixFilePermissions(kRecordStorageFilename.DirName(),
                                            &actual_permissions));
  EXPECT_EQ(kPermissions700, actual_permissions);

  // Check permissions of record
  EXPECT_TRUE(base::GetPosixFilePermissions(kRecordStorageFilename,
                                            &actual_permissions));
  EXPECT_EQ(kPermissions600, actual_permissions);
}

TEST_F(BiodStorageBaseTest, DeleteRecord) {
  const std::vector<uint8_t> kEmpty;
  const Record kRecord = {
      {kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
      kData1};

  // Delete a non-existent record.
  EXPECT_TRUE(biod_storage_->DeleteRecord(kUserId1, kRecordId1));

  EXPECT_TRUE(
      biod_storage_->WriteRecord(kRecord.metadata, base::Value(kRecord.data)));

  // Check this record is properly written.
  std::unordered_set<std::string> user_ids({kUserId1});
  auto read_result = biod_storage_->ReadRecords(user_ids);
  EXPECT_EQ(read_result.size(), 1);
  const auto& record = read_result[0];
  EXPECT_TRUE(record.valid);
  EXPECT_EQ(record, kRecord);

  EXPECT_TRUE(biod_storage_->DeleteRecord(kUserId1, kRecordId1));

  // Check this record is properly deleted.
  read_result = biod_storage_->ReadRecords(user_ids);
  EXPECT_TRUE(read_result.empty());
}

TEST_F(BiodStorageBaseTest, GenerateNewRecordId) {
  // Check the two record ids are different.
  std::string record_id1(BiodStorage::GenerateNewRecordId());
  std::string record_id2(BiodStorage::GenerateNewRecordId());
  EXPECT_NE(record_id1, record_id2);
}

TEST_F(BiodStorageBaseTest, TestEqualOperator) {
  Record record = {
      {kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
      kData1};
  Record record_eq = {
      {kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
      kData1};
  Record record_eq2 = {
      {kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
      kData1,
      /* valid= */ false};
  Record record_ne = {
      {kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal2},
      kData1};

  EXPECT_EQ(record, record_eq);
  EXPECT_EQ(record, record_eq2);
  EXPECT_NE(record, record_ne);
}

TEST_F(BiodStorageBaseTest, TestReadValidationValueFromRecord) {
  auto record_dictionary = CreateRecordDictionary(kValidationVal1);
  auto ret = biod_storage_->ReadValidationValueFromRecord(record_dictionary,
                                                          kFilePath);
  EXPECT_TRUE(ret != nullptr);
  EXPECT_EQ(*ret, kValidationVal1);
}

/**
 * Tests for invalid records. In general records will be correctly formatted
 * since we follow a specific format when writing them, but we should be able
 * to handle invalid records from bugs, disk corruption, etc.
 */
class BiodStorageInvalidRecordTest : public ::testing::Test {
 public:
  BiodStorageInvalidRecordTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    root_path_ = temp_dir_.GetPath().AppendASCII(
        "biod_storage_invalid_record_test_root");
    biod_storage_ = std::make_unique<BiodStorage>(kBiometricsManagerName);
    // Since there is no session manager, allow accesses by default.
    biod_storage_->set_allow_access(true);
    biod_storage_->SetRootPathForTesting(root_path_);

    Record record = {
        {kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
        kData1};
    record_name_ = biod_storage_->GetRecordFilename(record.metadata);
    EXPECT_FALSE(record_name_.empty());
    EXPECT_TRUE(base::CreateDirectory(record_name_.DirName()));
  }

 protected:
  base::ScopedTempDir temp_dir_;
  base::FilePath root_path_;
  base::FilePath record_name_;
  std::unique_ptr<BiodStorageInterface> biod_storage_;
};

TEST_F(BiodStorageInvalidRecordTest, InvalidJSON) {
  EXPECT_TRUE(base::ImportantFileWriter::WriteFileAtomically(record_name_,
                                                             "this is not "
                                                             "JSON"));
  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_FALSE(read_result[0].valid);
}

TEST_F(BiodStorageInvalidRecordTest, MissingFormatVersion) {
  auto record = R"({
    "record_id": "00000000_0000_0000_0000_000000000001",
    "label": "some_label",
    "data": "some_data",
    "match_validation_value": "4567"
  })";

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));

  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_FALSE(read_result[0].valid);
}

TEST_F(BiodStorageInvalidRecordTest, InvalidFormatVersion) {
  auto record = R"({
    "record_id": "00000000_0000_0000_0000_000000000001",
    "label": "some_label",
    "data": "some_data",
    "match_validation_value": "4567",
    "version": -1
  })";

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));

  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_FALSE(read_result[0].valid);
}

TEST_F(BiodStorageInvalidRecordTest, MissingRecordId) {
  auto record = R"({
    "label": "some_label",
    "data": "some_data",
    "match_validation_value": "4567",
    "version": 2
  })";

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));

  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_FALSE(read_result[0].valid);
}

TEST_F(BiodStorageInvalidRecordTest, MissingRecordLabel) {
  auto record = R"({
    "record_id": "00000000_0000_0000_0000_000000000001",
    "data": "some_data",
    "match_validation_value": "4567",
    "version": 2
  })";

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));

  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_FALSE(read_result[0].valid);
}

TEST_F(BiodStorageInvalidRecordTest, MissingRecordData) {
  auto record = R"({
    "record_id": "00000000_0000_0000_0000_000000000001",
    "label": "some_label",
    "match_validation_value": "4567",
    "version": 2
  })";

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));

  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_FALSE(read_result[0].valid);
}

TEST_F(BiodStorageInvalidRecordTest, MissingValidationValue) {
  auto record = R"({
    "record_id": "00000000_0000_0000_0000_000000000001",
    "label": "some_label",
    "data": "some_data",
    "version": 2
  })";

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));

  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_FALSE(read_result[0].valid);
}

TEST_F(BiodStorageInvalidRecordTest, ValidationValueNotBase64) {
  auto record = R"({
    "record_id": "00000000_0000_0000_0000_000000000001",
    "label": "some_label",
    "data": "some_data",
    "match_validation_value": "not valid base64",
    "version": 2
  })";

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));

  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_FALSE(read_result[0].valid);
}

TEST_F(BiodStorageInvalidRecordTest, VersionOneWithoutValidationValueIsValid) {
  auto record = R"({
    "record_id": "00000000_0000_0000_0000_000000000001",
    "label": "some_label",
    "data": "some_data",
    "version": 1
  })";

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));

  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_TRUE(read_result[0].valid);
  EXPECT_TRUE(read_result[0].metadata.validation_val.empty());
  EXPECT_EQ(read_result[0].metadata.record_format_version,
            kRecordFormatVersionNoValidationValue);
}

TEST_F(BiodStorageInvalidRecordTest, RecordIdMismatch) {
  auto record = R"({
    "record_id": "5678",
    "label": "some_label",
    "data": "some_data",
    "match_validation_value": "4567",
    "version": 2
  })";

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));

  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_FALSE(read_result[0].valid);
}

/**
 * Tests to make sure we do not crash due to hitting the RLIMIT_MEMLOCK limit.
 * See http://b/181281782, http://b/175158241, and http://b/173655013.
 */
class BiodStorageMemlockTest
    : public testing::TestWithParam<MemlockTestParams> {
 public:
  BiodStorageMemlockTest() : params_(GetParam()) {
    CHECK(temp_dir_.CreateUniqueTempDir());
    root_path_ =
        temp_dir_.GetPath().AppendASCII("biod_storage_memlock_test_root");
    biod_storage_ = std::make_unique<BiodStorage>(kBiometricsManagerName);
    // Since there is no session manager, allow accesses by default.
    biod_storage_->set_allow_access(true);
    biod_storage_->SetRootPathForTesting(root_path_);

    Record record = {
        {kRecordFormatVersion, kRecordId1, kUserId1, kLabel1, kValidationVal1},
        kData1};
    record_name_ = biod_storage_->GetRecordFilename(record.metadata);
    EXPECT_FALSE(record_name_.empty());
    EXPECT_TRUE(base::CreateDirectory(record_name_.DirName()));

    struct rlimit limit;

    EXPECT_EQ(getrlimit(RLIMIT_MEMLOCK, &limit), 0);
    orig_limit_ = limit;

    limit.rlim_cur = params_.rlimit_bytes;
    EXPECT_LT(limit.rlim_cur, limit.rlim_max);
    EXPECT_EQ(setrlimit(RLIMIT_MEMLOCK, &limit), 0);

    EXPECT_EQ(getrlimit(RLIMIT_MEMLOCK, &limit), 0);
    EXPECT_EQ(limit.rlim_cur, params_.rlimit_bytes);
  }

  ~BiodStorageMemlockTest() override {
    // Restore original limits.
    EXPECT_EQ(setrlimit(RLIMIT_MEMLOCK, &orig_limit_), 0);
  }

 protected:
  const MemlockTestParams params_;
  base::ScopedTempDir temp_dir_;
  base::FilePath root_path_;
  base::FilePath record_name_;
  std::unique_ptr<BiodStorageInterface> biod_storage_;
  struct rlimit orig_limit_;
};

TEST_P(BiodStorageMemlockTest, ReadReadRecords) {
  base::Value::Dict record_value;
  record_value.Set("record_id", kRecordId1);
  record_value.Set("label", "some_label");
  record_value.Set("match_validation_value", "4567");
  record_value.Set("version", 2);
  std::vector<uint8_t> data(params_.template_size_bytes, 'a');
  record_value.Set("data", base::Base64Encode(data));

  std::string record;
  JSONStringValueSerializer json_serializer(&record);
  EXPECT_TRUE(json_serializer.Serialize(record_value));

  EXPECT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(record_name_, record));
  auto read_result = biod_storage_->ReadRecordsForSingleUser(kUserId1);
  EXPECT_EQ(read_result.size(), 1);
  EXPECT_TRUE(read_result[0].valid);
}

INSTANTIATE_TEST_SUITE_P(
    BiodStorageMemlock,
    BiodStorageMemlockTest,
    testing::Values(
        MemlockTestParams{
            .rlimit_bytes = kRlimitMemlockBytes,
            .template_size_bytes = kElan515TemplateSizeBytes,
        },
        MemlockTestParams{
            .rlimit_bytes = kRlimitMemlockBytes,
            .template_size_bytes = kElan80TemplateSizeBytes,
        },
        MemlockTestParams{
            .rlimit_bytes = kRlimitMemlockBytes,
            .template_size_bytes = kFpc1145TemplateSizeBytes,
        },
        MemlockTestParams{
            .rlimit_bytes = kRlimitMemlockBytes,
            .template_size_bytes = kFpc1025TemplateSizeBytes,
        }));

}  // namespace biod
