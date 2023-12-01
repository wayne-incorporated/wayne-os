// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/filesystem/file_handler.h"
#include "oobe_config/filesystem/file_handler_for_testing.h"

#include <unistd.h>
#include <optional>

#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <gtest/gtest.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/notreached.h>

namespace oobe_config {
namespace {

constexpr char kFileData[] =
    "5468696e6b20676f6f642e20537065616b20676f6f642e20446f20676f6f642e0d0a";

}  // namespace

class FileHandlerTest : public ::testing::Test {
 protected:
  // File and folder constants are duplicated for tests and production code
  // because checking that the correct path is used is part of the test.
  static constexpr char kExpectedRestorePath[] = "var/lib/oobe_config_restore";
  static constexpr char kExpectedSavePath[] = "var/lib/oobe_config_save";
  static constexpr char kExpectedPreservePath[] =
      "mnt/stateful_partition/unencrypted/preserve";
  static constexpr char kExpectedOpensslEncryptedRollbackData[] =
      "mnt/stateful_partition/unencrypted/preserve/rollback_data";
  static constexpr char kExpectedTpmEncryptedRollbackData[] =
      "mnt/stateful_partition/unencrypted/preserve/rollback_data_tpm";
  static constexpr char kExpectedDecryptedRollbackData[] =
      "var/lib/oobe_config_restore/rollback_data";
  static constexpr char kExpectedRollbackSaveTriggerFlag[] =
      "mnt/stateful_partition/.save_rollback_data";
  static constexpr char kExpectedDataSavedFlag[] =
      "var/lib/oobe_config_save/.data_saved";
  static constexpr char kExpectedOobeCompletedFlag[] =
      "home/chronos/.oobe_completed";
  static constexpr char kExpectedMetricsReportingEnabledFlag[] =
      "home/chronos/Consent To Send Stats";
  static constexpr char kExpectedPstoreData[] =
      "var/lib/oobe_config_save/data_for_pstore";
  static constexpr char kExpectedRamoopsPath[] = "sys/fs/pstore";
  static constexpr char kExpectedRamoopsData[] = "sys/fs/pstore/pmsg-ramoops-0";
  static constexpr char kExpectedRollbackMetricsData[] =
      "mnt/stateful_partition/unencrypted/preserve/"
      "enterprise-rollback-metrics-data";

  void VerifyHasFunction(const std::string& path,
                         base::RepeatingCallback<bool()> has_path) {
    base::FilePath rooted_path = RootedPath(path);

    ASSERT_FALSE(has_path.Run());
    ASSERT_TRUE(base::CreateDirectory(rooted_path));
    ASSERT_TRUE(has_path.Run());
    ASSERT_TRUE(base::DeletePathRecursively(rooted_path));
  }

  void VerifyCreateFunction(const std::string& path,
                            base::RepeatingCallback<bool()> create_path) {
    base::FilePath rooted_path = RootedPath(path);

    ASSERT_FALSE(base::PathExists(rooted_path));
    ASSERT_TRUE(create_path.Run());
    ASSERT_TRUE(base::PathExists(rooted_path));
    ASSERT_TRUE(base::DeletePathRecursively(rooted_path));
  }

  void VerifyReadFunction(
      const std::string& path,
      base::RepeatingCallback<bool(std::string*)> read_file) {
    base::FilePath rooted_path = RootedPath(path);

    ASSERT_FALSE(base::PathExists(rooted_path));
    if (!base::PathExists(rooted_path.DirName())) {
      ASSERT_TRUE(base::CreateDirectory(rooted_path.DirName()));
    }
    std::string read_data;
    ASSERT_FALSE(read_file.Run(&read_data));
    ASSERT_EQ(read_data, std::string());
    ASSERT_TRUE(base::WriteFile(rooted_path, kFileData));
    ASSERT_TRUE(read_file.Run(&read_data));
    ASSERT_EQ(read_data, kFileData);
    ASSERT_TRUE(base::DeleteFile(rooted_path));
  }

  void VerifyWriteFunction(
      const std::string& path,
      base::RepeatingCallback<bool(const std::string&)> write_file) {
    base::FilePath rooted_path = RootedPath(path);

    ASSERT_FALSE(base::PathExists(rooted_path));
    if (!base::PathExists(rooted_path.DirName())) {
      ASSERT_TRUE(base::CreateDirectory(rooted_path.DirName()));
    }
    std::string read_data;
    ASSERT_TRUE(write_file.Run(kFileData));
    ASSERT_TRUE(base::ReadFileToString(rooted_path, &read_data));
    ASSERT_EQ(read_data, kFileData);
    ASSERT_TRUE(base::DeleteFile(rooted_path));
  }

  void VerifyRemoveFunction(const std::string& path,
                            base::RepeatingCallback<bool()> remove_file) {
    base::FilePath rooted_path = RootedPath(path);

    // Removing non existent file returns true.
    ASSERT_FALSE(base::PathExists(rooted_path));
    ASSERT_TRUE(remove_file.Run());
    ASSERT_FALSE(base::PathExists(rooted_path));

    if (!base::PathExists(rooted_path.DirName())) {
      ASSERT_TRUE(base::CreateDirectory(rooted_path.DirName()));
    }
    ASSERT_TRUE(base::WriteFile(rooted_path, std::string()));
    ASSERT_TRUE(base::PathExists(rooted_path));
    ASSERT_TRUE(remove_file.Run());
    ASSERT_FALSE(base::PathExists(rooted_path));
  }

  void VerifyCreateFlagFunction(const std::string& path,
                                base::RepeatingCallback<bool()> create_flag) {
    base::FilePath rooted_path = RootedPath(path);

    ASSERT_FALSE(base::PathExists(rooted_path));
    if (!base::PathExists(rooted_path.DirName())) {
      ASSERT_TRUE(base::CreateDirectory(rooted_path.DirName()));
    }
    std::string read_data;
    ASSERT_TRUE(create_flag.Run());
    ASSERT_TRUE(base::ReadFileToString(rooted_path, &read_data));
    ASSERT_EQ(read_data, std::string());
    ASSERT_TRUE(base::DeleteFile(rooted_path));
  }

  base::FilePath RootedPath(const std::string& path) {
    return file_handler_.GetFullPath(path);
  }

  FileHandlerForTesting file_handler_;
};

TEST_F(FileHandlerTest, HasRestorePath) {
  VerifyHasFunction(FileHandlerTest::kExpectedRestorePath,
                    base::BindRepeating(&FileHandler::HasRestorePath,
                                        base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, RemoveRestorePath) {
  VerifyRemoveFunction(FileHandlerTest::kExpectedRestorePath,
                       base::BindRepeating(&FileHandler::RemoveRestorePath,
                                           base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, HasOpensslEncryptedRollbackData) {
  VerifyHasFunction(
      FileHandlerTest::kExpectedOpensslEncryptedRollbackData,
      base::BindRepeating(&FileHandler::HasOpensslEncryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, ReadOpensslEncryptedRollbackData) {
  VerifyReadFunction(
      FileHandlerTest::kExpectedOpensslEncryptedRollbackData,
      base::BindRepeating(&FileHandler::ReadOpensslEncryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, WriteOpensslEncryptedRollbackData) {
  VerifyWriteFunction(
      FileHandlerTest::kExpectedOpensslEncryptedRollbackData,
      base::BindRepeating(&FileHandler::WriteOpensslEncryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, RemoveOpensslEncryptedRollbackData) {
  VerifyRemoveFunction(
      FileHandlerTest::kExpectedOpensslEncryptedRollbackData,
      base::BindRepeating(&FileHandler::RemoveOpensslEncryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, HasTpmEncryptedRollbackData) {
  VerifyHasFunction(
      FileHandlerTest::kExpectedTpmEncryptedRollbackData,
      base::BindRepeating(&FileHandler::HasTpmEncryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, ReadTpmEncryptedRollbackData) {
  VerifyReadFunction(
      FileHandlerTest::kExpectedTpmEncryptedRollbackData,
      base::BindRepeating(&FileHandler::ReadTpmEncryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, WriteTpmEncryptedRollbackData) {
  VerifyWriteFunction(
      FileHandlerTest::kExpectedTpmEncryptedRollbackData,
      base::BindRepeating(&FileHandler::WriteTpmEncryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, RemoveTpmEncryptedRollbackData) {
  VerifyRemoveFunction(
      FileHandlerTest::kExpectedTpmEncryptedRollbackData,
      base::BindRepeating(&FileHandler::RemoveTpmEncryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, HasDecryptedRollbackData) {
  VerifyHasFunction(FileHandlerTest::kExpectedDecryptedRollbackData,
                    base::BindRepeating(&FileHandler::HasDecryptedRollbackData,
                                        base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, ReadDecryptedRollbackData) {
  VerifyReadFunction(
      FileHandlerTest::kExpectedDecryptedRollbackData,
      base::BindRepeating(&FileHandler::ReadDecryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, WriteDecryptedRollbackData) {
  VerifyWriteFunction(
      FileHandlerTest::kExpectedDecryptedRollbackData,
      base::BindRepeating(&FileHandler::WriteDecryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, RemoveDecryptedRollbackData) {
  VerifyRemoveFunction(
      FileHandlerTest::kExpectedDecryptedRollbackData,
      base::BindRepeating(&FileHandler::RemoveDecryptedRollbackData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, HasRollbackSaveTriggerFlag) {
  VerifyHasFunction(
      FileHandlerTest::kExpectedRollbackSaveTriggerFlag,
      base::BindRepeating(&FileHandler::HasRollbackSaveTriggerFlag,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, RemoveRollbackSaveTriggerFlag) {
  VerifyRemoveFunction(
      FileHandlerTest::kExpectedRollbackSaveTriggerFlag,
      base::BindRepeating(&FileHandler::RemoveRollbackSaveTriggerFlag,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, CreateDataSavedFlag) {
  VerifyCreateFlagFunction(
      FileHandlerTest::kExpectedDataSavedFlag,
      base::BindRepeating(&FileHandler::CreateDataSavedFlag,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, HasOobeCompletedFlag) {
  VerifyHasFunction(FileHandlerTest::kExpectedOobeCompletedFlag,
                    base::BindRepeating(&FileHandler::HasOobeCompletedFlag,
                                        base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, HasMetricsReportingEnabledFlag) {
  VerifyHasFunction(
      FileHandlerTest::kExpectedMetricsReportingEnabledFlag,
      base::BindRepeating(&FileHandler::HasMetricsReportingEnabledFlag,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, WritePstoreData) {
  VerifyWriteFunction(FileHandlerTest::kExpectedPstoreData,
                      base::BindRepeating(&FileHandler::WritePstoreData,
                                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, RamoopsFileEnumeratorEmptyFolder) {
  const base::FilePath path = RootedPath(FileHandlerTest::kExpectedRamoopsPath);

  ASSERT_FALSE(base::PathExists(path));
  ASSERT_TRUE(base::CreateDirectory(path));

  // Empty folder should give an enumerator, but no files to enumerate over.
  base::FileEnumerator enumerator_empty = file_handler_.RamoopsFileEnumerator();
  for (auto file = enumerator_empty.Next(); !file.empty();
       file = enumerator_empty.Next()) {
    NOTREACHED();
  }
}

TEST_F(FileHandlerTest, RamoopsFileEnumeratorTwoFiles) {
  const base::FilePath path = RootedPath(FileHandlerTest::kExpectedRamoopsPath);

  ASSERT_FALSE(base::PathExists(path));
  ASSERT_TRUE(base::CreateDirectory(path));

  ASSERT_TRUE(base::WriteFile(path.Append("file1"), kFileData));
  ASSERT_TRUE(base::WriteFile(path.Append("file2"), kFileData));
  base::FileEnumerator enumerator_files = file_handler_.RamoopsFileEnumerator();
  for (auto file = enumerator_files.Next(); !file.empty();
       file = enumerator_files.Next()) {
    std::string read_data;
    ASSERT_TRUE(base::ReadFileToString(file, &read_data));
    ASSERT_EQ(read_data, kFileData);
  }
  ASSERT_TRUE(base::DeletePathRecursively(path));
}

TEST_F(FileHandlerTest, CreateRestorePath) {
  VerifyCreateFunction(
      FileHandlerTest::kExpectedRestorePath,
      base::BindRepeating(&FileHandlerForTesting::CreateRestorePath,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, CreateSavePath) {
  VerifyCreateFunction(
      FileHandlerTest::kExpectedSavePath,
      base::BindRepeating(&FileHandlerForTesting::CreateSavePath,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, CreatePreservePath) {
  VerifyCreateFunction(
      FileHandlerTest::kExpectedPreservePath,
      base::BindRepeating(&FileHandlerForTesting::CreatePreservePath,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, HasDataSavedFlag) {
  VerifyHasFunction(
      FileHandlerTest::kExpectedDataSavedFlag,
      base::BindRepeating(&FileHandlerForTesting::HasDataSavedFlag,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, ReadPstoreData) {
  VerifyReadFunction(FileHandlerTest::kExpectedPstoreData,
                     base::BindRepeating(&FileHandlerForTesting::ReadPstoreData,
                                         base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, HasRollbackMetricsData) {
  VerifyHasFunction(FileHandlerTest::kExpectedRollbackMetricsData,
                    base::BindRepeating(&FileHandler::HasRollbackMetricsData,
                                        base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, ReadRollbackMetricsData) {
  VerifyReadFunction(FileHandlerTest::kExpectedRollbackMetricsData,
                     base::BindRepeating(&FileHandler::ReadRollbackMetricsData,
                                         base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, WriteRollbackMetricsData) {
  VerifyWriteFunction(
      FileHandlerTest::kExpectedRollbackMetricsData,
      base::BindRepeating(&FileHandler::WriteRollbackMetricsData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, RemoveRollbackMetricsData) {
  VerifyRemoveFunction(
      FileHandlerTest::kExpectedRollbackMetricsData,
      base::BindRepeating(&FileHandler::RemoveRollbackMetricsData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, CreateRamoopsPath) {
  VerifyCreateFunction(
      FileHandlerTest::kExpectedRamoopsPath,
      base::BindRepeating(&FileHandlerForTesting::CreateRamoopsPath,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, WriteRamoopsData) {
  VerifyWriteFunction(
      FileHandlerTest::kExpectedRamoopsData,
      base::BindRepeating(&FileHandlerForTesting::WriteRamoopsData,
                          base::Unretained(&file_handler_)));
}

TEST_F(FileHandlerTest, RemoveRamoops) {
  VerifyRemoveFunction(
      FileHandlerTest::kExpectedRamoopsData,
      base::BindRepeating(&FileHandlerForTesting::RemoveRamoopsData,
                          base::Unretained(&file_handler_)));
}

}  // namespace oobe_config
