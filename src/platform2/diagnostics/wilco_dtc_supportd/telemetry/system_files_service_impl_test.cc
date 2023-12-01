// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/system_files_service_impl.h"

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <tuple>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "diagnostics/wilco_dtc_supportd/telemetry/system_files_service.h"
#include "diagnostics/wilco_dtc_supportd/utils/file_test_utils.h"

using testing::AnyOf;
using testing::StrEq;

namespace diagnostics {
namespace wilco {
namespace {

std::string FakeFileContents() {
  constexpr char kFakeFileContents[] = "test1 \0 Œ test2/test3 \0 Ö";

  return std::string(std::begin(kFakeFileContents),
                     std::end(kFakeFileContents));
}
// Tests for SystemFilesService
class SystemFilesServiceTest : public testing::Test {
 public:
  SystemFilesServiceTest() = default;
  SystemFilesServiceTest(const SystemFilesServiceTest&) = delete;
  SystemFilesServiceTest& operator=(const SystemFilesServiceTest&) = delete;

  ~SystemFilesServiceTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    system_files_service_.set_root_dir_for_testing(temp_dir_.GetPath());
  }

 protected:
  base::ScopedTempDir temp_dir_;
  SystemFilesServiceImpl system_files_service_;
};

// Test that GetFileDump() returns false when the file doesn't exist.
TEST_F(SystemFilesServiceTest, NonExistingFile) {
  auto file_dump =
      system_files_service_.GetFileDump(SystemFilesService::File::kProcMeminfo);
  EXPECT_FALSE(file_dump);
}

// Test that GetFileDump() returns the requested file data when the file
// exists.
TEST_F(SystemFilesServiceTest, SimpleFile) {
  const base::FilePath kTestPath("proc/meminfo");

  base::FilePath abs_file = temp_dir_.GetPath().Append(kTestPath);

  ASSERT_TRUE(WriteFileAndCreateParentDirs(abs_file, FakeFileContents()));

  const auto file_dump =
      system_files_service_.GetFileDump(SystemFilesService::File::kProcMeminfo);

  EXPECT_TRUE(file_dump);
  EXPECT_EQ(file_dump.value().path, abs_file);
  EXPECT_EQ(file_dump.value().canonical_path, abs_file);
  EXPECT_EQ(file_dump.value().contents, FakeFileContents());
}

// Test that GetFileDump() returns the requested file data when the file
// exists and is a symlink.
TEST_F(SystemFilesServiceTest, Symlink) {
  const base::FilePath kTestPath("proc/meminfo");
  const base::FilePath kTestLinkPath("proc/loadavg");

  base::FilePath abs_file = temp_dir_.GetPath().Append(kTestPath);
  base::FilePath abs_link = temp_dir_.GetPath().Append(kTestLinkPath);

  ASSERT_TRUE(
      WriteFileAndCreateSymbolicLink(abs_file, FakeFileContents(), abs_link));

  const auto file_dump =
      system_files_service_.GetFileDump(SystemFilesService::File::kProcLoadavg);

  EXPECT_TRUE(file_dump);
  EXPECT_EQ(file_dump.value().path, abs_link);
  EXPECT_EQ(file_dump.value().canonical_path, abs_file);
  EXPECT_EQ(file_dump.value().contents, FakeFileContents());
}

// Test that GetVpdField() returns false when the VPD field doesn't exist.
TEST_F(SystemFilesServiceTest, NoVpdField) {
  EXPECT_FALSE(system_files_service_.GetVpdField(
      SystemFilesService::VpdField::kSerialNumber));
}

// Test that GetVpdField() returns false when the VPD field contains non ASCII
// symbols.
TEST_F(SystemFilesServiceTest, NonASCIIVpdField) {
  constexpr char kNonASCIIContent[] = "test1 Œ test2 不 test3";

  base::FilePath abs_file =
      temp_dir_.GetPath().Append("run/wilco_dtc/vpd_fields/system_id");

  ASSERT_TRUE(WriteFileAndCreateParentDirs(abs_file, kNonASCIIContent));

  EXPECT_FALSE(system_files_service_.GetVpdField(
      SystemFilesService::VpdField::kSystemId));
}

// Test that GetVpdField() returns false when the VPD field is empty.
TEST_F(SystemFilesServiceTest, EmptyVpdField) {
  base::FilePath abs_file =
      temp_dir_.GetPath().Append("run/wilco_dtc/vpd_fields/model_name");

  ASSERT_TRUE(WriteFileAndCreateParentDirs(abs_file, ""));

  EXPECT_FALSE(system_files_service_.GetVpdField(
      SystemFilesService::VpdField::kModelName));
}

// Test that GetVpdField() returns the requested trimmed VPD field when the VPD
// field exists.
TEST_F(SystemFilesServiceTest, TrimmedVpdField) {
  base::FilePath abs_file =
      temp_dir_.GetPath().Append("run/wilco_dtc/vpd_fields/ActivateDate");

  ASSERT_TRUE(
      WriteFileAndCreateParentDirs(abs_file, "\n \t 20 Apr 2020 \t\t \n\n"));

  auto vpd_field = system_files_service_.GetVpdField(
      SystemFilesService::VpdField::kActivateDate);

  EXPECT_TRUE(vpd_field);
  EXPECT_EQ(vpd_field.value(), "20 Apr 2020");
}

// Test that GetDirectoryDump() returns false when the directory doesn't
// exist.
TEST_F(SystemFilesServiceTest, NonExistingDirectory) {
  EXPECT_FALSE(system_files_service_.GetDirectoryDump(
      SystemFilesService::Directory::kSysFirmwareDmiTables));
}

// Test that GetDirectoryDump() returns a single file when called on a
// directory containing a single file.
TEST_F(SystemFilesServiceTest, SingleFileInDirectory) {
  const base::FilePath kDirPath("sys/firmware/dmi/tables/");
  const base::FilePath kFilePath("testf");

  base::FilePath abs_path =
      temp_dir_.GetPath().Append(kDirPath).Append(kFilePath);

  ASSERT_TRUE(WriteFileAndCreateParentDirs(abs_path, FakeFileContents()));

  auto file_dumps = system_files_service_.GetDirectoryDump(
      SystemFilesService::Directory::kSysFirmwareDmiTables);

  ASSERT_TRUE(file_dumps);
  ASSERT_EQ(file_dumps.value().size(), 1);

  EXPECT_EQ(file_dumps.value()[0]->path, abs_path);
  EXPECT_EQ(file_dumps.value()[0]->canonical_path, abs_path);
  EXPECT_EQ(file_dumps.value()[0]->contents, FakeFileContents());
}

// Test that GetDirectoryDump returns correct file dumps for files in nested
// directories.
TEST_F(SystemFilesServiceTest, GetFileInNestedDirectory) {
  const base::FilePath kDirPath("sys/firmware/dmi/tables/");
  const base::FilePath kFilePath("a.testf");
  const base::FilePath kNestedPath("b.testn/testf");

  std::string nested_file_contents = FakeFileContents() + " nested";

  base::FilePath abs_file_path =
      temp_dir_.GetPath().Append(kDirPath).Append(kFilePath);
  base::FilePath abs_nested_path =
      temp_dir_.GetPath().Append(kDirPath).Append(kNestedPath);

  ASSERT_TRUE(
      WriteFileAndCreateParentDirs(abs_nested_path, nested_file_contents));
  ASSERT_TRUE(WriteFileAndCreateParentDirs(abs_file_path, FakeFileContents()));

  auto file_dumps = system_files_service_.GetDirectoryDump(
      SystemFilesService::Directory::kSysFirmwareDmiTables);

  ASSERT_TRUE(file_dumps);
  ASSERT_EQ(file_dumps.value().size(), 2);

  // We need to sort to ensure ordering for the next checks as file listing
  // is not deterministic
  std::sort(file_dumps.value().begin(), file_dumps.value().end(),
            [](const std::unique_ptr<SystemFilesService::FileDump>& a,
               const std::unique_ptr<SystemFilesService::FileDump>& b) {
              return a->path.value() < b->path.value();
            });

  EXPECT_EQ(file_dumps.value()[0]->path, abs_file_path);
  EXPECT_EQ(file_dumps.value()[0]->canonical_path, abs_file_path);
  EXPECT_EQ(file_dumps.value()[0]->contents, FakeFileContents());

  EXPECT_EQ(file_dumps.value()[1]->path, abs_nested_path);
  EXPECT_EQ(file_dumps.value()[1]->canonical_path, abs_nested_path);
  EXPECT_EQ(file_dumps.value()[1]->contents, nested_file_contents);
}

TEST_F(SystemFilesServiceTest, ShouldFollowSymlink) {
  const base::FilePath kLinkPath("sys/class/net/");
  const base::FilePath kFilePath("a.testf");

  base::ScopedTempDir other_dir;
  ASSERT_TRUE(other_dir.CreateUniqueTempDir());

  base::FilePath abs_file_path = other_dir.GetPath().Append(kFilePath);
  base::FilePath abs_link_path =
      temp_dir_.GetPath().Append(kLinkPath).Append(kFilePath);

  ASSERT_TRUE(WriteFileAndCreateSymbolicLink(abs_file_path, FakeFileContents(),
                                             abs_link_path));

  auto file_dumps = system_files_service_.GetDirectoryDump(
      SystemFilesService::Directory::kSysClassNetwork);

  ASSERT_TRUE(file_dumps);
  ASSERT_EQ(file_dumps.value().size(), 1);

  EXPECT_EQ(file_dumps.value()[0]->path, abs_link_path);
  EXPECT_EQ(file_dumps.value()[0]->canonical_path, abs_file_path);
  EXPECT_EQ(file_dumps.value()[0]->contents, FakeFileContents());
}

// Test that GetDirectoryDump() returns an empty result when given a directory
// with only a cyclic symlink.
TEST_F(SystemFilesServiceTest, CyclicSymLink) {
  const base::FilePath kDirPath("sys/class/net/");
  const base::FilePath kLinkPath =
      base::FilePath("sys/firmware/dmi/tables/link");

  base::FilePath abs_path =
      temp_dir_.GetPath().Append(kDirPath).Append(kLinkPath);

  ASSERT_TRUE(CreateCyclicSymbolicLink(abs_path));

  auto file_dumps = system_files_service_.GetDirectoryDump(
      SystemFilesService::Directory::kSysClassNetwork);

  ASSERT_TRUE(file_dumps);
  EXPECT_EQ(file_dumps.value().size(), 0);
}

// Test that GetDirectoryDump() returns a single result when given a directory
// containing a file and a symlink to that same file.
TEST_F(SystemFilesServiceTest, DuplicateSymLink) {
  const base::FilePath kDirPath("sys/class/net/");
  const base::FilePath kFilePath("testf");
  const base::FilePath kLinkPath("linkf");

  base::FilePath abs_file_path =
      temp_dir_.GetPath().Append(kDirPath).Append(kFilePath);
  base::FilePath abs_link_path =
      temp_dir_.GetPath().Append(kDirPath).Append(kLinkPath);

  ASSERT_TRUE(WriteFileAndCreateSymbolicLink(abs_file_path, FakeFileContents(),
                                             abs_link_path));

  auto file_dumps = system_files_service_.GetDirectoryDump(
      SystemFilesService::Directory::kSysClassNetwork);

  ASSERT_TRUE(file_dumps);
  ASSERT_EQ(file_dumps.value().size(), 1);

  // The non-canonical path could be either |abs_file_path| or
  // |abs_link_path|. Dumping a directory uses base::FileIterator,
  // whose order is not guaranteed.
  EXPECT_THAT(
      file_dumps.value()[0]->path.value(),
      AnyOf(StrEq(abs_file_path.value()), StrEq(abs_link_path.value())));
  EXPECT_EQ(file_dumps.value()[0]->canonical_path, abs_file_path);
  EXPECT_EQ(file_dumps.value()[0]->contents, FakeFileContents());
}

TEST_F(SystemFilesServiceTest, ShouldNotFollowSymlink) {
  const base::FilePath kLinkPath("sys/firmware/dmi/tables/");
  const base::FilePath kFilePath("a.testf");

  base::ScopedTempDir other_dir;
  ASSERT_TRUE(other_dir.CreateUniqueTempDir());

  base::FilePath abs_file_path = other_dir.GetPath().Append(kFilePath);
  base::FilePath abs_link_path =
      temp_dir_.GetPath().Append(kLinkPath).Append(kFilePath);

  ASSERT_TRUE(WriteFileAndCreateSymbolicLink(abs_file_path, FakeFileContents(),
                                             abs_link_path));

  auto file_dumps = system_files_service_.GetDirectoryDump(
      SystemFilesService::Directory::kSysFirmwareDmiTables);

  ASSERT_TRUE(file_dumps);
  EXPECT_EQ(file_dumps.value().size(), 0);
}

// Ensure Location mapping is valid
class SystemFilesServiceFileLocationTest
    : public SystemFilesServiceTest,
      public testing::WithParamInterface<
          std::tuple<SystemFilesService::File, std::string>> {
 public:
  SystemFilesServiceFileLocationTest() = default;
  SystemFilesServiceFileLocationTest(
      const SystemFilesServiceFileLocationTest&) = delete;
  SystemFilesServiceFileLocationTest& operator=(
      const SystemFilesServiceFileLocationTest&) = delete;

  ~SystemFilesServiceFileLocationTest() override = default;

 protected:
  SystemFilesService::File GetLocationParam() const {
    return std::get<0>(GetParam());
  }

  const std::string& GetPathParam() const { return std::get<1>(GetParam()); }

  base::FilePath GetAbsoluteTestFilePath() const {
    return temp_dir_.GetPath().Append(GetPathParam());
  }
  const std::string& GetTestFileContents() const { return GetPathParam(); }
};

TEST_P(SystemFilesServiceFileLocationTest, Path) {
  EXPECT_EQ(system_files_service_.GetPathForFile(GetLocationParam()).value(),
            GetPathParam());
}

TEST_P(SystemFilesServiceFileLocationTest, Dump) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetAbsoluteTestFilePath(),
                                           GetTestFileContents()));

  const auto file_dump = system_files_service_.GetFileDump(GetLocationParam());

  EXPECT_TRUE(file_dump);
  EXPECT_EQ(file_dump.value().path, GetAbsoluteTestFilePath());
  EXPECT_EQ(file_dump.value().canonical_path, GetAbsoluteTestFilePath());
  EXPECT_EQ(file_dump.value().contents, GetTestFileContents());
}

INSTANTIATE_TEST_SUITE_P(
    ,
    SystemFilesServiceFileLocationTest,
    testing::Values(
        std::make_tuple(SystemFilesService::File::kProcUptime, "proc/uptime"),
        std::make_tuple(SystemFilesService::File::kProcMeminfo, "proc/meminfo"),
        std::make_tuple(SystemFilesService::File::kProcLoadavg, "proc/loadavg"),
        std::make_tuple(SystemFilesService::File::kProcStat, "proc/stat"),
        std::make_tuple(SystemFilesService::File::kProcNetNetstat,
                        "proc/net/netstat"),
        std::make_tuple(SystemFilesService::File::kProcNetDev, "proc/net/dev"),
        std::make_tuple(SystemFilesService::File::kProcDiskstats,
                        "proc/diskstats"),
        std::make_tuple(SystemFilesService::File::kProcCpuinfo, "proc/cpuinfo"),
        std::make_tuple(SystemFilesService::File::kProcVmstat, "proc/vmstat")));

class SystemFilesServiceDirectoryLocationTest
    : public SystemFilesServiceTest,
      public testing::WithParamInterface<
          std::tuple<SystemFilesService::Directory, std::string>> {
 public:
  SystemFilesServiceDirectoryLocationTest() = default;
  SystemFilesServiceDirectoryLocationTest(
      const SystemFilesServiceDirectoryLocationTest&) = delete;
  SystemFilesServiceDirectoryLocationTest& operator=(
      const SystemFilesServiceDirectoryLocationTest&) = delete;

 protected:
  SystemFilesService::Directory GetLocationParam() const {
    return std::get<0>(GetParam());
  }

  const std::string& GetPathParam() const { return std::get<1>(GetParam()); }

  base::FilePath GetAbsoluteTestFilePath() const {
    return temp_dir_.GetPath().Append(GetPathParam()).Append("f");
  }
  const std::string& GetTestFileContents() const { return GetPathParam(); }
};

TEST_P(SystemFilesServiceDirectoryLocationTest, Path) {
  EXPECT_EQ(
      system_files_service_.GetPathForDirectory(GetLocationParam()).value(),
      GetPathParam());
}

TEST_P(SystemFilesServiceDirectoryLocationTest, Dump) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetAbsoluteTestFilePath(),
                                           GetTestFileContents()));

  auto file_dumps = system_files_service_.GetDirectoryDump(GetLocationParam());

  ASSERT_TRUE(file_dumps);
  ASSERT_EQ(file_dumps.value().size(), 1);

  EXPECT_EQ(file_dumps.value()[0]->path, GetAbsoluteTestFilePath());
  EXPECT_EQ(file_dumps.value()[0]->canonical_path, GetAbsoluteTestFilePath());
  EXPECT_EQ(file_dumps.value()[0]->contents, GetTestFileContents());
}

INSTANTIATE_TEST_SUITE_P(
    ,
    SystemFilesServiceDirectoryLocationTest,
    testing::Values(
        std::make_tuple(SystemFilesService::Directory::kProcAcpiButton,
                        "proc/acpi/button/"),
        std::make_tuple(SystemFilesService::Directory::kSysClassHwmon,
                        "sys/class/hwmon/"),
        std::make_tuple(SystemFilesService::Directory::kSysClassThermal,
                        "sys/class/thermal/"),
        std::make_tuple(SystemFilesService::Directory::kSysFirmwareDmiTables,
                        "sys/firmware/dmi/tables/"),
        std::make_tuple(SystemFilesService::Directory::kSysClassPowerSupply,
                        "sys/class/power_supply/"),
        std::make_tuple(SystemFilesService::Directory::kSysClassBacklight,
                        "sys/class/backlight/"),
        std::make_tuple(SystemFilesService::Directory::kSysClassNetwork,
                        "sys/class/net/"),
        std::make_tuple(SystemFilesService::Directory::kSysDevicesSystemCpu,
                        "sys/devices/system/cpu/")));

class SystemFilesServiceVpdFieldTest
    : public SystemFilesServiceTest,
      public testing::WithParamInterface<
          std::tuple<SystemFilesService::VpdField, std::string>> {
 public:
  SystemFilesServiceVpdFieldTest() = default;
  ~SystemFilesServiceVpdFieldTest() override = default;

  SystemFilesServiceVpdFieldTest(const SystemFilesServiceVpdFieldTest&) =
      delete;
  SystemFilesServiceVpdFieldTest& operator=(
      const SystemFilesServiceVpdFieldTest&) = delete;

 protected:
  SystemFilesService::VpdField GetVpdFieldParam() const {
    return std::get<0>(GetParam());
  }

  const std::string& GetPathParam() const { return std::get<1>(GetParam()); }

  base::FilePath GetAbsoluteTestFilePath() const {
    return temp_dir_.GetPath().Append(GetPathParam());
  }
  const std::string& GetTestFileContents() const { return GetPathParam(); }
};

TEST_P(SystemFilesServiceVpdFieldTest, Path) {
  EXPECT_EQ(
      system_files_service_.GetPathForVpdField(GetVpdFieldParam()).value(),
      GetPathParam());
}

TEST_P(SystemFilesServiceVpdFieldTest, Dump) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetAbsoluteTestFilePath(),
                                           GetTestFileContents()));

  auto vpd_field = system_files_service_.GetVpdField(GetVpdFieldParam());

  EXPECT_TRUE(vpd_field);
  EXPECT_EQ(vpd_field.value(), GetTestFileContents());
}

INSTANTIATE_TEST_SUITE_P(
    ,
    SystemFilesServiceVpdFieldTest,
    testing::Values(std::make_tuple(SystemFilesService::VpdField::kActivateDate,
                                    "run/wilco_dtc/vpd_fields/ActivateDate"),
                    std::make_tuple(SystemFilesService::VpdField::kAssetId,
                                    "run/wilco_dtc/vpd_fields/asset_id"),
                    std::make_tuple(SystemFilesService::VpdField::kMfgDate,
                                    "run/wilco_dtc/vpd_fields/mfg_date"),
                    std::make_tuple(SystemFilesService::VpdField::kModelName,
                                    "run/wilco_dtc/vpd_fields/model_name"),
                    std::make_tuple(SystemFilesService::VpdField::kSerialNumber,
                                    "run/wilco_dtc/vpd_fields/serial_number"),
                    std::make_tuple(SystemFilesService::VpdField::kSkuNumber,
                                    "run/wilco_dtc/vpd_fields/sku_number"),
                    std::make_tuple(SystemFilesService::VpdField::kSystemId,
                                    "run/wilco_dtc/vpd_fields/system_id"),
                    std::make_tuple(SystemFilesService::VpdField::kUuid,
                                    "run/wilco_dtc/vpd_fields/uuid_id")));

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
