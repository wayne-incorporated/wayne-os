// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/cros_fp_firmware.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <string>
#include <unordered_set>
#include <vector>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/types/cxx23_to_underlying.h>
#include <fmap.h>
#include <gtest/gtest.h>

#include "biod/utils.h"

namespace {

constexpr int kTestImageBaseAddr = 0x8000000;
constexpr int kTestImageSize = 2 * 1024 * 1024;
constexpr char kTestImageFwName[] = "EC_FMAP";
constexpr char kTestImageROIDLabel[] = "RO_FRID";
constexpr char kTestImageRWIDLabel[] = "RW_FWID";
constexpr char kTestImageFileName[] = "nocturne_fp_v2.2.110-b936c0a3c.bin";
constexpr char kTestImageROVersion[] = "nocturne_fp_v2.2.64-58cf5974e";
constexpr char kTestImageRWVersion[] = "nocturne_fp_v2.2.110-b936c0a3c";

const std::vector<biod::CrosFpFirmware::Status> kCrosFpFirmwareStatuses = {
    biod::CrosFpFirmware::Status::kUninitialized,
    biod::CrosFpFirmware::Status::kOk,
    biod::CrosFpFirmware::Status::kNotFound,
    biod::CrosFpFirmware::Status::kOpenError,
    biod::CrosFpFirmware::Status::kBadFmap,
};

class Fmap {
 public:
  Fmap() : fmap_(nullptr) {}
  Fmap(const Fmap&) = delete;
  Fmap& operator=(const Fmap&) = delete;
  ~Fmap() { Destroy(); }

  bool Create(uint64_t base, uint32_t size, const char* name) {
    Destroy();
    // fmap_create does not modify name internally
    fmap_ = fmap_create(
        base, size,
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name)));
    return (fmap_ != nullptr);
  }
  bool AppendArea(uint32_t offset,
                  uint32_t size,
                  const char* name,
                  uint16_t flags) {
    CHECK(IsValid());
    return fmap_append_area(&fmap_, offset, size,
                            reinterpret_cast<const uint8_t*>(name), flags) >= 0;
  }
  bool IsValid() { return fmap_ != nullptr; }
  const char* GetData() { return reinterpret_cast<char*>(fmap_); }
  int GetDataLength() { return fmap_size(fmap_); }

 private:
  void Destroy() {
    if (IsValid()) {
      fmap_destroy(fmap_);
    }
  }

  struct fmap* fmap_;
};

}  // namespace

namespace biod {

class CrosFpFirmwareTest : public ::testing::Test {
 protected:
  void SetUp() override { CHECK(temp_dir_.CreateUniqueTempDir()); }

  void TearDown() override { EXPECT_TRUE(temp_dir_.Delete()); }

  const base::FilePath& GetTestTempDir() const { return temp_dir_.GetPath(); }

  bool CreateFakeImage(const base::FilePath& abspath,
                       const std::string& ro_version,
                       const std::string& rw_version,
                       uint32_t fmap_report_size = kTestImageSize,
                       bool fmap_ro_include = true,
                       bool fmap_rw_include = true,
                       uint32_t ver_area_offset = 0,
                       uint32_t ver_area_size = FMAP_STRLEN) {
    if (!GetTestTempDir().IsParent(abspath)) {
      LOG(ERROR) << "Asked to PlaceFakeImage outside test environment.";
      return false;
    }

    LOG(INFO) << "Creating fake image at: " << abspath.value();

    // FMAP_STRLEN is the max size of the string including a null character
    if (ro_version.length() >= FMAP_STRLEN) {
      LOG(ERROR) << "Error - ro_version, '" << ro_version
                 << "', is too long. Must be max " << FMAP_STRLEN
                 << " with null terminator.";
      return false;
    }
    if (rw_version.length() >= FMAP_STRLEN) {
      LOG(ERROR) << "Error - rw_version, '" << rw_version
                 << "', is too long. Must be max " << FMAP_STRLEN
                 << " with null terminator.";
      return false;
    }

    base::File file(abspath,
                    base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
    if (!file.IsValid()) {
      return false;
    }

    std::vector<char> verbuf(FMAP_STRLEN * 2);
    ro_version.copy(&verbuf[0 * FMAP_STRLEN], FMAP_STRLEN - 1);
    rw_version.copy(&verbuf[1 * FMAP_STRLEN], FMAP_STRLEN - 1);

    // place ro and rw versions at the front of the file
    if (file.WriteAtCurrentPos(&verbuf[0], 2 * FMAP_STRLEN) < 0) {
      LOG(ERROR) << "Failed to write version strings into fake image.";
      return false;
    }

    Fmap fmap;
    if (!fmap.Create(kTestImageBaseAddr, fmap_report_size, kTestImageFwName)) {
      LOG(ERROR) << "Failed to allocate fmap struct";
      return false;
    }
    if (fmap_ro_include) {
      if (!fmap.AppendArea(ver_area_offset + (0 * FMAP_STRLEN), ver_area_size,
                           kTestImageROIDLabel, FMAP_AREA_RO)) {
        LOG(ERROR) << "Failed to append " << kTestImageROIDLabel << " FW area.";
        return false;
      }
    }
    if (fmap_rw_include) {
      if (!fmap.AppendArea(ver_area_offset + (1 * FMAP_STRLEN), ver_area_size,
                           kTestImageRWIDLabel, FMAP_AREA_RO)) {
        LOG(ERROR) << "Failed to append " << kTestImageRWIDLabel << " FW area.";
        return false;
      }
    }
    if (!fmap.IsValid()) {
      LOG(ERROR) << "Fmap data or size are invalid.";
      return false;
    }
    if (file.WriteAtCurrentPos(fmap.GetData(), fmap.GetDataLength()) < 0) {
      LOG(ERROR) << "Failed to write fmap into fake image.";
      return false;
    }

    // we must grow the file to match or be larger than FMAP reported size
    if (!file.SetLength(kTestImageSize)) {
      LOG(ERROR) << "Failed to elongate fake image to typical size.";
      return false;
    }

    EXPECT_TRUE(base::PathExists(abspath));
    return true;
  }

  void TestExpectFailure(const base::FilePath& image_path,
                         biod::CrosFpFirmware::Status expect_status) {
    biod::CrosFpFirmware fw(image_path);

    EXPECT_STREQ(fw.GetPath().value().c_str(), image_path.value().c_str());
    EXPECT_EQ(fw.GetStatus(), expect_status);
    EXPECT_FALSE(fw.IsValid());
    EXPECT_STREQ(fw.GetStatusString().c_str(),
                 CrosFpFirmware::StatusToString(expect_status).c_str());
    biod::CrosFpFirmware::ImageVersion fwver = fw.GetVersion();
    LOG(INFO) << "Passed";
  }

  void TestExpectSuccess(const base::FilePath& image_path,
                         const std::string& expect_ro_version,
                         const std::string& expect_rw_version) {
    biod::CrosFpFirmware fw(image_path);

    EXPECT_STREQ(fw.GetPath().value().c_str(), image_path.value().c_str());
    EXPECT_EQ(fw.GetStatus(), biod::CrosFpFirmware::Status::kOk)
        << "The returned status is not the Ok status.";
    EXPECT_TRUE(fw.IsValid());
    EXPECT_STREQ(
        fw.GetStatusString().c_str(),
        CrosFpFirmware::StatusToString(biod::CrosFpFirmware::Status::kOk)
            .c_str())
        << "The status string returned did not match that of the Ok status.";
    biod::CrosFpFirmware::ImageVersion fwver = fw.GetVersion();
    EXPECT_STREQ(fwver.ro_version.c_str(), expect_ro_version.c_str())
        << "The decoded RO version string did not match.";
    EXPECT_STREQ(fwver.rw_version.c_str(), expect_rw_version.c_str())
        << "The decoded RW version string did not match.";
    LOG(INFO) << "Passed";
  }

  // this proxy function allows us to keep the core CrosFpFirmware class
  // clean from lots of friend declarations for each unit test fixture
  static std::string TestStatusToString(CrosFpFirmware::Status status) {
    return CrosFpFirmware::StatusToString(status);
  }

  base::ScopedTempDir temp_dir_;

  CrosFpFirmwareTest() = default;
  CrosFpFirmwareTest(const CrosFpFirmwareTest&) = delete;
  CrosFpFirmwareTest& operator=(const CrosFpFirmwareTest&) = delete;

  ~CrosFpFirmwareTest() override = default;

 private:
  FRIEND_TEST(CrosFpFirmwareTest, UniqueErrorMessages);
};

TEST_F(CrosFpFirmwareTest, InvalidPathBlank) {
  TestExpectFailure(
      // Given an empty firmware file path,
      base::FilePath(""),
      // expect to receive a firmware file not found error.
      biod::CrosFpFirmware::Status::kNotFound);
}

TEST_F(CrosFpFirmwareTest, InavlidPathOddChars) {
  TestExpectFailure(
      // Given a firmware file path "--",
      base::FilePath("--"),
      // expect to receive a firmware file not found error.
      biod::CrosFpFirmware::Status::kNotFound);
}

TEST_F(CrosFpFirmwareTest, GivenDirectory) {
  TestExpectFailure(
      // Given a directory as the firmware file path,
      GetTestTempDir(),
      // expect to receive a firmware file not found error.
      biod::CrosFpFirmware::Status::kNotFound);
}

TEST_F(CrosFpFirmwareTest, GivenEmptyFile) {
  // Given an empty file (of size 0),
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  base::File file(image_path,
                  base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  file.Close();
  EXPECT_TRUE(base::PathExists(image_path));

  // expect to receive an open file error (from mmap).
  TestExpectFailure(image_path, biod::CrosFpFirmware::Status::kOpenError);
}

TEST_F(CrosFpFirmwareTest, NoFMAP) {
  // Given a file that does not contain an FMAP,
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  base::File file(image_path,
                  base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  EXPECT_GE(file.WriteAtCurrentPos("a", 1), 1);
  file.Close();
  EXPECT_TRUE(base::PathExists(image_path));

  // expect to receive a bad-fmap error.
  TestExpectFailure(image_path, biod::CrosFpFirmware::Status::kBadFmap);
}

TEST_F(CrosFpFirmwareTest, FMAPReportsLargerSizeThanFileSize) {
  // Given a firmware file
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, kTestImageROVersion,
                              kTestImageRWVersion,
                              // whose FMAP reports an overall size larger
                              // than the actual file's size,
                              kTestImageSize + 1));

  // expect to receive a bad-fmap error.
  TestExpectFailure(image_path, biod::CrosFpFirmware::Status::kBadFmap);
}

TEST_F(CrosFpFirmwareTest, FMAPReportsZeroSize) {
  // Given a firmware file
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, kTestImageROVersion,
                              kTestImageRWVersion,
                              // whose FMAP reports an overall size of 0,
                              0));

  // expect to receive a bad-fmap error.
  TestExpectFailure(image_path, biod::CrosFpFirmware::Status::kBadFmap);
}

TEST_F(CrosFpFirmwareTest, GoodImageFile_DefaultVerAndFileName) {
  // Given a firmware file with a proper FMAP,
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(
      CreateFakeImage(image_path, kTestImageROVersion, kTestImageRWVersion));

  // expect properly decoded version strings.
  TestExpectSuccess(image_path, kTestImageROVersion, kTestImageRWVersion);
}

TEST_F(CrosFpFirmwareTest, GoodImageFile_UnknownVerAndFileName) {
  // Given a firmware file with a proper FMAP and different
  // version string,
  const char image_ro_version[] = "unknown_fp_v12.34.567-abc123456";
  const char image_rw_version[] = "unknown_fp_v765.43.21-abc123456";
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, image_ro_version, image_rw_version));

  // expect properly decoded version strings.
  TestExpectSuccess(image_path, image_ro_version, image_rw_version);
}

TEST_F(CrosFpFirmwareTest, GoodImageFile_BlankVerAndMinimalFileName) {
  // Given a firmware file with a proper FMAP and blank version strings,
  const char image_ro_version[] = "";
  const char image_rw_version[] = "";
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, image_ro_version, image_rw_version));

  // expect properly decoded (empty) version strings.
  TestExpectSuccess(image_path, image_ro_version, image_rw_version);
}

TEST_F(CrosFpFirmwareTest, FMAPMissingROArea) {
  // Given a firmware file
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, kTestImageROVersion,
                              kTestImageRWVersion, kTestImageSize,
                              // whose FMAP is missing an RO version area,
                              false, true));

  // expect to receive a bad-fmap error.
  TestExpectFailure(image_path, biod::CrosFpFirmware::Status::kBadFmap);
}

TEST_F(CrosFpFirmwareTest, FMAPMissingRWArea) {
  // Given a firmware file
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, kTestImageROVersion,
                              kTestImageRWVersion, kTestImageSize,
                              // whose FMAP is missing an RW version area,
                              true, false));

  // expect to receive a bad-fmap error.
  TestExpectFailure(image_path, biod::CrosFpFirmware::Status::kBadFmap);
}

TEST_F(CrosFpFirmwareTest, FMAPMissingRORWArea) {
  // Given a firmware file
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, kTestImageROVersion,
                              kTestImageRWVersion, kTestImageSize,
                              // whose FMAP is missing an RO and RW
                              // version area,
                              false, false));

  // expect to receive a bad-fmap error.
  TestExpectFailure(image_path, biod::CrosFpFirmware::Status::kBadFmap);
}

TEST_F(CrosFpFirmwareTest, FMAPVersionAreaOffsetPastFileLimit) {
  // Given a firmware file
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, kTestImageROVersion,
                              kTestImageRWVersion, kTestImageSize, true, true,
                              // whose FMAP version areas report offsets
                              // pointing outside the actual file,
                              kTestImageSize));

  // expect to receive a bad-fmap error.
  TestExpectFailure(image_path, biod::CrosFpFirmware::Status::kBadFmap);
}

TEST_F(CrosFpFirmwareTest, FMAPVersionAreaSizeLargerThanFile) {
  // Given a firmware file
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, kTestImageROVersion,
                              kTestImageRWVersion, kTestImageSize, true, true,
                              0,
                              // whose FMAP version areas report sizes
                              // which are larger than the actual file,
                              kTestImageSize + 1));

  // expect to receive a bad-fmap error.
  TestExpectFailure(image_path, biod::CrosFpFirmware::Status::kBadFmap);
}

TEST_F(CrosFpFirmwareTest, FMAPVersionAreaSizeIsZero) {
  // Given a firmware file
  const auto image_path = GetTestTempDir().Append(kTestImageFileName);
  EXPECT_TRUE(CreateFakeImage(image_path, kTestImageROVersion,
                              kTestImageRWVersion, kTestImageSize, true, true,
                              0,
                              // whose FMAP version areas report sizes of 0,
                              0));

  // expect properly decoded blank version strings.
  TestExpectSuccess(image_path, "", "");
}

TEST_F(CrosFpFirmwareTest, NonblankStatusMessages) {
  // Given a CrosFpFirmware status
  for (auto status : kCrosFpFirmwareStatuses) {
    // when we ask for the human readable string
    std::string msg = TestStatusToString(status);
    // expect it to not be "".
    EXPECT_FALSE(msg.empty()) << "Status " << base::to_underlying(status)
                              << " converts to a blank status string.";
  }
}

TEST_F(CrosFpFirmwareTest, UniqueStatusMessages) {
  // Given a set of all CrosFpFirmware status messages,
  std::unordered_set<std::string> status_msgs;
  for (auto status : kCrosFpFirmwareStatuses) {
    status_msgs.insert(TestStatusToString(status));
  }

  // expect the set to contain the same number of unique messages
  // as there are original statuses.
  EXPECT_EQ(status_msgs.size(), kCrosFpFirmwareStatuses.size())
      << "There are one or more non-unique status messages.";
}

}  // namespace biod
