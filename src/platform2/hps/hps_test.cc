// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ref_counted.h>
#include <base/sys_byteorder.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "hps/dev.h"
#include "hps/hal/fake_dev.h"
#include "hps/hps.h"
#include "hps/hps_impl.h"
#include "hps/hps_metrics.h"
#include "hps/hps_reg.h"
#include "hps/utils.h"
#include "metrics/metrics_library_mock.h"

using ::testing::_;
using testing::Return;

namespace hps {

class MockHpsDev : public hps::DevInterface {
 public:
  MOCK_METHOD(bool, Read, (uint8_t, uint8_t*, size_t), (override));
  MOCK_METHOD(bool, Write, (uint8_t, const uint8_t*, size_t), (override));
  MOCK_METHOD(std::optional<uint16_t>, ReadReg, (hps::HpsReg), (override));
  MOCK_METHOD(std::optional<std::string>,
              ReadStringReg,
              (hps::HpsReg, size_t len),
              (override));
  MOCK_METHOD(bool, WriteReg, (hps::HpsReg, uint16_t), (override));
  bool ReadDevice(uint8_t cmd, uint8_t* data, size_t len) override {
    return true;
  }
  bool WriteDevice(uint8_t cmd, const uint8_t* data, size_t len) override {
    return true;
  }
};

class MockHpsMetrics : public hps::HpsMetricsInterface {
 public:
  MOCK_METHOD(bool,
              SendHpsTurnOnResult,
              (HpsTurnOnResult, base::TimeDelta),
              (override));
  MOCK_METHOD(bool,
              SendHpsUpdateDuration,
              (HpsBank, base::TimeDelta),
              (override));
  MOCK_METHOD(void, SendImageValidity, (bool), (override));
};

// Override sleep to use MOCK_TIME functionality
class HPS_fake_sleep_for_test : public HPS_impl {
 public:
  HPS_fake_sleep_for_test(std::unique_ptr<DevInterface> dev,
                          std::unique_ptr<HpsMetricsInterface> metrics,
                          base::test::TaskEnvironment* task_environment)
      : HPS_impl(std::move(dev), std::move(metrics)),
        task_environment_(task_environment) {}

  void Sleep(base::TimeDelta duration) override {
    task_environment_->AdvanceClock(duration);
  }
  base::TimeDelta GetSystemSuspendTime() override {
    if (suspend_times_.empty())
      return base::TimeDelta();
    auto result = suspend_times_.front();
    suspend_times_.pop_front();
    return result;
  }

  base::test::TaskEnvironment* task_environment_;
  std::deque<base::TimeDelta> suspend_times_;
};

// A duplicate of HPSTest, but using a MockHpsDev, existing only while the
// tests are converted to using the mock. TODO(evanbenn) complete the
// conversion of the remainder of the tests
class HPSTestButUsingAMock : public testing::Test {
 protected:
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  void SetUp() override {
    auto dev = std::make_unique<MockHpsDev>();
    dev_ = dev.get();
    auto metrics = std::make_unique<MockHpsMetrics>();
    metrics_ = metrics.get();
    hps_ = std::make_unique<hps::HPS_fake_sleep_for_test>(
        std::move(dev), std::move(metrics), &task_environment_);
  }

  void CreateBlob(const base::FilePath& file, int len) {
    base::File f(file, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
    ASSERT_TRUE(f.IsValid());
    f.SetLength(len);
  }

  bool CheckMagic() { return hps_->CheckMagic(); }

  void ExpectRegisterDump() {
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kMagic)).WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kHwRev)).WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kSysStatus))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kBankReady))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kError)).WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kFeatEn)).WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kFeature0))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kFeature1))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kFirmwareVersionHigh))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kFirmwareVersionLow))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kFpgaBootCount))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kFpgaLoopCount))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kFpgaRomVersion))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kSpiFlashStatus))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kCameraConfig))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kOptionBytesConfig))
        .WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kPartIds)).WillOnce(Return(0x1234));
    EXPECT_CALL(*dev_, ReadStringReg(hps::HpsReg::kPreviousCrashMessage, 256))
        .WillOnce(Return("test"));
    EXPECT_CALL(*dev_, ReadStringReg(hps::HpsReg::kFpgaCrashMessage, 256))
        .WillOnce(Return("test"));
  }

  MockHpsDev* dev_;
  MockHpsMetrics* metrics_;
  std::unique_ptr<hps::HPS_impl> hps_;
};

class HPSTest : public testing::Test {
 protected:
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  void SetUp() override {
    auto fake = std::make_unique<hps::FakeDev>();
    fake_ = fake.get();
    auto metrics = std::make_unique<MockHpsMetrics>();
    metrics_ = metrics.get();
    hps_ = std::make_unique<hps::HPS_fake_sleep_for_test>(
        std::move(fake), std::move(metrics), &task_environment_);
  }

  void CreateBlob(const base::FilePath& file, int len) {
    base::File f(file, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
    ASSERT_TRUE(f.IsValid());
    f.SetLength(len);
  }

  hps::FakeDev* fake_;
  MockHpsMetrics* metrics_;
  std::unique_ptr<hps::HPS_fake_sleep_for_test> hps_;
};

class MockDownloadObserver {
 public:
  MOCK_METHOD(void,
              OnProgress,
              (const base::FilePath&, uint64_t, uint64_t, base::TimeDelta));
};

/*
 * Check for a magic number.
 */
TEST_F(HPSTestButUsingAMock, MagicNumber) {
  EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kMagic))
      .WillOnce(Return(hps::kHpsMagic));
  EXPECT_TRUE(CheckMagic());
}

/*
 * Check for a magic number but timeout.
 */
TEST_F(HPSTestButUsingAMock, MagicNumberTimeout) {
  EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kMagic))
      .WillRepeatedly(Return(std::nullopt));
  EXPECT_FALSE(CheckMagic());
}

TEST_F(HPSTestButUsingAMock, IsRunningOk) {
  EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kSysStatus))
      .WillOnce(Return(R2::kAppl));
  EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kError)).WillOnce(Return(0));
  EXPECT_TRUE(hps_->IsRunning());
}

TEST_F(HPSTestButUsingAMock, TransientCameraError) {
  EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kSysStatus))
      .WillOnce(Return(R2::kAppl));
  EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kError))
      .WillOnce(Return(hps::RError::kCameraImageTimeout));
  EXPECT_FALSE(hps_->IsRunning());
}

TEST_F(HPSTestButUsingAMock, TooManyTransientErrors) {
  for (int i = 0; i < 99; i++) {
    testing::InSequence s;
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kSysStatus))
        .WillOnce(Return(R2::kAppl));
    EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kError))
        .WillOnce(Return(hps::RError::kCameraImageTimeout));
    EXPECT_FALSE(hps_->IsRunning());
    testing::Mock::VerifyAndClearExpectations(dev_);
  }
  EXPECT_DEATH(
      {
        testing::InSequence s;
        EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kSysStatus))
            .WillOnce(Return(R2::kAppl));
        EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kError))
            .WillOnce(Return(hps::RError::kCameraImageTimeout));
        ExpectRegisterDump();
        hps_->IsRunning();
      },
      "Terminating for fatal error");
}

TEST_F(HPSTestButUsingAMock, IsRunningFailure) {
  EXPECT_DEATH(
      {
        testing::InSequence s;
        EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kSysStatus))
            .WillOnce(Return(R2::kAppl));
        EXPECT_CALL(*dev_, ReadReg(hps::HpsReg::kError))
            .WillOnce(Return(0x1234));
        ExpectRegisterDump();
        hps_->IsRunning();
      },
      "Terminating for fatal error");
}

/*
 * Check that features can be enabled/disabled, and
 * results are returned only when allowed.
 */
TEST_F(HPSTest, FeatureControl) {
  hps::FeatureResult feature_result;
  // No features enabled until module is ready.
  EXPECT_FALSE(hps_->Enable(0));
  EXPECT_FALSE(hps_->Enable(1));
  feature_result = hps_->Result(0);
  EXPECT_EQ(feature_result.valid, false);
  // Set the module to be ready for features.
  fake_->SkipBoot();
  EXPECT_FALSE(hps_->Enable(hps::kFeatures));
  EXPECT_FALSE(hps_->Disable(hps::kFeatures));
  feature_result = hps_->Result(hps::kFeatures);
  EXPECT_EQ(feature_result.valid, false);
  ASSERT_TRUE(hps_->Enable(0));
  ASSERT_TRUE(hps_->Enable(1));
  // Check that enabled features can be disabled.
  EXPECT_TRUE(hps_->Disable(0));
  EXPECT_TRUE(hps_->Disable(1));
  // Check that a result is returned if the feature is enabled.
  const int result = -42;
  fake_->SetF0Result(result, true);
  feature_result = hps_->Result(0);
  EXPECT_EQ(feature_result.valid, false);
  ASSERT_TRUE(hps_->Enable(0));
  // SendImageValidity is only sent when the device responds with 'invalid'.
  // The other 'Result' calls in this test do not query the device because
  // hps_impl has an internal state of enabled features 'feat_enabled_'.
  EXPECT_CALL(*metrics_, SendImageValidity(true)).Times(1);
  feature_result = hps_->Result(0);
  EXPECT_EQ(feature_result.valid, true);
  EXPECT_EQ(feature_result.inference_result, result);
  ASSERT_TRUE(hps_->Disable(0));
  feature_result = hps_->Result(0);
  EXPECT_EQ(feature_result.valid, false);
}

/*
 * Check that an invalid result sends SendImageValidity(false)
 */
TEST_F(HPSTest, FeatureInvalid) {
  hps::FeatureResult feature_result;
  const int result = -42;
  // Set the module to be ready for features.
  fake_->SkipBoot();
  fake_->SetF0Result(result, false);
  ASSERT_TRUE(hps_->Enable(0));
  EXPECT_CALL(*metrics_, SendImageValidity(false)).Times(1);
  feature_result = hps_->Result(0);
  EXPECT_EQ(feature_result.valid, false);
  EXPECT_EQ(feature_result.inference_result, result);
}

/*
 * Download testing.
 */
TEST_F(HPSTest, Download) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto f = temp_dir.GetPath().Append("blob");
  const int len = 1021;
  CreateBlob(f, len);

  // Download allowed to mcu flash in pre-booted state.
  ASSERT_TRUE(hps_->Download(hps::HpsBank::kMcuFlash, f));
  // Make sure the right amount was written.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), len);

  // Downloading a non existant file fails
  EXPECT_FALSE(hps_->Download(hps::HpsBank::kMcuFlash,
                              temp_dir.GetPath().Append("fake")));

  // Fail the memory write and confirm that the request fails.
  fake_->Set(hps::FakeDev::Flags::kMemFail);
  ASSERT_FALSE(hps_->Download(hps::HpsBank::kMcuFlash, f));
  // No change to length.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), len);
  fake_->Clear(hps::FakeDev::Flags::kMemFail);

  // Download fails when bank not ready
  EXPECT_FALSE(hps_->Download(hps::HpsBank::kSpiFlash, f));
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSpiFlash), 0);
}

/*
 * Download testing with small block size
 */
TEST_F(HPSTest, DownloadSmallBlocks) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto f = temp_dir.GetPath().Append("blob");
  const int len = 1024;
  CreateBlob(f, len);
  fake_->SetBlockSizeBytes(32);
  // Download allowed to mcu flash in pre-booted state.
  ASSERT_TRUE(hps_->Download(hps::HpsBank::kMcuFlash, f));
  // Make sure the right amount was written.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), len);
}

/*
 * Observing download progress.
 */
TEST_F(HPSTest, DownloadProgressObserver) {
  MockDownloadObserver observer;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto f1 = temp_dir.GetPath().Append("blob1");
  auto f2 = temp_dir.GetPath().Append("blob2");
  const int kBlockSize = 256;
  const int kLen1 = 1000;
  const int kLen2 = 128;
  CreateBlob(f1, kLen1);
  CreateBlob(f2, kLen2);
  fake_->SetBlockSizeBytes(kBlockSize);
  hps_->SetDownloadObserver(base::BindRepeating(
      &MockDownloadObserver::OnProgress, base::Unretained(&observer)));
  {
    // Download a file that is larger than the block size.
    testing::InSequence s;
    EXPECT_CALL(observer, OnProgress(f1, kLen1, kBlockSize, _));
    EXPECT_CALL(observer, OnProgress(f1, kLen1, kBlockSize * 2, _));
    EXPECT_CALL(observer, OnProgress(f1, kLen1, kBlockSize * 3, _));
    EXPECT_CALL(observer, OnProgress(f1, kLen1, kLen1, _));
    ASSERT_TRUE(hps_->Download(hps::HpsBank::kMcuFlash, f1));
  }
  {
    // Download a file that is smaller than the block size.
    testing::InSequence s;
    EXPECT_CALL(observer, OnProgress(f2, kLen2, kLen2, _));
    ASSERT_TRUE(hps_->Download(hps::HpsBank::kMcuFlash, f2));
  }
}

/*
 * Features cannot be enabled until after boot
 */
TEST_F(HPSTest, SkipBoot) {
  // Make sure features can't be enabled.
  ASSERT_FALSE(hps_->Enable(0));
  // Put the fake straight into application stage.
  fake_->SkipBoot();
  // Ensure that features can be enabled.
  EXPECT_TRUE(hps_->Enable(0));
}

/*
 * Test normal boot, where the versions match and
 * the files are verified, so no flash update should occur.
 */
TEST_F(HPSTest, NormalBoot) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  // Create MCU and SPI flash filenames (but do not
  // create the files themselves).
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");

  // Set the expected version
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  // Set up the version and files.
  hps_->Init(version, mcu, spi1, spi2);

  // Boot the module.
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();

  // Ensure that features can be enabled.
  EXPECT_TRUE(hps_->Enable(0));
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), 0);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSpiFlash), 0);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSocRom), 0);
}

TEST_F(HPSTest, PowerOnRecoverySucceeded) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  hps_->Init(version, mcu, spi1, spi2);

  // Make HPS initially fail to boot but recover after a power cycle.
  fake_->SetPowerOnFailureCount(2);
  EXPECT_CALL(
      *metrics_,
      SendHpsTurnOnResult(hps::HpsTurnOnResult::kPowerOnRecoverySucceeded, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();
}

TEST_F(HPSTest, PowerOnRecoveryFailed) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  hps_->Init(version, mcu, spi1, spi2);

  // Make HPS fail to boot enough times that hpsd gives up.
  fake_->SetPowerOnFailureCount(3);

  EXPECT_DEATH(
      {
        EXPECT_CALL(*metrics_,
                    SendHpsTurnOnResult(
                        hps::HpsTurnOnResult::kPowerOnRecoveryFailed, _))
            .Times(1);
        hps_->Boot();
      },
      "HPS device recovery failed");
}

TEST_F(HPSTest, TransientBootErrorWithSystemSuspend) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  hps_->Init(version, mcu, spi1, spi2);

  // Make the status register fail once.
  fake_->Set(hps::FakeDev::Flags::kFailStatusRegRead);

  // Simulate a 10 second system suspend.
  hps_->suspend_times_ = {base::TimeDelta(), base::Seconds(10)};

  // The transient error should be ignored, and booting eventually succeeds.
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();
}

TEST_F(HPSTest, TransientBootErrorWithoutSystemSuspend) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  hps_->Init(version, mcu, spi1, spi2);

  // Make the status register fail once.
  fake_->Set(hps::FakeDev::Flags::kFailStatusRegRead);

  // Since a system suspend isn't detected, the transient error becomes fatal.
  EXPECT_DEATH({ hps_->Boot(); }, "Terminating for boot fault");
}

/*
 * Test normal boot twice in a row, the device should boot if it is already
 * booted.
 */
TEST_F(HPSTest, NormalBootTwice) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  // Create MCU and SPI flash filenames (but do not
  // create the files themselves).
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");

  // Set the expected version
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  // Set up the version and files.
  hps_->Init(version, mcu, spi1, spi2);

  // Boot the module.
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(2);
  hps_->Boot();
  hps_->Boot();
}

/*
 * Test that the MCU flash is updated when not verified.
 */
TEST_F(HPSTest, McuUpdate) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  // Create MCU and SPI flash filenames (but do not
  // create the files themselves).
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");
  const int len = 1024;
  CreateBlob(mcu, len);

  // Set the expected version
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  fake_->Set(hps::FakeDev::Flags::kStage1NotVerified);
  fake_->Set(hps::FakeDev::Flags::kResetApplVerification);
  // Set up the version and files.
  hps_->Init(version, mcu, spi1, spi2);

  // Boot the module.
  EXPECT_CALL(*metrics_, SendHpsUpdateDuration(hps::HpsBank::kMcuFlash, _))
      .Times(1);
  EXPECT_CALL(*metrics_,
              SendHpsTurnOnResult(hps::HpsTurnOnResult::kMcuNotVerified, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();

  // Check that MCU was downloaded.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), len);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSpiFlash), 0);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSocRom), 0);
}

/*
 * Test that the MCU flash is updated when it has a flash ECC error.
 */
TEST_F(HPSTest, McuUpdateOnFlashEccError) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  // Create MCU and SPI flash filenames (but do not
  // create the files themselves).
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");
  const int len = 1024;
  CreateBlob(mcu, len);

  // Set the expected version
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  fake_->Set(hps::FakeDev::Flags::kFlashEccError);
  // Set up the version and files.
  hps_->Init(version, mcu, spi1, spi2);

  // Boot the module.
  EXPECT_CALL(*metrics_, SendHpsUpdateDuration(hps::HpsBank::kMcuFlash, _))
      .Times(1);
  EXPECT_CALL(*metrics_,
              SendHpsTurnOnResult(hps::HpsTurnOnResult::kMcuNotVerified, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();

  // Check that MCU firmware was downloaded.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), len);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSpiFlash), 0);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSocRom), 0);
}

/*
 * Test that the SPI flash is updated when not verified.
 */
TEST_F(HPSTest, SpiUpdate) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  // Create MCU and SPI flash filenames (but do not
  // create the files themselves).
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");

  const int len = 1024;
  CreateBlob(spi1, len);
  CreateBlob(spi2, len + 1);

  // Set the expected version
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  fake_->Set(hps::FakeDev::Flags::kSpiNotVerified);
  fake_->Set(hps::FakeDev::Flags::kResetSpiVerification);
  // Set up the version and files.
  hps_->Init(version, mcu, spi1, spi2);

  // Boot the module.
  EXPECT_CALL(*metrics_,
              SendHpsTurnOnResult(hps::HpsTurnOnResult::kSpiNotVerified, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsUpdateDuration(hps::HpsBank::kSpiFlash, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();

  // Check that SPI was downloaded.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), 0);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSpiFlash), len);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSocRom), len + 1);
}

/*
 * Test that the both SPI and MCU are updated
 * when not verified.
 */
TEST_F(HPSTest, BothUpdate) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  // Create MCU and SPI flash filenames (but do not
  // create the files themselves).
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");

  const int len = 1024;
  CreateBlob(mcu, len);
  CreateBlob(spi1, len + 1);
  CreateBlob(spi2, len + 2);

  // Set the expected version
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  fake_->Set(hps::FakeDev::Flags::kStage1NotVerified);
  fake_->Set(hps::FakeDev::Flags::kResetApplVerification);
  fake_->Set(hps::FakeDev::Flags::kSpiNotVerified);
  fake_->Set(hps::FakeDev::Flags::kResetSpiVerification);
  // Set up the version and files.
  hps_->Init(version, mcu, spi1, spi2);

  // Boot the module.
  EXPECT_CALL(*metrics_, SendHpsUpdateDuration(hps::HpsBank::kMcuFlash, _))
      .Times(1);
  EXPECT_CALL(*metrics_,
              SendHpsTurnOnResult(hps::HpsTurnOnResult::kMcuNotVerified, _))
      .Times(1);
  EXPECT_CALL(*metrics_,
              SendHpsTurnOnResult(hps::HpsTurnOnResult::kSpiNotVerified, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsUpdateDuration(hps::HpsBank::kSpiFlash, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();

  // Check that both MCU and SPI blobs were updated.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), len);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSpiFlash), len + 1);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSocRom), len + 2);
}

/*
 * When write protect is off non verified code should not be updated
 */
TEST_F(HPSTest, WpOffNoUpdate) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  // Create MCU and SPI flash filenames (but do not
  // create the files themselves).
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");

  const int len = 1024;
  CreateBlob(mcu, len);
  CreateBlob(spi1, len + 1);
  CreateBlob(spi2, len + 2);

  // Set the expected version
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  fake_->Set(hps::FakeDev::Flags::kStage1NotVerified);
  fake_->Set(hps::FakeDev::Flags::kWpOff);
  // Set up the version and files.
  hps_->Init(version, mcu, spi1, spi2);

  // Boot the module.
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();

  // Check that neither MCU nor SPI blobs were updated.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), 0);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSpiFlash), 0);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSocRom), 0);
}

/*
 * When write protect is off non verified code should be updated when the
 * versions differ
 */
TEST_F(HPSTest, WpOffUpdate) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  // Create MCU and SPI flash filenames (but do not
  // create the files themselves).
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");

  const int len = 1024;
  CreateBlob(mcu, len);
  CreateBlob(spi1, len + 1);
  CreateBlob(spi2, len + 2);

  // Set the expected version
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  fake_->Set(hps::FakeDev::Flags::kStage1NotVerified);
  fake_->Set(hps::FakeDev::Flags::kWpOff);
  fake_->Set(hps::FakeDev::Flags::kIncrementVersion);
  // Set up the version and files.
  hps_->Init(version + 1, mcu, spi1, spi2);

  // Boot the module.
  EXPECT_CALL(*metrics_,
              SendHpsTurnOnResult(hps::HpsTurnOnResult::kMcuVersionMismatch, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsUpdateDuration(hps::HpsBank::kMcuFlash, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();

  // Check that neither MCU nor SPI blobs were updated.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), len);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSpiFlash), 0);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSocRom), 0);
}

/*
 * Verify that mismatching version will update both MCU and SPI
 */
TEST_F(HPSTest, VersionUpdate) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  // Create MCU and SPI flash filenames (but do not
  // create the files themselves).
  auto mcu = temp_dir.GetPath().Append("mcu");
  auto spi1 = temp_dir.GetPath().Append("spi1");
  auto spi2 = temp_dir.GetPath().Append("spi2");

  const int len = 1024;
  CreateBlob(mcu, len);
  CreateBlob(spi1, len + 1);
  CreateBlob(spi2, len + 2);

  // Set the current version
  const uint32_t version = 0x01020304;
  fake_->SetVersion(version);
  fake_->Set(hps::FakeDev::Flags::kSpiNotVerified);
  fake_->Set(hps::FakeDev::Flags::kResetSpiVerification);
  fake_->Set(hps::FakeDev::Flags::kIncrementVersion);
  // Set up the version to be the next version.
  hps_->Init(version + 1, mcu, spi1, spi2);

  // Boot the module.
  EXPECT_CALL(*metrics_, SendHpsUpdateDuration(hps::HpsBank::kMcuFlash, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsUpdateDuration(hps::HpsBank::kSpiFlash, _))
      .Times(1);
  EXPECT_CALL(*metrics_,
              SendHpsTurnOnResult(hps::HpsTurnOnResult::kMcuVersionMismatch, _))
      .Times(1);
  EXPECT_CALL(*metrics_,
              SendHpsTurnOnResult(hps::HpsTurnOnResult::kSpiNotVerified, _))
      .Times(1);
  EXPECT_CALL(*metrics_, SendHpsTurnOnResult(hps::HpsTurnOnResult::kSuccess, _))
      .Times(1);
  hps_->Boot();

  // Check that both MCU and SPI were downloaded.
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kMcuFlash), len);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSpiFlash), len + 1);
  EXPECT_EQ(fake_->GetBankLen(hps::HpsBank::kSocRom), len + 2);
}

// Check ReadVersionFromFile reads the version correctly
TEST(ReadVersionFromFile, CorrectVersion) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath path = temp_dir.GetPath().Append("version.txt");
  base::File file(path,
                  base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  ASSERT_TRUE(file.IsValid());

  const uint32_t expected_version = 0xFFFFFFFFU;
  const std::string file_contents = "4294967295\n";
  ASSERT_EQ(
      file_contents.size(),
      file.WriteAtCurrentPos(file_contents.data(),
                             base::checked_cast<int>(file_contents.size())));

  uint32_t version;
  ASSERT_TRUE(hps::ReadVersionFromFile(path, &version));
  EXPECT_EQ(version, expected_version);
}

// Test ReadVersionFromFile behaviour when File is invalid
TEST(ReadVersionFromFile, BadFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath path = temp_dir.GetPath().Append("version.txt");

  // nonexistent file
  uint32_t version;
  EXPECT_FALSE(hps::ReadVersionFromFile(path, &version));

  // empty file
  base::File file(path,
                  base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  ASSERT_TRUE(file.IsValid());
  EXPECT_FALSE(hps::ReadVersionFromFile(path, &version));
}

}  // namespace hps
