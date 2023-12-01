/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdint.h>

#include <iostream>
#include <string>
#include <vector>

#include <base/containers/span.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/synchronization/waitable_event.h>
#include <base/test/task_environment.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <brillo/flag_helper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libudev.h>
#include <re2/re2.h>

#include "cros-camera/future.h"
#include "cros-camera/udev_watcher.h"
#include "hal/usb/tests/usb_dfu_device.h"

namespace cros::tests {

class CameraDfuTestEnvironment;

namespace {

constexpr size_t kDfuFileSuffixSize = 16;
constexpr base::TimeDelta kModeSwitchTimeout = base::Seconds(1);
constexpr base::TimeDelta kFirmwareDownloadTimeout = base::Seconds(15);

CameraDfuTestEnvironment* g_env;

}  // namespace

class CameraDfuTestEnvironment : public ::testing::Environment,
                                 public UdevWatcher::Observer {
 public:
  CameraDfuTestEnvironment(uint16_t app_vid,
                           uint16_t app_pid,
                           uint16_t dfu_vid,
                           uint16_t dfu_pid,
                           uint16_t fw1_version,
                           uint16_t fw2_version,
                           std::vector<unsigned char> fw1_blob,
                           std::vector<unsigned char> fw2_blob,
                           uint32_t quirks)
      : app_vid_(app_vid),
        app_pid_(app_pid),
        dfu_vid_(dfu_vid),
        dfu_pid_(dfu_pid),
        fw1_version_(fw1_version),
        fw2_version_(fw2_version),
        fw1_blob_(std::move(fw1_blob)),
        fw2_blob_(std::move(fw2_blob)),
        quirks_(quirks),
        usb_context_(UsbContext::Create()),
        udev_watcher_(this, "usb"),
        udev_watcher_thread_("UdevWatcherThread") {}

  void SetUp() override {
    // Validate inputs.
    ASSERT_FALSE(app_vid_ == dfu_vid_ && app_pid_ == dfu_pid_)
        << "VID:PIDs in APP mode and DFU mode should be different";
    ASSERT_NE(fw1_version_, fw2_version_)
        << "Testing firmware versions should be different";
    ASSERT_NE(fw1_blob_, fw2_blob_);
    // TODO(kamesan): Validate the DFU file suffix content.
    ASSERT_GT(fw1_blob_.size(), kDfuFileSuffixSize);
    ASSERT_GT(fw2_blob_.size(), kDfuFileSuffixSize);
    fw1_blob_.resize(fw1_blob_.size() - kDfuFileSuffixSize);
    fw2_blob_.resize(fw2_blob_.size() - kDfuFileSuffixSize);

    ASSERT_NE(usb_context_, nullptr);

    // Initialize |udev_watcher_| on |udev_watcher_thread_| to monitor target
    // device presence.
    ASSERT_TRUE(udev_watcher_thread_.Start());
    ASSERT_TRUE(udev_watcher_.Start(udev_watcher_thread_.task_runner()));
    auto future = Future<bool>::Create(nullptr);
    udev_watcher_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](UdevWatcher* udev_watcher, scoped_refptr<Future<bool>> future) {
              future->Set(udev_watcher->EnumerateExistingDevices());
            },
            &udev_watcher_, future));
    ASSERT_TRUE(future->Get()) << "Failed to enumerate udev devices";

    // Check target device presence and print info.
    ASSERT_TRUE(PutDeviceIntoAppMode()) << "Device not found";
    ASSERT_EQ(GetDfuModeDevice(), nullptr)
        << "Found conflicting device in DFU mode";
    auto app_dev = GetAppModeDevice();
    ASSERT_NE(app_dev, nullptr);
    orig_fw_version_ = app_dev->bcd_device();

    // Backup current firmware
    EXPECT_TRUE(BackupDeviceFirmware());

    LOG(INFO) << base::StringPrintf("APP mode VID:PID=%04x:%04x", app_vid_,
                                    app_pid_);
    LOG(INFO) << base::StringPrintf("DFU mode VID:PID=%04x:%04x", dfu_vid_,
                                    dfu_pid_);
    LOG(INFO) << base::StringPrintf("Testing firmware #1 version=%04x size=%zu",
                                    fw1_version_, fw1_blob_.size());
    LOG(INFO) << base::StringPrintf("Testing firmware #2 version=%04x size=%zu",
                                    fw2_version_, fw2_blob_.size());
    LOG(INFO) << base::StringPrintf("Device version=%04x", orig_fw_version_);
    LOG(INFO) << base::StringPrintf("Quirks=0x%x", quirks_);
  }

  void TearDown() override {
    // Try restore the device back to the original firmware version.
    EXPECT_TRUE(RestoreDeviceFirmware());
    EXPECT_TRUE(PutDeviceIntoAppMode());
    udev_watcher_thread_.Stop();
  }

  bool BackupDeviceFirmware() {
    if (!PutDeviceIntoDfuMode()) {
      LOG(ERROR) << "Put device into DFU mode failed";
      return false;
    }
    auto dfu_dev = GetDfuModeDevice();
    if (dfu_dev == nullptr) {
      LOG(ERROR) << "DFU device is NULL";
      return false;
    }
    if (fw1_version_ == orig_fw_version_) {
      LOG(INFO) << "fw1 equals to current fw, backup from fw1";
      ptr_orig_fw_blob_ = &fw1_blob_;
    } else if (fw2_version_ == orig_fw_version_) {
      LOG(INFO) << "fw2 equals to current fw, backup from fw2";
      ptr_orig_fw_blob_ = &fw2_blob_;
    } else {
      if (dfu_dev->attributes() & cros::kCanUpload) {
        orig_fw_blob_ = dfu_dev->Upload();
        if (orig_fw_blob_.size() == 0) {
          LOG(ERROR) << "Failed to upload device firmware to host";
          return false;
        }
        LOG(INFO) << base::StringPrintf(
            "Backup current firmware version=%04x size=%zu", orig_fw_version_,
            orig_fw_blob_.size());
        ptr_orig_fw_blob_ = &orig_fw_blob_;
      } else {
        LOG(WARNING) << "No backup firmware since device doesn't support "
                        "upload and the original firmware version doesn't "
                        "match fw1 or fw2";
        ptr_orig_fw_blob_ = nullptr;
        return true;
      }
    }
    return true;
  }

  bool RestoreDeviceFirmware() {
    if (!ptr_orig_fw_blob_) {
      LOG(WARNING) << "No backup firmware to restore the device. "
                      "Device firmware may be changed!";
      return true;
    }
    LOG(INFO) << base::StringPrintf("Original firmware version=%04x size=%zu",
                                    orig_fw_version_,
                                    ptr_orig_fw_blob_->size());
    if (!g_env->PutDeviceIntoDfuMode()) {
      LOG(ERROR) << "Failed to put device into DFU mode!";
      return false;
    }
    base::ElapsedTimer timer;
    {
      auto dfu_dev = g_env->GetDfuModeDevice();
      if (dfu_dev == nullptr) {
        LOG(ERROR) << "DFU device is NULL";
        return false;
      }
      if (!dfu_dev->Download(*ptr_orig_fw_blob_)) {
        LOG(ERROR) << "Failed to download Firmware";
        return false;
      }
      if (!dfu_dev->Attach()) {
        LOG(ERROR) << "Failed to attach DFU";
        return false;
      }
    }
    base::TimeDelta download_time = timer.Elapsed();
    LOG(INFO) << "Restoring firmware took " << download_time;
    return true;
  }

  std::unique_ptr<UsbDfuDevice> GetAppModeDevice() {
    return usb_context_->CreateUsbDfuDevice(app_vid_, app_pid_, quirks_);
  }

  std::unique_ptr<UsbDfuDevice> GetDfuModeDevice() {
    return usb_context_->CreateUsbDfuDevice(dfu_vid_, dfu_pid_, quirks_);
  }

  bool PutDeviceIntoAppMode() {
    if (!WaitForDeviceIntoAppMode()) {
      auto dfu_dev = g_env->GetDfuModeDevice();
      if (!dfu_dev || !dfu_dev->Attach() || !WaitForDeviceIntoAppMode()) {
        return false;
      }
    }
    return true;
  }

  bool PutDeviceIntoDfuMode() {
    if (!WaitForDeviceIntoDfuMode()) {
      auto app_dev = g_env->GetAppModeDevice();
      if (!app_dev || !app_dev->Detach() || !WaitForDeviceIntoDfuMode()) {
        return false;
      }
    }
    return true;
  }

  bool WaitForDeviceIntoAppMode() {
    return app_dev_arrived_.TimedWait(kModeSwitchTimeout);
  }

  bool WaitForDeviceIntoDfuMode() {
    return dfu_dev_arrived_.TimedWait(kModeSwitchTimeout);
  }

  void OnDeviceAdded(ScopedUdevDevicePtr device) override {
    DCHECK(udev_watcher_thread_.task_runner()->BelongsToCurrentThread());
    const char* vid_str =
        udev_device_get_sysattr_value(device.get(), "idVendor");
    const char* pid_str =
        udev_device_get_sysattr_value(device.get(), "idProduct");
    const char* path = udev_device_get_devnode(device.get());
    uint32_t vid, pid;
    if (!vid_str || !pid_str || !path ||
        !base::HexStringToUInt(vid_str, &vid) ||
        !base::HexStringToUInt(pid_str, &pid)) {
      return;
    }
    if (vid == app_vid_ && pid == app_pid_) {
      VLOG(1) << "Added APP mode device";
      CHECK(!app_dev_arrived_.IsSignaled());
      CHECK(!dfu_dev_arrived_.IsSignaled());
      app_dev_path_ = path;
      app_dev_arrived_.Signal();
    } else if (vid == dfu_vid_ && pid == dfu_pid_) {
      VLOG(1) << "Added DFU mode device";
      CHECK(!app_dev_arrived_.IsSignaled());
      CHECK(!dfu_dev_arrived_.IsSignaled());
      dfu_dev_path_ = path;
      dfu_dev_arrived_.Signal();
    }
  }

  void OnDeviceRemoved(ScopedUdevDevicePtr device) override {
    DCHECK(udev_watcher_thread_.task_runner()->BelongsToCurrentThread());
    const char* path = udev_device_get_devnode(device.get());
    if (!path) {
      return;
    }
    if (!app_dev_path_.empty() && app_dev_path_ == path) {
      VLOG(1) << "Removed APP mode device";
      CHECK(app_dev_arrived_.IsSignaled());
      CHECK(!dfu_dev_arrived_.IsSignaled());
      app_dev_path_.clear();
      app_dev_arrived_.Reset();
    } else if (!dfu_dev_path_.empty() && dfu_dev_path_ == path) {
      VLOG(1) << "Removed DFU mode device";
      CHECK(!app_dev_arrived_.IsSignaled());
      CHECK(dfu_dev_arrived_.IsSignaled());
      dfu_dev_path_.clear();
      dfu_dev_arrived_.Reset();
    }
  }

  uint16_t orig_fw_version() const { return orig_fw_version_; }
  uint16_t fw1_version() const { return fw1_version_; }
  uint16_t fw2_version() const { return fw2_version_; }
  const std::vector<unsigned char>& fw_blob() const { return orig_fw_blob_; }
  const std::vector<unsigned char>& fw1_blob() const { return fw1_blob_; }
  const std::vector<unsigned char>& fw2_blob() const { return fw2_blob_; }

 private:
  uint16_t app_vid_;
  uint16_t app_pid_;
  uint16_t dfu_vid_;
  uint16_t dfu_pid_;

  uint16_t orig_fw_version_;
  uint16_t fw1_version_;
  uint16_t fw2_version_;
  std::vector<unsigned char> orig_fw_blob_;
  std::vector<unsigned char> fw1_blob_;
  std::vector<unsigned char> fw2_blob_;
  std::vector<unsigned char>* ptr_orig_fw_blob_;

  uint32_t quirks_;

  std::unique_ptr<UsbContext> usb_context_;

  base::WaitableEvent app_dev_arrived_;
  base::WaitableEvent dfu_dev_arrived_;
  std::string app_dev_path_;
  std::string dfu_dev_path_;
  UdevWatcher udev_watcher_;
  base::Thread udev_watcher_thread_;
};

class CameraDfuTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Some device fails consecutive download/upload operations in DFU mode.
    // Restore to APP mode for each test.
    ASSERT_TRUE(g_env->PutDeviceIntoAppMode());
  }

  // Install expected good firmware to the device and validate.
  void DownloadAndValidate(const std::vector<unsigned char>& firmware,
                           uint16_t version) {
    ASSERT_TRUE(g_env->PutDeviceIntoDfuMode());

    base::ElapsedTimer timer;
    {
      auto dfu_dev = g_env->GetDfuModeDevice();
      ASSERT_NE(dfu_dev, nullptr);
      ASSERT_TRUE(dfu_dev->Download(firmware));
      ASSERT_TRUE(dfu_dev->Attach());
    }
    base::TimeDelta download_time = timer.Elapsed();
    LOG(INFO) << "Downloading firmware took " << download_time;
    EXPECT_LE(download_time, kFirmwareDownloadTimeout);

    ASSERT_TRUE(g_env->WaitForDeviceIntoAppMode());

    // Check version is updated in APP mode.
    {
      auto app_dev = g_env->GetAppModeDevice();
      ASSERT_NE(app_dev, nullptr);
      EXPECT_EQ(app_dev->bcd_device(), version);
      ASSERT_TRUE(app_dev->Detach());
    }
    ASSERT_TRUE(g_env->WaitForDeviceIntoDfuMode());

    // Check uploaded firmware is the same as downloaded.
    {
      auto dfu_dev = g_env->GetDfuModeDevice();
      ASSERT_NE(dfu_dev, nullptr);
      if (dfu_dev->attributes() & kCanUpload) {
        std::vector<unsigned char> uploaded_firmware = dfu_dev->Upload();
        EXPECT_EQ(uploaded_firmware.size(), firmware.size());
        EXPECT_EQ(uploaded_firmware, firmware);
      }
    }

    // TODO(kamesan): Check camera functional.
  }

  // Install given firmware to the device if version doesn't match.
  void MaybeDownloadForVersion(base::span<const unsigned char> firmware,
                               uint16_t version) {
    {
      ASSERT_TRUE(g_env->PutDeviceIntoAppMode());
      auto app_dev = g_env->GetAppModeDevice();
      ASSERT_NE(app_dev, nullptr);
      if (app_dev->bcd_device() != version) {
        ASSERT_TRUE(app_dev->Detach());
        app_dev.reset();
        ASSERT_TRUE(g_env->WaitForDeviceIntoDfuMode());
        auto dfu_dev = g_env->GetDfuModeDevice();
        ASSERT_NE(dfu_dev, nullptr);
        ASSERT_TRUE(dfu_dev->Download(firmware));
        ASSERT_TRUE(dfu_dev->Attach());
        ASSERT_TRUE(g_env->WaitForDeviceIntoAppMode());
      }
    }
    {
      auto app_dev = g_env->GetAppModeDevice();
      ASSERT_NE(app_dev, nullptr);
      ASSERT_EQ(app_dev->bcd_device(), version);
    }
  }

  // Install expected bad firmware to the device and check recovery.
  void DownloadBadFirmware(base::span<const unsigned char> firmware) {
    ASSERT_TRUE(g_env->PutDeviceIntoAppMode());
    uint16_t version;
    {
      auto app_dev = g_env->GetAppModeDevice();
      ASSERT_NE(app_dev, nullptr);
      version = app_dev->bcd_device();
      ASSERT_TRUE(app_dev->Detach());
    }
    ASSERT_TRUE(g_env->WaitForDeviceIntoDfuMode());
    {
      auto dfu_dev = g_env->GetDfuModeDevice();
      ASSERT_NE(dfu_dev, nullptr);
      // Transferring bad firmware could fail halfway.
      dfu_dev->Download(firmware);
      ASSERT_TRUE(dfu_dev->Attach());
    }
    ASSERT_TRUE(g_env->WaitForDeviceIntoAppMode());
    {
      auto app_dev = g_env->GetAppModeDevice();
      ASSERT_NE(app_dev, nullptr);
      // Device should recover back to the original version.
      ASSERT_EQ(app_dev->bcd_device(), version);
    }
  }
};

TEST_F(CameraDfuTest, SwitchModes) {
  ASSERT_TRUE(g_env->PutDeviceIntoAppMode());

  constexpr int kTestIterations = 2;
  for (int i = 0; i < kTestIterations; ++i) {
    {
      auto app_dev = g_env->GetAppModeDevice();
      ASSERT_NE(app_dev, nullptr);
      EXPECT_FALSE(app_dev->is_dfu_mode());
      ASSERT_TRUE(app_dev->Detach());
    }
    ASSERT_TRUE(g_env->WaitForDeviceIntoDfuMode());
    {
      auto dfu_dev = g_env->GetDfuModeDevice();
      ASSERT_NE(dfu_dev, nullptr);
      EXPECT_TRUE(dfu_dev->is_dfu_mode());
      ASSERT_TRUE(dfu_dev->Attach());
    }
    ASSERT_TRUE(g_env->WaitForDeviceIntoAppMode());
  }
}

TEST_F(CameraDfuTest, Attributes) {
  ASSERT_TRUE(g_env->PutDeviceIntoDfuMode());
  {
    auto dfu_dev = g_env->GetDfuModeDevice();
    ASSERT_NE(dfu_dev, nullptr);
    EXPECT_TRUE(dfu_dev->attributes() & kCanDownload);
    // TODO(kamesan): Remove this check when UsbDfuDevice supports devices
    // without this bit.
    EXPECT_TRUE(dfu_dev->attributes() & kManifestationTolerant);
    LOG(INFO) << "DFU attributes: " << dfu_dev->attributes();
  }
}

TEST_F(CameraDfuTest, Upload) {
  ASSERT_TRUE(g_env->PutDeviceIntoDfuMode());
  {
    auto dfu_dev = g_env->GetDfuModeDevice();
    ASSERT_NE(dfu_dev, nullptr);
    if (!(dfu_dev->attributes() & cros::kCanUpload)) {
      GTEST_SKIP() << "Device doesn't support upload or is ignored";
    }
    std::vector<unsigned char> firmware = dfu_dev->Upload();
    EXPECT_GT(firmware.size(), 0u);
    LOG(INFO) << "Uploaded firmware of size " << firmware.size();
  }
}

TEST_F(CameraDfuTest, DownloadFirmware1) {
  DownloadAndValidate(g_env->fw1_blob(), g_env->fw1_version());
}

TEST_F(CameraDfuTest, DownloadFirmware2) {
  DownloadAndValidate(g_env->fw2_blob(), g_env->fw2_version());
}

TEST_F(CameraDfuTest, DownloadBadFirmwares1) {
  MaybeDownloadForVersion(g_env->fw2_blob(), g_env->fw2_version());
  {
    // Truncate firmware blob.
    std::vector<unsigned char> firmware = g_env->fw1_blob();
    firmware.resize(firmware.size() / 2);

    DownloadBadFirmware(firmware);
  }
  {
    // Flip one byte of the firmware blob.
    std::vector<unsigned char> firmware = g_env->fw1_blob();
    size_t byte = firmware.size() / 2;
    firmware[byte] = ~firmware[byte];

    DownloadBadFirmware(firmware);
  }
}

TEST_F(CameraDfuTest, DownloadBadFirmwares2) {
  MaybeDownloadForVersion(g_env->fw1_blob(), g_env->fw1_version());
  {
    // Truncate firmware blob.
    std::vector<unsigned char> firmware = g_env->fw2_blob();
    firmware.resize(firmware.size() / 2);

    DownloadBadFirmware(firmware);
  }
  {
    // Flip one byte of the firmware blob.
    std::vector<unsigned char> firmware = g_env->fw2_blob();
    size_t byte = firmware.size() / 2;
    firmware[byte] = ~firmware[byte];

    DownloadBadFirmware(firmware);
  }
}

}  // namespace cros::tests

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  base::CommandLine::Init(argc, argv);

  logging::LoggingSettings settings;
  logging::InitLogging(settings);

  DEFINE_string(app_mode_id, "", "USB VID:PID in APP mode");
  DEFINE_string(dfu_mode_id, "", "USB VID:PID in DFU mode");
  DEFINE_string(fw1_path, "", "Path to the testing DFU firmware file #1");
  DEFINE_string(fw1_version, "", "Version (BCD) of testing firmware #1");
  DEFINE_string(fw2_path, "", "Path to the testing DFU firmware file #2");
  DEFINE_string(fw2_version, "", "Version (BCD) of testing firmware #2");
  DEFINE_string(quirks, "", "Comma-separated device quirk strings");

  // Add a newline at the beginning of the usage text to separate the help
  // message from gtest.
  brillo::FlagHelper::Init(argc, argv,
                           "\nTest USB camera firmware update flow.");

  uint16_t app_vid, app_pid;
  if (!RE2::FullMatch(FLAGS_app_mode_id, "([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})",
                      RE2::Hex(&app_vid), RE2::Hex(&app_pid))) {
    LOG(ERROR) << "Failed to parse app_mode_id";
    return 1;
  }
  uint16_t dfu_vid, dfu_pid;
  if (!RE2::FullMatch(FLAGS_dfu_mode_id, "([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})",
                      RE2::Hex(&dfu_vid), RE2::Hex(&dfu_pid))) {
    LOG(ERROR) << "Failed to parse dfu_mode_id";
    return 1;
  }

  uint16_t fw1_version, fw2_version;
  if (!RE2::FullMatch(FLAGS_fw1_version, "([0-9A-Fa-f]{4})",
                      RE2::Hex(&fw1_version))) {
    LOG(ERROR) << "Failed to parse fw1_version";
    return 1;
  }
  if (!RE2::FullMatch(FLAGS_fw2_version, "([0-9A-Fa-f]{4})",
                      RE2::Hex(&fw2_version))) {
    LOG(ERROR) << "Failed to parse fw2_version";
    return 1;
  }

  std::string fw1_blob, fw2_blob;
  if (!base::ReadFileToString(base::FilePath(FLAGS_fw1_path), &fw1_blob)) {
    LOG(ERROR) << "Failed to read firmware file from fw1_path";
    return 1;
  }
  if (!base::ReadFileToString(base::FilePath(FLAGS_fw2_path), &fw2_blob)) {
    LOG(ERROR) << "Failed to read firmware file from fw2_path";
    return 1;
  }

  uint32_t quirks = 0;
  for (const std::string& quirk_str : base::SplitString(
           FLAGS_quirks, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL)) {
    if (quirk_str == "detach-for-attach") {
      quirks |= cros::kDfuQuirkDetachForAttach;
    } else if (quirk_str == "ignore-upload") {
      quirks |= cros::kDfuQuirkIgnoreUpload;
    } else {
      LOG(ERROR) << "Unknown quirk: " << quirk_str;
      return 1;
    }
  }

  cros::tests::g_env = new cros::tests::CameraDfuTestEnvironment(
      app_vid, app_pid, dfu_vid, dfu_pid, fw1_version, fw2_version,
      std::vector<unsigned char>(fw1_blob.begin(), fw1_blob.end()),
      std::vector<unsigned char>(fw2_blob.begin(), fw2_blob.end()), quirks);
  ::testing::AddGlobalTestEnvironment(cros::tests::g_env);

  return RUN_ALL_TESTS();
}
