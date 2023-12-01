// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/modem_flasher.h"

#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <chromeos/switches/modemfwd_switches.h>
#include <gtest/gtest.h>

#include "modemfwd/firmware_directory_stub.h"
#include "modemfwd/mock_journal.h"
#include "modemfwd/mock_metrics.h"
#include "modemfwd/mock_modem.h"
#include "modemfwd/mock_notification_manager.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Mock;
using ::testing::Return;

namespace modemfwd {

namespace {

constexpr char kDeviceId1[] = "device:id:1";
constexpr char kEquipmentId1[] = "equipment_id_1";

constexpr char kMainFirmware1Path[] = "main_fw_1.fls";
constexpr char kMainFirmware1Version[] = "versionA";

constexpr char kMainFirmware2Path[] = "main_fw_2.fls";
constexpr char kMainFirmware2Version[] = "versionB";

constexpr char kOemFirmware1Path[] = "oem_cust_1.fls";
constexpr char kOemFirmware1Version[] = "6000.1";

constexpr char kOemFirmware2Path[] = "oem_cust_2.fls";
constexpr char kOemFirmware2Version[] = "6000.2";

constexpr char kCarrier1[] = "uuid_1";
constexpr char kCarrier1Mvno[] = "uuid_1_1";
constexpr char kCarrier1Firmware1Path[] = "carrier_1_fw_1.fls";
constexpr char kCarrier1Firmware1Version[] = "v1.00";
constexpr char kCarrier1Firmware2Path[] = "carrier_1_fw_2.fls";
constexpr char kCarrier1Firmware2Version[] = "v1.10";

constexpr char kCarrier2[] = "uuid_2";
constexpr char kCarrier2Firmware1Path[] = "carrier_2_fw_1.fls";
constexpr char kCarrier2Firmware1Version[] = "4500.15.65";

constexpr char kGenericCarrierFirmware1Path[] = "generic_fw_1.fls";
constexpr char kGenericCarrierFirmware1Version[] = "2017-10-13";
constexpr char kGenericCarrierFirmware2Path[] = "generic_fw_2.fls";
constexpr char kGenericCarrierFirmware2Version[] = "2017-10-14";

// Associated payloads
constexpr char kApFirmwareTag[] = "ap";
constexpr char kApFirmware1Path[] = "ap_firmware";
constexpr char kApFirmware1Version[] = "abc.a40";

constexpr char kApFirmware2Path[] = "ap_firmware_2";
constexpr char kApFirmware2Version[] = "def.g50";

constexpr char kDevFirmwareTag[] = "dev";
constexpr char kDevFirmwarePath[] = "dev_firmware";
constexpr char kDevFirmwareVersion[] = "000.012";

}  // namespace

class ModemFlasherTest : public ::testing::Test {
 public:
  ModemFlasherTest() {
    firmware_directory_ =
        std::make_unique<FirmwareDirectoryStub>(base::FilePath());

    auto journal = std::make_unique<MockJournal>();
    journal_ = journal.get();

    notification_mgr_ = std::make_unique<MockNotificationManager>();
    mock_metrics_ = std::make_unique<MockMetrics>();
    modem_flasher_ = std::make_unique<ModemFlasher>(
        firmware_directory_.get(), std::move(journal), notification_mgr_.get(),
        mock_metrics_.get());

    only_main_ = {kFwMain};
    only_carrier_ = {kFwCarrier};
  }

 protected:
  void AddMainFirmwareFile(const std::string& device_id,
                           const base::FilePath& rel_firmware_path,
                           const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddMainFirmware(kDeviceId1, firmware_info);
  }

  void AddAssocFirmwareFile(const std::string& main_fw_path,
                            const std::string& firmware_id,
                            const base::FilePath& rel_firmware_path,
                            const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddAssocFirmware(main_fw_path, firmware_id,
                                          firmware_info);
  }

  void AddMainFirmwareFileForCarrier(const std::string& device_id,
                                     const std::string& carrier_name,
                                     const base::FilePath& rel_firmware_path,
                                     const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddMainFirmwareForCarrier(kDeviceId1, carrier_name,
                                                   firmware_info);
  }

  void AddOemFirmwareFile(const std::string& device_id,
                          const base::FilePath& rel_firmware_path,
                          const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddOemFirmware(kDeviceId1, firmware_info);
  }

  void AddOemFirmwareFileForCarrier(const std::string& device_id,
                                    const std::string& carrier_name,
                                    const base::FilePath& rel_firmware_path,
                                    const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddOemFirmwareForCarrier(kDeviceId1, carrier_name,
                                                  firmware_info);
  }

  void AddCarrierFirmwareFile(const std::string& device_id,
                              const std::string& carrier_name,
                              const base::FilePath& rel_firmware_path,
                              const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddCarrierFirmware(kDeviceId1, carrier_name,
                                            firmware_info);
  }

  std::unique_ptr<MockModem> GetDefaultModem() {
    auto modem = std::make_unique<MockModem>();
    ON_CALL(*modem, GetDeviceId()).WillByDefault(Return(kDeviceId1));
    ON_CALL(*modem, GetEquipmentId()).WillByDefault(Return(kEquipmentId1));
    ON_CALL(*modem, GetCarrierId()).WillByDefault(Return(kCarrier1));
    ON_CALL(*modem, GetMainFirmwareVersion())
        .WillByDefault(Return(kMainFirmware1Version));
    ON_CALL(*modem, GetOemFirmwareVersion())
        .WillByDefault(Return(kOemFirmware1Version));
    ON_CALL(*modem, GetCarrierFirmwareId()).WillByDefault(Return(""));
    ON_CALL(*modem, GetCarrierFirmwareVersion()).WillByDefault(Return(""));

    // Since the equipment ID is the main identifier we should always expect
    // to want to know what it is.
    EXPECT_CALL(*modem, GetEquipmentId()).Times(AtLeast(1));
    return modem;
  }

  void SetCarrierFirmwareInfo(MockModem* modem,
                              const std::string& carrier_id,
                              const std::string& version) {
    ON_CALL(*modem, GetCarrierFirmwareId()).WillByDefault(Return(carrier_id));
    ON_CALL(*modem, GetCarrierFirmwareVersion()).WillByDefault(Return(version));
  }

  brillo::ErrorPtr err;
  MockJournal* journal_;
  std::unique_ptr<ModemFlasher> modem_flasher_;
  std::unique_ptr<MockNotificationManager> notification_mgr_;
  std::unique_ptr<MockMetrics> mock_metrics_;
  // helpers for the mock_journal calls
  std::vector<std::string> only_main_;
  std::vector<std::string> only_carrier_;

 private:
  std::unique_ptr<FirmwareDirectoryStub> firmware_directory_;
};

TEST_F(ModemFlasherTest, NothingToFlash) {
  auto modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, FlashMainFirmware) {
  base::FilePath new_firmware(kMainFirmware2Path);
  AddMainFirmwareFile(kDeviceId1, new_firmware, kMainFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> main_cfg = {
      {kFwMain, new_firmware, kMainFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(main_cfg)).WillOnce(Return(true));
  EXPECT_CALL(*mock_metrics_, SendFwFlashTime()).Times(1);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, FlashMainFirmwareEmptyCarrier) {
  base::FilePath new_firmware(kMainFirmware2Path);
  AddMainFirmwareFile(kDeviceId1, new_firmware, kMainFirmware2Version);

  auto modem = GetDefaultModem();
  ON_CALL(*modem, GetCarrierId()).WillByDefault(Return(""));

  // Flash the main fw even when the carrier is unknown
  std::vector<FirmwareConfig> main_cfg = {
      {kFwMain, new_firmware, kMainFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(main_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, SkipSameMainVersion) {
  base::FilePath firmware(kMainFirmware1Path);
  AddMainFirmwareFile(kDeviceId1, firmware, kMainFirmware1Version);

  auto modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, SkipSameOemVersion) {
  base::FilePath firmware(kOemFirmware1Path);
  AddOemFirmwareFile(kDeviceId1, firmware, kOemFirmware1Version);

  auto modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetOemFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, UpgradeOemFirmware) {
  base::FilePath new_firmware(kOemFirmware2Path);
  AddOemFirmwareFile(kDeviceId1, new_firmware, kOemFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> oem_cfg = {
      {kFwOem, new_firmware, kOemFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetOemFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(oem_cfg)).WillOnce(Return(true));
  EXPECT_CALL(*mock_metrics_, SendFwFlashTime()).Times(1);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, UpgradeCarrierFirmware) {
  base::FilePath new_firmware(kCarrier1Firmware2Path);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1, new_firmware,
                         kCarrier1Firmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_cfg = {
      {kFwCarrier, new_firmware, kCarrier1Firmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, SwitchCarrierFirmwareForSimHotSwap) {
  base::FilePath original_firmware(kCarrier1Firmware1Path);
  base::FilePath other_firmware(kCarrier2Firmware1Path);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1, original_firmware,
                         kCarrier1Firmware1Version);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier2, other_firmware,
                         kCarrier2Firmware1Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_other_cfg = {
      {kFwCarrier, other_firmware, kCarrier2Firmware1Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(kCarrier2));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_other_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // After the modem reboots, the helper hopefully reports the new carrier.
  SetCarrierFirmwareInfo(modem.get(), kCarrier2, kCarrier2Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // Suppose we swap the SIM back to the first one. Then we should try to
  // flash the first firmware again.
  modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_orig_cfg = {
      {kFwCarrier, original_firmware, kCarrier1Firmware1Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier2, kCarrier2Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_orig_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, BlockAfterMainFlashFailure) {
  base::FilePath new_firmware(kMainFirmware2Path);
  AddMainFirmwareFile(kDeviceId1, new_firmware, kMainFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> main_cfg = {
      {kFwMain, new_firmware, kMainFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(main_cfg)).WillRepeatedly(Return(false));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_NE(err.get(), nullptr);

  // ModemFlasher retries once on a failure, so fail twice.
  modem = GetDefaultModem();
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_NE(err.get(), nullptr);

  // Here the modem would reboot, but ModemFlasher should keep track of its
  // IMEI and ensure we don't even check the main firmware version or
  // carrier.
  modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(0);
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(0);
  EXPECT_CALL(*modem, GetCarrierId()).Times(0);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  std::cout << err->GetCode() << " " << err->GetMessage() << "\n";
  ASSERT_NE(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, BlockAfterCarrierFlashFailure) {
  base::FilePath new_firmware(kCarrier1Firmware2Path);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1, new_firmware,
                         kCarrier1Firmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_cfg = {
      {kFwCarrier, new_firmware, kCarrier1Firmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_cfg))
      .WillRepeatedly(Return(false));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_NE(err.get(), nullptr);

  // ModemFlasher retries once on a failure, so fail twice.
  modem = GetDefaultModem();
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_NE(err.get(), nullptr);

  modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(0);
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(0);
  EXPECT_CALL(*modem, GetCarrierId()).Times(0);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_NE(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, RefuseToFlashMainFirmwareTwice) {
  base::FilePath new_firmware(kMainFirmware2Path);
  AddMainFirmwareFile(kDeviceId1, new_firmware, kMainFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> main_cfg = {
      {kFwMain, new_firmware, kMainFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(main_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // We've had issues in the past where the firmware version is updated
  // but the modem still reports the old version string. Refuse to flash
  // the main firmware twice because that should never be correct behavior
  // in one session. Otherwise, we might try to flash the main firmware
  // over and over.
  modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(0);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, RefuseToFlashOemFirmwareTwice) {
  base::FilePath new_firmware(kOemFirmware2Path);
  AddOemFirmwareFile(kDeviceId1, new_firmware, kOemFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> oem_cfg = {
      {kFwOem, new_firmware, kOemFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetOemFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(oem_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // Assume that the modem fails to return properly the new version.
  modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetOemFirmwareVersion()).Times(0);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, RefuseToFlashCarrierFirmwareTwice) {
  base::FilePath new_firmware(kCarrier1Firmware2Path);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1, new_firmware,
                         kCarrier1Firmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_cfg = {
      {kFwCarrier, new_firmware, kCarrier1Firmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // Assume the carrier firmware doesn't have an updated version string in it,
  // i.e. the modem will return the old version string even if it's been
  // updated.
  modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, RefuseToReflashCarrierAcrossHotSwap) {
  // Upgrade carrier firmware.
  base::FilePath new_firmware(kCarrier1Firmware2Path);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1, new_firmware,
                         kCarrier1Firmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_cfg = {
      {kFwCarrier, new_firmware, kCarrier1Firmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // Switch carriers, but there won't be firmware for the new one.
  modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(kCarrier2));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware2Version);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // Suppose we swap the SIM back to the first one. We should not flash
  // firmware that we already know we successfully flashed.
  modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware2Version);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, UpgradeGenericFirmware) {
  base::FilePath new_firmware(kGenericCarrierFirmware2Path);
  AddCarrierFirmwareFile(kDeviceId1, FirmwareDirectory::kGenericCarrierId,
                         new_firmware, kGenericCarrierFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_cfg = {
      {kFwCarrier, new_firmware, kGenericCarrierFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), FirmwareDirectory::kGenericCarrierId,
                         kGenericCarrierFirmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, SkipSameGenericFirmware) {
  base::FilePath generic_firmware(kGenericCarrierFirmware1Path);
  AddCarrierFirmwareFile(kDeviceId1, FirmwareDirectory::kGenericCarrierId,
                         generic_firmware, kGenericCarrierFirmware1Version);

  auto modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), FirmwareDirectory::kGenericCarrierId,
                         kGenericCarrierFirmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, TwoCarriersUsingGenericFirmware) {
  base::FilePath generic_firmware(kGenericCarrierFirmware1Path);
  AddCarrierFirmwareFile(kDeviceId1, FirmwareDirectory::kGenericCarrierId,
                         generic_firmware, kGenericCarrierFirmware1Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_cfg = {
      {kFwCarrier, generic_firmware, kGenericCarrierFirmware1Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(carrier_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // When we try to flash again and the modem reports a different carrier,
  // we should expect that the ModemFlasher refuses to flash the same firmware,
  // since there is generic firmware and no carrier has its own firmware.
  modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), FirmwareDirectory::kGenericCarrierId,
                         kGenericCarrierFirmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, HotSwapWithGenericFirmware) {
  base::FilePath original_firmware(kGenericCarrierFirmware1Path);
  base::FilePath other_firmware(kCarrier2Firmware1Path);
  AddCarrierFirmwareFile(kDeviceId1, FirmwareDirectory::kGenericCarrierId,
                         original_firmware, kGenericCarrierFirmware1Version);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier2, other_firmware,
                         kCarrier2Firmware1Version);

  // Even though there is generic firmware, we should try to use specific
  // ones first if they exist.
  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_other_cfg = {
      {kFwCarrier, other_firmware, kCarrier2Firmware1Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(kCarrier2));
  SetCarrierFirmwareInfo(modem.get(), FirmwareDirectory::kGenericCarrierId,
                         kGenericCarrierFirmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_other_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // Reboot the modem.
  SetCarrierFirmwareInfo(modem.get(), kCarrier2, kCarrier2Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // Suppose we swap the SIM back to the first one. Then we should try to
  // flash the generic firmware again.
  modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_orig_cfg = {
      {kFwCarrier, original_firmware, kGenericCarrierFirmware1Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier2, kCarrier2Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_orig_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, WritesToJournal) {
  base::FilePath new_firmware(kMainFirmware2Path);
  AddMainFirmwareFile(kDeviceId1, new_firmware, kMainFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> main_cfg = {
      {kFwMain, new_firmware, kMainFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(main_cfg)).WillOnce(Return(true));
  EXPECT_CALL(*journal_, MarkStartOfFlashingFirmware(only_main_, kDeviceId1, _))
      .Times(1);
  EXPECT_CALL(*journal_, MarkEndOfFlashingFirmware(kDeviceId1, _)).Times(1);
  base::OnceClosure cb =
      modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
  // The cleanup callback marks the end of flashing the firmware.
  ASSERT_FALSE(cb.is_null());
  std::move(cb).Run();
}

TEST_F(ModemFlasherTest, WritesToJournalOnFailure) {
  base::FilePath new_firmware(kMainFirmware2Path);
  AddMainFirmwareFile(kDeviceId1, new_firmware, kMainFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> main_cfg = {
      {kFwMain, new_firmware, kMainFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(main_cfg)).WillOnce(Return(false));
  EXPECT_CALL(*journal_, MarkStartOfFlashingFirmware(only_main_, kDeviceId1, _))
      .Times(1);
  EXPECT_CALL(*journal_, MarkEndOfFlashingFirmware(kDeviceId1, _)).Times(1);
  // There should be no journal cleanup after the flashing fails.
  base::OnceClosure cb =
      modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_NE(err.get(), nullptr);
  ASSERT_TRUE(cb.is_null());
}

TEST_F(ModemFlasherTest, WritesCarrierSwitchesToJournal) {
  base::FilePath original_firmware(kCarrier1Firmware1Path);
  base::FilePath other_firmware(kCarrier2Firmware1Path);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1, original_firmware,
                         kCarrier1Firmware1Version);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier2, other_firmware,
                         kCarrier2Firmware1Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_other_cfg = {
      {kFwCarrier, other_firmware, kCarrier2Firmware1Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(kCarrier2));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_other_cfg)).WillOnce(Return(true));
  EXPECT_CALL(*journal_,
              MarkStartOfFlashingFirmware(only_carrier_, kDeviceId1, kCarrier2))
      .Times(1);
  EXPECT_CALL(*journal_, MarkEndOfFlashingFirmware(kDeviceId1, kCarrier2))
      .Times(1);
  base::OnceClosure cb =
      modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
  ASSERT_FALSE(cb.is_null());
  std::move(cb).Run();

  // After the modem reboots, the helper hopefully reports the new carrier.
  SetCarrierFirmwareInfo(modem.get(), kCarrier2, kCarrier2Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
  ASSERT_TRUE(cb.is_null());

  // Suppose we swap the SIM back to the first one. Then we should try to
  // flash the first firmware again.
  modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_orig_cfg = {
      {kFwCarrier, original_firmware, kCarrier1Firmware1Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier2, kCarrier2Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_orig_cfg)).WillOnce(Return(true));
  EXPECT_CALL(*journal_,
              MarkStartOfFlashingFirmware(only_carrier_, kDeviceId1, kCarrier1))
      .Times(1);
  EXPECT_CALL(*journal_, MarkEndOfFlashingFirmware(kDeviceId1, kCarrier1))
      .Times(1);
  cb = modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
  ASSERT_FALSE(cb.is_null());
  std::move(cb).Run();
}

TEST_F(ModemFlasherTest, CarrierSwitchingMainFirmware) {
  base::FilePath original_main(kMainFirmware1Path);
  AddMainFirmwareFile(kDeviceId1, original_main, kMainFirmware1Version);
  base::FilePath other_main(kMainFirmware2Path);
  AddMainFirmwareFileForCarrier(kDeviceId1, kCarrier2, other_main,
                                kMainFirmware2Version);

  base::FilePath original_oem(kOemFirmware1Path);
  AddOemFirmwareFile(kDeviceId1, original_oem, kOemFirmware1Version);
  base::FilePath other_oem(kOemFirmware2Path);
  AddOemFirmwareFileForCarrier(kDeviceId1, kCarrier2, other_oem,
                               kOemFirmware2Version);

  base::FilePath original_carrier(kCarrier1Firmware1Path);
  base::FilePath other_carrier(kCarrier2Firmware1Path);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1, original_carrier,
                         kCarrier1Firmware1Version);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier2, other_carrier,
                         kCarrier2Firmware1Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> other_cfg = {
      {kFwMain, other_main, kMainFirmware2Version},
      {kFwOem, other_oem, kOemFirmware2Version},
      {kFwCarrier, other_carrier, kCarrier2Firmware1Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(kCarrier2));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(other_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);

  // Switch the carrier back and make sure we flash all firmware blobs
  // again.
  modem = GetDefaultModem();
  std::vector<FirmwareConfig> orig_cfg = {
      {kFwMain, original_main, kMainFirmware1Version},
      {kFwOem, original_oem, kOemFirmware1Version},
      {kFwCarrier, original_carrier, kCarrier1Firmware1Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(kMainFirmware2Version));
  EXPECT_CALL(*modem, GetOemFirmwareVersion())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(kOemFirmware2Version));
  EXPECT_CALL(*modem, GetCarrierId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(kCarrier1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier2, kCarrier2Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(orig_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, InhibitDuringMainFirmwareFlash) {
  base::FilePath new_firmware(kMainFirmware2Path);
  AddMainFirmwareFile(kDeviceId1, new_firmware, kMainFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> main_cfg = {
      {kFwMain, new_firmware, kMainFirmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(main_cfg)).WillOnce(Return(true));
  EXPECT_CALL(*modem, SetInhibited(true)).WillOnce(Return(true));
  EXPECT_CALL(*modem, SetInhibited(false)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, InhibitDuringCarrierFirmwareFlash) {
  base::FilePath new_firmware(kCarrier1Firmware2Path);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1, new_firmware,
                         kCarrier1Firmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> carrier_cfg = {
      {kFwCarrier, new_firmware, kCarrier1Firmware2Version}};
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  SetCarrierFirmwareInfo(modem.get(), kCarrier1, kCarrier1Firmware1Version);
  EXPECT_CALL(*modem, FlashFirmwares(carrier_cfg)).WillOnce(Return(true));
  EXPECT_CALL(*modem, SetInhibited(true)).WillOnce(Return(true));
  EXPECT_CALL(*modem, SetInhibited(false)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, SkipCarrierWithTwoUuidSameFirmware) {
  base::FilePath current_firmware(kCarrier1Firmware1Path);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1, current_firmware,
                         kCarrier1Firmware2Version);
  AddCarrierFirmwareFile(kDeviceId1, kCarrier1Mvno, current_firmware,
                         kCarrier1Firmware2Version);

  auto modem = GetDefaultModem();
  EXPECT_CALL(*modem, GetDeviceId()).Times(AtLeast(1));
  EXPECT_CALL(*modem, GetCarrierFirmwareVersion()).Times(AtLeast(1));
  // The modem will say that the currently flashed firmware has the carrier UUID
  // KCarrier1Mvno while the current carrier UUID is always returned as
  // kCarrier1.
  SetCarrierFirmwareInfo(modem.get(), kCarrier1Mvno, kCarrier1Firmware2Version);
  EXPECT_CALL(*modem, FlashFirmwares(_)).Times(0);
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, FlashSingleAssociatedFirmware) {
  const base::FilePath main_fw_path(kMainFirmware2Path);
  AddMainFirmwareFile(kDeviceId1, main_fw_path, kMainFirmware2Version);
  const base::FilePath ap_fw_path(kApFirmware1Path);
  AddAssocFirmwareFile(kMainFirmware2Path, kApFirmwareTag, ap_fw_path,
                       kApFirmware1Version);
  const base::FilePath dev_fw_path(kDevFirmwarePath);
  AddAssocFirmwareFile(kMainFirmware2Path, kDevFirmwareTag, dev_fw_path,
                       kDevFirmwareVersion);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> main_cfg = {
      {kFwMain, main_fw_path, kMainFirmware2Version},
      {kApFirmwareTag, ap_fw_path, kApFirmware1Version},
      {kDevFirmwareTag, dev_fw_path, kDevFirmwareVersion}};
  EXPECT_CALL(*modem, FlashFirmwares(main_cfg)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

TEST_F(ModemFlasherTest, UpgradeAssocFirmwareOnly) {
  const base::FilePath main_fw_path(kMainFirmware1Path);
  AddMainFirmwareFile(kDeviceId1, main_fw_path, kMainFirmware1Version);
  const base::FilePath ap_fw_path(kApFirmware2Path);
  AddAssocFirmwareFile(kMainFirmware1Path, kApFirmwareTag, ap_fw_path,
                       kApFirmware2Version);

  auto modem = GetDefaultModem();
  std::vector<FirmwareConfig> config = {
      {kApFirmwareTag, ap_fw_path, kApFirmware2Version}};
  EXPECT_CALL(*modem, GetMainFirmwareVersion()).Times(AtLeast(1));
  EXPECT_CALL(*modem, FlashFirmwares(config)).WillOnce(Return(true));
  modem_flasher_->TryFlash(modem.get(), scoped_refptr<dbus::Bus>(), &err);
  ASSERT_EQ(err.get(), nullptr);
}

}  // namespace modemfwd
