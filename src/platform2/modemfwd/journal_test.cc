// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/journal.h"

#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <chromeos/switches/modemfwd_switches.h>
#include <gtest/gtest.h>

#include "modemfwd/firmware_directory_stub.h"
#include "modemfwd/mock_modem_helper.h"
#include "modemfwd/modem_helper_directory_stub.h"
#include "modemfwd/scoped_temp_file.h"

using ::testing::_;
using ::testing::Return;

namespace modemfwd {

namespace {

constexpr char kDeviceId[] = "foobar";
constexpr char kCarrierId[] = "carrier";

constexpr char kMainFirmwarePath[] = "main_firmware.fls";
constexpr char kMainFirmwareVersion[] = "1.0";

constexpr char kOemFirmwarePath[] = "oem_cust.fls";
constexpr char kOemFirmwareVersion[] = "1.0";

constexpr char kCarrierFirmwarePath[] = "carrier_firmware.fls";
constexpr char kCarrierFirmwareVersion[] = "1.0";

// Associated payloads
constexpr char kApFirmwareTag[] = "ap";
constexpr char kApFirmwarePath[] = "ap_firmware";
constexpr char kApFirmwareVersion[] = "abc.a40";

constexpr char kDevFirmwareTag[] = "dev";
constexpr char kDevFirmwarePath[] = "dev_firmware";
constexpr char kDevFirmwareVersion[] = "000.012";

}  // namespace

class JournalTest : public ::testing::Test {
 public:
  JournalTest()
      : journal_file_(ScopedTempFile::Create()),
        firmware_directory_(new FirmwareDirectoryStub(base::FilePath())),
        modem_helper_directory_(new ModemHelperDirectoryStub) {
    CHECK(journal_file_);
    EXPECT_CALL(modem_helper_, GetFirmwareInfo(_, _)).Times(0);
    modem_helper_directory_->AddHelper(kDeviceId, &modem_helper_);
  }

 protected:
  void SetUpJournal(const std::string& journal_text) {
    CHECK_EQ(base::WriteFile(journal_file_->path(), journal_text.data(),
                             journal_text.size()),
             journal_text.size());
  }

  std::unique_ptr<Journal> GetJournal() {
    return OpenJournal(journal_file_->path(), firmware_directory_.get(),
                       modem_helper_directory_.get());
  }

  void AddMainFirmwareFile(const base::FilePath& rel_firmware_path,
                           const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddMainFirmware(kDeviceId, firmware_info);
  }

  void AddAssocFirmwareFile(const std::string& main_fw_path,
                            const std::string& firmware_id,
                            const base::FilePath& rel_firmware_path,
                            const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddAssocFirmware(main_fw_path, firmware_id,
                                          firmware_info);
  }

  void AddOemFirmwareFile(const base::FilePath& rel_firmware_path,
                          const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddOemFirmware(kDeviceId, firmware_info);
  }

  void AddCarrierFirmwareFile(const base::FilePath& rel_firmware_path,
                              const std::string& version) {
    FirmwareFileInfo firmware_info(rel_firmware_path.value(), version);
    firmware_directory_->AddCarrierFirmware(kDeviceId, kCarrierId,
                                            firmware_info);
  }

  MockModemHelper modem_helper_;

 private:
  std::unique_ptr<ScopedTempFile> journal_file_;
  std::unique_ptr<FirmwareDirectoryStub> firmware_directory_;
  std::unique_ptr<ModemHelperDirectoryStub> modem_helper_directory_;
};

TEST_F(JournalTest, EmptyJournal) {
  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  GetJournal();
}

TEST_F(JournalTest, PriorRunWasNotInterrupted_Main) {
  auto journal = GetJournal();
  journal->MarkStartOfFlashingFirmware({kFwMain}, kDeviceId, kCarrierId);
  journal->MarkEndOfFlashingFirmware(kDeviceId, kCarrierId);

  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  // Getting a new journal simulates a crash or shutdown.
  journal = GetJournal();
}

TEST_F(JournalTest, PriorRunWasInterrupted_Main) {
  const base::FilePath main_fw_path(kMainFirmwarePath);
  AddMainFirmwareFile(main_fw_path, kMainFirmwareVersion);

  auto journal = GetJournal();
  journal->MarkStartOfFlashingFirmware({kFwMain}, kDeviceId, kCarrierId);

  const std::vector<FirmwareConfig> main_cfg = {
      {kFwMain, main_fw_path, kMainFirmwareVersion}};
  EXPECT_CALL(modem_helper_, FlashFirmwares(main_cfg)).WillOnce(Return(true));
  journal = GetJournal();

  // Test that the journal is cleared afterwards, so we don't try to
  // flash a second time if we crash again.
  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  journal = GetJournal();
}

TEST_F(JournalTest, PriorRunWasNotInterrupted_Oem) {
  auto journal = GetJournal();
  journal->MarkStartOfFlashingFirmware({kFwOem}, kDeviceId, kCarrierId);
  journal->MarkEndOfFlashingFirmware(kDeviceId, kCarrierId);

  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  // Getting a new journal simulates a crash or shutdown.
  journal = GetJournal();
}

TEST_F(JournalTest, PriorRunWasInterrupted_Oem) {
  const base::FilePath oem_fw_path(kOemFirmwarePath);
  AddOemFirmwareFile(oem_fw_path, kOemFirmwareVersion);

  auto journal = GetJournal();
  journal->MarkStartOfFlashingFirmware({kFwOem}, kDeviceId, kCarrierId);

  const std::vector<FirmwareConfig> oem_cfg = {
      {kFwOem, oem_fw_path, kOemFirmwareVersion}};
  EXPECT_CALL(modem_helper_, FlashFirmwares(oem_cfg)).WillOnce(Return(true));
  journal = GetJournal();

  // Test that the journal is cleared afterwards, so we don't try to
  // flash a second time if we crash again.
  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  journal = GetJournal();
}

TEST_F(JournalTest, PriorRunWasNotInterrupted_Carrier) {
  auto journal = GetJournal();
  journal->MarkStartOfFlashingFirmware({kFwCarrier}, kDeviceId, kCarrierId);
  journal->MarkEndOfFlashingFirmware(kDeviceId, kCarrierId);

  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  // Getting a new journal simulates a crash or shutdown.
  journal = GetJournal();
}

TEST_F(JournalTest, PriorRunWasInterrupted_Carrier) {
  const base::FilePath carrier_fw_path(kCarrierFirmwarePath);
  AddCarrierFirmwareFile(carrier_fw_path, kCarrierFirmwareVersion);

  auto journal = GetJournal();
  journal->MarkStartOfFlashingFirmware({kFwCarrier}, kDeviceId, kCarrierId);

  const std::vector<FirmwareConfig> carrier_cfg = {
      {kFwCarrier, carrier_fw_path, kCarrierFirmwareVersion}};
  EXPECT_CALL(modem_helper_, FlashFirmwares(carrier_cfg))
      .WillOnce(Return(true));
  journal = GetJournal();

  // Test that the journal is cleared afterwards, so we don't try to
  // flash a second time if we crash again.
  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  journal = GetJournal();
}

TEST_F(JournalTest, PriorRunWasInterrupted_MultipleFirmwares) {
  const base::FilePath main_fw_path(kMainFirmwarePath);
  AddMainFirmwareFile(main_fw_path, kMainFirmwareVersion);
  const base::FilePath oem_fw_path(kOemFirmwarePath);
  AddOemFirmwareFile(oem_fw_path, kOemFirmwareVersion);
  const base::FilePath carrier_fw_path(kCarrierFirmwarePath);
  AddCarrierFirmwareFile(carrier_fw_path, kCarrierFirmwareVersion);

  auto journal = GetJournal();
  journal->MarkStartOfFlashingFirmware({kFwMain, kFwOem, kFwCarrier}, kDeviceId,
                                       kCarrierId);

  const std::vector<FirmwareConfig> all_cfg = {
      {kFwMain, main_fw_path, kMainFirmwareVersion},
      {kFwOem, oem_fw_path, kOemFirmwareVersion},
      {kFwCarrier, carrier_fw_path, kCarrierFirmwareVersion}};
  EXPECT_CALL(modem_helper_, FlashFirmwares(all_cfg)).WillOnce(Return(true));
  journal = GetJournal();

  // Test that the journal is cleared afterwards, so we don't try to
  // flash a second time if we crash again.
  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  journal = GetJournal();
}

TEST_F(JournalTest, IgnoreMalformedJournalEntries) {
  SetUpJournal("blahblah");
  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  GetJournal();
}

TEST_F(JournalTest, MultipleEntries) {
  auto journal = GetJournal();
  journal->MarkStartOfFlashingFirmware({kFwMain}, kDeviceId, kCarrierId);
  journal->MarkEndOfFlashingFirmware(kDeviceId, kCarrierId);
  journal->MarkStartOfFlashingFirmware({kFwCarrier}, kDeviceId, kCarrierId);
  journal->MarkEndOfFlashingFirmware(kDeviceId, kCarrierId);

  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  journal = GetJournal();
}

TEST_F(JournalTest, PriorRunWasInterrupted_AssociatedFirmware) {
  // Main + 2 associated payloads
  const base::FilePath main_fw_path(kMainFirmwarePath);
  AddMainFirmwareFile(main_fw_path, kMainFirmwareVersion);
  const base::FilePath ap_fw_path(kApFirmwarePath);
  AddAssocFirmwareFile(kMainFirmwarePath, kApFirmwareTag, ap_fw_path,
                       kApFirmwareVersion);
  const base::FilePath dev_fw_path(kDevFirmwarePath);
  AddAssocFirmwareFile(kMainFirmwarePath, kDevFirmwareTag, dev_fw_path,
                       kDevFirmwareVersion);

  auto journal = GetJournal();
  journal->MarkStartOfFlashingFirmware(
      {kFwMain, kApFirmwareTag, kDevFirmwareTag}, kDeviceId, kCarrierId);

  const std::vector<FirmwareConfig> all_cfg = {
      {kFwMain, main_fw_path, kMainFirmwareVersion},
      {kApFirmwareTag, ap_fw_path, kApFirmwareVersion},
      {kDevFirmwareTag, dev_fw_path, kDevFirmwareVersion}};
  EXPECT_CALL(modem_helper_, FlashFirmwares(all_cfg)).WillOnce(Return(true));
  journal = GetJournal();

  // Test that the journal is cleared afterwards, so we don't try to
  // flash a second time if we crash again.
  EXPECT_CALL(modem_helper_, FlashFirmwares(_)).Times(0);
  journal = GetJournal();
}

}  // namespace modemfwd
