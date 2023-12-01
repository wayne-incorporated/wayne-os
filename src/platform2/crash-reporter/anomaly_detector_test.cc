// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/anomaly_detector.h"

#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "crash-reporter/anomaly_detector_test_utils.h"
#include "crash-reporter/util.h"

namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::NiceMock;
using ::testing::Return;

using ::anomaly::CryptohomeParser;
using ::anomaly::HermesParser;
using ::anomaly::KernelParser;
using ::anomaly::ParserRun;
using ::anomaly::ParserTest;
using ::anomaly::SELinuxParser;
using ::anomaly::ServiceParser;
using ::anomaly::ShillParser;
using ::anomaly::SuspendParser;
using ::anomaly::TcsdParser;
using ::anomaly::TerminaParser;

const ParserRun simple_run;
const ParserRun empty{.expected_size = 0};

}  // namespace

TEST(AnomalyDetectorTest, KernelAth10kSNOCError) {
  ParserRun wifi_error = {
      .expected_text =
          "[393652.069986] ath10k_snoc 18800000.wifi: "
          "firmware crashed! (guid 7c8da1e6-f8fe-4665-8257-5a476a7bc786)\n"
          "[393652.070050] ath10k_snoc 18800000.wifi: "
          "wcn3990 hw1.0 target 0x00000008 chip_id 0x00000000 sub 0000:0000\n"
          "[393652.070086] ath10k_snoc 18800000.wifi: "
          "kconfig debug 1 debugfs 1 tracing 0 dfs 0 testmode 1\n"
          "[393652.070124] ath10k_snoc 18800000.wifi: "
          "firmware ver 1.0.0.922 api 5 features "
          "wowlan,mfp,mgmt-tx-by-reference"
          ",non-bmi,single-chan-info-per-channel crc32 3f19f7c1\n"
          "[393652.070158] ath10k_snoc 18800000.wifi: "
          "board_file api 2 bmi_id N/A crc32 00000000\n"
          "[393652.070195] ath10k_snoc 18800000.wifi: "
          "htt-ver 3.86 wmi-op 4 htt-op 3 cal file max-sta 32 raw 0 hwcrypto "
          "1\n",
      .expected_flags = {{"--kernel_ath10k_error", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_ATH10K_SNOC", {wifi_error}, &parser);
}

TEST(AnomalyDetectorTest, KernelAth10kSDIOError) {
  ParserRun wifi_error = {
      .expected_text =
          "[10108611.994407] ath10k_sdio mmc1:0001:1: "
          "firmware crashed! (guid bfc44e6c-4cef-425b-b9ca-5530c650d0a3)\n"
          "[10108611.994442] ath10k_sdio mmc1:0001:1: "
          "qca6174 hw3.2 sdio target 0x05030000 chip_id 0x00000000 sub "
          "0000:0000\n"
          "[10108611.994457] ath10k_sdio mmc1:0001:1: "
          "kconfig debug 1 debugfs 1 tracing 1 dfs 0 testmode 1\n"
          "[10108611.996680] ath10k_sdio mmc1:0001:1: "
          "firmware ver WLAN.RMH.4.4.1-00077 api 6 features wowlan,ignore-otp "
          "crc32 a48b7c2f\n"
          "[10108611.999858] ath10k_sdio mmc1:0001:1: "
          "board_file api 2 bmi_id 0:4 crc32 fe1026b8\n"
          "[10108611.999887] ath10k_sdio mmc1:0001:1: "
          "htt-ver 3.86 wmi-op 4 htt-op 3 cal otp max-sta 32 raw 0 hwcrypto "
          "1\n",
      .expected_flags = {{"--kernel_ath10k_error", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_ATH10K_SDIO", {wifi_error}, &parser);
}

TEST(AnomalyDetectorTest, KernelAth10kPCIError) {
  ParserRun wifi_error = {
      .expected_text =
          "[ 1582.994118] ath10k_pci 0000:01:00.0: "
          "firmware crashed! (guid cad1f078-23d2-4cfe-a58a-1e9d353acb7e)\n"
          "[ 1582.994133] ath10k_pci 0000:01:00.0: "
          "qca6174 hw3.2 target 0x05030000 chip_id 0x00340aff sub 17aa:0827\n"
          "[ 1582.994141] ath10k_pci 0000:01:00.0: "
          "kconfig debug 1 debugfs 1 tracing 1 dfs 0 testmode 1\n"
          "[ 1582.995552] ath10k_pci 0000:01:00.0: "
          "firmware ver WLAN.RM.4.4.1-00157-QCARMSWPZ-1 api 6 features "
          "wowlan,ignore-otp,mfp crc32 90eebefb\n"
          "[ 1582.996924] ath10k_pci 0000:01:00.0: "
          "board_file api 2 bmi_id N/A crc32 bebf3597\n"
          "[ 1582.996936] ath10k_pci 0000:01:00.0: "
          "htt-ver 3.60 wmi-op 4 htt-op 3 cal otp max-sta 32 raw 0 hwcrypto "
          "1\n",
      .expected_flags = {{"--kernel_ath10k_error", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_ATH10K_PCI", {wifi_error}, &parser);
}

TEST(AnomalyDetectorTest, KernelAth10kErrorNoEnd) {
  ParserRun wifi_error = {
      .expected_text =
          "[393652.069986] ath10k_snoc 18800000.wifi: firmware crashed! "
          "(guid 7c8da1e6-f8fe-4665-8257-5a476a7bc786)\n"
          "[393652.070050] ath10k_snoc 18800000.wifi: wcn3990 hw1.0 target "
          "0x00000008 chip_id 0x00000000 sub 0000:0000\n"
          "[393652.070086] ath10k_snoc 18800000.wifi: kconfig debug 1 debugfs "
          "1 tracing 0 dfs 0 testmode 1\n"
          "[393652.070124] ath10k_snoc 18800000.wifi: firmware ver 1.0.0.922 "
          "api 5 features wowlan,mfp,mgmt-tx-by-reference,non-bmi,single-chan"
          "-info-per-channel crc32 3f19f7c1\n"
          "[393652.070158] ath10k_snoc 18800000.wifi: board_file api 2 bmi_id"
          " N/A crc32 00000000\n",
      .expected_flags = {{"--kernel_ath10k_error", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_ATH10K_NO_END", {wifi_error}, &parser);
}

TEST(AnomalyDetectorTest, KernelIwlwifiErrorLmacUmac) {
  ParserRun wifi_error = {
      .expected_text =
          "[15883.337352] iwlwifi 0000:00:0c.0: Loaded firmware version: "
          "46.b20aefee.0\n"
          "[15883.337355] iwlwifi 0000:00:0c.0: 0x00000084 | "
          "NMI_INTERRUPT_UNKNOWN\n"
          "[15883.337357] iwlwifi 0000:00:0c.0: 0x000022F0 | trm_hw_status0\n"
          "[15883.337359] iwlwifi 0000:00:0c.0: 0x00000000 | trm_hw_status1\n"
          "[15883.337362] iwlwifi 0000:00:0c.0: 0x0048751E | branchlink2\n"
          "[15883.337364] iwlwifi 0000:00:0c.0: 0x00479236 | interruptlink1\n"
          "[15883.337366] iwlwifi 0000:00:0c.0: 0x0000AE00 | interruptlink2\n"
          "[15883.337369] iwlwifi 0000:00:0c.0: 0x0001A2D6 | data1\n"
          "[15883.337371] iwlwifi 0000:00:0c.0: 0xFF000000 | data2\n"
          "[15883.337373] iwlwifi 0000:00:0c.0: 0xF0000000 | data3\n"
          "[15883.337376] iwlwifi 0000:00:0c.0: 0x00000000 | beacon time\n"
          "[15883.337378] iwlwifi 0000:00:0c.0: 0x158DE6F7 | tsf low\n"
          "[15883.337380] iwlwifi 0000:00:0c.0: 0x00000000 | tsf hi\n"
          "[15883.337383] iwlwifi 0000:00:0c.0: 0x00000000 | time gp1\n"
          "[15883.337385] iwlwifi 0000:00:0c.0: 0x158DE6F9 | time gp2\n"
          "[15883.337388] iwlwifi 0000:00:0c.0: 0x00000001 | uCode revision "
          "type\n"
          "[15883.337390] iwlwifi 0000:00:0c.0: 0x0000002E | uCode version "
          "major\n"
          "[15883.337392] iwlwifi 0000:00:0c.0: 0xB20AEFEE | uCode version "
          "minor\n"
          "[15883.337394] iwlwifi 0000:00:0c.0: 0x00000312 | hw version\n"
          "[15883.337397] iwlwifi 0000:00:0c.0: 0x00C89008 | board version\n"
          "[15883.337399] iwlwifi 0000:00:0c.0: 0x007B019C | hcmd\n"
          "[15883.337401] iwlwifi 0000:00:0c.0: 0x00022000 | isr0\n"
          "[15883.337404] iwlwifi 0000:00:0c.0: 0x00000000 | isr1\n"
          "[15883.337406] iwlwifi 0000:00:0c.0: 0x08001802 | isr2\n"
          "[15883.337408] iwlwifi 0000:00:0c.0: 0x40400180 | isr3\n"
          "[15883.337411] iwlwifi 0000:00:0c.0: 0x00000000 | isr4\n"
          "[15883.337413] iwlwifi 0000:00:0c.0: 0x007B019C | last cmd Id\n"
          "[15883.337415] iwlwifi 0000:00:0c.0: 0x0001A2D6 | wait_event\n"
          "[15883.337417] iwlwifi 0000:00:0c.0: 0x00000000 | l2p_control\n"
          "[15883.337420] iwlwifi 0000:00:0c.0: 0x00000000 | l2p_duration\n"
          "[15883.337422] iwlwifi 0000:00:0c.0: 0x00000000 | l2p_mhvalid\n"
          "[15883.337424] iwlwifi 0000:00:0c.0: 0x00000000 | l2p_addr_match\n"
          "[15883.337427] iwlwifi 0000:00:0c.0: 0x0000008F | lmpm_pmg_sel\n"
          "[15883.337429] iwlwifi 0000:00:0c.0: 0x24021230 | timestamp\n"
          "[15883.337432] iwlwifi 0000:00:0c.0: 0x0000B0D8 | flow_handler\n"
          "[15883.337464] iwlwifi 0000:00:0c.0: Start IWL Error Log Dump:\n"
          "[15883.337467] iwlwifi 0000:00:0c.0: Status: 0x00000100, count: 7\n"
          "[15883.337470] iwlwifi 0000:00:0c.0: 0x20000066 | "
          "NMI_INTERRUPT_HOST\n"
          "[15883.337472] iwlwifi 0000:00:0c.0: 0x00000000 | umac branchlink1\n"
          "[15883.337475] iwlwifi 0000:00:0c.0: 0xC008821A | umac branchlink2\n"
          "[15883.337477] iwlwifi 0000:00:0c.0: 0x00000000 | umac "
          "interruptlink1\n"
          "[15883.337479] iwlwifi 0000:00:0c.0: 0x8044FBD2 | umac "
          "interruptlink2\n"
          "[15883.337481] iwlwifi 0000:00:0c.0: 0x01000000 | umac data1\n"
          "[15883.337484] iwlwifi 0000:00:0c.0: 0x8044FBD2 | umac data2\n"
          "[15883.337486] iwlwifi 0000:00:0c.0: 0xDEADBEEF | umac data3\n"
          "[15883.337488] iwlwifi 0000:00:0c.0: 0x0000002E | umac major\n"
          "[15883.337490] iwlwifi 0000:00:0c.0: 0xB20AEFEE | umac minor\n"
          "[15883.337493] iwlwifi 0000:00:0c.0: 0x158DE6F4 | frame pointer\n"
          "[15883.337511] iwlwifi 0000:00:0c.0: 0xC088627C | stack pointer\n"
          "[15883.337514] iwlwifi 0000:00:0c.0: 0x007B019C | last host cmd\n"
          "[15883.337516] iwlwifi 0000:00:0c.0: 0x00000000 | isr status reg\n",
      .expected_flags = {{"--kernel_iwlwifi_error", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_IWLWIFI_LMAC_UMAC", {wifi_error}, &parser);
}

TEST(AnomalyDetectorTest, KernelIwlwifiErrorLmacTwoSpace) {
  ParserRun wifi_error = {
      .expected_text =
          "[79553.430924] iwlwifi 0000:02:00.0: Loaded firmware version: "
          "29.116a852a.0 7265D-29.ucode\n"
          "[79553.430930] iwlwifi 0000:02:00.0: 0x00000084 | "
          "NMI_INTERRUPT_UNKNOWN       \n"
          "[79553.430935] iwlwifi 0000:02:00.0: 0x00A002F0 | trm_hw_status0\n"
          "[79553.430939] iwlwifi 0000:02:00.0: 0x00000000 | trm_hw_status1\n"
          "[79553.430944] iwlwifi 0000:02:00.0: 0x00043D6C | branchlink2\n"
          "[79553.430948] iwlwifi 0000:02:00.0: 0x0004AFD6 | interruptlink1\n"
          "[79553.430953] iwlwifi 0000:02:00.0: 0x0004AFD6 | interruptlink2\n"
          "[79553.430957] iwlwifi 0000:02:00.0: 0x00000000 | data1\n"
          "[79553.430961] iwlwifi 0000:02:00.0: 0x00000080 | data2\n"
          "[79553.430966] iwlwifi 0000:02:00.0: 0x07230000 | data3\n"
          "[79553.430970] iwlwifi 0000:02:00.0: 0x1E00B95C | beacon time\n"
          "[79553.430975] iwlwifi 0000:02:00.0: 0xE6A38917 | tsf low\n"
          "[79553.430979] iwlwifi 0000:02:00.0: 0x00000011 | tsf hi\n"
          "[79553.430983] iwlwifi 0000:02:00.0: 0x00000000 | time gp1\n"
          "[79553.430988] iwlwifi 0000:02:00.0: 0x8540E3A4 | time gp2\n"
          "[79553.430992] iwlwifi 0000:02:00.0: 0x00000001 | uCode revision "
          "type\n"
          "[79553.430996] iwlwifi 0000:02:00.0: 0x0000001D | uCode version "
          "major\n"
          "[79553.431013] iwlwifi 0000:02:00.0: 0x116A852A | uCode version "
          "minor\n"
          "[79553.431017] iwlwifi 0000:02:00.0: 0x00000210 | hw version\n"
          "[79553.431021] iwlwifi 0000:02:00.0: 0x00489200 | board version\n"
          "[79553.431025] iwlwifi 0000:02:00.0: 0x0000001C | hcmd\n"
          "[79553.431030] iwlwifi 0000:02:00.0: 0x00022000 | isr0\n"
          "[79553.431034] iwlwifi 0000:02:00.0: 0x00000000 | isr1\n"
          "[79553.431039] iwlwifi 0000:02:00.0: 0x0000000A | isr2\n"
          "[79553.431043] iwlwifi 0000:02:00.0: 0x0041D4C0 | isr3\n"
          "[79553.431047] iwlwifi 0000:02:00.0: 0x00000000 | isr4\n"
          "[79553.431052] iwlwifi 0000:02:00.0: 0x00230151 | last cmd Id\n"
          "[79553.431056] iwlwifi 0000:02:00.0: 0x00000000 | wait_event\n"
          "[79553.431060] iwlwifi 0000:02:00.0: 0x0000A8CB | l2p_control\n"
          "[79553.431082] iwlwifi 0000:02:00.0: 0x00000020 | l2p_duration\n"
          "[79553.431086] iwlwifi 0000:02:00.0: 0x00000003 | l2p_mhvalid\n"
          "[79553.431091] iwlwifi 0000:02:00.0: 0x000000CE | l2p_addr_match\n"
          "[79553.431095] iwlwifi 0000:02:00.0: 0x00000005 | lmpm_pmg_sel\n"
          "[79553.431100] iwlwifi 0000:02:00.0: 0x07071159 | timestamp\n"
          "[79553.431104] iwlwifi 0000:02:00.0: 0x00340010 | flow_handler\n",
      .expected_flags = {{"--kernel_iwlwifi_error", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_IWLWIFI_LMAC_TWO_SPACE", {wifi_error}, &parser);
}

TEST(AnomalyDetectorTest, KernelIwlwifiDriverError) {
  ParserRun wifi_error = {
      .expected_text =
          "0000:01:00.0: Loaded firmware version: 17.bfb58538.0 7260-17.ucode\n"
          "2020-09-01T11:03:11.221401-07:00 ERR kernel: [ 2448.183344] iwlwifi "
          "0000:01:00.0: 0x00000000 | ADVANCED_SYSASSERT\n"
          "2020-09-01T11:03:11.221407-07:00 ERR kernel: [ 2448.183349] iwlwifi "
          "0000:01:00.0: 0x00000000 | trm_hw_status0\n"
          "2020-09-01T11:03:11.221409-07:00 ERR kernel: [ 2448.183353] iwlwifi "
          "0000:01:00.0: 0x00000000 | trm_hw_status1\n"
          "2020-09-01T11:03:11.221412-07:00 ERR kernel: [ 2448.183357] iwlwifi "
          "0000:01:00.0: 0x00000000 | branchlink2\n"
          "2020-09-01T11:03:11.221415-07:00 ERR kernel: [ 2448.183361] iwlwifi "
          "0000:01:00.0: 0x00000000 | interruptlink1\n"
          "2020-09-01T11:03:11.221417-07:00 ERR kernel: [ 2448.183365] iwlwifi "
          "0000:01:00.0: 0x00000000 | interruptlink2\n"
          "2020-09-01T11:03:11.221420-07:00 ERR kernel: [ 2448.183368] iwlwifi "
          "0000:01:00.0: 0x00000000 | data1\n"
          "2020-09-01T11:03:11.221422-07:00 ERR kernel: [ 2448.183372] iwlwifi "
          "0000:01:00.0: 0x00000000 | data2\n"
          "2020-09-01T11:03:11.221425-07:00 ERR kernel: [ 2448.183376] iwlwifi "
          "0000:01:00.0: 0x00000000 | data3\n"
          "2020-09-01T11:03:11.221427-07:00 ERR kernel: [ 2448.183380] iwlwifi "
          "0000:01:00.0: 0x00000000 | beacon time\n"
          "2020-09-01T11:03:11.221429-07:00 ERR kernel: [ 2448.183384] iwlwifi "
          "0000:01:00.0: 0x00000000 | tsf low\n"
          "2020-09-01T11:03:11.221432-07:00 ERR kernel: [ 2448.183388] iwlwifi "
          "0000:01:00.0: 0x00000000 | tsf hi\n"
          "2020-09-01T11:03:11.221434-07:00 ERR kernel: [ 2448.183392] iwlwifi "
          "0000:01:00.0: 0x00000000 | time gp1\n"
          "2020-09-01T11:03:11.221436-07:00 ERR kernel: [ 2448.183396] iwlwifi "
          "0000:01:00.0: 0x00000000 | time gp2\n"
          "2020-09-01T11:03:11.221438-07:00 ERR kernel: [ 2448.183400] iwlwifi "
          "0000:01:00.0: 0x00000000 | uCode revision type\n"
          "2020-09-01T11:03:11.221440-07:00 ERR kernel: [ 2448.183404] iwlwifi "
          "0000:01:00.0: 0x00000000 | uCode version major\n"
          "2020-09-01T11:03:11.221443-07:00 ERR kernel: [ 2448.183408] iwlwifi "
          "0000:01:00.0: 0x00000000 | uCode version minor\n"
          "2020-09-01T11:03:11.221445-07:00 ERR kernel: [ 2448.183412] iwlwifi "
          "0000:01:00.0: 0x00000000 | hw version\n"
          "2020-09-01T11:03:11.221447-07:00 ERR kernel: [ 2448.183416] iwlwifi "
          "0000:01:00.0: 0x00000000 | board version\n"
          "2020-09-01T11:03:11.221449-07:00 ERR kernel: [ 2448.183419] iwlwifi "
          "0000:01:00.0: 0x00000000 | hcmd\n"
          "2020-09-01T11:03:11.221451-07:00 ERR kernel: [ 2448.183423] iwlwifi "
          "0000:01:00.0: 0x00000000 | isr0\n"
          "2020-09-01T11:03:11.221453-07:00 ERR kernel: [ 2448.183427] iwlwifi "
          "0000:01:00.0: 0x00000000 | isr1\n"
          "2020-09-01T11:03:11.221455-07:00 ERR kernel: [ 2448.183431] iwlwifi "
          "0000:01:00.0: 0x00000000 | isr2\n"
          "2020-09-01T11:03:11.221457-07:00 ERR kernel: [ 2448.183435] iwlwifi "
          "0000:01:00.0: 0x00000000 | isr3\n"
          "2020-09-01T11:03:11.221459-07:00 ERR kernel: [ 2448.183439] iwlwifi "
          "0000:01:00.0: 0x00000000 | isr4\n"
          "2020-09-01T11:03:11.221461-07:00 ERR kernel: [ 2448.183442] iwlwifi "
          "0000:01:00.0: 0x00000000 | last cmd Id\n"
          "2020-09-01T11:03:11.221464-07:00 ERR kernel: [ 2448.183446] iwlwifi "
          "0000:01:00.0: 0x00000000 | wait_event\n"
          "2020-09-01T11:03:11.221466-07:00 ERR kernel: [ 2448.183450] iwlwifi "
          "0000:01:00.0: 0x00000000 | l2p_control\n"
          "2020-09-01T11:03:11.221468-07:00 ERR kernel: [ 2448.183454] iwlwifi "
          "0000:01:00.0: 0x00000000 | l2p_duration\n"
          "2020-09-01T11:03:11.221470-07:00 ERR kernel: [ 2448.183458] iwlwifi "
          "0000:01:00.0: 0x00000000 | l2p_mhvalid\n"
          "2020-09-01T11:03:11.221472-07:00 ERR kernel: [ 2448.183461] iwlwifi "
          "0000:01:00.0: 0x00000000 | l2p_addr_match\n"
          "2020-09-01T11:03:11.221474-07:00 ERR kernel: [ 2448.183465] iwlwifi "
          "0000:01:00.0: 0x00000000 | lmpm_pmg_sel\n"
          "2020-09-01T11:03:11.221475-07:00 ERR kernel: [ 2448.183469] iwlwifi "
          "0000:01:00.0: 0x00000000 | timestamp\n"
          "2020-09-01T11:03:11.221478-07:00 ERR kernel: [ 2448.183473] iwlwifi "
          "0000:01:00.0: 0x00000000 | flow_handler\n",
      .expected_flags = {{"--kernel_iwlwifi_error", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_IWLWIFI_DRIVER_ERROR", {wifi_error}, &parser);
}

TEST(AnomalyDetectorTest, KernelIwlwifiErrorLmac) {
  ParserRun wifi_error = {
      .expected_text =
          "[15883.337352] iwlwifi 0000:00:0c.0: Loaded firmware version: "
          "46.b20aefee.0\n"
          "[15883.337355] iwlwifi 0000:00:0c.0: 0x00000084 | "
          "NMI_INTERRUPT_UNKNOWN\n"
          "[15883.337357] iwlwifi 0000:00:0c.0: 0x000022F0 | trm_hw_status0\n"
          "[15883.337359] iwlwifi 0000:00:0c.0: 0x00000000 | trm_hw_status1\n"
          "[15883.337362] iwlwifi 0000:00:0c.0: 0x0048751E | branchlink2\n"
          "[15883.337364] iwlwifi 0000:00:0c.0: 0x00479236 | interruptlink1\n"
          "[15883.337366] iwlwifi 0000:00:0c.0: 0x0000AE00 | interruptlink2\n"
          "[15883.337369] iwlwifi 0000:00:0c.0: 0x0001A2D6 | data1\n"
          "[15883.337371] iwlwifi 0000:00:0c.0: 0xFF000000 | data2\n"
          "[15883.337373] iwlwifi 0000:00:0c.0: 0xF0000000 | data3\n"
          "[15883.337376] iwlwifi 0000:00:0c.0: 0x00000000 | beacon time\n"
          "[15883.337378] iwlwifi 0000:00:0c.0: 0x158DE6F7 | tsf low\n"
          "[15883.337380] iwlwifi 0000:00:0c.0: 0x00000000 | tsf hi\n"
          "[15883.337383] iwlwifi 0000:00:0c.0: 0x00000000 | time gp1\n"
          "[15883.337385] iwlwifi 0000:00:0c.0: 0x158DE6F9 | time gp2\n"
          "[15883.337388] iwlwifi 0000:00:0c.0: 0x00000001 | uCode revision "
          "type\n"
          "[15883.337390] iwlwifi 0000:00:0c.0: 0x0000002E | uCode version "
          "major\n"
          "[15883.337392] iwlwifi 0000:00:0c.0: 0xB20AEFEE | uCode version "
          "minor\n"
          "[15883.337394] iwlwifi 0000:00:0c.0: 0x00000312 | hw version\n"
          "[15883.337397] iwlwifi 0000:00:0c.0: 0x00C89008 | board version\n"
          "[15883.337399] iwlwifi 0000:00:0c.0: 0x007B019C | hcmd\n"
          "[15883.337401] iwlwifi 0000:00:0c.0: 0x00022000 | isr0\n"
          "[15883.337404] iwlwifi 0000:00:0c.0: 0x00000000 | isr1\n"
          "[15883.337406] iwlwifi 0000:00:0c.0: 0x08001802 | isr2\n"
          "[15883.337408] iwlwifi 0000:00:0c.0: 0x40400180 | isr3\n"
          "[15883.337411] iwlwifi 0000:00:0c.0: 0x00000000 | isr4\n"
          "[15883.337413] iwlwifi 0000:00:0c.0: 0x007B019C | last cmd Id\n"
          "[15883.337415] iwlwifi 0000:00:0c.0: 0x0001A2D6 | wait_event\n"
          "[15883.337417] iwlwifi 0000:00:0c.0: 0x00000000 | l2p_control\n"
          "[15883.337420] iwlwifi 0000:00:0c.0: 0x00000000 | l2p_duration\n"
          "[15883.337422] iwlwifi 0000:00:0c.0: 0x00000000 | l2p_mhvalid\n"
          "[15883.337424] iwlwifi 0000:00:0c.0: 0x00000000 | l2p_addr_match\n"
          "[15883.337427] iwlwifi 0000:00:0c.0: 0x0000008F | lmpm_pmg_sel\n"
          "[15883.337429] iwlwifi 0000:00:0c.0: 0x24021230 | timestamp\n"
          "[15883.337432] iwlwifi 0000:00:0c.0: 0x0000B0D8 | flow_handler\n",
      .expected_flags = {{"--kernel_iwlwifi_error", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_IWLWIFI_LMAC", {wifi_error}, &parser);
}

TEST(AnomalyDetectorTest, KernelSMMU_FAULT) {
  ParserRun smmu_error = {
      .expected_text =
          "[   74.047205] arm-smmu 15000000.iommu: Unhandled context fault: "
          "fsr=0x402, iova=0x04367000, fsynr=0x30023, cbfrsynra=0x800, cb=5\n",
      .expected_flags = {{"--kernel_smmu_fault"}}};
  KernelParser parser(true);
  ParserTest("TEST_SMMU_FAULT", {smmu_error}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarning) {
  ParserRun second{
      .find_this = "ttm_bo_vm.c",
      .replace_with = "file_one.c",
      .expected_text = "0x19e/0x1ab [ttm]()\n[ 3955.309298] Modules linked in",
      .expected_flags = {{"--kernel_warning", "--weight=10"}}};
  KernelParser parser(true);
  ParserTest("TEST_WARNING", {simple_run, second}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningNoDuplicate) {
  ParserRun identical_warning{.expected_size = 0};
  KernelParser parser(true);
  ParserTest("TEST_WARNING", {simple_run, identical_warning}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningHeader) {
  ParserRun warning_message{.expected_text = "Test Warning message asdfghjkl"};
  KernelParser parser(true);
  ParserTest("TEST_WARNING_HEADER", {warning_message}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningOld) {
  KernelParser parser(true);
  ParserTest("TEST_WARNING_OLD", {simple_run}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningOldARM64) {
  ParserRun unknown_function{.expected_text = "-unknown-function\n"};
  KernelParser parser(true);
  ParserTest("TEST_WARNING_OLD_ARM64", {unknown_function}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningWifi) {
  ParserRun wifi_warning = {
      .find_this = "gpu/drm/ttm",
      .replace_with = "net/wireless",
      .expected_flags = {{"--kernel_wifi_warning", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_WARNING", {wifi_warning}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningWifiMac80211) {
  ParserRun wifi_warning = {
      .expected_flags = {{"--kernel_wifi_warning", "--weight=50"}}};
  KernelParser parser(true);
  ParserTest("TEST_WIFI_WARNING", {wifi_warning}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningSuspend_v4_14) {
  ParserRun suspend_warning = {
      .find_this = "gpu/drm/ttm",
      .replace_with = "idle",
      .expected_flags = {{"--kernel_suspend_warning", "--weight=10"}}};
  KernelParser parser(true);
  ParserTest("TEST_WARNING", {suspend_warning}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningSuspend_EC) {
  ParserRun suspend_warning = {
      .find_this = "gpu/drm/ttm/ttm_bo_vm.c",
      .replace_with = "platform/chrome/cros_ec.c",
      .expected_flags = {{"--kernel_suspend_warning", "--weight=10"}}};
  KernelParser parser(true);
  ParserTest("TEST_WARNING", {suspend_warning}, &parser);
}

TEST(AnomalyDetectorTest, CrashReporterCrash) {
  ParserRun crash_reporter_crash = {
      .expected_flags = {{"--crash_reporter_crashed"}}};
  KernelParser parser(true);
  ParserTest("TEST_CR_CRASH", {crash_reporter_crash}, &parser);
}

TEST(AnomalyDetectorTest, CrashReporterCrashRateLimit) {
  ParserRun crash_reporter_crash = {
      .expected_flags = {{"--crash_reporter_crashed"}}};
  KernelParser parser(true);
  ParserTest("TEST_CR_CRASH", {crash_reporter_crash, empty, empty}, &parser);
}

TEST(AnomalyDetectorTest, ServiceFailure) {
  ParserRun one{.expected_text = "-exit2-"};
  ParserRun two{.find_this = "crash-crash", .replace_with = "fresh-fresh"};
  ServiceParser parser(true);
  ParserTest("TEST_SERVICE_FAILURE", {one, two}, &parser);
}

TEST(AnomalyDetectorTest, ServiceFailureArc) {
  ParserRun service_failure = {
      .find_this = "crash-crash",
      .replace_with = "arc-crash",
      .expected_text = "-exit2-arc-",
      .expected_flags = {{"--arc_service_failure=arc-crash"}}};
  ServiceParser parser(true);
  ParserTest("TEST_SERVICE_FAILURE", {service_failure}, &parser);
}

TEST(AnomalyDetectorTest, ServiceFailureCamera) {
  ParserRun service_failure = {.find_this = "crash-crash",
                               .replace_with = "cros-camera",
                               .expected_size = 0};
  ServiceParser parser(true);
  ParserTest("TEST_SERVICE_FAILURE", {service_failure}, &parser);
}

TEST(AnomalyDetectorTest, SELinuxViolation) {
  ParserRun selinux_violation = {
      .expected_text =
          "-selinux-u:r:cros_init:s0-u:r:kernel:s0-module_request-init-",
      .expected_flags = {{"--selinux_violation", "--weight=100"}}};
  SELinuxParser parser(true);
  ParserTest("TEST_SELINUX", {selinux_violation}, &parser);
}

TEST(AnomalyDetectorTest, SELinuxViolationPermissive) {
  ParserRun selinux_violation = {.find_this = "permissive=0",
                                 .replace_with = "permissive=1",
                                 .expected_size = 0};
  SELinuxParser parser(true);
  ParserTest("TEST_SELINUX", {selinux_violation}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningSuspend_v4_19_up) {
  ParserRun suspend_warning = {
      .expected_flags = {{"--kernel_suspend_warning", "--weight=10"}}};
  KernelParser parser(true);
  ParserTest("TEST_SUSPEND_WARNING_LOWERCASE", {suspend_warning}, &parser);
}

TEST(AnomalyDetectorTest, KernelWarningSuspendNoDuplicate_v4_19_up) {
  ParserRun identical_warning{.expected_size = 0};
  KernelParser parser(true);
  ParserTest("TEST_SUSPEND_WARNING_LOWERCASE", {simple_run, identical_warning},
             &parser);
}

// Verify that we skip non-CrOS selinux violations
TEST(AnomalyDetectorTest, SELinuxViolationNonCros) {
  ParserRun selinux_violation = {
      .find_this = "cros_init", .replace_with = "init", .expected_size = 0};
  SELinuxParser parser(true);
  ParserTest("TEST_SELINUX", {selinux_violation}, &parser);
}

TEST(AnomalyDetectorTest, SuspendFailure) {
  ParserRun suspend_failure = {
      .expected_text =
          "-suspend failure: device: dummy_dev step: suspend errno: -22",
      .expected_flags = {{"--suspend_failure"}}};
  SuspendParser parser(true);
  ParserTest("TEST_SUSPEND_FAILURE", {suspend_failure}, &parser);
}

MATCHER_P2(SignalEq, interface, member, "") {
  return (arg->GetInterface() == interface && arg->GetMember() == member);
}

TEST(AnomalyDetectorTest, BTRFSExtentCorruption) {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::MockBus> bus = new dbus::MockBus(options);

  auto obj_path = dbus::ObjectPath(anomaly_detector::kAnomalyEventServicePath);
  scoped_refptr<dbus::MockExportedObject> exported_object =
      new dbus::MockExportedObject(bus.get(), obj_path);

  EXPECT_CALL(*bus, GetExportedObject(Eq(obj_path)))
      .WillOnce(Return(exported_object.get()));
  EXPECT_CALL(*exported_object,
              SendSignal(SignalEq(
                  anomaly_detector::kAnomalyEventServiceInterface,
                  anomaly_detector::kAnomalyGuestFileCorruptionSignalName)))
      .Times(1);

  auto metrics = std::make_unique<NiceMock<MetricsLibraryMock>>();
  EXPECT_CALL(*metrics, SendCrosEventToUMA(_)).Times(0);

  TerminaParser parser(bus, std::move(metrics), /*testonly_send_all=*/true);

  parser.ParseLogEntryForBtrfs(
      3,
      "BTRFS warning (device vdb): csum failed root 5 ino 257 off 409600 csum "
      "0x76ad9387 expected csum 0xd8d34542 mirror 1");
}

TEST(AnomalyDetectorTest, BTRFSTreeCorruption) {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::MockBus> bus = new dbus::MockBus(options);

  auto obj_path = dbus::ObjectPath(anomaly_detector::kAnomalyEventServicePath);
  scoped_refptr<dbus::MockExportedObject> exported_object =
      new dbus::MockExportedObject(bus.get(), obj_path);

  EXPECT_CALL(*bus, GetExportedObject(Eq(obj_path)))
      .Times(2)
      .WillRepeatedly(Return(exported_object.get()));
  EXPECT_CALL(*exported_object,
              SendSignal(SignalEq(
                  anomaly_detector::kAnomalyEventServiceInterface,
                  anomaly_detector::kAnomalyGuestFileCorruptionSignalName)))
      .Times(2);

  auto metrics = std::make_unique<NiceMock<MetricsLibraryMock>>();
  EXPECT_CALL(*metrics, SendCrosEventToUMA(_)).Times(0);

  TerminaParser parser(bus, std::move(metrics), /*testonly_send_all=*/true);

  // prior to 5.14
  parser.ParseLogEntryForBtrfs(
      3,
      "BTRFS warning (device vdb): vdb checksum verify failed "
      "on 122798080 wanted 4E5B4C99 found 5F261FEB level 0");

  // since 5.14
  parser.ParseLogEntryForBtrfs(
      3,
      "BTRFS warning (device vdb): checksum verify failed "
      "on 122798080 wanted 4E5B4C99 found 5F261FEB level 0");
}

TEST(AnomalyDetectorTest, OomEvent) {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::MockBus> bus = new dbus::MockBus(options);

  auto obj_path = dbus::ObjectPath(anomaly_detector::kAnomalyEventServicePath);
  scoped_refptr<dbus::MockExportedObject> exported_object =
      new dbus::MockExportedObject(bus.get(), obj_path);

  EXPECT_CALL(*bus, GetExportedObject(Eq(obj_path)))
      .WillOnce(Return(exported_object.get()));
  EXPECT_CALL(
      *exported_object,
      SendSignal(SignalEq(anomaly_detector::kAnomalyEventServiceInterface,
                          anomaly_detector::kAnomalyGuestOomEventSignalName)))
      .Times(1);

  auto metrics = std::make_unique<NiceMock<MetricsLibraryMock>>();
  EXPECT_CALL(*metrics, SendCrosEventToUMA("Crostini.OomEvent"))
      .WillOnce(Return(true));

  TerminaParser parser(bus, std::move(metrics), /*testonly_send_all=*/true);

  std::string oom_log =
      "Out of memory: Killed process 293 (python 3.6) total-vm:15633956kB, "
      "anon-rss:14596640kB, file-rss:4kB, shmem-rss:0kB, UID:0 "
      "pgtables:28628kB "
      "oom_score_adj:0";

  auto crash_report = parser.ParseLogEntryForOom(3, oom_log);

  EXPECT_THAT(crash_report->text,
              testing::HasSubstr("guest-oom-event-python_3_6"));
  EXPECT_THAT(crash_report->text, testing::HasSubstr(oom_log));

  std::vector<std::string> expected_flags = {"--guest_oom_event"};
  EXPECT_EQ(crash_report->flags, expected_flags);
}

TEST(AnomalyDetectorTest, CryptohomeMountFailure) {
  ParserRun cryptohome_mount_failure = {
      .expected_flags = {{"--mount_failure", "--mount_device=cryptohome"}}};
  CryptohomeParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CRYPTOHOME_MOUNT_FAILURE", {cryptohome_mount_failure},
             &parser);
}

TEST(AnomalyDetectorTest, CryptohomeIgnoreMountFailure) {
  ParserRun cryptohome_mount_failure = {.expected_size = 0};
  CryptohomeParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CRYPTOHOME_MOUNT_FAILURE_IGNORE", {cryptohome_mount_failure},
             &parser);
}

TEST(AnomalyDetectorTest, CryptohomeIgnoreFailedLogin) {
  ParserRun cryptohome_mount_failure = {.expected_size = 0};
  CryptohomeParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CRYPTOHOME_FAILED_LOGIN_IGNORE", {cryptohome_mount_failure},
             &parser);
}

TEST(AnomalyDetectorTest, CryptohomeRecoveryRequestFailure) {
  ParserRun cryptohome_recovery_failure = {
      .expected_text = "GetRecoveryRequest-3-recovery-failure",
      .expected_flags = {{"--cryptohome_recovery_failure"}}};
  CryptohomeParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CRYPTOHOME_RECOVERY_REQUEST_FAILURE",
             {cryptohome_recovery_failure}, &parser);
}

TEST(AnomalyDetectorTest, CryptohomeRecoveryDeriveFailure) {
  ParserRun cryptohome_recovery_failure = {
      .expected_text = "Derive-8-recovery-failure",
      .expected_flags = {{"--cryptohome_recovery_failure"}}};
  CryptohomeParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CRYPTOHOME_RECOVERY_DERIVE_FAILURE",
             {cryptohome_recovery_failure}, &parser);
}

TEST(AnomalyDetectorTest, CryptohomeRecoveryIgnoreFailure) {
  ParserRun no_failure = {.expected_size = 0};
  CryptohomeParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CRYPTOHOME_RECOVERY_NO_FAILURE", {no_failure}, &parser);
}

TEST(AnomalyDetectorTest, TcsdAuthFailure) {
  ParserRun tcsd_auth_failure = {.expected_text = "b349c715-auth failure",
                                 .expected_flags = {{"--auth_failure"}}};
  ParserTest<TcsdParser>("TEST_TCSD_AUTH_FAILURE", {tcsd_auth_failure});
}

TEST(AnomalyDetectorTest, TcsdAuthFailureBlocklist) {
  ParserRun tcsd_auth_failure = {.expected_size = 0};
  ParserTest<TcsdParser>("TEST_TCSD_AUTH_FAILURE_BLOCKLIST",
                         {tcsd_auth_failure});
}

TEST(AnomalyDetectorTest, CellularFailureMM) {
  ParserRun modem_failure = {
      .expected_text = "Core.Failed",
      .expected_flags = {
          {"--modem_failure", base::StringPrintf("--weight=%d", 50)}}};
  ShillParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CELLULAR_FAILURE_MM", {modem_failure}, &parser);
}

TEST(AnomalyDetectorTest, CellularFailureEnable) {
  ParserRun enable_failure = {
      .expected_text = "InProgress-enable",
      .expected_flags = {
          {"--modem_failure", base::StringPrintf("--weight=%d", 200)}}};
  ShillParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CELLULAR_FAILURE_ENABLE", {enable_failure}, &parser);
}

TEST(AnomalyDetectorTest, CellularFailureConnect) {
  ParserRun connect_failure = {
      .expected_text = "auto-connect",
      .expected_flags = {
          {"--modem_failure", base::StringPrintf("--weight=%d", 5)}}};
  ShillParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CELLULAR_FAILURE_CONNECT", {connect_failure}, &parser);
}

TEST(AnomalyDetectorTest, CellularFailureBlocked) {
  ParserRun modem_failure = {.expected_size = 0};
  ShillParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CELLULAR_FAILURE_BLOCKED", {modem_failure}, &parser);
}

TEST(AnomalyDetectorTest, CellularFailureEntitlementCheck) {
  ParserRun entitlement_failure = {
      .expected_text = "EntitlementCheckFailure",
      .expected_flags = {
          {"--modem_failure", base::StringPrintf("--weight=%d", 50)}}};
  ShillParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_CELLULAR_FAILURE_ENTITLEMENT_CHECK", {entitlement_failure},
             &parser);
}

TEST(AnomalyDetectorTest, ESimInstallSendHttpsFailure) {
  ParserRun install_failure = {
      .expected_text = "SendHttpsFailure",
      .expected_flags = {
          {"--hermes_failure", base::StringPrintf("--weight=%d", 5)}}};
  HermesParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_ESIM_INSTALL_SEND_HTTPS_FAILURE", {install_failure},
             &parser);
}

TEST(AnomalyDetectorTest, ESimInstallUnknownFailure) {
  ParserRun install_failure = {
      .expected_text = "Unknown",
      .expected_flags = {
          {"--hermes_failure", base::StringPrintf("--weight=%d", 1)}}};
  HermesParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_ESIM_INSTALL_UNKNOWN_FAILURE", {install_failure}, &parser);
}

TEST(AnomalyDetectorTest, ESimInstallFailureBlocked) {
  ParserRun install_failure = {.expected_size = 0};
  HermesParser parser(/*testonly_send_all=*/true);
  ParserTest("TEST_ESIM_INSTALL_MALFORMED_RESPONSE", {install_failure},
             &parser);
}
