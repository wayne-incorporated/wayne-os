// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/kernel_warning_collector.h"

#include <unistd.h>

#include <string>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

using base::FilePath;

namespace {

const char kTestFilename[] = "test-kernel-warning";
const char kTestCrashDirectory[] = "test-crash-directory";

}  // namespace

class KernelWarningCollectorMock : public KernelWarningCollector {
 public:
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

class KernelWarningCollectorTest : public ::testing::Test {
  void SetUp() {
    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_.Initialize(false);
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_path_ = scoped_temp_dir_.GetPath().Append(kTestFilename);
    collector_.warning_report_path_ = test_path_.value();

    test_crash_directory_ =
        scoped_temp_dir_.GetPath().Append(kTestCrashDirectory);
    CreateDirectory(test_crash_directory_);
    collector_.set_crash_directory_for_test(test_crash_directory_);
  }

 protected:
  KernelWarningCollectorMock collector_;
  base::ScopedTempDir scoped_temp_dir_;
  FilePath test_path_;
  FilePath test_crash_directory_;
};

TEST_F(KernelWarningCollectorTest, CollectOK) {
  // Collector produces a crash report.
  ASSERT_TRUE(
      test_util::CreateFile(test_path_,
                            "70e67541-iwl_mvm_rm_sta+0x161/0x344 [iwlmvm]()\n"
                            "\n"
                            "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(10, KernelWarningCollector::WarningType::kGeneric));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_warning_iwl_mvm_rm_sta.*.meta",
      "sig=70e67541-iwl_mvm_rm_sta+0x161/0x344 [iwlmvm]()"));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_warning_iwl_mvm_rm_sta.*.meta",
      "upload_var_weight=10"));
}

TEST_F(KernelWarningCollectorTest, CollectBad) {
  // Collector fails to collect a single line without newline
  ASSERT_TRUE(
      test_util::CreateFile(test_path_,
                            "[    0.000000] percpu: Embedded 32 pages/cpu "
                            "s91880 r8192 d31000 u131072"));
  EXPECT_FALSE(
      collector_.Collect(10, KernelWarningCollector::WarningType::kGeneric));
  EXPECT_TRUE(IsDirectoryEmpty(test_crash_directory_));
}

TEST_F(KernelWarningCollectorTest, CollectOKMultiline) {
  // Collector produces a crash report.
  ASSERT_TRUE(
      test_util::CreateFile(test_path_,
                            "Warning message trigger count: 0\n"
                            "70e67541-iwl_mvm_rm_sta+0x161/0x344 [iwlmvm]()\n"
                            "\n"
                            "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(10, KernelWarningCollector::WarningType::kGeneric));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_warning_iwl_mvm_rm_sta.*.meta",
      "sig=70e67541-iwl_mvm_rm_sta+0x161/0x344 [iwlmvm]()"));
}

TEST_F(KernelWarningCollectorTest, CollectOKUnknownFunc) {
  // Collector produces a crash report.
  ASSERT_TRUE(
      test_util::CreateFile(test_path_,
                            "70e67541-unknown-function+0x161/0x344 [iwlmvm]()\n"
                            "\n"
                            "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(10, KernelWarningCollector::WarningType::kGeneric));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_warning_unknown_function.*.meta",
      "sig=70e67541-unknown-function+0x161/0x344 [iwlmvm]()"));
}

TEST_F(KernelWarningCollectorTest, CollectOKBadSig) {
  // Collector produces a crash report.
  ASSERT_TRUE(test_util::CreateFile(test_path_,
                                    "70e67541-0x161/0x344 [iwlmvm]()\n"
                                    "\n"
                                    "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(10, KernelWarningCollector::WarningType::kGeneric));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_warning.*.meta",
      "sig=70e67541-0x161/0x344 [iwlmvm]()"));
}

TEST_F(KernelWarningCollectorTest, CollectWifiWarningOK) {
  // Collector produces a crash report with a different exec name.
  ASSERT_TRUE(
      test_util::CreateFile(test_path_,
                            "70e67541-iwl_mvm_rm_sta+0x161/0x344 [iwlmvm]()\n"
                            "\n"
                            "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(50, KernelWarningCollector::WarningType::kWifi));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_crash_directory_, "kernel_wifi_warning_iwl_mvm_rm_sta.*.meta",
      nullptr));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_wifi_warning_iwl_mvm_rm_sta.*.meta",
      "upload_var_weight=50"));
}

TEST_F(KernelWarningCollectorTest, CollectAth10k) {
  // Collector produces a crash report.
  ASSERT_TRUE(test_util::CreateFile(
      test_path_,
      "[393652.069986] ath10k_snoc 18800000.wifi: "
      "firmware crashed! (guid 7c8da1e6-f8fe-4665-8257-5a476a7bc786)\n"
      "[393652.070050] ath10k_snoc 18800000.wifi: "
      "wcn3990 hw1.0 target 0x00000008 chip_id 0x00000000 sub 0000:0000\n"
      "[393652.070086] ath10k_snoc 18800000.wifi: "
      "kconfig debug 1 debugfs 1 tracing 0 dfs 0 testmode 1\n"
      "[393652.070124] ath10k_snoc 18800000.wifi: "
      "firmware ver 1.0.0.922 api 5 features wowlan,mfp,mgmt-tx-"
      "by-reference,non-bmi,single-chan-info-per-channel crc32 3f19f7c1\n"
      "[393652.070158] ath10k_snoc 18800000.wifi: "
      "board_file api 2 bmi_id N/A crc32 00000000\n"
      "[393652.070195] ath10k_snoc 18800000.wifi: "
      "htt-ver 3.86 wmi-op 4 htt-op 3 cal file max-sta 32 raw 0 hwcrypto 1\n"
      "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(50, KernelWarningCollector::WarningType::kAth10k));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_ath10k_error_firmware_crashed.*.meta",
      "sig=ath10k_snoc 18800000.wifi: firmware crashed"));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_ath10k_error_firmware_crashed.*.meta",
      "upload_var_weight=50"));
}

TEST_F(KernelWarningCollectorTest, CollectUMACOK) {
  // Collector produces a crash report.
  ASSERT_TRUE(test_util::CreateFile(
      test_path_,
      "[47755.132606] iwlwifi 0000:00:14.3: Microcode SW error detected. "
      "Restarting 0x0.\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Start IWL Error Log Dump:\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Status: 0x00000040, count: 6\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Loaded firmware version: "
      "53.c31ac674.0 "
      "QuZ-a0-hr-b0-53.ucode\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000071 | "
      "NMI_INTERRUPT_UMAC_FATAL    \n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x000022F0 | trm_hw_status0\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | trm_hw_status1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x004C9C3A | branchlink2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00016176 | interruptlink1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00016176 | interruptlink2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x004C496C | data1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00001000 | data2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | data3\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x2D807673 | beacon time\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x95C4099B | tsf low\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000002 | tsf hi\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | time gp1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x011EEC18 | time gp2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000001 | uCode revision type\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000035 | uCode version major\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xC31AC674 | uCode version minor\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000351 | hw version\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00C89004 | board version\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x80B1FC19 | hcmd\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00020000 | isr0\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | isr1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x08F00002 | isr2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x04C37FCC | isr3\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | isr4\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x003B019C | last cmd Id\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x004C496C | wait_event\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | l2p_control\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | l2p_duration\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | l2p_mhvalid\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | l2p_addr_match\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x0000004B | lmpm_pmg_sel\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | timestamp\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x000050A8 | flow_handler\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Start IWL Error Log Dump:\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Status: 0x00000040, count: 7\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x201002FF | ADVANCED_SYSASSERT\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | umac branchlink1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x80467A40 | umac branchlink2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xC00866A8 | umac interruptlink1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | umac interruptlink2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x003C0102 | umac data1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xDEADBEEF | umac data2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xDEADBEEF | umac data3\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000035 | umac major\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xC31AC674 | umac minor\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x011EEC0D | frame pointer\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xC0886C40 | stack pointer\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x003C0102 | last host cmd\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | isr status reg\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Fseq Registers:\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x60000000 | FSEQ_ERROR_CODE\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x80290033 | "
      "FSEQ_TOP_INIT_VERSION\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00090006 | "
      "FSEQ_CNVIO_INIT_VERSION\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x0000A481 | FSEQ_OTP_VERSION\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000003 | "
      "FSEQ_TOP_CONTENT_VERSION\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x4552414E | FSEQ_ALIVE_TOKEN\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x20000302 | FSEQ_CNVI_ID\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x01300504 | FSEQ_CNVR_ID\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x20000302 | CNVI_AUX_MISC_CHIP\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x01300504 | CNVR_AUX_MISC_CHIP\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x05B0905B | "
      "CNVR_SCU_SD_REGS_SD_REG_DIG_DCDC_VTRIM\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x0000025B | "
      "CNVR_SCU_SD_REGS_SD_REG_ACTIVE_VDIG_MIRROR\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Collecting data: trigger 2 fired.\n"
      "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(50, KernelWarningCollector::WarningType::kIwlwifi));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_iwlwifi_error_ADVANCED_SYSASSERT.*.meta",
      "sig=iwlwifi 0000:00:14.3: 0x201002FF | ADVANCED_SYSASSERT"));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_iwlwifi_error_ADVANCED_SYSASSERT.*.meta",
      "upload_var_weight=50"));
}

TEST_F(KernelWarningCollectorTest, CollectSMMUFaultOk) {
  ASSERT_TRUE(test_util::CreateFile(
      test_path_,
      "[   74.047205] arm-smmu 15000000.iommu: Unhandled context fault: "
      "fsr=0x402, iova=0x04367000, fsynr=0x30023, cbfrsynra=0x800, cb=5\n"
      "[   75.303729] ath10k_snoc 18800000.wifi: failed to synchronize thermal "
      "read\n"
      "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(1, KernelWarningCollector::WarningType::kSMMUFault));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_smmu_fault_15000000_iommu.*.meta",
      "sig=fsr=0x402, iova=0x04367000, fsynr=0x30023, cbfrsynra=0x800, cb=5"));
  // Should *not* have a weight
  EXPECT_FALSE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_smmu_fault_15000000_iommu.*.meta",
      "upload_var_weight="));
}

TEST_F(KernelWarningCollectorTest, CollectSMMUFaultBad) {
  ASSERT_TRUE(test_util::CreateFile(
      test_path_,
      "[    1.566661] arm-smmu 5040000.iommu:  8 context banks "
      "(0 stage-2 only)\n"
      "[    1.573025] arm-smmu 5040000.iommu:  Supported page sizes: "
      "0x63315000\n"
      "[    1.579385] arm-smmu 5040000.iommu:  Stage-1: 48-bit VA -> "
      "36-bit IPA\n"
      "<remaining log contents>"));
  EXPECT_FALSE(
      collector_.Collect(1, KernelWarningCollector::WarningType::kSMMUFault));
  EXPECT_TRUE(IsDirectoryEmpty(test_crash_directory_));
}

TEST_F(KernelWarningCollectorTest, CollectLMACOK) {
  // Collector produces a crash report.
  ASSERT_TRUE(test_util::CreateFile(
      test_path_,
      "[47755.132606] iwlwifi 0000:00:14.3: Microcode SW error detected. "
      "Restarting 0x0.\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Start IWL Error Log Dump:\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Status: 0x00000040, count: 6\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Loaded firmware version: "
      "53.c31ac674.0 "
      "QuZ-a0-hr-b0-53.ucode\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000084 | NMI_INTERRUPT_UNKNOWN "
      "      \n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x000022F0 | trm_hw_status0\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | trm_hw_status1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x004C9C3A | branchlink2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x0000890E | interruptlink1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x0000890E | interruptlink2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x004C492A | data1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xFF000000 | data2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | data3\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xB180600C | beacon time\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x94A49FFF | tsf low\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000002 | tsf hi\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | time gp1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x10D5DCA1 | time gp2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000001 | uCode revision type\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000035 | uCode version major\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xC31AC674 | uCode version minor\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000351 | hw version\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00C89004 | board version\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x80F3FC19 | hcmd\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00020000 | isr0\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | isr1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x08F04002 | isr2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x04C01FCC | isr3\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | isr4\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00E4019C | last cmd Id\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x004C492A | wait_event\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | l2p_control\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | l2p_duration\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | l2p_mhvalid\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | l2p_addr_match\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000048 | lmpm_pmg_sel\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | timestamp\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x0000A8B8 | flow_handler\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Start IWL Error Log Dump:\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Status: 0x00000040, count: 7\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x20000066 | NMI_INTERRUPT_HOST\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | umac branchlink1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x80467A40 | umac branchlink2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | umac interruptlink1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x80475DFC | umac interruptlink2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x01000000 | umac data1\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x80475DFC | umac data2\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000000 | umac data3\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000035 | umac major\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xC31AC674 | umac minor\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x10D5DCA0 | frame pointer\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0xC088621C | stack pointer\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00E60400 | last host cmd\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000009 | isr status reg\n"
      "[47755.132606] iwlwifi 0000:00:14.3: Fseq Registers:\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x60000000 | FSEQ_ERROR_CODE\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x80290033 | "
      "FSEQ_TOP_INIT_VERSION\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00090006 | "
      "FSEQ_CNVIO_INIT_VERSION\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x0000A481 | FSEQ_OTP_VERSION\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x00000003 | "
      "FSEQ_TOP_CONTENT_VERSION\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x4552414E | FSEQ_ALIVE_TOKEN\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x20000302 | FSEQ_CNVI_ID\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x01300504 | FSEQ_CNVR_ID\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x20000302 | CNVI_AUX_MISC_CHIP\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x01300504 | CNVR_AUX_MISC_CHIP\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x05B0905B | "
      "CNVR_SCU_SD_REGS_SD_REG_DIG_DCDC_VTRIM\n"
      "[47755.132606] iwlwifi 0000:00:14.3: 0x0000025B | "
      "CNVR_SCU_SD_REGS_SD_REG_ACTIVE_VDIG_MIRROR\n"
      "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(50, KernelWarningCollector::WarningType::kIwlwifi));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_,
      "kernel_iwlwifi_error_NMI_INTERRUPT_UNKNOWN.*.meta",
      "sig=iwlwifi 0000:00:14.3: 0x00000084 | NMI_INTERRUPT_UNKNOWN"));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_,
      "kernel_iwlwifi_error_NMI_INTERRUPT_UNKNOWN.*.meta",
      "upload_var_weight=50"));
}

TEST_F(KernelWarningCollectorTest, CollectDriverError) {
  // Collector produces a crash report.
  ASSERT_TRUE(test_util::CreateFile(
      test_path_,
      "[47755.132606] iwlwifi 0000:01:00.0: Current CMD queue read_ptr 20 "
      "write_ptr 21\n"
      "[47755.132606] iwlwifi 0000:01:00.0: Loaded firmware version: "
      "17.bfb58538.0 "
      "7260-17.ucode\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | ADVANCED_SYSASSERT\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | trm_hw_status0\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | trm_hw_status1\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | branchlink2\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | interruptlink1\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | interruptlink2\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | data1\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | data2\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | data3\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | beacon time\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | tsf low\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | tsf hi\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | time gp1\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | time gp2\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | uCode revision type\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | uCode version major\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | uCode version minor\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | hw version\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | board version\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | hcmd\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | isr0\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | isr1\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | isr2\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | isr3\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | isr4\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | last cmd Id\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | wait_event\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | l2p_control\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | l2p_duration\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | l2p_mhvalid\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | l2p_addr_match\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | lmpm_pmg_sel\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | timestamp\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | flow_handler\n"
      "[47755.132606] iwlwifi 0000:01:00.0: Fseq Registers:\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | FSEQ_ERROR_CODE\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | "
      "FSEQ_TOP_INIT_VERSION\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | "
      "FSEQ_CNVIO_INIT_VERSION\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | FSEQ_OTP_VERSION\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | "
      "FSEQ_TOP_CONTENT_VERSION\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | FSEQ_ALIVE_TOKEN\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | FSEQ_CNVI_ID\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | FSEQ_CNVR_ID\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | CNVI_AUX_MISC_CHIP\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | CNVR_AUX_MISC_CHIP\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | "
      "CNVR_SCU_SD_REGS_SD_REG_DIG_DCDC_VTRIM\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | "
      "CNVR_SCU_SD_REGS_SD_REG_ACTIVE_VDIG_MIRROR\n"
      "[47755.132606] iwlwifi 0000:01:00.0: Collecting data: trigger 2 fired.\n"
      "ieee80211 phy0: Hardware restart was requested\n"
      "[47755.132606] iwlwifi 0000:01:00.0: Scan failed! ret -110\n"
      "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(50, KernelWarningCollector::WarningType::kIwlwifi));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_iwlwifi_error_ADVANCED_SYSASSERT.*.meta",
      "sig=iwlwifi 0000:01:00.0: 0x00000000 | ADVANCED_SYSASSERT"));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_iwlwifi_error_ADVANCED_SYSASSERT.*.meta",
      "upload_var_weight=50"));
}

TEST_F(KernelWarningCollectorTest, CollectOKBadIwlwifiSig) {
  // Collector produces a crash report.
  ASSERT_TRUE(test_util::CreateFile(
      test_path_,
      "[47755.132606] iwlwifi 0000:01:00.0: Microcode SW error detected. "
      "Restarting 0x0.\n"
      "[47755.132606] iwlwifi 0000:01:00.0: Start IWL Error Log Dump:\n"
      "[47755.132606] iwlwifi 0000:01:00.0: Status: 0x00000100, count: 6\n"
      "[47755.132606] iwlwifi 0000:01:00.0: Loaded firmware version: "
      "43.95eb4e97.0\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000071 | BAD_COMMAND\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x000022F0 | trm_hw_status0\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | trm_hw_status1\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x0000C860 | flow_handler\n"
      "[47755.132606] iwlwifi 0000:01:00.0: Start IWL Error Log Dump:\n"
      "[47755.132606] iwlwifi 0000:01:00.0: Status: 0x00000100, count: 7\n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x20000079 | \n"
      "[47755.132606] iwlwifi 0000:01:00.0: 0x00000000 | umac branchlink1\n"
      "<remaining log contents>"));
  EXPECT_TRUE(
      collector_.Collect(50, KernelWarningCollector::WarningType::kIwlwifi));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_iwlwifi_error.*.meta",
      "sig=iwlwifi unknown signature"));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      test_crash_directory_, "kernel_iwlwifi_error.*.meta",
      "upload_var_weight=50"));
}
