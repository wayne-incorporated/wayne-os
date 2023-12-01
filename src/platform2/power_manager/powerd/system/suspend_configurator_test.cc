// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/suspend_configurator.h"

#include <stdint.h>
#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <featured/fake_platform_features.h>
#include <gtest/gtest.h>

#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

// Path to write to configure system suspend mode.
static constexpr char kSuspendModePath[] = "/sys/power/mem_sleep";

// suspend to idle (S0iX) suspend mode
static constexpr char kSuspendModeFreeze[] = "s2idle";

// shallow/standby(S1) suspend mode
static constexpr char kSuspendModeShallow[] = "shallow";

// deep sleep(S3) suspend mode
static constexpr char kSuspendModeDeep[] = "deep";

static constexpr char kECLastResumeResultPath[] =
    "/sys/kernel/debug/cros_ec/last_resume_result";

static constexpr char kECResumeResultHang[] = "0x80000001";
static constexpr char kECResumeResultNoHang[] = "0x7FFFFFFF";

static constexpr char amd_cpuinfo_data[] =
    "processor       : 0\r\n"
    "vendor_id       : AuthenticAMD\r\n"
    "cpu family      : 23\r\n"
    "model           : 160\r\n"
    "model name      : AMD Eng Sample: 100-000000779-40_Y\r\n"
    "stepping        : 0\r\n"
    "microcode       : 0x8a00006\r\n"
    "cpu MHz         : 800.000\r\n"
    "cache size      : 512 KB\r\n"
    "physical id     : 0\r\n"
    "siblings        : 4\r\n"
    "core id         : 0\r\n"
    "cpu cores       : 2\r\n"
    "apicid          : 0\r\n"
    "initial apicid  : 0\r\n"
    "fpu             : yes\r\n"
    "fpu_exception   : yes\r\n"
    "cpuid level     : 16\r\n"
    "wp              : yes\r\n"
    "flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge "
    "mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext "
    "fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid "
    "extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 "
    "sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy "
    "svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs "
    "skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx "
    "cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase "
    "bmi1 avx2 smep bmi2 cqm rdt_a rdseed adx smap clflushopt clwb sha_ni "
    "xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total "
    "cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt "
    "lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists "
    "pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip rdpid "
    "overflow_recov succor smca sme sev sev_es\r\n"
    "bugs            : sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass "
    "retbleed\r\n"
    "bogomips        : 2395.60\r\n"
    "TLB size        : 3072 4K pages\r\n"
    "clflush size    : 64\r\n"
    "cache_alignment : 64\r\n"
    "address sizes   : 44 bits physical, 48 bits virtual\r\n"
    "power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]\r\n"
    "\r\n"
    "processor       : 1\r\n"
    "vendor_id       : AuthenticAMD\r\n"
    "cpu family      : 23\r\n"
    "model           : 160\r\n"
    "model name      : AMD Eng Sample: 100-000000779-40_Y\r\n"
    "stepping        : 0\r\n"
    "microcode       : 0x8a00006\r\n"
    "cpu MHz         : 1200.000\r\n"
    "cache size      : 512 KB\r\n"
    "physical id     : 0\r\n"
    "siblings        : 4\r\n"
    "core id         : 0\r\n"
    "cpu cores       : 2\r\n"
    "apicid          : 1\r\n"
    "initial apicid  : 1\r\n"
    "fpu             : yes\r\n"
    "fpu_exception   : yes\r\n"
    "cpuid level     : 16\r\n"
    "wp              : yes\r\n"
    "flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge "
    "mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext "
    "fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid "
    "extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 "
    "sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy "
    "svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs "
    "skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx "
    "cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase "
    "bmi1 avx2 smep bmi2 cqm rdt_a rdseed adx smap clflushopt clwb sha_ni "
    "xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total "
    "cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt "
    "lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists "
    "pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip rdpid "
    "overflow_recov succor smca sme sev sev_es\r\n"
    "bugs            : sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass "
    "retbleed\r\n"
    "bogomips        : 2395.60\r\n"
    "TLB size        : 3072 4K pages\r\n"
    "clflush size    : 64\r\n"
    "cache_alignment : 64\r\n"
    "address sizes   : 44 bits physical, 48 bits virtual\r\n"
    "power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]\r\n";

static constexpr char intel_cpuinfo_data[] =
    "processor       : 0\r\n"
    "vendor_id       : GenuineIntel\r\n"
    "cpu family      : 6\r\n"
    "model           : 141\r\n"
    "model name      : 11th Gen Intel(R) Core(TM) i7-11850H @ 2.50GHz\r\n"
    "stepping        : 1\r\n"
    "microcode       : 0x40\r\n"
    "cpu MHz         : 2500.000\r\n"
    "cache size      : 24576 KB\r\n"
    "physical id     : 0\r\n"
    "siblings        : 16\r\n"
    "core id         : 0\r\n"
    "cpu cores       : 8\r\n"
    "apicid          : 0\r\n"
    "initial apicid  : 0\r\n"
    "fpu             : yes\r\n"
    "fpu_exception   : yes\r\n"
    "cpuid level     : 27\r\n"
    "wp              : yes\r\n"
    "flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge "
    "mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe "
    "syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts "
    "rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni "
    "pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr "
    "pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave "
    "avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb cat_l2 "
    "invpcid_single cdp_l2 ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi "
    "flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms "
    "invpcid rdt_a avx512f avx512dq rdseed adx smap avx512ifma clflushopt "
    "clwb intel_pt avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 "
    "xsaves split_lock_detect dtherm ida arat pln pts hwp hwp_notify "
    "hwp_act_window hwp_epp hwp_pkg_req avx512vbmi umip pku ospke avx512_vbmi2 "
    "gfni vaes vpclmulqdq avx512_vnni avx512_bitalg tme avx512_vpopcntdq rdpid "
    "movdiri movdir64b fsrm avx512_vp2intersect md_clear ibt flush_l1d "
    "arch_capabilities\r\n"
    "vmx flags       : vnmi preemption_timer posted_intr invvpid ept_x_only "
    "ept_ad ept_1gb flexpriority apicv tsc_offset vtpr mtf vapic ept vpid "
    "unrestricted_guest vapic_reg vid ple shadow_vmcs pml ept_mode_based_exec "
    "tsc_scaling\r\n"
    "bugs            : spectre_v1 spectre_v2 spec_store_bypass swapgs "
    "eibrs_pbrsb\r\n"
    "bogomips        : 4992.00\r\n"
    "clflush size    : 64\r\n"
    "cache_alignment : 64\r\n"
    "address sizes   : 39 bits physical, 48 bits virtual\r\n"
    "power management:\r\n"
    "\r\n"
    "processor       : 1\r\n"
    "vendor_id       : GenuineIntel\r\n"
    "cpu family      : 6\r\n"
    "model           : 141\r\n"
    "model name      : 11th Gen Intel(R) Core(TM) i7-11850H @ 2.50GHz\r\n"
    "stepping        : 1\r\n"
    "microcode       : 0x40\r\n"
    "cpu MHz         : 2500.000\r\n"
    "cache size      : 24576 KB\r\n"
    "physical id     : 0\r\n"
    "siblings        : 16\r\n"
    "core id         : 1\r\n"
    "cpu cores       : 8\r\n"
    "apicid          : 2\r\n"
    "initial apicid  : 2\r\n"
    "fpu             : yes\r\n"
    "fpu_exception   : yes\r\n"
    "cpuid level     : 27\r\n"
    "wp              : yes\r\n"
    "flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge "
    "mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe "
    "syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts "
    "rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni "
    "pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr "
    "pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave "
    "avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb cat_l2 "
    "invpcid_single cdp_l2 ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi "
    "flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms "
    "invpcid rdt_a avx512f avx512dq rdseed adx smap avx512ifma clflushopt "
    "clwb intel_pt avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 "
    "xsaves split_lock_detect dtherm ida arat pln pts hwp hwp_notify "
    "hwp_act_window hwp_epp hwp_pkg_req avx512vbmi umip pku ospke avx512_vbmi2 "
    "gfni vaes vpclmulqdq avx512_vnni avx512_bitalg tme avx512_vpopcntdq rdpid "
    "movdiri movdir64b fsrm avx512_vp2intersect md_clear ibt flush_l1d "
    "arch_capabilities\r\n"
    "vmx flags       : vnmi preemption_timer posted_intr invvpid ept_x_only "
    "ept_ad ept_1gb flexpriority apicv tsc_offset vtpr mtf vapic ept vpid "
    "unrestricted_guest vapic_reg vid ple shadow_vmcs pml ept_mode_based_exec "
    "tsc_scaling\r\n"
    "bugs            : spectre_v1 spectre_v2 spec_store_bypass swapgs "
    "eibrs_pbrsb\r\n"
    "bogomips        : 4992.00\r\n"
    "clflush size    : 64\r\n"
    "cache_alignment : 64\r\n"
    "address sizes   : 39 bits physical, 48 bits virtual\r\n"
    "power management:\r\n";

// Creates an empty file rooted in |temp_root_dir|. For example if
// |temp_root_dir| is "/tmp/xxx" and |file_path| is "/sys/power/temp",
// creates "/tmp/xxx/sys/power/temp" with all necessary root directories.
void CreateFileInTempRootDir(const base::FilePath& temp_root_dir,
                             const std::string& file_path) {
  CHECK(!file_path.empty());
  CHECK(base::StartsWith(file_path, "/"));
  base::FilePath path = temp_root_dir.Append(file_path.substr(1));
  ASSERT_TRUE(base::CreateDirectory(path.DirName()));
  CHECK_EQ(base::WriteFile(path, "", 0), 0);
}
// Deletes a file rooted in |temp_root_dir|.
void DeleteFileInTempRootDir(const base::FilePath& temp_root_dir,
                             const std::string& file_path) {
  CHECK(!file_path.empty());
  CHECK(base::StartsWith(file_path, "/"));
  base::FilePath path = temp_root_dir.Append(file_path.substr(1));
  ASSERT_TRUE(base::DirectoryExists(path.DirName()));
  CHECK(base::DeleteFile(path));
}
}  // namespace

class SuspendConfiguratorTest : public TestEnvironment {
 public:
  SuspendConfiguratorTest() {
    // Temporary directory mimicking a root directory.
    CHECK(temp_root_dir_.CreateUniqueTempDir());
    base::FilePath temp_root_dir_path = temp_root_dir_.GetPath();
    suspend_configurator_.set_prefix_path_for_testing(temp_root_dir_path);
    platform_features_ =
        std::make_unique<feature::FakePlatformFeatures>(dbus_wrapper_.GetBus());

    CreateFileInTempRootDir(temp_root_dir_path,
                            SuspendConfigurator::kConsoleSuspendPath.value());
    CreateFileInTempRootDir(temp_root_dir_path, kSuspendModePath);
    CreateFileInTempRootDir(temp_root_dir_path, kCpuInfoPath);
  }

  ~SuspendConfiguratorTest() override = default;

 protected:
  // Returns |orig| rooted within the temporary root dir created for testing.
  base::FilePath GetPath(const base::FilePath& orig) const {
    return temp_root_dir_.GetPath().Append(orig.value().substr(1));
  }

  std::string ReadFile(const base::FilePath& file) {
    std::string file_contents;
    EXPECT_TRUE(base::ReadFileToString(file, &file_contents));
    return file_contents;
  }

  void WriteCpuInfoFile(const char cpuinfo_data[], size_t len) {
    base::FilePath cpuinfo_path = GetPath(base::FilePath(kCpuInfoPath));
    CHECK_EQ(base::WriteFile(cpuinfo_path, cpuinfo_data, len), len);
  }

  base::ScopedTempDir temp_root_dir_;
  system::DBusWrapperStub dbus_wrapper_;
  std::unique_ptr<feature::FakePlatformFeatures> platform_features_;
  FakePrefs prefs_;
  SuspendConfigurator suspend_configurator_;
};

// Test console is enabled during supend to S3 by default.
TEST_F(SuspendConfiguratorTest, TestDefaultConsoleSuspendForS3) {
  base::FilePath console_suspend_path =
      GetPath(SuspendConfigurator::kConsoleSuspendPath);
  prefs_.SetInt64(kSuspendToIdlePref, 0);
  suspend_configurator_.Init(platform_features_.get(), &prefs_);
  // Make sure console is enabled if system suspends to S3.
  EXPECT_EQ("N", ReadFile(console_suspend_path));
}

// Test console is disabled during supend to S0iX for Intel cpus
TEST_F(SuspendConfiguratorTest, TestDefaultConsoleSuspendForIntelS0ix) {
  base::FilePath console_suspend_path =
      GetPath(SuspendConfigurator::kConsoleSuspendPath);
  prefs_.SetInt64(kSuspendToIdlePref, 1);
  WriteCpuInfoFile(intel_cpuinfo_data, sizeof(intel_cpuinfo_data));
  suspend_configurator_.Init(platform_features_.get(), &prefs_);
  // Make sure console is disabled if S0ix is enabled.
  EXPECT_EQ("Y", ReadFile(console_suspend_path));
}

// Test console is enabled during supend to S0iX for AMD cpus
TEST_F(SuspendConfiguratorTest, TestDefaultConsoleSuspendForAmdS0ix) {
  base::FilePath console_suspend_path =
      GetPath(SuspendConfigurator::kConsoleSuspendPath);
  prefs_.SetInt64(kSuspendToIdlePref, 1);
  WriteCpuInfoFile(amd_cpuinfo_data, sizeof(amd_cpuinfo_data));
  suspend_configurator_.Init(platform_features_.get(), &prefs_);
  // Make sure console is enabled if S0ix is enabled.
  EXPECT_EQ("N", ReadFile(console_suspend_path));
}

// Test default value to suspend console is overwritten if
// |kEnableConsoleDuringSuspendPref| is set.
TEST_F(SuspendConfiguratorTest, TestDefaultConsoleSuspendOverwritten) {
  base::FilePath console_suspend_path =
      GetPath(SuspendConfigurator::kConsoleSuspendPath);
  prefs_.SetInt64(kSuspendToIdlePref, 1);
  prefs_.SetInt64(kEnableConsoleDuringSuspendPref, 1);
  suspend_configurator_.Init(platform_features_.get(), &prefs_);
  // Make sure console is not disabled though the default is to disable it.
  EXPECT_EQ("N", ReadFile(console_suspend_path));
}

// Test that suspend mode is set to |kSuspendModeFreeze| if suspend_to_idle is
// enabled.
TEST_F(SuspendConfiguratorTest, TestSuspendModeIdle) {
  base::FilePath suspend_mode_path = GetPath(base::FilePath(kSuspendModePath));
  // Suspend mode should be configured to |kSuspendModeFreeze| even when
  // |kSuspendModePref| is configured to something else.
  prefs_.SetInt64(kSuspendToIdlePref, 1);
  prefs_.SetString(kSuspendModePref, kSuspendModeShallow);
  suspend_configurator_.Init(platform_features_.get(), &prefs_);

  suspend_configurator_.PrepareForSuspend(base::TimeDelta());
  EXPECT_EQ(kSuspendModeFreeze, ReadFile(suspend_mode_path));
}

// Test that suspend mode is set to |kSuspendModeShallow| if |kSuspendModePref|
// is set to same when s0ix is not enabled.
TEST_F(SuspendConfiguratorTest, TestSuspendModeShallow) {
  base::FilePath suspend_mode_path = GetPath(base::FilePath(kSuspendModePath));
  prefs_.SetInt64(kSuspendToIdlePref, 0);
  prefs_.SetString(kSuspendModePref, kSuspendModeShallow);
  suspend_configurator_.Init(platform_features_.get(), &prefs_);

  suspend_configurator_.PrepareForSuspend(base::TimeDelta());
  EXPECT_EQ(kSuspendModeShallow, ReadFile(suspend_mode_path));
}

// Test that suspend mode is set to |kSuspendModeDeep| if |kSuspendModePref|
// is invalid .
TEST_F(SuspendConfiguratorTest, TestSuspendModeDeep) {
  base::FilePath suspend_mode_path = GetPath(base::FilePath(kSuspendModePath));
  prefs_.SetInt64(kSuspendToIdlePref, 0);
  prefs_.SetString(kSuspendModePref, "Junk");
  suspend_configurator_.Init(platform_features_.get(), &prefs_);

  suspend_configurator_.PrepareForSuspend(base::TimeDelta());
  EXPECT_EQ(kSuspendModeDeep, ReadFile(suspend_mode_path));
}

// Test that UndoPrepareForSuspend() returns success when
// |kECLastResumeResultPath| does not exist .
TEST_F(SuspendConfiguratorTest, TestNokECLastResumeResultPath) {
  EXPECT_TRUE(suspend_configurator_.UndoPrepareForSuspend());
}

// Test that UndoPrepareForSuspend() returns success/failure based on value in
// |kECLastResumeResultPath|.
TEST_F(SuspendConfiguratorTest, TestkECLastResumeResultPathExist) {
  CreateFileInTempRootDir(temp_root_dir_.GetPath(), kECLastResumeResultPath);
  // Empty |kECLastResumeResultPath| file should not fail suspend.
  EXPECT_TRUE(suspend_configurator_.UndoPrepareForSuspend());

  // Write a value that indicates hang to |kECLastResumeResultPath| and test
  // UndoPrepareForSuspend() returns false.
  std::string last_resume_result_string = kECResumeResultHang;
  ASSERT_EQ(base::WriteFile(GetPath(base::FilePath(kECLastResumeResultPath)),
                            last_resume_result_string.c_str(),
                            last_resume_result_string.length()),
            last_resume_result_string.length());
  EXPECT_FALSE(suspend_configurator_.UndoPrepareForSuspend());

  // Write a value that does not indicate hang to |kECLastResumeResultPath| and
  // test UndoPrepareForSuspend() returns true.
  last_resume_result_string = kECResumeResultNoHang;
  ASSERT_EQ(base::WriteFile(GetPath(base::FilePath(kECLastResumeResultPath)),
                            last_resume_result_string.c_str(),
                            last_resume_result_string.length()),
            last_resume_result_string.length());
  EXPECT_TRUE(suspend_configurator_.UndoPrepareForSuspend());
}

TEST_F(SuspendConfiguratorTest, TestIsHibernateAvailable) {
  suspend_configurator_.Init(platform_features_.get(), &prefs_);

  EXPECT_FALSE(suspend_configurator_.IsHibernateAvailable());

  CreateFileInTempRootDir(temp_root_dir_.GetPath(), kSnapshotDevicePath);
  EXPECT_FALSE(suspend_configurator_.IsHibernateAvailable());

  DeleteFileInTempRootDir(temp_root_dir_.GetPath(), kSnapshotDevicePath);
  CreateFileInTempRootDir(temp_root_dir_.GetPath(), kHibermanExecutablePath);
  EXPECT_FALSE(suspend_configurator_.IsHibernateAvailable());

  CreateFileInTempRootDir(temp_root_dir_.GetPath(), kSnapshotDevicePath);
  platform_features_->SetEnabled(kSuspendToHibernateFeatureName, true);
  EXPECT_TRUE(suspend_configurator_.IsHibernateAvailable());
  platform_features_->SetEnabled(kSuspendToHibernateFeatureName, false);
  EXPECT_FALSE(suspend_configurator_.IsHibernateAvailable());
}

}  // namespace power_manager::system
