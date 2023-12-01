// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/fetchers/cpu_fetcher.h"
#include "diagnostics/cros_healthd/system/fake_system_utilities.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/cros_healthd/system/system_utilities_constants.h"
#include "diagnostics/cros_healthd/utils/procfs_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"
#include "diagnostics/mojom/public/nullable_primitives.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::Invoke;
using ::testing::UnorderedElementsAreArray;
using VulnerabilityInfoMap =
    base::flat_map<std::string, mojom::VulnerabilityInfoPtr>;

// POD struct for ParseCpuArchitectureTest.
struct ParseCpuArchitectureTestParams {
  std::string uname_machine;
  mojom::CpuArchitectureEnum expected_mojo_enum;
};

// No other logical IDs should be used, or the logic for writing C-state files
// will break.
constexpr int kFirstLogicalId = 0;
constexpr int kSecondLogicalId = 1;
constexpr int kThirdLogicalId = 12;

// First C-State directory to be written.
constexpr char kFirstCStateDir[] = "state0";

constexpr char kNonIntegralFileContents[] = "Not an integer!";

constexpr char kHardwareDescriptionCpuinfoContents[] =
    "Hardware\t: Rockchip (Device Tree)\nRevision\t: 0000\nSerial\t: "
    "0000000000000000\n\n";
constexpr char kNoModelNameCpuinfoContents[] = "processor\t: 0\nflags\t:\n\n";
constexpr char kFakeCpuinfoContents[] =
    "processor\t: 0\nmodel name\t: Dank CPU 1 @ 8.90GHz\nflags\t:\n\n"
    "processor\t: 1\nmodel name\t: Dank CPU 1 @ 8.90GHz\nflags\t:\n\n"
    "processor\t: 12\nmodel name\t: Dank CPU 2 @ 2.80GHz\nflags\t:\n\n";
constexpr char kFirstFakeModelName[] = "Dank CPU 1 @ 8.90GHz";
constexpr char kSecondFakeModelName[] = "Dank CPU 2 @ 2.80GHz";

constexpr uint32_t kFirstFakeMaxClockSpeed = 3400000;
constexpr uint32_t kSecondFakeMaxClockSpeed = 1600000;
constexpr uint32_t kThirdFakeMaxClockSpeed = 1800000;

constexpr char kBadPresentContents[] = "Char-7";
constexpr char kFakePresentContents[] = "0-7";
constexpr uint32_t kExpectedNumTotalThreads = 8;

constexpr uint32_t kFirstFakeScalingCurrentFrequency = 859429;
constexpr uint32_t kSecondFakeScalingCurrentFrequency = 637382;
constexpr uint32_t kThirdFakeScalingCurrentFrequency = 737382;

constexpr uint32_t kFirstFakeScalingMaxFrequency = 2800000;
constexpr uint32_t kSecondFakeScalingMaxFrequency = 1400000;
constexpr uint32_t kThirdFakeScalingMaxFrequency = 1700000;

constexpr char kFirstFakeCStateNameContents[] = "C1-SKL";
constexpr uint64_t kFirstFakeCStateTime = 536018855;
constexpr char kSecondFakeCStateNameContents[] = "C10-SKL";
constexpr uint64_t kSecondFakeCStateTime = 473634000891;
constexpr char kThirdFakeCStateNameContents[] = "C7s-SKL";
constexpr uint64_t kThirdFakeCStateTime = 473634000891;
constexpr char kFourthFakeCStateNameContents[] = "C1E-SKL";
constexpr uint64_t kFourthFakeCStateTime = 79901786;

constexpr char kBadStatContents[] =
    "cpu   12389 69724 98732420 420347203\ncpu0  0 10 890 473634000891\n";
constexpr char kMissingLogicalCpuStatContents[] =
    "cpu   12389 69724 98732420 420347203\n"
    "cpu0  69234 98 0 2349\n"
    "cpu12 0 64823 293802 871239\n";
constexpr char kFakeStatContents[] =
    "cpu   12389 69724 98732420 420347203\n"
    "cpu0  69234 98 0 2349\n"
    "cpu1  989 0 4536824 123\n"
    "cpu12 0 64823 293802 871239\n";
constexpr uint64_t kFirstFakeUserTime = 69234;
constexpr uint64_t kFirstFakeSystemTime = 0;
constexpr uint32_t kFirstFakeIdleTime = 2349;
constexpr uint64_t kSecondFakeUserTime = 989;
constexpr uint64_t kSecondFakeSystemTime = 4536824;
constexpr uint32_t kSecondFakeIdleTime = 123;
constexpr uint64_t kThirdFakeUserTime = 0;
constexpr uint64_t kThirdFakeSystemTime = 293802;
constexpr uint32_t kThirdFakeIdleTime = 871239;

constexpr char kFirstFakeCpuTemperatureDir[] = "sys/class/hwmon/hwmon1/device";
constexpr char kFirstFakeCpuTemperatureInputFile[] = "temp9_input";
constexpr char kFirstFakeCpuTemperatureLabelFile[] = "name";
constexpr int32_t kFirstFakeCpuTemperature = -186;
constexpr int32_t kFirstFakeCpuTemperatureMilliDegrees =
    kFirstFakeCpuTemperature * 1000;
constexpr char kFirstFakeCpuTemperatureLabel[] = "First Temperature Label";
constexpr char kSecondFakeCpuTemperatureDir[] = "sys/class/hwmon/hwmon2";
constexpr char kSecondFakeCpuTemperatureInputFile[] = "temp1_input";
constexpr char kSecondFakeCpuTemperatureLabelFile[] = "temp1_label";
constexpr int32_t kSecondFakeCpuTemperature = 99;
constexpr int32_t kSecondFakeCpuTemperatureMilliDegrees =
    kSecondFakeCpuTemperature * 1000;
constexpr char kSecondFakeCpuTemperatureLabel[] = "Second Temperature Label";

constexpr char kFakeCryptoContents[] =
    "name\t: crypto_name\n"
    "driver\t: driver_name\n"
    "module\t: module_name\n";

constexpr char kSoCIDContents[] = "jep106:0426:8192";

// Workaround matchers for UnorderedElementsAreArray not accepting
// move-only types.

// This matcher expects a std::cref(mojom::CStateInfoPtr) and
// checks each of the fields for equality.
MATCHER_P(MatchesCStateInfoPtr, ptr, "") {
  return arg->name == ptr.get()->name &&
         arg->time_in_state_since_last_boot_us ==
             ptr.get()->time_in_state_since_last_boot_us;
}

// This matcher expects a std::cref(mojom::CpuTemperatureChannelPtr) and
// checks each of the fields for equality.
MATCHER_P(MatchesCpuTemperatureChannelPtr, ptr, "") {
  return arg->label == ptr.get()->label &&
         arg->temperature_celsius == ptr.get()->temperature_celsius;
}

// Note that this function only works for Logical CPUs with one or two C-states.
// Luckily, that's all we need for solid unit tests.
void VerifyLogicalCpu(
    uint32_t expected_max_clock_speed_khz,
    uint32_t expected_scaling_max_frequency_khz,
    uint32_t expected_scaling_current_frequency_khz,
    uint32_t expected_user_time_user_hz,
    uint32_t expected_system_time_user_hz,
    uint64_t expected_idle_time_user_hz,
    const std::vector<std::pair<std::string, uint64_t>>& expected_c_states,
    const mojom::LogicalCpuInfoPtr& actual_data) {
  ASSERT_FALSE(actual_data.is_null());
  EXPECT_EQ(actual_data->max_clock_speed_khz, expected_max_clock_speed_khz);
  EXPECT_EQ(actual_data->scaling_max_frequency_khz,
            expected_scaling_max_frequency_khz);
  EXPECT_EQ(actual_data->scaling_current_frequency_khz,
            expected_scaling_current_frequency_khz);
  EXPECT_EQ(actual_data->user_time_user_hz, expected_user_time_user_hz);
  EXPECT_EQ(actual_data->system_time_user_hz, expected_system_time_user_hz);
  EXPECT_EQ(actual_data->idle_time_user_hz, expected_idle_time_user_hz);

  const auto& c_states = actual_data->c_states;
  int c_state_size = c_states.size();
  int expected_c_state_size = expected_c_states.size();
  ASSERT_TRUE(c_state_size == expected_c_state_size &&
              (c_state_size == 1 || c_state_size == 2));
  if (c_state_size == 1) {
    const auto& c_state = c_states[0];
    ASSERT_FALSE(c_state.is_null());
    const auto& expected_c_state = expected_c_states[0];
    EXPECT_EQ(c_state->name, expected_c_state.first);
    EXPECT_EQ(c_state->time_in_state_since_last_boot_us,
              expected_c_state.second);
  } else {
    // Since fetching C-states uses base::FileEnumerator, we're not guaranteed
    // the order of the two results.
    auto first_expected_c_state = mojom::CpuCStateInfo::New(
        expected_c_states[0].first, expected_c_states[0].second);
    auto second_expected_c_state = mojom::CpuCStateInfo::New(
        expected_c_states[1].first, expected_c_states[1].second);
    EXPECT_THAT(
        c_states,
        UnorderedElementsAreArray(
            {MatchesCStateInfoPtr(std::cref(first_expected_c_state)),
             MatchesCStateInfoPtr(std::cref(second_expected_c_state))}));
  }
}

// Verifies that the two received CPU temperature channels have the correct
// values.
void VerifyCpuTemps(
    const std::vector<mojom::CpuTemperatureChannelPtr>& cpu_temps) {
  ASSERT_EQ(cpu_temps.size(), 2);

  // Since fetching temperatures uses base::FileEnumerator, we're not
  // guaranteed the order of the two results.
  auto first_expected_temp = mojom::CpuTemperatureChannel::New(
      kFirstFakeCpuTemperatureLabel, kFirstFakeCpuTemperature);
  auto second_expected_temp = mojom::CpuTemperatureChannel::New(
      kSecondFakeCpuTemperatureLabel, kSecondFakeCpuTemperature);
  EXPECT_THAT(
      cpu_temps,
      UnorderedElementsAreArray(
          {MatchesCpuTemperatureChannelPtr(std::cref(first_expected_temp)),
           MatchesCpuTemperatureChannelPtr(std::cref(second_expected_temp))}));
}

class CpuFetcherTest : public testing::Test {
 protected:
  CpuFetcherTest() = default;

  void SetUp() override {
    // Set up valid files for two physical CPUs, the first of which has two
    // logical CPUs. Individual tests are expected to override this
    // configuration when necessary.

    // Write /proc/cpuinfo.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcCpuInfoPath(root_dir()),
                                             kFakeCpuinfoContents));
    // Write /proc/stat.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcStatPath(root_dir()),
                                             kFakeStatContents));
    // Write /sys/devices/system/cpu/present.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        root_dir().Append(kRelativeCpuDir).Append(kPresentFileName),
        kFakePresentContents));
    // Write policy data for the first logical CPU.
    WritePolicyData(base::NumberToString(kFirstFakeMaxClockSpeed),
                    base::NumberToString(kFirstFakeScalingMaxFrequency),
                    base::NumberToString(kFirstFakeScalingCurrentFrequency),
                    kFirstLogicalId);
    // Write policy data for the second logical CPU.
    WritePolicyData(base::NumberToString(kSecondFakeMaxClockSpeed),
                    base::NumberToString(kSecondFakeScalingMaxFrequency),
                    base::NumberToString(kSecondFakeScalingCurrentFrequency),
                    kSecondLogicalId);
    // Write policy data for the third logical CPU.
    WritePolicyData(base::NumberToString(kThirdFakeMaxClockSpeed),
                    base::NumberToString(kThirdFakeScalingMaxFrequency),
                    base::NumberToString(kThirdFakeScalingCurrentFrequency),
                    kThirdLogicalId);
    // Write C-state data for the first logical CPU.
    WriteCStateData(kFirstCStates, kFirstLogicalId);
    // Write C-state data for the second logical CPU.
    WriteCStateData(kSecondCStates, kSecondLogicalId);
    // Write C-state data for the third logical CPU.
    WriteCStateData(kThirdCStates, kThirdLogicalId);

    // Write physical ID data for the first logical CPU.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetPhysicalPackageIdPath(root_dir(), kFirstLogicalId), "0"));
    // Write physical ID data for the second logical CPU.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetPhysicalPackageIdPath(root_dir(), kSecondLogicalId), "0"));
    // Write physical ID data for the third logical CPU.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetPhysicalPackageIdPath(root_dir(), kThirdLogicalId), "1"));

    // Write core ID data for the first logical CPU.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetCoreIdPath(root_dir(), kFirstLogicalId), "0"));
    // Write core ID data for the second logical CPU.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetCoreIdPath(root_dir(), kSecondLogicalId), "0"));
    // Write core ID data for the third logical CPU.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetCoreIdPath(root_dir(), kThirdLogicalId), "0"));

    // Write CPU temperature data.
    base::FilePath first_temp_dir =
        root_dir().AppendASCII(kFirstFakeCpuTemperatureDir);
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        first_temp_dir.AppendASCII(kFirstFakeCpuTemperatureInputFile),
        base::NumberToString(kFirstFakeCpuTemperatureMilliDegrees)));
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        first_temp_dir.AppendASCII(kFirstFakeCpuTemperatureLabelFile),
        kFirstFakeCpuTemperatureLabel));
    base::FilePath second_temp_dir =
        root_dir().AppendASCII(kSecondFakeCpuTemperatureDir);
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        second_temp_dir.AppendASCII(kSecondFakeCpuTemperatureInputFile),
        base::NumberToString(kSecondFakeCpuTemperatureMilliDegrees)));
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        second_temp_dir.AppendASCII(kSecondFakeCpuTemperatureLabelFile),
        kSecondFakeCpuTemperatureLabel));

    // Write /proc/crypto.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcCryptoPath(root_dir()),
                                             kFakeCryptoContents));
    // Set the fake uname response.
    fake_system_utils()->SetUnameResponse(/*ret_code=*/0, kUnameMachineX86_64);
    // Write the virtualization files.
    SetupDefaultVirtualizationFiles();
  }

  void TearDown() override {
    // Wait for all task to be done.
    task_environment_.RunUntilIdle();
  }

  // Write the fake vulnerability files for unit testing
  void SetVulnerabiility(const std::string& filename,
                         const std::string& content) {
    ASSERT_TRUE(WriteFileAndCreateParentDirs(root_dir()
                                                 .Append(kRelativeCpuDir)
                                                 .Append(kVulnerabilityDirName)
                                                 .Append(filename),
                                             content));
  }

  void SetupDefaultVirtualizationFiles() {
    ASSERT_TRUE(WriteFileAndCreateParentDirs(root_dir()
                                                 .Append(kRelativeCpuDir)
                                                 .Append(kSmtDirName)
                                                 .Append(kSmtActiveFileName),
                                             "1"));
    ASSERT_TRUE(WriteFileAndCreateParentDirs(root_dir()
                                                 .Append(kRelativeCpuDir)
                                                 .Append(kSmtDirName)
                                                 .Append(kSmtControlFileName),
                                             "on"));
  }

  const base::FilePath& root_dir() { return mock_context_.root_dir(); }
  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  FakeSystemUtilities* fake_system_utils() const {
    return mock_context_.fake_system_utils();
  }

  mojom::CpuResultPtr FetchCpuInfoSync() {
    base::test::TestFuture<mojom::CpuResultPtr> future;
    FetchCpuInfo(&mock_context_, future.GetCallback());
    return future.Take();
  }

  const std::vector<std::pair<std::string, uint64_t>>& GetCStateVector(
      int logical_id) {
    if (logical_id == kFirstLogicalId) {
      return kFirstCStates;
    } else if (logical_id == kSecondLogicalId) {
      return kSecondCStates;
    } else if (logical_id == kThirdLogicalId) {
      return kThirdCStates;
    }

    NOTREACHED();
    return kFirstCStates;
  }

  // Verifies that the received PhysicalCpuInfoPtrs matched the expected default
  // value.
  void VerifyPhysicalCpus(
      const std::vector<mojom::PhysicalCpuInfoPtr>& physical_cpus) {
    ASSERT_EQ(physical_cpus.size(), 2);
    const auto& first_physical_cpu = physical_cpus[0];
    ASSERT_FALSE(first_physical_cpu.is_null());
    EXPECT_EQ(first_physical_cpu->model_name, kFirstFakeModelName);
    const auto& first_logical_cpus = first_physical_cpu->logical_cpus;
    ASSERT_EQ(first_logical_cpus.size(), 2);
    VerifyLogicalCpu(kFirstFakeMaxClockSpeed, kFirstFakeScalingMaxFrequency,
                     kFirstFakeScalingCurrentFrequency, kFirstFakeUserTime,
                     kFirstFakeSystemTime, kFirstFakeIdleTime,
                     GetCStateVector(kFirstLogicalId), first_logical_cpus[0]);
    VerifyLogicalCpu(kSecondFakeMaxClockSpeed, kSecondFakeScalingMaxFrequency,
                     kSecondFakeScalingCurrentFrequency, kSecondFakeUserTime,
                     kSecondFakeSystemTime, kSecondFakeIdleTime,
                     GetCStateVector(kSecondLogicalId), first_logical_cpus[1]);
    const auto& second_physical_cpu = physical_cpus[1];
    ASSERT_FALSE(second_physical_cpu.is_null());
    EXPECT_EQ(second_physical_cpu->model_name, kSecondFakeModelName);
    const auto& second_logical_cpus = second_physical_cpu->logical_cpus;
    ASSERT_EQ(second_logical_cpus.size(), 1);
    VerifyLogicalCpu(kThirdFakeMaxClockSpeed, kThirdFakeScalingMaxFrequency,
                     kThirdFakeScalingCurrentFrequency, kThirdFakeUserTime,
                     kThirdFakeSystemTime, kThirdFakeIdleTime,
                     GetCStateVector(kThirdLogicalId), second_logical_cpus[0]);
  }

  void SetReadMsrResponse(uint32_t expected_msr_reg,
                          uint32_t expected_logical_id,
                          uint64_t expected_val) {
    EXPECT_CALL(*mock_executor(),
                ReadMsr(expected_msr_reg, expected_logical_id, _))
        .WillRepeatedly(
            Invoke([expected_val](uint32_t msr_reg, uint32_t cpu_index,
                                  mojom::Executor::ReadMsrCallback callback) {
              std::move(callback).Run(mojom::NullableUint64::New(expected_val));
            }));
  }

 private:
  // Writes pairs of data into the name and time files of the appropriate
  // C-state directory.
  void WriteCStateData(
      const std::vector<std::pair<std::string, uint64_t>>& data,
      int logical_id) {
    for (const auto& pair : data)
      WriteCStateFiles(logical_id, pair.first,
                       base::NumberToString(pair.second));
  }

  // Writes to cpuinfo_max_freq, scaling_max_freq, and scaling_cur_freq. If any
  // of the optional values are std::nullopt, the corresponding file will not
  // be written.
  void WritePolicyData(const std::string cpuinfo_max_freq_contents,
                       const std::string scaling_max_freq_contents,
                       const std::string scaling_cur_freq_contents,
                       int logical_id) {
    WritePolicyFile(logical_id, kCpuinfoMaxFreqFileName,
                    cpuinfo_max_freq_contents);

    WritePolicyFile(logical_id, kScalingMaxFreqFileName,
                    scaling_max_freq_contents);

    WritePolicyFile(logical_id, kScalingCurFreqFileName,
                    scaling_cur_freq_contents);
  }

  // Helper to write individual C-state files.
  void WriteCStateFiles(int logical_id,
                        const std::string& name_contents,
                        const std::string& time_contents) {
    auto policy_dir = GetCStateDirectoryPath(root_dir(), logical_id);
    int state_to_write = c_states_written[logical_id];
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        policy_dir.Append("state" + base::NumberToString(state_to_write))
            .Append(kCStateNameFileName),
        name_contents));
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        policy_dir.Append("state" + base::NumberToString(state_to_write))
            .Append(kCStateTimeFileName),
        time_contents));
    c_states_written[logical_id] += 1;
  }

  // Helper to write individual policy files.
  void WritePolicyFile(int logical_id,
                       const std::string& file_name,
                       const std::string& file_contents) {
    auto policy_dir = GetCpuFreqDirectoryPath(root_dir(), logical_id);
    ASSERT_TRUE(WriteFileAndCreateParentDirs(policy_dir.Append(file_name),
                                             file_contents));
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  MockContext mock_context_;
  // Records the next C-state file to be written.
  std::map<int, int> c_states_written = {
      {kFirstLogicalId, 0}, {kSecondLogicalId, 0}, {kThirdLogicalId, 0}};
  // C-state data for each of the three logical CPUs tested.
  const std::vector<std::pair<std::string, uint64_t>> kFirstCStates = {
      {kFirstFakeCStateNameContents, kFirstFakeCStateTime},
      {kSecondFakeCStateNameContents, kSecondFakeCStateTime}};
  const std::vector<std::pair<std::string, uint64_t>> kSecondCStates = {
      {kThirdFakeCStateNameContents, kThirdFakeCStateTime}};
  const std::vector<std::pair<std::string, uint64_t>> kThirdCStates = {
      {kFourthFakeCStateNameContents, kFourthFakeCStateTime}};
};

// Test that CPU info can be read when it exists.
TEST_F(CpuFetcherTest, TestFetchCpu) {
  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  EXPECT_EQ(cpu_info->num_total_threads, kExpectedNumTotalThreads);
  EXPECT_EQ(cpu_info->architecture, mojom::CpuArchitectureEnum::kX86_64);
  VerifyPhysicalCpus(cpu_info->physical_cpus);
  VerifyCpuTemps(cpu_info->temperature_channels);
}

// Test that we handle a cpuinfo file for processors without physical_ids.
TEST_F(CpuFetcherTest, NoPhysicalIdFile) {
  ASSERT_TRUE(brillo::DeleteFile(GetPhysicalPackageIdPath(root_dir(), 0)));

  auto cpu_result = FetchCpuInfoSync();
  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a missing cpuinfo file.
TEST_F(CpuFetcherTest, MissingCpuinfoFile) {
  ASSERT_TRUE(brillo::DeleteFile(GetProcCpuInfoPath(root_dir())));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle a cpuinfo file with a hardware description block.
TEST_F(CpuFetcherTest, HardwareDescriptionCpuinfoFile) {
  std::string cpu_info_contents = kFakeCpuinfoContents;
  cpu_info_contents += kHardwareDescriptionCpuinfoContents;
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcCpuInfoPath(root_dir()),
                                           cpu_info_contents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  EXPECT_EQ(cpu_info->num_total_threads, kExpectedNumTotalThreads);
  EXPECT_EQ(cpu_info->architecture, mojom::CpuArchitectureEnum::kX86_64);
  VerifyPhysicalCpus(cpu_info->physical_cpus);
  VerifyCpuTemps(cpu_info->temperature_channels);
}

// Test that we handle a cpuinfo file without a model name.
TEST_F(CpuFetcherTest, NoModelNameCpuinfoFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcCpuInfoPath(root_dir()),
                                           kNoModelNameCpuinfoContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus.size(), 1);
  EXPECT_FALSE(
      cpu_result->get_cpu_info()->physical_cpus[0]->model_name.has_value());
}

// Test that we handle a cpuinfo file without any CPU Flags.
TEST_F(CpuFetcherTest, NoCpuFlagsCpuinfoFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcCpuInfoPath(root_dir()),
      "processor\t: 0\nmodel name\t: Dank CPU 1 @ 8.90GHz\n\n"));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a cpuinfo file with valid CPU Flags.
TEST_F(CpuFetcherTest, ValidX86CpuFlagsCpuinfoFile) {
  ASSERT_TRUE(
      WriteFileAndCreateParentDirs(GetProcCpuInfoPath(root_dir()),
                                   "processor\t: 0\nmodel name\t: Dank CPU 1 @ "
                                   "8.90GHz\nflags\t: f1 f2 f3\n\n"));

  std::vector<std::string> expected{"f1", "f2", "f3"};

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus.size(), 1);
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus[0]->flags, expected);
}

// Test that we handle a cpuinfo file with valid CPU Flags.
TEST_F(CpuFetcherTest, ValidArmCpuFlagsCpuinfoFile) {
  ASSERT_TRUE(
      WriteFileAndCreateParentDirs(GetProcCpuInfoPath(root_dir()),
                                   "processor\t: 0\nmodel name\t: Dank CPU 1 @ "
                                   "8.90GHz\nFeatures\t: f1 f2 f3\n\n"));

  std::vector<std::string> expected{"f1", "f2", "f3"};

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus.size(), 1);
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus[0]->flags, expected);
}

// Test that we have soc_id for Arm devices.
TEST_F(CpuFetcherTest, ModelNameFromSoCID) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcCpuInfoPath(root_dir()),
                                           kNoModelNameCpuinfoContents));
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      root_dir().Append(kRelativeSoCDevicesDir).Append("soc0").Append("soc_id"),
      kSoCIDContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus.size(), 1);

  auto model_name = cpu_result->get_cpu_info()->physical_cpus[0]->model_name;
  EXPECT_TRUE(model_name.has_value());
  ASSERT_EQ(model_name.value(), "MediaTek 8192");
}

// Test that we have device tree compatible string for Arm devices.
TEST_F(CpuFetcherTest, ModelNameFromCompatibleString) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcCpuInfoPath(root_dir()),
                                           kNoModelNameCpuinfoContents));
  auto compatible_file = root_dir().Append(kRelativeCompatibleFile);
  ASSERT_TRUE(base::CreateDirectory(compatible_file.DirName()));

  constexpr uint8_t data[] = {'g', 'o', 'o', 'g',  'l', 'e', ',', 'h', 'a', 'y',
                              'a', 't', 'o', '\0', 'm', 'e', 'd', 'i', 'a', 't',
                              'e', 'k', ',', '8',  '1', '9', '2', '\0'};
  EXPECT_TRUE(base::WriteFile(compatible_file, data));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus.size(), 1);

  auto model_name = cpu_result->get_cpu_info()->physical_cpus[0]->model_name;
  EXPECT_TRUE(model_name.has_value());
  ASSERT_EQ(model_name.value(), "MediaTek 8192");
}

// Test that we handle a missing stat file.
TEST_F(CpuFetcherTest, MissingStatFile) {
  ASSERT_TRUE(brillo::DeleteFile(GetProcStatPath(root_dir())));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle an incorrectly-formatted stat file.
TEST_F(CpuFetcherTest, IncorrectlyFormattedStatFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcStatPath(root_dir()),
                                           kBadStatContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a stat file which is missing an entry for an existing
// logical CPU.
TEST_F(CpuFetcherTest, StatFileMissingLogicalCpuEntry) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcStatPath(root_dir()),
                                           kMissingLogicalCpuStatContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a missing present file.
TEST_F(CpuFetcherTest, MissingPresentFile) {
  ASSERT_TRUE(brillo::DeleteFile(
      root_dir().Append(kRelativeCpuDir).Append(kPresentFileName)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle an incorrectly-formatted present file.
TEST_F(CpuFetcherTest, IncorrectlyFormattedPresentFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      root_dir().Append(kRelativeCpuDir).Append(kPresentFileName),
      kBadPresentContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a single threaded present file.
TEST_F(CpuFetcherTest, SingleThreadedPresentFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      root_dir().Append(kRelativeCpuDir).Append(kPresentFileName), "0"));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  EXPECT_EQ(cpu_info->num_total_threads, 1);
}

// Test that we handle a complexly-formatted present file.
TEST_F(CpuFetcherTest, ComplexlyFormattedPresentFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      root_dir().Append(kRelativeCpuDir).Append(kPresentFileName),
      "0,2-3,5-7"));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  EXPECT_EQ(cpu_info->num_total_threads, 6);
}

// Test that we handle a missing cpuinfo_freq directory.
TEST_F(CpuFetcherTest, MissingCpuinfoFreqDirectory) {
  ASSERT_TRUE(brillo::DeletePathRecursively(
      GetCpuFreqDirectoryPath(root_dir(), kFirstLogicalId)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  const auto& logical_cpu_1 = cpu_info->physical_cpus[0]->logical_cpus[0];
  EXPECT_EQ(logical_cpu_1->max_clock_speed_khz, 0);
  EXPECT_EQ(logical_cpu_1->scaling_max_frequency_khz, 0);
  EXPECT_EQ(logical_cpu_1->scaling_current_frequency_khz, 0);
}

// Test that we handle a missing cpuinfo_max_freq file.
TEST_F(CpuFetcherTest, MissingCpuinfoMaxFreqFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetCpuFreqDirectoryPath(root_dir(), kFirstLogicalId)
                             .Append(kCpuinfoMaxFreqFileName)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle an incorrectly-formatted cpuinfo_max_freq file.
TEST_F(CpuFetcherTest, IncorrectlyFormattedCpuinfoMaxFreqFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetCpuFreqDirectoryPath(root_dir(), kFirstLogicalId)
          .Append(kCpuinfoMaxFreqFileName),
      kNonIntegralFileContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle a missing scaling_max_freq file.
TEST_F(CpuFetcherTest, MissingScalingMaxFreqFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetCpuFreqDirectoryPath(root_dir(), kFirstLogicalId)
                             .Append(kScalingMaxFreqFileName)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle an incorrectly-formatted scaling_max_freq file.
TEST_F(CpuFetcherTest, IncorrectlyFormattedScalingMaxFreqFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetCpuFreqDirectoryPath(root_dir(), kFirstLogicalId)
          .Append(kScalingMaxFreqFileName),
      kNonIntegralFileContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle a missing scaling_cur_freq file.
TEST_F(CpuFetcherTest, MissingScalingCurFreqFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetCpuFreqDirectoryPath(root_dir(), kFirstLogicalId)
                             .Append(kScalingCurFreqFileName)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle an incorrectly-formatted scaling_cur_freq file.
TEST_F(CpuFetcherTest, IncorrectlyFormattedScalingCurFreqFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetCpuFreqDirectoryPath(root_dir(), kFirstLogicalId)
          .Append(kScalingCurFreqFileName),
      kNonIntegralFileContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle a missing C-state name file.
TEST_F(CpuFetcherTest, MissingCStateNameFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetCStateDirectoryPath(root_dir(), kFirstLogicalId)
                             .Append(kFirstCStateDir)
                             .Append(kCStateNameFileName)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle a missing C-state time file.
TEST_F(CpuFetcherTest, MissingCStateTimeFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetCStateDirectoryPath(root_dir(), kFirstLogicalId)
                             .Append(kFirstCStateDir)
                             .Append(kCStateTimeFileName)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle an incorrectly-formatted C-state time file.
TEST_F(CpuFetcherTest, IncorrectlyFormattedCStateTimeFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetCStateDirectoryPath(root_dir(), kFirstLogicalId)
          .Append(kFirstCStateDir)
          .Append(kCStateTimeFileName),
      kNonIntegralFileContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle missing crypto file.
TEST_F(CpuFetcherTest, MissingCryptoFile) {
  ASSERT_TRUE(brillo::DeleteFile(GetProcCryptoPath(root_dir())));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle CPU temperatures without labels.
TEST_F(CpuFetcherTest, CpuTemperatureWithoutLabel) {
  ASSERT_TRUE(
      brillo::DeleteFile(root_dir()
                             .AppendASCII(kFirstFakeCpuTemperatureDir)
                             .AppendASCII(kFirstFakeCpuTemperatureLabelFile)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  EXPECT_EQ(cpu_info->num_total_threads, kExpectedNumTotalThreads);
  EXPECT_EQ(cpu_info->architecture, mojom::CpuArchitectureEnum::kX86_64);
  VerifyPhysicalCpus(cpu_info->physical_cpus);

  const auto& cpu_temps = cpu_info->temperature_channels;
  ASSERT_EQ(cpu_temps.size(), 2);

  // Since fetching temperatures uses base::FileEnumerator, we're not
  // guaranteed the order of the two results.
  auto first_expected_temp =
      mojom::CpuTemperatureChannel::New(std::nullopt, kFirstFakeCpuTemperature);
  auto second_expected_temp = mojom::CpuTemperatureChannel::New(
      kSecondFakeCpuTemperatureLabel, kSecondFakeCpuTemperature);
  EXPECT_THAT(
      cpu_temps,
      UnorderedElementsAreArray(
          {MatchesCpuTemperatureChannelPtr(std::cref(first_expected_temp)),
           MatchesCpuTemperatureChannelPtr(std::cref(second_expected_temp))}));
}

// Test that we handle incorrectly-formatted CPU temperature files.
TEST_F(CpuFetcherTest, IncorrectlyFormattedTemperature) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      root_dir()
          .AppendASCII(kFirstFakeCpuTemperatureDir)
          .AppendASCII(kFirstFakeCpuTemperatureInputFile),
      kNonIntegralFileContents));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  EXPECT_EQ(cpu_info->num_total_threads, kExpectedNumTotalThreads);
  EXPECT_EQ(cpu_info->architecture, mojom::CpuArchitectureEnum::kX86_64);
  VerifyPhysicalCpus(cpu_info->physical_cpus);

  // We shouldn't have data corresponding to the first fake temperature values,
  // because it was formatted incorrectly.
  const auto& cpu_temps = cpu_info->temperature_channels;
  ASSERT_EQ(cpu_temps.size(), 1);
  const auto& second_temp = cpu_temps[0];
  ASSERT_FALSE(second_temp.is_null());
  ASSERT_TRUE(second_temp->label.has_value());
  EXPECT_EQ(second_temp->label.value(), kSecondFakeCpuTemperatureLabel);
  EXPECT_EQ(second_temp->temperature_celsius, kSecondFakeCpuTemperature);
}

// Test that we handle uname failing.
TEST_F(CpuFetcherTest, UnameFailure) {
  fake_system_utils()->SetUnameResponse(-1, std::nullopt);

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  EXPECT_EQ(cpu_result->get_cpu_info()->architecture,
            mojom::CpuArchitectureEnum::kUnknown);
}

// Test that we handle normal vulnerability files.
TEST_F(CpuFetcherTest, NormalVulnerabilityFile) {
  VulnerabilityInfoMap expected;
  SetVulnerabiility("Vulnerability1", "Not affected");
  expected["Vulnerability1"] = mojom::VulnerabilityInfo::New(
      mojom::VulnerabilityInfo::Status::kNotAffected, "Not affected");
  SetVulnerabiility("Vulnerability2", "Vulnerable");
  expected["Vulnerability2"] = mojom::VulnerabilityInfo::New(
      mojom::VulnerabilityInfo::Status::kVulnerable, "Vulnerable");
  SetVulnerabiility("Vulnerability3", "Mitigation: Fake Mitigation Effect");
  expected["Vulnerability3"] = mojom::VulnerabilityInfo::New(
      mojom::VulnerabilityInfo::Status::kMitigation,
      "Mitigation: Fake Mitigation Effect");

  auto cpu_result = FetchCpuInfoSync();
  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  ASSERT_TRUE(cpu_info->vulnerabilities.has_value());
  EXPECT_EQ(cpu_info->vulnerabilities, expected);
}

// Test that we can parse status from vulnerability messages correctly.
TEST_F(CpuFetcherTest, ParseVulnerabilityMessageForStatus) {
  std::vector<std::pair<std::string, mojom::VulnerabilityInfo::Status>>
      message_to_expected_status = {
          {"Not affected", mojom::VulnerabilityInfo::Status::kNotAffected},
          {"Vulnerable", mojom::VulnerabilityInfo::Status::kVulnerable},
          {"Mitigation: Fake Mitigation Effect",
           mojom::VulnerabilityInfo::Status::kMitigation},
          {"Vulnerable: Vulnerable with message",
           mojom::VulnerabilityInfo::Status::kVulnerable},
          {"Unknown: Unknown status",
           mojom::VulnerabilityInfo::Status::kUnknown},
          {"KVM: Vulnerable: KVM vulnerability",
           mojom::VulnerabilityInfo::Status::kVulnerable},
          {"KVM: Mitigation: KVM mitigation",
           mojom::VulnerabilityInfo::Status::kMitigation},
          {"Processor vulnerable",
           mojom::VulnerabilityInfo::Status::kVulnerable},
          {"Random unrecognized message",
           mojom::VulnerabilityInfo::Status::kUnrecognized}};

  for (const auto& message_status : message_to_expected_status) {
    ASSERT_EQ(GetVulnerabilityStatusFromMessage(message_status.first),
              message_status.second);
  }
}

// Test that we handle missing kvm file.
TEST_F(CpuFetcherTest, MissingKvmFile) {
  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  ASSERT_EQ(cpu_info->virtualization->has_kvm_device, false);
}

// Test that we handle missing kvm file.
TEST_F(CpuFetcherTest, ExistingKvmFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      root_dir().Append(kRelativeKvmFilePath), ""));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  ASSERT_EQ(cpu_info->virtualization->has_kvm_device, true);
}

// Test that we handle missing SMT Active file.
TEST_F(CpuFetcherTest, MissingSmtActiveFile) {
  ASSERT_TRUE(brillo::DeleteFile(root_dir()
                                     .Append(kRelativeCpuDir)
                                     .Append(kSmtDirName)
                                     .Append(kSmtActiveFileName)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle Incorrectly Formatted SMT Active file.
TEST_F(CpuFetcherTest, IncorrectlyFormattedSMTActiveFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(root_dir()
                                               .Append(kRelativeCpuDir)
                                               .Append(kSmtDirName)
                                               .Append(kSmtActiveFileName),
                                           "1000"));
  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle Active SMT Active file.
TEST_F(CpuFetcherTest, ActiveSMTActiveFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(root_dir()
                                               .Append(kRelativeCpuDir)
                                               .Append(kSmtDirName)
                                               .Append(kSmtActiveFileName),
                                           "1"));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  ASSERT_EQ(cpu_info->virtualization->is_smt_active, true);
}

// Test that we handle Inactive SMT Active file.
TEST_F(CpuFetcherTest, InactiveSMTActiveFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(root_dir()
                                               .Append(kRelativeCpuDir)
                                               .Append(kSmtDirName)
                                               .Append(kSmtActiveFileName),
                                           "0"));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();
  ASSERT_EQ(cpu_info->virtualization->is_smt_active, false);
}

// Test that we handle missing SMT Control file.
TEST_F(CpuFetcherTest, MissingSmtControlFile) {
  ASSERT_TRUE(brillo::DeleteFile(root_dir()
                                     .Append(kRelativeCpuDir)
                                     .Append(kSmtDirName)
                                     .Append(kSmtControlFileName)));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kFileReadError);
}

// Test that we handle Incorrectly Formatted SMT Control file.
TEST_F(CpuFetcherTest, IncorrectlyFormattedSMTControlFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(root_dir()
                                               .Append(kRelativeCpuDir)
                                               .Append(kSmtDirName)
                                               .Append(kSmtControlFileName),
                                           "WRONG"));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kParseError);
}

// POD struct for ParseSmtControlTest.
struct ParseSmtControlTestParams {
  std::string smt_control_content;
  mojom::VirtualizationInfo::SMTControl expected_mojo_enum;
};

// Tests that CpuFetcher can correctly parse each known SMT Control.
//
// This is a parameterized test with the following parameters (accessed
// through the ParseSmtControlTestParams POD struct):
// * |raw_state| - written to /proc/|kPid|/stat's process state field.
// * |expected_mojo_state| - expected value of the returned ProcessInfo's state
//                           field.
class ParseSmtControlTest
    : public CpuFetcherTest,
      public testing::WithParamInterface<ParseSmtControlTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():
  ParseSmtControlTestParams params() const { return GetParam(); }
};

// Test that we can parse the given uname response for CPU architecture.
TEST_P(ParseSmtControlTest, ParseSmtControl) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(root_dir()
                                               .Append(kRelativeCpuDir)
                                               .Append(kSmtDirName)
                                               .Append(kSmtControlFileName),
                                           params().smt_control_content));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  EXPECT_EQ(cpu_result->get_cpu_info()->virtualization->smt_control,
            params().expected_mojo_enum);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    ParseSmtControlTest,
    testing::Values(
        ParseSmtControlTestParams{"on",
                                  mojom::VirtualizationInfo::SMTControl::kOn},
        ParseSmtControlTestParams{"off",
                                  mojom::VirtualizationInfo::SMTControl::kOff},
        ParseSmtControlTestParams{
            "forceoff", mojom::VirtualizationInfo::SMTControl::kForceOff},
        ParseSmtControlTestParams{
            "notsupported",
            mojom::VirtualizationInfo::SMTControl::kNotSupported},
        ParseSmtControlTestParams{
            "notimplemented",
            mojom::VirtualizationInfo::SMTControl::kNotImplemented}));

// Tests that CpuFetcher can correctly parse each known architecture.
//
// This is a parameterized test with the following parameters (accessed
// through the ParseCpuArchitectureTestParams POD struct):
// * |raw_state| - written to /proc/|kPid|/stat's process state field.
// * |expected_mojo_state| - expected value of the returned ProcessInfo's state
//                           field.
class ParseCpuArchitectureTest
    : public CpuFetcherTest,
      public testing::WithParamInterface<ParseCpuArchitectureTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():
  ParseCpuArchitectureTestParams params() const {
    return GetParam();
  }  // namespace
};   // namespace diagnostics

// Test that we can parse the given uname response for CPU architecture.
TEST_P(ParseCpuArchitectureTest, ParseUnameResponse) {
  fake_system_utils()->SetUnameResponse(0, params().uname_machine);

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  EXPECT_EQ(cpu_result->get_cpu_info()->architecture,
            params().expected_mojo_enum);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    ParseCpuArchitectureTest,
    testing::Values(
        ParseCpuArchitectureTestParams{kUnameMachineX86_64,
                                       mojom::CpuArchitectureEnum::kX86_64},
        ParseCpuArchitectureTestParams{kUnameMachineAArch64,
                                       mojom::CpuArchitectureEnum::kAArch64},
        ParseCpuArchitectureTestParams{kUnameMachineArmv7l,
                                       mojom::CpuArchitectureEnum::kArmv7l},
        ParseCpuArchitectureTestParams{"Unknown uname machine",
                                       mojom::CpuArchitectureEnum::kUnknown}));

// Test that we handle cpu with no virtualization.
TEST_F(CpuFetcherTest, NoVirtualizationEnabled) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcCpuInfoPath(root_dir()),
      "processor\t: 0\nmodel name\t: model\nflags\t: \n\n"));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus.size(), 1);
  ASSERT_TRUE(
      cpu_result->get_cpu_info()->physical_cpus[0]->virtualization.is_null());
}

// Test that we handle different flag values of vmx cpu virtualization.
TEST_F(CpuFetcherTest, TestVmxVirtualizationFlags) {
  // Add two CPUs, with the second CPU having a different physical ID compared
  // to logical ID.
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcCpuInfoPath(root_dir()),
      "processor\t: 0\nmodel name\t: model\nphysical id\t: 0\nflags\t:\n\n"
      "processor\t: 12\nmodel name\t: model\nphysical id\t: 1\nflags\t: "
      "vmx\n\n"));

  std::vector<
      std::tuple</*val*/ uint64_t, /*is_locked*/ bool, /*is_enabled*/ bool>>
      vmx_msr_tests = {{0, false, false},
                       {kIA32FeatureLocked, true, false},
                       {kIA32FeatureEnableVmxInsideSmx, false, true},
                       {kIA32FeatureEnableVmxOutsideSmx, false, true}};

  for (const auto& msr_test : vmx_msr_tests) {
    // Set the mock executor response for ReadMsr calls. Make sure that the call
    // uses logical ID instead of physical ID.
    SetReadMsrResponse(cpu_msr::kIA32FeatureControl, 12, std::get<0>(msr_test));

    auto cpu_result = FetchCpuInfoSync();

    ASSERT_TRUE(cpu_result->is_cpu_info());
    ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus.size(), 2);
    ASSERT_EQ(
        cpu_result->get_cpu_info()->physical_cpus[1]->virtualization->type,
        mojom::CpuVirtualizationInfo::Type::kVMX);
    ASSERT_EQ(
        cpu_result->get_cpu_info()->physical_cpus[1]->virtualization->is_locked,
        std::get<1>(msr_test));
    ASSERT_EQ(cpu_result->get_cpu_info()
                  ->physical_cpus[1]
                  ->virtualization->is_enabled,
              std::get<2>(msr_test));
  }
}

// Test that we handle different flag values of svm cpu virtualization.
TEST_F(CpuFetcherTest, TestSvmVirtualizationFlags) {
  // Add two CPUs, with the second CPU having a different physical ID compared
  // to logical ID.
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcCpuInfoPath(root_dir()),
      "processor\t: 0\nmodel name\t: model\nphysical id\t: 0\nflags\t:\n\n"
      "processor\t: 12\nmodel name\t: model\nphysical id\t: 1\nflags\t: "
      "svm\n\n"));

  std::vector<
      std::tuple</*val*/ uint64_t, /*is_locked*/ bool, /*is_enabled*/ bool>>
      svm_msr_tests = {{0, false, true},
                       {kVmCrLockedBit, true, true},
                       {kVmCrSvmeDisabledBit, false, false}};

  for (const auto& msr_test : svm_msr_tests) {
    // Set the mock executor response for ReadMsr calls. Make sure that the call
    // uses logical ID instead of physical ID.
    SetReadMsrResponse(cpu_msr::kVmCr, 12, std::get<0>(msr_test));

    auto cpu_result = FetchCpuInfoSync();

    ASSERT_TRUE(cpu_result->is_cpu_info());
    ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus.size(), 2);
    ASSERT_EQ(
        cpu_result->get_cpu_info()->physical_cpus[1]->virtualization->type,
        mojom::CpuVirtualizationInfo::Type::kSVM);
    ASSERT_EQ(
        cpu_result->get_cpu_info()->physical_cpus[1]->virtualization->is_locked,
        std::get<1>(msr_test));
    ASSERT_EQ(cpu_result->get_cpu_info()
                  ->physical_cpus[1]
                  ->virtualization->is_enabled,
              std::get<2>(msr_test));
  }
}

// Test that we handle different types of vmx cpu virtualization based on
// different physical CPU.
TEST_F(CpuFetcherTest, TestMultipleCpuVirtualization) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcCpuInfoPath(root_dir()),
      "processor\t: 0\nmodel name\t: model\nphysical id\t: 0\nflags\t: vmx\n\n"
      "processor\t: 12\nmodel name\t: model\nphysical id\t: 1\nflags\t: "
      "svm\n\n"));

  // Set the mock executor response for ReadMsr calls.
  SetReadMsrResponse(cpu_msr::kIA32FeatureControl, 0, 0);
  SetReadMsrResponse(cpu_msr::kVmCr, 12, 0);

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus.size(), 2);
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus[0]->virtualization->type,
            mojom::CpuVirtualizationInfo::Type::kVMX);
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus[1]->virtualization->type,
            mojom::CpuVirtualizationInfo::Type::kSVM);
}

TEST_F(CpuFetcherTest, TestParseCpuFlags) {
  // Test that "vmx flags" won't be treated as "flags".
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcCpuInfoPath(root_dir()),
      "processor\t: 0\nmodel name\t: model\nphysical id\t: 0\n"
      "flags\t: cpu_flags\nvmx flags\t:vmx_flags\n\n"));

  // Set the mock executor response for ReadMsr calls.
  SetReadMsrResponse(cpu_msr::kIA32FeatureControl, 0, 0);

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  ASSERT_EQ(cpu_result->get_cpu_info()->physical_cpus[0]->flags,
            std::vector<std::string>{"cpu_flags"});
}

TEST_F(CpuFetcherTest, ValidCoreIdFile) {
  // Write core ID data for the first logical CPU.
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetCoreIdPath(root_dir(), kFirstLogicalId), "10"));
  // Write core ID data for the second logical CPU.
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetCoreIdPath(root_dir(), kSecondLogicalId), "11"));
  // Write core ID data for the third logical CPU.
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetCoreIdPath(root_dir(), kThirdLogicalId), "12"));

  auto cpu_result = FetchCpuInfoSync();

  ASSERT_TRUE(cpu_result->is_cpu_info());
  const auto& cpu_info = cpu_result->get_cpu_info();

  ASSERT_EQ(cpu_info->physical_cpus.size(), 2);
  ASSERT_EQ(cpu_info->physical_cpus[0]->logical_cpus.size(), 2);
  ASSERT_EQ(cpu_info->physical_cpus[1]->logical_cpus.size(), 1);
  EXPECT_EQ(cpu_info->physical_cpus[0]->logical_cpus[0]->core_id, 10);
  EXPECT_EQ(cpu_info->physical_cpus[0]->logical_cpus[1]->core_id, 11);
  EXPECT_EQ(cpu_info->physical_cpus[1]->logical_cpus[0]->core_id, 12);
}

TEST_F(CpuFetcherTest, InvalidCoreIdFile) {
  // Write core ID data for the first logical CPU.
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetCoreIdPath(root_dir(), kFirstLogicalId), "InvalidContent"));

  auto cpu_result = FetchCpuInfoSync();
  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a cpuinfo file for processors without core_id.
TEST_F(CpuFetcherTest, NoCoreIdFile) {
  ASSERT_TRUE(base::DeleteFile(GetCoreIdPath(root_dir(), 0)));

  auto cpu_result = FetchCpuInfoSync();
  ASSERT_TRUE(cpu_result->is_error());
  EXPECT_EQ(cpu_result->get_error()->type, mojom::ErrorType::kParseError);
}
}  // namespace
}  // namespace diagnostics
