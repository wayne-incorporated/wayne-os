// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Fuzzer for thermal_device / cooling_device
//
// Randomly generate sysfs data for cooling device

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/current_thread.h>
#include <base/task/single_thread_task_executor.h>
#include <base/test/test_mock_time_task_runner.h>
#include <brillo/file_utils.h>
#include <brillo/message_loops/base_message_loop.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "power_manager/powerd/system/thermal/cooling_device.h"
#include "power_manager/powerd/system/thermal/thermal_device_factory.h"

namespace {
constexpr base::TimeDelta kPollInterval = base::Milliseconds(10);
}  // namespace

namespace power_manager::system {

namespace {

std::string GenerateCoolingDeviceType(FuzzedDataProvider* data_provider) {
  bool is_random_type = data_provider->ConsumeBool();

  if (is_random_type)
    return data_provider->ConsumeRandomLengthString(32);

  std::string types[] = {"Processor", "TFN1", "TCHG"};
  return types[data_provider->ConsumeIntegralInRange(0, 2)];
}

void WriteNumberToFile(base::FilePath file, int num) {
  std::string num_string = base::NumberToString(num);
  CHECK(brillo::WriteStringToFile(file, num_string));
}

}  // namespace

class ThermalDeviceFuzzer {
 public:
  ThermalDeviceFuzzer() { CHECK(scoped_temp_dir_.CreateUniqueTempDir()); }
  ThermalDeviceFuzzer(const ThermalDeviceFuzzer&) = delete;
  ThermalDeviceFuzzer& operator=(const ThermalDeviceFuzzer&) = delete;

  ~ThermalDeviceFuzzer() {
    CHECK(base::DeletePathRecursively(scoped_temp_dir_.GetPath()));
  }

  // Setup sysfs and create cooling device using ThermalDeviceFactory.
  void Setup(FuzzedDataProvider* data_provider) {
    base::FilePath temp_dir = scoped_temp_dir_.GetPath();
    std::vector<std::string> dirs;

    base::FilePath device_dir = temp_dir.Append("cooling_device0");
    CHECK(base::CreateDirectory(device_dir));

    std::string type = GenerateCoolingDeviceType(data_provider);
    base::FilePath type_file = device_dir.Append("type");
    CHECK(brillo::WriteStringToFile(type_file, type));

    max_state_ = data_provider->ConsumeIntegralInRange(0, 100);
    base::FilePath max_state_file = device_dir.Append("max_state");
    WriteNumberToFile(max_state_file, max_state_);

    cur_state_file_ = device_dir.Append("cur_state");
    WriteNumberToFile(cur_state_file_, 0);

    auto cooling_devices =
        ThermalDeviceFactory::CreateThermalDevices(temp_dir.value().c_str());
    CHECK_EQ(cooling_devices.size(), 1);

    // Move cooling_devices_[0] to cooling_device
    cooling_device.reset(static_cast<CoolingDevice*>(cooling_devices[0].get()));
    cooling_devices[0].release();

    cooling_device->set_poll_interval_for_testing(kPollInterval);
    cooling_device->Init(false /* read_immedieatly */);
  }

  void WriteNewThermalData(FuzzedDataProvider* data_provider) {
    int cur_state = data_provider->ConsumeIntegralInRange(0, max_state_);
    WriteNumberToFile(cur_state_file_, cur_state);
  }

 private:
  base::ScopedTempDir scoped_temp_dir_;
  base::FilePath cur_state_file_;
  int max_state_;
  std::unique_ptr<CoolingDevice> cooling_device;
};

}  // namespace power_manager::system

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  // Mock main task runner
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      new base::TestMockTimeTaskRunner();
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  // Add a TaskRunner where we can control time.
  base::CurrentIOThread::Get()->SetTaskRunner(task_runner);

  // Initialize brillo::BaseMessageLoop
  brillo::BaseMessageLoop brillo_loop(task_runner);
  brillo_loop.SetAsCurrent();

  auto fuzzed_data_provider = std::make_unique<FuzzedDataProvider>(data, size);
  auto thermal_device_fuzzer =
      std::make_unique<power_manager::system::ThermalDeviceFuzzer>();

  thermal_device_fuzzer->Setup(fuzzed_data_provider.get());

  for (int i = 0; i < 100; i++) {
    thermal_device_fuzzer->WriteNewThermalData(fuzzed_data_provider.get());
    task_runner->FastForwardBy(kPollInterval);
  }

  return 0;
}
