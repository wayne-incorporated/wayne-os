// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor.h"
#include "power_manager/powerd/system/ambient_light_sensor_delegate_file.h"

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

namespace power_manager::system {

class AmbientLightSensorFuzzer {
 public:
  AmbientLightSensorFuzzer() { CHECK(temp_dir_.CreateUniqueTempDir()); }
  AmbientLightSensorFuzzer(const AmbientLightSensorFuzzer&) = delete;
  AmbientLightSensorFuzzer& operator=(const AmbientLightSensorFuzzer&) = delete;

  ~AmbientLightSensorFuzzer() {
    CHECK(base::DeletePathRecursively(temp_dir_.GetPath()));
  }

  void SetUp(FuzzedDataProvider& data_provider, bool is_color) {
    base::FilePath device0_dir = temp_dir_.GetPath().Append("device0");
    CHECK(base::CreateDirectory(device0_dir));

    base::FilePath data0_file_ = device0_dir.Append("illuminance0_input");
    CHECK(brillo::WriteStringToFile(
        data0_file_,
        base::NumberToString(data_provider.ConsumeIntegral<uint32_t>())));

    // Add Color channels.
    if (is_color) {
      base::FilePath color_file = device0_dir.Append("in_illuminance_red_raw");
      CHECK(brillo::WriteStringToFile(
          color_file,
          base::NumberToString(data_provider.ConsumeIntegral<uint32_t>())));
      color_file = device0_dir.Append("in_illuminance_green_raw");
      CHECK(brillo::WriteStringToFile(
          color_file,
          base::NumberToString(data_provider.ConsumeIntegral<uint32_t>())));
      color_file = device0_dir.Append("in_illuminance_blue_raw");
      CHECK(brillo::WriteStringToFile(
          color_file,
          base::NumberToString(data_provider.ConsumeIntegral<uint32_t>())));
    }

    base::FilePath loc0_file_ = device0_dir.Append("location");
    CHECK(brillo::WriteStringToFile(loc0_file_, "lid"));

    sensor_ = std::make_unique<system::AmbientLightSensor>();

    auto als = std::make_unique<system::AmbientLightSensorDelegateFile>(
        SensorLocation::LID, false);
    als_ = als.get();

    sensor_->SetDelegate(std::move(als));
    als_->set_device_list_path_for_testing(temp_dir_.GetPath());
  }

  std::unique_ptr<AmbientLightSensor> sensor_;
  AmbientLightSensorDelegateFile* als_;

 protected:
  base::ScopedTempDir temp_dir_;
};

}  // namespace power_manager::system

// Disable logging.
struct Environment {
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

static void InitAndRunAls(
    bool is_color,
    FuzzedDataProvider& fuzz_dp,
    scoped_refptr<base::TestMockTimeTaskRunner> task_runner) {
  auto als_fuzzer =
      std::make_unique<power_manager::system::AmbientLightSensorFuzzer>();

  base::TestMockTimeTaskRunner::ScopedContext scoped_context(task_runner.get());
  als_fuzzer->SetUp(fuzz_dp, is_color);
  als_fuzzer->als_->Init(false /* read immediately */);

  // Move time ahead enough so that async file reads occur.
  task_runner->FastForwardBy(base::Milliseconds(4000));
}

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

  auto fuzz_dp = std::make_unique<FuzzedDataProvider>(data, size);
  // Test with color channels.
  InitAndRunAls(true, *fuzz_dp, task_runner);
  // Test without color channels.
  InitAndRunAls(false, *fuzz_dp, task_runner);

  return 0;
}
