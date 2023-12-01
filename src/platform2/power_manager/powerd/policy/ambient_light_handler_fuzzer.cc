// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Fuzzer for ambient_light_handler
//
// Randomly generate ambient light pref up to 10 steps and test reading
// the mock light sensor up to 10000 times.

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <vector>

#include "power_manager/powerd/policy/ambient_light_handler.h"
#include "power_manager/powerd/policy/ambient_light_pref_fuzz_util.h"
#include "power_manager/powerd/system/ambient_light_sensor_stub.h"

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

namespace power_manager::policy {

// AmbientLightHandler::Delegate implementation that does nothing.
class FuzzTestDelegate : public AmbientLightHandler::Delegate {
 public:
  FuzzTestDelegate() = default;
  ~FuzzTestDelegate() override = default;

  double percent() const { return 0; }
  AmbientLightHandler::BrightnessChangeCause cause() const {
    return AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT;
  }

  void SetBrightnessPercentForAmbientLight(
      double brightness_percent,
      AmbientLightHandler::BrightnessChangeCause cause) override {}

  void OnColorTemperatureChanged(int color_temperature) override {}
};

}  // namespace power_manager::policy

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);

  power_manager::system::AmbientLightSensorStub light_sensor(0);
  power_manager::policy::FuzzTestDelegate delegate;
  power_manager::policy::AmbientLightHandler handler(&light_sensor, &delegate);

  constexpr int kLuxMax = 20000;

  std::string pref =
      power_manager::policy::test::GenerateAmbientLightPref(&data_provider);

  double initial_brightness_percent =
      data_provider.ConsumeFloatingPointInRange<double>(0, 100);
  double smoothing_constant =
      data_provider.ConsumeFloatingPointInRange<double>(0.01, 1);

  handler.Init(pref, initial_brightness_percent, smoothing_constant);

  int num_readings = data_provider.ConsumeIntegralInRange<int>(0, 10000);
  for (int i = 0; i < num_readings; i++) {
    light_sensor.set_lux(data_provider.ConsumeIntegralInRange<int>(0, kLuxMax));
    handler.OnAmbientLightUpdated(&light_sensor);
  }

  return 0;
}
