// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Fuzzer for internal_backlight_controller
//
// Randomly generate ambient light pref up to 10 steps and initial lux
// to verify GetInitialBrightnessPercent().
// Then fuzz the SetBacklightBrightnessRequest proto up to 10000 times.

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <string>

#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/ambient_light_pref_fuzz_util.h"
#include "power_manager/powerd/policy/internal_backlight_controller.h"
#include "power_manager/powerd/system/ambient_light_sensor_stub.h"
#include "power_manager/powerd/system/backlight_stub.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/display/display_power_setter_stub.h"
#include "power_manager/proto_bindings/backlight.pb.h"

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);

  constexpr int kLuxMax = 20000;
  constexpr int kLevelMax = 65535;
  std::string kNoAlsAcBrightness = "80.0";
  std::string kNoAlsBatteryBrightness = "60.0";

  int initial_level = data_provider.ConsumeIntegralInRange<int>(0, kLevelMax);
  int initial_lux = data_provider.ConsumeIntegralInRange<int>(0, kLuxMax);

  power_manager::FakePrefs prefs;
  power_manager::system::AmbientLightSensorStub light_sensor(initial_lux);
  power_manager::system::BacklightStub backlight(
      kLevelMax, initial_level,
      power_manager::system::BacklightInterface::BrightnessScale::kUnknown);
  power_manager::system::DBusWrapperStub dbus_wrapper;
  power_manager::system::DisplayPowerSetterStub display_power_setter;

  // Need to be unique pointer to avoid ASAN stack-use-after-scope check.
  auto controller =
      std::make_unique<power_manager::policy::InternalBacklightController>();

  std::string ambient_light_pref =
      power_manager::policy::test::GenerateAmbientLightPref(&data_provider);

  prefs.SetString(power_manager::kInternalBacklightAlsStepsPref,
                  ambient_light_pref);
  prefs.SetString(power_manager::kInternalBacklightNoAlsAcBrightnessPref,
                  kNoAlsAcBrightness);
  prefs.SetString(power_manager::kInternalBacklightNoAlsBatteryBrightnessPref,
                  kNoAlsBatteryBrightness);
  prefs.SetDouble(power_manager::kAlsSmoothingConstantPref,
                  data_provider.ConsumeFloatingPointInRange<double>(0.01, 1));

  controller->Init(&backlight, &prefs, &light_sensor, &display_power_setter,
                   &dbus_wrapper, power_manager::LidState::OPEN);

  int num_adjusts = data_provider.ConsumeIntegralInRange<int>(0, 10000);
  for (int i = 0; i < num_adjusts; i++) {
    dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                                 power_manager::kSetScreenBrightnessMethod);
    dbus::MessageWriter writer(&method_call);

    power_manager::SetBacklightBrightnessRequest proto;
    proto.set_percent(
        data_provider.ConsumeFloatingPointInRange<double>(0, 100));
    proto.set_transition(
        power_manager::SetBacklightBrightnessRequest_Transition_INSTANT);
    proto.set_cause(
        data_provider.ConsumeBool()
            ? power_manager::SetBacklightBrightnessRequest_Cause_MODEL
            : power_manager::SetBacklightBrightnessRequest_Cause_USER_REQUEST);
    writer.AppendProtoAsArrayOfBytes(proto);
    dbus_wrapper.CallExportedMethodSync(&method_call);
  }
  return 0;
}
