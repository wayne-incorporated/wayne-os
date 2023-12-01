// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/containers/span.h>
#include <base/notreached.h>
#include <gtest/gtest.h>

#include "runtime_probe/functions/input_device.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

constexpr auto kInputDevicesPath = "/proc/bus/input/devices";

constexpr auto kBitsPerBitmap = sizeof(long) * CHAR_BIT;  // NOLINT(runtime/int)

std::string GetStylusKey() {
  if (kBitsPerBitmap == 64) {
    return "800 0 0 0 0 0";
  } else if (kBitsPerBitmap == 32) {
    return "800 0 0 0 0 0 0 0 0 0 0";
  } else {
    NOTREACHED() << "Invalid kBitsPerBitmap: " << kBitsPerBitmap;
    return "";
  }
}

std::string GetTouchscreenAbs() {
  if (kBitsPerBitmap == 64) {
    return "800000000000";
  } else if (kBitsPerBitmap == 32) {
    return "8000 0";
  } else {
    NOTREACHED() << "Invalid kBitsPerBitmap: " << kBitsPerBitmap;
    return "";
  }
}

std::string GetTouchpadKey() {
  if (kBitsPerBitmap == 64) {
    return "400 10000 0 0 0 0";
  } else if (kBitsPerBitmap == 32) {
    return "400 0 10000 0 0 0 0 0 0 0 0";
  } else {
    NOTREACHED() << "Invalid kBitsPerBitmap: " << kBitsPerBitmap;
    return "";
  }
}

class InputDeviceFunctionTest : public BaseFunctionTest {};

TEST_F(InputDeviceFunctionTest, ProbeStylus) {
  // Input device with KEY representing a stylus.
  std::string input_device =
      R"(I: Bus=1234 Vendor=5678 Product=90ab Version=cdef
N: Name="Stylus 1"
P: Phys=i2c-ELAN6915:00
S: Sysfs=/devices/XXX/1234:5678:90ab.0001/input/input7
H: Handlers=event7
B: KEY=)" +
      GetStylusKey() + R"(
B: ABS=0)";

  SetFile(kInputDevicesPath, input_device);
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "bus": "1234",
        "device_type": "TYPE_STYLUS",
        "event": "event7",
        "name": "Stylus 1",
        "product": "90ab",
        "vendor": "5678",
        "version": "cdef"
      }
    ]
  )JSON");
  ans[0].GetDict().Set(
      "path",
      GetPathUnderRoot({"sys/devices/XXX/1234:5678:90ab.0001/input/input7"})
          .value());

  auto probe_function = CreateProbeFunction<InputDeviceFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(InputDeviceFunctionTest, ProbeTouchscreen) {
  // Input device with KEY representing a touchscreen.
  std::string input_device =
      R"(I: Bus=0018 Vendor=04f3 Product=2d5a Version=0100
N: Name="Touchscreen 1"
P: Phys=i2c-ELAN6915:00
S: Sysfs=/devices/XXX/0018:04F3:2D5A.0001/input/input4
H: Handlers=event4
B: KEY=0
B: ABS=)" +
      GetTouchscreenAbs();

  SetFile(kInputDevicesPath, input_device);
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "bus": "0018",
        "device_type": "TYPE_TOUCHSCREEN",
        "event": "event4",
        "name": "Touchscreen 1",
        "product": "2d5a",
        "vendor": "04f3",
        "version": "0100"
      }
    ]
  )JSON");
  ans[0].GetDict().Set(
      "path",
      GetPathUnderRoot({"sys/devices/XXX/0018:04F3:2D5A.0001/input/input4"})
          .value());

  auto probe_function = CreateProbeFunction<InputDeviceFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(InputDeviceFunctionTest, ProbeTouchpad) {
  // Input device with KEY and ABS representing a touchpad.
  std::string input_device =
      R"(I: Bus=0018 Vendor=04f3 Product=00bc Version=0000
N: Name="Touchpad 1"
P: Phys=
S: Sysfs=/devices/XXX/i2c-ELAN0000:00/input/input11
H: Handlers=event9
B: KEY=)" +
      GetTouchpadKey() + R"(
B: ABS=0)";

  SetFile(kInputDevicesPath, input_device);
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "bus": "0018",
        "device_type": "TYPE_TOUCHPAD",
        "event": "event9",
        "name": "Touchpad 1",
        "product": "00bc",
        "vendor": "04f3",
        "version": "0000"
      }
    ]
  )JSON");
  ans[0].GetDict().Set(
      "path",
      GetPathUnderRoot({"sys/devices/XXX/i2c-ELAN0000:00/input/input11"})
          .value());

  auto probe_function = CreateProbeFunction<InputDeviceFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(InputDeviceFunctionTest, ProbeUnknowInputDevice) {
  // Input device that is not a stylus, touchscreen or touchpad.
  std::string input_device =
      R"(I: Bus=0000 Vendor=0000 Product=0000 Version=0000
N: Name="Unknown Device 1"
P: Phys=ALSA
S: Sysfs=/devices/XXX/jsl_rt5682_rt1015/sound/card0/input12
H: Handlers=kbd event10
B: KEY=0
B: SW=14)";

  SetFile(kInputDevicesPath, input_device);
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "bus": "0000",
        "device_type": "TYPE_UNKNOWN",
        "event": "event10",
        "name": "Unknown Device 1",
        "product": "0000",
        "vendor": "0000",
        "version": "0000"
      }
    ]
  )JSON");
  ans[0].GetDict().Set(
      "path", GetPathUnderRoot(
                  {"sys/devices/XXX/jsl_rt5682_rt1015/sound/card0/input12"})
                  .value());

  auto probe_function = CreateProbeFunction<InputDeviceFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(InputDeviceFunctionTest, ProbeMultipleInputDevices) {
  std::string input_devices =
      R"(I: Bus=1234 Vendor=5678 Product=90ab Version=cdef
N: Name="Stylus 1"
P: Phys=i2c-ELAN6915:00
S: Sysfs=/devices/XXX/1234:5678:90ab.0001/input/input7
H: Handlers=event7
B: KEY=)" +
      GetStylusKey() + R"(
B: ABS=0

I: Bus=0018 Vendor=04f3 Product=2d5a Version=0100
N: Name="Touchscreen 1"
P: Phys=i2c-ELAN6915:00
S: Sysfs=/devices/XXX/0018:04F3:2D5A.0001/input/input4
H: Handlers=event4
B: KEY=0
B: ABS=)" +
      GetTouchscreenAbs();

  SetFile(kInputDevicesPath, input_devices);

  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "bus": "1234",
        "device_type": "TYPE_STYLUS",
        "event": "event7",
        "name": "Stylus 1",
        "product": "90ab",
        "vendor": "5678",
        "version": "cdef"
      },
      {
        "bus": "0018",
        "device_type": "TYPE_TOUCHSCREEN",
        "event": "event4",
        "name": "Touchscreen 1",
        "product": "2d5a",
        "vendor": "04f3",
        "version": "0100"
      }
    ]
  )JSON");
  ans[0].GetDict().Set(
      "path",
      GetPathUnderRoot({"sys/devices/XXX/1234:5678:90ab.0001/input/input7"})
          .value());
  ans[1].GetDict().Set(
      "path",
      GetPathUnderRoot({"sys/devices/XXX/0018:04F3:2D5A.0001/input/input4"})
          .value());

  auto probe_function = CreateProbeFunction<InputDeviceFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(InputDeviceFunctionTest, ProbeFilteredInputDevice) {
  std::string input_devices =
      R"(I: Bus=1234 Vendor=5678 Product=90ab Version=cdef
N: Name="Stylus 1"
P: Phys=i2c-ELAN6915:00
S: Sysfs=/devices/XXX/1234:5678:90ab.0001/input/input7
H: Handlers=event7
B: KEY=)" +
      GetStylusKey() + R"(
B: ABS=0

I: Bus=0018 Vendor=04f3 Product=2d5a Version=0100
N: Name="Touchscreen 1"
P: Phys=i2c-ELAN6915:00
S: Sysfs=/devices/XXX/0018:04F3:2D5A.0001/input/input4
H: Handlers=event4
B: KEY=0
B: ABS=)" +
      GetTouchscreenAbs();

  SetFile(kInputDevicesPath, input_devices);

  base::Value::Dict arg;
  arg.Set("device_type", "stylus");

  // Only contain results of given device type.
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "bus": "1234",
        "device_type": "TYPE_STYLUS",
        "event": "event7",
        "name": "Stylus 1",
        "product": "90ab",
        "vendor": "5678",
        "version": "cdef"
      }
    ]
  )JSON");
  ans[0].GetDict().Set(
      "path",
      GetPathUnderRoot({"sys/devices/XXX/1234:5678:90ab.0001/input/input7"})
          .value());

  auto probe_function = CreateProbeFunction<InputDeviceFunction>(arg);
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(InputDeviceFunctionTest, ProbeTouchscreenI2cDevice) {
  std::string input_device =
      R"(I: Bus=0018 Vendor=0000 Product=2d5a Version=0100
N: Name="ELAN0001:00 0000:2D5A"
P: Phys=i2c-ELAN0001:00
S: Sysfs=/devices/XXX/i2c-ELAN0001:00/0018:0000:2D5A.0001/input/input4
H: Handlers=event4
B: KEY=0
B: ABS=)" +
      GetTouchscreenAbs();

  SetFile(kInputDevicesPath, input_device);

  SetDirectory("sys/bus/i2c/drivers/elants_i2c");
  SetSymbolicLink("/sys/bus/i2c/drivers/elants_i2c",
                  "sys/devices/XXX/i2c-ELAN0001:00/0018:0000:2D5A.0001/input/"
                  "input4/device/driver");
  SetFile({"sys/devices/XXX/i2c-ELAN0001:00/0018:0000:2D5A.0001/input/input4/"
           "device/name"},
          "ABCD0000");
  SetFile({"sys/devices/XXX/i2c-ELAN0001:00/0018:0000:2D5A.0001/input/input4/"
           "device/hw_version"},
          "1234");
  SetFile({"sys/devices/XXX/i2c-ELAN0001:00/0018:0000:2D5A.0001/input/input4/"
           "device/fw_version"},
          "5678");

  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "bus": "0018",
        "device_type": "TYPE_TOUCHSCREEN",
        "event": "event4",
        "name": "ABCD0000",
        "product": "1234",
        "vendor": "04f3",
        "version": "0100",
        "fw_version": "5678"
      }
    ]
  )JSON");

  ans[0].GetDict().Set(
      "path",
      GetPathUnderRoot(
          {"sys/devices/XXX/i2c-ELAN0001:00/0018:0000:2D5A.0001/input/input4"})
          .value());

  auto probe_function = CreateProbeFunction<InputDeviceFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(InputDeviceFunctionTest, ProcfsNotExist) {
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");

  auto probe_function = CreateProbeFunction<InputDeviceFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe
