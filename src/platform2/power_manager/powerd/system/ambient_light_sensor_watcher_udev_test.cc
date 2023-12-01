// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_watcher_udev.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "power_manager/powerd/system/ambient_light_sensor_watcher_observer_stub.h"
#include "power_manager/powerd/system/udev_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

constexpr char kGoodSysname[] = "iio:device0";
constexpr char kGoodSyspath[] =
    "/sys/my/mock/device/HID-SENSOR-200041/more/mock/path";

}  // namespace

class AmbientLightSensorWatcherUdevTest : public TestEnvironment {
 public:
  AmbientLightSensorWatcherUdevTest() = default;
  ~AmbientLightSensorWatcherUdevTest() override = default;

 protected:
  void Init() { watcher_.Init(&udev_); }

  // Add a sensor device to the udev stub so that it will show up as already
  // connected when the AmbientLightSensorWatcherUdev is initialized.
  void AddExistingDevice() {
    UdevDeviceInfo device_info;
    device_info.subsystem = AmbientLightSensorWatcherUdev::kIioUdevSubsystem;
    device_info.devtype = AmbientLightSensorWatcherUdev::kIioUdevDevice;
    device_info.sysname = kGoodSysname;
    device_info.syspath = kGoodSyspath;
    udev_.AddSubsystemDevice(device_info.subsystem, device_info, {});
  }

  // Send a udev ADD event for a device with the given parameters.
  void AddDevice(const std::string& subsystem,
                 const std::string& devtype,
                 const std::string& sysname,
                 const std::string& syspath) {
    UdevEvent iio_event;
    iio_event.action = UdevEvent::Action::ADD;
    iio_event.device_info.subsystem = subsystem;
    iio_event.device_info.devtype = devtype;
    iio_event.device_info.sysname = sysname;
    iio_event.device_info.syspath = syspath;
    udev_.NotifySubsystemObservers(iio_event);
  }

  // Send a udev ADD event for the known good ALS device.
  void AddDevice() {
    AddDevice(AmbientLightSensorWatcherUdev::kIioUdevSubsystem,
              AmbientLightSensorWatcherUdev::kIioUdevDevice, kGoodSysname,
              kGoodSyspath);
  }

  // Send a udev REMOVE event for the known good ALS device.
  void RemoveDevice() {
    UdevEvent iio_event;
    iio_event.action = UdevEvent::Action::REMOVE;
    iio_event.device_info.subsystem =
        AmbientLightSensorWatcherUdev::kIioUdevSubsystem;
    iio_event.device_info.devtype =
        AmbientLightSensorWatcherUdev::kIioUdevDevice;
    iio_event.device_info.sysname = kGoodSysname;
    iio_event.device_info.syspath = kGoodSyspath;
    udev_.NotifySubsystemObservers(iio_event);
  }

  UdevStub udev_;
  AmbientLightSensorWatcherUdev watcher_;
};

TEST_F(AmbientLightSensorWatcherUdevTest, DetectExistingDevice) {
  AmbientLightSensorWatcherObserverStub observer(&watcher_);
  AddExistingDevice();
  Init();
  EXPECT_EQ(1, observer.num_als_changes());
  EXPECT_EQ(1, watcher_.GetAmbientLightSensors().size());
}

TEST_F(AmbientLightSensorWatcherUdevTest, GoodDevice) {
  AmbientLightSensorWatcherObserverStub observer(&watcher_);
  Init();
  AddDevice();
  const std::vector<AmbientLightSensorInfo> sensors =
      watcher_.GetAmbientLightSensors();
  EXPECT_EQ(1, observer.num_als_changes());
  ASSERT_EQ(1, sensors.size());
  EXPECT_EQ(kGoodSyspath, sensors[0].iio_path.value());
  EXPECT_EQ(kGoodSysname, sensors[0].device);
}

TEST_F(AmbientLightSensorWatcherUdevTest, BadDeviceWrongSubsystem) {
  AmbientLightSensorWatcherObserverStub observer(&watcher_);
  Init();
  AddDevice("usb", AmbientLightSensorWatcherUdev::kIioUdevDevice, kGoodSysname,
            kGoodSyspath);
  EXPECT_EQ(0, observer.num_als_changes());
  EXPECT_EQ(0, watcher_.GetAmbientLightSensors().size());
}

TEST_F(AmbientLightSensorWatcherUdevTest, BadDeviceWrongDeviceType) {
  AmbientLightSensorWatcherObserverStub observer(&watcher_);
  Init();
  AddDevice(AmbientLightSensorWatcherUdev::kIioUdevSubsystem, "trigger",
            kGoodSysname, kGoodSyspath);
  EXPECT_EQ(0, observer.num_als_changes());
  EXPECT_EQ(0, watcher_.GetAmbientLightSensors().size());
}

TEST_F(AmbientLightSensorWatcherUdevTest, BadDeviceWrongSyspath) {
  AmbientLightSensorWatcherObserverStub observer(&watcher_);
  Init();
  AddDevice(AmbientLightSensorWatcherUdev::kIioUdevSubsystem,
            AmbientLightSensorWatcherUdev::kIioUdevDevice, kGoodSysname,
            "/sys/not/a/usb/hid/sensor");
  EXPECT_EQ(0, observer.num_als_changes());
  EXPECT_EQ(0, watcher_.GetAmbientLightSensors().size());
}

TEST_F(AmbientLightSensorWatcherUdevTest, DuplicateDevice) {
  AmbientLightSensorWatcherObserverStub observer(&watcher_);
  Init();
  AddDevice();
  AddDevice();
  EXPECT_EQ(1, observer.num_als_changes());
  EXPECT_EQ(1, watcher_.GetAmbientLightSensors().size());
}

TEST_F(AmbientLightSensorWatcherUdevTest, RemoveDevice) {
  AmbientLightSensorWatcherObserverStub observer(&watcher_);
  Init();
  AddDevice();
  EXPECT_EQ(1, observer.num_als_changes());
  EXPECT_EQ(1, watcher_.GetAmbientLightSensors().size());
  RemoveDevice();
  EXPECT_EQ(2, observer.num_als_changes());
  EXPECT_EQ(0, watcher_.GetAmbientLightSensors().size());
}

}  // namespace power_manager::system
