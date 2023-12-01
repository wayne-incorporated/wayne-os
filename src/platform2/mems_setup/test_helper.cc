// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <libmems/common_types.h>
#include <libmems/iio_device_impl.h>
#include "mems_setup/test_helper.h"

using libmems::fakes::FakeIioChannel;
using libmems::fakes::FakeIioContext;
using libmems::fakes::FakeIioDevice;
using mems_setup::fakes::FakeDelegate;

namespace mems_setup {
namespace testing {

bool FakeSysfsTrigger::WriteNumberAttribute(const std::string& name,
                                            int64_t value) {
  bool ok = this->FakeIioDevice::WriteNumberAttribute(name, value);
  if (ok && name == "add_trigger" && value == 0) {
    mock_context_->AddTrigger(std::move(mock_trigger_));
  }
  return ok;
}

void FakeSysfsTrigger::AddMockTrigger() {
  mock_context_->AddTrigger(std::move(mock_trigger_));
}

SensorTestBase::SensorTestBase(const char* name, int id)
    : mock_context_(new FakeIioContext), mock_delegate_(new FakeDelegate) {
  sensor_kind_ = mems_setup::SensorKindFromString(name ? name : "");
  auto channel = std::make_unique<FakeIioChannel>("calibration", false);
  auto device = std::make_unique<FakeIioDevice>(mock_context_.get(), name, id);
  auto trigger =
      std::make_unique<FakeIioDevice>(mock_context_.get(), "sysfstrig0", 1);
  mock_trigger1_ = trigger.get();
  auto mock_sysfs_trigger = std::make_unique<FakeSysfsTrigger>(
      mock_context_.get(), std::move(trigger));
  mock_sysfs_trigger_ = mock_sysfs_trigger.get();

  device->AddChannel(std::move(channel));
  mock_device_ = device.get();

  mock_context_->AddDevice(std::move(device));
  mock_context_->AddTrigger(std::move(mock_sysfs_trigger));

  std::string dev_name =
      libmems::IioDeviceImpl::GetStringFromId(mock_device_->GetId());
  // /dev/iio:deviceX
  base::FilePath dev_path =
      base::FilePath(libmems::kDevString).Append(dev_name.c_str());
  mock_delegate_->CreateFile(dev_path);
}

void SensorTestBase::SetSingleSensor(const char* location) {
  mock_device_->WriteStringAttribute("location", location);

  if (sensor_kind_ == SensorKind::ACCELEROMETER) {
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("accel_x", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("accel_y", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("accel_z", false));

    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("timestamp", true));
  } else if (sensor_kind_ == SensorKind::GYROSCOPE) {
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("anglvel_x", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("anglvel_y", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("anglvel_z", false));

    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("timestamp", true));
  } else if (sensor_kind_ == SensorKind::LIGHT) {
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("illuminance", false));

    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("timestamp", true));
  } else if (sensor_kind_ == SensorKind::PROXIMITY) {
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("proximity0", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("proximity1", false));
  }
}

void SensorTestBase::SetSharedSensor() {
  if (sensor_kind_ == SensorKind::ACCELEROMETER) {
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("accel_x_base", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("accel_y_base", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("accel_z_base", false));

    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("accel_x_lid", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("accel_y_lid", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("accel_z_lid", false));

    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("timestamp", true));
  } else if (sensor_kind_ == SensorKind::GYROSCOPE) {
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("anglvel_x_base", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("anglvel_y_base", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("anglvel_z_base", false));

    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("anglvel_x_lid", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("anglvel_y_lid", false));
    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("anglvel_z_lid", false));

    mock_device_->AddChannel(
        std::make_unique<FakeIioChannel>("timestamp", true));
  }
}

void SensorTestBase::SetColorLightSensor() {
  if (sensor_kind_ != SensorKind::LIGHT)
    return;

  mock_device_->AddChannel(
      std::make_unique<FakeIioChannel>("illuminance", false));
  mock_device_->AddChannel(
      std::make_unique<FakeIioChannel>("illuminance_red", false));
  mock_device_->AddChannel(
      std::make_unique<FakeIioChannel>("illuminance_green", false));
  mock_device_->AddChannel(
      std::make_unique<FakeIioChannel>("illuminance_blue", false));

  mock_device_->AddChannel(std::make_unique<FakeIioChannel>("timestamp", true));
}

void SensorTestBase::ConfigureVpd(
    std::initializer_list<std::pair<const char*, const char*>> values) {
  for (const auto& value : values) {
    mock_delegate_->SetVpdValue(value.first, value.second);
  }
}

Configuration* SensorTestBase::GetConfiguration() {
  if (config_ == nullptr) {
    config_.reset(new Configuration(mock_context_.get(), mock_device_,
                                    mock_delegate_.get()));
  }

  return config_.get();
}

}  // namespace testing
}  // namespace mems_setup
