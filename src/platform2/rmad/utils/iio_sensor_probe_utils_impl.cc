// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/iio_sensor_probe_utils_impl.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <libmems/iio_channel.h>
#include <libmems/iio_context_impl.h>

#include "rmad/proto_bindings/rmad.pb.h"

namespace {

constexpr char kIioDeviceAttributeLocation[] = "location";
constexpr char kAccelerometerChannelPrefix[] = "accel";
constexpr char kGyroscopeChannelPrefix[] = "anglvel";
const std::vector<std::string> kCalibratableSensorChannelPrefix = {
    kAccelerometerChannelPrefix, kGyroscopeChannelPrefix};

// Use location + name as a key to map to a specific component.
const std::map<std::string, rmad::RmadComponent>
    kIioSensorLocationChannelPrefixMap = {
        {"base:accel", rmad::RMAD_COMPONENT_BASE_ACCELEROMETER},
        {"base:anglvel", rmad::RMAD_COMPONENT_BASE_GYROSCOPE},
        {"lid:accel", rmad::RMAD_COMPONENT_LID_ACCELEROMETER},
        {"lid:anglvel", rmad::RMAD_COMPONENT_LID_GYROSCOPE}};

}  // namespace

namespace rmad {

IioSensorProbeUtilsImpl::IioSensorProbeUtilsImpl() {
  iio_context_ = std::make_unique<libmems::IioContextImpl>();
}

IioSensorProbeUtilsImpl::IioSensorProbeUtilsImpl(
    std::unique_ptr<libmems::IioContext> iio_context)
    : iio_context_(std::move(iio_context)) {}

std::set<RmadComponent> IioSensorProbeUtilsImpl::Probe() {
  std::set<RmadComponent> probed_components;
  for (const auto& device : iio_context_->GetAllDevices()) {
    auto location = device->ReadStringAttribute(kIioDeviceAttributeLocation);
    if (!location.has_value()) {
      continue;
    }

    auto channels = device->GetAllChannels();
    for (auto channel_prefix : kCalibratableSensorChannelPrefix) {
      bool calibratable = false;
      for (auto channel : channels) {
        if (0 == channel_prefix.compare(0, channel_prefix.length(),
                                        channel->GetId(), 0,
                                        channel_prefix.length())) {
          calibratable = true;
          break;
        }
      }
      if (calibratable) {
        std::string key = location.value() + ":" + channel_prefix;
        if (kIioSensorLocationChannelPrefixMap.count(key)) {
          probed_components.insert(kIioSensorLocationChannelPrefixMap.at(key));
        }
        break;
      }
    }
  }

  return probed_components;
}

}  // namespace rmad
