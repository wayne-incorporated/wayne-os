// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_SENSOR_DEVICE_H_
#define RMAD_UTILS_MOCK_SENSOR_DEVICE_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include "iioservice/mojo/sensor.mojom.h"

namespace rmad {
class MockSensorDevice : public cros::mojom::SensorDevice {
 public:
  MOCK_METHOD(void, SetTimeout, (uint32_t), (override));
  MOCK_METHOD(void, GetAllChannelIds, (GetAllChannelIdsCallback), (override));
  MOCK_METHOD(void,
              GetAttributes,
              (const std::vector<std::string>&, GetAttributesCallback),
              (override));
  MOCK_METHOD(void, SetFrequency, (double, SetFrequencyCallback), (override));
  MOCK_METHOD(void,
              StartReadingSamples,
              (mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver>),
              (override));
  MOCK_METHOD(void, StopReadingSamples, (), (override));
  MOCK_METHOD(void,
              SetChannelsEnabled,
              (const std::vector<int>&, bool, SetChannelsEnabledCallback),
              (override));
  MOCK_METHOD(void,
              GetChannelsEnabled,
              (const std::vector<int>&, GetChannelsEnabledCallback),
              (override));
  MOCK_METHOD(void,
              GetChannelsAttributes,
              (const std::vector<int>&,
               const std::string&,
               GetChannelsAttributesCallback),
              (override));
  MOCK_METHOD(void, GetAllEvents, (GetAllEventsCallback), (override));
  MOCK_METHOD(void,
              GetEventsAttributes,
              (const std::vector<int>&,
               const std::string&,
               GetEventsAttributesCallback),
              (override));
  MOCK_METHOD(void,
              StartReadingEvents,
              (const std::vector<int>&,
               mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver>),
              (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_SENSOR_DEVICE_H_
