// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_SENSOR_SERVICE_H_
#define RMAD_UTILS_MOCK_SENSOR_SERVICE_H_

#include <gmock/gmock.h>
#include <iioservice/mojo/sensor.mojom.h>

namespace rmad {

class MockSensorService : public cros::mojom::SensorService {
 public:
  MOCK_METHOD(void,
              GetDevice,
              (int, mojo::PendingReceiver<cros::mojom::SensorDevice>),
              (override));
  MOCK_METHOD(void,
              GetDeviceIds,
              (cros::mojom::DeviceType, GetDeviceIdsCallback),
              (override));
  MOCK_METHOD(void, GetAllDeviceIds, (GetAllDeviceIdsCallback), (override));
  MOCK_METHOD(void,
              RegisterNewDevicesObserver,
              (mojo::PendingRemote<cros::mojom::SensorServiceNewDevicesObserver>
                   observer),
              (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_SENSOR_SERVICE_H_
