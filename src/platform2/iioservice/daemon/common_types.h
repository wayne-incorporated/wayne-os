// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_COMMON_TYPES_H_
#define IIOSERVICE_DAEMON_COMMON_TYPES_H_

#include <linux/iio/types.h>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <mojo/public/cpp/bindings/receiver_set.h>

#include <libmems/iio_device.h>

#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

enum Location {
  kNone = 0,
  kBase = 1,
  kLid = 2,
  kCamera = 3,
};

class DeviceData {
 public:
  DeviceData(libmems::IioDevice* const iio_device = nullptr,
             std::set<cros::mojom::DeviceType> types = {});

  libmems::IioDevice* const iio_device;
  const std::set<cros::mojom::DeviceType> types;
  const bool on_dut;

  const int iio_device_id;
};

class ClientData {
 public:
  explicit ClientData(const mojo::ReceiverId id,
                      DeviceData* device_data = nullptr);

  bool IsSampleActive() const;

  void ResetTimeout();
  uint32_t GetTimeout();

  const mojo::ReceiverId id;
  DeviceData* const device_data;

  std::set<int32_t> enabled_chn_indices;
  double frequency = -1;    // Hz
  uint32_t timeout = 5000;  // millisecond
  uint32_t consecutive_timeouts_ = 0;
  mojo::Remote<cros::mojom::SensorDeviceSamplesObserver> samples_observer;
};

std::vector<std::string> GetGravityChannels();

constexpr char kInputAttr[] = "input";

// Number of axes for x, y, and z.
constexpr int kNumberOfAxes = 3;
constexpr char kChannelFormat[] = "%s_%c";
constexpr char kChannelAxes[kNumberOfAxes] = {'x', 'y', 'z'};
constexpr char kAccel3d[] = "accel_3d";
constexpr char kAccelMatrixAttribute[] = "in_accel_mount_matrix";

constexpr char kSamplingFrequencyAvailableFormat[] = "0.000000 %.6f %.6f";
std::string GetSamplingFrequencyAvailable(double min_frequency,
                                          double max_frequency);

std::optional<std::string> DeviceTypeToString(cros::mojom::DeviceType type);

cros::mojom::IioChanType ConvertChanType(iio_chan_type chan_type);
cros::mojom::IioEventType ConvertEventType(iio_event_type event_type);
cros::mojom::IioEventDirection ConvertDirection(iio_event_direction direction);

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_COMMON_TYPES_H_
