// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_IIO_SENSOR_PROBE_UTILS_H_
#define RMAD_UTILS_IIO_SENSOR_PROBE_UTILS_H_

#include <set>

#include "rmad/proto_bindings/rmad.pb.h"

namespace rmad {

class IioSensorProbeUtils {
 public:
  IioSensorProbeUtils() = default;
  virtual ~IioSensorProbeUtils() = default;

  virtual std::set<RmadComponent> Probe() = 0;
};

}  // namespace rmad

#endif  // RMAD_UTILS_IIO_SENSOR_PROBE_UTILS_H_
