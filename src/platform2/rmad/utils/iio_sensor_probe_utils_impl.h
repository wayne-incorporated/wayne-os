// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_IIO_SENSOR_PROBE_UTILS_IMPL_H_
#define RMAD_UTILS_IIO_SENSOR_PROBE_UTILS_IMPL_H_

#include "rmad/utils/iio_sensor_probe_utils.h"

#include <memory>
#include <set>

#include <libmems/iio_context.h>

#include "rmad/proto_bindings/rmad.pb.h"

namespace rmad {

class IioSensorProbeUtilsImpl : public IioSensorProbeUtils {
 public:
  IioSensorProbeUtilsImpl();
  // Used to inject mock |iio_context_| for testing.
  explicit IioSensorProbeUtilsImpl(
      std::unique_ptr<libmems::IioContext> iio_context);
  ~IioSensorProbeUtilsImpl() override = default;

  std::set<RmadComponent> Probe() override;

 private:
  std::unique_ptr<libmems::IioContext> iio_context_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_IIO_SENSOR_PROBE_UTILS_IMPL_H_
