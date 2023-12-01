// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_MOJO_SERVICE_UTILS_H_
#define RMAD_UTILS_MOCK_MOJO_SERVICE_UTILS_H_

#include <map>
#include <memory>
#include <utility>

#include <gmock/gmock.h>

#include "rmad/utils/mojo_service_utils.h"

namespace rmad {

class MockMojoServiceUtils : public MojoServiceUtils {
 public:
  MOCK_METHOD(cros::mojom::SensorDevice*, GetSensorDevice, (int), (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_MOJO_SERVICE_UTILS_H_
