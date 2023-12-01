// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_INFO_COMMAND_H_
#define LIBEC_FINGERPRINT_FP_INFO_COMMAND_H_

#include <memory>

#include <brillo/brillo_export.h>

#include "libec/ec_command.h"
#include "libec/ec_command_async.h"
#include "libec/fingerprint/fp_sensor_errors.h"
#include "libec/fingerprint/sensor_id.h"
#include "libec/fingerprint/sensor_image.h"
#include "libec/fingerprint/template_info.h"

namespace ec {

class BRILLO_EXPORT FpInfoCommand
    : public EcCommand<EmptyParam, struct ec_response_fp_info> {
 public:
  static constexpr int kDeadPixelsUnknown = -1;

  FpInfoCommand() : EcCommand(EC_CMD_FP_INFO, kVersionOne) {}
  ~FpInfoCommand() override = default;

  SensorId* sensor_id();
  SensorImage* sensor_image();
  TemplateInfo* template_info();
  int NumDeadPixels();
  FpSensorErrors GetFpSensorErrors();

 private:
  std::unique_ptr<SensorId> sensor_id_;
  std::unique_ptr<SensorImage> sensor_image_;
  std::unique_ptr<TemplateInfo> template_info_;
};

}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_INFO_COMMAND_H_
