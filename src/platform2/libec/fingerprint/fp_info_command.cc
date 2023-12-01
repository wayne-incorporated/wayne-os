// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/fingerprint/fp_info_command.h"

namespace ec {

/**
 * @return non-owning pointer which can be nullptr if command hasn't been run.
 */
SensorId* FpInfoCommand::sensor_id() {
  if (!Resp()) {
    return nullptr;
  }
  if (!sensor_id_) {
    sensor_id_ =
        std::make_unique<SensorId>(Resp()->vendor_id, Resp()->product_id,
                                   Resp()->model_id, Resp()->version);
  }
  return sensor_id_.get();
}

/**
 * @return non-owning pointer which can be nullptr if command hasn't been run.
 */
SensorImage* FpInfoCommand::sensor_image() {
  if (!Resp()) {
    return nullptr;
  }
  if (!sensor_image_) {
    sensor_image_ = std::make_unique<SensorImage>(
        Resp()->width, Resp()->height, Resp()->frame_size, Resp()->pixel_format,
        Resp()->bpp);
  }
  return sensor_image_.get();
}

/**
 * @return non-owning pointer which can be nullptr if command hasn't been run.
 */
TemplateInfo* FpInfoCommand::template_info() {
  if (!Resp()) {
    return nullptr;
  }
  if (!template_info_) {
    template_info_ = std::make_unique<TemplateInfo>(
        Resp()->template_version, Resp()->template_size, Resp()->template_max,
        Resp()->template_valid, Resp()->template_dirty);
  }
  return template_info_.get();
}

/**
 * @return number of dead pixels or kDeadPixelsUnknown
 */
int FpInfoCommand::NumDeadPixels() {
  if (!Resp()) {
    return kDeadPixelsUnknown;
  }
  uint16_t num_dead_pixels = Resp()->errors;
  if (num_dead_pixels == FP_ERROR_DEAD_PIXELS_UNKNOWN) {
    return kDeadPixelsUnknown;
  }
  return num_dead_pixels;
}

/**
 * @return FpSensorErrors
 */
FpSensorErrors FpInfoCommand::GetFpSensorErrors() {
  FpSensorErrors ret = FpSensorErrors::kNone;

  if (!Resp()) {
    return ret;
  }

  auto errors = Resp()->errors;

  if (errors & FP_ERROR_NO_IRQ) {
    ret |= FpSensorErrors::kNoIrq;
  }
  if (errors & FP_ERROR_BAD_HWID) {
    ret |= FpSensorErrors::kBadHardwareID;
  }
  if (errors & FP_ERROR_INIT_FAIL) {
    ret |= FpSensorErrors::kInitializationFailure;
  }
  if (errors & FP_ERROR_SPI_COMM) {
    ret |= FpSensorErrors::kSpiCommunication;
  }
  if ((FP_ERROR_DEAD_PIXELS(errors) != FP_ERROR_DEAD_PIXELS_UNKNOWN) &&
      (FP_ERROR_DEAD_PIXELS(errors) != 0)) {
    ret |= FpSensorErrors::kDeadPixels;
  }

  return ret;
}

}  // namespace ec
