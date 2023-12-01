// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/samples_handler_fusion_gravity.h"

#include <utility>

#include <aosp/frameworks/native/services/sensorservice/mat.h>
#include <aosp/frameworks/native/services/sensorservice/vec.h>
#include <base/notreached.h>

#include "iioservice/include/common.h"

namespace iioservice {

namespace {

constexpr float GRAVITY_EARTH = 9.80665f;

}  // namespace

SamplesHandlerFusionGravity::SamplesHandlerFusionGravity(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    std::vector<std::string> channel_ids,
    UpdateFrequencyCallback callback)
    : SamplesHandlerFusion(std::move(ipc_task_runner),
                           std::move(channel_ids),
                           std::move(callback)) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
}

SamplesHandlerFusionGravity::~SamplesHandlerFusionGravity() = default;

void SamplesHandlerFusionGravity::SetScale(cros::mojom::DeviceType type,
                                           double scale) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  switch (type) {
    case cros::mojom::DeviceType::ACCEL:
      accel_scale_ = scale;
      break;

    case cros::mojom::DeviceType::ANGLVEL:
      gyro_scale_ = scale;
      break;

    default:
      NOTREACHED() << "Invalid type: " << type;
      break;
  }
}

void SamplesHandlerFusionGravity::HandleAccelSample(
    std::vector<int64_t> accel_sample) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK_EQ(accel_sample.size(), kNumberOfAxes + 1);

  if (!accel_scale_.has_value())
    return;

  int64_t dT_int = accel_sample.back() - accel_timestamp_;
  if (dT_int > 0 && dT_int < (int64_t)(1e8)) {  // 0.1sec }
    const float dT = (dT_int) / 1000000000.0f;

    android::vec3_t a;
    for (int i = 0; i < kNumberOfAxes; ++i)
      a[i] = accel_scale_.value() * accel_sample[i];

    fusion_.HandleAccel(a, dT);
  }

  accel_timestamp_ = accel_sample.back();

  if (!fusion_.HasEstimate())
    return;

  const android::mat33_t R(fusion_.GetRotationMatrix());
  android::vec3_t g = R[2] * GRAVITY_EARTH;
  base::flat_map<int32_t, int64_t> gravity_sample;
  gravity_sample.emplace(0, g.x / accel_scale_.value());
  gravity_sample.emplace(1, g.y / accel_scale_.value());
  gravity_sample.emplace(2, g.z / accel_scale_.value());
  gravity_sample.emplace(3, accel_timestamp_);

  OnSampleAvailableOnThread(gravity_sample);
}

void SamplesHandlerFusionGravity::HandleGyroSample(
    std::vector<int64_t> gyro_sample) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK_EQ(gyro_sample.size(), kNumberOfAxes + 1);

  if (!gyro_scale_.has_value())
    return;

  int64_t dT_int = gyro_sample.back() - gyro_timestamp_;
  if (dT_int > 0 && dT_int < (int64_t)(5e7)) {  // 0.05sec }
    const float dT = (dT_int) / 1000000000.0f;

    android::vec3_t w;
    for (int i = 0; i < kNumberOfAxes; ++i)
      w[i] = gyro_scale_.value() * gyro_sample[i];

    fusion_.HandleGyro(w, dT);
  }

  gyro_timestamp_ = gyro_sample.back();
}

bool SamplesHandlerFusionGravity::SampleIsValid(
    const base::flat_map<int32_t, int64_t>& sample) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  for (int i = 0; i < kNumberOfAxes + 1; ++i) {
    if (sample.find(i) == sample.end())
      return false;
  }

  return true;
}

}  // namespace iioservice
