// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/sensor_device_fusion_gravity.h"

#include <optional>
#include <utility>

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_number_conversions.h>

#include "iioservice/daemon/samples_handler_fusion_gravity.h"
#include "iioservice/include/common.h"

namespace iioservice {

// static
constexpr char SensorDeviceFusionGravity::kName[];
constexpr double SensorDeviceFusionGravity::kAccelMinFrequency;
constexpr double SensorDeviceFusionGravity::kGyroMinFrequency;

// static
SensorDeviceFusion::ScopedSensorDeviceFusion SensorDeviceFusionGravity::Create(
    int32_t id,
    Location location,
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    base::RepeatingCallback<
        void(int32_t iio_device_id,
             mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
        iio_add_receiver_callback,
    double max_frequency,
    int32_t accel_id,
    int32_t gyro_id) {
  DCHECK(ipc_task_runner->RunsTasksInCurrentSequence());

  ScopedSensorDeviceFusion device(nullptr, SensorDeviceFusionDeleter);

  device.reset(new SensorDeviceFusionGravity(
      id, location, std::move(ipc_task_runner),
      std::move(iio_add_receiver_callback), max_frequency, GetGravityChannels(),
      accel_id, gyro_id));

  return device;
}

SensorDeviceFusionGravity::~SensorDeviceFusionGravity() = default;

void SensorDeviceFusionGravity::GetAttributes(
    const std::vector<std::string>& attr_names,
    GetAttributesCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  accel_->GetAttributes(attr_names, std::move(callback));
}

void SensorDeviceFusionGravity::GetChannelsAttributes(
    const std::vector<int32_t>& iio_chn_indices,
    const std::string& attr_name,
    GetChannelsAttributesCallback callback) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  // Do not provide gravity device channels' attributes.
  std::move(callback).Run(std::vector<std::optional<std::string>>(
      iio_chn_indices.size(), std::nullopt));
}

void SensorDeviceFusionGravity::UpdateRequestedFrequency(double frequency) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  SensorDeviceFusion::UpdateRequestedFrequency(frequency);

  accel_->SetFrequency(FixFrequencyWithMin(kAccelMinFrequency, frequency),
                       base::BindOnce(&SamplesHandlerFusion::SetDevFrequency,
                                      samples_handler_->GetWeakPtr()));

  gyro_->SetFrequency(FixFrequencyWithMin(kGyroMinFrequency, frequency));
}

SensorDeviceFusionGravity::SensorDeviceFusionGravity(
    int32_t id,
    Location location,
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    base::RepeatingCallback<
        void(int32_t iio_device_id,
             mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
        iio_add_receiver_callback,
    double max_frequency,
    std::vector<std::string> channel_ids,
    int32_t accel_id,
    int32_t gyro_id)
    : SensorDeviceFusion(id,
                         cros::mojom::DeviceType::GRAVITY,
                         location,
                         std::move(ipc_task_runner),
                         std::move(iio_add_receiver_callback),
                         max_frequency,
                         std::move(channel_ids)) {
  auto samples_handler = std::make_unique<SamplesHandlerFusionGravity>(
      ipc_task_runner_, channel_ids_,
      base::BindRepeating(&SensorDeviceFusionGravity::UpdateRequestedFrequency,
                          weak_factory_.GetWeakPtr()));

  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  auto accel = std::make_unique<IioDeviceHandler>(
      ipc_task_runner_, accel_id, cros::mojom::DeviceType::ACCEL,
      iio_add_receiver_callback_,
      base::BindRepeating(&SamplesHandlerFusionGravity::HandleAccelSample,
                          samples_handler->GetWeakPtr()),
      base::BindRepeating(&SensorDeviceFusionGravity::OnReadFailed,
                          weak_factory_.GetWeakPtr(),
                          cros::mojom::DeviceType::ACCEL),
      base::BindOnce(&SensorDeviceFusionGravity::Invalidate,
                     weak_factory_.GetWeakPtr()));
  accel_ = accel.get();
  iio_device_handlers_.push_back(std::move(accel));

  auto gyro = std::make_unique<IioDeviceHandler>(
      ipc_task_runner_, gyro_id, cros::mojom::DeviceType::ANGLVEL,
      iio_add_receiver_callback_,
      base::BindRepeating(&SamplesHandlerFusionGravity::HandleGyroSample,
                          samples_handler->GetWeakPtr()),
      base::BindRepeating(&SensorDeviceFusionGravity::OnReadFailed,
                          weak_factory_.GetWeakPtr(),
                          cros::mojom::DeviceType::ANGLVEL),
      base::BindOnce(&SensorDeviceFusionGravity::Invalidate,
                     weak_factory_.GetWeakPtr()));
  gyro_ = gyro.get();
  iio_device_handlers_.push_back(std::move(gyro));

  samples_handler_ = std::move(samples_handler);

  accel_->SetAttribute(
      cros::mojom::kSamplingFrequencyAvailable,
      GetSamplingFrequencyAvailable(kAccelMinFrequency, max_frequency));
  // Reuse "gravity" as the device name.
  accel_->SetAttribute(cros::mojom::kDeviceName, kName);
  accel_->GetAttributes(
      {cros::mojom::kScale},
      base::BindOnce(&SensorDeviceFusionGravity::GetScaleCallback,
                     weak_factory_.GetWeakPtr(),
                     cros::mojom::DeviceType::ACCEL));
  gyro_->GetAttributes(
      {cros::mojom::kScale},
      base::BindOnce(&SensorDeviceFusionGravity::GetScaleCallback,
                     weak_factory_.GetWeakPtr(),
                     cros::mojom::DeviceType::ANGLVEL));
}

void SensorDeviceFusionGravity::GetScaleCallback(
    cros::mojom::DeviceType type,
    const std::vector<std::optional<std::string>>& values) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  double scale = 1.0;
  if (values.empty() || !values[0]) {
    LOGF(ERROR) << "Cannot retrieve scale attribute from type: " << type;
  } else {
    if (values.size() > 1)
      LOGF(ERROR) << "Invalid size of attribute values: " << values.size();

    if (!values[0] || !base::StringToDouble(*values[0], &scale)) {
      LOGF(ERROR) << "Invalid scale: " << values[0].value_or("")
                  << ", for DeviceType: " << type;
    }
  }

  static_cast<SamplesHandlerFusionGravity*>(samples_handler_.get())
      ->SetScale(type, scale);
}

void SensorDeviceFusionGravity::OnReadFailed(cros::mojom::DeviceType type) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  LOGF(ERROR) << "OnReadFailed: " << type;
  // TODO(chenghaoyang)
}

}  // namespace iioservice
