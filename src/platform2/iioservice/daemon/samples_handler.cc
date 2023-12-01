// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/samples_handler.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/time/time.h>
#include <libmems/common_types.h>
#include <libmems/iio_channel.h>
#include <libmems/iio_context.h>
#include <libmems/iio_device.h>

#include "iioservice/daemon/sensor_metrics.h"
#include "iioservice/include/common.h"

namespace iioservice {

namespace {

constexpr char kHWFifoFlushPath[] = "buffer/hwfifo_flush";

constexpr char kAccelChannelNameFormat[] = "%s_%c";

constexpr double kAcpiAlsMinFrequency = 0.1;
constexpr double kAcpiAlsMaxFrequency = 2.0;

constexpr double kHidMinFrequency = 0.1;
constexpr double kHidMaxFrequency = 200.0;

constexpr cros::mojom::DeviceType kOnChangeDeviceTypes[] = {
    cros::mojom::DeviceType::LIGHT};

bool IsOnChangeDevice(ClientData* client_data) {
  if (!client_data->device_data->iio_device->HasFifo())
    return false;

  for (auto type : kOnChangeDeviceTypes) {
    if (base::Contains(client_data->device_data->types, type))
      return true;
  }

  return false;
}

}  // namespace

// static
void SamplesHandler::SamplesHandlerDeleter(SamplesHandler* handler) {
  if (handler == nullptr)
    return;

  if (!handler->sample_task_runner_->BelongsToCurrentThread()) {
    handler->sample_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&SamplesHandler::SamplesHandlerDeleter, handler));
    return;
  }

  delete handler;
}

// static
bool SamplesHandler::DisableBufferAndEnableChannels(
    libmems::IioDevice* iio_device) {
  if (iio_device->IsBufferEnabled() && !iio_device->DisableBuffer()) {
    LOGF(ERROR) << "Failed to disable buffer";
    return false;
  }

  iio_device->EnableAllChannels();

  return true;
}

// static
SamplesHandler::ScopedSamplesHandler SamplesHandler::Create(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> sample_task_runner,
    DeviceData* const device_data) {
  ScopedSamplesHandler handler(nullptr, SamplesHandlerDeleter);

  auto* iio_device = device_data->iio_device;
  if (!iio_device->HasFifo() && !iio_device->GetTrigger() &&
      !iio_device->GetHrtimer()) {
    LOGF(ERROR) << "Device " << iio_device->GetId()
                << " has neither fifo, nor trigger, nor hrtimer. Cannot read "
                   "samples from it.";
    return handler;
  }

  if (!DisableBufferAndEnableChannels(iio_device))
    return handler;

  double min_freq, max_freq;
  if (strcmp(iio_device->GetName(), "acpi-als") == 0) {
    min_freq = kAcpiAlsMinFrequency;
    max_freq = kAcpiAlsMaxFrequency;
  } else if (!iio_device->GetMinMaxFrequency(&min_freq, &max_freq)) {
    min_freq = kHidMinFrequency;
    max_freq = kHidMaxFrequency;
  }

  handler.reset(new SamplesHandler(std::move(ipc_task_runner),
                                   std::move(sample_task_runner), device_data,
                                   min_freq, max_freq));
  return handler;
}

SamplesHandler::~SamplesHandler() {
  DCHECK(sample_task_runner_->BelongsToCurrentThread());

  iio_device_->FreeBuffer();
  if (requested_frequency_ > 0.0 &&
      !iio_device_->WriteDoubleAttribute(libmems::kSamplingFrequencyAttr, 0.0))
    LOGF(ERROR) << "Failed to set frequency";

  SensorMetrics::GetInstance()->SendSensorUsage(iio_device_->GetId(), 0.0);

  for (ClientData* client : inactive_clients_) {
    if (client->samples_observer.is_bound()) {
      SensorMetrics::GetInstance()->SendSensorObserverClosed();
      client->samples_observer.reset();
    }
  }

  for (auto& [client, _] : clients_map_) {
    if (client->samples_observer.is_bound()) {
      SensorMetrics::GetInstance()->SendSensorObserverClosed();
      client->samples_observer.reset();
    }
  }
}

void SamplesHandler::ResetWithReason(
    cros::mojom::SensorDeviceDisconnectReason reason,
    std::string description,
    base::OnceCallback<void()> callback) {
  sample_task_runner_->PostTaskAndReply(
      FROM_HERE,
      base::BindOnce(&SamplesHandler::ResetWithReasonOnThread,
                     weak_factory_.GetWeakPtr(), reason, description),
      std::move(callback));
}

void SamplesHandler::AddClient(
    ClientData* client_data,
    mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer) {
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);

  sample_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&SamplesHandler::AddClientOnThread,
                                weak_factory_.GetWeakPtr(), client_data,
                                std::move(observer)));
}

void SamplesHandler::RemoveClient(ClientData* client_data,
                                  base::OnceClosure callback) {
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);

  sample_task_runner_->PostTaskAndReply(
      FROM_HERE,
      base::BindOnce(&SamplesHandler::RemoveClientOnThread,
                     weak_factory_.GetWeakPtr(), client_data),
      std::move(callback));
}

void SamplesHandler::UpdateFrequency(
    ClientData* client_data,
    double frequency,
    cros::mojom::SensorDevice::SetFrequencyCallback callback) {
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);

  sample_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&SamplesHandler::UpdateFrequencyOnThread,
                                weak_factory_.GetWeakPtr(), client_data,
                                frequency, std::move(callback)));
}

void SamplesHandler::UpdateChannelsEnabled(
    ClientData* client_data,
    const std::vector<int32_t>& iio_chn_indices,
    bool en,
    cros::mojom::SensorDevice::SetChannelsEnabledCallback callback) {
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);

  sample_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&SamplesHandler::UpdateChannelsEnabledOnThread,
                     weak_factory_.GetWeakPtr(), client_data,
                     std::move(iio_chn_indices), en, std::move(callback)));
}

void SamplesHandler::GetChannelsEnabled(
    ClientData* client_data,
    const std::vector<int32_t>& iio_chn_indices,
    cros::mojom::SensorDevice::GetChannelsEnabledCallback callback) {
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);

  sample_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&SamplesHandler::GetChannelsEnabledOnThread,
                     weak_factory_.GetWeakPtr(), client_data,
                     std::move(iio_chn_indices), std::move(callback)));
}

SamplesHandler::SamplesHandler(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> sample_task_runner,
    DeviceData* const device_data,
    double min_freq,
    double max_freq)
    : SamplesHandlerBase(sample_task_runner),
      ipc_task_runner_(std::move(ipc_task_runner)),
      sample_task_runner_(std::move(sample_task_runner)),
      iio_device_(device_data->iio_device),
      dev_min_frequency_(min_freq),
      dev_max_frequency_(max_freq) {
  DCHECK_GE(dev_max_frequency_, dev_min_frequency_);

  std::vector<std::string> channel_ids;
  for (auto channel : iio_device_->GetAllChannels())
    channel_ids.push_back(channel->GetId());

  SetNoBatchChannels(channel_ids);

  // Set |accel_matrix_|.
  if (!base::Contains(device_data->types, cros::mojom::DeviceType::ACCEL))
    return;

  for (int i = 0; i < kNumberOfAxes; ++i) {
    std::string channel_name =
        base::StringPrintf(kAccelChannelNameFormat,
                           cros::mojom::kAccelerometerChannel, kChannelAxes[i]);

    std::vector<libmems::IioChannel*> channels = iio_device_->GetAllChannels();
    for (int j = 0; j < channels.size(); ++j) {
      if (channel_name.compare(channels[j]->GetId()) == 0) {
        accel_axis_indices_[i] = j;
        break;
      }
    }

    if (accel_axis_indices_[i] == -1) {
      for (int k = 0; k < kNumberOfAxes; ++k)
        accel_axis_indices_[k] = -1;

      return;
    }
  }

  bool read_matrix_attribute = false;
  auto accel_mount_matrix =
      iio_device_->ReadStringAttribute(kAccelMatrixAttribute);

  if (accel_mount_matrix.has_value()) {
    std::vector<std::string> matrix =
        base::SplitString(accel_mount_matrix.value(), ";",
                          base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    if (matrix.size() == kNumberOfAxes) {
      read_matrix_attribute = true;
      for (int i = 0; read_matrix_attribute && i < matrix.size(); ++i) {
        std::vector<std::string> values = base::SplitString(
            matrix[i], ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

        if (values.size() != kNumberOfAxes) {
          read_matrix_attribute = false;
          break;
        }

        for (int j = 0; j < values.size(); ++j) {
          if (!base::StringToDouble(values[j], &accel_matrix_[i][j])) {
            read_matrix_attribute = false;
            break;
          }
        }
      }
    }
  }

  if (!read_matrix_attribute) {
    for (int i = 0; i < kNumberOfAxes; ++i) {
      for (int j = 0; j < kNumberOfAxes; ++j) {
        accel_matrix_[i][j] = (i == j)
                                  ? (strncmp(iio_device_->GetName(), kAccel3d,
                                             std::size(kAccel3d)) == 0
                                         ? -1
                                         : 1)
                                  : 0;
      }
    }
  }
}

void SamplesHandler::SetSampleWatcherOnThread() {
  DCHECK(sample_task_runner_->BelongsToCurrentThread());
  DCHECK(!watcher_.get());

  // Flush the old samples in EC FIFO.
  if (iio_device_->HasFifo()) {
    if (!iio_device_->WriteStringAttribute(kHWFifoFlushPath, "1\n"))
      LOGF(ERROR) << "Failed to flush the old samples in EC FIFO";
  } else if (iio_device_->GetHrtimer()) {
    auto* hrtimer = iio_device_->GetHrtimer();
    if (hrtimer && !iio_device_->SetTrigger(hrtimer)) {
      LOGF(ERROR) << "Failed to set trigger";
      return;
    }
  }

  if (!iio_device_->CreateBuffer()) {
    LOGF(ERROR) << "Failed to create buffer";
    for (auto& [client_data, _] : clients_map_) {
      client_data->samples_observer->OnErrorOccurred(
          cros::mojom::ObserverErrorType::GET_FD_FAILED);
    }

    return;
  }

  auto fd = iio_device_->GetBufferFd();
  if (!fd.has_value()) {
    LOGF(ERROR) << "Failed to get fd";
    for (auto& [client_data, _] : clients_map_) {
      client_data->samples_observer->OnErrorOccurred(
          cros::mojom::ObserverErrorType::GET_FD_FAILED);
    }

    return;
  }

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd.value(),
      base::BindRepeating(&SamplesHandler::OnSampleAvailableWithoutBlocking,
                          weak_factory_.GetWeakPtr()));
}

void SamplesHandler::StopSampleWatcherOnThread() {
  DCHECK(sample_task_runner_->BelongsToCurrentThread());

  watcher_.reset();
  iio_device_->FreeBuffer();
  if (iio_device_->GetHrtimer())
    iio_device_->SetTrigger(nullptr);
}

void SamplesHandler::AddActiveClientOnThread(ClientData* client_data) {
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);

  SamplesHandlerBase::AddActiveClientOnThread(client_data);

  if (IsOnChangeDevice(client_data)) {
    // Read the first sample of the ON_CHANGE sensor for the sensor client.
    libmems::IioDevice::IioSample sample;
    for (int32_t index : client_data->enabled_chn_indices) {
      auto channel = client_data->device_data->iio_device->GetChannel(index);

      // Read the current time for the timestamp channel.
      if (base::StringPiece(cros::mojom::kTimestampChannel) ==
          channel->GetId()) {
        struct timespec ts = {};
        if (clock_gettime(CLOCK_BOOTTIME, &ts) < 0) {
          PLOG(ERROR) << "clock_gettime(CLOCK_BOOTTIME) failed";
        } else {
          sample[index] =
              static_cast<int64_t>(ts.tv_sec) * 1000 * 1000 * 1000 + ts.tv_nsec;
        }

        continue;
      }

      // Read from the input attribute or the raw attribute.
      auto value_opt = channel->ReadNumberAttribute(kInputAttr);
      if (!value_opt.has_value())
        value_opt = channel->ReadNumberAttribute(libmems::kRawAttr);

      if (value_opt.has_value())
        sample[index] = value_opt.value();
    }

    if (!sample.empty())
      client_data->samples_observer->OnSampleUpdated(std::move(sample));
  }

  if (!watcher_.get())
    SetSampleWatcherOnThread();
}

void SamplesHandler::RemoveActiveClientOnThread(ClientData* client_data,
                                                double orig_freq) {
  DCHECK(sample_task_runner_->BelongsToCurrentThread());
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);
  DCHECK_GE(orig_freq, libmems::kFrequencyEpsilon);
  DCHECK(clients_map_.find(client_data) != clients_map_.end());

  SamplesHandlerBase::RemoveActiveClientOnThread(client_data, orig_freq);

  if (clients_map_.empty())
    StopSampleWatcherOnThread();
}

double SamplesHandler::FixFrequency(double frequency) {
  if (frequency < libmems::kFrequencyEpsilon)
    return 0.0;

  if (frequency > dev_max_frequency_)
    return dev_max_frequency_;

  return frequency;
}

double SamplesHandler::FixFrequencyWithMin(double frequency) {
  if (frequency < libmems::kFrequencyEpsilon)
    return 0.0;

  if (frequency < dev_min_frequency_)
    return dev_min_frequency_;

  if (frequency > dev_max_frequency_)
    return dev_max_frequency_;

  return frequency;
}

void SamplesHandler::UpdateFrequencyOnThread(
    ClientData* client_data,
    double frequency,
    cros::mojom::SensorDevice::SetFrequencyCallback callback) {
  DCHECK(sample_task_runner_->BelongsToCurrentThread());
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);

  frequency = FixFrequency(frequency);

  double orig_freq = client_data->frequency;
  client_data->frequency = frequency;
  ipc_task_runner_->PostTask(FROM_HERE,
                             base::BindOnce(std::move(callback), frequency));

  auto it = inactive_clients_.find(client_data);
  if (it != inactive_clients_.end()) {
    if (client_data->IsSampleActive()) {
      // The client is now active.
      inactive_clients_.erase(it);
      AddActiveClientOnThread(client_data);
    }

    return;
  }

  if (clients_map_.find(client_data) == clients_map_.end())
    return;

  if (!client_data->IsSampleActive()) {
    // The client is now inactive
    RemoveActiveClientOnThread(client_data, orig_freq);
    inactive_clients_.emplace(client_data);

    return;
  }

  // The client remains active
  DCHECK(client_data->samples_observer.is_bound());

  if (AddFrequencyOnThread(client_data->frequency) &&
      RemoveFrequencyOnThread(orig_freq)) {
    return;
  }

  // Failed to set device frequency
  client_data->samples_observer->OnErrorOccurred(
      cros::mojom::ObserverErrorType::SET_FREQUENCY_IO_FAILED);
}

bool SamplesHandler::UpdateRequestedFrequencyOnThread() {
  DCHECK(sample_task_runner_->BelongsToCurrentThread());

  double frequency = GetRequestedFrequencyOnThread();

  // We didn't limit clients' frequency to be greater than or equal to
  // |dev_min_frequency_|, but we need to do that when setting the real
  // frequency.
  frequency = FixFrequencyWithMin(frequency);

  if (frequency == requested_frequency_)
    return true;

  SensorMetrics::GetInstance()->SendSensorUsage(iio_device_->GetId(),
                                                frequency);

  requested_frequency_ = frequency;

  if (!iio_device_->WriteDoubleAttribute(libmems::kSamplingFrequencyAttr,
                                         frequency)) {
    /*
     * The frequency attributes may not exist on some sensors (acpi-als).
     * Ignore the error when the sensor does not have FIFO.
     */
    if (iio_device_->HasFifo()) {
      LOGF(ERROR) << "Failed to set frequency";
      return false;
    }

    // HID sensors require to set sampling frequency in channels' attributes.
    for (auto& channel : iio_device_->GetAllChannels()) {
      if (channel->IsEnabled())
        channel->WriteDoubleAttribute(libmems::kSamplingFrequencyAttr,
                                      frequency);
    }
  }

  // |sampling_frequency| returns by the EC is the current sensors ODR. It may
  // be higher than requested when the EC needs higher speed, or just different
  // if the EC is slow to set the new sensor ODR. Use requested |frequency| as
  // base for downsampling.
  dev_frequency_ = frequency;

  if (iio_device_->HasFifo()) {
    double ec_period = 0;
    if (dev_frequency_ > libmems::kFrequencyEpsilon)
      ec_period = 1.0 / dev_frequency_;

    if (!iio_device_->WriteDoubleAttribute(libmems::kHWFifoTimeoutAttr,
                                           ec_period)) {
      LOGF(ERROR) << "Failed to set fifo timeout";
      return false;
    }

    return true;
  }

  // If |iio_device_| has a hrtimer, set up its sampling frequency attribute.
  if (iio_device_->GetHrtimer() &&
      !iio_device_->GetHrtimer()->WriteDoubleAttribute(
          libmems::kSamplingFrequencyAttr, frequency)) {
    LOGF(ERROR) << "Failed to set hrtimer's frequency";
    return false;
  }

  return true;
}

void SamplesHandler::UpdateChannelsEnabledOnThread(
    ClientData* client_data,
    const std::vector<int32_t>& iio_chn_indices,
    bool en,
    cros::mojom::SensorDevice::SetChannelsEnabledCallback callback) {
  DCHECK(sample_task_runner_->BelongsToCurrentThread());
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);

  std::vector<int32_t> failed_indices;

  if (en) {
    for (int32_t chn_index : iio_chn_indices) {
      auto chn = iio_device_->GetChannel(chn_index);
      if (!chn || !chn->IsEnabled()) {
        LOGF(ERROR) << "Failed to enable chn with index: " << chn_index;
        failed_indices.push_back(chn_index);
        continue;
      }

      client_data->enabled_chn_indices.emplace(chn_index);
    }
  } else {
    for (int32_t chn_index : iio_chn_indices) {
      client_data->enabled_chn_indices.erase(chn_index);
      // remove cached chn's moving average
      clients_map_[client_data]->chns_.erase(chn_index);
    }
  }

  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(std::move(callback), std::move(failed_indices)));

  auto it = inactive_clients_.find(client_data);
  if (it != inactive_clients_.end()) {
    if (client_data->IsSampleActive()) {
      // The client is now active.
      inactive_clients_.erase(it);
      AddActiveClientOnThread(client_data);
    }

    return;
  }

  if (clients_map_.find(client_data) == clients_map_.end())
    return;

  if (client_data->IsSampleActive()) {
    // The client remains active
    return;
  }

  RemoveActiveClientOnThread(client_data, client_data->frequency);
  inactive_clients_.emplace(client_data);
}

void SamplesHandler::GetChannelsEnabledOnThread(
    ClientData* client_data,
    const std::vector<int32_t>& iio_chn_indices,
    cros::mojom::SensorDevice::GetChannelsEnabledCallback callback) {
  DCHECK(sample_task_runner_->BelongsToCurrentThread());
  DCHECK_EQ(client_data->device_data->iio_device, iio_device_);

  std::vector<bool> enabled;

  for (int32_t chn_index : iio_chn_indices) {
    enabled.push_back(client_data->enabled_chn_indices.find(chn_index) !=
                      client_data->enabled_chn_indices.end());
  }

  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(std::move(callback), std::move(enabled)));
}

void SamplesHandler::OnSampleAvailableWithoutBlocking() {
  DCHECK(sample_task_runner_->BelongsToCurrentThread());
  DCHECK(num_read_failed_logs_ == 0 || num_read_failed_logs_recovery_ == 0);

  auto sample = iio_device_->ReadSample();
  if (!sample) {
    AddReadFailedLogOnThread();
    for (auto& [client_data, _] : clients_map_) {
      client_data->samples_observer->OnErrorOccurred(
          cros::mojom::ObserverErrorType::READ_FAILED);
    }

    return;
  }

  if (accel_axis_indices_[0] != -1) {
    DCHECK(accel_axis_indices_[1] != -1 && accel_axis_indices_[2] != -1);
    auto sample_orig = sample.value();
    for (int i = 0; i < kNumberOfAxes; ++i) {
      sample.value()[i] = 0;
      for (int j = 0; j < kNumberOfAxes; ++j) {
        sample.value()[i] +=
            sample_orig[accel_axis_indices_[j]] * accel_matrix_[i][j];
      }
    }
  }

  OnSampleAvailableOnThread(sample.value());
}

}  // namespace iioservice
