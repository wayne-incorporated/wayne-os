// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SAMPLES_HANDLER_H_
#define IIOSERVICE_DAEMON_SAMPLES_HANDLER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <libmems/iio_context.h>
#include <libmems/iio_device.h>
#include <mojo/public/cpp/bindings/receiver_set.h>

#include "iioservice/daemon/common_types.h"
#include "iioservice/daemon/samples_handler_base.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

// A SamplesHandler is a handler of an IioDevice's samples. The user should add,
// remove, and update clients with frequencies and channels, and this handler
// will dispatch samples with clients' desired frequencies and channels when
// samples are received from the kernel.
// The user can provide the same |sample_task_runner| to all SamplesHandler as
// there is no blocking function in SamplesHandler and the thread would not be
// heavily loaded.
class SamplesHandler : public SamplesHandlerBase {
 public:
  static void SamplesHandlerDeleter(SamplesHandler* handler);
  using ScopedSamplesHandler =
      std::unique_ptr<SamplesHandler, decltype(&SamplesHandlerDeleter)>;

  static bool DisableBufferAndEnableChannels(libmems::IioDevice* iio_device);
  static ScopedSamplesHandler Create(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> sample_task_runner,
      DeviceData* const device_data);

  virtual ~SamplesHandler();

  void ResetWithReason(cros::mojom::SensorDeviceDisconnectReason reason,
                       std::string description,
                       base::OnceCallback<void()> callback);

  // It's the user's responsibility to maintain |client_data| before being
  // removed or this class being destructed.
  // |client_data.iio_device| should be the same as |iio_device_|.
  void AddClient(
      ClientData* client_data,
      mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer);
  void RemoveClient(ClientData* client_data, base::OnceClosure callback);

  void UpdateFrequency(
      ClientData* client_data,
      double frequency,
      cros::mojom::SensorDevice::SetFrequencyCallback callback);
  void UpdateChannelsEnabled(
      ClientData* client_data,
      const std::vector<int32_t>& iio_chn_indices,
      bool en,
      cros::mojom::SensorDevice::SetChannelsEnabledCallback callback);

  void GetChannelsEnabled(
      ClientData* client_data,
      const std::vector<int32_t>& iio_chn_indices,
      cros::mojom::SensorDevice::GetChannelsEnabledCallback callback);

 protected:
  // use fifo
  SamplesHandler(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
                 scoped_refptr<base::SingleThreadTaskRunner> sample_task_runner,
                 DeviceData* const device_data,
                 double min_freq,
                 double max_freq);

  void SetSampleWatcherOnThread();
  void StopSampleWatcherOnThread();

  double FixFrequency(double frequency) override;
  double FixFrequencyWithMin(double frequency);

  void AddActiveClientOnThread(ClientData* client_data) override;

  void RemoveActiveClientOnThread(ClientData* client_data,
                                  double orig_freq) override;

  void UpdateFrequencyOnThread(
      ClientData* client_data,
      double frequency,
      cros::mojom::SensorDevice::SetFrequencyCallback callback);

  bool UpdateRequestedFrequencyOnThread() override;

  void UpdateChannelsEnabledOnThread(
      ClientData* client_data,
      const std::vector<int32_t>& iio_chn_indices,
      bool en,
      cros::mojom::SensorDevice::SetChannelsEnabledCallback callback);

  void GetChannelsEnabledOnThread(
      ClientData* client_data,
      const std::vector<int32_t>& iio_chn_indices,
      cros::mojom::SensorDevice::GetChannelsEnabledCallback callback);

  void OnSampleAvailableWithoutBlocking();

  scoped_refptr<base::SequencedTaskRunner> ipc_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> sample_task_runner_;
  libmems::IioDevice* iio_device_;

  double dev_min_frequency_ = 0.0;
  double dev_max_frequency_ = 0.0;

  int accel_axis_indices_[3] = {-1, -1, -1};
  double accel_matrix_[3][3];

  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;

 private:
  base::WeakPtrFactory<SamplesHandler> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SAMPLES_HANDLER_H_
