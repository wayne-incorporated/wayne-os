// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SENSOR_DEVICE_IMPL_H_
#define IIOSERVICE_DAEMON_SENSOR_DEVICE_IMPL_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/threading/thread.h>
#include <libmems/iio_context.h>
#include <libmems/iio_device.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "iioservice/daemon/common_types.h"
#include "iioservice/daemon/events_handler.h"
#include "iioservice/daemon/samples_handler.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class SensorDeviceImpl final : public cros::mojom::SensorDevice {
 public:
  static void SensorDeviceImplDeleter(SensorDeviceImpl* device);
  using ScopedSensorDeviceImpl =
      std::unique_ptr<SensorDeviceImpl, decltype(&SensorDeviceImplDeleter)>;

  static ScopedSensorDeviceImpl Create(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      libmems::IioContext* context);

  ~SensorDeviceImpl();

  void OnDeviceAdded(libmems::IioDevice* iio_device,
                     const std::set<cros::mojom::DeviceType>& types);
  void OnDeviceRemoved(int iio_device_id);

  void AddReceiver(int32_t iio_device_id,
                   mojo::PendingReceiver<cros::mojom::SensorDevice> request);

  // cros::mojom::SensorDevice overrides:
  void SetTimeout(uint32_t timeout) override;
  void GetAttributes(const std::vector<std::string>& attr_names,
                     GetAttributesCallback callback) override;
  void SetFrequency(double frequency, SetFrequencyCallback callback) override;
  void StartReadingSamples(
      mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer)
      override;
  void StopReadingSamples() override;
  void GetAllChannelIds(GetAllChannelIdsCallback callback) override;
  void SetChannelsEnabled(const std::vector<int32_t>& iio_chn_indices,
                          bool en,
                          SetChannelsEnabledCallback callback) override;
  void GetChannelsEnabled(const std::vector<int32_t>& iio_chn_indices,
                          GetChannelsEnabledCallback callback) override;
  void GetChannelsAttributes(const std::vector<int32_t>& iio_chn_indices,
                             const std::string& attr_name,
                             GetChannelsAttributesCallback callback) override;
  void GetAllEvents(GetAllEventsCallback callback) override;
  void GetEventsAttributes(const std::vector<int32_t>& iio_event_indices,
                           const std::string& attr_name,
                           GetEventsAttributesCallback callback) override;
  void StartReadingEvents(
      const std::vector<int32_t>& iio_event_indices,
      mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> observer)
      override;

  base::WeakPtr<SensorDeviceImpl> GetWeakPtr();

 private:
  SensorDeviceImpl(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
                   libmems::IioContext* context,
                   std::unique_ptr<base::Thread> thread);

  void OnSensorDeviceDisconnect();
  void RemoveClient(mojo::ReceiverId id);

  void OnSamplesObserverDisconnect(mojo::ReceiverId id);
  void StopReadingSamplesOnClient(mojo::ReceiverId id,
                                  base::OnceClosure callback);
  void StopReadingEventsOnClient(mojo::ReceiverId id,
                                 base::OnceClosure callback);

  scoped_refptr<base::SequencedTaskRunner> ipc_task_runner_;
  libmems::IioContext* context_;  // non-owned
  mojo::ReceiverSet<cros::mojom::SensorDevice> receiver_set_;
  std::unique_ptr<base::Thread> sample_thread_;

  // First is iio device id, second is the device's data.
  std::map<int32_t, DeviceData> devices_;

  // As |clients_| contain some data that should only be used in
  // |sample_thread_|, make sure |sample_thread_| is stopped before destructing
  // |clients_|.
  std::map<mojo::ReceiverId, ClientData> clients_;

  std::map<int, SamplesHandler::ScopedSamplesHandler> samples_handlers_;
  std::map<int, EventsHandler::ScopedEventsHandler> events_handlers_;

  base::WeakPtrFactory<SensorDeviceImpl> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SENSOR_DEVICE_IMPL_H_
