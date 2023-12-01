// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SENSOR_DEVICE_FUSION_H_
#define IIOSERVICE_DAEMON_SENSOR_DEVICE_FUSION_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "iioservice/daemon/common_types.h"
#include "iioservice/daemon/samples_handler_fusion.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class SensorDeviceFusionTest;

// SensorDeviceFusion is a base class that handles mojo requests for one fusion
// device.
class SensorDeviceFusion : public cros::mojom::SensorDevice {
 public:
  static void SensorDeviceFusionDeleter(SensorDeviceFusion* device);
  using ScopedSensorDeviceFusion =
      std::unique_ptr<SensorDeviceFusion, decltype(&SensorDeviceFusionDeleter)>;

  class IioDeviceHandler : public cros::mojom::SensorDeviceSamplesObserver {
   public:
    IioDeviceHandler(
        scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
        int32_t iio_device_id,
        cros::mojom::DeviceType type,
        base::RepeatingCallback<
            void(int32_t iio_device_id,
                 mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
            iio_add_receiver_callback,
        base::RepeatingCallback<void(std::vector<int64_t>)>
            on_sample_updated_callback,
        base::RepeatingCallback<void()> on_read_failed_callback,
        base::OnceCallback<void()> invalidate_callback);

    void SetAttribute(std::string attr_name,
                      std::optional<std::string> attr_value);

    void SetFrequency(double frequency,
                      cros::mojom::SensorDevice::SetFrequencyCallback callback =
                          base::OnceCallback<void(double)>());
    void GetAttributes(
        const std::vector<std::string>& attr_names,
        cros::mojom::SensorDevice::GetAttributesCallback callback);

    void DisableSamples();

    // cros::mojom::SensorDeviceSamplesObserver overrides:
    void OnSampleUpdated(
        const base::flat_map<int32_t, int64_t>& sample) override;
    void OnErrorOccurred(cros::mojom::ObserverErrorType type) override;

   private:
    void Invalidate();

    // Set |channel_ids_| based on |type_|;
    void SetChannelIds();

    void OnIioDeviceDisconnect();
    void OnObserverDisconnect();

    void SetFrequencyCallback(
        double requested_frequency,
        cros::mojom::SensorDevice::SetFrequencyCallback callback,
        double result_frequency);
    void GetAttributesCallback(
        const std::vector<std::string>& attr_names,
        cros::mojom::SensorDevice::GetAttributesCallback callback,
        const std::vector<std::optional<std::string>>& values);

    void GetAllChannelIdsCallback(const std::vector<std::string>& iio_chn_ids);
    void SetChannelsEnabledCallback(const std::vector<int32_t>& failed_indices);

    void StartReading();

    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner_;
    int32_t iio_device_id_;
    cros::mojom::DeviceType type_;
    base::RepeatingCallback<void(std::vector<int64_t>)>
        on_sample_updated_callback_;
    base::RepeatingCallback<void()> on_read_failed_callback_;
    base::OnceCallback<void()> invalidate_callback_;

    mojo::Remote<cros::mojom::SensorDevice> remote_;

    // Overridden attributes.
    std::map<std::string, std::optional<std::string>> attributes_;

    // Required channel ids.
    std::vector<std::string> channel_ids_;
    // Indices of the required channels |channel_ids_|.
    std::vector<int32_t> channel_indices_;

    mojo::Receiver<cros::mojom::SensorDeviceSamplesObserver> receiver_{this};

    base::WeakPtrFactory<IioDeviceHandler> weak_factory_{this};
  };

  virtual void AddReceiver(
      mojo::PendingReceiver<cros::mojom::SensorDevice> request);

  // cros::mojom::SensorDevice overrides:
  void SetTimeout(uint32_t timeout) override;
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
  void GetAllEvents(GetAllEventsCallback callback) override;
  void GetEventsAttributes(const std::vector<int32_t>& iio_event_indices,
                           const std::string& attr_name,
                           GetEventsAttributesCallback callback) override;
  void StartReadingEvents(
      const std::vector<int32_t>& iio_event_indices,
      mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> observer)
      override;

 protected:
  friend SensorDeviceFusionTest;

  // Set |samples_handler_| in the derived class' c'tor.
  SensorDeviceFusion(
      int32_t id,
      cros::mojom::DeviceType type,
      Location location,
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      base::RepeatingCallback<
          void(int32_t iio_device_id,
               mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
          iio_add_receiver_callback,
      double max_frequency,
      std::vector<std::string> channel_ids);

  virtual void Invalidate();

  // Called by |samples_handler_|, which indicates the max frequency among
  // sensor clients on this fusion device.
  virtual void UpdateRequestedFrequency(double frequency);

  void OnSensorDeviceDisconnect();
  void OnIioDeviceDisconnect(int32_t iio_device_id,
                             cros::mojom::DeviceType type);

  void StopReadingSamplesOnClient(mojo::ReceiverId id);

  double FixFrequency(double frequency);
  double FixFrequencyWithMin(double min_frequency, double frequency);

  int32_t id_;
  cros::mojom::DeviceType type_;
  Location location_;
  scoped_refptr<base::SequencedTaskRunner> ipc_task_runner_;
  base::RepeatingCallback<void(
      int32_t iio_device_id,
      mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
      iio_add_receiver_callback_;
  double max_frequency_;
  std::vector<std::string> channel_ids_;

  // If true, fail SetFrequency and SetChannelsEnabled and reading samples.
  bool invalid_ = false;

  mojo::ReceiverSet<cros::mojom::SensorDevice> receiver_set_;

  // First is the id of the mojo client using this fusion device, second is its
  // data.
  std::map<mojo::ReceiverId, ClientData> clients_;

  // The derived classes should store the IioDeviceHandlers here.
  std::vector<std::unique_ptr<IioDeviceHandler>> iio_device_handlers_;

  std::unique_ptr<SamplesHandlerFusion> samples_handler_;

  // The max frequency among sensor clients.
  double requested_frequency_;

 private:
  base::WeakPtrFactory<SensorDeviceFusion> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SENSOR_DEVICE_FUSION_H_
