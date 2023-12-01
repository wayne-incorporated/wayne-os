// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SAMPLES_HANDLER_FUSION_H_
#define IIOSERVICE_DAEMON_SAMPLES_HANDLER_FUSION_H_

#include <map>
#include <set>
#include <string>
#include <vector>

#include <base/containers/flat_map.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>

#include "iioservice/daemon/common_types.h"
#include "iioservice/daemon/samples_handler_base.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class SamplesHandlerFusionTestWithParam;

// Should only be used on the IPC thread.
class SamplesHandlerFusion : public SamplesHandlerBase {
 public:
  using UpdateFrequencyCallback = base::RepeatingCallback<void(double)>;

  SamplesHandlerFusion(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
                       std::vector<std::string> channel_ids,
                       UpdateFrequencyCallback callback);

  virtual ~SamplesHandlerFusion();

  // It's the user's responsibility to maintain |client_data| before being
  // removed or this class being destructed.
  // |client_data.iio_device| should be the same as |iio_device_|.
  void AddClient(
      ClientData* client_data,
      mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer);
  void RemoveClient(ClientData* client_data);
  void UpdateFrequency(ClientData* client_data, double frequency);

  void SetDevFrequency(double frequency) { dev_frequency_ = frequency; }

  void Invalidate();

  base::WeakPtr<SamplesHandlerFusion> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

 protected:
  friend SamplesHandlerFusionTestWithParam;

  // SamplesHandlerBase overrides:
  bool UpdateRequestedFrequencyOnThread() override;
  void OnSampleAvailableOnThread(
      const base::flat_map<int32_t, int64_t>& sample) override;

  virtual bool SampleIsValid(const base::flat_map<int32_t, int64_t>& sample);

  scoped_refptr<base::SequencedTaskRunner> ipc_task_runner_;
  UpdateFrequencyCallback update_frequency_callback_;

  bool invalid_ = false;

 private:
  base::WeakPtrFactory<SamplesHandlerFusion> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SAMPLES_HANDLER_FUSION_H_
