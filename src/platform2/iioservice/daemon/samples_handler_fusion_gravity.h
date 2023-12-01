// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SAMPLES_HANDLER_FUSION_GRAVITY_H_
#define IIOSERVICE_DAEMON_SAMPLES_HANDLER_FUSION_GRAVITY_H_

#include <optional>
#include <string>
#include <vector>

#include <base/containers/flat_map.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>

#include "iioservice/daemon/fusion.h"
#include "iioservice/daemon/samples_handler_fusion.h"

namespace iioservice {

class SamplesHandlerFusionGravity final : public SamplesHandlerFusion {
 public:
  SamplesHandlerFusionGravity(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      std::vector<std::string> channel_ids,
      UpdateFrequencyCallback callback);
  SamplesHandlerFusionGravity(const SamplesHandlerFusionGravity&) = delete;
  SamplesHandlerFusionGravity& operator=(const SamplesHandlerFusionGravity&) =
      delete;
  ~SamplesHandlerFusionGravity();

  void SetScale(cros::mojom::DeviceType type, double scale);

  void HandleAccelSample(std::vector<int64_t> accel_sample);
  void HandleGyroSample(std::vector<int64_t> gyro_sample);

  base::WeakPtr<SamplesHandlerFusionGravity> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

 protected:
  // SamplesHandlerFusion overrides:
  bool SampleIsValid(const base::flat_map<int32_t, int64_t>& sample);

 private:
  Fusion fusion_;

  std::optional<double> accel_scale_;
  std::optional<double> gyro_scale_;

  int64_t accel_timestamp_ = 0;
  int64_t gyro_timestamp_ = 0;

  base::WeakPtrFactory<SamplesHandlerFusionGravity> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SAMPLES_HANDLER_FUSION_GRAVITY_H_
