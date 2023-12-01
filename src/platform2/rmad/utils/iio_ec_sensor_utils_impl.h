// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_IIO_EC_SENSOR_UTILS_IMPL_H_
#define RMAD_UTILS_IIO_EC_SENSOR_UTILS_IMPL_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "rmad/utils/iio_ec_sensor_utils.h"
#include "rmad/utils/mojo_service_utils.h"

namespace rmad {

class IioEcSensorUtilsImpl : public IioEcSensorUtils,
                             public cros::mojom::SensorDeviceSamplesObserver {
 public:
  explicit IioEcSensorUtilsImpl(scoped_refptr<MojoServiceUtils> mojo_service,
                                const std::string& location,
                                const std::string& name);
  // Used to inject |sysfs_prefix| for testing.
  explicit IioEcSensorUtilsImpl(scoped_refptr<MojoServiceUtils> mojo_service,
                                const std::string& location,
                                const std::string& name,
                                const std::string& sysfs_prefix);
  ~IioEcSensorUtilsImpl() = default;

  bool GetAvgData(GetAvgDataCallback result_callback,
                  const std::vector<std::string>& channels,
                  int samples) override;
  bool GetSysValues(const std::vector<std::string>& entries,
                    std::vector<double>* values) const override;

  bool IsInitialized() const { return initialized_; }

 private:
  void Initialize();
  // To find out a specific sensor and how to communicate with it, we will check
  // the value in sysfs and then get all the necessary information in the init
  // step.
  bool InitializeFromSysfsPath(const base::FilePath& sysfs_path);
  void FinishSampling();

  // Overrides.
  void OnSampleUpdated(const base::flat_map<int, int64_t>& sample) override;
  void OnErrorOccurred(cros::mojom::ObserverErrorType type) override;

  void HandleGetAllChannelIds(const std::vector<std::string>& channels);
  void HandleSetChannelsEnabled(const std::vector<int>& failed_channel_ids);

  std::string sysfs_prefix_;
  base::FilePath sysfs_path_;
  int id_;
  double frequency_;
  double scale_;
  bool initialized_;
  GetAvgDataCallback get_avg_data_result_callback_;
  std::map<std::string, int> channel_id_map_;
  std::map<int, std::vector<double>> sampled_data_;
  std::vector<std::string> target_channels_;
  std::vector<int> target_channel_ids_;
  int sample_times_;
  int samples_to_discard_;
  scoped_refptr<MojoServiceUtils> mojo_service_;
  mojo::Receiver<cros::mojom::SensorDeviceSamplesObserver>
      device_sample_receiver_{this};

  base::WeakPtrFactory<IioEcSensorUtilsImpl> weak_ptr_factory_{this};
};

}  // namespace rmad

#endif  // RMAD_UTILS_IIO_EC_SENSOR_UTILS_IMPL_H_
