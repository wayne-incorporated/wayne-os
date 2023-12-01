// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_IIO_EC_SENSOR_UTILS_H_
#define RMAD_UTILS_IIO_EC_SENSOR_UTILS_H_

#include <string>
#include <vector>

#include <base/functional/callback.h>

namespace rmad {

using GetAvgDataCallback =
    base::OnceCallback<void(const std::vector<double>& avg_data,
                            const std::vector<double>& variance_data)>;

class IioEcSensorUtils {
 public:
  explicit IioEcSensorUtils(const std::string& location,
                            const std::string& name)
      : location_(location), name_(name) {}
  virtual ~IioEcSensorUtils() = default;

  // Get the location of the ec sensor, which can be "base" or "lid".
  const std::string& GetLocation() const { return location_; }

  // Get sensor name of the ec sensor.
  const std::string& GetName() const { return name_; }

  // Use the given |channels| to get a specific number (|samples|) of data and
  // save the average value to |avg_data|. If there are any errors, leave
  // |avg_data| unaffected. If |variance| is set, it is computed when |samples|
  // > 1, otherwise the function fails. Returns true if the function succeeds,
  // otherwise returns false.
  virtual bool GetAvgData(GetAvgDataCallback result_callback,
                          const std::vector<std::string>& channels,
                          int samples) = 0;

  // Read |entries| to |values| in the sysfs of iioservice.
  // Returns true if it succeeds for all entries, otherwise it returns false.
  virtual bool GetSysValues(const std::vector<std::string>& entries,
                            std::vector<double>* values) const = 0;

 protected:
  // For each sensor, we can identify it by its location (base or lid)
  // and name (cros-ec-accel or cros-ec-gyro)
  std::string location_;
  std::string name_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_IIO_EC_SENSOR_UTILS_H_
