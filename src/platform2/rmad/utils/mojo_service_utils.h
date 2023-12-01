// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOJO_SERVICE_UTILS_H_
#define RMAD_UTILS_MOJO_SERVICE_UTILS_H_

#include <map>

#include <base/memory/ref_counted.h>
#include <iioservice/mojo/sensor.mojom.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo_service_manager/lib/mojom/service_manager.mojom.h>

namespace rmad {

class MojoServiceUtils : public base::RefCounted<MojoServiceUtils> {
 public:
  MojoServiceUtils() = default;
  virtual cros::mojom::SensorDevice* GetSensorDevice(int device_id) = 0;

 protected:
  // Hide the destructor so we don't accidentally delete this while there are
  // references to it.
  friend class base::RefCounted<MojoServiceUtils>;
  virtual ~MojoServiceUtils() = default;
};

class MojoServiceUtilsImpl : public MojoServiceUtils {
 public:
  MojoServiceUtilsImpl() = default;
  MojoServiceUtilsImpl(const MojoServiceUtilsImpl&) = delete;
  MojoServiceUtilsImpl& operator=(const MojoServiceUtilsImpl&) = delete;

  void Initialize();
  cros::mojom::SensorDevice* GetSensorDevice(int device_id) override;

  // Functions for testing.
  void SetSensorServiceForTesting(
      mojo::PendingRemote<cros::mojom::SensorService> service);
  void InsertDeviceForTesting(int device_id);
  void SetInitializedForTesting();
  void SetConnectionErrorHandler(base::RepeatingCallback<void()> callback);

 private:
  bool is_initialized = false;
  mojo::Remote<chromeos::mojo_service_manager::mojom::ServiceManager>
      service_manager_;
  mojo::Remote<cros::mojom::SensorService> sensor_service_;
  std::map<int, mojo::Remote<cros::mojom::SensorDevice>> sensor_devices_map_;
  base::RepeatingCallback<void()> connection_error_callback_ =
      base::DoNothing();
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOJO_SERVICE_UTILS_H_
