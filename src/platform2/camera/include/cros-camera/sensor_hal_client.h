/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_SENSOR_HAL_CLIENT_H_
#define CAMERA_INCLUDE_CROS_CAMERA_SENSOR_HAL_CLIENT_H_

#include <map>
#include <memory>
#include <vector>

#include <base/functional/callback.h>

#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/export.h"

namespace cros {

// SamplesObserver imitates the iioservice mojo interface:
// cros::mojom::SensorDeviceSamplesObserver, which waits for samples and errors
// from iioservice.
//
// The user should implement this virtual class to get notified when samples and
// errors come in the mojo IPC thread, which is the thread that
// CameraMojoChannelManager uses to communicate with iioservice in mojo
// channels.
// Note that the user should NOT block in the mojo IPC thread, as it's used to
// send and receive multiple IPC calls. Most SensorHalClient's functions defined
// below are blocking functions and therefore should not be used in the mojo IPC
// thread.
class CROS_CAMERA_EXPORT SamplesObserver {
 public:
  struct Sample {
    double x_value;
    double y_value;
    double z_value;
    int64_t timestamp;
  };
  // Enumeration of receiver errors.
  enum class ErrorType {
    // Mojo connection to SensorHalDispatcher is broken.
    // Abort all usages.
    MOJO_DISCONNECTED = 0,
    // Error when setting configurations to iioservice.
    // Abort all usages.
    INVALID_ARGUMENT = 1,
    // A sample read failed. Other samples should still be read. If this
    // happens too frequently, the user could abort all usages.
    READ_FAILED = 2,
    // The device is removed from the system and is no longer available. The
    // user should abort all usages and choose other devices instead.
    // The SamplesObserver will be automatically unregistered in
    // SensorHalClient.
    DEVICE_REMOVED = 3,
  };

  // |OnSampleUpdated| and |OnErrorOccurred| are guaranteed to be called in
  // sequence (in the IPC thread). Users can send them to other sequences by
  // posting tasks.

  // |sample| contains the 3d calibrated and scaled data in x, y, and z axes.
  // |sample.timestamp| contains the timestamp of |sample|.
  virtual void OnSampleUpdated(Sample sample) = 0;
  virtual void OnErrorOccurred(ErrorType error) = 0;
};

// SensorHalClient is a wrapper class of the iioservice mojo interfaces, which
// gets connected to chromium's SensorHalDispatcher and iioservice, retrieves
// the information of devices, and lets the user register SamplesObservers.
//
// Note that the user should not use SensorHalClient's methods in the IPC
// thread, which is the thread to receive samples and errors in SamplesObserver,
// as they are blocking functions and will wait for callbacks in the IPC thread.
//
// Example:
//   SensorHalClient* sensor_hal_client = SensorHalClient::GetInstance(token);
//
//   // Look for the accelerometer on LID.
//   if (!sensor_hal_client->HasDevice(SensorHalClient::DeviceType::kAccel,
//       SensorHalClient::Location::kLid)) {
//     // No accel on LID. Abort.
//   }
//
//   // Implement an observer based on SamplesObserver.
//   SamplesObserverImpl samples_observer;
//
//   // Register |samples_observer| with 100Hz on the accelerometer on lid.
//   sensor_hal_client->RegisterSamplesObserver(
//       SensorHalClient::DeviceType::kAccel,
//       SensorHalClient::Location::kLid,
//       100.0,
//       &samples_observer);
//
//   // Wait for samples or errors on the IPC thread.
//
//   // Unregister |samples_observer| before destructing it.
//   sensor_hal_client->UnregisterSamplesObserver(&samples_observer);
//
class CROS_CAMERA_EXPORT SensorHalClient {
 public:
  enum class DeviceType {
    kNone = 0,     // Not used. Just making the order the same with iioservice:
                   // cros::mojom::DeviceType.
    kAccel = 1,    // Accelerometer.
    kAnglVel = 2,  // Gyroscope.
    kMagn = 3,     // Magnetometer.
    kGravity = 4,  // Gravity fusion sensor.
  };

  enum class Location {
    kNone = 0,  // The device doesn't have the location attribute.
    kBase = 1,
    kLid = 2,
    kCamera = 3,
  };

  static SensorHalClient* GetInstance(CameraMojoChannelManagerToken* token);

  virtual ~SensorHalClient() = default;

  // Check if a device exists by |type| and |location|.
  virtual bool HasDevice(DeviceType type, Location location) = 0;

  // Register |samples_observer| with |frequency| to the device with |type| and
  // |location|. The pair of |type| and |location| should exist in the result of
  // the previous query: |HasDevice|.
  // It's the user's responsibility to ensure |samples_observer| is valid until
  // UnregisterSamplesObserver is called.
  // Return true if success; Return false if device with |type| and |location|
  // doesn't exist, or |frequency| is invalid, or |samples_observer| is already
  // registered to another device.
  virtual bool RegisterSamplesObserver(DeviceType type,
                                       Location location,
                                       double frequency,
                                       SamplesObserver* samples_observer) = 0;

  // Unregister |samples_observer| to prevent getting more samples. It should be
  // called before destructing |samples_observer|.
  virtual void UnregisterSamplesObserver(SamplesObserver* samples_observer) = 0;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_SENSOR_HAL_CLIENT_H_
