// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_LOCAL_SERVICE_H_
#define SHILL_WIFI_LOCAL_SERVICE_H_

#include <string>

#include "shill/mockable.h"
#include "shill/refptr_types.h"

namespace shill {

class KeyValueStore;
class LocalDevice;
class Manager;

// LocalService superclass. This class is used as a base class for local
// connection service. Individual local connection service will inherit from
// this class.
class LocalService {
 public:
  enum class LocalServiceState {
    // Service is not active.
    kStateIdle,
    // L2 service starting.
    kStateStarting,
    // L2 service is up.
    kStateUp,
  };
  static const char* StateToString(const LocalServiceState& state);

  LocalService(LocalDeviceConstRefPtr device);
  LocalService(const LocalService&) = delete;
  LocalService& operator=(const LocalService&) = delete;

  virtual ~LocalService();

  // Each child class should implement this method to generate a wpa_supplicant
  // recognizable dictionary to be used to set the network parameters.
  virtual KeyValueStore GetSupplicantConfigurationParameters() const = 0;

  // Updates the state of the Service and alerts the device event listener.
  void SetState(LocalServiceState state);

  // Return if the service is up.
  bool IsUp() const;

  const std::string& log_name() const { return log_name_; }
  LocalServiceState state() const { return state_; }

 private:
  static bool IsUpState(LocalServiceState state);

  friend class LocalServiceTest;

  LocalDeviceConstRefPtr device_;
  LocalServiceState state_;

  // Name used for logging. It includes the service type, and other
  // non PII identifiers.
  std::string log_name_;
  // A unique identifier for the service.
  unsigned int serial_number_;
  // The |serial_number_| for the next Service.
  static unsigned int next_serial_number_;
};

}  // namespace shill

#endif  // SHILL_WIFI_LOCAL_SERVICE_H_
