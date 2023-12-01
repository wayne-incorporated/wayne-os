// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_IIO_CONTEXT_H_
#define LIBMEMS_IIO_CONTEXT_H_

#include <iio.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "libmems/export.h"

namespace libmems {

class IioDevice;

// The IioContext is the root of the tree of IIO devices on the system.
// A context is - at its core - a container of devices, which can be
// retrieved via GetDevicesByName, GetDeviceById and GetAllDevices, providing
// the devices's name, id or nothing as input.
class LIBMEMS_EXPORT IioContext {
 public:
  virtual ~IioContext() = default;

  // If there's no devices or triggers in the sysfs yet, context cannot be
  // created.
  // Returns true if the context is valid and available.
  virtual bool IsValid() const = 0;

  // Returns the iio_context object underlying this object, if any is available.
  // Returns nullptr if no iio_device exists.
  virtual iio_context* GetCurrentContext() const = 0;

  // libiio loads the device list at context creation time, and does not
  // have a way to update it as new devices appear on the system.
  // This is a helper that allows a rescan of the system to find new devices
  // dynamically at runtime. It should be called after any actions that cause
  // new devices of interest to show up.
  virtual void Reload() = 0;

  // Sets |timeout| in milliseconds for I/O operations, mainly for reading
  // events. Sets |timeout| as 0 to specify that no timeout should occur.
  // Default for network/unix_socket backend: 5000 milliseconds.
  // Default for local backend: 1000 millisecond.
  // Returns true if success.
  virtual bool SetTimeout(uint32_t timeout) = 0;

  // Returns IioDevices as a vector given the device's name. Only devices with
  // id having "iio:device" as the prefix would be available.
  // Returns an empty vector if no device can be found.
  // The device objects are guaranteed to stay valid as long as this context
  // object is valid.
  virtual std::vector<IioDevice*> GetDevicesByName(const std::string& name) = 0;

  // Returns an IioDevice given the device's ID by int. Real id in string would
  // be "iio:device|id|".
  // Returns nullptr if the device cannot be found. The
  // device object is guaranteed to stay valid as long as this context object is
  // valid.
  virtual IioDevice* GetDeviceById(int id) = 0;

  // Returns all IioDevices as a vector. Only devices with id having
  // "iio:device" as the prefix would be available.
  // Returns an empty vector if no device can be found.
  // The device objects are guaranteed to stay valid as long as this context
  // object is valid.
  virtual std::vector<IioDevice*> GetAllDevices() = 0;

  // Returns triggers as a vector given the trigger's name.
  // Returns an empty vector if no device can be found.
  // The trigger objects are guaranteed to stay valid as long as this context
  // object is valid.
  virtual std::vector<IioDevice*> GetTriggersByName(
      const std::string& name) = 0;

  // Returns an IioDevice given the trigger's ID by int. Real id in string would
  // be "trigger|id|". If |id| is -1, trigger iio_sysfs_trigger is returned.
  // Returns nullptr if the device cannot be found. The
  // device object is guaranteed to stay valid as long as this context object is
  // valid.
  virtual IioDevice* GetTriggerById(int id) = 0;

  // Returns all triggers as a vector.
  // Returns an empty vector if no device can be found.
  // The device objects are guaranteed to stay valid as long as this context
  // object is valid.
  virtual std::vector<IioDevice*> GetAllTriggers() = 0;

 protected:
  IioContext() = default;
  IioContext(const IioContext&) = delete;
  IioContext& operator=(const IioContext&) = delete;
};

}  // namespace libmems

#endif  // LIBMEMS_IIO_CONTEXT_H_
