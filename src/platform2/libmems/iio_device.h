// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_IIO_DEVICE_H_
#define LIBMEMS_IIO_DEVICE_H_

#include <iio.h>

#include <linux/iio/events.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/containers/flat_map.h>
#include <base/files/file_path.h>
#include <base/time/time.h>

#include "libmems/export.h"
#include "libmems/iio_event.h"

namespace libmems {

class IioContext;
class IioChannel;

// The IioDevice represents a single IIO device, such as a gyroscope.
// It offers facilities to read and write attributes on the device, as well as
// configure channels, trigger and buffer for a sensor.
class LIBMEMS_EXPORT IioDevice {
 public:
  // first is channel index; second is the channel's value
  using IioSample = base::flat_map<int32_t, int64_t>;

  virtual ~IioDevice();

  // Returns the IIO context that contains this device.
  virtual IioContext* GetContext() const = 0;

  // Returns the value of the 'name' attribute of this device.
  // It is allowed to return an empty string.
  virtual const char* GetName() const = 0;

  // Returns the unique IIO identifier of this device/trigger.
  // Return id greater or equal to 0 if it's a device.
  // Return id be -1 if it's iio_sysfs_trigger, greater or equal to 0 if it's a
  // trigger.
  virtual int GetId() const = 0;

  // This call is used to enable setting UNIX permissions and ownership on the
  // attributes of a sensor. It should not be used as a replacement for the
  // read/write attribute accessors below.
  virtual base::FilePath GetPath() const = 0;

  std::optional<base::FilePath> GetAbsoluteSysPath() const;

  std::optional<std::string> GetLocation() const;

  // Reads the |name| attribute of this device and returns the value
  // as a string. It will return std::nullopt if the attribute cannot
  // be read.
  virtual std::optional<std::string> ReadStringAttribute(
      const std::string& name) const = 0;

  // Reads the |name| attribute of this device and returns the value
  // as a signed number. It will return std::nullopt if the attribute
  // cannot be read or is not a valid number.
  virtual std::optional<int64_t> ReadNumberAttribute(
      const std::string& name) const = 0;

  // Reads the |name| attribute of this device and returns the value
  // as a double precision floating point. It will return std::nullopt
  // if the attribute cannot be read or is not a valid number.
  virtual std::optional<double> ReadDoubleAttribute(
      const std::string& name) const = 0;

  // Writes the string |value| to the attribute |name| of this device. Returns
  // false if an error occurs.
  virtual bool WriteStringAttribute(const std::string& name,
                                    const std::string& value) = 0;

  // Writes the number |value| to the attribute |name| of this device. Returns
  // false if an error occurs.
  virtual bool WriteNumberAttribute(const std::string& name, int64_t value) = 0;

  // Writes the floating point |value| to the attribute |name| of this device.
  // Returns false if an error occurs.
  virtual bool WriteDoubleAttribute(const std::string& name, double value) = 0;

  // Returns true if this device has a fifo queue for samples.
  virtual bool HasFifo() const = 0;

  // Returns true if this device represents a single sensor, vs. a device
  // representing all available cros_ec sensors on the system, as defined
  // before 3.18 kernel.
  bool IsSingleSensor() const;

  // Returns the iio_device object underlying this object, if any is available.
  // Returns nullptr if no iio_device exists, e.g. a mock object.
  virtual iio_device* GetUnderlyingIioDevice() const = 0;

  // Sets |trigger| as the IIO trigger device for this device. It is expected
  // that |trigger| is owned by the same IIO context as this device.
  virtual bool SetTrigger(IioDevice* trigger_device) = 0;

  // Returns the IIO trigger device for this device, or nullptr if this device
  // has no trigger, or the trigger can't be found.
  virtual IioDevice* GetTrigger() = 0;

  // Returns the IIO hrtimer trigger device for this device, or nullptr if there
  // is no such hrtimer trigger device.
  virtual IioDevice* GetHrtimer() = 0;

  // Returns all channels belonging to this device.
  std::vector<IioChannel*> GetAllChannels();

  // Enables all channels belonging to this device.
  void EnableAllChannels();

  // Finds the IIO channel |index| as the index in this device and returns it.
  // It will return nullptr if no such channel can be found.
  IioChannel* GetChannel(int32_t index);

  // Finds the IIO channel |name| as id or name for this device and returns it.
  // It will return nullptr if no such channel can be found.
  IioChannel* GetChannel(const std::string& name);

  // Returns all events belonging to this device.
  std::vector<IioEvent*> GetAllEvents();

  // Enables all events belonging to this device.
  void EnableAllEvents();

  // Finds the IIO event |index| as the index in this device and returns it.
  // It will return nullptr if no such channel can be found.
  IioEvent* GetEvent(int32_t index);

  // Returns the sample size in this device.
  // Returns std::nullopt on failure.
  virtual std::optional<size_t> GetSampleSize() const = 0;

  // Enables the IIO buffer on this device and configures it to return
  // |num| samples on access. This buffer's lifetime can exceed that of the
  // IioContext, and that it's caller responsibility to know when to let go of
  // the buffer with DisableBuffer if at all.
  // It should not be used along with GetBufferFd or ReadEvent.
  // Returns false on failure.
  virtual bool EnableBuffer(size_t num) = 0;

  // Disables the IIO buffer on this device. Returns false on failure.
  virtual bool DisableBuffer() = 0;

  // Returns true if the IIO buffer is enabled for this device.
  // If it is enabled, it sets |num| to the number of samples.
  virtual bool IsBufferEnabled(size_t* num = nullptr) const = 0;

  // Creates the IIO buffer if it doesn't exist.
  // Returns false if the IIO buffer is already created.
  // Returns false on buffer not created.
  // The buffer's lifetime is managed by the client, which will be disabled when
  // FreeBuffer is called or the IioDevice along with the IioContext gets
  // destroyed. It should not be used along with EnableBuffer.
  virtual bool CreateBuffer() = 0;

  // Gets the file descriptor to poll for samples if the IIO buffer is created
  // by CreateBuffer.
  // Returns std::nullopt on failure.
  // The buffer's lifetime is managed by the IioDevice, which will be disabled
  // when the IioDevice along with the IioContext gets destroyed. It should not
  // be used along with EnableBuffer.
  virtual std::optional<int32_t> GetBufferFd() = 0;

  // Reads & returns one sample if the IIO buffer is created by CreateBuffer.
  // Returns std::nullopt on failure.
  // The buffer's lifetime is managed by the IioDevice, which will be disabled
  // when the IioDevice along with the IioContext gets destroyed. It should not
  // be used along with EnableBuffer.
  virtual std::optional<IioSample> ReadSample() = 0;

  // Frees the IIO buffer created by CreateBuffer if it exists. It should not be
  // used along with EnableBuffer.
  virtual void FreeBuffer() = 0;

  // Gets the file descriptor to poll for events.
  // Returns std::nullopt on failure.
  virtual std::optional<int32_t> GetEventFd() = 0;

  // Reads & returns one event.
  // Returns std::nullopt on failure.
  virtual std::optional<iio_event_data> ReadEvent() = 0;

  bool GetMinMaxFrequency(double* min_freq, double* max_freq);

 protected:
  struct ChannelData {
    std::string chn_id;
    std::unique_ptr<IioChannel> chn;
  };

  static std::optional<int> GetIdAfterPrefix(const char* id_str,
                                             const char* prefix);

  IioDevice() = default;
  IioDevice(const IioDevice&) = delete;
  IioDevice& operator=(const IioDevice&) = delete;

  std::vector<ChannelData> channels_;
  std::vector<std::unique_ptr<IioEvent>> events_;
};

}  // namespace libmems

#endif  // LIBMEMS_IIO_DEVICE_H_
