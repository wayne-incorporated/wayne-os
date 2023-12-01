// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_IIO_DEVICE_TRIGGER_IMPL_H_
#define LIBMEMS_IIO_DEVICE_TRIGGER_IMPL_H_

#include <iio.h>

#include <optional>
#include <string>
#include <vector>

#include "libmems/export.h"
#include "libmems/iio_device.h"

namespace libmems {

class IioChannel;
class IioContext;
class IioContextImpl;

class LIBMEMS_EXPORT IioDeviceTriggerImpl : public IioDevice {
 public:
  // Return -1 for iio_sysfs_trigger
  static std::optional<int> GetIdFromString(const char* id_str);
  // Return iio_sysfs_trigger for -1
  static std::string GetStringFromId(int id);

  // iio_device objects are kept alive by the IioContextImpl.
  IioDeviceTriggerImpl(IioContextImpl* ctx, iio_device* dev);
  IioDeviceTriggerImpl(const IioDeviceTriggerImpl&) = delete;
  IioDeviceTriggerImpl& operator=(const IioDeviceTriggerImpl&) = delete;

  ~IioDeviceTriggerImpl() override = default;

  IioContext* GetContext() const override;

  const char* GetName() const override;
  // Return -1 for iio_sysfs_trigger
  int GetId() const override;

  base::FilePath GetPath() const override;

  std::optional<std::string> ReadStringAttribute(
      const std::string& name) const override;
  std::optional<int64_t> ReadNumberAttribute(
      const std::string& name) const override;
  std::optional<double> ReadDoubleAttribute(
      const std::string& name) const override;

  bool WriteStringAttribute(const std::string& name,
                            const std::string& value) override {
    return false;
  }
  bool WriteNumberAttribute(const std::string& name, int64_t value) override;
  bool WriteDoubleAttribute(const std::string& name, double value) override;

  bool HasFifo() const override { return false; }

  iio_device* GetUnderlyingIioDevice() const override { return nullptr; }

  bool SetTrigger(IioDevice* trigger_device) override { return false; }
  IioDevice* GetTrigger() override { return nullptr; }
  IioDevice* GetHrtimer() override { return nullptr; }

  std::optional<size_t> GetSampleSize() const override { return std::nullopt; }

  bool EnableBuffer(size_t num) override { return false; }
  bool DisableBuffer() override { return false; }
  bool IsBufferEnabled(size_t* num = nullptr) const override { return false; }

  bool CreateBuffer() override { return false; }
  std::optional<int32_t> GetBufferFd() override { return std::nullopt; }
  std::optional<IioSample> ReadSample() override { return std::nullopt; }
  void FreeBuffer() override {}

  std::optional<int32_t> GetEventFd() override { return std::nullopt; }
  std::optional<iio_event_data> ReadEvent() override { return std::nullopt; }

 private:
  IioContextImpl* context_;    // non-owned
  iio_device* const trigger_;  // non-owned

  std::string log_prefix_;
};

}  // namespace libmems

#endif  // LIBMEMS_IIO_DEVICE_TRIGGER_IMPL_H_
