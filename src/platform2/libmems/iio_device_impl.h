// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_IIO_DEVICE_IMPL_H_
#define LIBMEMS_IIO_DEVICE_IMPL_H_

#include <iio.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "libmems/export.h"
#include "libmems/iio_device.h"

namespace libmems {

class IioChannelImpl;
class IioContext;
class IioContextImpl;

class LIBMEMS_EXPORT IioDeviceImpl : public IioDevice {
 public:
  static std::optional<int> GetIdFromString(const char* id_str);
  static std::string GetStringFromId(int id);

  // iio_device objects are kept alive by the IioContextImpl.
  IioDeviceImpl(IioContextImpl* ctx, iio_device* dev);
  IioDeviceImpl(const IioDeviceImpl&) = delete;
  IioDeviceImpl& operator=(const IioDeviceImpl&) = delete;

  ~IioDeviceImpl() override = default;

  IioContext* GetContext() const override;

  const char* GetName() const override;
  int GetId() const override;

  base::FilePath GetPath() const override;

  std::optional<std::string> ReadStringAttribute(
      const std::string& name) const override;
  std::optional<int64_t> ReadNumberAttribute(
      const std::string& name) const override;
  std::optional<double> ReadDoubleAttribute(
      const std::string& name) const override;

  bool WriteStringAttribute(const std::string& name,
                            const std::string& value) override;
  bool WriteNumberAttribute(const std::string& name, int64_t value) override;
  bool WriteDoubleAttribute(const std::string& name, double value) override;

  bool HasFifo() const override;

  iio_device* GetUnderlyingIioDevice() const override;

  bool SetTrigger(IioDevice* trigger_device) override;
  IioDevice* GetTrigger() override;
  IioDevice* GetHrtimer() override;

  std::optional<size_t> GetSampleSize() const override;

  bool EnableBuffer(size_t num) override;
  bool DisableBuffer() override;
  bool IsBufferEnabled(size_t* num = nullptr) const override;

  bool CreateBuffer() override;
  std::optional<int32_t> GetBufferFd() override;
  std::optional<IioSample> ReadSample() override;
  void FreeBuffer() override;

  std::optional<int32_t> GetEventFd() override;
  std::optional<iio_event_data> ReadEvent() override;

 private:
  static void IioBufferDeleter(iio_buffer* buffer);

  IioSample DeserializeSample(const uint8_t* src);

  IioContextImpl* context_;   // non-owned
  iio_device* const device_;  // non-owned

  IioDevice* hrtimer_ = nullptr;

  using ScopedBuffer = std::unique_ptr<iio_buffer, decltype(&IioBufferDeleter)>;
  ScopedBuffer buffer_;
  std::optional<int32_t> event_fd_;

  std::string log_prefix_;
};

}  // namespace libmems

#endif  // LIBMEMS_IIO_DEVICE_IMPL_H_
