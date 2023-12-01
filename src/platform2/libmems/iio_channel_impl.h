// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_IIO_CHANNEL_IMPL_H_
#define LIBMEMS_IIO_CHANNEL_IMPL_H_

#include <iio.h>

#include <memory>
#include <optional>
#include <string>

#include "libmems/export.h"
#include "libmems/iio_channel.h"

namespace libmems {

class IioDevice;

class LIBMEMS_EXPORT IioChannelImpl : public IioChannel {
 public:
  // iio_channel objects are kept alive by the IioContextImpl.
  IioChannelImpl(iio_channel* channel, int device_id, const char* device_name);
  IioChannelImpl(const IioChannelImpl&) = delete;
  IioChannelImpl& operator=(const IioChannelImpl&) = delete;

  ~IioChannelImpl() override = default;

  const char* GetId() const override;

  bool IsEnabled() const override;
  void SetEnabled(bool en) override;

  bool SetScanElementsEnabled(bool en) override;

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

  std::optional<int64_t> Convert(const uint8_t* src) const;
  std::optional<uint64_t> Length() const;

 private:
  iio_channel* const channel_;  // non-owned

  std::string log_prefix_;
};

}  // namespace libmems

#endif  // LIBMEMS_IIO_CHANNEL_IMPL_H_
