// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_IIO_EVENT_IMPL_H_
#define LIBMEMS_IIO_EVENT_IMPL_H_

#include <memory>
#include <optional>
#include <string>

#include <base/files/file_path.h>

#include "libmems/export.h"
#include "libmems/iio_event.h"

namespace libmems {

class LIBMEMS_EXPORT IioEventImpl : public IioEvent {
 public:
  // in_[chan_type][channel]_[event_type]_[direction]_en.
  static std::unique_ptr<IioEventImpl> Create(base::FilePath file);

  IioEventImpl(const IioEventImpl&) = delete;
  IioEventImpl& operator=(const IioEventImpl&) = delete;
  ~IioEventImpl() override = default;

  // IioEvent overrides.
  bool IsEnabled() const override;
  void SetEnabled(bool en) override;
  std::optional<std::string> ReadStringAttribute(
      const std::string& name) const override;
  bool WriteStringAttribute(const std::string& name,
                            const std::string& value) override;

 private:
  IioEventImpl(base::FilePath event_dir,
               std::string event_pattern,
               iio_chan_type chan_type,
               iio_event_type event_type,
               iio_event_direction direction,
               int channel);

  base::FilePath GetAttributePath(const std::string& attribute) const;

  // /sys/bus/iio/devices/iio:deviceX/events/.
  base::FilePath event_dir_;
  // Ex: "in_proximity0_thresh_either_%s".
  std::string event_pattern_;
};

}  // namespace libmems

#endif  // LIBMEMS_IIO_EVENT_IMPL_H_
