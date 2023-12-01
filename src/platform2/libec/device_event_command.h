// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_DEVICE_EVENT_COMMAND_H_
#define LIBEC_DEVICE_EVENT_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT DeviceEventCommand
    : public EcCommand<struct ec_params_device_event,
                       struct ec_response_device_event> {
 public:
  explicit DeviceEventCommand(bool clear_pending_events);
  explicit DeviceEventCommand(enum ec_device_event event,
                              bool enable,
                              uint32_t cur_event_mask);
  ~DeviceEventCommand() override = default;

  bool IsEnabled(enum ec_device_event event) const;
  uint32_t GetMask() const;
};

static_assert(!std::is_copy_constructible<DeviceEventCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<DeviceEventCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_DEVICE_EVENT_COMMAND_H_
