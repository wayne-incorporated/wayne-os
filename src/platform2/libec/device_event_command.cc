// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/device_event_command.h"

namespace ec {

DeviceEventCommand::DeviceEventCommand(bool clear_pending_events)
    : EcCommand(EC_CMD_DEVICE_EVENT) {
  if (clear_pending_events) {
    Req()->param = EC_DEVICE_EVENT_PARAM_GET_CURRENT_EVENTS;
  } else {
    Req()->param = EC_DEVICE_EVENT_PARAM_GET_ENABLED_EVENTS;
  }
}

DeviceEventCommand::DeviceEventCommand(enum ec_device_event event,
                                       bool enable,
                                       uint32_t cur_event_mask)
    : EcCommand(EC_CMD_DEVICE_EVENT) {
  Req()->param = EC_DEVICE_EVENT_PARAM_SET_ENABLED_EVENTS;
  if (enable) {
    Req()->event_mask = cur_event_mask | EC_DEVICE_EVENT_MASK(event);
  } else {
    Req()->event_mask = cur_event_mask & ~EC_DEVICE_EVENT_MASK(event);
  }
}

bool DeviceEventCommand::IsEnabled(enum ec_device_event event) const {
  return Resp()->event_mask & EC_DEVICE_EVENT_MASK(event);
}

uint32_t DeviceEventCommand::GetMask() const {
  return Resp()->event_mask;
}

}  // namespace ec
