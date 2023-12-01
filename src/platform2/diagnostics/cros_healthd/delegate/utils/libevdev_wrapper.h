// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_LIBEVDEV_WRAPPER_H_
#define DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_LIBEVDEV_WRAPPER_H_

#include <linux/input.h>
#include <string>

namespace diagnostics {

// An thin interface to access |struct libevdev|.
class LibevdevWrapper {
 public:
  virtual ~LibevdevWrapper() = default;

  // Wrapper of |libevdev_has_property|.
  virtual bool HasProperty(unsigned int prop) = 0;
  // Wrapper of |libevdev_has_event_type|.
  virtual bool HasEventType(unsigned int type) = 0;
  // Wrapper of |libevdev_has_event_code|.
  virtual bool HasEventCode(unsigned int type, unsigned int code) = 0;
  // Wrapper of |libevdev_get_name|.
  virtual std::string GetName() = 0;
  // Wrapper of |libevdev_get_id_bustype|.
  virtual int GetIdBustype() = 0;
  // Wrapper of |libevdev_get_abs_maximum|.
  virtual int GetAbsMaximum(unsigned int code) = 0;
  // Wrapper of |libevdev_get_event_value|.
  virtual int GetEventValue(unsigned int type, unsigned int code) = 0;
  // Wrapper of |libevdev_get_num_slots|.
  virtual int GetNumSlots() = 0;
  // Wrapper of |libevdev_fetch_slot_value|.
  virtual int FetchSlotValue(unsigned int slot,
                             unsigned int code,
                             int* value) = 0;
  // Wrapper of |libevdev_next_event|.
  virtual int NextEvent(unsigned int flags, input_event* ev) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_LIBEVDEV_WRAPPER_H_
