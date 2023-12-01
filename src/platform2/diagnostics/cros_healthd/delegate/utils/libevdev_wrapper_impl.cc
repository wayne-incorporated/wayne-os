// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/delegate/utils/libevdev_wrapper_impl.h"

#include <libevdev/libevdev.h>
#include <memory>
#include <string>

#include <base/check.h>
#include <base/memory/ptr_util.h>

namespace diagnostics {

std::unique_ptr<LibevdevWrapper> LibevdevWrapperImpl::Create(int fd) {
  auto dev_ptr = base::WrapUnique(new LibevdevWrapperImpl(libevdev_new()));
  int rc = libevdev_set_fd(dev_ptr->dev_, fd);
  if (rc < 0) {
    return nullptr;
  }
  return dev_ptr;
}

LibevdevWrapperImpl::LibevdevWrapperImpl(libevdev* dev) : dev_(dev) {
  CHECK(dev_);
}

LibevdevWrapperImpl::~LibevdevWrapperImpl() {
  libevdev_free(dev_);
}

bool LibevdevWrapperImpl::HasProperty(unsigned int prop) {
  return libevdev_has_property(dev_, prop);
}

bool LibevdevWrapperImpl::HasEventType(unsigned int type) {
  return libevdev_has_event_type(dev_, type);
}

bool LibevdevWrapperImpl::HasEventCode(unsigned int type, unsigned int code) {
  return libevdev_has_event_code(dev_, type, code);
}

std::string LibevdevWrapperImpl::GetName() {
  return std::string(libevdev_get_name(dev_));
}

int LibevdevWrapperImpl::GetIdBustype() {
  return libevdev_get_id_bustype(dev_);
}

int LibevdevWrapperImpl::GetAbsMaximum(unsigned int code) {
  return libevdev_get_abs_maximum(dev_, code);
}

int LibevdevWrapperImpl::GetEventValue(unsigned int type, unsigned int code) {
  return libevdev_get_event_value(dev_, type, code);
}

int LibevdevWrapperImpl::GetNumSlots() {
  return libevdev_get_num_slots(dev_);
}

int LibevdevWrapperImpl::FetchSlotValue(unsigned int slot,
                                        unsigned int code,
                                        int* value) {
  return libevdev_fetch_slot_value(dev_, slot, code, value);
}

int LibevdevWrapperImpl::NextEvent(unsigned int flags, input_event* ev) {
  return libevdev_next_event(dev_, flags, ev);
}

}  // namespace diagnostics
