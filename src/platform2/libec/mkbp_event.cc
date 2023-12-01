// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/mkbp_event.h"

#include <poll.h>
#include <sys/ioctl.h>

#include <base/posix/eintr_wrapper.h>
#include <chromeos/ec/cros_ec_dev.h>

namespace ec {

MkbpEvent::MkbpEvent(int fd, enum ec_mkbp_event event_type)
    : fd_(fd), event_type_(event_type) {}

int MkbpEvent::Enable() {
  return HANDLE_EINTR(
      ioctl(fd_, CROS_EC_DEV_IOCEVENTMASK_V2, 1 << event_type_));
}

int MkbpEvent::Wait(int timeout) {
  struct pollfd pf = {.fd = fd_, .events = POLLIN};

  int rv = poll(&pf, 1, timeout);
  if (rv != 1)
    return rv;

  if (pf.revents != POLLIN)
    return -pf.revents;

  return rv;
}

}  // namespace ec
