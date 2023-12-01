// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_MKBP_EVENT_H_
#define LIBEC_MKBP_EVENT_H_

#include <brillo/brillo_export.h>
#include <chromeos/ec/ec_commands.h>

namespace ec {

// A normal flow should be:
//   1. Create |MkbpEvent| object.
//   2. Call |Enable| to enable the event.
//   3. Do something that would trigger the event.
//   4. Call sync method |Wait|, this is blocked until the event is fired.
class BRILLO_EXPORT MkbpEvent {
 public:
  MkbpEvent(int fd, enum ec_mkbp_event event_type);
  ~MkbpEvent() = default;

  // The return value is the same as ioctl.
  int Enable();

  // This is a blocking function, it'll wait until timeout.
  // The return value of only successful case is 1.
  int Wait(int timeout);

 private:
  int fd_;
  enum ec_mkbp_event event_type_;
};

}  // namespace ec

#endif  // LIBEC_MKBP_EVENT_H_
