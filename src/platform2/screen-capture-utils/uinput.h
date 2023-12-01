// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SCREEN_CAPTURE_UTILS_UINPUT_H_
#define SCREEN_CAPTURE_UTILS_UINPUT_H_

#include <memory>

#include <rfb/rfb.h>

namespace screenshot {

// Convert keysym to scancode.
int KeySymToScancode(rfbKeySym key);

// Manager of uinput devices. Implementation hidden in UinputImpl to avoid
// dependencies in header.
class Uinput {
 public:
  // Creates a new instance, sets up uinput devices, and routes input events
  // from the server to the newly created devices.
  // Only one instance can be alive at a time, since libvncserver only accepts
  // plain function pointers for input event callbacks, meaning the callback is
  // static and we cannot simply attach a particular Uinput instance to a server
  // instance.
  static std::unique_ptr<Uinput> Create(rfbScreenInfoPtr server);

  Uinput(const Uinput&) = delete;
  Uinput& operator=(const Uinput&) = delete;

  // Existing uinput devices are destroyed upon destruction.
  virtual ~Uinput() = default;

 protected:
  Uinput() = default;
};

}  // namespace screenshot

#endif  // SCREEN_CAPTURE_UTILS_UINPUT_H_
