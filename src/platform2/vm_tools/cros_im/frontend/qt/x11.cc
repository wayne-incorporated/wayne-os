// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <X11/Xlib.h>

#include "frontend/qt/x11.h"

namespace cros_im {
namespace qt {

char* DisplayName(void* display) {
  // This need to be in a separate cc file due to including Xlib will cause Qt
  // fail to compile
  return DisplayString(display);
}

}  // namespace qt
}  // namespace cros_im
