// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_FRONTEND_GTK_X11_H_
#define VM_TOOLS_CROS_IM_FRONTEND_GTK_X11_H_

namespace cros_im {
namespace gtk {

// We use the text_input Wayland protocol to support IMEs regardless of whether
// a GTK application is running under Wayland or X11. In the latter case, this
// function is used to set up a Wayland connection and add the relevant event
// handling to the application's main loop.
bool SetUpWaylandForX11();

}  // namespace gtk
}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_FRONTEND_GTK_X11_H_
