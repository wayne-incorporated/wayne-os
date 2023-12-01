// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "xcb-shim.h"  // NOLINT(build/include_directory)
#include <xcb/xproto.h>

xcb_connection_t* XcbShim::connect(const char* displayname, int* screenp) {
  return xcb_connect(displayname, screenp);
}

xcb_void_cookie_t XcbShim::configure_window(xcb_connection_t* c,
                                            xcb_window_t window,
                                            uint16_t value_mask,
                                            const void* value_list) {
  return xcb_configure_window(c, window, value_mask, value_list);
}

xcb_void_cookie_t XcbShim::change_property(xcb_connection_t* c,
                                           uint8_t mode,
                                           xcb_window_t window,
                                           xcb_atom_t property,
                                           xcb_atom_t type,
                                           uint8_t format,
                                           uint32_t data_len,
                                           const void* data) {
  return xcb_change_property(c, mode, window, property, type, format, data_len,
                             data);
}

xcb_void_cookie_t XcbShim::send_event(xcb_connection_t* c,
                                      uint8_t propagate,
                                      xcb_window_t destination,
                                      uint32_t event_mask,
                                      const char* event) {
  return xcb_send_event(c, propagate, destination, event_mask, event);
}

xcb_void_cookie_t XcbShim::change_window_attributes(xcb_connection_t* c,
                                                    xcb_window_t window,
                                                    uint32_t value_mask,
                                                    const void* value_list) {
  return xcb_change_window_attributes(c, window, value_mask, value_list);
}

static XcbShim* xcb_singleton = nullptr;

XcbShim* xcb() {
  return xcb_singleton;
}

void set_xcb_shim(XcbShim* shim) {
  xcb_singleton = shim;
}
