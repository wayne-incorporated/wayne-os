// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SOMMELIER_XCB_XCB_SHIM_H_
#define VM_TOOLS_SOMMELIER_XCB_XCB_SHIM_H_

#include <xcb/xcb.h>

class XcbShim {
 public:
  XcbShim() = default;
  XcbShim(XcbShim&&) = delete;
  XcbShim& operator=(XcbShim&&) = delete;

  virtual ~XcbShim() = default;

  virtual xcb_connection_t* connect(const char* displayname, int* screenp);
  virtual xcb_void_cookie_t configure_window(xcb_connection_t* c,
                                             xcb_window_t window,
                                             uint16_t value_mask,
                                             const void* value_list);
  virtual xcb_void_cookie_t change_property(xcb_connection_t* c,
                                            uint8_t mode,
                                            xcb_window_t window,
                                            xcb_atom_t property,
                                            xcb_atom_t type,
                                            uint8_t format,
                                            uint32_t data_len,
                                            const void* data);
  virtual xcb_void_cookie_t send_event(xcb_connection_t* c,
                                       uint8_t propagate,
                                       xcb_window_t destination,
                                       uint32_t event_mask,
                                       const char* event);
  virtual xcb_void_cookie_t change_window_attributes(xcb_connection_t* c,
                                                     xcb_window_t window,
                                                     uint32_t value_mask,
                                                     const void* value_list);
};

XcbShim* xcb();
void set_xcb_shim(XcbShim* shim);

#endif  // VM_TOOLS_SOMMELIER_XCB_XCB_SHIM_H_
