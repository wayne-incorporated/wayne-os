// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SOMMELIER_XCB_MOCK_XCB_SHIM_H_
#define VM_TOOLS_SOMMELIER_XCB_MOCK_XCB_SHIM_H_

#include <gmock/gmock.h>

#include "xcb-shim.h"  // NOLINT(build/include_directory)

class MockXcbShim : public XcbShim {
 public:
  MOCK_METHOD(xcb_connection_t*,
              connect,
              (const char* displayname, int* screenp),
              (override));

  MOCK_METHOD(xcb_void_cookie_t,
              configure_window,
              (xcb_connection_t * c,
               xcb_window_t window,
               uint16_t value_mask,
               const void* value_list),
              (override));

  MOCK_METHOD(xcb_void_cookie_t,
              change_property,
              (xcb_connection_t * c,
               uint8_t mode,
               xcb_window_t window,
               xcb_atom_t property,
               xcb_atom_t type,
               uint8_t format,
               uint32_t data_len,
               const void* data),
              (override));

  MOCK_METHOD(xcb_void_cookie_t,
              send_event,
              (xcb_connection_t * c,
               uint8_t propagate,
               xcb_window_t destination,
               uint32_t event_mask,
               const char* event),
              (override));

  MOCK_METHOD(xcb_void_cookie_t,
              change_window_attributes,
              (xcb_connection_t * c,
               xcb_window_t window,
               uint32_t value_mask,
               const void* value_list),
              (override));
};

#endif  // VM_TOOLS_SOMMELIER_XCB_MOCK_XCB_SHIM_H_
