// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_TEST_MOCK_WAYLAND_CLIENT_H_
#define VM_TOOLS_CROS_IM_BACKEND_TEST_MOCK_WAYLAND_CLIENT_H_

#include <cstddef>
#include <cstdint>

// This file provides mock implementations of the APIs normally defined and
// implemented in wayland-client.h and wayland-client-protocol.h.

struct wl_display {};
struct wl_registry;
struct zwp_text_input_v1;

struct wl_interface {};

enum wl_keyboard_key_state {
  WL_KEYBOARD_KEY_STATE_RELEASED = 0,
  WL_KEYBOARD_KEY_STATE_PRESSED = 1,
};

struct wl_registry_listener {
  void (*global)(void*,
                 wl_registry*,
                 uint32_t name,
                 const char* interface,
                 uint32_t version);
  void (*global_remove)(void*, wl_registry*, uint32_t name);
};

// Functions for X11 integrations
wl_display* wl_display_connect(const char* name);
int wl_display_get_fd(wl_display* display);
int wl_display_flush(wl_display* display);
int wl_display_dispatch(wl_display* display);
void wl_display_disconnect(wl_display* display);

wl_registry* wl_display_get_registry(wl_display*);

void wl_registry_add_listener(wl_registry*, const wl_registry_listener*, void*);

void* wl_registry_bind(wl_registry* wl_registry,
                       uint32_t name,
                       const wl_interface* interface,
                       uint32_t version);

extern const wl_interface wl_seat_interface;

#endif  // VM_TOOLS_CROS_IM_BACKEND_TEST_MOCK_WAYLAND_CLIENT_H_
