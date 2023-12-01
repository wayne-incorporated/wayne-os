// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/test/mock_wayland_client.h"

const wl_interface wl_seat_interface = {};

// Functions for X11 integrations

// TODO(timloh): This is technically enough to run the GTK tests under X11, but
// it would be nice to actually test the code in gtk/x11.cc for integrating with
// the main event loop.
wl_display* wl_display_connect(const char* name) {
  static wl_display display;
  return &display;
}
int wl_display_get_fd(wl_display* display) {
  return 0;
}
int wl_display_flush(wl_display* display) {
  return 0;
}
int wl_display_dispatch(wl_display* display) {
  return 0;
}
void wl_display_disconnect(wl_display* display) {}

wl_registry* wl_display_get_registry(wl_display*) {
  return nullptr;
}

void wl_registry_add_listener(wl_registry* registry,
                              const wl_registry_listener* listener,
                              void* data) {
  listener->global(data, registry, /*name=*/0, "wl_seat",
                   /*version=*/5);
  listener->global(data, registry, /*name=*/0, "zwp_text_input_manager_v1",
                   /*version=*/1);
  listener->global(data, registry, /*name=*/0, "zcr_text_input_extension_v1",
                   /*version=*/9);
  listener->global(data, registry, /*name=*/0, "zcr_text_input_x11_v1",
                   /*version=*/1);
}

void* wl_registry_bind(wl_registry* wl_registry,
                       uint32_t name,
                       const wl_interface* interface,
                       uint32_t version) {
  // Return a non-null void*. This is called for a few different globals and
  // an actual implementation wouldn't return the same value twice, but this is
  // currently sufficient for our mock.
  static int object;
  return &object;
}
