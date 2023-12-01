// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SOMMELIER_TESTING_SOMMELIER_TEST_UTIL_H_
#define VM_TOOLS_SOMMELIER_TESTING_SOMMELIER_TEST_UTIL_H_

#include <gtest/gtest.h>
#include <wayland-server.h>

#include "../sommelier.h"                // NOLINT(build/include_directory)
#include "aura-shell-client-protocol.h"  // NOLINT(build/include_directory)
#include "gaming-input-unstable-v2-client-protocol.h"  // NOLINT(build/include_directory)
#include "viewporter-client-protocol.h"  // NOLINT(build/include_directory)
#include "xdg-output-unstable-v1-client-protocol.h"  // NOLINT(build/include_directory)
#include "xdg-shell-client-protocol.h"  // NOLINT(build/include_directory)

// Maps a wayland object to its listener struct.
template <typename WaylandType>
struct WlToListener;

#define MAP_STRUCT_TO_LISTENER(WlType, Listener) \
  template <>                                    \
  struct WlToListener<WlType> {                  \
    using type = Listener;                       \
  };

MAP_STRUCT_TO_LISTENER(xdg_wm_base*, xdg_wm_base_listener);
MAP_STRUCT_TO_LISTENER(xdg_surface*, xdg_surface_listener);
MAP_STRUCT_TO_LISTENER(xdg_toplevel*, xdg_toplevel_listener);
MAP_STRUCT_TO_LISTENER(wl_output*, wl_output_listener);
MAP_STRUCT_TO_LISTENER(wl_callback*, wl_callback_listener);
MAP_STRUCT_TO_LISTENER(wl_surface*, wl_surface_listener);
MAP_STRUCT_TO_LISTENER(zaura_output*, zaura_output_listener);
MAP_STRUCT_TO_LISTENER(zaura_toplevel*, zaura_toplevel_listener);
MAP_STRUCT_TO_LISTENER(zxdg_output_v1*, zxdg_output_v1_listener);
MAP_STRUCT_TO_LISTENER(zcr_gaming_seat_v2*, zcr_gaming_seat_v2_listener);
MAP_STRUCT_TO_LISTENER(zcr_gamepad_v2*, zcr_gamepad_v2_listener);

namespace vm_tools {
namespace sommelier {

// This function retrieves Sommelier's listeners for events received
// from the host, so we can call them directly in the test rather than
// (a) exporting the actual functions (which are typically static), or (b)
// creating a fake host compositor to dispatch events via libwayland
// (unnecessarily complicated).
template <typename T>
const typename WlToListener<T>::type* HostEventHandler(T proxy) {
  const void* listener =
      wl_proxy_get_listener(reinterpret_cast<wl_proxy*>(proxy));
  EXPECT_NE(listener, nullptr);
  return static_cast<const typename WlToListener<T>::type*>(listener);
}

uint32_t XdgToplevelId(sl_window* window);
uint32_t AuraSurfaceId(sl_window* window);
uint32_t AuraToplevelId(sl_window* window);
uint32_t SurfaceId(wl_surface* wl_surface);

}  // namespace sommelier
}  // namespace vm_tools

#endif  // VM_TOOLS_SOMMELIER_TESTING_SOMMELIER_TEST_UTIL_H_
