// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sommelier-test-util.h"  // NOLINT(build/include_directory)

#include <gtest/gtest.h>

namespace vm_tools {
namespace sommelier {

uint32_t XdgToplevelId(sl_window* window) {
  assert(window->xdg_toplevel);
  return wl_proxy_get_id(reinterpret_cast<wl_proxy*>(window->xdg_toplevel));
}

uint32_t AuraSurfaceId(sl_window* window) {
  assert(window->aura_surface);
  return wl_proxy_get_id(reinterpret_cast<wl_proxy*>(window->aura_surface));
}

uint32_t AuraToplevelId(sl_window* window) {
  assert(window->aura_toplevel);
  return wl_proxy_get_id(reinterpret_cast<wl_proxy*>(window->aura_toplevel));
}

uint32_t SurfaceId(wl_surface* wl_surface) {
  assert(wl_surface);
  return wl_proxy_get_id(reinterpret_cast<wl_proxy*>(wl_surface));
}

}  // namespace sommelier
}  // namespace vm_tools
