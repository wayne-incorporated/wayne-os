// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// RAII wrappers for GLib types.

#ifndef GLIB_BRIDGE_GLIB_SCOPERS_H_
#define GLIB_BRIDGE_GLIB_SCOPERS_H_

#include <glib.h>

#include <memory>

namespace glib_bridge {

template <typename T>
struct GObjectUnref {
  void operator()(T* obj) {
    if (obj)
      g_object_unref(obj);
  }
};

template <typename T>
using ScopedGObject = std::unique_ptr<T, GObjectUnref<T>>;

}  // namespace glib_bridge

#endif  // GLIB_BRIDGE_GLIB_SCOPERS_H_
