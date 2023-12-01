// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gdk/gdkwayland.h>
#include <gdk/gdkx.h>
// Remove definitions from X11 headers that collide with our code.
#undef FocusIn
#undef FocusOut
#include <gtk/gtk.h>

#include "backend/wayland_manager.h"
#include "frontend/gtk/cros_gtk_im_context.h"
#include "frontend/gtk/x11.h"

// This file defines the functions required to wire up a GTK IM module.

namespace cros_im {
namespace gtk {

namespace {

// We want to be able to control rollout with a Chrome flag so we set
// default_locales to "" and have garcon enable us via GTK_IM_MODULE when the
// flag is set.
#ifdef TEST_BACKEND
const GtkIMContextInfo kContextInfo = {
    "test-cros", "Test ChromeOS IME bridge", "test-cros", "/usr/share/locale",
    "",
};
#else
const GtkIMContextInfo kContextInfo = {
    "cros", "ChromeOS IME bridge", "cros", "/usr/share/locale", "",
};
#endif

const GtkIMContextInfo* kContextInfoList[] = {&kContextInfo};

}  // namespace

extern "C" {

void im_module_list(const GtkIMContextInfo*** contexts, unsigned* n_contexts) {
  *n_contexts = 1;
  *contexts = kContextInfoList;
}

void im_module_init(GTypeModule* module) {
  g_type_module_use(module);

  GdkDisplay* gdk_display = gdk_display_get_default();
  if (!gdk_display) {
    g_warning("GdkDisplay wasn't found");
    return;
  }
  if (GDK_IS_X11_DISPLAY(gdk_display)) {
    if (!SetUpWaylandForX11())
      return;
  } else if (GDK_IS_WAYLAND_DISPLAY(gdk_display)) {
    WaylandManager::CreateInstance(
        gdk_wayland_display_get_wl_display(gdk_display));
  } else {
    g_warning("Unknown GdkDisplay type");
    return;
  }

  CrosGtkIMContext::RegisterType(module);
}

void im_module_exit() {}

GtkIMContext* im_module_create(const char* context_id) {
  g_assert_cmpstr(context_id, ==, kContextInfo.context_id);
  return CrosGtkIMContext::Create();
}

}  // extern "C"

}  // namespace gtk
}  // namespace cros_im
