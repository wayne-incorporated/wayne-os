// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "frontend/gtk/x11.h"

#include <gdk/gdk.h>
#include <glib.h>
#include <glib-unix.h>

#include "backend/wayland_manager.h"

namespace cros_im {
namespace gtk {

namespace {

// Returns whether check() needs to be called
gboolean FlushRequests(GSource* base, int* timeout) {
  WaylandManager::Get()->FlushRequests();
  return false;
}

GSourceFuncs kSourceFuncs = {FlushRequests, nullptr, nullptr, nullptr};

}  // namespace

gboolean DispatchEvents(int fd, GIOCondition condition, void* user_data) {
  WaylandManager::Get()->DispatchEvents();
  return true;
}

bool SetUpWaylandForX11() {
  if (!WaylandManager::CreateX11Instance(
          gdk_display_get_name(gdk_display_get_default()))) {
    return false;
  }

  // Similar to gdk/wayland/gdkeventsource.c, this will trigger a call to
  // |FlushRequests()| on main loop iterations (aka when there might be
  // requests to flush).
  GSource* source = g_source_new(&kSourceFuncs, sizeof(GSource));
  g_source_set_name(source, "cros_im Wayland event source");
  g_source_set_priority(source, GDK_PRIORITY_EVENTS);
  g_source_attach(source, nullptr);

  // Monitor the Wayland socket for events from the host.
  g_unix_fd_add(WaylandManager::Get()->GetFd(), G_IO_IN, &DispatchEvents,
                nullptr);

  // Process any already-queued events immediately.
  WaylandManager::Get()->DispatchEvents();

  return true;
}

}  // namespace gtk
}  // namespace cros_im
