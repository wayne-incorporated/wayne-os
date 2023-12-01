// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wayland-client.h>
#include <wayland-client-protocol.h>

#include "base/command_line.h"
#include "base/logging.h"
#include "base/memory/writable_shared_memory_region.h"
#include "base/strings/string_number_conversions.h"
#include "brillo/syslog_logging.h"

constexpr char kBgColorFlag[] = "bgcolor";
constexpr char kWidthFlag[] = "width";
constexpr char kHeightFlag[] = "height";
constexpr char kTitleFlag[] = "title";

struct demo_data {
  uint32_t bgcolor;
  uint32_t width;
  uint32_t height;
  std::string title;
  int scale;
  struct wl_compositor* compositor;
  struct wl_shell* shell;
  struct wl_shm* shm;
  struct wl_surface* surface;
  struct wl_shell_surface* shell_surface;
  struct wl_buffer* buffer;
  struct wl_callback* callback;
  struct wl_callback_listener* callback_listener;
  struct wl_output* output;
  struct wl_output_listener* output_listener;
  struct wl_keyboard_listener* keyboard_listener;
  void* shm_ptr;
  bool done;
};

void keyboard_keymap(void* data,
                     struct wl_keyboard* keyboard,
                     uint32_t format,
                     int32_t fd,
                     uint32_t size) {}

void keyboard_enter(void* data,
                    struct wl_keyboard* keyboard,
                    uint32_t serial,
                    struct wl_surface* surface,
                    struct wl_array* keys) {}

void keyboard_leave(void* data,
                    struct wl_keyboard* keyboard,
                    uint32_t serial,
                    struct wl_surface* surface) {}

void keyboard_key(void* data,
                  struct wl_keyboard* keyboard,
                  uint32_t serial,
                  uint32_t time,
                  uint32_t key,
                  uint32_t state) {
  struct demo_data* data_ptr = reinterpret_cast<struct demo_data*>(data);
  // Key pressed.
  if (state == 1) {
    LOG(INFO) << "wayland_demo application detected keypress";
    data_ptr->done = true;
  }
}

void keyboard_modifiers(void* data,
                        struct wl_keyboard* keyboard,
                        uint32_t serial,
                        uint32_t mods_depressed,
                        uint32_t mods_latched,
                        uint32_t mods_locked,
                        uint32_t group) {}

void keyboard_repeat_info(void* data,
                          struct wl_keyboard* keyboard,
                          int32_t rate,
                          int32_t delay) {}

void demo_registry_listener(void* data,
                            struct wl_registry* registry,
                            uint32_t id,
                            const char* interface,
                            uint32_t version) {
  struct demo_data* data_ptr = reinterpret_cast<struct demo_data*>(data);
  if (!strcmp("wl_compositor", interface)) {
    data_ptr->compositor = reinterpret_cast<struct wl_compositor*>(
        wl_registry_bind(registry, id, &wl_compositor_interface, version));
  } else if (!strcmp("wl_shell", interface)) {
    data_ptr->shell = reinterpret_cast<struct wl_shell*>(
        wl_registry_bind(registry, id, &wl_shell_interface, version));
  } else if (!strcmp("wl_shm", interface)) {
    data_ptr->shm = reinterpret_cast<struct wl_shm*>(
        wl_registry_bind(registry, id, &wl_shm_interface, version));
  } else if (!strcmp("wl_output", interface)) {
    data_ptr->output = reinterpret_cast<struct wl_output*>(
        wl_registry_bind(registry, id, &wl_output_interface, version));
    wl_output_add_listener(data_ptr->output, data_ptr->output_listener,
                           data_ptr);
  } else if (!strcmp("wl_seat", interface)) {
    struct wl_seat* seat = reinterpret_cast<struct wl_seat*>(
        wl_registry_bind(registry, id, &wl_seat_interface, version));
    wl_keyboard_add_listener(wl_seat_get_keyboard(seat),
                             data_ptr->keyboard_listener, data_ptr);
  }
}

void demo_registry_remover(void* data,
                           struct wl_registry* registry,
                           uint32_t id) {}

void shell_surface_ping(void* data,
                        struct wl_shell_surface* shell_surface,
                        uint32_t serial) {
  wl_shell_surface_pong(shell_surface, serial);
}

void shell_surface_configure(void* data,
                             struct wl_shell_surface* shell_surface,
                             uint32_t edges,
                             int32_t width,
                             int32_t height) {}

void shell_surface_popup_done(void* data,
                              struct wl_shell_surface* shell_surface) {}

void demo_draw(void* data, struct wl_callback* callback, uint32_t time) {
  struct demo_data* data_ptr = reinterpret_cast<struct demo_data*>(data);
  wl_callback_destroy(data_ptr->callback);
  wl_surface_damage(data_ptr->surface, 0, 0, data_ptr->width, data_ptr->height);
  uint32_t* surface_data = reinterpret_cast<uint32_t*>(data_ptr->shm_ptr);
  for (int i = 0; i < data_ptr->width * data_ptr->height; ++i) {
    surface_data[i] = data_ptr->bgcolor;
  }
  data_ptr->callback = wl_surface_frame(data_ptr->surface);
  wl_surface_attach(data_ptr->surface, data_ptr->buffer, 0, 0);
  wl_callback_add_listener(data_ptr->callback, data_ptr->callback_listener,
                           data_ptr);
  wl_surface_commit(data_ptr->surface);
}

void output_geometry(void* data,
                     struct wl_output* output,
                     int32_t x,
                     int32_t y,
                     int32_t physical_width,
                     int32_t physical_height,
                     int32_t subpixel,
                     const char* make,
                     const char* model,
                     int32_t transform) {}

void output_mode(void* data,
                 struct wl_output* output,
                 uint32_t flags,
                 int32_t width,
                 int32_t height,
                 int32_t refresh) {
  struct demo_data* data_ptr = reinterpret_cast<struct demo_data*>(data);
  if (data_ptr->width == 0) {
    data_ptr->width = width;
    if (data_ptr->scale != 0) {
      data_ptr->width /= data_ptr->scale;
    }
  }
  if (data_ptr->height == 0) {
    data_ptr->height = height;
    if (data_ptr->scale != 0) {
      data_ptr->height /= data_ptr->scale;
    }
  }
}

void output_done(void* data, struct wl_output* output) {}

void output_scale(void* data, struct wl_output* output, int32_t factor) {
  struct demo_data* data_ptr = reinterpret_cast<struct demo_data*>(data);
  data_ptr->scale = factor;
  if (data_ptr->width != 0) {
    data_ptr->width /= factor;
  }
  if (data_ptr->height != 0) {
    data_ptr->height /= factor;
  }
}

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog);
  LOG(INFO) << "Starting wayland_demo application";

  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  struct demo_data data;
  memset(&data, 0, sizeof(data));
  data.done = false;

  data.bgcolor = 0x3388DD;
  if (cl->HasSwitch(kBgColorFlag)) {
    data.bgcolor =
        strtoul(cl->GetSwitchValueASCII(kBgColorFlag).c_str(), nullptr, 0);
  }
  if (cl->HasSwitch(kWidthFlag)) {
    if (!base::StringToUint(cl->GetSwitchValueASCII(kWidthFlag), &data.width)) {
      LOG(ERROR) << "Invalid width parameter passed";
      return -1;
    }
  }
  if (cl->HasSwitch(kHeightFlag)) {
    if (!base::StringToUint(cl->GetSwitchValueASCII(kHeightFlag),
                            &data.height)) {
      LOG(ERROR) << "Invalid height parameter passed";
      return -1;
    }
  }
  data.title = "wayland_demo";
  if (cl->HasSwitch(kTitleFlag)) {
    data.title = cl->GetSwitchValueASCII(kTitleFlag);
  }

  struct wl_display* display = wl_display_connect(nullptr);
  if (!display) {
    LOG(ERROR) << "Failed connecting to display";
    return -1;
  }

  struct wl_output_listener output_listener = {output_geometry, output_mode,
                                               output_done, output_scale};
  data.output_listener = &output_listener;
  struct wl_registry_listener registry_listener = {
      demo_registry_listener,
      demo_registry_remover,
  };
  struct wl_keyboard_listener keyboard_listener = {
      keyboard_keymap, keyboard_enter,     keyboard_leave,
      keyboard_key,    keyboard_modifiers, keyboard_repeat_info};
  data.keyboard_listener = &keyboard_listener;

  struct wl_registry* registry = wl_display_get_registry(display);
  wl_registry_add_listener(registry, &registry_listener, &data);

  wl_display_dispatch(display);
  wl_display_roundtrip(display);

  if (!data.compositor) {
    LOG(ERROR) << "Failed to find compositor";
    return -1;
  }
  if (!data.output) {
    LOG(ERROR) << "Failed to get output";
    return -1;
  }

  // Do another roundtrip to ensure we get the wl_output callbacks.
  wl_display_roundtrip(display);

  data.surface = wl_compositor_create_surface(data.compositor);
  if (!data.surface) {
    LOG(ERROR) << "Failed creating surface";
    return -1;
  }
  if (!data.shell) {
    LOG(ERROR) << "Failed getting shell";
    return -1;
  }

  data.shell_surface = wl_shell_get_shell_surface(data.shell, data.surface);
  if (!data.shell_surface) {
    LOG(ERROR) << "Failed getting shell surface";
    return -1;
  }
  const struct wl_shell_surface_listener shell_surface_listener = {
      shell_surface_ping, shell_surface_configure, shell_surface_popup_done};
  wl_shell_surface_add_listener(data.shell_surface, &shell_surface_listener,
                                nullptr);

  wl_shell_surface_set_toplevel(data.shell_surface);
  wl_shell_surface_set_class(data.shell_surface, data.title.c_str());
  wl_shell_surface_set_title(data.shell_surface, data.title.c_str());
  data.callback = wl_surface_frame(data.surface);
  struct wl_callback_listener callback_listener = {demo_draw};
  data.callback_listener = &callback_listener;
  wl_callback_add_listener(data.callback, data.callback_listener, &data);

  if (!data.shm) {
    LOG(ERROR) << "Failed getting shared memory";
    return -1;
  }

  size_t stride = data.width * 4 /* 32bpp */;
  size_t shm_size = stride * data.height;
  base::WritableSharedMemoryRegion shm_region =
      base::WritableSharedMemoryRegion::Create(shm_size);
  base::WritableSharedMemoryMapping shm_mapping = shm_region.Map();
  data.shm_ptr = shm_mapping.memory();
  base::subtle::PlatformSharedMemoryRegion platform_region =
      base::WritableSharedMemoryRegion::TakeHandleForSerialization(
          std::move(shm_region));
  base::ScopedFD handle = std::move(platform_region.PassPlatformHandle().fd);

  struct wl_shm_pool* pool =
      wl_shm_create_pool(data.shm, handle.get(), shm_size);
  data.buffer = wl_shm_pool_create_buffer(pool, 0, data.width, data.height,
                                          stride, WL_SHM_FORMAT_XRGB8888);
  wl_shm_pool_destroy(pool);

  wl_surface_attach(data.surface, data.buffer, 0, 0);
  wl_surface_commit(data.surface);

  demo_draw(&data, nullptr, 0);
  LOG(INFO) << "wayland_demo application displaying, waiting for keypress";
  do {
  } while (wl_display_dispatch(display) != -1 && !data.done);

  wl_display_disconnect(display);
  LOG(INFO) << "wayland_demo application exiting";
  return 0;
}
