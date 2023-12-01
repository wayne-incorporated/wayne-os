// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/wayland_manager.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <errno.h>
#include <string>

#include "backend/text_input.h"
#include "backend/wayland_client.h"

namespace cros_im {

namespace {

constexpr int kWlSeatVersion = 1;
constexpr int kTextInputManagerVersion = 1;
constexpr int kTextInputX11Version = 1;

WaylandManager* g_instance = nullptr;

void on_global(void* data,
               wl_registry* registry,
               uint32_t name,
               const char* interface,
               uint32_t version) {
  reinterpret_cast<WaylandManager*>(data)->OnGlobal(registry, name, interface,
                                                    version);
}

void on_global_remove(void* data, wl_registry* registry, uint32_t name) {
  reinterpret_cast<WaylandManager*>(data)->OnGlobalRemove(registry, name);
}

constexpr wl_registry_listener kRegistryListener = {
    .global = on_global,
    .global_remove = on_global_remove,
};

}  // namespace

const int WaylandManager::kTextInputExtensionMinVersion;
const int WaylandManager::kTextInputExtensionMaxVersion;

void WaylandManager::CreateInstance(wl_display* display) {
  if (g_instance) {
    printf("WaylandManager has already been instantiated.\n");
    return;
  }

  g_instance = new WaylandManager(AppType::kWayland, display);
}

bool WaylandManager::CreateX11Instance(const char* display_name) {
  if (g_instance) {
    printf("WaylandManager has already been instantiated.\n");
    return false;
  }

  std::string wl_id = std::string("DISPLAY-") + display_name + "-wl";
  struct wl_display* display = wl_display_connect(wl_id.c_str());
  if (!display) {
    printf("Failed to connect to Wayland compositor \"%s\".\n", wl_id.c_str());
    return false;
  }

  g_instance = new WaylandManager(AppType::kX11, display);
  return true;
}

bool WaylandManager::HasInstance() {
  return g_instance;
}

WaylandManager* WaylandManager::Get() {
  return g_instance;
}

uint32_t WaylandManager::GetFd() {
  return wl_display_get_fd(display_);
}

void WaylandManager::FlushRequests() {
  // TODO(b/252723634): This may fail (return -1) and set errno to EAGAIN if it
  // couldn't write all data.
  int res = wl_display_flush(display_);
  if (res == -1) {
    printf("Error flushing requests, error: %d (%s)\n", errno,
           std::strerror(errno));
  }
}

void WaylandManager::DispatchEvents() {
  FlushRequests();
  int res = wl_display_dispatch(display_);
  if (res == -1) {
    printf("Error dispatching events, error: %d (%s)\n", errno,
           std::strerror(errno));
  }
}

zwp_text_input_v1* WaylandManager::CreateTextInput(
    const zwp_text_input_v1_listener* listener, void* listener_data) {
  if (!IsInitialized())
    return nullptr;
  auto* text_input =
      zwp_text_input_manager_v1_create_text_input(text_input_manager_);
  zwp_text_input_v1_add_listener(text_input, listener, listener_data);
  return text_input;
}

zcr_extended_text_input_v1* WaylandManager::CreateExtendedTextInput(
    zwp_text_input_v1* text_input,
    const zcr_extended_text_input_v1_listener* listener,
    void* listener_data) {
  if (!IsInitialized())
    return nullptr;
  auto* extended_text_input =
      zcr_text_input_extension_v1_get_extended_text_input(text_input_extension_,
                                                          text_input);
  zcr_extended_text_input_v1_add_listener(extended_text_input, listener,
                                          listener_data);
  return extended_text_input;
}

void WaylandManager::OnGlobal(wl_registry* registry,
                              uint32_t name,
                              const char* interface,
                              uint32_t version) {
  if (strcmp(interface, "wl_seat") == 0) {
    // We don't support compositors which advertise multiple seats.
    assert(!wl_seat_);
    assert(version >= kWlSeatVersion);
    wl_seat_ = reinterpret_cast<wl_seat*>(
        wl_registry_bind(registry, name, &wl_seat_interface, kWlSeatVersion));
    wl_seat_id_ = name;
  } else if (strcmp(interface, "zwp_text_input_manager_v1") == 0) {
    assert(!text_input_manager_);
    assert(version >= kTextInputManagerVersion);
    text_input_manager_ = reinterpret_cast<zwp_text_input_manager_v1*>(
        wl_registry_bind(registry, name, &zwp_text_input_manager_v1_interface,
                         kTextInputManagerVersion));
    text_input_manager_id_ = name;
  } else if (strcmp(interface, "zcr_text_input_extension_v1") == 0) {
    assert(!text_input_extension_);
    assert(version >= kTextInputExtensionMinVersion);
    text_input_extension_version_ =
        std::min(static_cast<int>(version), kTextInputExtensionMaxVersion);
    text_input_extension_ = reinterpret_cast<zcr_text_input_extension_v1*>(
        wl_registry_bind(registry, name, &zcr_text_input_extension_v1_interface,
                         text_input_extension_version_));
    text_input_extension_id_ = name;
  } else if (strcmp(interface, "zcr_text_input_x11_v1") == 0) {
    assert(!text_input_x11_);
    assert(version >= kTextInputX11Version);
    text_input_x11_ = reinterpret_cast<zcr_text_input_x11_v1*>(
        wl_registry_bind(registry, name, &zcr_text_input_x11_v1_interface,
                         kTextInputX11Version));
    text_input_x11_id_ = name;
  }
}

void WaylandManager::OnGlobalRemove(wl_registry* registry, uint32_t name) {
  if (name == wl_seat_id_) {
    printf("The global wl_seat was removed.\n");
    wl_seat_ = nullptr;
    wl_seat_id_ = 0;
  } else if (name == text_input_manager_id_) {
    printf("The global zwp_text_input_manager_v1 was removed.\n");
    text_input_manager_ = nullptr;
    text_input_manager_id_ = 0;
  } else if (name == text_input_extension_id_) {
    printf("The global zcr_text_input_extension_v1 was removed.\n");
    text_input_extension_ = nullptr;
    text_input_extension_id_ = 0;
  } else if (name == text_input_x11_id_) {
    printf("The global zcr_text_input_x11_v1 was removed.\n");
    text_input_x11_ = nullptr;
    text_input_x11_id_ = 0;
  }
}

WaylandManager::WaylandManager(AppType app_type, wl_display* display)
    : app_type_(app_type), display_(display) {
  display_ = display;
  wl_registry* registry = wl_display_get_registry(display);
  wl_registry_add_listener(registry, &kRegistryListener, this);
}

WaylandManager::~WaylandManager() {
  if (app_type_ == AppType::kX11)
    wl_display_disconnect(display_);
}

bool WaylandManager::IsInitialized() const {
  if (!(wl_seat_ && text_input_manager_ && text_input_extension_))
    return false;

  if (app_type_ == AppType::kX11 && !text_input_x11_)
    return false;

  return true;
}

}  // namespace cros_im
