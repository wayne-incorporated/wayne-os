// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_WAYLAND_MANAGER_H_
#define VM_TOOLS_CROS_IM_BACKEND_WAYLAND_MANAGER_H_

#include <cstdint>

struct wl_display;
struct wl_registry;
struct wl_seat;
struct zwp_text_input_v1;
struct zwp_text_input_v1_listener;
struct zwp_text_input_manager_v1;
struct zcr_extended_text_input_v1;
struct zcr_extended_text_input_v1_listener;
struct zcr_text_input_extension_v1;
struct zcr_text_input_x11_v1;

namespace cros_im {

// WaylandManager manages the Wayland connection and provides text_input objects
// to clients. It supports using an existing Wayland connection or creating a
// new one (for X11 app support).
class WaylandManager {
 public:
  // Created zcr_extended_text_input_v1 objects have a version in the range
  // [min, max] (inclusive). On creation, the caller should provide a listener
  // that supports the max version, and check GetTextInputExtensionVersion()
  // before making requests from above the min version.
  // The min version should be at most the version supported by Exo/sommelier
  // at the time of the last branch, and it is safe to have this lag behind.
  static const int kTextInputExtensionMinVersion = 4;
  static const int kTextInputExtensionMaxVersion = 9;

  static void CreateInstance(wl_display* display);
  // Returns whether we were successfully able to make a connection.
  static bool CreateX11Instance(const char* display_name);
  static bool HasInstance();
  static WaylandManager* Get();

  // These functions let X11 clients integrate the Wayland requests and events
  // into their event loop.

  // The file descriptor for receiving events. Should only be poll()'d from a
  // single thread to avoid potential deadlocks.
  uint32_t GetFd();
  // Flush pending requests to the compositor.
  void FlushRequests();
  // Dispatches any received events. This blocks if there are no events to read
  // from the fd (it is not possible to check if there are events available).
  void DispatchEvents();

  // These return non-null if and only if initialization is complete.
  zwp_text_input_v1* CreateTextInput(const zwp_text_input_v1_listener* listener,
                                     void* listener_data);
  zcr_extended_text_input_v1* CreateExtendedTextInput(
      zwp_text_input_v1* text_input,
      const zcr_extended_text_input_v1_listener* listener,
      void* listener_data);

  // Once initialized, these are not expected to change.
  wl_seat* GetSeat() { return wl_seat_; }
  zcr_text_input_x11_v1* GetTextInputX11() { return text_input_x11_; }
  int GetTextInputExtensionVersion() { return text_input_extension_version_; }

  // Callbacks for wayland global events.
  void OnGlobal(wl_registry* registry,
                uint32_t name,
                const char* interface,
                uint32_t version);
  void OnGlobalRemove(wl_registry* registry, uint32_t name);

 private:
  enum class AppType {
    kWayland,
    kX11,
  };
  explicit WaylandManager(AppType app_type, wl_display* display);
  ~WaylandManager();

  bool IsInitialized() const;

  AppType app_type_;

  wl_display* display_ = nullptr;

  wl_seat* wl_seat_ = nullptr;
  uint32_t wl_seat_id_ = 0;
  // Creates text_input objects
  zwp_text_input_manager_v1* text_input_manager_ = nullptr;
  uint32_t text_input_manager_id_ = 0;
  // Creates extended_text_input objects
  zcr_text_input_extension_v1* text_input_extension_ = nullptr;
  uint32_t text_input_extension_id_ = 0;
  // For X11 app support
  zcr_text_input_x11_v1* text_input_x11_ = nullptr;
  uint32_t text_input_x11_id_ = 0;

  int text_input_extension_version_ = 0;
};

}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_BACKEND_WAYLAND_MANAGER_H_
