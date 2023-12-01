// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PCIGUARD_EVENT_HANDLER_H_
#define PCIGUARD_EVENT_HANDLER_H_

#include "pciguard/authorizer.h"

#include <memory>

namespace pciguard {

// A class for handling all events.
class EventHandler {
 public:
  explicit EventHandler(SysfsUtils* utils);
  EventHandler(const EventHandler&) = delete;
  EventHandler& operator=(const EventHandler&) = delete;
  ~EventHandler() = default;

  void OnUserLogin();

  void OnUserLogout();

  void OnScreenLocked();

  void OnScreenUnlocked();

  void OnUserPermissionChanged(bool new_permission);

  void OnNewThunderboltDev(base::FilePath path);

 private:
  enum {
    NO_USER_LOGGED_IN,
    USER_LOGGED_IN_BUT_SCREEN_LOCKED,
    USER_LOGGED_IN_SCREEN_UNLOCKED,
  } state_;

  std::unique_ptr<Authorizer> authorizer_;

  // Protects concurrent access to state_ and authorizer_
  std::mutex lock_;

  // User Permission from chrome browser, to allow external PCI devices.
  bool user_permission_;

  SysfsUtils* utils_;

  // Logs the event
  void LogEvent(const char ev[]);

  friend class EventHandlerTest;
};

}  // namespace pciguard

#endif  // PCIGUARD_EVENT_HANDLER_H_
