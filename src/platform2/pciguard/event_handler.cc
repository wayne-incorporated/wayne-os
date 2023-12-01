// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "pciguard/event_handler.h"

#include <base/check.h>
#include <base/logging.h>

namespace pciguard {

// TODO(b/176184431): Don't assume NO_USER_LOGGED_IN on init.
EventHandler::EventHandler(SysfsUtils* utils)
    : state_(NO_USER_LOGGED_IN),
      authorizer_(nullptr),
      user_permission_(false),
      utils_(utils) {
  CHECK(utils);
}

void EventHandler::LogEvent(const char ev[]) {
  const char* states[] = {
      [NO_USER_LOGGED_IN] = "NO_USER_LOGGED_IN",
      [USER_LOGGED_IN_BUT_SCREEN_LOCKED] = "USER_LOGGED_IN_BUT_SCREEN_LOCKED",
      [USER_LOGGED_IN_SCREEN_UNLOCKED] = "USER_LOGGED_IN_SCREEN_UNLOCKED",
  };

  LOG(INFO) << "CurrentState=" << states[state_]
            << ", UserPermission=" << user_permission_
            << ", received event=" << ev;
}

// In a multiuser login scenario, session manager sends session-starting once
// for every time a user is logged in. So this function could get called
// multiple times before a single call to OnUserLogout() logs out all the users.
void EventHandler::OnUserLogin() {
  DCHECK(!authorizer_);

  std::lock_guard<std::mutex> lock(lock_);
  LogEvent("User-Login");

  // It is important to have this state check, whenever we go from a more
  // restrictive state to a less restrictive state to ensure that we always
  // err on the cautious side should the events arrive out of order or are
  // processed out of order.
  if (state_ == NO_USER_LOGGED_IN)
    state_ = USER_LOGGED_IN_SCREEN_UNLOCKED;
}

void EventHandler::OnUserLogout() {
  std::lock_guard<std::mutex> lock(lock_);
  LogEvent("User-Logout");

  // Don't check for current state when going to a super restrictive state.
  state_ = NO_USER_LOGGED_IN;
  authorizer_.reset();
  user_permission_ = false;

  utils_->DeauthorizeAllDevices();
}

void EventHandler::OnScreenLocked() {
  std::lock_guard<std::mutex> lock(lock_);
  LogEvent("Screen-Locked");

  // Check to ensure we only allow to go from less restrictive state to more
  // restrictive state.
  if (state_ == USER_LOGGED_IN_SCREEN_UNLOCKED)
    state_ = USER_LOGGED_IN_BUT_SCREEN_LOCKED;

  authorizer_.reset();

  utils_->DenyNewDevices();
}

void EventHandler::OnScreenUnlocked() {
  DCHECK(!authorizer_);

  std::lock_guard<std::mutex> lock(lock_);
  LogEvent("Screen-Unlocked");

  // It is important to have this state check, whenever we go from a more
  // restrictive state to a less restrictive state to ensure that we always
  // err on the cautious side should the events arrive or are processed out
  // of order.
  if (state_ == USER_LOGGED_IN_BUT_SCREEN_LOCKED) {
    state_ = USER_LOGGED_IN_SCREEN_UNLOCKED;
    if (user_permission_) {
      authorizer_ = std::make_unique<Authorizer>(utils_);
      authorizer_->SubmitJob(Authorizer::AUTHORIZE_ALL_DEVICES,
                             base::FilePath(""));
    }
  }
}

void EventHandler::OnNewThunderboltDev(base::FilePath path) {
  std::lock_guard<std::mutex> lock(lock_);
  LogEvent("New-Thunderbolt-Dev");

  if (authorizer_)
    authorizer_->SubmitJob(Authorizer::AUTHORIZE_1_DEVICE, path);
}

void EventHandler::OnUserPermissionChanged(bool new_permission) {
  std::lock_guard<std::mutex> lock(lock_);

  if (new_permission == user_permission_) {
    LOG(INFO) << "UserPermissionChange notification (new val=" << new_permission
              << "), but no change. Ignoring.";
    return;
  }

  if (new_permission) {
    LogEvent("User-Permission-Allowed");
    // It is important to have this state check, whenever we go from a more
    // restrictive state to a less restrictive state to ensure that we always
    // err on the cautious side should the events arrive or are processed out
    // of order.
    if (state_ == USER_LOGGED_IN_SCREEN_UNLOCKED) {
      user_permission_ = true;
      if (!authorizer_) {
        authorizer_ = std::make_unique<Authorizer>(utils_);
        authorizer_->SubmitJob(Authorizer::AUTHORIZE_ALL_DEVICES,
                               base::FilePath(""));
      }
    }
  } else {
    LogEvent("User-Permission-Denied");
    // No state check needed.
    authorizer_.reset();
    utils_->DeauthorizeAllDevices();
    user_permission_ = false;
  }
}

}  // namespace pciguard
