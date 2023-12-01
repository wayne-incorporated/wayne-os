// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/screens/screen_base.h"

#include <base/logging.h>

#include "minios/error.h"
#include "minios/key_reader.h"

namespace minios {

const int kBtnYStep = 40;

ScreenBase::ScreenBase(int button_count,
                       int index,
                       State::States state,
                       std::shared_ptr<DrawInterface> draw_utils,
                       ScreenControllerInterface* screen_controller)
    : button_count_(button_count),
      index_(index),
      draw_utils_(draw_utils),
      screen_controller_(screen_controller) {
  state_.set_state(state);
}

void ScreenBase::UpdateButtonsIndex(int key, bool* enter) {
  int starting_index = index_;
  // Make sure index is in range, if not reset to 0.
  if (starting_index < 0 || starting_index >= button_count_)
    starting_index = 0;

  // Modify selected index and enter state based on user key input.
  if (key == KEY_UP || key == KEY_VOLUMEUP) {
    if (starting_index > 0) {
      starting_index--;
    }
  } else if (key == KEY_DOWN || key == KEY_VOLUMEDOWN) {
    if (starting_index < (button_count_ - 1)) {
      starting_index++;
    }
  } else if (key == KEY_ENTER || key == KEY_POWER) {
    *enter = true;
  } else {
    LOG(ERROR) << "Unknown key value: " << key;
  }
  index_ = starting_index;
}

void ScreenBase::SetState(State::States state) {
  state_.set_state(state);
  screen_controller_->OnStateChanged(state_);
}

bool ScreenBase::MoveForward(brillo::ErrorPtr* error) {
  Error::AddTo(error, FROM_HERE, error::kFailedGoToNextScreen,
               "Not supported for screen: " + GetName());

  return false;
}

bool ScreenBase::MoveBackward(brillo::ErrorPtr* error) {
  Error::AddTo(error, FROM_HERE, error::kFailedGoToPrevScreen,
               "Not supported for screen: " + GetName());

  return false;
}

}  // namespace minios
