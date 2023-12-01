// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_SCREENS_SCREEN_BASE_H_
#define MINIOS_SCREENS_SCREEN_BASE_H_

#include <memory>

#include <base/logging.h>
#include <gtest/gtest_prod.h>

#include "minios/draw_interface.h"
#include "minios/screen_controller_interface.h"
#include "minios/screen_interface.h"

namespace minios {

extern const int kBtnYStep;

class ScreenBase : public ScreenInterface {
 public:
  ScreenBase(int button_count,
             int index,
             State::States state,
             std::shared_ptr<DrawInterface> draw_utils,
             ScreenControllerInterface* screen_controller);

  void SetButtonCountForTest(int button_count) { button_count_ = button_count; }

  int GetButtonCountForTest() { return button_count_; }

  void SetIndexForTest(int index) { index_ = index; }

  int GetIndexForTest() { return index_; }

  // `ScreenInterface` overrides.
  bool MoveForward(brillo::ErrorPtr* error) override;
  bool MoveBackward(brillo::ErrorPtr* error) override;
  State GetState() override { return state_; }

 protected:
  FRIEND_TEST(ScreenBaseTest, UpdateButtons);
  FRIEND_TEST(ScreenBaseTest, UpdateButtonsIsDetachable);

  // Set the current state. Notify if the state changes.
  void SetState(State::States state);

  // Changes the index and enter value based on the given key. Unknown keys are
  // ignored and index is kept within the range of menu items. Enter is whether
  // the enter key was pressed and released.
  virtual void UpdateButtonsIndex(int key, bool* enter);

  // The number of buttons or dropdown items on the page.
  int button_count_;

  // The current screen index.
  int index_;

  // The current `State`.
  State state_;

  std::shared_ptr<DrawInterface> draw_utils_;

  ScreenControllerInterface* screen_controller_;
};

}  // namespace minios

#endif  // MINIOS_SCREENS_SCREEN_BASE_H_
