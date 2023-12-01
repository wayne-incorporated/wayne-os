// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_SCREENS_SCREEN_PERMISSION_H_
#define MINIOS_SCREENS_SCREEN_PERMISSION_H_

#include <memory>
#include <string>

#include "minios/screens/screen_base.h"

namespace minios {

class ScreenPermission : public ScreenBase {
 public:
  ScreenPermission(std::shared_ptr<DrawInterface> draw_utils,
                   ScreenControllerInterface* screen_controller);

  ~ScreenPermission() = default;

  ScreenPermission(const ScreenPermission&) = delete;
  ScreenPermission& operator=(const ScreenPermission&) = delete;

  void Show() override;
  void Reset() override;
  void OnKeyPress(int key_changed) override;
  ScreenType GetType() override;
  std::string GetName() override;
  bool MoveForward(brillo::ErrorPtr* error) override;
  bool MoveBackward(brillo::ErrorPtr* error) override;

 private:
  // Updates buttons with current selection.
  void ShowButtons();
};

}  // namespace minios

#endif  // MINIOS_SCREENS_SCREEN_PERMISSION_H_
