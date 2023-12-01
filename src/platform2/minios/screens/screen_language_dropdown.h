// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_SCREENS_SCREEN_LANGUAGE_DROPDOWN_H_
#define MINIOS_SCREENS_SCREEN_LANGUAGE_DROPDOWN_H_

#include <memory>
#include <string>

#include "minios/screens/screen_base.h"

namespace minios {

class ScreenLanguageDropdown : public ScreenBase {
 public:
  ScreenLanguageDropdown(std::shared_ptr<DrawInterface> draw_utils,
                         ScreenControllerInterface* screen_controller);
  ~ScreenLanguageDropdown() = default;

  ScreenLanguageDropdown(const ScreenLanguageDropdown&) = delete;
  ScreenLanguageDropdown& operator=(const ScreenLanguageDropdown&) = delete;

  void Show() override;

  void Reset() override;

  void OnKeyPress(int key_changed) override;

  ScreenType GetType() override;
  std::string GetName() override;

 private:
  // Updates locale dropdown menu with current selection.
  void UpdateMenu();
};

}  // namespace minios

#endif  // MINIOS_SCREENS_SCREEN_LANGUAGE_DROPDOWN_H_
