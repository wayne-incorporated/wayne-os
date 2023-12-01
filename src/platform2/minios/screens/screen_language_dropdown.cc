// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/key_reader.h"
#include "minios/screens/screen_language_dropdown.h"

namespace minios {

ScreenLanguageDropdown::ScreenLanguageDropdown(
    std::shared_ptr<DrawInterface> draw_utils,
    ScreenControllerInterface* screen_controller)
    : ScreenBase(draw_utils->GetSupportedLocalesSize(),
                 /*index_=*/1,
                 State::LANGUAGE_SELECTION,
                 draw_utils,
                 screen_controller) {}

void ScreenLanguageDropdown::Show() {
  draw_utils_->ShowLanguageMenu(false);
  // Find index of current locale to show in the dropdown.
  index_ = draw_utils_->FindLocaleIndex(index_);
  draw_utils_->ShowLanguageDropdown(index_);
}

void ScreenLanguageDropdown::UpdateMenu() {
  draw_utils_->ShowLanguageDropdown(index_);
}

void ScreenLanguageDropdown::OnKeyPress(int key_changed) {
  bool enter = false;
  UpdateButtonsIndex(key_changed, &enter);
  if (enter) {
    screen_controller_->UpdateLocale(this, index_);
  } else if (key_changed == KEY_ESC) {
    // Cancel language selection by ESC.
    screen_controller_->OnBackward(this);
  } else {
    UpdateMenu();
  }
}

void ScreenLanguageDropdown::Reset() {
  index_ = 0;
}

ScreenType ScreenLanguageDropdown::GetType() {
  return ScreenType::kLanguageDropDownScreen;
}

std::string ScreenLanguageDropdown::GetName() {
  return "ScreenLanguageDropdown";
}

}  // namespace minios
