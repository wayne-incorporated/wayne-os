// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_DRAW_INTERFACE_H_
#define MINIOS_DRAW_INTERFACE_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace minios {

class DrawInterface {
 public:
  virtual ~DrawInterface() = default;

  virtual bool Init() = 0;

  // Show dynamic text using pre-rendered glyphs. Colors 'white', 'grey' and
  // 'black'. Returns true on success.
  virtual bool ShowText(const std::string& text,
                        int glyph_offset_h,
                        int glyph_offset_v,
                        const std::string& color) = 0;
  // Shows image at offsets given a full file path. Returns true on success.
  virtual bool ShowImage(const base::FilePath& image_name,
                         int offset_x,
                         int offset_y) = 0;
  // Shows a box at given offsets. Color should be given as a hex string.
  // Returns true on success.
  virtual bool ShowBox(int offset_x,
                       int offset_y,
                       int size_x,
                       int size_y,
                       const std::string& color) = 0;

  // Shows message image at the given offset. All message tokens are in
  // `/etc/screens`. Falls back to English if chosen locale is not available.
  virtual bool ShowMessage(const std::string& message_token,
                           int offset_x,
                           int offset_y) = 0;

  // Shows title and uses title offsets.
  virtual void ShowInstructions(const std::string& message_token) = 0;

  // Shows the title and corresponding description using offsets from
  // `constants` to place.
  virtual void ShowInstructionsWithTitle(const std::string& message_token) = 0;

  // Returns whether device has a detachable keyboard and sets `is_detachable`.
  virtual bool IsDetachable() = 0;

  // Show button, focus changes the button color to indicate selection. Returns
  // false on error.
  virtual void ShowButton(const std::string& message_token,
                          int offset_y,
                          bool is_selected,
                          int inner_width,
                          bool is_text) = 0;

  // Shows stepper icons given a list of steps. Currently icons available in
  // 'kScreens' only go up to 3. Steps can be a number '1', 'error', or 'done'.
  // Defaults to done if requested icon not found.
  virtual void ShowStepper(const std::vector<std::string>& steps) = 0;

  // Shows advanced options buttons at the bottom of the screen.
  virtual void ShowAdvancedOptionsButtons(bool focused) = 0;

  // Clears screen and shows footer and language drop down menu.
  virtual void MessageBaseScreen() = 0;

  // Shows the language dropdown button.
  virtual void ShowLanguageDropdown(int current_index) = 0;

  // Finds and updates the index of `locale_` in `supported_locales` or falls
  // back to a default.
  virtual int FindLocaleIndex(int current_index) = 0;

  // Shows language menu drop down button on base screen. Button is highlighted
  // if it is currently selected.
  virtual void ShowLanguageMenu(bool is_selected) = 0;

  // Does all the reloading needed when the locale is changed, including
  // repainting the screen. Called after `LanguageDropdown` is done.
  virtual void LocaleChange(int selected_locale) = 0;

  // Show an empty progress bar.
  virtual void ShowProgressBar() = 0;

  // Show progress bar at percentage given.
  virtual void ShowProgressPercentage(double progress) = 0;

  // Show indeterminate progress bar.
  virtual void ShowIndeterminateProgressBar() = 0;

  // Hide/Stop indeterminate progress bar.
  virtual void HideIndeterminateProgressBar() = 0;

  // Returns number of locales.
  virtual int GetSupportedLocalesSize() = 0;

  // Returns the default button width, read from constants.
  virtual int GetDefaultButtonWidth() = 0;

  // Returns the frecon canvas size.
  virtual int GetFreconCanvasSize() = 0;

  // Returns the screen assets path.
  virtual base::FilePath GetScreenPath() = 0;

  // Returns whether the current locale is read from right to left.
  virtual bool IsLocaleRightToLeft() = 0;
};

}  // namespace minios

#endif  // MINIOS_DRAW_INTERFACE_H_
