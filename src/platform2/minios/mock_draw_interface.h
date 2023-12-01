// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_DRAW_INTERFACE_H_
#define MINIOS_MOCK_DRAW_INTERFACE_H_

#include <base/files/file_path.h>
#include <gmock/gmock.h>

#include <string>
#include <vector>

#include "minios/draw_interface.h"

namespace minios {

class MockDrawInterface : public DrawInterface {
 public:
  MockDrawInterface() = default;
  ~MockDrawInterface() = default;

  MockDrawInterface(const MockDrawInterface&) = delete;
  MockDrawInterface& operator=(const MockDrawInterface&) = delete;

  MOCK_METHOD(bool, Init, ());
  MOCK_METHOD(bool,
              ShowBox,
              (int offset_x,
               int offset_y,
               int size_x,
               int size_y,
               const std::string& color));
  MOCK_METHOD(bool,
              ShowImage,
              (const base::FilePath& image_name, int offset_x, int offset_y));
  MOCK_METHOD(bool,
              ShowMessage,
              (const std::string& message_token, int offset_x, int offset_y));
  MOCK_METHOD(bool,
              ShowText,
              (const std::string& text,
               int glyph_offset_h,
               int glyph_offset_v,
               const std::string& color));
  MOCK_METHOD(void, ShowInstructions, (const std::string& message_token));
  MOCK_METHOD(void,
              ShowInstructionsWithTitle,
              (const std::string& message_token));
  MOCK_METHOD(bool, IsDetachable, ());
  MOCK_METHOD(void,
              ShowButton,
              (const std::string& message_token,
               int offset_y,
               bool is_selected,
               int inner_width,
               bool is_text));
  MOCK_METHOD(void, ShowStepper, (const std::vector<std::string>& steps));
  MOCK_METHOD(void, ShowAdvancedOptionsButtons, (bool focused));
  MOCK_METHOD(void, MessageBaseScreen, ());
  MOCK_METHOD(void, ShowLanguageDropdown, (int current_index));
  MOCK_METHOD(int, FindLocaleIndex, (int current_index));
  MOCK_METHOD(void, ShowLanguageMenu, (bool is_selected));
  MOCK_METHOD(void, LocaleChange, (int selected_locale));
  MOCK_METHOD(void, ShowProgressBar, ());
  MOCK_METHOD(void, ShowProgressPercentage, (double progress));
  MOCK_METHOD(void, ShowIndeterminateProgressBar, ());
  MOCK_METHOD(void, HideIndeterminateProgressBar, ());
  MOCK_METHOD(int, GetSupportedLocalesSize, ());
  MOCK_METHOD(int, GetDefaultButtonWidth, ());
  MOCK_METHOD(int, GetFreconCanvasSize, ());
  MOCK_METHOD(base::FilePath, GetScreenPath, ());
  MOCK_METHOD(bool, IsLocaleRightToLeft, ());
};

}  // namespace minios

#endif  // MINIOS_MOCK_DRAW_INTERFACE_H_
