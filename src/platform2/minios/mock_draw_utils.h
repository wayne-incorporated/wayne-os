// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_DRAW_UTILS_H_
#define MINIOS_MOCK_DRAW_UTILS_H_

#include <gmock/gmock.h>

#include <string>
#include <vector>

#include "minios/draw_utils.h"

namespace minios {

class MockDrawUtils : public DrawUtils {
 public:
  MockDrawUtils() : DrawUtils(nullptr) {}
  MOCK_METHOD(bool, Init, (), (override));
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
  MOCK_METHOD(void,
              ShowInstructionsWithTitle,
              (const std::string& message_token));
};

}  // namespace minios

#endif  // MINIOS_MOCK_DRAW_UTILS_H_
