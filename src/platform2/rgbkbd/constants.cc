// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rgbkbd/constants.h"

#include <base/no_destructor.h>
#include <vector>

namespace rgbkbd {

const std::vector<std::vector<uint32_t>>& GetIndividualKeyZones() {
  static const base::NoDestructor<std::vector<std::vector<uint32_t>>>
      individual_key_zones({
          {
              1,              // ~
              2,              // 1
              16,             // Tab
              17,             // Q
              30,             // Search/Launcher
              31,             // A
              kLeftShiftKey,  // Left Shift
              46,             // Z
              58,             // Ctrl
              60,             // Left Alt
              110,            // Escape
              111,            // T1: Back
          },
          {
              3,    // 2
              4,    // 3
              5,    // 4
              18,   // W
              19,   // E
              20,   // R
              32,   // S
              33,   // D
              34,   // F
              47,   // X
              48,   // C
              49,   // V
              112,  // T2: Refresh
              113,  // T3: Full Screen
              114,  // T4: Overview
          },
          {
              6,    // 5
              7,    // 6
              8,    // 7
              9,    // 8
              21,   // T
              22,   // Y
              23,   // U
              35,   // G
              36,   // H
              50,   // B
              61,   // Space Bar
              115,  // T5: Snapshot
              116,  // T6: Brightness Down
              117,  // T7: Brightness Up
              118,  // T8: RGB Backlight Off
              119,  // T9: Play/Pause
          },
          {
              10,   // 9
              11,   // 0
              12,   // -
              24,   // I
              25,   // O
              26,   // P
              37,   // J
              38,   // K
              39,   // L
              51,   // N
              52,   // M
              53,   // ,
              120,  // T10: Mic Mute
              121,  // T1: Volume Mute
              122,  // T9: Play/Pause
              123,  // T10: Mic Mute
          },
          {
              13,              // =
              15,              // Backspace
              27,              // [
              28,              // ]
              29,              // Backslash
              40,              // ;
              41,              // '
              43,              // Enter
              54,              // .
              55,              // /
              kRightShiftKey,  // Right Shift
              59,              // Power
              62,              // Right Alt
              64,              // Right Ctrl
              79,              // Left Arrow
              83,              // Top Arrow
              84,              // Bottom Arrow
              89,              // Right Arrow
          },
      });
  return *individual_key_zones;
}

const std::vector<std::vector<uint32_t>>& GetFourtyLedZones() {
  static const base::NoDestructor<std::vector<std::vector<uint32_t>>>
      fourty_led_zones({
          {
              1,
              2,
              3,
              4,
              5,
              6,
              7,
              8,
              9,
              10,
          },
          {
              11,
              12,
              13,
              14,
              15,
              16,
              17,
              18,
              19,
              20,
          },
          {
              21,
              22,
              23,
              24,
              25,
              26,
              27,
              28,
              29,
              30,
          },
          {
              31,
              32,
              33,
              34,
              35,
              36,
              37,
              38,
              39,
              40,
          },
      });
  return *fourty_led_zones;
}

const std::vector<std::vector<uint32_t>>& GetTwelveLedZones() {
  static const base::NoDestructor<std::vector<std::vector<uint32_t>>>
      twelve_led_zones({
          {
              1,
              2,
              3,
          },
          {
              4,
              5,
              6,
          },
          {
              7,
              8,
              9,
          },
          {
              10,
              11,
              12,
          },
      });
  return *twelve_led_zones;
}

const std::vector<std::vector<uint32_t>>& GetFourLedZones() {
  static const base::NoDestructor<std::vector<std::vector<uint32_t>>>
      four_led_zones({
          {
              1,
          },
          {
              2,
          },
          {
              3,
          },
          {
              4,
          },
      });
  return *four_led_zones;
}

}  // namespace rgbkbd
