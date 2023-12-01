// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RGBKBD_CONSTANTS_H_
#define RGBKBD_CONSTANTS_H_

#include <cstdint>
#include <vector>

namespace rgbkbd {

struct Color {
  constexpr Color(uint8_t r, uint8_t g, uint8_t b) : r(r), g(g), b(b) {}
  uint8_t r = 0;
  uint8_t g = 0;
  uint8_t b = 0;

  bool operator==(const Color& rhs) const {
    return (r == rhs.r) && (g == rhs.g) && (b == rhs.b);
  }
};

struct KeyColor {
  constexpr KeyColor(uint32_t key, Color color) : key(key), color(color) {}
  uint32_t key;
  Color color;
};

// Prism USB Vendor/Product ids.
constexpr uint16_t kPrismVendorId = 0x18d1;
constexpr uint16_t kPrismProductId = 0x5022;

// The color for highlighting Shifts when Caps Lock is on.
static constexpr Color kCapsLockHighlight = Color(/*r=*/255, /*g=*/77, /*b=*/0);

// Default background color.
static constexpr Color kWhiteBackgroundColor =
    Color(/*r=*/255, /*g=*/255, /*b=*/210);

static constexpr uint32_t kLeftShiftKey = 44;
static constexpr uint32_t kRightShiftKey = 57;

// Rainbow mode constants.
static constexpr Color kRainbowRed = Color(/*r=*/0xc5, /*g=*/0x22, /*b=*/0x1f);
static constexpr Color kRainbowYellow =
    Color(/*r=*/0xec, /*g=*/0x6a, /*b=*/0x08);
static constexpr Color kRainbowGreen =
    Color(/*r=*/0x1b, /*g=*/0xb3, /*b=*/0x19);
static constexpr Color kRainbowLightBlue =
    Color(/*r=*/0x20, /*g=*/0xb1, /*b=*/0x89);
static constexpr Color kRainbowIndigo =
    Color(/*r=*/0x19, /*g=*/0x37, /*b=*/0xd2);
static constexpr Color kRainbowPurple =
    Color(/*r=*/0x84, /*g=*/0x20, /*b=*/0xb4);

// If there are no RGB capabilities, all zones will be empty.
const std::vector<uint32_t> kEmptyZone = std::vector<uint32_t>();

const Color kIndividualKeyRainbowColors[] = {
    kRainbowRed, kRainbowYellow, kRainbowGreen, kRainbowIndigo, kRainbowPurple,
};

const Color kFourZonesRainbowColors[] = {
    kRainbowRed,
    kRainbowYellow,
    kRainbowGreen,
    kRainbowLightBlue,
};

const KeyColor kRainbowModeIndividualKey[] = {
    // Keys 42, 45, 56, 63, [65-78], [80-82], [85-88], [90-109] are not present
    // in this layout.
    {1, kRainbowRed},                  // ~
    {2, kRainbowRed},                  // 1
    {16, kRainbowRed},                 // Tab
    {17, kRainbowRed},                 // Q
    {30, kRainbowRed},                 // Search/Launcher
    {31, kRainbowRed},                 // A
    {kLeftShiftKey, kRainbowRed},      // Left Shift
    {46, kRainbowRed},                 // Z
    {58, kRainbowRed},                 // Ctrl
    {60, kRainbowRed},                 // Left Alt
    {110, kRainbowRed},                // Escape
    {111, kRainbowRed},                // T1: Back
    {3, kRainbowYellow},               // 2
    {4, kRainbowYellow},               // 3
    {5, kRainbowYellow},               // 4
    {18, kRainbowYellow},              // W
    {19, kRainbowYellow},              // E
    {20, kRainbowYellow},              // R
    {32, kRainbowYellow},              // S
    {33, kRainbowYellow},              // D
    {34, kRainbowYellow},              // F
    {47, kRainbowYellow},              // X
    {48, kRainbowYellow},              // C
    {49, kRainbowYellow},              // V
    {112, kRainbowYellow},             // T2: Refresh
    {113, kRainbowYellow},             // T3: Full Screen
    {114, kRainbowYellow},             // T4: Overview
    {6, kRainbowGreen},                // 5
    {7, kRainbowGreen},                // 6
    {8, kRainbowGreen},                // 7
    {9, kRainbowGreen},                // 8
    {21, kRainbowGreen},               // T
    {22, kRainbowGreen},               // Y
    {23, kRainbowGreen},               // U
    {35, kRainbowGreen},               // G
    {36, kRainbowGreen},               // H
    {50, kRainbowGreen},               // B
    {61, kRainbowGreen},               // Space Bar
    {115, kRainbowGreen},              // T5: Snapshot
    {116, kRainbowGreen},              // T6: Brightness Down
    {117, kRainbowGreen},              // T7: Brightness Up
    {118, kRainbowGreen},              // T8: RGB Backlight Off
    {119, kRainbowGreen},              // T9: Play/Pause
    {10, kRainbowIndigo},              // 9
    {11, kRainbowIndigo},              // 0
    {12, kRainbowIndigo},              // -
    {24, kRainbowIndigo},              // I
    {25, kRainbowIndigo},              // O
    {26, kRainbowIndigo},              // P
    {37, kRainbowIndigo},              // J
    {38, kRainbowIndigo},              // K
    {39, kRainbowIndigo},              // L
    {51, kRainbowIndigo},              // N
    {52, kRainbowIndigo},              // M
    {53, kRainbowIndigo},              // ,
    {120, kRainbowIndigo},             // T10: Mic Mute
    {121, kRainbowIndigo},             // T1: Volume Mute
    {122, kRainbowIndigo},             // T9: Play/Pause
    {123, kRainbowIndigo},             // T10: Mic Mute
    {13, kRainbowPurple},              // =
    {15, kRainbowPurple},              // Backspace
    {27, kRainbowPurple},              // [
    {28, kRainbowPurple},              // ]
    {29, kRainbowPurple},              // Backslash
    {40, kRainbowPurple},              // ;
    {41, kRainbowPurple},              // '
    {43, kRainbowPurple},              // Enter
    {54, kRainbowPurple},              // .
    {55, kRainbowPurple},              // /
    {kRightShiftKey, kRainbowPurple},  // Right Shift
    {59, kRainbowPurple},              // Power
    {62, kRainbowPurple},              // Right Alt
    {64, kRainbowPurple},              // Right Ctrl
    {79, kRainbowPurple},              // Left Arrow
    {83, kRainbowPurple},              // Top Arrow
    {84, kRainbowPurple},              // Bottom Arrow
    {89, kRainbowPurple},              // Right Arrow
};

const KeyColor kRainbowModeFourZoneFortyLed[] = {
    {1, kRainbowRed},        {2, kRainbowRed},        {3, kRainbowRed},
    {4, kRainbowRed},        {5, kRainbowRed},        {6, kRainbowRed},
    {7, kRainbowRed},        {8, kRainbowRed},        {9, kRainbowRed},
    {10, kRainbowRed},       {11, kRainbowYellow},    {12, kRainbowYellow},
    {13, kRainbowYellow},    {14, kRainbowYellow},    {15, kRainbowYellow},
    {16, kRainbowYellow},    {17, kRainbowYellow},    {18, kRainbowYellow},
    {19, kRainbowYellow},    {20, kRainbowYellow},    {21, kRainbowGreen},
    {22, kRainbowGreen},     {23, kRainbowGreen},     {24, kRainbowGreen},
    {25, kRainbowGreen},     {26, kRainbowGreen},     {27, kRainbowGreen},
    {28, kRainbowGreen},     {29, kRainbowGreen},     {30, kRainbowGreen},
    {31, kRainbowLightBlue}, {32, kRainbowLightBlue}, {33, kRainbowLightBlue},
    {34, kRainbowLightBlue}, {35, kRainbowLightBlue}, {36, kRainbowLightBlue},
    {37, kRainbowLightBlue}, {38, kRainbowLightBlue}, {39, kRainbowLightBlue},
    {40, kRainbowLightBlue},
};

// TODO(michaelcheco): Update mapping once colors are finalized.
const KeyColor kRainbowModeFourZoneTwelveLed[] = {
    {1, kRainbowRed},        {2, kRainbowRed},        {3, kRainbowRed},
    {4, kRainbowYellow},     {5, kRainbowYellow},     {6, kRainbowYellow},
    {7, kRainbowGreen},      {8, kRainbowGreen},      {9, kRainbowGreen},
    {10, kRainbowLightBlue}, {11, kRainbowLightBlue}, {12, kRainbowLightBlue},
};

// TODO(michaelcheco): Update mapping once colors are finalized.
const KeyColor kRainbowModeFourZoneFourLed[] = {{1, kRainbowRed},
                                                {2, kRainbowYellow},
                                                {3, kRainbowGreen},
                                                {4, kRainbowLightBlue}};

const std::vector<std::vector<uint32_t>>& GetIndividualKeyZones();
const std::vector<std::vector<uint32_t>>& GetFourtyLedZones();
const std::vector<std::vector<uint32_t>>& GetTwelveLedZones();
const std::vector<std::vector<uint32_t>>& GetFourLedZones();

}  // namespace rgbkbd

#endif  // RGBKBD_CONSTANTS_H_
