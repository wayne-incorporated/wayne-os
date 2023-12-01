// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/draw_utils.h"

#include <algorithm>
#include <utility>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

namespace minios {

// Dropdown Menu Colors.
const char kMenuBlack[] = "0x202124";
const char kMenuBlue[] = "0x8AB4F8";
const char kMenuGrey[] = "0x3F4042";
const char kMenuDropdownFrameNavy[] = "0x435066";
const char kMenuDropdownBackgroundBlack[] = "0x2D2E30";
const char kMenuButtonFrameGrey[] = "0x9AA0A6";
const char kAdvancedBtnBackground[] = "0x2B2F37";

// Dimension Constants
const int kButtonHeight = 32;
const int kButtonMargin = 8;
const int kDefaultMessageWidth = 720;
const int kMonospaceGlyphHeight = 20;
const int kMonospaceGlyphWidth = 10;
const int kDefaultButtonWidth = 80;
const int kProgressBarYScale = 12;
constexpr int kProgressBarHeight = 4;

// Frecon constants
constexpr char kScreens[] = "etc/screens";
constexpr int kFreconScalingFactor = 1;
constexpr int kCanvasSize = 1080;
constexpr int kSmallCanvasSize = 900;
constexpr int kFreconNoOffset = 0;

namespace {
constexpr char kConsole0[] = "run/frecon/vt0";

// Dimensions and spacing.
constexpr int kNewLineChar = 10;

constexpr char kButtonWidthToken[] = "DEBUG_OPTIONS_BTN_WIDTH";

// The index for en-US in `supported_locales`.
constexpr int kEnglishIndex = 9;

// The resolution at which we draw segments of the indeterminate progress bar.
// Tail is slightly slower than head in an attempt to approximate the material
// design guidelines for indeterminate progress bars.
constexpr float kProgressBarHeadSegments = 50.0f;
constexpr float kProgressBarTailSegments = 57.0f;

// Convert a floating point value to the nearest even integer.
int nearbyeven(const float value) {
  return static_cast<int>(std::nearbyint(value * 0.5f) * 2.0f);
}
}  // namespace

bool DrawUtils::Init() {
  ReadHardwareId();
  // TODO(vyshu): Change constants.sh and lang_constants.sh to simple text file.
  ReadDimensionConstants();
  if (!ReadLangConstants()) {
    return false;
  }
  GetFreconConstants();
  InitIndeterminateProgressBar();
  return true;
}

bool DrawUtils::ShowText(const std::string& text,
                         int glyph_offset_h,
                         int glyph_offset_v,
                         const std::string& color) {
  base::FilePath glyph_dir = screens_path_.Append("glyphs").Append(color);
  const int kTextStart = glyph_offset_h;

  for (const auto& chr : text) {
    int char_num = static_cast<int>(chr);
    base::FilePath chr_file_path =
        glyph_dir.Append(base::NumberToString(char_num) + ".png");
    if (char_num == kNewLineChar) {
      glyph_offset_v += kMonospaceGlyphHeight;
      glyph_offset_h = kTextStart;
    } else {
      int offset_rtl = IsLocaleRightToLeft() ? -glyph_offset_h : glyph_offset_h;
      if (!ShowImage(chr_file_path, offset_rtl, glyph_offset_v)) {
        LOG(ERROR) << "Failed to show image " << chr_file_path << " for text "
                   << text;
        return false;
      }
      glyph_offset_h += kMonospaceGlyphWidth;
    }
  }
  return true;
}

bool DrawUtils::ShowImage(const base::FilePath& image_name,
                          int offset_x,
                          int offset_y) {
  if (IsLocaleRightToLeft())
    offset_x = -offset_x;
  std::string command = base::StringPrintf(
      "\033]image:file=%s;offset=%d,%d;scale=%d\a", image_name.value().c_str(),
      offset_x, offset_y, frecon_scale_factor_);
  if (!base::AppendToFile(base::FilePath(root_).Append(kConsole0), command)) {
    LOG(ERROR) << "Could not write " << image_name << "  to console.";
    return false;
  }

  return true;
}

bool DrawUtils::ShowBox(int offset_x,
                        int offset_y,
                        int size_x,
                        int size_y,
                        const std::string& color) {
  size_x = std::max(size_x, 1);
  size_y = std::max(size_y, 1);
  if (IsLocaleRightToLeft())
    offset_x = -offset_x;

  std::string command = base::StringPrintf(
      "\033]box:color=%s;size=%d,%d;offset=%d,%d;scale=%d\a", color.c_str(),
      size_x, size_y, offset_x, offset_y, frecon_scale_factor_);

  if (!base::AppendToFile(base::FilePath(root_).Append(kConsole0), command)) {
    LOG(ERROR) << "Could not write show box command to console.";
    return false;
  }

  return true;
}

bool DrawUtils::ShowMessage(const std::string& message_token,
                            int offset_x,
                            int offset_y) {
  // Determine the filename of the message resource. Fall back to en-US if
  // the localized version of the message is not available.
  base::FilePath message_file_path =
      screens_path_.Append(locale_).Append(message_token + ".png");
  if (!base::PathExists(message_file_path)) {
    if (locale_ == "en-US") {
      LOG(ERROR) << "Message " << message_token
                 << " not found in en-US. No fallback available.";
      return false;
    }
    LOG(WARNING) << "Could not find " << message_token << " in " << locale_
                 << " trying default locale en-US.";
    message_file_path =
        screens_path_.Append("en-US").Append(message_token + ".png");
    if (!base::PathExists(message_file_path)) {
      LOG(ERROR) << "Message " << message_token << " not found in path "
                 << message_file_path;
      return false;
    }
  }
  return ShowImage(message_file_path, offset_x, offset_y);
}

void DrawUtils::ShowInstructions(const std::string& message_token) {
  const int kXOffset = (-frecon_canvas_size_ / 2) + (kDefaultMessageWidth / 2);
  const int kYOffset = (-frecon_canvas_size_ / 4);
  if (!ShowMessage(message_token, kXOffset, kYOffset))
    LOG(WARNING) << "Unable to show " << message_token;
}

void DrawUtils::ShowInstructionsWithTitle(const std::string& message_token) {
  const int kXOffset = (-frecon_canvas_size_ / 2) + (kDefaultMessageWidth / 2);

  int title_height;
  if (!GetDimension("TITLE_" + message_token + "_HEIGHT", &title_height)) {
    title_height = 40;
    LOG(WARNING) << "Unable to get title constant for  " << message_token
                 << ". Defaulting to " << title_height;
  }
  int desc_height;
  if (!GetDimension("DESC_" + message_token + "_HEIGHT", &desc_height)) {
    desc_height = 40;
    LOG(WARNING) << "Unable to get description constant for  " << message_token
                 << ". Defaulting to " << desc_height;
  }

  const int kTitleY = (-frecon_canvas_size_ / 2) + 220 + (title_height / 2);
  const int kDescY = kTitleY + (title_height / 2) + 16 + (desc_height / 2);
  if (!ShowMessage("title_" + message_token, kXOffset, kTitleY))
    LOG(WARNING) << "Unable to show title " << message_token;
  if (!ShowMessage("desc_" + message_token, kXOffset, kDescY))
    LOG(WARNING) << "Unable to show description " << message_token;
}

int DrawUtils::FindLocaleIndex(int current_index) {
  auto locale =
      std::find(supported_locales_.begin(), supported_locales_.end(), locale_);
  if (locale == supported_locales_.end()) {
    // Default to en-US.
    LOG(WARNING) << " Could not find an index to match current locale "
                 << locale_ << ". Defaulting to index " << kEnglishIndex
                 << " for " << supported_locales_[kEnglishIndex];
    return kEnglishIndex;
  }
  return std::distance(supported_locales_.begin(), locale);
}

void DrawUtils::ShowProgressBar(int offset_x,
                                int size_x,
                                const std::string& color) {
  // No-op if offset is outside the bounds of the canvas.
  if (offset_x > frecon_offset_limit_ || offset_x < -frecon_offset_limit_)
    return;

  const int offset_y = -frecon_canvas_size_ / kProgressBarYScale;
  // Clamp to the right boundary of the canvas.
  const int max_x = offset_x + (size_x / 2);
  if (max_x > frecon_offset_limit_) {
    size_x = nearbyeven(frecon_offset_limit_ - (offset_x - (size_x / 2)));
    offset_x = frecon_offset_limit_ - (size_x / 2);
  }
  // Clamp to the left boundary of the canvas.
  const int min_x = offset_x - (size_x / 2);
  if (min_x < -frecon_offset_limit_) {
    size_x = nearbyeven((offset_x + (size_x / 2)) - (-frecon_offset_limit_));
    offset_x = -frecon_offset_limit_ + (size_x / 2);
  }
  ShowBox(offset_x, offset_y, size_x, kProgressBarHeight, color);
}

void DrawUtils::ShowProgressBar() {
  ShowProgressBar(kFreconNoOffset, frecon_canvas_size_, kMenuGrey);
}

void DrawUtils::ShowProgressPercentage(double progress) {
  if (progress < 0 || progress > 1) {
    LOG(WARNING) << "Invalid value of progress: " << progress;
    return;
  }
  // Should be at canvas width at 100%.
  const double kProgressIncrement = frecon_canvas_size_ / 100.0;
  const int kLeftIncrement = -frecon_canvas_size_ / 2;
  int progress_length = kProgressIncrement * progress * 100;
  ShowProgressBar(kLeftIncrement + progress_length / 2, progress_length,
                  kMenuBlue);
}

void DrawUtils::ShowIndeterminateProgressBar() {
  InitIndeterminateProgressBar();
  // Show background for progress bar.
  ShowProgressBar();
  timer_.Start(FROM_HERE, kAnimationPeriod, this,
               &DrawUtils::DrawIndeterminateProgressBar);
}

void DrawUtils::HideIndeterminateProgressBar() {
  timer_.AbandonAndStop();
  // Clear progress bar.
  ShowProgressBar(kFreconNoOffset, frecon_canvas_size_, kMenuBlack);
}

void DrawUtils::InitIndeterminateProgressBar() {
  // Calculate segment sizes as even numbers.
  segment_size_head_ =
      nearbyeven(frecon_canvas_size_ / kProgressBarHeadSegments);
  segment_size_tail_ =
      nearbyeven(frecon_canvas_size_ / kProgressBarTailSegments);
  ResetIndeterminateProgressBar();
}

void DrawUtils::ResetIndeterminateProgressBar() {
  constexpr int tail_delay = 20;
  indeterminate_progress_bar_head_ = -frecon_offset_limit_;
  indeterminate_progress_bar_tail_ =
      -frecon_offset_limit_ - (tail_delay * segment_size_tail_);
}

void DrawUtils::DrawIndeterminateProgressBar() {
  indeterminate_progress_bar_head_ += (segment_size_head_ / 2);
  ShowProgressBar(indeterminate_progress_bar_head_, segment_size_head_,
                  kMenuBlue);
  indeterminate_progress_bar_tail_ += (segment_size_tail_ / 2);
  ShowProgressBar(indeterminate_progress_bar_tail_, segment_size_tail_,
                  kMenuGrey);

  // Move offset to 5/6 of box just drawn so that there is 1/6 overlap instead
  // of 1/2 overlap with the next box to be drawn.
  indeterminate_progress_bar_head_ +=
      std::nearbyint((segment_size_head_ / 6.0) * 2.0f);
  indeterminate_progress_bar_tail_ +=
      std::nearbyint((segment_size_tail_ / 6.0) * 2.0f);
  if (indeterminate_progress_bar_tail_ > frecon_offset_limit_) {
    ResetIndeterminateProgressBar();
  }
}

void DrawUtils::ClearMainArea() {
  constexpr int kFooterHeight = 142;
  if (!ShowBox(0, -kFooterHeight / 2, frecon_canvas_size_ + 200,
               (frecon_canvas_size_ - kFooterHeight), kMenuBlack))
    LOG(WARNING) << "Could not clear main area.";
}

void DrawUtils::ClearScreen() {
  if (!ShowBox(0, 0, frecon_canvas_size_ + 100, frecon_canvas_size_,
               kMenuBlack))
    LOG(WARNING) << "Could not clear screen.";
}

void DrawUtils::ShowButton(const std::string& message_token,
                           int offset_y,
                           bool is_selected,
                           int inner_width,
                           bool is_text) {
  const int kBtnPadding = 32;  // Left and right padding.
  int left_padding_x = (-frecon_canvas_size_ / 2) + (kBtnPadding / 2);
  const int kOffsetX = left_padding_x + (kBtnPadding / 2) + (inner_width / 2);
  int right_padding_x = kOffsetX + (kBtnPadding / 2) + (inner_width / 2);
  // Clear previous state.
  if (!ShowBox(kOffsetX, offset_y, (kBtnPadding * 2 + inner_width),
               kButtonHeight, kMenuBlack)) {
    LOG(WARNING) << "Could not clear button area.";
  }

  if (IsLocaleRightToLeft()) {
    std::swap(left_padding_x, right_padding_x);
  }

  if (is_selected) {
    ShowImage(screens_path_.Append("btn_bg_left_focused.png"), left_padding_x,
              offset_y);
    ShowImage(screens_path_.Append("btn_bg_right_focused.png"), right_padding_x,
              offset_y);

    ShowBox(kOffsetX, offset_y, inner_width, kButtonHeight, kMenuBlue);
    if (is_text) {
      ShowText(message_token, left_padding_x, offset_y, "black");
    } else {
      ShowMessage(message_token + "_focused", kOffsetX, offset_y);
    }
  } else {
    ShowImage(screens_path_.Append("btn_bg_left.png"), left_padding_x,
              offset_y);
    ShowImage(screens_path_.Append("btn_bg_right.png"), right_padding_x,
              offset_y);
    ShowBox(kOffsetX, offset_y - (kButtonHeight / 2) + 1, inner_width, 1,
            kMenuButtonFrameGrey);
    ShowBox(kOffsetX, offset_y + (kButtonHeight / 2), inner_width, 1,
            kMenuButtonFrameGrey);
    if (is_text) {
      ShowText(message_token, left_padding_x, offset_y, "white");
    } else {
      ShowMessage(message_token, kOffsetX, offset_y);
    }
  }
}

void DrawUtils::ShowStepper(const std::vector<std::string>& steps) {
  // The icon real size is 24x24, but it occupies a 36x36 block. Use 36 here for
  // simplicity.
  constexpr int kIconSize = 36;
  constexpr int kSeparatorLength = 46;
  constexpr int kPadding = 6;

  int stepper_x = (-frecon_canvas_size_ / 2) + (kIconSize / 2);
  constexpr int kStepperXStep = kIconSize + kSeparatorLength + (kPadding * 2);
  const int kStepperY = 144 - (frecon_canvas_size_ / 2);
  int separator_x = (-frecon_canvas_size_ / 2) + kIconSize + kPadding +
                    (kSeparatorLength / 2);

  for (const auto& step : steps) {
    base::FilePath stepper_image = screens_path_.Append("ic_" + step + ".png");
    if (!base::PathExists(stepper_image)) {
      // TODO(vyshu): Create a new generic icon to be used instead of done.
      LOG(WARNING) << "Stepper icon " << stepper_image
                   << " not found. Defaulting to the done icon.";
      stepper_image = screens_path_.Append("ic_done.png");
      if (!base::PathExists(stepper_image)) {
        LOG(ERROR) << "Could not find stepper icon done. Cannot show stepper.";
        return;
      }
    }
    ShowImage(stepper_image, stepper_x, kStepperY);
    stepper_x += kStepperXStep;
  }

  for (int i = 0; i < steps.size() - 1; ++i) {
    ShowBox(separator_x, kStepperY, kSeparatorLength, 1, kMenuGrey);
    separator_x += kStepperXStep;
  }
}

void DrawUtils::ShowLanguageDropdown(int current_index) {
  constexpr int kItemHeight = 40;
  const int kItemPerPage = (frecon_canvas_size_ - 260) / kItemHeight;

  // Pick begin index such that the selected index is centered on the screen if
  // possible.
  int begin_index =
      std::clamp(current_index - kItemPerPage / 2, 0,
                 static_cast<int>(supported_locales_.size()) - kItemPerPage);

  int offset_y = -frecon_canvas_size_ / 2 + 88;
  const int kBackgroundX = -frecon_canvas_size_ / 2 + 360;
  for (int i = begin_index;
       i < (begin_index + kItemPerPage) && i < supported_locales_.size(); i++) {
    // Get placement for the language image.
    int language_width;
    if (!GetLangConstants(supported_locales_[i], &language_width)) {
      language_width = 95;
      LOG(WARNING) << "Could not get width for " << supported_locales_[i]
                   << ". Defaulting to " << language_width;
    }
    int lang_x = -frecon_canvas_size_ / 2 + language_width / 2 + 40;

    // This is the currently selected language. Show in blue.
    if (current_index == i) {
      ShowBox(kBackgroundX, offset_y, 720, 40, kMenuBlue);
      ShowImage(screens_path_.Append(supported_locales_[i])
                    .Append("language_focused.png"),
                lang_x, offset_y);
    } else {
      ShowBox(kBackgroundX, offset_y, 720, 40, kMenuDropdownFrameNavy);
      ShowBox(kBackgroundX, offset_y, 718, 38, kMenuDropdownBackgroundBlack);
      ShowImage(
          screens_path_.Append(supported_locales_[i]).Append("language.png"),
          lang_x, offset_y);
    }
    offset_y += kItemHeight;
  }
}

void DrawUtils::ShowLanguageMenu(bool is_selected) {
  const int kOffsetY = -frecon_canvas_size_ / 2 + 40;
  const int kBgX = -frecon_canvas_size_ / 2 + 145;
  const int kGlobeX = -frecon_canvas_size_ / 2 + 20;
  const int kArrowX = -frecon_canvas_size_ / 2 + 268;
  int language_width;
  if (!GetLangConstants(locale_, &language_width)) {
    language_width = 100;
    LOG(WARNING) << "Could not get language width for " << locale_
                 << ". Defaulting to 100.";
  }
  const int kTextX = -frecon_canvas_size_ / 2 + 40 + language_width / 2;

  base::FilePath menu_background =
      is_selected ? screens_path_.Append("language_menu_bg_focused.png")
                  : screens_path_.Append("language_menu_bg.png");

  ShowImage(menu_background, kBgX, kOffsetY);
  ShowImage(screens_path_.Append("ic_language_filled-bg.png"), kGlobeX,
            kOffsetY);

  ShowImage(screens_path_.Append("ic_dropdown.png"), kArrowX, kOffsetY);
  ShowMessage("language_folded", kTextX, kOffsetY);
}

void DrawUtils::ShowAdvancedOptionsButtons(bool focused) {
  const int kOffsetY = frecon_canvas_size_ / 2 - 222;

  int power_btn_width;
  GetDimension("BUTTON_btn_power_off_WIDTH", &power_btn_width);
  const int kInnerWidth = power_btn_width + 60;
  const int kBtnCenter = (-frecon_canvas_size_ + kInnerWidth) / 2;

  // Clear previous state.
  ShowBox(kBtnCenter, kOffsetY, kInnerWidth + 40, kButtonHeight, kMenuBlack);

  int left_padding_x = (-frecon_canvas_size_ - 12) / 2;
  int right_padding_x = (-frecon_canvas_size_ + 8) / 2 + kInnerWidth;
  if (IsLocaleRightToLeft())
    std::swap(left_padding_x, right_padding_x);

  if (focused) {
    ShowImage(screens_path_.Append("adv_btn_bg_left.png"), left_padding_x,
              kOffsetY);
    ShowImage(screens_path_.Append("adv_btn_bg_right.png"), right_padding_x,
              kOffsetY);
    // Box outline created when button is focused.
    ShowBox(kBtnCenter - 4, kOffsetY, kInnerWidth + 2, kButtonHeight,
            kMenuBlue);
    ShowBox(kBtnCenter - 4, kOffsetY, kInnerWidth + 2, kButtonHeight - 4,
            kAdvancedBtnBackground);
  }

  std::string power_icon = focused ? "power_focused.png" : "power.png";
  ShowImage(screens_path_.Append(power_icon), -frecon_canvas_size_ / 2 + 10,
            kOffsetY);

  std::string power_token = focused ? "btn_power_off_focused" : "btn_power_off";
  ShowMessage(power_token, -frecon_canvas_size_ / 2 + 36 + power_btn_width / 2,
              kOffsetY);

  std::string arrow =
      IsLocaleRightToLeft() ? "ic_dropleft-blue" : "ic_dropright-blue";
  arrow = focused ? arrow.append("_focused.png") : arrow.append(".png");

  ShowImage(screens_path_.Append(arrow),
            -frecon_canvas_size_ / 2 + 58 + power_btn_width, kOffsetY);
}

void DrawUtils::ShowFooter() {
  constexpr int kQrCodeSize = 86;
  const int kQrCodeX = (-frecon_canvas_size_ / 2) + (kQrCodeSize / 2);
  const int kQrCodeY = (frecon_canvas_size_ / 2) - (kQrCodeSize / 2) - 56;

  const int kSeparatorX = 410 - (frecon_canvas_size_ / 2);
  const int kSeparatorY = kQrCodeY;
  constexpr int kFooterLineHeight = 18;

  const int kFooterY = (frecon_canvas_size_ / 2) - kQrCodeSize + 9 - 56;
  const int kFooterLeftX =
      kQrCodeX + (kQrCodeSize / 2) + 16 + (kDefaultMessageWidth / 2);
  const int kFooterRightX = kSeparatorX + 32 + (kDefaultMessageWidth / 2);

  ShowMessage("footer_left_1", kFooterLeftX, kFooterY);
  ShowMessage("footer_left_2", kFooterLeftX,
              kFooterY + kFooterLineHeight * 2 + 14);
  ShowMessage("footer_left_3", kFooterLeftX,
              kFooterY + kFooterLineHeight * 3 + 14);

  constexpr int kNavButtonHeight = 24;
  const int kNavButtonY =
      (frecon_canvas_size_ / 2) - (kNavButtonHeight / 2) - 56;
  int nav_btn_x = kSeparatorX + 32;
  // Navigation key icons.
  const std::string kFooterType = is_detachable_ ? "tablet" : "clamshell";
  const std::string kNavKeyEnter =
      is_detachable_ ? "button_power" : "key_enter";
  const std::string kNavKeyUp = is_detachable_ ? "button_volume_up" : "key_up";
  const std::string kNavKeyDown =
      is_detachable_ ? "button_volume_down" : "key_down";

  constexpr int kUpDownIconWidth = 24;
  constexpr int kIconPadding = 8;
  const int kEnterIconWidth = is_detachable_ ? 40 : 66;

  ShowMessage("footer_right_1_" + kFooterType, kFooterRightX, kFooterY);
  ShowMessage("footer_right_2_" + kFooterType, kFooterRightX,
              kFooterY + kFooterLineHeight + 8);

  nav_btn_x += kEnterIconWidth / 2;
  ShowImage(screens_path_.Append("nav-" + kNavKeyEnter + ".png"), nav_btn_x,
            kNavButtonY);
  nav_btn_x += kEnterIconWidth / 2 + kIconPadding + kUpDownIconWidth / 2;
  ShowImage(screens_path_.Append("nav-" + kNavKeyUp + ".png"), nav_btn_x,
            kNavButtonY);
  nav_btn_x += kIconPadding + kUpDownIconWidth;
  ShowImage(screens_path_.Append("nav-" + kNavKeyDown + ".png"), nav_btn_x,
            kNavButtonY);

  ShowImage(screens_path_.Append("qr_code.png"), kQrCodeX, kQrCodeY);
  int hwid_len = hwid_.size();
  int hwid_x = kQrCodeX + (kQrCodeSize / 2) + 16 + 5;
  const int kHwidY = kFooterY + kFooterLineHeight;

  if (IsLocaleRightToLeft()) {
    hwid_x = -hwid_x - kMonospaceGlyphWidth * (hwid_len - 2);
  }

  ShowText(hwid_, hwid_x, kHwidY, "grey");
  ShowBox(kSeparatorX, kSeparatorY, 1, kQrCodeSize, kMenuGrey);
}

void DrawUtils::LocaleChange(int selected_locale) {
  // Change locale and update constants.
  locale_ = supported_locales_[selected_locale];
  ReadDimensionConstants();
  ClearScreen();
  ShowFooter();
}

void DrawUtils::MessageBaseScreen() {
  ClearMainArea();
  ShowLanguageMenu(false);
  ShowFooter();
}

void DrawUtils::ReadDimensionConstants() {
  image_dimensions_.clear();
  base::FilePath path = screens_path_.Append(locale_).Append("constants.sh");
  std::string dimension_consts;
  if (!ReadFileToString(path, &dimension_consts)) {
    LOG(ERROR) << "Could not read constants.sh file for language " << locale_;
    return;
  }
  if (!base::SplitStringIntoKeyValuePairs(dimension_consts, '=', '\n',
                                          &image_dimensions_)) {
    LOG(WARNING) << "Unable to parse all dimension information for " << locale_;
    return;
  }

  // Save default button width for this locale.
  if (!GetDimension(kButtonWidthToken, &default_button_width_)) {
    default_button_width_ = kDefaultButtonWidth;
    LOG(WARNING) << "Unable to get dimension for " << kButtonWidthToken
                 << ". Defaulting to width " << kDefaultButtonWidth;
  }
}

bool DrawUtils::GetDimension(const std::string& token, int* token_dimension) {
  if (image_dimensions_.empty()) {
    LOG(ERROR) << "No dimensions available.";
    return false;
  }

  // Find the dimension for the token.
  for (const auto& dimension : image_dimensions_) {
    if (dimension.first == token) {
      if (!base::StringToInt(dimension.second, token_dimension)) {
        LOG(ERROR) << "Could not convert " << dimension.second
                   << " to a number.";
        return false;
      }
      return true;
    }
  }
  return false;
}

void DrawUtils::GetFreconConstants() {
  base::FilePath scale_factor_path =
      root_.Append("etc").Append("frecon").Append("scale");
  std::string frecon_scale_factor;
  if (!ReadFileToString(scale_factor_path, &frecon_scale_factor)) {
    frecon_scale_factor_ = kFreconScalingFactor;
    LOG(WARNING) << "Could not read frecon scale factor from /etc. Defaulting "
                    "to scale "
                 << kFreconScalingFactor;
  } else {
    base::TrimString(frecon_scale_factor, " \n", &frecon_scale_factor);
    if (!base::StringToInt(frecon_scale_factor, &frecon_scale_factor_)) {
      frecon_scale_factor_ = kFreconScalingFactor;
      LOG(WARNING) << "Could not convert " << frecon_scale_factor_
                   << " to an int. Defaulting to scale "
                   << kFreconScalingFactor;
    }
  }

  base::FilePath canvas_size_path =
      root_.Append("etc").Append("frecon").Append("size");
  std::string frecon_canvas_size;
  if (!ReadFileToString(canvas_size_path, &frecon_canvas_size)) {
    frecon_canvas_size_ = kCanvasSize;
    LOG(WARNING) << "Could not read frecon canvas size from /etc/frecon."
                 << " Defaulting to canvas size " << kCanvasSize;
  } else {
    base::TrimString(frecon_canvas_size, " \n", &frecon_canvas_size);
    if (!base::StringToInt(frecon_canvas_size, &frecon_canvas_size_)) {
      frecon_canvas_size_ = kCanvasSize;
      LOG(WARNING) << "Could not convert " << frecon_canvas_size
                   << " to int. Defaulting to canvas size " << kCanvasSize;
    }
  }
  frecon_offset_limit_ = frecon_canvas_size_ / 2;
}

bool DrawUtils::ReadLangConstants() {
  lang_constants_.clear();
  supported_locales_.clear();
  // Read language widths from lang_constants.sh into memory.
  auto lang_constants_path = screens_path_.Append("lang_constants.sh");
  if (!base::PathExists(lang_constants_path)) {
    LOG(ERROR) << "Language constants path: " << lang_constants_path
               << " not found.";
    return false;
  }

  std::string const_values;
  if (!ReadFileToString(lang_constants_path, &const_values)) {
    LOG(ERROR) << "Could not read lang constants file " << lang_constants_path;
    return false;
  }

  if (!base::SplitStringIntoKeyValuePairs(const_values, '=', '\n',
                                          &lang_constants_)) {
    LOG(ERROR) << "Unable to parse language width information.";
    return false;
  }
  for (const auto& pair : lang_constants_) {
    if (pair.first == "SUPPORTED_LOCALES") {
      // Parse list of supported locales and store separately.
      std::string locale_list;
      if (!base::RemoveChars(pair.second, "\"", &locale_list))
        LOG(WARNING) << "Unable to remove surrounding quotes from locale list.";
      supported_locales_ = base::SplitString(
          locale_list, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    }
  }

  if (supported_locales_.empty()) {
    LOG(ERROR) << "Unable to get supported locales. Will not be able to "
                  "change locale.";
    return false;
  }
  return true;
}

bool DrawUtils::GetLangConstants(const std::string& locale, int* lang_width) {
  if (lang_constants_.empty()) {
    LOG(ERROR) << "No language widths available.";
    return false;
  }

  // Lang_consts uses '_' while supported locale list uses '-'.
  std::string token;
  base::ReplaceChars(locale, "-", "_", &token);
  token = "LANGUAGE_" + token + "_WIDTH";

  // Find the width for the token.
  for (const auto& width_token : lang_constants_) {
    if (width_token.first == token) {
      if (!base::StringToInt(width_token.second, lang_width)) {
        LOG(ERROR) << "Could not convert " << width_token.second
                   << " to a number.";
        return false;
      }
      return true;
    }
  }
  return false;
}

bool DrawUtils::IsLocaleRightToLeft() {
  return (locale_ == "ar" || locale_ == "fa" || locale_ == "he");  // nocheck
}

bool DrawUtils::IsDetachable() {
  is_detachable_ =
      base::PathExists(root_.Append("etc/cros-initramfs/is_detachable"));
  return is_detachable_;
}

void DrawUtils::ReadHardwareId() {
  int exit_code = 0;
  std::string output, error;
  if (!process_manager_->RunCommandWithOutput({"/bin/crossystem", "hwid"},
                                              &exit_code, &output, &error) ||
      exit_code) {
    hwid_ = "CHROMEBOOK";
    PLOG(WARNING)
        << "Could not get hwid from crossystem. Exited with exit code "
        << exit_code << " and error " << error
        << ". Defaulting to 'CHROMEBOOK'.";
    return;
  }

  // Truncate HWID.
  std::vector<std::string> hwid_parts = base::SplitString(
      output, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  hwid_ = hwid_parts[0];
  return;
}

}  // namespace minios
