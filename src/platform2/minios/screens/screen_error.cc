// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/screens/screen_error.h"

#include <linux/input.h>

#include <base/logging.h>

#include "minios/draw_utils.h"
#include "minios/utils.h"

namespace minios {

ScreenError::ScreenError(ScreenType error_screen,
                         std::shared_ptr<DrawInterface> draw_utils,
                         ScreenControllerInterface* screen_controller)
    : ScreenBase(
          /*button_count=*/4,
          /*index_=*/1,
          State::ERROR,
          draw_utils,
          screen_controller),
      error_screen_(error_screen) {}

std::string ScreenError::GetErrorMessage() {
  switch (error_screen_) {
    case ScreenType::kDownloadError:
      return "MiniOS_download_error";
    case ScreenType::kNetworkError:
      return "MiniOS_network_error";
    case ScreenType::kPasswordError:
      return "MiniOS_password_error";
    case ScreenType::kConnectionError:
      return "MiniOS_connection_error";
    case ScreenType::kGeneralError:
      return "MiniOS_general_error";
    default:
      LOG(FATAL) << "Not a valid error screen.";
      return "";
  }
}

void ScreenError::Show() {
  draw_utils_->MessageBaseScreen();
  std::string error_message = GetErrorMessage();

  base::FilePath error_path_title =
      draw_utils_->GetScreenPath().Append("en-US").Append(
          "title_" + error_message + ".png");
  base::FilePath error_path_desc =
      draw_utils_->GetScreenPath().Append("en-US").Append(
          "desc_" + error_message + ".png");
  if (!base::PathExists(error_path_title) ||
      !base::PathExists(error_path_desc)) {
    LOG(WARNING) << "Could not find error " << error_message;
    error_message = "MiniOS_general_error";
  }

  draw_utils_->ShowInstructionsWithTitle(error_message);
  ShowButtons();
  SetState(State::ERROR);
}

void ScreenError::ShowButtons() {
  draw_utils_->ShowLanguageMenu(index_ == 0);
  const int kBtnY =
      (-draw_utils_->GetFreconCanvasSize() / 2) + 318 + kBtnYStep * 2;
  draw_utils_->ShowButton("btn_try_again", kBtnY, index_ == 1,
                          draw_utils_->GetDefaultButtonWidth(), false);
  draw_utils_->ShowButton("btn_MiniOS_advanced_options", kBtnY + kBtnYStep,
                          index_ == 2, draw_utils_->GetDefaultButtonWidth(),
                          false);
  draw_utils_->ShowAdvancedOptionsButtons(index_ == 3);
}

void ScreenError::OnKeyPress(int key_changed) {
  bool enter = false;
  UpdateButtonsIndex(key_changed, &enter);
  if (enter) {
    switch (index_) {
      case 0:
        screen_controller_->SwitchLocale(this);
        break;
      case 1:
        screen_controller_->OnBackward(this);
        break;
      case 2:
        screen_controller_->OnForward(this);
        break;
      case 3:
        TriggerShutdown();
        break;
      default:
        LOG(FATAL) << "Index " << index_ << " is not valid.";
    }
  } else {
    ShowButtons();
  }
}

void ScreenError::Reset() {
  index_ = 1;
}

ScreenType ScreenError::GetType() {
  return error_screen_;
}

std::string ScreenError::GetName() {
  switch (error_screen_) {
    case ScreenType::kDownloadError:
      return "ScreenDownloadError";
    case ScreenType::kNetworkError:
      return "ScreenNetworkError";
    case ScreenType::kPasswordError:
      return "ScreenPasswordError";
    case ScreenType::kConnectionError:
      return "ScreenConnectionError";
    case ScreenType::kGeneralError:
      return "ScreenGeneralError";
    default:
      LOG(ERROR) << "Not a valid error screen.";
      return "";
  }
}

bool ScreenError::MoveForward(brillo::ErrorPtr* error) {
  index_ = 2;
  OnKeyPress(KEY_ENTER);
  return true;
}

bool ScreenError::MoveBackward(brillo::ErrorPtr* error) {
  index_ = 1;
  OnKeyPress(KEY_ENTER);
  return true;
}

}  // namespace minios
