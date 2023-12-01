// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_SCREENS_SCREEN_LOG_H_
#define MINIOS_SCREENS_SCREEN_LOG_H_

#include <memory>
#include <string>
#include <vector>

#include "minios/screens/screen_base.h"

namespace minios {

class ScreenLog : public ScreenBase {
 public:
  ScreenLog(std::shared_ptr<DrawInterface> draw_utils,
            ScreenControllerInterface* screen_controller);

  ~ScreenLog() = default;

  ScreenLog(const ScreenLog&) = delete;
  ScreenLog& operator=(const ScreenLog&) = delete;

  void Show() override;
  void Reset() override;
  void OnKeyPress(int key_changed) override;
  ScreenType GetType() override;
  std::string GetName() override;
  bool MoveBackward(brillo::ErrorPtr* error) override;

 private:
  // Updates buttons with current selection.
  void ShowButtons();

  // Updates the logs shown based on the up/down buttons pressed.
  void UpdateLogArea();

  // Used to keep track of the log to display.
  base::FilePath log_path_;
  // Used to keep track of the byte offsets in the file.
  size_t log_offset_idx_ = 0;
  std::vector<int64_t> log_offsets_ = {0};
};

}  // namespace minios

#endif  // MINIOS_SCREENS_SCREEN_LOG_H_
