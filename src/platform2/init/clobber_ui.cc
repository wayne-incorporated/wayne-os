// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/clobber_ui.h"

#include <inttypes.h>
#include <sys/ioctl.h>
#include <termios.h>

#include <string>
#include <utility>

#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace {

bool MakeTTYRaw(const base::File& tty) {
  struct termios terminal_properties;
  if (tcgetattr(tty.GetPlatformFile(), &terminal_properties) != 0) {
    PLOG(WARNING) << "Getting properties of output TTY failed";
    return false;
  }

  cfmakeraw(&terminal_properties);
  if (tcsetattr(tty.GetPlatformFile(), TCSANOW, &terminal_properties) != 0) {
    PLOG(WARNING) << "Setting properties of output TTY failed";
    return false;
  }
  return true;
}

bool GetTerminalWidth(const base::File& terminal, int* width_out) {
  if (!width_out) {
    LOG(ERROR) << "width_out cannot be NULL";
    return false;
  }

  struct winsize window_size;
  int ret = ioctl(terminal.GetPlatformFile(), TIOCGWINSZ, &window_size);
  if (ret) {
    PLOG(ERROR) << "TIOCGWINSZ ioctl failed";
    return false;
  }

  *width_out = window_size.ws_col;
  return true;
}

// If |terminal_width| is non-zero, we will display a progress bar based
// on that width value. Otherwise, we will not display a progress bar.
std::string BuildUiString(int terminal_width,
                          const base::TimeDelta& elapsed,
                          double progress) {
  std::string elapsed_time =
      base::StringPrintf("%d:%02d:%02" PRIi64, elapsed.InHours(),
                         elapsed.InMinutes() % 60, elapsed.InSeconds() % 60);
  std::string percent_done = base::StringPrintf("%3.0f%%", progress * 100);

  // Determine how much space we would have for a progress bar in our terminal.
  int progress_bar_width = 0;
  if (terminal_width > 0) {
    // Subtract 2 for padding spaces and 2 for bounding brackets.
    progress_bar_width =
        terminal_width - elapsed_time.length() - percent_done.length() - 2 - 2;
  }

  // Only show a progress bar if we have space.
  if (progress_bar_width > 0) {
    std::string progress_bar(progress_bar_width * progress, '=');
    if (progress_bar.length() < progress_bar_width) {
      // If we haven't filled up the width, add a '>' to the end of the
      // progress bar and pad with zeros to fill the width.
      progress_bar += ">";
      progress_bar +=
          std::string(progress_bar_width - progress_bar.length(), ' ');
    }
    return elapsed_time + " [" + progress_bar + "] " + percent_done;
  } else {
    return elapsed_time + " " + percent_done;
  }
}

}  // namespace

ClobberUi::ClobberUi(base::File&& terminal)
    : terminal_(std::move(terminal)), mode_(kIdle) {
  if (!MakeTTYRaw(terminal_)) {
    LOG(ERROR) << "Failed to set terminal to raw mode.";
  }
}

bool ClobberUi::StartWipeUi(int64_t bytes_to_write) {
  if (!wipe_ui_thread_.is_null()) {
    LOG(ERROR) << "UI is already running.";
    return false;
  }
  mode_ = kWipeUi;

  base::AutoLock auto_lock(lock_);
  state_.running = true;
  state_.total_bytes_written = 0;
  state_.bytes_to_write = bytes_to_write;
  if (!base::PlatformThread::Create(0, this, &wipe_ui_thread_)) {
    LOG(ERROR) << "Failed to create wipe UI thread.";
    return false;
  }

  return true;
}

bool ClobberUi::UpdateWipeProgress(int64_t total_bytes_written) {
  base::AutoLock auto_lock(lock_);
  if (wipe_ui_thread_.is_null() || mode_ != kWipeUi || !state_.running) {
    LOG(ERROR) << "Cannot update progress, wipe UI is not running.";
    return false;
  }

  state_.total_bytes_written = total_bytes_written;
  return true;
}

bool ClobberUi::StopWipeUi() {
  if (wipe_ui_thread_.is_null()) {
    LOG(ERROR) << "Failed to stop wipe UI, thread is not running.";
    return false;
  }

  if (mode_ != kWipeUi) {
    LOG(ERROR) << "Failed to stop wipe UI, current UI is not a wipe UI.";
    return false;
  }

  {
    base::AutoLock auto_lock(lock_);
    if (!state_.running) {
      LOG(ERROR) << "Failed to stop wipe UI, wipe UI is already being stopped.";
      return false;
    }
    state_.running = false;
  }

  base::PlatformThread::Join(wipe_ui_thread_);
  wipe_ui_thread_ = base::PlatformThreadHandle();
  mode_ = kIdle;
  return true;
}

bool ClobberUi::ShowCountdownTimer(const base::TimeDelta& duration) {
  if (mode_ != kIdle) {
    LOG(ERROR) << "Failed to show countdown timer, UI is already in use.";
    return false;
  }
  mode_ = kCountdownUi;

  base::TimeTicks start_time = base::TimeTicks::Now();
  base::TimeDelta elapsed = base::TimeTicks::Now() - start_time;
  while (elapsed < duration) {
    base::TimeDelta remaining = duration - elapsed;
    std::string countdown =
        base::StringPrintf("%2d:%02" PRIi64 "\r", remaining.InMinutes(),
                           remaining.InSeconds() % 60);
    terminal_.WriteAtCurrentPos(countdown.c_str(), countdown.size());
    base::PlatformThread::Sleep(base::Milliseconds(100));
    elapsed = base::TimeTicks::Now() - start_time;
  }

  mode_ = kIdle;
  return true;
}

// static
std::string ClobberUi::BuildUiStringForTest(int terminal_width,
                                            const base::TimeDelta& elapsed,
                                            double progress) {
  return BuildUiString(terminal_width, elapsed, progress);
}

void ClobberUi::ThreadMain() {
  base::TimeTicks start_time = base::TimeTicks::Now();
  base::AutoLock auto_lock(lock_);
  bool show_progress_bar = true;
  while (state_.running) {
    base::TimeDelta elapsed = base::TimeTicks::Now() - start_time;
    double progress =
        static_cast<double>(state_.total_bytes_written) / state_.bytes_to_write;

    int terminal_width = 0;
    if (show_progress_bar && !GetTerminalWidth(terminal_, &terminal_width)) {
      LOG(WARNING)
          << "Getting terminal width failed. No progress bar will be shown.";
      show_progress_bar = false;
    }
    std::string output = BuildUiString(terminal_width, elapsed, progress);

    terminal_.WriteAtCurrentPos("\r", 1);
    terminal_.WriteAtCurrentPos(output.c_str(), output.size());

    {
      base::AutoUnlock auto_unlock(lock_);
      base::PlatformThread::Sleep(base::Milliseconds(100));
    }
  }
}
