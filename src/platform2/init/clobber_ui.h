// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_CLOBBER_UI_H_
#define INIT_CLOBBER_UI_H_

#include <cstdlib>
#include <memory>
#include <string>

#include <base/files/file.h>
#include <base/synchronization/lock.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>

// ClobberUi's public class methods are not thread-safe.
class ClobberUi : private base::PlatformThread::Delegate {
 public:
  explicit ClobberUi(base::File&& terminal);

  bool StartWipeUi(int64_t bytes_to_write);
  bool UpdateWipeProgress(int64_t total_bytes_written);
  bool StopWipeUi();

  bool ShowCountdownTimer(const base::TimeDelta& duration);

  static std::string BuildUiStringForTest(int terminal_width,
                                          const base::TimeDelta& elapsed,
                                          double progress);

 private:
  // base::PlatformThread::Delegate interface.
  void ThreadMain() override;

  enum UiMode {
    kIdle,         // No UI is currently being displayed.
    kWipeUi,       // The disk wipe progress UI is being shown.
    kCountdownUi,  // A countdown timer UI is being shown.
  };

  struct WipeState {
    bool running;
    int64_t total_bytes_written;
    int64_t bytes_to_write;
  };

  base::File terminal_;

  base::PlatformThreadHandle wipe_ui_thread_;
  UiMode mode_;
  base::Lock lock_;
  WipeState state_;  // Protected by lock_.
};

#endif  // INIT_CLOBBER_UI_H_
