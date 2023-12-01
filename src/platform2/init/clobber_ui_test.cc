// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/clobber_ui.h"

#include <string>
#include <utility>

#include <base/time/time.h>
#include <gtest/gtest.h>

namespace {

base::TimeDelta BuildTimeDelta(int hours, int minutes, int seconds) {
  return base::Hours(hours) + base::Minutes(minutes) + base::Seconds(seconds);
}

}  // namespace

TEST(BuildUiString, NoProgressBarEmpty) {
  base::TimeDelta elapsed = BuildTimeDelta(0, 40, 27);
  double progress = 0.0;
  std::string ui_string = ClobberUi::BuildUiStringForTest(0, elapsed, progress);
  EXPECT_NE(ui_string.find("0:40:27"), std::string::npos);
  EXPECT_NE(ui_string.find("0%"), std::string::npos);
}

TEST(BuildUiString, NoProgressBarStarted) {
  base::TimeDelta elapsed = BuildTimeDelta(0, 21, 0);
  double progress = 0.27;
  std::string ui_string = ClobberUi::BuildUiStringForTest(0, elapsed, progress);
  EXPECT_NE(ui_string.find("0:21:00"), std::string::npos);
  EXPECT_NE(ui_string.find("27%"), std::string::npos);
}

TEST(BuildUiString, NoProgressBarFinishing) {
  base::TimeDelta elapsed = BuildTimeDelta(1, 0, 7);
  double progress = 0.95;
  std::string ui_string = ClobberUi::BuildUiStringForTest(0, elapsed, progress);
  EXPECT_NE(ui_string.find("1:00:07"), std::string::npos);
  EXPECT_NE(ui_string.find("95%"), std::string::npos);
}

TEST(BuildUiString, NoProgressBarFinished) {
  base::TimeDelta elapsed = BuildTimeDelta(12, 2, 14);
  double progress = 1.0;
  std::string ui_string = ClobberUi::BuildUiStringForTest(0, elapsed, progress);
  EXPECT_NE(ui_string.find("12:02:14"), std::string::npos);
  EXPECT_NE(ui_string.find("100%"), std::string::npos);
}

TEST(BuildUiString, WithProgressBarEmpty) {
  int terminal_width = 80;
  base::TimeDelta elapsed = BuildTimeDelta(0, 40, 27);
  double progress = 0.0;
  std::string ui_string =
      ClobberUi::BuildUiStringForTest(terminal_width, elapsed, progress);
  EXPECT_NE(ui_string.find("0:40:27"), std::string::npos);
  EXPECT_NE(ui_string.find("0%"), std::string::npos);
}

TEST(BuildUiString, WithProgressBarStarted) {
  int terminal_width = 80;
  base::TimeDelta elapsed = BuildTimeDelta(0, 21, 0);
  double progress = 0.27;
  std::string ui_string =
      ClobberUi::BuildUiStringForTest(terminal_width, elapsed, progress);
  EXPECT_NE(ui_string.find("0:21:00"), std::string::npos);
  EXPECT_NE(ui_string.find("27%"), std::string::npos);
}

TEST(BuildUiString, WithProgressBarFinishing) {
  int terminal_width = 80;
  base::TimeDelta elapsed = BuildTimeDelta(1, 0, 7);
  double progress = 0.95;
  std::string ui_string =
      ClobberUi::BuildUiStringForTest(terminal_width, elapsed, progress);
  EXPECT_NE(ui_string.find("1:00:07"), std::string::npos);
  EXPECT_NE(ui_string.find("95%"), std::string::npos);
}

TEST(BuildUiString, WithProgressBarFinished) {
  base::TimeDelta elapsed = BuildTimeDelta(12, 2, 14);
  double progress = 1.0;
  std::string ui_string = ClobberUi::BuildUiStringForTest(0, elapsed, progress);
  EXPECT_NE(ui_string.find("12:02:14"), std::string::npos);
  EXPECT_NE(ui_string.find("100%"), std::string::npos);
}

TEST(CallSequencing, WipeProgress) {
  base::File dev_null(base::FilePath("/dev/null"),
                      base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  ClobberUi ui(std::move(dev_null));
  base::TimeDelta zero = base::Seconds(0);
  ASSERT_TRUE(ui.ShowCountdownTimer(zero));
  ASSERT_TRUE(ui.StartWipeUi(100));
  ASSERT_FALSE(ui.ShowCountdownTimer(zero));
  ASSERT_TRUE(ui.UpdateWipeProgress(50));
  ASSERT_FALSE(ui.ShowCountdownTimer(zero));
  ASSERT_TRUE(ui.UpdateWipeProgress(100));
  ASSERT_FALSE(ui.ShowCountdownTimer(zero));
  ASSERT_TRUE(ui.StopWipeUi());
  ASSERT_TRUE(ui.ShowCountdownTimer(zero));
}
