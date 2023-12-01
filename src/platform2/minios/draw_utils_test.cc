// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/file_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "minios/draw_utils.h"
#include "minios/mock_draw_utils.h"
#include "minios/mock_process_manager.h"

using testing::_;

namespace minios {

class DrawUtilsTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_root_ = temp_dir_.GetPath().value();
    draw_utils_.SetRootForTest(test_root_);

    screens_path_ = base::FilePath(test_root_).Append("etc/screens");

    base::FilePath locale_dir_en =
        base::FilePath(screens_path_).Append("en-US");
    ASSERT_TRUE(base::CreateDirectory(locale_dir_en));
    base::FilePath locale_dir_fr = base::FilePath(screens_path_).Append("fr");
    ASSERT_TRUE(CreateDirectory(locale_dir_fr));
    // Create and write constants file.
    std::string token_consts =
        "TITLE_minios_token_HEIGHT=38 \nDESC_minios_token_HEIGHT=44\n"
        "DESC_screen_token_HEIGHT=incorrect\nDEBUG_OPTIONS_BTN_WIDTH=99\n";
    ASSERT_TRUE(
        base::WriteFile(locale_dir_en.Append("constants.sh"), token_consts));

    // Create directories.
    ASSERT_TRUE(
        base::CreateDirectory(base::FilePath(test_root_).Append("run/frecon")));
    console_ = base::FilePath(test_root_).Append("run/frecon/vt0");
    ASSERT_TRUE(base::WriteFile(console_, ""));
    ASSERT_TRUE(CreateDirectory(
        base::FilePath(screens_path_).Append("glyphs").Append("white")));
    ASSERT_TRUE(base::CreateDirectory(
        base::FilePath(test_root_).Append("usr/share/misc")));
  }

 protected:
  // Test directory.
  base::ScopedTempDir temp_dir_;
  // Path to output pts.
  base::FilePath console_;
  // Path to /etc/screens in test directory.
  base::FilePath screens_path_;
  std::string test_root_;
  MockProcessManager mock_process_manager_;
  DrawUtils draw_utils_{&mock_process_manager_};
};

TEST_F(DrawUtilsTest, ShowText) {
  EXPECT_TRUE(draw_utils_.ShowText("chrome", 200, -100, "white"));

  std::string written_command;
  EXPECT_TRUE(ReadFileToString(console_, &written_command));
  std::string expected_command =
      "\x1B]image:file=" + test_root_ + "/etc/screens/glyphs/" +
      "white/99.png;offset=200,-100;scale=1\a\x1B]image:file=" + test_root_ +
      "/etc/screens/glyphs/white/"
      "104.png;offset=210,-100;scale=1\a\x1B]image:file=" +
      test_root_ +
      "/etc/screens/glyphs/white/"
      "114.png;offset=220,-100;scale=1\a\x1B]image:file=" +
      test_root_ +
      "/etc/screens/glyphs/white/"
      "111.png;offset=230,-100;scale=1\a\x1B]image:file=" +
      test_root_ +
      "/etc/screens/glyphs/white/"
      "109.png;offset=240,-100;scale=1\a\x1B]image:file=" +
      test_root_ +
      "/etc/screens/glyphs/white/"
      "101.png;offset=250,-100;scale=1\a";
  EXPECT_EQ(expected_command, written_command);
}

TEST_F(DrawUtilsTest, ShowImageTest) {
  EXPECT_TRUE(draw_utils_.ShowImage(
      base::FilePath(test_root_).Append("image.png"), 50, 20));

  std::string written_command;
  EXPECT_TRUE(ReadFileToString(console_, &written_command));
  EXPECT_EQ(
      "\x1B]image:file=" + test_root_ + "/image.png;offset=50,20;scale=1\a",
      written_command);
}

TEST_F(DrawUtilsTest, ShowImageRtl) {
  draw_utils_.SetLanguageForTest("ar");
  EXPECT_TRUE(draw_utils_.ShowImage(
      base::FilePath(test_root_).Append("image.png"), 50, 10));

  std::string written_command;
  EXPECT_TRUE(ReadFileToString(console_, &written_command));
  EXPECT_EQ(
      "\x1B]image:file=" + test_root_ + "/image.png;offset=-50,10;scale=1\a",
      written_command);
}

TEST_F(DrawUtilsTest, ShowBox) {
  EXPECT_TRUE(draw_utils_.ShowBox(-100, -200, 50, 40, "0x8AB4F8"));
  std::string written_command;
  EXPECT_TRUE(ReadFileToString(console_, &written_command));
  EXPECT_EQ("\x1B]box:color=0x8AB4F8;size=50,40;offset=-100,-200;scale=1\a",
            written_command);
}

TEST_F(DrawUtilsTest, ShowBoxRtl) {
  // Set locale to be read right to left.
  draw_utils_.SetLanguageForTest("ar");
  EXPECT_TRUE(draw_utils_.ShowBox(-100, -200, 50, 20, "0x8AB4F8"));
  std::string written_command;
  EXPECT_TRUE(ReadFileToString(console_, &written_command));
  // X offset should be inverted.
  EXPECT_EQ("\x1B]box:color=0x8AB4F8;size=50,20;offset=100,-200;scale=1\a",
            written_command);
}

TEST_F(DrawUtilsTest, ShowMessage) {
  brillo::TouchFile(screens_path_.Append("fr").Append("minios_token.png"));

  // Override language to french.
  draw_utils_.SetLanguageForTest("fr");
  EXPECT_TRUE(draw_utils_.ShowMessage("minios_token", 0, 20));

  std::string written_command;
  EXPECT_TRUE(ReadFileToString(console_, &written_command));
  EXPECT_EQ("\x1B]image:file=" + test_root_ +
                "/etc/screens/fr/minios_token.png;offset=0,20;scale=1\a",
            written_command);
}

TEST_F(DrawUtilsTest, ShowMessageFallback) {
  // Create french and english image files.
  brillo::TouchFile(screens_path_.Append("fr").Append("not_minios_token.png"));
  brillo::TouchFile(screens_path_.Append("en-US").Append("minios_token.png"));

  // Override language to french.
  draw_utils_.SetLanguageForTest("fr");
  EXPECT_TRUE(draw_utils_.ShowMessage("minios_token", 0, 20));

  // French token does not exist, fall back to english token.
  std::string written_command;
  EXPECT_TRUE(ReadFileToString(console_, &written_command));
  EXPECT_EQ("\x1B]image:file=" + test_root_ +
                "/etc/screens/en-US/minios_token.png;offset=0,20;scale=1\a",
            written_command);
}

TEST_F(DrawUtilsTest, InstructionsWithTitle) {
  // Create english title and description tokens.
  brillo::TouchFile(
      screens_path_.Append("en-US").Append("title_minios_token.png"));
  brillo::TouchFile(
      screens_path_.Append("en-US").Append("desc_minios_token.png"));

  draw_utils_.ReadDimensionConstants();
  draw_utils_.ShowInstructionsWithTitle("minios_token");

  std::string written_command;
  EXPECT_TRUE(ReadFileToString(console_, &written_command));
  std::string expected_command =
      "\x1B]image:file=" + test_root_ +
      "/etc/screens/en-US/"
      "title_minios_token.png;offset=-180,-301;scale=1\a\x1B]image:file=" +
      test_root_ +
      "/etc/screens/en-US/desc_minios_token.png;offset=-180,-244;scale=1\a";

  EXPECT_EQ(expected_command, written_command);
}

TEST_F(DrawUtilsTest, ReadDimension) {
  std::string token_consts =
      "TITLE_minios_token_HEIGHT=\nDESC_minios_token_HEIGHT=44\nDESC_"
      "screen_token_HEIGHT=incorrect\n screen_whitespace_HEIGHT=  77  \n";
  ASSERT_TRUE(base::WriteFile(
      base::FilePath(screens_path_).Append("fr").Append("constants.sh"),
      token_consts));

  // Loads French dimension constants into memory.
  draw_utils_.SetLanguageForTest("fr");

  EXPECT_EQ(4, draw_utils_.image_dimensions_.size());
  EXPECT_EQ("  77", draw_utils_.image_dimensions_[3].second);
}

TEST_F(DrawUtilsTest, GetDimension) {
  draw_utils_.ReadDimensionConstants();
  int dimension;
  EXPECT_FALSE(draw_utils_.GetDimension("DESC_invalid_HEIGHT", &dimension));
  EXPECT_FALSE(draw_utils_.GetDimension("incorrect_DESC_minios_token_HEIGHT",
                                        &dimension));
  // Not a number.
  EXPECT_FALSE(
      draw_utils_.GetDimension("DESC_screen_token_HEIGHT", &dimension));

  // Correctly returns the dimension.
  EXPECT_TRUE(
      draw_utils_.GetDimension("TITLE_minios_token_HEIGHT", &dimension));
  EXPECT_EQ(38, dimension);
}

TEST_F(DrawUtilsTest, GetLangConsts) {
  std::string lang_consts =
      "LANGUAGE_en_US_WIDTH=99\nLANGUAGE_fi_WIDTH=44\nLANGUAGE_mr_WIDTH="
      "incorrect\n LANGUAGE_ko_WIDTH=  77 \n  SUPPORTED_LOCALES=\"en-US fi mr "
      "ko\"";
  ASSERT_TRUE(
      base::WriteFile(screens_path_.Append("lang_constants.sh"), lang_consts));
  EXPECT_TRUE(draw_utils_.ReadLangConstants());

  EXPECT_EQ(5, draw_utils_.lang_constants_.size());
  EXPECT_EQ(4, draw_utils_.GetSupportedLocalesSize());
  int lang_width;
  EXPECT_TRUE(draw_utils_.GetLangConstants("en-US", &lang_width));
  EXPECT_EQ(99, lang_width);
  // Incorrect or doesn't exist.
  EXPECT_FALSE(draw_utils_.GetLangConstants("fr", &lang_width));
  EXPECT_FALSE(draw_utils_.GetLangConstants("mr", &lang_width));
}

TEST_F(DrawUtilsTest, CheckRightToLeft) {
  draw_utils_.SetLanguageForTest("fr");
  EXPECT_FALSE(draw_utils_.IsLocaleRightToLeft());

  // Three languages are read from right to left.
  draw_utils_.SetLanguageForTest("he");
  EXPECT_TRUE(draw_utils_.IsLocaleRightToLeft());

  draw_utils_.SetLanguageForTest("fa");
  EXPECT_TRUE(draw_utils_.IsLocaleRightToLeft());

  draw_utils_.SetLanguageForTest("ar");
  EXPECT_TRUE(draw_utils_.IsLocaleRightToLeft());
}

TEST_F(DrawUtilsTest, GetLangConstsError) {
  std::string lang_consts =
      "LANGUAGE_en_US_WIDTH=99\nLANGUAGE_fi_WIDTH=44\nLANGUAGE_mr_WIDTH="
      "incorrect\n LANGUAGE_ko_WIDTH=  77 \n  SUPPORTED_LOCALES=";
  ASSERT_TRUE(
      base::WriteFile(screens_path_.Append("lang_constants.sh"), lang_consts));
  EXPECT_FALSE(draw_utils_.ReadLangConstants());
}

TEST_F(DrawUtilsTest, CheckDetachable) {
  EXPECT_FALSE(draw_utils_.IsDetachable());

  brillo::TouchFile(
      base::FilePath(test_root_).Append("etc/cros-initramfs/is_detachable"));

  EXPECT_TRUE(draw_utils_.IsDetachable());
}

TEST_F(DrawUtilsTest, GetHwidFromCommand) {
  std::string output = "Nightfury TEST ID";
  EXPECT_CALL(mock_process_manager_, RunCommandWithOutput(_, _, _, _))
      .WillOnce(testing::DoAll(testing::SetArgPointee<2>(output),
                               testing::Return(true)));
  draw_utils_.ReadHardwareId();
  // Returns truncated hwid.
  EXPECT_EQ(draw_utils_.hwid_, "Nightfury");
}

TEST_F(DrawUtilsTest, GetHwidFromDefault) {
  EXPECT_CALL(mock_process_manager_, RunCommandWithOutput(_, _, _, _))
      .WillOnce(testing::Return(false));
  draw_utils_.ReadHardwareId();
  EXPECT_EQ(draw_utils_.hwid_, "CHROMEBOOK");
}

TEST_F(DrawUtilsTest, GetFreconConstFile) {
  std::string frecon_scale_factor = "2";
  std::string frecon_canvas_size = "1100";
  ASSERT_TRUE(CreateDirectory(
      base::FilePath(test_root_).Append("etc").Append("frecon")));
  ASSERT_TRUE(
      base::WriteFile(base::FilePath(test_root_).Append("etc/frecon/scale"),
                      frecon_scale_factor));
  ASSERT_TRUE(
      base::WriteFile(base::FilePath(test_root_).Append("etc/frecon/size"),
                      frecon_canvas_size));

  draw_utils_.GetFreconConstants();
  EXPECT_EQ(draw_utils_.frecon_scale_factor_, 2);
  EXPECT_EQ(draw_utils_.frecon_canvas_size_, 1100);
}

TEST_F(DrawUtilsTest, GetFreconConstNoInt) {
  // Set  the values to be incorrectly formatted.
  std::string frecon_scale_factor = " not a scale ";
  std::string frecon_canvas_size = " not a number ";
  ASSERT_TRUE(CreateDirectory(
      base::FilePath(test_root_).Append("etc").Append("frecon")));
  ASSERT_TRUE(
      base::WriteFile(base::FilePath(test_root_).Append("etc/frecon/scale"),
                      frecon_scale_factor));
  ASSERT_TRUE(
      base::WriteFile(base::FilePath(test_root_).Append("etc/frecon/size"),
                      frecon_canvas_size));

  draw_utils_.GetFreconConstants();
  // Keeps default value.
  EXPECT_EQ(draw_utils_.frecon_scale_factor_, kFreconScalingFactor);
  EXPECT_EQ(draw_utils_.frecon_canvas_size_, kCanvasSize);
}

TEST_F(DrawUtilsTest, GetFreconConstNoFile) {
  // Should keep the default value.
  draw_utils_.GetFreconConstants();
  EXPECT_EQ(draw_utils_.frecon_scale_factor_, kFreconScalingFactor);
  EXPECT_EQ(draw_utils_.frecon_canvas_size_, kCanvasSize);
}

class DrawUtilsTestMocks : public ::testing::Test {
 public:
  void SetUp() override {
    base::ScopedTempDir temp_dir_;
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    screens_path_ = base::FilePath(temp_dir_.GetPath()).Append(kScreens);
    brillo::TouchFile(screens_path_.Append("en-US").Append("constants.sh"));
    mock_draw_utils_.SetRootForTest(temp_dir_.GetPath().value());
  }

 protected:
  base::FilePath screens_path_;
  MockDrawUtils mock_draw_utils_;
};

TEST_F(DrawUtilsTestMocks, ShowButtonFocused) {
  const int offset_y = 50;
  const int inner_width = 45;
  std::string message = "btn_enter";

  // Clear the button area.
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, offset_y, _, _, kMenuBlack))
      .WillRepeatedly(testing::Return(true));

  // Show button.
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("btn_bg_left_focused.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("btn_bg_right_focused.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, offset_y, inner_width, _, kMenuBlue))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowMessage(message + "_focused", _, offset_y))
      .WillOnce(testing::Return(true));

  brillo::TouchFile(
      screens_path_.Append("en-US").Append(message + "_focused.png"));
  mock_draw_utils_.ShowButton(message, offset_y, /*focus=*/true, inner_width,
                              false);
}

TEST_F(DrawUtilsTestMocks, ShowButton) {
  const int offset_y = 50;
  const int inner_width = 45;
  const std::string message = "btn_enter";

  // Clear the button area.
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, offset_y, _, _, kMenuBlack))
      .WillRepeatedly(testing::Return(true));

  // Show button.
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("btn_bg_left.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("btn_bg_right.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowMessage(message, _, offset_y))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, _, _, _, kMenuButtonFrameGrey))
      .Times(2)
      .WillRepeatedly(testing::Return(true));

  brillo::TouchFile(screens_path_.Append("en-US").Append(message + ".png"));
  mock_draw_utils_.ShowButton(message, offset_y, /*focus=*/false, inner_width,
                              false);
}

TEST_F(DrawUtilsTestMocks, ShowButtonTextFocused) {
  const int offset_y = 50;
  const int inner_width = 45;
  std::string text_message = "enter";

  // Clear the button area.
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, offset_y, _, _, kMenuBlack))
      .WillRepeatedly(testing::Return(true));

  // Show button.
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("btn_bg_left_focused.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("btn_bg_right_focused.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, offset_y, inner_width, _, kMenuBlue))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowText(text_message, _, _, "black"))
      .WillOnce(testing::Return(true));

  mock_draw_utils_.ShowButton(text_message, offset_y, /*focus=*/true,
                              inner_width, true);
}

TEST_F(DrawUtilsTestMocks, ShowButtonText) {
  const int offset_y = 50;
  const int inner_width = 45;
  const std::string text_message = "btn_enter";

  // Clear the button area.
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, offset_y, _, _, kMenuBlack))
      .WillRepeatedly(testing::Return(true));

  // Show button.
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("btn_bg_left.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("btn_bg_right.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowText(text_message, _, _, "white"))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, _, _, _, kMenuButtonFrameGrey))
      .Times(2)
      .WillRepeatedly(testing::Return(true));

  mock_draw_utils_.ShowButton(text_message, offset_y, /*focus=*/false,
                              inner_width, true);
}

TEST_F(DrawUtilsTestMocks, ShowStepper) {
  const std::string step1 = "done";
  const std::string step2 = "2";
  const std::string step3 = "error";

  // Create icons.
  brillo::TouchFile(screens_path_.Append("ic_" + step1 + ".png"));
  brillo::TouchFile(screens_path_.Append("ic_" + step2 + ".png"));
  brillo::TouchFile(screens_path_.Append("ic_" + step3 + ".png"));

  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("ic_" + step1 + ".png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("ic_" + step2 + ".png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("ic_" + step3 + ".png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, _, _, _, kMenuGrey))
      .Times(2)
      .WillRepeatedly(testing::Return(true));

  mock_draw_utils_.ShowStepper({step1, step2, step3});
}

TEST_F(DrawUtilsTestMocks, ShowStepperError) {
  brillo::TouchFile(screens_path_.Append("ic_done.png"));

  const std::string step1 = "done";
  const std::string step2 = "2";
  const std::string step3 = "error";

  // Stepper icons not found. Default to done.
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("ic_done.png"), _, _))
      .Times(3)
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, _, _, _, kMenuGrey))
      .Times(2)
      .WillRepeatedly(testing::Return(true));
  mock_draw_utils_.ShowStepper({step1, step2, step3});
}

TEST_F(DrawUtilsTestMocks, ShowLanguageMenu) {
  EXPECT_CALL(
      mock_draw_utils_,
      ShowImage(screens_path_.Append("language_menu_bg_focused.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(
      mock_draw_utils_,
      ShowImage(screens_path_.Append("ic_language_filled-bg.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_,
              ShowImage(screens_path_.Append("ic_dropdown.png"), _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowMessage("language_folded", _, _))
      .WillOnce(testing::Return(true));

  mock_draw_utils_.ShowLanguageMenu(/* focus=*/true);
}

TEST_F(DrawUtilsTestMocks, ShowFooter) {
  // Show left and right footer components.
  EXPECT_CALL(mock_draw_utils_,
              ShowMessage(testing::StartsWith("footer_left"), _, _))
      .Times(3)
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_,
              ShowMessage(testing::StartsWith("footer_right"), _, _))
      .Times(2)
      .WillRepeatedly(testing::Return(true));

  // Show key icons and QR code and HWID text glyphs.
  EXPECT_CALL(mock_draw_utils_, ShowImage(_, _, _))
      .Times(testing::AnyNumber())
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, _, _, _, kMenuGrey))
      .WillOnce(testing::Return(true));

  mock_draw_utils_.ShowFooter();
}

TEST_F(DrawUtilsTestMocks, ShowProgressPercentage) {
  // Invalid progress percentage doesn't show anything.
  mock_draw_utils_.ShowProgressPercentage(1.1);

  // Otherwise will show box.
  EXPECT_CALL(mock_draw_utils_, ShowBox(_, _, _, _, _))
      .WillOnce(testing::Return(true));
  mock_draw_utils_.ShowProgressPercentage(.5);
}

}  // namespace minios
