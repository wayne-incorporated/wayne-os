// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <linux/input.h>

#include <utility>

#include <base/test/mock_log.h>
#include <brillo/message_loops/fake_message_loop.h>
#include <gtest/gtest.h>

#include "minios/draw_interface.h"
#include "minios/mock_draw_interface.h"
#include "minios/mock_network_manager.h"
#include "minios/mock_process_manager.h"
#include "minios/mock_screen_interface.h"
#include "minios/mock_state_reporter_interface.h"
#include "minios/mock_update_engine_proxy.h"
#include "minios/screen_controller.h"
#include "minios/utils.h"

using testing::_;
using testing::HasSubstr;
using ::testing::NiceMock;

namespace minios {

class ScreenControllerTest : public ::testing::Test {
 public:
  void SetUp() override {
    loop_.SetAsCurrent();
    screen_controller_.SetCurrentScreenForTest(ScreenType::kWelcomeScreen);
  }

 protected:
  std::shared_ptr<MockDrawInterface> draw_interface_ =
      std::make_shared<NiceMock<MockDrawInterface>>();
  std::shared_ptr<MockUpdateEngineProxy> mock_update_engine_proxy_ =
      std::make_shared<NiceMock<MockUpdateEngineProxy>>();
  MockScreenInterface mock_screen_;
  std::shared_ptr<NetworkManagerInterface> mock_network_manager_ =
      std::make_shared<NiceMock<MockNetworkManager>>();
  MockProcessManager process_manager_;
  ScreenController screen_controller_{draw_interface_,
                                      mock_update_engine_proxy_,
                                      mock_network_manager_, &process_manager_};

  base::SimpleTestClock clock_;
  brillo::FakeMessageLoop loop_{&clock_};
};

TEST_F(ScreenControllerTest, VerifyInitFailueNoDrawUtil) {
  // Setup a mock logger to ensure alert is printed on a failed connect.
  base::test::MockLog mock_log;
  mock_log.StartCapturingLogs();

  EXPECT_CALL(*draw_interface_, Init()).WillOnce(testing::Return(false));

  // Logger expectation.
  EXPECT_CALL(mock_log, Log(::logging::LOGGING_ERROR, _, _, _,
                            HasSubstr(AlertLogTag(kCategoryInit).c_str())));

  EXPECT_FALSE(screen_controller_.Init());
}

TEST_F(ScreenControllerTest, OnForward) {
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kWelcomeScreen));
  screen_controller_.OnForward(&mock_screen_);
  EXPECT_EQ(ScreenType::kNetworkDropDownScreen,
            screen_controller_.GetCurrentScreen());

  // Go ask for user permission after getting network info.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kNetworkDropDownScreen));
  screen_controller_.OnForward(&mock_screen_);
  EXPECT_EQ(ScreenType::kUserPermissionScreen,
            screen_controller_.GetCurrentScreen());

  // Forward from error screen goes to debug options.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kGeneralError));
  screen_controller_.OnForward(&mock_screen_);
  EXPECT_EQ(ScreenType::kDebugOptionsScreen,
            screen_controller_.GetCurrentScreen());

  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kDebugOptionsScreen));
  screen_controller_.OnForward(&mock_screen_);
  EXPECT_EQ(ScreenType::kLogScreen, screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, OnBackward) {
  // Backward from log screen goes to debug options.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kLogScreen));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kDebugOptionsScreen,
            screen_controller_.GetCurrentScreen());

  // Permission denied goes back to the start screen.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kUserPermissionScreen));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kWelcomeScreen, screen_controller_.GetCurrentScreen());

  screen_controller_.SetCurrentScreenForTest(
      ScreenType::kNetworkDropDownScreen);
  // Password screen goes back to the first network screen.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kPasswordError));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kNetworkDropDownScreen,
            screen_controller_.GetCurrentScreen());

  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kNetworkDropDownScreen));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kWelcomeScreen, screen_controller_.GetCurrentScreen());

  // Cannot go back from `kWelcomeScreen'.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kWelcomeScreen));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kWelcomeScreen, screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, ChangeLocale) {
  screen_controller_.SetCurrentScreenForTest(
      ScreenType::kNetworkDropDownScreen);

  screen_controller_.SwitchLocale(&mock_screen_);
  EXPECT_EQ(ScreenType::kLanguageDropDownScreen,
            screen_controller_.GetCurrentScreen());

  // Return from language dropdown, return to original screen.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kLanguageDropDownScreen));
  screen_controller_.UpdateLocale(&mock_screen_, /*index=*/1);
  EXPECT_EQ(ScreenType::kNetworkDropDownScreen,
            screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, CancelChangeLocale) {
  screen_controller_.SetCurrentScreenForTest(
      ScreenType::kNetworkDropDownScreen);

  screen_controller_.SwitchLocale(&mock_screen_);
  EXPECT_EQ(ScreenType::kLanguageDropDownScreen,
            screen_controller_.GetCurrentScreen());

  // Cancel language dropdown selection, return to original screen.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kLanguageDropDownScreen));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kNetworkDropDownScreen,
            screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, NullScreenCancelChangeLocale) {
  screen_controller_.SwitchLocale(nullptr);
  EXPECT_EQ(ScreenType::kLanguageDropDownScreen,
            screen_controller_.GetCurrentScreen());

  // Cancel language dropdown selection, return to welcome screen.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kLanguageDropDownScreen));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kWelcomeScreen, screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, RestartFromDownloadError) {
  // Starting from Download error screen.
  screen_controller_.SetCurrentScreenForTest(ScreenType::kDownloadError);
  EXPECT_EQ(ScreenType::kDownloadError, screen_controller_.GetCurrentScreen());

  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kDownloadError));
  screen_controller_.OnBackward(&mock_screen_);

  // Back to start screen.
  EXPECT_EQ(ScreenType::kWelcomeScreen, screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, RestartFromNetworkError) {
  // Starting from network error screen.
  screen_controller_.SetCurrentScreenForTest(ScreenType::kNetworkError);

  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kNetworkError));
  screen_controller_.OnBackward(&mock_screen_);

  // Back to dropdown.
  EXPECT_EQ(ScreenType::kNetworkDropDownScreen,
            screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, RestartFromPasswordError) {
  // Start from password error screen.
  screen_controller_.SetCurrentScreenForTest(
      ScreenType::kNetworkDropDownScreen);
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kPasswordError));
  screen_controller_.OnBackward(&mock_screen_);

  // Back to dropdown.
  EXPECT_EQ(ScreenType::kNetworkDropDownScreen,
            screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, DebugOptionsToError) {
  // Going back from debug options should return to the error screen it was
  // called from.
  screen_controller_.SetCurrentScreenForTest(ScreenType::kNetworkError);
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kNetworkError));
  screen_controller_.OnForward(&mock_screen_);
  EXPECT_EQ(ScreenType::kDebugOptionsScreen,
            screen_controller_.GetCurrentScreen());

  // Go to log screen.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kDebugOptionsScreen));
  screen_controller_.OnForward(&mock_screen_);
  EXPECT_EQ(ScreenType::kLogScreen, screen_controller_.GetCurrentScreen());

  // Go back all the way to the original error screen.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kLogScreen));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kDebugOptionsScreen,
            screen_controller_.GetCurrentScreen());

  // Back to `kNetworkError`.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kDebugOptionsScreen));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kNetworkError, screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, DebugOptionsBackInvalid) {
  // Going back from debug options should return to the error screen it was
  // called from, but if there is no valid error screen, go back to the
  // beginning.
  EXPECT_CALL(mock_screen_, GetType())
      .WillOnce(testing::Return(ScreenType::kDebugOptionsScreen));
  screen_controller_.OnBackward(&mock_screen_);
  EXPECT_EQ(ScreenType::kWelcomeScreen, screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, GetState) {
  State state;
  std::unique_ptr<MockScreenInterface> mock_screen =
      std::make_unique<MockScreenInterface>();
  EXPECT_CALL(*mock_screen, GetState);
  screen_controller_.SetCurrentScreenForTest(std::move(mock_screen));
  screen_controller_.GetState(&state);
}

TEST_F(ScreenControllerTest, MoveBackward) {
  std::unique_ptr<MockScreenInterface> mock_screen =
      std::make_unique<MockScreenInterface>();
  EXPECT_CALL(*mock_screen, MoveBackward(nullptr))
      .WillOnce(testing::Return(true));
  screen_controller_.SetCurrentScreenForTest(std::move(mock_screen));
  EXPECT_TRUE(screen_controller_.MoveBackward(nullptr));
}

TEST_F(ScreenControllerTest, MoveForward) {
  std::unique_ptr<MockScreenInterface> mock_screen =
      std::make_unique<MockScreenInterface>();
  EXPECT_CALL(*mock_screen, MoveForward(nullptr))
      .WillOnce(testing::Return(true));
  screen_controller_.SetCurrentScreenForTest(std::move(mock_screen));
  EXPECT_TRUE(screen_controller_.MoveForward(nullptr));
}

TEST_F(ScreenControllerTest, PressKey) {
  std::unique_ptr<MockScreenInterface> mock_screen =
      std::make_unique<MockScreenInterface>();
  EXPECT_CALL(*mock_screen, OnKeyPress(KEY_ENTER));
  screen_controller_.SetCurrentScreenForTest(std::move(mock_screen));
  screen_controller_.PressKey(KEY_ENTER);
}

TEST_F(ScreenControllerTest, Reset) {
  screen_controller_.SetCurrentScreenForTest(
      ScreenType::kNetworkDropDownScreen);
  EXPECT_TRUE(screen_controller_.Reset(nullptr));
  EXPECT_EQ(ScreenType::kWelcomeScreen, screen_controller_.GetCurrentScreen());

  // Reset should fail on download page.
  screen_controller_.SetCurrentScreenForTest(ScreenType::kStartDownload);
  EXPECT_FALSE(screen_controller_.Reset(nullptr));
  EXPECT_EQ(ScreenType::kStartDownload, screen_controller_.GetCurrentScreen());
}

TEST_F(ScreenControllerTest, OnStateChanged) {
  MockStateReporterInterface state_reporter;
  EXPECT_CALL(state_reporter, StateChanged)
      .WillOnce(testing::Invoke([](const State& state) -> void {
        EXPECT_EQ(State::CONNECTED, state.state());
      }));
  screen_controller_.SetStateReporter(&state_reporter);
  State state;
  state.set_state(State::CONNECTED);
  screen_controller_.OnStateChanged(state);
}

}  // namespace minios
