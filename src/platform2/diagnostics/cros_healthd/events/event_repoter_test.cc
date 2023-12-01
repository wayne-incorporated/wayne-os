// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/events/event_reporter.h"
#include "diagnostics/cros_healthd/events/mock_event_observer.h"
#include "diagnostics/cros_healthd/system/fake_mojo_service.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/external/input.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::Invoke;

class EventReporterTest : public testing::Test {
  void SetUp() {
    mock_context_.fake_mojo_service()->InitializeFakeMojoService();
    event_reporter_ = std::make_unique<EventReporter>(&mock_context_);
    event_reporter_->AddObserver(
        mock_observer_.receiver().BindNewPipeAndPassRemote());
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  MockContext mock_context_;
  std::unique_ptr<EventReporter> event_reporter_;
  testing::StrictMock<MockEventObserver> mock_observer_;
};

TEST_F(EventReporterTest, KeyboardDiagnostic) {
  auto keyboard_diagnostic_event_info =
      ash::diagnostics::mojom::KeyboardDiagnosticEventInfo::New();
  keyboard_diagnostic_event_info->keyboard_info =
      ash::diagnostics::mojom::KeyboardInfo::New();

  base::RunLoop run_loop;
  EXPECT_CALL(mock_observer_, OnEvent(_))
      .WillOnce(Invoke([&](mojom::EventInfoPtr info) {
        EXPECT_TRUE(info->is_keyboard_diagnostic_event_info());
        EXPECT_EQ(info->get_keyboard_diagnostic_event_info(),
                  keyboard_diagnostic_event_info);
        run_loop.Quit();
      }));

  event_reporter_->SendKeyboardDiagnosticEvent(
      keyboard_diagnostic_event_info.Clone());
  run_loop.Run();
}

}  // namespace
}  // namespace diagnostics
