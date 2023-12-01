// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <base/test/test_future.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/fetchers/input_fetcher.h"
#include "diagnostics/cros_healthd/system/fake_mojo_service.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/cros_healthd/utils/mojo_task_environment.h"
#include "diagnostics/mojom/external/cros_healthd_internal.mojom.h"

namespace diagnostics {
namespace {

namespace internal_mojom = ::ash::cros_healthd::internal::mojom;
namespace mojom = ::ash::cros_healthd::mojom;

class InputFetcherTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_context_.fake_mojo_service()->InitializeFakeMojoService();
  }

  mojom::InputResultPtr FetchInput() {
    base::test::TestFuture<mojom::InputResultPtr> future;
    input_fetcher_.Fetch(future.GetCallback());
    return future.Take();
  }

  FakeChromiumDataCollector& fake_chromium_data_collector() {
    return mock_context_.fake_mojo_service()->fake_chromium_data_collector();
  }

  MojoTaskEnvironment env_;
  MockContext mock_context_;
  InputFetcher input_fetcher_{&mock_context_};
};

TEST_F(InputFetcherTest, FetchTouchscreenDevices) {
  auto fake_device = internal_mojom::TouchscreenDevice::New();
  fake_device->input_device = internal_mojom::InputDevice::New();
  fake_device->input_device->name = "FakeName";
  fake_device->input_device->connection_type =
      internal_mojom::InputDevice::ConnectionType::kBluetooth;
  fake_device->input_device->physical_location = "physical_location";
  fake_device->input_device->is_enabled = true;
  fake_device->input_device->sysfs_path = "sysfs_path";
  fake_device->touch_points = 42;
  fake_device->has_stylus = true;
  fake_device->has_stylus_garage_switch = true;
  fake_chromium_data_collector().touchscreen_devices().push_back(
      fake_device.Clone());

  auto expected_device = mojom::TouchscreenDevice::New();
  expected_device->input_device = mojom::InputDevice::New();
  expected_device->input_device->name = "FakeName";
  expected_device->input_device->connection_type =
      mojom::InputDevice::ConnectionType::kBluetooth;
  expected_device->input_device->physical_location = "physical_location";
  expected_device->input_device->is_enabled = true;
  expected_device->touch_points = 42;
  expected_device->has_stylus = true;
  expected_device->has_stylus_garage_switch = true;

  auto result = FetchInput();
  EXPECT_EQ(result->get_input_info()->touchscreen_devices.size(), 1);
  EXPECT_EQ(result->get_input_info()->touchscreen_devices[0], expected_device);
}

TEST_F(InputFetcherTest, FetchTouchpadLibraryName) {
  fake_chromium_data_collector().touchpad_library_name() =
      "FakeTouchpadLibraryName";

  auto result = FetchInput();
  EXPECT_EQ(result->get_input_info()->touchpad_library_name,
            "FakeTouchpadLibraryName");
}

TEST_F(InputFetcherTest, FetchFailed) {
  // Reset the receiver to emulate the service disconnected.
  fake_chromium_data_collector().receiver().reset();

  auto result = FetchInput();
  EXPECT_EQ(result->get_error()->type, mojom::ErrorType::kServiceUnavailable);
}

}  // namespace
}  // namespace diagnostics
