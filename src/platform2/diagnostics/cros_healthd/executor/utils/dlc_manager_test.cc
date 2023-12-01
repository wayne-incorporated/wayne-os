// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/errors/error.h>
#include <dbus/mock_object_proxy.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>
// NOLINTNEXTLINE(build/include_alpha) dbus-proxy-mocks.h needs dlcservice.pb.h
#include <dlcservice/dbus-proxy-mocks.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/executor/utils/dlc_manager.h"

namespace diagnostics {
namespace {

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::WithArg;
using ::testing::WithArgs;
using ::testing::WithoutArgs;

class DlcManagerTest : public testing::Test {
 protected:
  DlcManagerTest() = default;
  DlcManagerTest(const DlcManagerTest&) = delete;
  DlcManagerTest& operator=(const DlcManagerTest&) = delete;

  void SetUp() override {
    dlc_service_object_proxy_ =
        new dbus::MockObjectProxy(nullptr, "", dbus::ObjectPath("/"));
    ON_CALL(mock_dlc_service_, GetObjectProxy())
        .WillByDefault(Return(dlc_service_object_proxy_.get()));
  }

  std::optional<base::FilePath> GetBinaryRootPathSync(
      const std::string& dlc_id) {
    base::test::TestFuture<std::optional<base::FilePath>> future;
    dlc_manager_.GetBinaryRootPath(dlc_id, future.GetCallback());
    return future.Get();
  }

  void SetDlcServiceAvailability(bool available) {
    EXPECT_CALL(*dlc_service_object_proxy_.get(),
                DoWaitForServiceToBeAvailable(_))
        .WillOnce(WithArg<0>(
            [=](dbus::ObjectProxy::WaitForServiceToBeAvailableCallback*
                    callback) { std::move(*callback).Run(available); }));
  }

  void SetRegisterDlcStateChangedCall(bool is_success) {
    EXPECT_CALL(mock_dlc_service_, DoRegisterDlcStateChangedSignalHandler(_, _))
        .WillOnce(WithArgs<0, 1>(
            [=](const base::RepeatingCallback<void(
                    const dlcservice::DlcState&)>& signal_callback,
                dbus::ObjectProxy::OnConnectedCallback* on_connected_callback) {
              if (is_success)
                state_changed_cb = signal_callback;
              std::move(*on_connected_callback).Run("", "", is_success);
            }));
  }

  void SetUpIntializedDlcManager() {
    SetDlcServiceAvailability(/*available=*/true);
    SetRegisterDlcStateChangedCall(/*is_success=*/true);
    dlc_manager_.Initialize();
  }

  void SetUpNotIntializedDlcManager() {
    SetDlcServiceAvailability(/*available=*/false);
    dlc_manager_.Initialize();
  }

  void SetInstallDlcCall(const dlcservice::DlcState& state, bool is_success) {
    EXPECT_CALL(mock_dlc_service_, InstallAsync(_, _, _, _))
        .WillOnce(WithArgs<0, 1, 2>(Invoke(
            [=](const dlcservice::InstallRequest& in_install_request,
                base::OnceCallback<void()> success_callback,
                base::OnceCallback<void(brillo::Error*)> error_callback) {
              last_install_dlc_id = in_install_request.id();
              if (is_success) {
                std::move(success_callback).Run();
                state_changed_cb.Run(state);
              } else {
                auto error = brillo::Error::Create(FROM_HERE, "", "", "");
                std::move(error_callback).Run(error.get());
              }
            })));
  }

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  org::chromium::DlcServiceInterfaceProxyMock mock_dlc_service_;
  base::RepeatingCallback<void(const dlcservice::DlcState&)> state_changed_cb;
  std::optional<std::string> last_install_dlc_id;

 private:
  scoped_refptr<dbus::MockObjectProxy> dlc_service_object_proxy_;
  DlcManager dlc_manager_{&mock_dlc_service_};
};

// Test that DLC manager can get the DLC root path successfully.
TEST_F(DlcManagerTest, GetRootPathSuccess) {
  SetUpIntializedDlcManager();
  auto state = dlcservice::DlcState{};
  state.set_id("test-dlc");
  state.set_state(dlcservice::DlcState::INSTALLED);
  state.set_root_path("/run/imageloader/test-dlc/package/root");
  SetInstallDlcCall(state, /*is_success=*/true);

  EXPECT_EQ(GetBinaryRootPathSync("test-dlc"),
            base::FilePath(state.root_path()));
  EXPECT_EQ(last_install_dlc_id, "test-dlc");
}

// Test that DLC manager handle the error when DLC service is unavailable.
TEST_F(DlcManagerTest, DlcServiceUnavailableError) {
  auto start_ticks_ = base::TimeTicks::Now();
  SetUpNotIntializedDlcManager();
  SetDlcServiceAvailability(/*available=*/false);

  EXPECT_FALSE(GetBinaryRootPathSync("test-dlc").has_value());
  EXPECT_FALSE(last_install_dlc_id.has_value());
  EXPECT_LT(base::TimeTicks::Now() - start_ticks_, kGetDlcRootPathTimeout)
      << "Unexpected to reach timeout";
}

// Test that DLC manager handle the error of registering DLC state change events
// failure.
TEST_F(DlcManagerTest, RegisterDlcStateChangedError) {
  auto start_ticks_ = base::TimeTicks::Now();
  SetUpNotIntializedDlcManager();
  SetDlcServiceAvailability(/*available=*/true);
  SetRegisterDlcStateChangedCall(/*is_success=*/false);

  EXPECT_FALSE(GetBinaryRootPathSync("test-dlc").has_value());
  EXPECT_FALSE(last_install_dlc_id.has_value());
  EXPECT_LT(base::TimeTicks::Now() - start_ticks_, kGetDlcRootPathTimeout)
      << "Unexpected to reach timeout";
}

// Test that DLC manager handle the error of installing DLC.
TEST_F(DlcManagerTest, InstallDlcError) {
  SetUpIntializedDlcManager();
  auto state = dlcservice::DlcState{};
  state.set_id("test-dlc");
  state.set_state(dlcservice::DlcState::INSTALLED);
  SetInstallDlcCall(state, /*is_success=*/false);

  EXPECT_FALSE(GetBinaryRootPathSync("test-dlc").has_value());
  EXPECT_EQ(last_install_dlc_id, "test-dlc");
}

// Test that DLC manager handle the error of getting not-installed state DLC
// after installation.
TEST_F(DlcManagerTest, InstallDlcNotInstalledStateError) {
  SetUpIntializedDlcManager();
  auto state = dlcservice::DlcState{};
  state.set_id("test-dlc");
  state.set_state(dlcservice::DlcState::NOT_INSTALLED);
  SetInstallDlcCall(state, /*is_success=*/true);

  EXPECT_FALSE(GetBinaryRootPathSync("test-dlc").has_value());
  EXPECT_EQ(last_install_dlc_id, "test-dlc");
}

// Test that DLC manager handle the timeout error of getting DLC root path.
TEST_F(DlcManagerTest, GetRootPathSuccessTimeoutError) {
  SetUpNotIntializedDlcManager();
  SetDlcServiceAvailability(/*available=*/true);

  EXPECT_CALL(mock_dlc_service_, DoRegisterDlcStateChangedSignalHandler(_, _))
      .WillOnce(WithoutArgs(
          [&]() { task_environment_.FastForwardBy(kGetDlcRootPathTimeout); }));

  EXPECT_FALSE(GetBinaryRootPathSync("test-dlc").has_value());
  EXPECT_FALSE(last_install_dlc_id.has_value());
}

}  // namespace
}  // namespace diagnostics
