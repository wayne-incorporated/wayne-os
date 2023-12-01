// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_base.h"
#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_constants.h"
#include "diagnostics/cros_healthd/system/mock_bluetooth_info_manager.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxy-mocks.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;

class BluetoothRoutineBaseTest : public testing::Test {
 protected:
  BluetoothRoutineBaseTest() = default;
  BluetoothRoutineBaseTest(const BluetoothRoutineBaseTest&) = delete;
  BluetoothRoutineBaseTest& operator=(const BluetoothRoutineBaseTest&) = delete;

  MockBluetoothInfoManager* mock_bluetooth_info_manager() {
    return mock_context_.mock_bluetooth_info_manager();
  }

  MockContext mock_context_;
  StrictMock<org::bluez::Adapter1ProxyMock> mock_adapter_proxy_;

 private:
  base::test::TaskEnvironment task_environment_;
};

// Test that the BluetoothRoutineBase can get adapter successfully.
TEST_F(BluetoothRoutineBaseTest, GetAdapterSuccess) {
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          &mock_adapter_proxy_}));
  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  EXPECT_EQ(routine_base->GetAdapter(), &mock_adapter_proxy_);
}

// Test that the BluetoothRoutineBase can handle empty adapters and return null.
TEST_F(BluetoothRoutineBaseTest, EmptyAdapter) {
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{}));
  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  ASSERT_EQ(routine_base->GetAdapter(), nullptr);
}

// Test that the BluetoothRoutineBase can handle null adapter and return null.
TEST_F(BluetoothRoutineBaseTest, NullAdapter) {
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          nullptr, &mock_adapter_proxy_}));
  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  ASSERT_EQ(routine_base->GetAdapter(), nullptr);
}

// Test that the BluetoothRoutineBase can ensure the adapter is powered on
// successfully.
TEST_F(BluetoothRoutineBaseTest, EnsureAdapterPowerOnSuccess) {
  base::RunLoop run_loop;
  InSequence s;
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          &mock_adapter_proxy_}));
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  EXPECT_CALL(mock_adapter_proxy_, set_powered(_, _))
      .WillOnce(
          Invoke([](bool powered, base::OnceCallback<void(bool)> on_finish) {
            EXPECT_TRUE(powered);
            std::move(on_finish).Run(true);
          }));

  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  routine_base->EnsureAdapterPoweredState(
      /*powered=*/true, base::BindLambdaForTesting([&](bool is_success) {
        EXPECT_TRUE(is_success);
        run_loop.Quit();
      }));
  run_loop.Run();
}

// Test that the BluetoothRoutineBase can ensure the adapter is powered off
// successfully.
TEST_F(BluetoothRoutineBaseTest, EnsureAdapterPowerOffSuccess) {
  base::RunLoop run_loop;
  InSequence s;
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          &mock_adapter_proxy_}));
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));
  EXPECT_CALL(mock_adapter_proxy_, set_powered(_, _))
      .WillOnce(
          Invoke([](bool powered, base::OnceCallback<void(bool)> on_finish) {
            EXPECT_FALSE(powered);
            std::move(on_finish).Run(true);
          }));

  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  routine_base->EnsureAdapterPoweredState(
      /*powered=*/false, base::BindLambdaForTesting([&](bool is_success) {
        EXPECT_TRUE(is_success);
        run_loop.Quit();
      }));
  run_loop.Run();
}

// Test that the BluetoothRoutineBase can ensure the adapter is powered on
// successfully when the adapter is already powered on.
TEST_F(BluetoothRoutineBaseTest, AdapterAlreadyPoweredOn) {
  base::RunLoop run_loop;
  InSequence s;
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          &mock_adapter_proxy_}));
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));

  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  routine_base->EnsureAdapterPoweredState(
      /*powered=*/true, base::BindLambdaForTesting([&](bool is_success) {
        EXPECT_TRUE(is_success);
        run_loop.Quit();
      }));
  run_loop.Run();
}

// Test that the BluetoothRoutineBase can handle null adapter when powering on
// the adapter.
TEST_F(BluetoothRoutineBaseTest, NoAdapterPoweredOn) {
  base::RunLoop run_loop;
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(
          Return(std::vector<org::bluez::Adapter1ProxyInterface*>{nullptr}));

  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  routine_base->EnsureAdapterPoweredState(
      /*powered=*/true, base::BindLambdaForTesting([&](bool is_success) {
        EXPECT_FALSE(is_success);
        run_loop.Quit();
      }));
  run_loop.Run();
}

// Test that the BluetoothRoutineBase can pass the pre-check.
TEST_F(BluetoothRoutineBaseTest, PreCheckPassed) {
  base::RunLoop run_loop;
  InSequence s;
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          &mock_adapter_proxy_}));
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));
  EXPECT_CALL(mock_adapter_proxy_, discovering()).WillOnce(Return(false));

  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  routine_base->RunPreCheck(
      base::BindLambdaForTesting([&]() { run_loop.Quit(); }),
      base::NullCallback());
  run_loop.Run();
}

// Test that the BluetoothRoutineBase can handle null adapter when running
// pre-check.
TEST_F(BluetoothRoutineBaseTest, PreCheckFailedNoAdapter) {
  base::RunLoop run_loop;
  InSequence s;
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(
          Return(std::vector<org::bluez::Adapter1ProxyInterface*>{nullptr}));

  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  routine_base->RunPreCheck(
      base::NullCallback(),
      base::BindLambdaForTesting([&](mojom::DiagnosticRoutineStatusEnum status,
                                     const std::string& error_message) {
        EXPECT_EQ(status, mojom::DiagnosticRoutineStatusEnum::kError);
        EXPECT_EQ(error_message, kBluetoothRoutineFailedGetAdapter);
        run_loop.Quit();
      }));
  run_loop.Run();
}

// Test that the BluetoothRoutineBase can handle that the adapter is already in
// discovery mode when running pre-check.
TEST_F(BluetoothRoutineBaseTest, PreCheckFailedDiscoveringOn) {
  base::RunLoop run_loop;
  InSequence s;
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
      .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
          &mock_adapter_proxy_}));
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));
  EXPECT_CALL(mock_adapter_proxy_, discovering()).WillOnce(Return(true));

  auto routine_base = std::make_unique<BluetoothRoutineBase>(&mock_context_);
  routine_base->RunPreCheck(
      base::NullCallback(),
      base::BindLambdaForTesting([&](mojom::DiagnosticRoutineStatusEnum status,
                                     const std::string& error_message) {
        EXPECT_EQ(status, mojom::DiagnosticRoutineStatusEnum::kFailed);
        EXPECT_EQ(error_message, kBluetoothRoutineFailedDiscoveryMode);
        run_loop.Quit();
      }));
  run_loop.Run();
}

}  // namespace
}  // namespace diagnostics
