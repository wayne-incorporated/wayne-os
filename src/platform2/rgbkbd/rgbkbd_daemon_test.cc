// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <memory>
#include <utility>

#include <base/test/task_environment.h>
#include <brillo/dbus/dbus_object_test_helpers.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/rgbkbd/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libcrossystem/crossystem_fake.h>
#include <libcrossystem/crossystem.h>

#include "rgbkbd/rgbkbd_daemon.h"

using dbus::Response;
using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

namespace rgbkbd {

namespace {

// Some arbitrary D-Bus message serial number. Required for mocking D-Bus calls.
const int kDBusSerial = 24;

}  //  namespace

class RgbkbdDaemonTest : public testing::Test {
 public:
  RgbkbdDaemonTest() {
    cros_config_ = std::make_unique<brillo::FakeCrosConfig>();
    crossystem_ = std::make_unique<crossystem::Crossystem>(
        std::make_unique<crossystem::fake::CrossystemFake>());

    dbus::Bus::Options options;
    mock_bus_ = base::MakeRefCounted<NiceMock<dbus::MockBus>>(options);
    dbus::ObjectPath path(rgbkbd::kRgbkbdServicePath);

    mock_object_proxy_ = base::MakeRefCounted<NiceMock<dbus::MockObjectProxy>>(
        mock_bus_.get(), rgbkbd::kRgbkbdServiceName, path);
    mock_exported_object_ =
        base::MakeRefCounted<StrictMock<dbus::MockExportedObject>>(
            mock_bus_.get(), path);

    ON_CALL(*mock_bus_, GetExportedObject(path))
        .WillByDefault(Return(mock_exported_object_.get()));

    ON_CALL(*mock_bus_, GetDBusTaskRunner())
        .WillByDefault(
            Return(task_environment_.GetMainThreadTaskRunner().get()));

    EXPECT_CALL(*mock_exported_object_, ExportMethod(_, _, _, _))
        .Times(testing::AnyNumber());
    adaptor_.reset(new DBusAdaptor(mock_bus_, cros_config_.get(),
                                   crossystem_.get(), /*daemon=*/nullptr));
  }

  RgbkbdDaemonTest(const RgbkbdDaemonTest&) = delete;
  RgbkbdDaemonTest& operator=(const RgbkbdDaemonTest&) = delete;
  ~RgbkbdDaemonTest() override = default;

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy_;
  scoped_refptr<dbus::MockExportedObject> mock_exported_object_;
  std::unique_ptr<rgbkbd::DBusAdaptor> adaptor_;
  std::unique_ptr<brillo::FakeCrosConfig> cros_config_;
  std::unique_ptr<crossystem::Crossystem> crossystem_;
};

void OnGetRgbKeyboardCapabilities(RgbKeyboardCapabilities expected,
                                  std::unique_ptr<dbus::Response> response) {
  dbus::MessageReader reader(response.get());
  uint32_t capability;
  EXPECT_TRUE(reader.PopUint32(&capability));
  EXPECT_EQ(expected, static_cast<RgbKeyboardCapabilities>(capability));
}

TEST_F(RgbkbdDaemonTest, SetTestingModeOutOfBoundsCapabilities) {
  crossystem_->VbSetSystemPropertyInt("cros_debug", 1);
  adaptor_->SetTestingMode(/*enable_testing=*/true, /*capability=*/99);

  dbus::MethodCall method_call(rgbkbd::kRgbkbdServiceName,
                               rgbkbd::kGetRgbKeyboardCapabilities);
  method_call.SetSerial(kDBusSerial);
  auto cb = std::make_unique<brillo::dbus_utils::DBusMethodResponse<uint32_t>>(
      &method_call, base::BindOnce(&OnGetRgbKeyboardCapabilities,
                                   RgbKeyboardCapabilities::kNone));

  adaptor_->GetRgbKeyboardCapabilities(std::move(cb));
}

TEST_F(RgbkbdDaemonTest, SetTestingModeBarelyOutOfBoundsCapabilities) {
  crossystem_->VbSetSystemPropertyInt("cros_debug", 1);
  adaptor_->SetTestingMode(
      /*enable_testing=*/true,
      /*capability=*/static_cast<int>(RgbKeyboardCapabilities::kMaxValue) + 1);

  dbus::MethodCall method_call(rgbkbd::kRgbkbdServiceName,
                               rgbkbd::kGetRgbKeyboardCapabilities);
  method_call.SetSerial(kDBusSerial);
  auto cb = std::make_unique<brillo::dbus_utils::DBusMethodResponse<uint32_t>>(
      &method_call, base::BindOnce(&OnGetRgbKeyboardCapabilities,
                                   RgbKeyboardCapabilities::kNone));

  adaptor_->GetRgbKeyboardCapabilities(std::move(cb));
}

TEST_F(RgbkbdDaemonTest, SetTestingModeBarelyInBoundsCapabilities) {
  crossystem_->VbSetSystemPropertyInt("cros_debug", 1);
  adaptor_->SetTestingMode(
      /*enable_testing=*/true,
      /*capability=*/static_cast<int>(RgbKeyboardCapabilities::kMaxValue));

  dbus::MethodCall method_call(rgbkbd::kRgbkbdServiceName,
                               rgbkbd::kGetRgbKeyboardCapabilities);
  method_call.SetSerial(kDBusSerial);
  auto cb = std::make_unique<brillo::dbus_utils::DBusMethodResponse<uint32_t>>(
      &method_call, base::BindOnce(&OnGetRgbKeyboardCapabilities,
                                   RgbKeyboardCapabilities::kMaxValue));

  adaptor_->GetRgbKeyboardCapabilities(std::move(cb));
}

TEST_F(RgbkbdDaemonTest, SetTestingModeWithinBoundsCapabilities) {
  crossystem_->VbSetSystemPropertyInt("cros_debug", 1);
  adaptor_->SetTestingMode(
      /*enable_testing=*/true,
      static_cast<uint32_t>(RgbKeyboardCapabilities::kFourZoneFourLed));

  dbus::MethodCall method_call(rgbkbd::kRgbkbdServiceName,
                               rgbkbd::kGetRgbKeyboardCapabilities);
  method_call.SetSerial(kDBusSerial);
  auto cb = std::make_unique<brillo::dbus_utils::DBusMethodResponse<uint32_t>>(
      &method_call, base::BindOnce(&OnGetRgbKeyboardCapabilities,
                                   RgbKeyboardCapabilities::kFourZoneFourLed));

  adaptor_->GetRgbKeyboardCapabilities(std::move(cb));
}

TEST_F(RgbkbdDaemonTest, SetTestingModeOffDoesntChangeCapability) {
  crossystem_->VbSetSystemPropertyInt("cros_debug", 1);
  adaptor_->SetTestingMode(
      /*enable_testing=*/true,
      static_cast<uint32_t>(RgbKeyboardCapabilities::kFourZoneFourLed));
  dbus::MethodCall method_call(rgbkbd::kRgbkbdServiceName,
                               rgbkbd::kGetRgbKeyboardCapabilities);
  method_call.SetSerial(kDBusSerial);
  auto cb = std::make_unique<brillo::dbus_utils::DBusMethodResponse<uint32_t>>(
      &method_call, base::BindOnce(&OnGetRgbKeyboardCapabilities,
                                   RgbKeyboardCapabilities::kFourZoneFourLed));

  adaptor_->GetRgbKeyboardCapabilities(std::move(cb));

  // Set testing mode off with a different capability, this should not change
  // capability.
  adaptor_->SetTestingMode(
      /*enable_testing=*/false,
      static_cast<uint32_t>(RgbKeyboardCapabilities::kFourZoneFortyLed));
  auto cb_2 =
      std::make_unique<brillo::dbus_utils::DBusMethodResponse<uint32_t>>(
          &method_call,
          base::BindOnce(&OnGetRgbKeyboardCapabilities,
                         RgbKeyboardCapabilities::kFourZoneFourLed));
  adaptor_->GetRgbKeyboardCapabilities(std::move(cb_2));
}

TEST_F(RgbkbdDaemonTest, SetTestingModeWhileNotInDebug) {
  adaptor_->SetTestingMode(
      /*enable_testing=*/true,
      static_cast<uint32_t>(RgbKeyboardCapabilities::kFourZoneFourLed));

  dbus::MethodCall method_call1(rgbkbd::kRgbkbdServiceName,
                                rgbkbd::kGetRgbKeyboardCapabilities);
  method_call1.SetSerial(kDBusSerial);
  auto cb1 = std::make_unique<brillo::dbus_utils::DBusMethodResponse<uint32_t>>(
      &method_call1, base::BindOnce(&OnGetRgbKeyboardCapabilities,
                                    RgbKeyboardCapabilities::kNone));

  adaptor_->GetRgbKeyboardCapabilities(std::move(cb1));

  crossystem_->VbSetSystemPropertyInt("cros_debug", 0);

  adaptor_->SetTestingMode(
      /*enable_testing=*/true,
      static_cast<uint32_t>(RgbKeyboardCapabilities::kFourZoneFourLed));

  dbus::MethodCall method_call2(rgbkbd::kRgbkbdServiceName,
                                rgbkbd::kGetRgbKeyboardCapabilities);
  method_call2.SetSerial(kDBusSerial);
  auto cb2 = std::make_unique<brillo::dbus_utils::DBusMethodResponse<uint32_t>>(
      &method_call2, base::BindOnce(&OnGetRgbKeyboardCapabilities,
                                    RgbKeyboardCapabilities::kNone));

  adaptor_->GetRgbKeyboardCapabilities(std::move(cb2));
}

}  // namespace rgbkbd
