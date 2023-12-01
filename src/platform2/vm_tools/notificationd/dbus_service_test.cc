// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/memory/ref_counted.h>
#include <base/memory/scoped_refptr.h>
#include <base/run_loop.h>
#include <base/values.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/values_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "vm_tools/notificationd/notification_daemon.h"

using ::testing::_;
using ::testing::Invoke;

namespace {

class MockNotificationDaemon : public vm_tools::notificationd::DBusInterface {
 public:
  MockNotificationDaemon() : dbus_service() {}

  bool GetCapabilities(std::vector<std::string>* out_capabilities) override {
    *out_capabilities = capabilities_;
    return true;
  }

  bool Notify(const NotifyArgument& input, uint32_t* out_id) override {
    received_notify_arg_ = input;
    *out_id = notify_out_id_;
    return true;
  }

  bool GetServerInformation(ServerInformation* output) override {
    *output = server_info_;
    return true;
  }

  bool CloseNotification(uint32_t id) override {
    received_close_notification_id_ = id;
    return true;
  }

  void SetCapabilities(const std::vector<std::string>& capabilities) {
    capabilities_ = capabilities;
  }

  void SetServerInformation(const ServerInformation& server_info) {
    server_info_ = server_info;
  }

  void SetNotifyOutId(uint32_t out_id) { notify_out_id_ = out_id; }

  const NotifyArgument& GetReceivedNotifyArg() const {
    return received_notify_arg_;
  }

  uint32_t received_close_notification_id() const {
    return received_close_notification_id_;
  }

 private:
  std::vector<std::string> capabilities_;
  ServerInformation server_info_;
  NotifyArgument received_notify_arg_;
  uint32_t notify_out_id_;
  uint32_t received_close_notification_id_;

  std::unique_ptr<vm_tools::notificationd::DBusService> dbus_service;

  FRIEND_TEST(DBusServiceTest, GetCapabilities);
  FRIEND_TEST(DBusServiceTest, Notify);
  FRIEND_TEST(DBusServiceTest, GetServerInformation);
  FRIEND_TEST(DBusServiceTest, CloseNotification);
};

}  // namespace

namespace vm_tools {
namespace notificationd {

class DBusServiceTest : public ::testing::Test {
 public:
  DBusServiceTest() = default;
  DBusServiceTest(const DBusServiceTest&) = delete;
  DBusServiceTest& operator=(const DBusServiceTest&) = delete;

  // Create dummy method call.
  std::unique_ptr<dbus::MethodCall> CreateMockMethodCall(
      const std::string& method_name) {
    const uint32_t kSerial = 123;
    auto method_call = std::make_unique<dbus::MethodCall>(
        "org.freedesktop.Notifications", method_name);
    method_call->SetSerial(kSerial);
    return method_call;
  }

  void AppendStringArray(dbus::MessageWriter* writer,
                         const std::vector<std::string>& array) {
    dbus::MessageWriter array_writer(nullptr);
    writer->OpenArray("s", &array_writer);
    for (const auto& str : array) {
      array_writer.AppendString(str);
    }
    writer->CloseContainer(&array_writer);
  }

  void AppendEmptyVariantDict(dbus::MessageWriter* writer) {
    dbus::MessageWriter array_writer(nullptr);
    writer->OpenArray("{sv}", &array_writer);

    writer->CloseContainer(&array_writer);
  }
};

// Test if dbus adaptor can properly call GetCapability method and recieve the
// data from notification daemon.
TEST_F(DBusServiceTest, GetCapabilities) {
  MockNotificationDaemon daemon;
  DBusService dbus_service(&daemon);

  const std::vector<std::string> expected_data = {"body", "actions",
                                                  "action-icons"};
  daemon.SetCapabilities(expected_data);

  auto method_call = CreateMockMethodCall("GetCapabilities");

  auto response = dbus_service.CallGetCapabilities(method_call.get());
  ASSERT_TRUE(response.get() != nullptr);

  // Parse resonse
  dbus::MessageReader reader(response.get());
  base::Value value(PopDataAsValue(&reader));
  ASSERT_FALSE(value.is_none());
  ASSERT_FALSE(reader.HasMoreData());
  ASSERT_TRUE(value.is_list());
  std::vector<std::string> received_data;
  for (const auto& element : value.GetList()) {
    ASSERT_TRUE(element.is_string());
    received_data.push_back(element.GetString());
  }

  EXPECT_EQ(received_data, expected_data);
}

// Test if dbus adaptor can properly call GetServerInformation method and
// recieve the data from notification daemon.
TEST_F(DBusServiceTest, GetServerInformation) {
  MockNotificationDaemon daemon;
  DBusService dbus_service(&daemon);

  const NotificationDaemon::ServerInformation expected_data = {
      .name = "NameTest",
      .vendor = "VendorTest",
      .version = "VersionTest",
      .spec_version = "SpecVersionTest"};
  daemon.SetServerInformation(expected_data);

  auto method_call = CreateMockMethodCall("GetServerInformation");

  auto response = dbus_service.CallGetServerInformation(method_call.get());
  ASSERT_TRUE(response.get() != nullptr);

  // Parse response
  dbus::MessageReader reader(response.get());
  NotificationDaemon::ServerInformation received_data;
  ASSERT_TRUE(reader.PopString(&received_data.name));
  ASSERT_TRUE(reader.PopString(&received_data.vendor));
  ASSERT_TRUE(reader.PopString(&received_data.version));
  ASSERT_TRUE(reader.PopString(&received_data.spec_version));
  ASSERT_FALSE(reader.HasMoreData());

  EXPECT_EQ(received_data.name, expected_data.name);
  EXPECT_EQ(received_data.vendor, expected_data.vendor);
  EXPECT_EQ(received_data.version, expected_data.version);
  EXPECT_EQ(received_data.spec_version, expected_data.spec_version);
}

// Test if dbus adaptor can properly call Notify method and recieve the data
// from notification daemon.
TEST_F(DBusServiceTest, Notify) {
  MockNotificationDaemon daemon;
  DBusService dbus_service(&daemon);

  const NotificationDaemon::NotifyArgument expected_data = {
      .app_name = "AppNameTest",
      .replaces_id = 1,
      .app_icon = "AppIconTest",
      .summary = "SummaryTest",
      .body = "BodyTest",
      .actions = {"ActionTest1", "ActionTest2", "Actiontest3"},
      .hints = {{"KeyTest1", "ValueTest1"}},
      .expire_timeout = 2};
  const uint32_t expected_out_id = 333;
  daemon.SetNotifyOutId(expected_out_id);

  auto method_call = CreateMockMethodCall("Notify");

  // Prepare args for the method call
  dbus::MessageWriter writer(method_call.get());
  writer.AppendString(expected_data.app_name);
  writer.AppendUint32(expected_data.replaces_id);
  writer.AppendString(expected_data.app_icon);
  writer.AppendString(expected_data.summary);
  writer.AppendString(expected_data.body);
  AppendStringArray(&writer, expected_data.actions);
  AppendEmptyVariantDict(&writer);
  writer.AppendInt32(expected_data.expire_timeout);

  auto response = dbus_service.CallNotify(method_call.get());
  ASSERT_TRUE(response.get() != nullptr);

  // Test args
  const auto received_args = daemon.GetReceivedNotifyArg();
  EXPECT_EQ(received_args.app_name, expected_data.app_name);
  EXPECT_EQ(received_args.replaces_id, expected_data.replaces_id);
  EXPECT_EQ(received_args.app_icon, expected_data.app_icon);
  EXPECT_EQ(received_args.summary, expected_data.summary);
  EXPECT_EQ(received_args.body, expected_data.body);
  EXPECT_EQ(received_args.actions, expected_data.actions);
  // parsing hints is not implemented yet.
  EXPECT_NE(received_args.hints, expected_data.hints);
  EXPECT_EQ(received_args.expire_timeout, expected_data.expire_timeout);

  // Parse response
  dbus::MessageReader reader(response.get());
  uint32_t received_out_id = 0;
  ASSERT_TRUE(reader.PopUint32(&received_out_id));
  ASSERT_FALSE(reader.HasMoreData());

  // Test response
  EXPECT_EQ(received_out_id, expected_out_id);
}

// Test if dbus adaptor can properly call CloseNotification method.
TEST_F(DBusServiceTest, CloseNotification) {
  MockNotificationDaemon daemon;
  DBusService dbus_service(&daemon);

  const uint32_t expected_data = 777;
  auto method_call = CreateMockMethodCall("CloseNotification");

  // Prepare args for the method call
  dbus::MessageWriter writer(method_call.get());
  writer.AppendUint32(expected_data);

  auto response = dbus_service.CallCloseNotification(method_call.get());
  ASSERT_TRUE(response.get() != nullptr);

  // Test received data
  EXPECT_EQ(daemon.received_close_notification_id(), expected_data);

  // Parse response (expects no data in response)
  dbus::MessageReader reader(response.get());
  ASSERT_FALSE(reader.HasMoreData());
}

// Test if dbus adaptor can properly send NotificationClosed signal.
TEST_F(DBusServiceTest, NotificationClosedSignal) {
  DBusService dbus_service(nullptr);

  // Prepare mock exported object
  const dbus::ObjectPath kObjectPath("/org/example/TestService");
  auto mock_exported_object =
      base::MakeRefCounted<dbus::MockExportedObject>(nullptr, kObjectPath);
  dbus_service.exported_object_ = mock_exported_object.get();

  // Expected data
  const uint32_t expected_id = 456;
  const auto expected_reason = DBusService::ClosedReason::BY_USER;

  // Test if SendSignal is called once with expected args
  EXPECT_CALL(*mock_exported_object.get(), SendSignal(_))
      .WillOnce(Invoke([&](dbus::Signal* signal) {
        dbus::MessageReader reader(signal);

        uint32_t id = -1;
        uint32_t reason = -1;
        ASSERT_TRUE(reader.PopUint32(&id));
        ASSERT_TRUE(reader.PopUint32(&reason));
        ASSERT_FALSE(reader.HasMoreData());

        EXPECT_EQ(id, expected_id);
        EXPECT_EQ(reason, static_cast<uint32_t>(expected_reason));
      }));

  // Send signal
  dbus_service.SendNotificationClosedSignal(expected_id, expected_reason);
}

// Test if dbus adaptor can properly send ActionInvoked signal.
TEST_F(DBusServiceTest, ActionInvokedSignal) {
  DBusService dbus_service(nullptr);

  // Prepare mock exported object
  const dbus::ObjectPath kObjectPath("/org/example/TestService");
  auto mock_exported_object =
      base::MakeRefCounted<dbus::MockExportedObject>(nullptr, kObjectPath);
  dbus_service.exported_object_ = mock_exported_object.get();

  // Expected data
  const uint32_t expected_id = 456;
  const std::string expected_action_key = "Test action key";

  // Test if SendSignal is called once with expected args
  EXPECT_CALL(*mock_exported_object.get(), SendSignal(_))
      .WillOnce(Invoke([&](dbus::Signal* signal) {
        dbus::MessageReader reader(signal);

        uint32_t id = -1;
        std::string action_key;
        ASSERT_TRUE(reader.PopUint32(&id));
        ASSERT_TRUE(reader.PopString(&action_key));
        ASSERT_FALSE(reader.HasMoreData());

        EXPECT_EQ(id, expected_id);
        EXPECT_EQ(action_key, expected_action_key);
      }));

  // Send signal
  dbus_service.SendActionInvokedSignal(expected_id, expected_action_key);
}

}  // namespace notificationd
}  // namespace vm_tools
