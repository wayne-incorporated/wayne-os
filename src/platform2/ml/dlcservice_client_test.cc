// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/run_loop.h>
#include <dbus/dlcservice/dbus-constants.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_proxy.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>
#include <gtest/gtest.h>

#include "ml/dlcservice_client.h"

namespace ml {

// A random string returned as a root_path.
constexpr char kDlcValidFakePath[] = "/valid/fake-path";
constexpr char kRandomDlcId[] = "random-dlc-id";

class DlcserviceClientTest : public ::testing::Test {
 public:
  void SetUp() override {
    method_call_ = std::make_unique<dbus::MethodCall>(
        dlcservice::kDlcServiceInterface, dlcservice::kGetDlcStateMethod);
    method_call_->SetSerial(123);
    err_response_ = dbus::ErrorResponse::FromMethodCall(
        method_call_.get(), "org.ErrorName", "Random error message");
    response_ = dbus::Response::FromMethodCall(method_call_.get());
    response_writer_ = std::make_unique<dbus::MessageWriter>(response_.get());
  }

  // Expect correct path is extract from the `response`.
  void ExpectRootPathFromResponse(const std::string& expected_path,
                                  dbus::Response* response,
                                  dbus::ErrorResponse* err_response) {
    bool get_path_callback_done = false;
    DlcserviceClient::OnGetDlcStateComplete(
        base::BindOnce(
            [](bool* const get_path_callback_done,
               const std::string& expected_path, const std::string& root_path) {
              *get_path_callback_done = true;
              EXPECT_EQ(expected_path, root_path);
            },
            &get_path_callback_done, expected_path),
        response, err_response);

    base::RunLoop().RunUntilIdle();
    EXPECT_TRUE(get_path_callback_done);
  }

 protected:
  std::unique_ptr<dbus::MethodCall> method_call_;
  std::unique_ptr<dbus::ErrorResponse> err_response_;
  std::unique_ptr<dbus::Response> response_;
  std::unique_ptr<dbus::MessageWriter> response_writer_;
};

// root_path_ should be empty if the response is empty.
TEST_F(DlcserviceClientTest, ShouldReturnEmptyForNoResponse) {
  ExpectRootPathFromResponse("", nullptr, err_response_.get());
}

// root_path_ should be empty if the response is invalid.
TEST_F(DlcserviceClientTest, ShouldReturnEmptyOnInvalidResponse) {
  response_writer_->AppendString("random_string");
  ExpectRootPathFromResponse("", response_.get(), err_response_.get());
}

// root_path_ should be empty if the dlc state is not installed.
TEST_F(DlcserviceClientTest, ShouldReturnEmptyIfNotInstalled) {
  dlcservice::DlcState dlc_state;
  dlc_state.set_state(dlcservice::DlcState::INSTALLING);
  dlc_state.set_root_path(kDlcValidFakePath);
  response_writer_->AppendProtoAsArrayOfBytes(dlc_state);
  ExpectRootPathFromResponse("", response_.get(), err_response_.get());
}

// root_path_ should be valid if the dlc state is installed.
TEST_F(DlcserviceClientTest, ShouldReturnRootPathIfInstalled) {
  dlcservice::DlcState dlc_state;
  dlc_state.set_state(dlcservice::DlcState::INSTALLED);
  dlc_state.set_root_path(kDlcValidFakePath);
  response_writer_->AppendProtoAsArrayOfBytes(dlc_state);
  ExpectRootPathFromResponse(kDlcValidFakePath, response_.get(),
                             err_response_.get());
}

// Test GetDlcRootPath call is passed correctly.
TEST_F(DlcserviceClientTest, ShouldInitializeAndCallWithCorrectDbusInterface) {
  scoped_refptr<dbus::MockBus> bus = new dbus::MockBus(dbus::Bus::Options());
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy =
      new dbus::MockObjectProxy(
          bus.get(), dlcservice::kDlcServiceServiceName,
          dbus::ObjectPath(dlcservice::kDlcServiceServicePath));

  // Mock the GetObjectProxy for the `bus_`.
  EXPECT_CALL(*bus, GetObjectProxy(
                        dlcservice::kDlcServiceServiceName,
                        dbus::ObjectPath(dlcservice::kDlcServiceServicePath)))
      .WillOnce(testing::Return(mock_object_proxy.get()));

  // Mock the CallMethodWithErrorResponse for the `mock_object_proxy_`.
  EXPECT_CALL(*mock_object_proxy,
              DoCallMethodWithErrorResponse(testing::_, testing::_, testing::_))
      .WillOnce(testing::WithArgs<0>(
          testing::Invoke([](dbus::MethodCall* method_call) {
            EXPECT_EQ(method_call->GetInterface(),
                      dlcservice::kDlcServiceInterface);
            EXPECT_EQ(method_call->GetMember(), dlcservice::kGetDlcStateMethod);

            // Get dlc_id
            std::string dlc_id;
            EXPECT_TRUE(dbus::MessageReader(method_call).PopString(&dlc_id));
            EXPECT_TRUE(dlc_id.find(kRandomDlcId) != std::string::npos);
          })));

  DlcserviceClient(bus.get()).GetDlcRootPath(kRandomDlcId,
                                             base::NullCallback());
  base::RunLoop().RunUntilIdle();
}

}  // namespace ml
