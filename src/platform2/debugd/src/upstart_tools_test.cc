// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/upstart_tools.h"

#include <memory>
#include <utility>

#include <brillo/dbus/mock_dbus_method_response.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::_;
using testing::ByMove;
using testing::Eq;
using testing::Invoke;
using testing::Return;
using testing::WithArgs;

namespace {

// Matcher for D-Bus method names to be used in CallMethod*().
MATCHER_P(IsMethod, method_name, "") {
  return arg->GetMember() == method_name;
}

}  // namespace

namespace debugd {

class UpstartToolsTest : public testing::Test {
 public:
  UpstartToolsTest() : bus_(new dbus::MockBus{dbus::Bus::Options{}}) {
    upstart_object_proxy_ =
        new dbus::MockObjectProxy(bus_.get(), "com.ubuntu.Upstart",
                                  dbus::ObjectPath("/com/ubuntu/Upstart"));
    job_object_proxy_ = new dbus::MockObjectProxy(
        bus_.get(), "com.ubuntu.Upstart",
        dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob"));
  }

  void ExpectUpstartCalls() {
    EXPECT_CALL(*bus_, GetObjectProxy("com.ubuntu.Upstart",
                                      dbus::ObjectPath("/com/ubuntu/Upstart")))
        .WillOnce(Return(upstart_object_proxy_.get()));
  }

  // Creates a response for CallMethodAndBlock Calls.
  std::unique_ptr<dbus::Response> CreateMockResponse(
      dbus::MethodCall* method_call, int timeout_ms) {
    std::unique_ptr<dbus::Response> job_response =
        dbus::Response::CreateEmpty();
    dbus::MessageWriter response_writer(job_response.get());
    response_writer.AppendObjectPath(
        dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob"));

    return job_response;
  }

  void SetUp() override {
    ExpectUpstartCalls();
    upstart_tools_ = std::make_unique<UpstartToolsImpl>(bus_);
  }

  UpstartTools* upstart_tools() { return upstart_tools_.get(); }

 protected:
  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> job_object_proxy_;

 private:
  scoped_refptr<dbus::MockObjectProxy> upstart_object_proxy_;
  std::unique_ptr<UpstartTools> upstart_tools_;
};

TEST_F(UpstartToolsTest, TestIsJobRunning) {
  EXPECT_CALL(*bus_, GetObjectProxy(
                         "com.ubuntu.Upstart",
                         dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob")))
      .WillOnce(Return(job_object_proxy_.get()));
  std::unique_ptr<dbus::Response> job_response = dbus::Response::CreateEmpty();
  dbus::MessageWriter response_writer(job_response.get());
  response_writer.AppendObjectPath(
      dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob"));
  dbus::MethodCall method_call("com.ubuntu.Upstart0_6.Job", "GetInstance");
  EXPECT_CALL(*job_object_proxy_,
              CallMethodAndBlock(IsMethod("GetInstance"), _))
      .WillOnce(Return(ByMove(std::move(job_response))));
  brillo::ErrorPtr error;
  bool result = upstart_tools()->IsJobRunning("fakejob", &error);
  EXPECT_EQ(error, nullptr);
  EXPECT_EQ(result, true);
}

TEST_F(UpstartToolsTest, TestRestartJob) {
  EXPECT_CALL(*bus_, GetObjectProxy(
                         "com.ubuntu.Upstart",
                         dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob")))
      .WillOnce(Return(job_object_proxy_.get()));
  std::unique_ptr<dbus::Response> job_response = dbus::Response::CreateEmpty();
  dbus::MessageWriter response_writer(job_response.get());
  response_writer.AppendObjectPath(
      dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob"));
  EXPECT_CALL(*job_object_proxy_, CallMethodAndBlock(IsMethod("Restart"), _))
      .WillOnce(Return(ByMove(std::move(job_response))));
  brillo::ErrorPtr error;
  bool result = upstart_tools()->RestartJob("fakejob", &error);
  EXPECT_EQ(error, nullptr);
  EXPECT_EQ(result, true);
}

TEST_F(UpstartToolsTest, TestStopJob) {
  EXPECT_CALL(*bus_, GetObjectProxy(
                         "com.ubuntu.Upstart",
                         dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob")))
      .WillRepeatedly(Return(job_object_proxy_.get()));
  std::unique_ptr<dbus::Response> job_response = dbus::Response::CreateEmpty();
  dbus::MessageWriter response_writer(job_response.get());
  response_writer.AppendObjectPath(
      dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob"));
  EXPECT_CALL(*job_object_proxy_, CallMethodAndBlock(_, _))
      .WillRepeatedly(Invoke(this, &UpstartToolsTest::CreateMockResponse));
  brillo::ErrorPtr error;
  bool result = upstart_tools()->StopJob("fakejob", &error);
  EXPECT_EQ(error, nullptr);
  EXPECT_EQ(result, true);
}

TEST_F(UpstartToolsTest, TestStartJob) {
  EXPECT_CALL(*bus_, GetObjectProxy(
                         "com.ubuntu.Upstart",
                         dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob")))
      .WillOnce(Return(job_object_proxy_.get()));
  std::unique_ptr<dbus::Response> job_response = dbus::Response::CreateEmpty();
  dbus::MessageWriter response_writer(job_response.get());
  response_writer.AppendObjectPath(
      dbus::ObjectPath("/com/ubuntu/Upstart/jobs/fakejob"));
  EXPECT_CALL(*job_object_proxy_, CallMethodAndBlock(_, _))
      .WillRepeatedly(Invoke(this, &UpstartToolsTest::CreateMockResponse));
  brillo::ErrorPtr error;
  bool result = upstart_tools()->StartJob("fakejob", &error);
  EXPECT_EQ(error, nullptr);
  EXPECT_EQ(result, true);
}

}  // namespace debugd
