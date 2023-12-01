// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/executor/upstart_tools.h"

#include <memory>
#include <string>
#include <utility>

#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "printscanmgr/mojom/executor.mojom.h"

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

namespace printscanmgr {

class UpstartToolsTest : public testing::Test {
 public:
  UpstartToolsTest() : bus_(new dbus::MockBus{dbus::Bus::Options{}}) {
    upstart_object_proxy_ =
        new dbus::MockObjectProxy(bus_.get(), "com.ubuntu.Upstart",
                                  dbus::ObjectPath("/com/ubuntu/Upstart"));
    job_object_proxy_ = new dbus::MockObjectProxy(
        bus_.get(), "com.ubuntu.Upstart",
        dbus::ObjectPath("/com/ubuntu/Upstart/jobs/lorgnette"));
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
        dbus::ObjectPath("/com/ubuntu/Upstart/jobs/lorgnette"));

    return job_response;
  }

  void SetUp() override {
    ExpectUpstartCalls();
    upstart_tools_ = UpstartTools::Create(bus_);
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
  EXPECT_CALL(
      *bus_,
      GetObjectProxy("com.ubuntu.Upstart",
                     dbus::ObjectPath("/com/ubuntu/Upstart/jobs/lorgnette")))
      .WillOnce(Return(job_object_proxy_.get()));
  std::unique_ptr<dbus::Response> job_response = dbus::Response::CreateEmpty();
  dbus::MessageWriter response_writer(job_response.get());
  response_writer.AppendObjectPath(
      dbus::ObjectPath("/com/ubuntu/Upstart/jobs/lorgnette"));
  dbus::MethodCall method_call("com.ubuntu.Upstart0_6.Job", "GetInstance");
  EXPECT_CALL(*job_object_proxy_,
              CallMethodAndBlock(IsMethod("GetInstance"), _))
      .WillOnce(Return(ByMove(std::move(job_response))));
  std::string error;
  bool result =
      upstart_tools()->IsJobRunning(mojom::UpstartJob::kLorgnette, &error);
  EXPECT_EQ(error, "");
  EXPECT_EQ(result, true);
}

TEST_F(UpstartToolsTest, TestRestartJob) {
  EXPECT_CALL(
      *bus_,
      GetObjectProxy("com.ubuntu.Upstart",
                     dbus::ObjectPath("/com/ubuntu/Upstart/jobs/lorgnette")))
      .WillOnce(Return(job_object_proxy_.get()));
  std::unique_ptr<dbus::Response> job_response = dbus::Response::CreateEmpty();
  dbus::MessageWriter response_writer(job_response.get());
  response_writer.AppendObjectPath(
      dbus::ObjectPath("/com/ubuntu/Upstart/jobs/lorgnette"));
  EXPECT_CALL(*job_object_proxy_, CallMethodAndBlock(IsMethod("Restart"), _))
      .WillOnce(Return(ByMove(std::move(job_response))));
  std::string error;
  bool result =
      upstart_tools()->RestartJob(mojom::UpstartJob::kLorgnette, &error);
  EXPECT_EQ(error, "");
  EXPECT_EQ(result, true);
}

TEST_F(UpstartToolsTest, TestStopJob) {
  EXPECT_CALL(
      *bus_,
      GetObjectProxy("com.ubuntu.Upstart",
                     dbus::ObjectPath("/com/ubuntu/Upstart/jobs/lorgnette")))
      .WillRepeatedly(Return(job_object_proxy_.get()));
  std::unique_ptr<dbus::Response> job_response = dbus::Response::CreateEmpty();
  dbus::MessageWriter response_writer(job_response.get());
  response_writer.AppendObjectPath(
      dbus::ObjectPath("/com/ubuntu/Upstart/jobs/lorgnette"));
  EXPECT_CALL(*job_object_proxy_, CallMethodAndBlock(_, _))
      .WillRepeatedly(Invoke(this, &UpstartToolsTest::CreateMockResponse));
  std::string error;
  bool result = upstart_tools()->StopJob(mojom::UpstartJob::kLorgnette, &error);
  EXPECT_EQ(error, "");
  EXPECT_EQ(result, true);
}

}  // namespace printscanmgr
