// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/dbus/dbus_method_invoker.h>

#include <stdio.h>
#include <unistd.h>

#include <string>

#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/scoped_dbus_error.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "brillo/dbus/test.pb.h"

using testing::_;
using testing::AnyNumber;
using testing::InSequence;
using testing::Invoke;
using testing::Return;

using dbus::MessageReader;
using dbus::MessageWriter;
using dbus::Response;

namespace {

void SuccessCallback(const std::string& expected_result,
                     int* counter,
                     const std::string& actual_result) {
  (*counter)++;
  EXPECT_EQ(expected_result, actual_result);
}

void SimpleSuccessCallback(int* counter, const std::string& result) {
  (*counter)++;
}

void ErrorCallback(const std::string& domain,
                   const std::string& code,
                   const std::string& message,
                   int* counter,
                   brillo::Error* error) {
  (*counter)++;
  ASSERT_NE(nullptr, error);
  EXPECT_EQ(domain, error->GetDomain());
  EXPECT_EQ(code, error->GetCode());
  EXPECT_EQ(message, error->GetMessage());
}

void SimpleErrorCallback(int* counter, brillo::Error* error) {
  (*counter)++;
}

}  // namespace

namespace brillo {
namespace dbus_utils {

const char kTestPath[] = "/test/path";
const char kTestServiceName[] = "org.test.Object";
const char kTestInterface[] = "org.test.Object.TestInterface";
const char kTestMethod1[] = "TestMethod1";
const char kTestMethod2[] = "TestMethod2";
const char kTestMethod3[] = "TestMethod3";
const char kTestMethod4[] = "TestMethod4";

class DBusMethodInvokerTest : public testing::Test {
 public:
  void SetUp() override {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::MockBus(options);
    // By default, don't worry about threading assertions.
    EXPECT_CALL(*bus_, AssertOnOriginThread()).Times(AnyNumber());
    EXPECT_CALL(*bus_, AssertOnDBusThread()).Times(AnyNumber());
    // Use a mock exported object.
    mock_object_proxy_ = new dbus::MockObjectProxy(bus_.get(), kTestServiceName,
                                                   dbus::ObjectPath(kTestPath));
    EXPECT_CALL(*bus_,
                GetObjectProxy(kTestServiceName, dbus::ObjectPath(kTestPath)))
        .WillRepeatedly(Return(mock_object_proxy_.get()));
    int def_timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT;
    EXPECT_CALL(*mock_object_proxy_,
                CallMethodAndBlockWithErrorDetails(_, def_timeout_ms, _))
        .WillRepeatedly(Invoke(this, &DBusMethodInvokerTest::CreateResponse));
  }

  void TearDown() override { bus_ = nullptr; }

  std::unique_ptr<Response> CreateResponse(dbus::MethodCall* method_call,
                                           int /* timeout_ms */,
                                           dbus::ScopedDBusError* dbus_error) {
    if (method_call->GetInterface() == kTestInterface) {
      if (method_call->GetMember() == kTestMethod1) {
        MessageReader reader(method_call);
        int v1, v2;
        // Input: two ints.
        // Output: sum of the ints converted to string.
        if (reader.PopInt32(&v1) && reader.PopInt32(&v2)) {
          auto response = Response::CreateEmpty();
          MessageWriter writer(response.get());
          writer.AppendString(std::to_string(v1 + v2));
          return response;
        }
      } else if (method_call->GetMember() == kTestMethod2) {
        method_call->SetSerial(123);
        dbus_set_error(dbus_error->get(), "org.MyError", "My error message");
        return std::unique_ptr<dbus::Response>();
      } else if (method_call->GetMember() == kTestMethod3) {
        MessageReader reader(method_call);
        dbus_utils_test::TestMessage msg;
        if (PopValueFromReader(&reader, &msg)) {
          auto response = Response::CreateEmpty();
          MessageWriter writer(response.get());
          AppendValueToWriter(&writer, msg);
          return response;
        }
      } else if (method_call->GetMember() == kTestMethod4) {
        method_call->SetSerial(123);
        MessageReader reader(method_call);
        base::ScopedFD fd;
        if (reader.PopFileDescriptor(&fd)) {
          auto response = Response::CreateEmpty();
          MessageWriter writer(response.get());
          writer.AppendFileDescriptor(fd.get());
          return response;
        }
      }
    }

    LOG(ERROR) << "Unexpected method call: " << method_call->ToString();
    return std::unique_ptr<dbus::Response>();
  }

  std::string CallTestMethod(int v1, int v2) {
    std::unique_ptr<dbus::Response> response =
        brillo::dbus_utils::CallMethodAndBlock(mock_object_proxy_.get(),
                                               kTestInterface, kTestMethod1,
                                               nullptr, v1, v2);
    EXPECT_NE(nullptr, response.get());
    std::string result;
    using brillo::dbus_utils::ExtractMethodCallResults;
    EXPECT_TRUE(ExtractMethodCallResults(response.get(), nullptr, &result));
    return result;
  }

  dbus_utils_test::TestMessage CallProtobufTestMethod(
      const dbus_utils_test::TestMessage& message) {
    std::unique_ptr<dbus::Response> response =
        brillo::dbus_utils::CallMethodAndBlock(mock_object_proxy_.get(),
                                               kTestInterface, kTestMethod3,
                                               nullptr, message);
    EXPECT_NE(nullptr, response.get());
    dbus_utils_test::TestMessage result;
    using brillo::dbus_utils::ExtractMethodCallResults;
    EXPECT_TRUE(ExtractMethodCallResults(response.get(), nullptr, &result));
    return result;
  }

  // Sends a file descriptor received over D-Bus back to the caller using the
  // new types.
  base::ScopedFD EchoFD(base::ScopedFD fd_in) {
    std::unique_ptr<dbus::Response> response =
        brillo::dbus_utils::CallMethodAndBlock(mock_object_proxy_.get(),
                                               kTestInterface, kTestMethod4,
                                               nullptr, std::move(fd_in));
    EXPECT_NE(nullptr, response.get());
    base::ScopedFD fd_out;
    using brillo::dbus_utils::ExtractMethodCallResults;
    EXPECT_TRUE(ExtractMethodCallResults(response.get(), nullptr, &fd_out));
    return fd_out;
  }
  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy_;
};

TEST_F(DBusMethodInvokerTest, TestSuccess) {
  EXPECT_EQ("4", CallTestMethod(2, 2));
  EXPECT_EQ("10", CallTestMethod(3, 7));
  EXPECT_EQ("-4", CallTestMethod(13, -17));
}

TEST_F(DBusMethodInvokerTest, TestFailure) {
  brillo::ErrorPtr error;
  std::unique_ptr<dbus::Response> response =
      brillo::dbus_utils::CallMethodAndBlock(
          mock_object_proxy_.get(), kTestInterface, kTestMethod2, &error);
  EXPECT_EQ(nullptr, response.get());
  EXPECT_EQ(brillo::errors::dbus::kDomain, error->GetDomain());
  EXPECT_EQ("org.MyError", error->GetCode());
  EXPECT_NE(std::string::npos, error->GetMessage().find("My error message"));
}

TEST_F(DBusMethodInvokerTest, TestProtobuf) {
  dbus_utils_test::TestMessage test_message;
  test_message.set_foo(123);
  test_message.set_bar("bar");

  dbus_utils_test::TestMessage resp = CallProtobufTestMethod(test_message);

  EXPECT_EQ(123, resp.foo());
  EXPECT_EQ("bar", resp.bar());
}

TEST_F(DBusMethodInvokerTest, TestFileDescriptors) {
  {
    base::ScopedFD out_fd = EchoFD(base::ScopedFD(dup(STDIN_FILENO)));
    ASSERT_TRUE(out_fd.is_valid());
  }
  {
    base::ScopedFD out_fd = EchoFD(base::ScopedFD(dup(STDOUT_FILENO)));
    ASSERT_TRUE(out_fd.is_valid());
  }
}

//////////////////////////////////////////////////////////////////////////////
// Asynchronous method invocation support

class AsyncDBusMethodInvokerTest : public testing::Test {
 public:
  void SetUp() override {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::MockBus(options);
    // By default, don't worry about threading assertions.
    EXPECT_CALL(*bus_, AssertOnOriginThread()).Times(AnyNumber());
    EXPECT_CALL(*bus_, AssertOnDBusThread()).Times(AnyNumber());
    // Use a mock exported object.
    mock_object_proxy_ = new dbus::MockObjectProxy(bus_.get(), kTestServiceName,
                                                   dbus::ObjectPath(kTestPath));
    EXPECT_CALL(*bus_,
                GetObjectProxy(kTestServiceName, dbus::ObjectPath(kTestPath)))
        .WillRepeatedly(Return(mock_object_proxy_.get()));
    int def_timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT;
    EXPECT_CALL(*mock_object_proxy_,
                DoCallMethodWithErrorCallback(_, def_timeout_ms, _, _))
        .WillRepeatedly(Invoke(this, &AsyncDBusMethodInvokerTest::HandleCall));
  }

  void TearDown() override { bus_ = nullptr; }

  void HandleCall(dbus::MethodCall* method_call,
                  int /* timeout_ms */,
                  dbus::ObjectProxy::ResponseCallback* success_callback,
                  dbus::ObjectProxy::ErrorCallback* error_callback) {
    if (method_call->GetInterface() == kTestInterface) {
      if (method_call->GetMember() == kTestMethod1) {
        MessageReader reader(method_call);
        int v1, v2;
        // Input: two ints.
        // Output: sum of the ints converted to string.
        if (reader.PopInt32(&v1) && reader.PopInt32(&v2)) {
          auto response = Response::CreateEmpty();
          MessageWriter writer(response.get());
          writer.AppendString(std::to_string(v1 + v2));
          std::move(*success_callback).Run(response.get());
        }
        return;
      } else if (method_call->GetMember() == kTestMethod2) {
        method_call->SetSerial(123);
        auto error_response = dbus::ErrorResponse::FromMethodCall(
            method_call, "org.MyError", "My error message");
        std::move(*error_callback).Run(error_response.get());
        return;
      }
    }

    LOG(FATAL) << "Unexpected method call: " << method_call->ToString();
  }

  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy_;
};

TEST_F(AsyncDBusMethodInvokerTest, TestSuccess) {
  int error_count = 0;
  int success_count = 0;
  brillo::dbus_utils::CallMethod(
      mock_object_proxy_.get(), kTestInterface, kTestMethod1,
      base::BindOnce(SuccessCallback, "4", &success_count),
      base::BindOnce(SimpleErrorCallback, &error_count), 2, 2);
  brillo::dbus_utils::CallMethod(
      mock_object_proxy_.get(), kTestInterface, kTestMethod1,
      base::BindOnce(SuccessCallback, "10", &success_count),
      base::BindOnce(SimpleErrorCallback, &error_count), 3, 7);
  brillo::dbus_utils::CallMethod(
      mock_object_proxy_.get(), kTestInterface, kTestMethod1,
      base::BindOnce(SuccessCallback, "-4", &success_count),
      base::BindOnce(SimpleErrorCallback, &error_count), 13, -17);
  EXPECT_EQ(0, error_count);
  EXPECT_EQ(3, success_count);
}

TEST_F(AsyncDBusMethodInvokerTest, TestFailure) {
  int error_count = 0;
  int success_count = 0;
  brillo::dbus_utils::CallMethod(
      mock_object_proxy_.get(), kTestInterface, kTestMethod2,
      base::BindOnce(SimpleSuccessCallback, &success_count),
      base::BindOnce(ErrorCallback, brillo::errors::dbus::kDomain,
                     "org.MyError", "My error message", &error_count),
      2, 2);
  EXPECT_EQ(1, error_count);
  EXPECT_EQ(0, success_count);
}

}  // namespace dbus_utils
}  // namespace brillo
