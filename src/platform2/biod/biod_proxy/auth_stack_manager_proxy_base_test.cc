// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <functional>
#include <memory>
#include <optional>
#include <utility>

#include <base/test/bind.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "biod/biod_proxy/auth_stack_manager_proxy_base.h"

namespace biod {

using testing::_;
using testing::ByMove;
using testing::Return;

constexpr char kFakeUserId[] = "fake_user";

class AuthStackManagerProxyBaseTest : public testing::Test {
 public:
  void SetUp() override {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    mock_bus_ = base::MakeRefCounted<dbus::MockBus>(options);

    mock_object_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        mock_bus_.get(), kBiodServiceName, dbus::ObjectPath(kBiodServicePath));

    // Set an expectation so that the MockBus will return our mock proxy.
    EXPECT_CALL(*mock_bus_, GetObjectProxy(kBiodServiceName,
                                           dbus::ObjectPath(kBiodServicePath)))
        .WillOnce(Return(mock_object_proxy_.get()));

    proxy_base_ = AuthStackManagerProxyBase::Create(
        mock_bus_.get(), dbus::ObjectPath(kBiodServicePath));
  }

  dbus::ObjectProxy* GetBiodEnrollSession() {
    return proxy_base_->biod_enroll_session_;
  }

  dbus::ObjectProxy* GetBiodAuthSession() {
    return proxy_base_->biod_auth_session_;
  }

  std::unique_ptr<AuthStackManagerProxyBase> proxy_base_;
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy_;
  scoped_refptr<dbus::MockBus> mock_bus_;
  bool status_ = false;
};

namespace {

// Test that StartEnrollSession returns nullptr if no dbus response.
TEST_F(AuthStackManagerProxyBaseTest, StartEnrollSessionNoResponse) {
  // Set the underlying |mock_object_proxy_| to invoke the dbus callback (in
  // this case OnStartEnrollSessionResponse) with an empty response.
  auto ExecuteCallbackWithEmptyResponse =
      [](dbus::MethodCall* unused_method, int unused_ms,
         base::OnceCallback<void(dbus::Response*)>* dbus_callback) {
        std::unique_ptr<dbus::Response> fake_response =
            dbus::Response::CreateEmpty();
        std::move(*dbus_callback).Run(fake_response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethod(_, _, _))
      .WillOnce(ExecuteCallbackWithEmptyResponse);
  status_ = true;
  proxy_base_->StartEnrollSession(
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_FALSE(status_);
  EXPECT_EQ(GetBiodEnrollSession(), nullptr);
}

// Test that StartEnrollSession succeeds and the object proxy saved by
// StartEnrollSession is what the mock provides.
TEST_F(AuthStackManagerProxyBaseTest, StartEnrollSessionGetSessionProxy) {
  // The path must be correctly formatted for the writer to accept it.
  const dbus::ObjectPath enroll_session_path("/org/chromium/Foo/AuthSession");
  auto enroll_session_proxy = base::MakeRefCounted<dbus::MockObjectProxy>(
      mock_bus_.get(), kBiodServiceName, enroll_session_path);
  // Set the underlying |mock_object_proxy_| to invoke the dbus callback (in
  // this case OnStartEnrollSessionResponse) with a fake response containing
  // |enroll_session_path|.
  auto ExecuteCallbackWithFakeResponse =
      [enroll_session_path](
          dbus::MethodCall* unused_method, int unused_ms,
          base::OnceCallback<void(dbus::Response*)>* dbus_callback) {
        std::unique_ptr<dbus::Response> fake_response =
            dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(fake_response.get());
        writer.AppendObjectPath(enroll_session_path);
        std::move(*dbus_callback).Run(fake_response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethod(_, _, _))
      .WillOnce(ExecuteCallbackWithFakeResponse);
  // Once OnStartEnrollSessionResponse is invoked with the fake response, it
  // extracts |enroll_session_path| from the fake response and asks |mock_bus_|
  // for the corresponding ObjectProxy, which we set to be
  // |enroll_session_proxy|. If OnStartEnrollSessionResponse is unable to
  // extract the correct ObjectPath, the bus will not return the correct
  // ObjectProxy, which we catch in the end.
  EXPECT_CALL(*mock_bus_, GetObjectProxy(kBiodServiceName, enroll_session_path))
      .WillOnce(Return(enroll_session_proxy.get()));

  status_ = false;
  // Install a lambda as the client callback and verify it is run.
  proxy_base_->StartEnrollSession(
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(status_);
  EXPECT_EQ(GetBiodEnrollSession(), enroll_session_proxy.get());
}

// Test that CreateCredential succeeds and the returned reply is what the mock
// provides.
TEST_F(AuthStackManagerProxyBaseTest, CreateCredential) {
  CreateCredentialReply reply;
  reply.set_record_id("fake");
  // Set the underlying |mock_object_proxy_| to invoke the dbus callback (in
  // this case OnCreateCredentialResponse) with a fake response containing
  // |reply|.
  auto ExecuteCallbackWithFakeResponse =
      [reply](dbus::MethodCall* unused_method, int unused_ms,
              base::OnceCallback<void(dbus::Response*)>* dbus_callback) {
        std::unique_ptr<dbus::Response> fake_response =
            dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(fake_response.get());
        writer.AppendProtoAsArrayOfBytes(reply);
        std::move(*dbus_callback).Run(fake_response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethod(_, _, _))
      .WillOnce(ExecuteCallbackWithFakeResponse);

  CreateCredentialRequest request;
  std::optional<CreateCredentialReply> reply_ret;
  // Install a lambda as the client callback and verify it is run.
  proxy_base_->CreateCredential(
      request, base::BindLambdaForTesting(
                   [&reply_ret](std::optional<CreateCredentialReply> reply) {
                     reply_ret = reply;
                   }));
  ASSERT_TRUE(reply_ret.has_value());
  EXPECT_EQ(reply_ret->record_id(), reply.record_id());
}

// Test that CreateCredential returns nullopt when the dbus response
// is unexpected.
TEST_F(AuthStackManagerProxyBaseTest, CreateCredentialInvalidResponse) {
  // Set the underlying |mock_object_proxy_| to invoke the dbus callback (in
  // this case OnCreateCredentialResponse) with an empty response.
  auto ExecuteCallbackWithEmptyResponse =
      [](dbus::MethodCall* unused_method, int unused_ms,
         base::OnceCallback<void(dbus::Response*)>* dbus_callback) {
        std::unique_ptr<dbus::Response> fake_response =
            dbus::Response::CreateEmpty();
        std::move(*dbus_callback).Run(fake_response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethod(_, _, _))
      .WillOnce(ExecuteCallbackWithEmptyResponse);

  CreateCredentialRequest request;
  std::optional<CreateCredentialReply> reply_ret;
  // Install a lambda as the client callback and verify it is run.
  proxy_base_->CreateCredential(
      request, base::BindLambdaForTesting(
                   [&reply_ret](std::optional<CreateCredentialReply> reply) {
                     reply_ret = reply;
                   }));
  EXPECT_FALSE(reply_ret.has_value());
}

// Test that StartAuthSession returns nullptr if no dbus response.
TEST_F(AuthStackManagerProxyBaseTest, StartAuthSessionNoResponse) {
  // Set the underlying |mock_object_proxy_| to invoke the dbus callback (in
  // this case OnStartAuthSessionResponse) with an empty response.
  auto ExecuteCallbackWithEmptyResponse =
      [](dbus::MethodCall* unused_method, int unused_ms,
         base::OnceCallback<void(dbus::Response*)>* dbus_callback) {
        std::unique_ptr<dbus::Response> fake_response =
            dbus::Response::CreateEmpty();
        std::move(*dbus_callback).Run(fake_response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethod(_, _, _))
      .WillOnce(ExecuteCallbackWithEmptyResponse);
  status_ = true;
  proxy_base_->StartAuthSession(
      kFakeUserId,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_FALSE(status_);
}

// Test that StartAuthSession succeeds and the object proxy saved by
// StartAuthSession is what the mock provides.
TEST_F(AuthStackManagerProxyBaseTest, StartAuthSessionGetSessionProxy) {
  // The path must be correctly formatted for the writer to accept it.
  const dbus::ObjectPath auth_session_path("/org/chromium/Foo/AuthSession");
  auto auth_session_proxy = base::MakeRefCounted<dbus::MockObjectProxy>(
      mock_bus_.get(), kBiodServiceName, auth_session_path);
  // Set the underlying |mock_object_proxy_| to invoke the dbus callback (in
  // this case OnStartAuthSessionResponse) with a fake response containing
  // |auth_session_path|.
  auto ExecuteCallbackWithFakeResponse =
      [auth_session_path](
          dbus::MethodCall* call, int unused_ms,
          base::OnceCallback<void(dbus::Response*)>* dbus_callback) {
        dbus::MessageReader reader(call);
        std::string user_id;
        ASSERT_TRUE(reader.PopString(&user_id));
        EXPECT_EQ(user_id, kFakeUserId);
        std::unique_ptr<dbus::Response> fake_response =
            dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(fake_response.get());
        writer.AppendObjectPath(auth_session_path);
        std::move(*dbus_callback).Run(fake_response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethod(_, _, _))
      .WillOnce(ExecuteCallbackWithFakeResponse);
  // Once OnStartAuthSessionResponse is invoked with the fake response, it
  // extracts |auth_session_path| from the fake response and asks |mock_bus_|
  // for the corresponding ObjectProxy, which we set to be |auth_session_proxy|.
  // If OnStartAuthSessionResponse is unable to extract the correct ObjectPath,
  // the bus will not return the correct ObjectProxy, which we catch in the end.
  EXPECT_CALL(*mock_bus_, GetObjectProxy(kBiodServiceName, auth_session_path))
      .WillOnce(Return(auth_session_proxy.get()));

  status_ = false;
  // Install a lambda as the client callback and verify it is run.
  proxy_base_->StartAuthSession(
      kFakeUserId,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(status_);
  EXPECT_EQ(GetBiodAuthSession(), auth_session_proxy.get());
}

// Test that AuthenticateCredential succeeds and the returned reply is what the
// mock provides.
TEST_F(AuthStackManagerProxyBaseTest, AuthenticateCredential) {
  AuthenticateCredentialReply reply;
  reply.set_record_id("fake");
  // Set the underlying |mock_object_proxy_| to invoke the dbus callback (in
  // this case OnAuthenticateCredentialResponse) with a fake response containing
  // |reply|.
  auto ExecuteCallbackWithFakeResponse =
      [reply](dbus::MethodCall* unused_method, int unused_ms,
              base::OnceCallback<void(dbus::Response*)>* dbus_callback) {
        std::unique_ptr<dbus::Response> fake_response =
            dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(fake_response.get());
        writer.AppendProtoAsArrayOfBytes(reply);
        std::move(*dbus_callback).Run(fake_response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethod(_, _, _))
      .WillOnce(ExecuteCallbackWithFakeResponse);

  AuthenticateCredentialRequest request;
  std::optional<AuthenticateCredentialReply> reply_ret;
  // Install a lambda as the client callback and verify it is run.
  proxy_base_->AuthenticateCredential(
      request,
      base::BindLambdaForTesting(
          [&reply_ret](std::optional<AuthenticateCredentialReply> reply) {
            reply_ret = reply;
          }));
  ASSERT_TRUE(reply_ret.has_value());
  EXPECT_EQ(reply_ret->record_id(), reply.record_id());
}

// Test that AuthenticateCredential returns nullopt when the dbus response
// is unexpected.
TEST_F(AuthStackManagerProxyBaseTest, AuthenticateCredentialInvalidResponse) {
  // Set the underlying |mock_object_proxy_| to invoke the dbus callback (in
  // this case OnAuthenticateCredentialResponse) with an empty response.
  auto ExecuteCallbackWithEmptyResponse =
      [](dbus::MethodCall* unused_method, int unused_ms,
         base::OnceCallback<void(dbus::Response*)>* dbus_callback) {
        std::unique_ptr<dbus::Response> fake_response =
            dbus::Response::CreateEmpty();
        std::move(*dbus_callback).Run(fake_response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethod(_, _, _))
      .WillOnce(ExecuteCallbackWithEmptyResponse);

  AuthenticateCredentialRequest request;
  std::optional<AuthenticateCredentialReply> reply_ret;
  // Install a lambda as the client callback and verify it is run.
  proxy_base_->AuthenticateCredential(
      request,
      base::BindLambdaForTesting(
          [&reply_ret](std::optional<AuthenticateCredentialReply> reply) {
            reply_ret = reply;
          }));
  EXPECT_FALSE(reply_ret.has_value());
}

}  // namespace
}  // namespace biod
