// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <functional>
#include <memory>
#include <utility>

#include <base/test/bind.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "biod/biod_proxy/biometrics_manager_proxy_base.h"

namespace biod {

using testing::_;
using testing::ByMove;
using testing::Return;

class BiometricsManagerProxyBaseTest : public testing::Test {
 public:
  BiometricsManagerProxyBaseTest() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    mock_bus_ = base::MakeRefCounted<dbus::MockBus>(options);

    mock_object_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        mock_bus_.get(), kBiodServiceName, dbus::ObjectPath(kBiodServicePath));

    // Set an expectation so that the MockBus will return our mock proxy.
    EXPECT_CALL(*mock_bus_, GetObjectProxy(kBiodServiceName,
                                           dbus::ObjectPath(kBiodServicePath)))
        .WillOnce(Return(mock_object_proxy_.get()));

    proxy_base_ = BiometricsManagerProxyBase::Create(
        mock_bus_.get(), dbus::ObjectPath(kBiodServicePath));
  }

  void CallFinish(bool success) { proxy_base_->OnFinish(success); }

  void CallOnSignalConnected(bool success) {
    proxy_base_->OnSignalConnected("unused interface", "unused signal",
                                   success);
  }

  void CallOnSessionFailed() { proxy_base_->OnSessionFailed(nullptr); }

  dbus::ObjectProxy* GetBiodAuthSession() {
    return proxy_base_->biod_auth_session_;
  }

  std::unique_ptr<BiometricsManagerProxyBase> proxy_base_;
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy_;
  scoped_refptr<dbus::MockBus> mock_bus_;
  bool status_ = false;
};

namespace {

// Test that we can install and exercise a custom finish handler.
TEST_F(BiometricsManagerProxyBaseTest, RunFinishHandlerWithTrue) {
  status_ = false;
  proxy_base_->SetFinishHandler(
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  CallFinish(true);
  EXPECT_TRUE(status_);
}

// Test that we can install and exercise a custom finish handler.
TEST_F(BiometricsManagerProxyBaseTest, RunFinishHandlerWithFalse) {
  status_ = true;
  proxy_base_->SetFinishHandler(
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  CallFinish(false);
  EXPECT_FALSE(status_);
}

// Test that StartAuthSession returns nullptr if no dbus response.
TEST_F(BiometricsManagerProxyBaseTest, StartAuthSessionNoResponse) {
  EXPECT_CALL(*mock_object_proxy_, CallMethodAndBlock)
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));
  EXPECT_FALSE(proxy_base_->StartAuthSession());
  EXPECT_EQ(GetBiodAuthSession(), nullptr);
}

// Test that StartAuthSession succeeds and the object proxy saved by
// StartAuthSession is what the mock provides.
TEST_F(BiometricsManagerProxyBaseTest, StartAuthSessionGetSessionProxy) {
  // The path must be correctly formatted for the writer to accept it.
  const dbus::ObjectPath auth_session_path("/org/chromium/Foo/AuthSession");
  auto fake_response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(fake_response.get());
  writer.AppendObjectPath(auth_session_path);

  auto auth_session_proxy = base::MakeRefCounted<dbus::MockObjectProxy>(
      mock_bus_.get(), kBiodServiceName, auth_session_path);

  // Set the underlying mock proxy to return our fake_response, and set the
  // mock bus to return the predefined ObjectProxy once it sees that path,
  // which the class under test will extract from the fake_response.
  EXPECT_CALL(*mock_object_proxy_, CallMethodAndBlock)
      .WillOnce(Return(ByMove(std::move(fake_response))));
  EXPECT_CALL(*mock_bus_, GetObjectProxy(kBiodServiceName, auth_session_path))
      .WillOnce(Return(auth_session_proxy.get()));

  EXPECT_TRUE(proxy_base_->StartAuthSession());
  EXPECT_EQ(GetBiodAuthSession(), auth_session_proxy.get());
}

// Test that StartAuthSessionAsync succeeds and the object proxy saved by
// StartAuthSession is what the mock provides.
TEST_F(BiometricsManagerProxyBaseTest, StartAuthSessionGetSessionProxyAsync) {
  // The path must be correctly formatted for the writer to accept it.
  const dbus::ObjectPath auth_session_path("/org/chromium/Foo/AuthSession");
  auto auth_session_proxy = base::MakeRefCounted<dbus::MockObjectProxy>(
      mock_bus_.get(), kBiodServiceName, auth_session_path);
  // Set the underlying |mock_object_proxy_| to invoke the dbus callback (in
  // this case OnStartAuthSessionResp) with a fake response containing
  // |auth_session_path|.
  auto ExecuteCallbackWithFakeResponse =
      [auth_session_path](
          dbus::MethodCall* unused_method, int unused_ms,
          base::OnceCallback<void(dbus::Response*)>* dbus_callback) {
        std::unique_ptr<dbus::Response> fake_response =
            dbus::Response::CreateEmpty();
        dbus::MessageWriter writer(fake_response.get());
        writer.AppendObjectPath(auth_session_path);
        std::move(*dbus_callback).Run(fake_response.get());
      };
  EXPECT_CALL(*mock_object_proxy_, DoCallMethod(_, _, _))
      .WillOnce(ExecuteCallbackWithFakeResponse);
  // Once OnStartAuthSessionResp is invoked with the fake response, it extracts
  // |auth_session_path| from the fake response and asks |mock_bus_| for the
  // corresponding ObjectProxy, which we set to be |auth_session_proxy|.
  // If OnStartAuthSessionResp is unable to extract the correct ObjectPath, the
  // bus will not return the correct ObjectProxy, which we catch in the end.
  EXPECT_CALL(*mock_bus_, GetObjectProxy(kBiodServiceName, auth_session_path))
      .WillOnce(Return(auth_session_proxy.get()));

  status_ = false;
  // Install a lambda as the client callback and verify it is run.
  proxy_base_->StartAuthSessionAsync(
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(status_);
  EXPECT_EQ(GetBiodAuthSession(), auth_session_proxy.get());
}

// Test that OnSessionFailed will call on_finish_ with false
TEST_F(BiometricsManagerProxyBaseTest, OnSessionFailed) {
  status_ = true;
  proxy_base_->SetFinishHandler(
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  CallOnSessionFailed();
  EXPECT_FALSE(status_);
}

// Test that OnSignalConnected if failed will call on_finish_ with false
TEST_F(BiometricsManagerProxyBaseTest, OnSignalConnectFailed) {
  status_ = true;
  proxy_base_->SetFinishHandler(
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  CallOnSignalConnected(false);
  EXPECT_FALSE(status_);
}

}  // namespace
}  // namespace biod
