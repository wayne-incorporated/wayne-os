// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <brillo/errors/error.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "debugd/dbus-proxy-mocks.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/debugd_adapter.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/debugd_adapter_impl.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::StrictMock;
using ::testing::WithArg;

namespace diagnostics {
namespace wilco {
namespace {

constexpr char kSmartAttributes[] = "attributes";
constexpr char kNvmeIdentity[] = "identify_controller";
constexpr char kNvmeShortSelfTestOption[] = "short_self_test";
constexpr char kNvmeLongSelfTestOption[] = "long_self_test";
constexpr char kNvmeStopSelfTestOption[] = "stop_self_test";
constexpr int kNvmeGetLogPageId = 6;
constexpr int kNvmeGetLogDataLength = 16;
constexpr bool kNvmeGetLogRawBinary = true;

class MockCallback {
 public:
  MOCK_METHOD(void,
              OnStringResultCallback,
              (const std::string&, brillo::Error*));
};

class DebugdAdapterImplTest : public ::testing::Test {
 public:
  DebugdAdapterImplTest()
      : debugd_proxy_mock_(new StrictMock<org::chromium::debugdProxyMock>()),
        debugd_adapter_(std::make_unique<DebugdAdapterImpl>(
            std::unique_ptr<org::chromium::debugdProxyMock>(
                debugd_proxy_mock_))) {}
  DebugdAdapterImplTest(const DebugdAdapterImplTest&) = delete;
  DebugdAdapterImplTest& operator=(const DebugdAdapterImplTest&) = delete;

 protected:
  StrictMock<MockCallback> callback_;

  // Owned by |debugd_adapter_|.
  StrictMock<org::chromium::debugdProxyMock>* debugd_proxy_mock_;

  std::unique_ptr<DebugdAdapter> debugd_adapter_;
};

// Tests that GetSmartAttributes calls callback with output on success.
TEST_F(DebugdAdapterImplTest, GetSmartAttributes) {
  constexpr char kResult[] = "S.M.A.R.T. status";
  EXPECT_CALL(*debugd_proxy_mock_, SmartctlAsync(kSmartAttributes, _, _, _))
      .WillOnce(WithArg<1>(Invoke(
          [kResult](base::OnceCallback<void(const std::string& /* result */)>
                        success_callback) {
            std::move(success_callback).Run(kResult);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback(kResult, nullptr));
  debugd_adapter_->GetSmartAttributes(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that GetSmartAttributes calls callback with error on failure.
TEST_F(DebugdAdapterImplTest, GetSmartAttributesError) {
  const brillo::ErrorPtr kError = brillo::Error::Create(FROM_HERE, "", "", "");
  EXPECT_CALL(*debugd_proxy_mock_, SmartctlAsync(kSmartAttributes, _, _, _))
      .WillOnce(WithArg<2>(
          Invoke([error = kError.get()](
                     base::OnceCallback<void(brillo::Error*)> error_callback) {
            std::move(error_callback).Run(error);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback("", kError.get()));
  debugd_adapter_->GetSmartAttributes(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that GetNvmeIdentity calls callback with output on success.
TEST_F(DebugdAdapterImplTest, GetNvmeIdentity) {
  constexpr char kResult[] = "NVMe identity data";
  EXPECT_CALL(*debugd_proxy_mock_, NvmeAsync(kNvmeIdentity, _, _, _))
      .WillOnce(WithArg<1>(Invoke(
          [kResult](base::OnceCallback<void(const std::string& /* result */)>
                        success_callback) {
            std::move(success_callback).Run(kResult);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback(kResult, nullptr));
  debugd_adapter_->GetNvmeIdentity(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that GetNvmeIdentity calls callback with error on failure.
TEST_F(DebugdAdapterImplTest, GetNvmeIdentityError) {
  const brillo::ErrorPtr kError = brillo::Error::Create(FROM_HERE, "", "", "");
  EXPECT_CALL(*debugd_proxy_mock_, NvmeAsync(kNvmeIdentity, _, _, _))
      .WillOnce(WithArg<2>(
          Invoke([error = kError.get()](
                     base::OnceCallback<void(brillo::Error*)> error_callback) {
            std::move(error_callback).Run(error);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback("", kError.get()));
  debugd_adapter_->GetNvmeIdentity(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that GetNvmeIdentitySync returns the output on success.
TEST_F(DebugdAdapterImplTest, GetNvmeIdentitySync) {
  constexpr char kResult[] = "NVMe identity data";
  EXPECT_CALL(*debugd_proxy_mock_, Nvme(kNvmeIdentity, _, _, _))
      .WillOnce(WithArg<1>(Invoke([kResult](std::string* out_string) {
        *out_string = kResult;
        return true;
      })));
  auto result = debugd_adapter_->GetNvmeIdentitySync();
  EXPECT_EQ(result.value, kResult);
  EXPECT_FALSE(result.error);
}

// Tests that GetNvmeIdentitySync returns an error on failure.
TEST_F(DebugdAdapterImplTest, GetNvmeIdentitySyncError) {
  brillo::ErrorPtr kError = brillo::Error::Create(FROM_HERE, "", "", "");
  EXPECT_CALL(*debugd_proxy_mock_, Nvme(kNvmeIdentity, _, _, _))
      .WillOnce(WithArg<2>(Invoke([&kError](brillo::ErrorPtr* error) {
        *error = kError->Clone();
        return false;
      })));
  auto result = debugd_adapter_->GetNvmeIdentitySync();
  EXPECT_TRUE(result.error);
  EXPECT_EQ(result.error->GetLocation(), kError->GetLocation());
}

// Tests that RunNvmeShortSelfTest calls callback with output on success.
TEST_F(DebugdAdapterImplTest, RunNvmeShortSelfTest) {
  constexpr char kResult[] = "Device self-test started";
  EXPECT_CALL(*debugd_proxy_mock_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>(Invoke(
          [kResult](base::OnceCallback<void(const std::string& /* result */)>
                        success_callback) {
            std::move(success_callback).Run(kResult);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback(kResult, nullptr));
  debugd_adapter_->RunNvmeShortSelfTest(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that RunNvmeShortSelfTest calls callback with error on failure.
TEST_F(DebugdAdapterImplTest, RunNvmeShortSelfTestError) {
  const brillo::ErrorPtr kError = brillo::Error::Create(FROM_HERE, "", "", "");
  EXPECT_CALL(*debugd_proxy_mock_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<2>(
          Invoke([error = kError.get()](
                     base::OnceCallback<void(brillo::Error*)> error_callback) {
            std::move(error_callback).Run(error);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback("", kError.get()));
  debugd_adapter_->RunNvmeShortSelfTest(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that RunNvmeLongSelfTest calls callback with output on success.
TEST_F(DebugdAdapterImplTest, RunNvmeLongSelfTest) {
  constexpr char kResult[] = "Device self-test started";
  EXPECT_CALL(*debugd_proxy_mock_, NvmeAsync(kNvmeLongSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>(Invoke(
          [kResult](base::OnceCallback<void(const std::string& /* result */)>
                        success_callback) {
            std::move(success_callback).Run(kResult);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback(kResult, nullptr));
  debugd_adapter_->RunNvmeLongSelfTest(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that RunNvmeLongSelfTest calls callback with error on failure.
TEST_F(DebugdAdapterImplTest, RunNvmeLongSelfTestError) {
  const brillo::ErrorPtr kError = brillo::Error::Create(FROM_HERE, "", "", "");
  EXPECT_CALL(*debugd_proxy_mock_, NvmeAsync(kNvmeLongSelfTestOption, _, _, _))
      .WillOnce(WithArg<2>(
          Invoke([error = kError.get()](
                     base::OnceCallback<void(brillo::Error*)> error_callback) {
            std::move(error_callback).Run(error);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback("", kError.get()));
  debugd_adapter_->RunNvmeLongSelfTest(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that StopNvmeSelfTest calls callback with output on success.
TEST_F(DebugdAdapterImplTest, StopNvmeSelfTest) {
  constexpr char kResult[] = "Aborting device self-test operation";
  EXPECT_CALL(*debugd_proxy_mock_, NvmeAsync(kNvmeStopSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>(Invoke(
          [kResult](base::OnceCallback<void(const std::string& /* result */)>
                        success_callback) {
            std::move(success_callback).Run(kResult);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback(kResult, nullptr));
  debugd_adapter_->StopNvmeSelfTest(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that StopNvmeSelfTest calls callback with error on failure.
TEST_F(DebugdAdapterImplTest, StopNvmeSelfTestError) {
  const brillo::ErrorPtr kError = brillo::Error::Create(FROM_HERE, "", "", "");
  EXPECT_CALL(*debugd_proxy_mock_, NvmeAsync(kNvmeStopSelfTestOption, _, _, _))
      .WillOnce(WithArg<2>(
          Invoke([error = kError.get()](
                     base::OnceCallback<void(brillo::Error*)> error_callback) {
            std::move(error_callback).Run(error);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback("", kError.get()));
  debugd_adapter_->StopNvmeSelfTest(base::BindOnce(
      &MockCallback::OnStringResultCallback, base::Unretained(&callback_)));
}

// Tests that GetNvmeLog calls callback with output on success.
TEST_F(DebugdAdapterImplTest, GetNvmeLog) {
  constexpr char kResult[] = "AAAAABEAAACHEAAAAAAAAA==";
  EXPECT_CALL(*debugd_proxy_mock_,
              NvmeLogAsync(kNvmeGetLogPageId, kNvmeGetLogDataLength,
                           kNvmeGetLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>(Invoke(
          [kResult](base::OnceCallback<void(const std::string& /* result */)>
                        success_callback) {
            std::move(success_callback).Run(kResult);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback(kResult, nullptr));
  debugd_adapter_->GetNvmeLog(
      kNvmeGetLogPageId, kNvmeGetLogDataLength, kNvmeGetLogRawBinary,
      base::BindOnce(&MockCallback::OnStringResultCallback,
                     base::Unretained(&callback_)));
}

// Tests that GetNvmeLog calls callback with error on failure.
TEST_F(DebugdAdapterImplTest, GetNvmeLogError) {
  const brillo::ErrorPtr kError = brillo::Error::Create(FROM_HERE, "", "", "");
  EXPECT_CALL(*debugd_proxy_mock_,
              NvmeLogAsync(kNvmeGetLogPageId, kNvmeGetLogDataLength,
                           kNvmeGetLogRawBinary, _, _, _))
      .WillOnce(WithArg<4>(
          Invoke([error = kError.get()](
                     base::OnceCallback<void(brillo::Error*)> error_callback) {
            std::move(error_callback).Run(error);
          })));
  EXPECT_CALL(callback_, OnStringResultCallback("", kError.get()));
  debugd_adapter_->GetNvmeLog(
      kNvmeGetLogPageId, kNvmeGetLogDataLength, kNvmeGetLogRawBinary,
      base::BindOnce(&MockCallback::OnStringResultCallback,
                     base::Unretained(&callback_)));
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
