// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vmm_swap_low_disk_policy.h"

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <brillo/errors/error.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <spaced/dbus-proxies.h>
#include <spaced/dbus-proxy-mocks.h>
#include <spaced/disk_usage_proxy.h>

using ::testing::_;

namespace vm_tools::concierge {

namespace {
std::function<void(const std::string&,
                   base::OnceCallback<void(int64_t)>,
                   base::OnceCallback<void(brillo::Error*)>,
                   int)>
SpacedProxyReturnsSuccess(int64_t size) {
  return [size](const std::string& in_path,
                base::OnceCallback<void(int64_t)> success_callback,
                base::OnceCallback<void(brillo::Error*)> error_callback,
                int timeout_ms) { std::move(success_callback).Run(size); };
}

class VmmSwapLowDiskPolicyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto file_path = base::FilePath("test");
    mock_ = new org::chromium::SpacedProxyMock();
    disk_usage_proxy_ = std::make_unique<spaced::DiskUsageProxy>(
        std::unique_ptr<org::chromium::SpacedProxyMock>(mock_));
    policy_ = std::make_unique<VmmSwapLowDiskPolicy>(
        file_path,
        raw_ref<spaced::DiskUsageProxy>::from_ptr(disk_usage_proxy_.get()));
  }

  raw_ptr<org::chromium::SpacedProxyMock> mock_;
  std::unique_ptr<spaced::DiskUsageProxy> disk_usage_proxy_;
  std::unique_ptr<VmmSwapLowDiskPolicy> policy_;
};

class VmmSwapLowDiskPolicyResult final {
 public:
  base::OnceCallback<void(bool)> Callback() {
    return base::BindOnce(&VmmSwapLowDiskPolicyResult::Update,
                          base::Unretained(this));
  }

  std::optional<bool> result_;

 private:
  void Update(bool result) { result_ = result; }
};
}  // namespace

TEST_F(VmmSwapLowDiskPolicyTest, CanSwapOut) {
  VmmSwapLowDiskPolicyResult result;

  // Free space = 10 GiB
  EXPECT_CALL(*mock_, GetFreeDiskSpaceAsync(_, _, _, _))
      .WillOnce(SpacedProxyReturnsSuccess((int64_t)10 << 30));
  // Guest memory = 1 GiB
  policy_->CanEnable(1 << 30, result.Callback());
  EXPECT_TRUE(result.result_.has_value());
  EXPECT_TRUE(result.result_.value());
}

TEST_F(VmmSwapLowDiskPolicyTest, CanSwapOutOnBorder) {
  VmmSwapLowDiskPolicyResult result;

  // Free space = 3 GiB
  EXPECT_CALL(*mock_, GetFreeDiskSpaceAsync(_, _, _, _))
      .WillOnce(SpacedProxyReturnsSuccess((int64_t)3 << 30));
  // Guest memory = 1 GiB
  policy_->CanEnable(1 << 30, result.Callback());
  EXPECT_TRUE(result.result_.has_value());
  EXPECT_TRUE(result.result_.value());
}

TEST_F(VmmSwapLowDiskPolicyTest, CanSwapOutFreeMemoryIsLow) {
  VmmSwapLowDiskPolicyResult result;

  // Free space = 3 GiB - 1
  EXPECT_CALL(*mock_, GetFreeDiskSpaceAsync(_, _, _, _))
      .WillOnce(SpacedProxyReturnsSuccess(((int64_t)3 << 30) - 1));
  // Guest memory = 1 GiB
  policy_->CanEnable(1 << 30, result.Callback());
  EXPECT_TRUE(result.result_.has_value());
  EXPECT_FALSE(result.result_.value());
}

TEST_F(VmmSwapLowDiskPolicyTest, CanSwapOutFreeMemoryIsZero) {
  VmmSwapLowDiskPolicyResult result;

  // Free space = 0
  EXPECT_CALL(*mock_, GetFreeDiskSpaceAsync(_, _, _, _))
      .WillOnce(SpacedProxyReturnsSuccess(0));
  // Guest memory = 1 GiB
  policy_->CanEnable(1 << 30, result.Callback());
  EXPECT_TRUE(result.result_.has_value());
  EXPECT_FALSE(result.result_.value());
}

TEST_F(VmmSwapLowDiskPolicyTest, CanSwapOutGuestMemoryIsLowAndBorder) {
  VmmSwapLowDiskPolicyResult result;

  // Free space = 2.5 GiB
  EXPECT_CALL(*mock_, GetFreeDiskSpaceAsync(_, _, _, _))
      .WillOnce(SpacedProxyReturnsSuccess((int64_t)5 << 29));
  // Guest memory = 0.5 GiB
  policy_->CanEnable(1 << 29, result.Callback());
  EXPECT_TRUE(result.result_.has_value());
  EXPECT_TRUE(result.result_.value());
}

TEST_F(VmmSwapLowDiskPolicyTest, CanSwapOutGuestMemoryIsLow) {
  VmmSwapLowDiskPolicyResult result;

  // Free space = 2.5 GiB - 1
  EXPECT_CALL(*mock_, GetFreeDiskSpaceAsync(_, _, _, _))
      .WillOnce(SpacedProxyReturnsSuccess(((int64_t)3 << 29) - 1));
  // Guest memory = 0.5 GiB
  policy_->CanEnable(1 << 29, result.Callback());
  EXPECT_TRUE(result.result_.has_value());
  EXPECT_FALSE(result.result_.value());
}

TEST_F(VmmSwapLowDiskPolicyTest, CanSwapOutSpacedFailure) {
  VmmSwapLowDiskPolicyResult result;

  // spaced return negative value
  EXPECT_CALL(*mock_, GetFreeDiskSpaceAsync(_, _, _, _))
      .WillOnce(SpacedProxyReturnsSuccess(-1));
  policy_->CanEnable(1 << 30, result.Callback());
  EXPECT_TRUE(result.result_.has_value());
  EXPECT_FALSE(result.result_.value());
}

TEST_F(VmmSwapLowDiskPolicyTest, CanSwapOutDBusFailure) {
  VmmSwapLowDiskPolicyResult result;

  // DBus error.
  EXPECT_CALL(*mock_, GetFreeDiskSpaceAsync(_, _, _, _))
      .WillOnce([](const std::string& in_path,
                   base::OnceCallback<void(int64_t)> success_callback,
                   base::OnceCallback<void(brillo::Error*)> error_callback,
                   int timeout_ms) {
        auto error =
            brillo::Error::CreateNoLog(FROM_HERE, brillo::errors::dbus::kDomain,
                                       "dummy", "message", nullptr);
        std::move(error_callback).Run(error.get());
      });
  policy_->CanEnable(1 << 30, result.Callback());
  EXPECT_TRUE(result.result_.has_value());
  EXPECT_FALSE(result.result_.value());
}

}  // namespace vm_tools::concierge
