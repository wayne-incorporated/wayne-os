// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/dhcp_provider.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>

#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/network/dhcp_controller.h"

using testing::_;
using testing::StrictMock;
using testing::Test;

namespace shill {

namespace {
const char kDeviceName[] = "testdevicename";
const char kStorageIdentifier[] = "teststorageidentifier";
const bool kArpGateway = false;
}  // namespace

class DHCPProviderTest : public Test {
 public:
  DHCPProviderTest() : provider_(DHCPProvider::GetInstance()) {
    provider_->control_interface_ = &control_;
    provider_->dispatcher_ = &dispatcher_;
  }

  void SetUp() {
    // DHCPProvider is a singleton, there is no guarentee that it is
    // not setup/used elsewhere, so reset its state before running our
    // tests.
    provider_->controllers_.clear();
    provider_->recently_unbound_pids_.clear();
  }

 protected:
  void RetireUnboundPID(int pid) { provider_->RetireUnboundPID(pid); }

  static DHCPProvider::Options CreateOptions() {
    DHCPProvider::Options opts;
    opts.use_arp_gateway = kArpGateway;
    opts.hostname = kDeviceName;
    opts.lease_name = kStorageIdentifier;
    return opts;
  }

  MockControl control_;
  DHCPProvider* provider_;
  StrictMock<MockEventDispatcher> dispatcher_;
};

TEST_F(DHCPProviderTest, CreateController) {
  auto config = provider_->CreateController(kDeviceName, CreateOptions(),
                                            Technology::kUnknown);
  EXPECT_NE(nullptr, config);
  EXPECT_EQ(kDeviceName, config->device_name());
  EXPECT_TRUE(provider_->controllers_.empty());
}

TEST_F(DHCPProviderTest, DestroyLease) {
  base::ScopedTempDir temp_dir;
  base::FilePath lease_file;
  EXPECT_TRUE(temp_dir.CreateUniqueTempDir());
  provider_->root_ = temp_dir.GetPath();
  lease_file = provider_->root_.Append(
      base::StringPrintf(DHCPProvider::kDHCPCDPathFormatLease, kDeviceName));
  EXPECT_TRUE(base::CreateDirectory(lease_file.DirName()));
  EXPECT_EQ(0, base::WriteFile(lease_file, "", 0));
  EXPECT_TRUE(base::PathExists(lease_file));
  provider_->DestroyLease(kDeviceName);
  EXPECT_FALSE(base::PathExists(lease_file));
}

TEST_F(DHCPProviderTest, BindAndUnbind) {
  int kPid = 999;
  EXPECT_EQ(nullptr, provider_->GetController(kPid));
  EXPECT_FALSE(provider_->IsRecentlyUnbound(kPid));

  auto config = provider_->CreateController(kDeviceName, CreateOptions(),
                                            Technology::kUnknown);
  provider_->BindPID(kPid, config->weak_ptr_factory_.GetWeakPtr());
  EXPECT_NE(nullptr, provider_->GetController(kPid));
  EXPECT_FALSE(provider_->IsRecentlyUnbound(kPid));

  // TODO(pstew): crbug.com/502320
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, _));
  provider_->UnbindPID(kPid);
  EXPECT_EQ(nullptr, provider_->GetController(kPid));
  EXPECT_TRUE(provider_->IsRecentlyUnbound(kPid));

  RetireUnboundPID(kPid);  // Execute as if the PostDelayedTask() timer expired.
  EXPECT_EQ(nullptr, provider_->GetController(kPid));
  EXPECT_FALSE(provider_->IsRecentlyUnbound(kPid));

  // Destroying the DHCPController object should also trigger an Unbind().
  provider_->BindPID(kPid, config->weak_ptr_factory_.GetWeakPtr());
  config->pid_ = kPid;
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, _));
  config = nullptr;
  EXPECT_EQ(nullptr, provider_->GetController(kPid));
}

}  // namespace shill
