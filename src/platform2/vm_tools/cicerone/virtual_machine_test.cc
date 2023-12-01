// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/logging.h>
#include <base/uuid.h>
#include <gtest/gtest.h>

#include <vm_cicerone/cicerone_service.pb.h>
#include "vm_tools/cicerone/virtual_machine.h"

namespace vm_tools {
namespace cicerone {
namespace {

// Fake IP addresses to use for testing.
constexpr char kFakeIp1[] = "1.2.3.4";
constexpr char kFakeIp2[] = "5.6.7.8";

// Fake garcon vsock ports to use for testing.
constexpr uint32_t kFakeGarconPort1 = 1234;
constexpr uint32_t kFakeGarconPort2 = 2345;

// Fake container names to use for testing.
constexpr char kFakeContainerName1[] = "box";
constexpr char kFakeContainerName2[] = "cube";

constexpr char kVmToken[] = "token";

}  // namespace

// Test fixture for actually testing the VirtualMachine functionality.
class VirtualMachineTest : public ::testing::Test {
 public:
  VirtualMachineTest() : termina_vm_(1, 2, ""), plugin_vm_(0, 3, kVmToken) {}
  VirtualMachineTest(const VirtualMachineTest&) = delete;
  VirtualMachineTest& operator=(const VirtualMachineTest&) = delete;

  ~VirtualMachineTest() override = default;

 protected:
  // Actual virtual machine being tested.
  VirtualMachine termina_vm_;
  VirtualMachine plugin_vm_;
};

TEST_F(VirtualMachineTest, NoContainerToken) {
  // If the token was never generated, then [un]registration should fail.
  EXPECT_FALSE(termina_vm_.RegisterContainer(
      base::Uuid::GenerateRandomV4().AsLowercaseString(), kFakeGarconPort1,
      kFakeIp1));
  EXPECT_FALSE(termina_vm_.UnregisterContainer(
      base::Uuid::GenerateRandomV4().AsLowercaseString()));
}

TEST_F(VirtualMachineTest, InvalidContainerToken) {
  // If the wrong token is used, then registration should fail.
  std::string token = termina_vm_.GenerateContainerToken(kFakeContainerName1);
  EXPECT_FALSE(termina_vm_.RegisterContainer(
      base::Uuid::GenerateRandomV4().AsLowercaseString(), kFakeGarconPort1,
      kFakeIp1));
  // Invalid token should fail unregister operation.
  EXPECT_FALSE(termina_vm_.UnregisterContainer(
      base::Uuid::GenerateRandomV4().AsLowercaseString()));
}

TEST_F(VirtualMachineTest, ValidContainerToken) {
  // Valid process for generating a token and then registering it and
  // unregistering it.
  std::string token = termina_vm_.GenerateContainerToken(kFakeContainerName1);
  EXPECT_TRUE(termina_vm_.RegisterContainer(token, kFakeGarconPort1, kFakeIp1));
  EXPECT_EQ(kFakeContainerName1, termina_vm_.GetContainerNameForToken(token));
  EXPECT_TRUE(termina_vm_.UnregisterContainer(token));
  EXPECT_EQ("", termina_vm_.GetContainerNameForToken(token));
}

TEST_F(VirtualMachineTest, ReuseContainerToken) {
  // Re-registering the same token is valid and unregistering it should work.
  std::string token = termina_vm_.GenerateContainerToken(kFakeContainerName1);
  EXPECT_TRUE(termina_vm_.RegisterContainer(token, kFakeGarconPort1, kFakeIp1));
  EXPECT_TRUE(termina_vm_.RegisterContainer(token, kFakeGarconPort2, kFakeIp2));
  EXPECT_EQ(kFakeContainerName1, termina_vm_.GetContainerNameForToken(token));
  EXPECT_TRUE(termina_vm_.UnregisterContainer(token));
  EXPECT_EQ("", termina_vm_.GetContainerNameForToken(token));
}

TEST_F(VirtualMachineTest, MultipleContainerTokens) {
  // Valid process for generating a token and then registering it from multiple
  // containers and also unregistering them.
  std::string token1 = termina_vm_.GenerateContainerToken(kFakeContainerName1);
  EXPECT_TRUE(
      termina_vm_.RegisterContainer(token1, kFakeGarconPort1, kFakeIp1));
  std::string token2 = termina_vm_.GenerateContainerToken(kFakeContainerName2);
  EXPECT_TRUE(
      termina_vm_.RegisterContainer(token2, kFakeGarconPort2, kFakeIp2));
  EXPECT_EQ(kFakeContainerName1, termina_vm_.GetContainerNameForToken(token1));
  EXPECT_EQ(kFakeContainerName2, termina_vm_.GetContainerNameForToken(token2));

  // Now unregister the first one.
  EXPECT_TRUE(termina_vm_.UnregisterContainer(token1));
  EXPECT_EQ("", termina_vm_.GetContainerNameForToken(token1));

  // Second one should still be there.
  EXPECT_EQ(kFakeContainerName2, termina_vm_.GetContainerNameForToken(token2));

  // No unregister the second one.
  EXPECT_TRUE(termina_vm_.UnregisterContainer(token2));
  EXPECT_EQ("", termina_vm_.GetContainerNameForToken(token2));
}

TEST_F(VirtualMachineTest, PluginVmRegisterContainer) {
  // We should fail registration with an invalid token, and succeed with a valid
  // token.
  EXPECT_FALSE(
      plugin_vm_.RegisterContainer("bad_token", kFakeGarconPort1, kFakeIp1));
  EXPECT_TRUE(
      plugin_vm_.RegisterContainer(kVmToken, kFakeGarconPort1, kFakeIp1));
  // There is no unregistration of plugin VM containers since they are
  // artificial.
}

TEST_F(VirtualMachineTest, VerifyVmTypes) {
  EXPECT_EQ(termina_vm_.GetType(), VirtualMachine::VmType::TERMINA);
  EXPECT_EQ(plugin_vm_.GetType(), VirtualMachine::VmType::PLUGIN_VM);
}

class UpgradeContainerTest : public VirtualMachineTest {
 public:
  void SetUp() override {
    std::string token = termina_vm_.GenerateContainerToken(kFakeContainerName1);
    EXPECT_TRUE(
        termina_vm_.RegisterContainer(token, kFakeGarconPort1, kFakeIp1));
    container_ = termina_vm_.GetContainerForName(kFakeContainerName1);
    EXPECT_NE(container_, nullptr);
  }

 protected:
  const Container* container_;
};

}  // namespace cicerone
}  // namespace vm_tools
