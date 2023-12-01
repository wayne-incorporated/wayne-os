// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_RULE_TEST_H_
#define PERMISSION_BROKER_RULE_TEST_H_

#include <string>

#include <gtest/gtest.h>

#include "permission_broker/udev_scopers.h"

namespace permission_broker {

class RuleTest : public testing::Test {
 public:
  RuleTest();
  ~RuleTest() override;

 protected:
  // Find the udev_device matching |path|. FAILs the test if the device is not
  // found.
  ScopedUdevDevicePtr FindDevice(const std::string& path);

 private:
  ScopedUdevPtr udev_;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_RULE_TEST_H_
