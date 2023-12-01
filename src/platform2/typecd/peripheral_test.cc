// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/peripheral.h"

#include <string>

#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "typecd/test_constants.h"
#include "typecd/test_utils.h"

namespace typecd {

class PeripheralTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    temp_dir_ = scoped_temp_dir_.GetPath();
  }

 public:
  base::FilePath temp_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

TEST_F(PeripheralTest, CheckPDRevision) {
  // Set up fake sysfs paths.
  auto path = temp_dir_.Append(std::string("port0-fake_periheral"));
  ASSERT_TRUE(base::CreateDirectory(path));
  Peripheral p(path);
  EXPECT_EQ(p.GetPDRevision(), PDRevision::kNone);

  // Gibberish PD revision values should be rejected.
  auto pd_rev = base::StringPrintf("a.f");
  ASSERT_TRUE(base::WriteFile(path.Append("usb_power_delivery_revision"),
                              pd_rev.c_str(), pd_rev.length()));
  p.UpdatePDRevision();
  EXPECT_EQ(p.GetPDRevision(), PDRevision::kNone);

  pd_rev = base::StringPrintf("!*(&#@$>SC(&(*)(#@>C>");
  ASSERT_TRUE(base::WriteFile(path.Append("usb_power_delivery_revision"),
                              pd_rev.c_str(), pd_rev.length()));
  p.UpdatePDRevision();
  EXPECT_EQ(p.GetPDRevision(), PDRevision::kNone);

  // Legitimate PD revision values should be parsed correctly.
  pd_rev = base::StringPrintf("3.0");
  ASSERT_TRUE(base::WriteFile(path.Append("usb_power_delivery_revision"),
                              pd_rev.c_str(), pd_rev.length()));
  p.UpdatePDRevision();
  EXPECT_EQ(p.GetPDRevision(), PDRevision::k30);
}

}  // namespace typecd
