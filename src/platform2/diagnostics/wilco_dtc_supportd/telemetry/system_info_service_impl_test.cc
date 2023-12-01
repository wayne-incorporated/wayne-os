// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/system_info_service_impl.h"

#include <string>

#include <base/strings/stringprintf.h>
#include <base/test/scoped_chromeos_version_info.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/wilco_dtc_supportd/telemetry/system_info_service.h"

namespace diagnostics {
namespace wilco {
namespace {

class SystemInfoServiceImplTest : public testing::Test {
 public:
  SystemInfoServiceImplTest() = default;
  ~SystemInfoServiceImplTest() override = default;

  SystemInfoServiceImplTest(const SystemInfoServiceImplTest&) = delete;
  SystemInfoServiceImplTest& operator=(const SystemInfoServiceImplTest&) =
      delete;

  SystemInfoService* service() { return &service_; }

 private:
  SystemInfoServiceImpl service_;
};

TEST_F(SystemInfoServiceImplTest, GetOsVersion) {
  constexpr char kOsVersion[] = "11932.0.2019_03_20_1100";

  base::test::ScopedChromeOSVersionInfo version_info(
      base::StringPrintf("CHROMEOS_RELEASE_VERSION=%s", kOsVersion),
      base::Time());

  std::string version;
  EXPECT_TRUE(service()->GetOsVersion(&version));
  EXPECT_EQ(version, kOsVersion);
}

TEST_F(SystemInfoServiceImplTest, GetOsVersionNoLsbRelease) {
  base::test::ScopedChromeOSVersionInfo version_info("", base::Time());

  std::string version;
  EXPECT_FALSE(service()->GetOsVersion(&version));
}

TEST_F(SystemInfoServiceImplTest, GetOsMilestone) {
  constexpr int kMilestone = 75;

  base::test::ScopedChromeOSVersionInfo version(
      base::StringPrintf("CHROMEOS_RELEASE_CHROME_MILESTONE=%d", kMilestone),
      base::Time());

  int milestone = 0;
  EXPECT_TRUE(service()->GetOsMilestone(&milestone));
  EXPECT_EQ(milestone, kMilestone);
}

TEST_F(SystemInfoServiceImplTest, GetOsMilestoneNoLsbRelease) {
  base::test::ScopedChromeOSVersionInfo version("", base::Time());

  int milestone = 0;
  EXPECT_FALSE(service()->GetOsMilestone(&milestone));
}

TEST_F(SystemInfoServiceImplTest, GetOsMilestoneNotInteger) {
  base::test::ScopedChromeOSVersionInfo version(
      "CHROMEOS_RELEASE_CHROME_MILESTONE=abcdef", base::Time());

  int milestone = 0;
  EXPECT_FALSE(service()->GetOsMilestone(&milestone));
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
