// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/chromeos_postinst.cc"

#include <memory>

#include <gtest/gtest.h>

#include "installer/chromeos_install_config.h"
#include "installer/metrics.h"
#include "installer/mock_metrics.h"

using ::testing::Expectation;

TEST(PostinstSuccessUMATest, Unknown) {
  MockMetrics metrics;

  EXPECT_CALL(
      metrics,
      SendBooleanMetric(
          "Installer.Postinstall.NonChromebookBiosSuccess.Unknown", true));
  SendNonChromebookBiosSuccess(metrics, BiosType::kUnknown, true);
}

TEST(PostinstSuccessUMATest, Secure) {
  MockMetrics metrics;

  EXPECT_CALL(
      metrics,
      SendBooleanMetric("Installer.Postinstall.NonChromebookBiosSuccess.Secure",
                        true));
  SendNonChromebookBiosSuccess(metrics, BiosType::kSecure, true);
}

TEST(PostinstSuccessUMATest, UBoot) {
  MockMetrics metrics;

  EXPECT_CALL(
      metrics,
      SendBooleanMetric("Installer.Postinstall.NonChromebookBiosSuccess.UBoot",
                        true));
  SendNonChromebookBiosSuccess(metrics, BiosType::kUBoot, true);
}

TEST(PostinstSuccessUMATest, Legacy) {
  MockMetrics metrics;

  EXPECT_CALL(
      metrics,
      SendBooleanMetric("Installer.Postinstall.NonChromebookBiosSuccess.Legacy",
                        true));
  SendNonChromebookBiosSuccess(metrics, BiosType::kLegacy, true);
}

TEST(PostinstSuccessUMATest, EFI) {
  MockMetrics metrics;

  EXPECT_CALL(metrics,
              SendBooleanMetric(
                  "Installer.Postinstall.NonChromebookBiosSuccess.EFI", true));
  SendNonChromebookBiosSuccess(metrics, BiosType::kEFI, true);
}
