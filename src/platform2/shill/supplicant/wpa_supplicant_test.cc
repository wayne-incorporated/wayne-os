// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/supplicant/wpa_supplicant.h"

#include <string>

#include <gtest/gtest.h>

#include "shill/mock_log.h"

using testing::_;
using testing::EndsWith;

namespace shill {

class WPASupplicantTest : public testing::Test {
 public:
  WPASupplicantTest() = default;
  ~WPASupplicantTest() override = default;

 protected:
  KeyValueStore property_map_;
};

TEST_F(WPASupplicantTest, ExtractRemoteCertificationEmpty) {
  std::string subject;
  uint32_t depth = 0;
  ScopedMockLog log;
  EXPECT_CALL(log,
              Log(logging::LOGGING_ERROR, _, EndsWith("no depth parameter.")));
  EXPECT_FALSE(WPASupplicant::ExtractRemoteCertification(property_map_,
                                                         &subject, &depth));
  EXPECT_EQ("", subject);
  EXPECT_EQ(0, depth);
}

TEST_F(WPASupplicantTest, ExtractRemoteCertificationDepthOnly) {
  std::string subject;
  const uint32_t kDepthValue = 100;
  uint32_t depth = kDepthValue - 1;
  property_map_.Set<uint32_t>(WPASupplicant::kInterfacePropertyDepth,
                              kDepthValue);
  ScopedMockLog log;
  EXPECT_CALL(
      log, Log(logging::LOGGING_ERROR, _, EndsWith("no subject parameter.")));
  EXPECT_FALSE(WPASupplicant::ExtractRemoteCertification(property_map_,
                                                         &subject, &depth));
  EXPECT_EQ("", subject);
  EXPECT_NE(kDepthValue, depth);
}

TEST_F(WPASupplicantTest, ExtractRemoteCertificationSubjectOnly) {
  const char kSubjectName[] = "subject-name";
  std::string subject;
  uint32_t depth = 0;
  property_map_.Set<std::string>(WPASupplicant::kInterfacePropertySubject,
                                 kSubjectName);
  ScopedMockLog log;
  EXPECT_CALL(log,
              Log(logging::LOGGING_ERROR, _, EndsWith("no depth parameter.")));
  EXPECT_FALSE(WPASupplicant::ExtractRemoteCertification(property_map_,
                                                         &subject, &depth));
  EXPECT_EQ("", subject);
  EXPECT_EQ(0, depth);
}

TEST_F(WPASupplicantTest, ExtractRemoteCertificationSubjectAndDepth) {
  const char kSubjectName[] = "subject-name";
  std::string subject;
  const uint32_t kDepthValue = 100;
  uint32_t depth = 0;
  property_map_.Set<std::string>(WPASupplicant::kInterfacePropertySubject,
                                 kSubjectName);
  property_map_.Set<uint32_t>(WPASupplicant::kInterfacePropertyDepth,
                              kDepthValue);
  EXPECT_TRUE(WPASupplicant::ExtractRemoteCertification(property_map_, &subject,
                                                        &depth));
  EXPECT_EQ(kSubjectName, subject);
  EXPECT_EQ(kDepthValue, depth);
}

}  // namespace shill
