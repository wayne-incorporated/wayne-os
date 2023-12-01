// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/ssfc/ssfc_prober.h"

#include <memory>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/system/mock_runtime_probe_client.h"
#include "rmad/utils/mock_cbi_utils.h"
#include "rmad/utils/mock_cros_config_utils.h"

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace {

constexpr uint32_t kOriginalSsfcValue = 0x11;
constexpr uint32_t kSsfcMask = 0x10;

constexpr rmad::RmadComponent kComponentApI2c = rmad::RMAD_COMPONENT_AP_I2C;
constexpr uint32_t kApI2cDefaultValue = 0;
constexpr char kApI2cName1[] = "ap_i2c_1";
constexpr uint32_t kApI2cValue1 = 0x1;
constexpr char kApI2cName2[] = "ap_i2c_2";
constexpr uint32_t kApI2cValue2 = 0x2;

constexpr rmad::RmadComponent kComponentEcI2c = rmad::RMAD_COMPONENT_EC_I2C;
constexpr uint32_t kEcI2cDefaultValue = 0x4;
constexpr char kEcI2cName1[] = "ec_i2c_1";
constexpr uint32_t kEcI2cValue1 = 0x8;
constexpr char kEcI2cName2[] = "ec_i2c_2";
constexpr uint32_t kEcI2cValue2 = 0xc;

}  // namespace

namespace rmad {

class SsfcProberImplTest : public testing::Test {
 public:
  SsfcProberImplTest() = default;

  std::unique_ptr<SsfcProberImpl> CreateSsfcProber(
      const RmadConfig& rmad_config = {},
      bool probe_success = true,
      const std::vector<std::pair<RmadComponent, std::string>>&
          probed_components = {{kComponentApI2c, kApI2cName1},
                               {kComponentEcI2c, kEcI2cName1}}) {
    // Mock |RuntimeProbeClient|.
    auto mock_runtime_probe_client =
        std::make_unique<NiceMock<MockRuntimeProbeClient>>();
    if (probe_success) {
      ON_CALL(*mock_runtime_probe_client, ProbeSsfcComponents(_, _))
          .WillByDefault(
              DoAll(SetArgPointee<1>(probed_components), Return(true)));
    } else {
      ON_CALL(*mock_runtime_probe_client, ProbeSsfcComponents(_, _))
          .WillByDefault(Return(false));
    }

    // Mock |CbiUtils|.
    auto mock_cbi_utils = std::make_unique<NiceMock<MockCbiUtils>>();
    ON_CALL(*mock_cbi_utils, GetSsfc(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(kOriginalSsfcValue), Return(true)));

    // Mock |CrosConfigUtils|.
    auto mock_cros_config_utils =
        std::make_unique<NiceMock<MockCrosConfigUtils>>();
    ON_CALL(*mock_cros_config_utils, GetRmadConfig(_))
        .WillByDefault(DoAll(SetArgPointee<0>(rmad_config), Return(true)));

    return std::make_unique<SsfcProberImpl>(
        std::move(mock_runtime_probe_client), std::move(mock_cbi_utils),
        std::move(mock_cros_config_utils));
  }
};

TEST_F(SsfcProberImplTest, IsSsfcRequired_True) {
  RmadConfig rmad_config = {.ssfc = {.component_type_configs = {{}}}};
  auto ssfc_prober = CreateSsfcProber(rmad_config);

  EXPECT_TRUE(ssfc_prober->IsSsfcRequired());
}

TEST_F(SsfcProberImplTest, IsSsfcRequired_False) {
  auto ssfc_prober = CreateSsfcProber();

  EXPECT_FALSE(ssfc_prober->IsSsfcRequired());
}

TEST_F(SsfcProberImplTest, ProbeSsfc_NotRequired) {
  auto ssfc_prober = CreateSsfcProber();

  uint32_t ssfc;
  EXPECT_FALSE(ssfc_prober->ProbeSsfc(&ssfc));
}

TEST_F(SsfcProberImplTest, ProbeSsfc_ProbeFailed) {
  RmadConfig rmad_config = {
      .ssfc = {.mask = kSsfcMask,
               .component_type_configs = {
                   {
                       .default_value = kApI2cDefaultValue,
                       .probeable_components = {{kApI2cName1, kApI2cValue1},
                                                {kApI2cName2, kApI2cValue2}},
                   },
                   {
                       .default_value = kEcI2cDefaultValue,
                       .probeable_components = {{kEcI2cName1, kEcI2cValue1},
                                                {kEcI2cName2, kEcI2cValue2}},
                   },
               }}};
  auto ssfc_prober = CreateSsfcProber(rmad_config, false);

  uint32_t ssfc;
  EXPECT_FALSE(ssfc_prober->ProbeSsfc(&ssfc));
}

TEST_F(SsfcProberImplTest, ProbeSsfc_Success_NoMask) {
  RmadConfig rmad_config = {
      .ssfc = {.component_type_configs = {
                   {
                       .default_value = kApI2cDefaultValue,
                       .probeable_components = {{kApI2cName1, kApI2cValue1},
                                                {kApI2cName2, kApI2cValue2}},
                   },
                   {
                       .default_value = kEcI2cDefaultValue,
                       .probeable_components = {{kEcI2cName1, kEcI2cValue1},
                                                {kEcI2cName2, kEcI2cValue2}},
                   },
               }}};
  auto ssfc_prober = CreateSsfcProber(rmad_config);

  uint32_t ssfc;
  EXPECT_TRUE(ssfc_prober->ProbeSsfc(&ssfc));
  EXPECT_EQ(kApI2cValue1 | kEcI2cValue1, ssfc);
}

TEST_F(SsfcProberImplTest, ProbeSsfc_Success_Mask) {
  RmadConfig rmad_config = {
      .ssfc = {.mask = kSsfcMask,
               .component_type_configs = {
                   {
                       .default_value = kApI2cDefaultValue,
                       .probeable_components = {{kApI2cName1, kApI2cValue1},
                                                {kApI2cName2, kApI2cValue2}},
                   },
                   {
                       .default_value = kEcI2cDefaultValue,
                       .probeable_components = {{kEcI2cName1, kEcI2cValue1},
                                                {kEcI2cName2, kEcI2cValue2}},
                   },
               }}};
  auto ssfc_prober = CreateSsfcProber(rmad_config);

  uint32_t ssfc;
  EXPECT_TRUE(ssfc_prober->ProbeSsfc(&ssfc));
  EXPECT_EQ((kOriginalSsfcValue & kSsfcMask) | kApI2cValue1 | kEcI2cValue1,
            ssfc);
}

TEST_F(SsfcProberImplTest, ProbeSsfc_Success_ComponentNotInConfig) {
  RmadConfig rmad_config = {
      .ssfc = {.component_type_configs = {{
                   .default_value = kApI2cDefaultValue,
                   .probeable_components = {{kApI2cName1, kApI2cValue1}},
               }}}};
  std::vector<std::pair<RmadComponent, std::string>> probed_components = {
      {kComponentApI2c, kApI2cName1}, {kComponentApI2c, kApI2cName2}};
  auto ssfc_prober = CreateSsfcProber(rmad_config, true, probed_components);

  uint32_t ssfc;
  EXPECT_TRUE(ssfc_prober->ProbeSsfc(&ssfc));
  EXPECT_EQ(kApI2cValue1, ssfc);
}

TEST_F(SsfcProberImplTest, ProbeSsfc_Success_DuplicateComponents) {
  RmadConfig rmad_config = {
      .ssfc = {.component_type_configs = {{
                   .default_value = kApI2cDefaultValue,
                   .probeable_components = {{kApI2cName1, kApI2cValue1}},
               }}}};
  std::vector<std::pair<RmadComponent, std::string>> probed_components = {
      {kComponentApI2c, kApI2cName1}, {kComponentApI2c, kApI2cName1}};
  auto ssfc_prober = CreateSsfcProber(rmad_config, true, probed_components);

  uint32_t ssfc;
  EXPECT_TRUE(ssfc_prober->ProbeSsfc(&ssfc));
  EXPECT_EQ(kApI2cValue1, ssfc);
}

TEST_F(SsfcProberImplTest, ProbeSsfc_Fail_MultipleComponents) {
  RmadConfig rmad_config = {
      .ssfc = {.component_type_configs = {{
                   .default_value = kApI2cDefaultValue,
                   .probeable_components = {{kApI2cName1, kApI2cValue1},
                                            {kApI2cName2, kApI2cValue2}},
               }}}};
  std::vector<std::pair<RmadComponent, std::string>> probed_components = {
      {kComponentApI2c, kApI2cName1}, {kComponentApI2c, kApI2cName2}};
  auto ssfc_prober = CreateSsfcProber(rmad_config, true, probed_components);

  uint32_t ssfc;
  EXPECT_FALSE(ssfc_prober->ProbeSsfc(&ssfc));
}

}  // namespace rmad
