// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/cros_config_utils_impl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace rmad {

// cros_config root path.
constexpr char kCrosRootPath[] = "/";
constexpr char kCrosModelNameKey[] = "name";

constexpr char kModelName[] = "TestModelName";
constexpr char kModelNameUnused[] = "TestModelNameUnused";

// cros_config identity path.
constexpr char kCrosIdentityPath[] = "/identity";
constexpr char kCrosIdentityPathKey[] = "identity";
constexpr char kCrosIdentitySkuKey[] = "sku-id";
constexpr char kCrosIdentityCustomLabelTagKey[] = "custom-label-tag";

constexpr uint64_t kSkuId = 1234567890;
constexpr uint64_t kSkuIdUnused = 1111111110;
constexpr uint64_t kSkuIdOther1 = 1111111111;
constexpr uint64_t kSkuIdOther2 = 1111111112;

constexpr char kCustomLabelTagEmpty[] = "";
constexpr char kCustomLabelTag[] = "TestCustomLabelTag";
constexpr char kCustomLabelTagUnused[] = "TestCustomLabelTagUnused";
constexpr char kCustomLabelTagOther[] = "TestCustomLabelTagOther";

// cros_config rmad path.
constexpr char kCrosRmadPath[] = "/rmad";
constexpr char kCrosRmadEnabledKey[] = "enabled";
constexpr char kCrosRmadHasCbiKey[] = "has-cbi";

constexpr char kTrueStr[] = "true";

// cros_config rmad/ssfc path.
constexpr char kCrosRmadSsfcPath[] = "/rmad/ssfc";
constexpr char kCrosRmadSsfcMaskKey[] = "mask";
constexpr char kCrosRmadSsfcComponentTypeConfigsPath[] =
    "/rmad/ssfc/component-type-configs";
constexpr char kCrosRmadSsfcComponentTypeKey[] = "component-type";
constexpr char kCrosRmadSsfcDefaultValueKey[] = "default-value";
constexpr char kCrosRmadSsfcProbeableComponentsRelPath[] =
    "probeable-components";
constexpr char kCrosRmadSsfcIdentifierKey[] = "identifier";
constexpr char kCrosRmadSsfcValueKey[] = "value";

constexpr char kUndefinedComponentType[] = "undefined_component_type";
constexpr uint32_t kSsfcMask = 0x8;
constexpr char kSsfcComponentType[] = "TestComponentType";
constexpr uint32_t kSsfcDefaultValue = 0x4;
constexpr char kSsfcIdentifier1[] = "TestComponent_1";
constexpr uint32_t kSsfcValue1 = 0x1;
constexpr char kSsfcIdentifier2[] = "TestComponent_2";
constexpr uint32_t kSsfcValue2 = 0x2;

// The first option of the WL list is always an empty string.
const std::vector<std::string> kTargetCustomLabelTagList = {
    kCustomLabelTag, kCustomLabelTagOther};
const std::vector<uint64_t> kTargetSkuIdList = {kSkuIdOther1, kSkuIdOther2,
                                                kSkuId};

class CrosConfigUtilsImplTest : public testing::Test {
 public:
  CrosConfigUtilsImplTest() {}

  base::FilePath CreateCrosConfigFs(
      const std::vector<std::string>& model_names,
      const std::vector<uint64_t>& sku_ids,
      const std::vector<std::string>& custom_label_tags) {
    EXPECT_EQ(model_names.size(), sku_ids.size());
    EXPECT_EQ(model_names.size(), custom_label_tags.size());

    base::FilePath root_path = temp_dir_.GetPath();

    for (size_t i = 0; i < model_names.size(); ++i) {
      base::FilePath config_path =
          root_path.AppendASCII(base::NumberToString(i));
      EXPECT_TRUE(base::CreateDirectory(config_path));

      base::FilePath model_path = config_path.AppendASCII(kCrosModelNameKey);
      EXPECT_TRUE(base::WriteFile(model_path, model_names[i]));

      base::FilePath identity_path =
          config_path.AppendASCII(kCrosIdentityPathKey);
      EXPECT_TRUE(base::CreateDirectory(identity_path));

      base::FilePath sku_path = identity_path.AppendASCII(kCrosIdentitySkuKey);
      EXPECT_TRUE(base::WriteFile(sku_path, base::NumberToString(sku_ids[i])));

      if (!custom_label_tags[i].empty()) {
        base::FilePath custom_label_tag_path =
            identity_path.AppendASCII(kCrosIdentityCustomLabelTagKey);
        EXPECT_TRUE(
            base::WriteFile(custom_label_tag_path, custom_label_tags[i]));
      }
    }

    return root_path;
  }

  std::unique_ptr<CrosConfigUtils> CreateCrosConfigUtils(
      bool custom_label = true,
      bool enable_rmad = true,
      bool set_optional = true) {
    auto fake_cros_config = std::make_unique<brillo::FakeCrosConfig>();
    fake_cros_config->SetString(kCrosRootPath, kCrosModelNameKey, kModelName);
    fake_cros_config->SetString(std::string(kCrosIdentityPath),
                                kCrosIdentitySkuKey,
                                base::NumberToString(kSkuId));

    base::FilePath cros_config_root_path;
    if (custom_label) {
      cros_config_root_path = CreateCrosConfigFs(
          {kModelName, kModelName, kModelName, kModelNameUnused},
          {kSkuId, kSkuIdOther1, kSkuIdOther2, kSkuIdUnused},
          {kCustomLabelTagEmpty, kCustomLabelTag, kCustomLabelTagOther,
           kCustomLabelTagUnused});
      fake_cros_config->SetString(std::string(kCrosIdentityPath),
                                  kCrosIdentityCustomLabelTagKey,
                                  kCustomLabelTag);
    } else {
      cros_config_root_path = CreateCrosConfigFs(
          {kModelName, kModelNameUnused, kModelNameUnused, kModelNameUnused},
          {kSkuId, kSkuIdOther1, kSkuIdOther2, kSkuIdUnused},
          {kCustomLabelTagEmpty, kCustomLabelTag, kCustomLabelTagOther,
           kCustomLabelTagUnused});
    }

    if (enable_rmad) {
      fake_cros_config->SetString(std::string(kCrosRmadPath),
                                  kCrosRmadEnabledKey, kTrueStr);
      fake_cros_config->SetString(std::string(kCrosRmadPath),
                                  kCrosRmadHasCbiKey, kTrueStr);
      if (set_optional) {
        fake_cros_config->SetString(std::string(kCrosRmadSsfcPath),
                                    kCrosRmadSsfcMaskKey,
                                    base::NumberToString(kSsfcMask));
        fake_cros_config->SetString(
            base::StringPrintf("%s/0", kCrosRmadSsfcComponentTypeConfigsPath),
            kCrosRmadSsfcComponentTypeKey, kSsfcComponentType);
        fake_cros_config->SetString(
            base::StringPrintf("%s/0", kCrosRmadSsfcComponentTypeConfigsPath),
            kCrosRmadSsfcDefaultValueKey,
            base::NumberToString(kSsfcDefaultValue));
      }

      fake_cros_config->SetString(
          base::StringPrintf("%s/0/%s/%d",
                             kCrosRmadSsfcComponentTypeConfigsPath,
                             kCrosRmadSsfcProbeableComponentsRelPath, 0),
          kCrosRmadSsfcIdentifierKey, kSsfcIdentifier1);
      fake_cros_config->SetString(
          base::StringPrintf("%s/0/%s/%d",
                             kCrosRmadSsfcComponentTypeConfigsPath,
                             kCrosRmadSsfcProbeableComponentsRelPath, 0),
          kCrosRmadSsfcValueKey, base::NumberToString(kSsfcValue1));
      fake_cros_config->SetString(
          base::StringPrintf("%s/0/%s/%d",
                             kCrosRmadSsfcComponentTypeConfigsPath,
                             kCrosRmadSsfcProbeableComponentsRelPath, 1),
          kCrosRmadSsfcIdentifierKey, kSsfcIdentifier2);
      fake_cros_config->SetString(
          base::StringPrintf("%s/0/%s/%d",
                             kCrosRmadSsfcComponentTypeConfigsPath,
                             kCrosRmadSsfcProbeableComponentsRelPath, 1),
          kCrosRmadSsfcValueKey, base::NumberToString(kSsfcValue2));
    }

    return std::make_unique<CrosConfigUtilsImpl>(
        cros_config_root_path.MaybeAsASCII(), std::move(fake_cros_config));
  }

 protected:
  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  base::ScopedTempDir temp_dir_;
};

TEST_F(CrosConfigUtilsImplTest, GetRmadConfig_Enabled) {
  auto cros_config_utils = CreateCrosConfigUtils(true, true);

  RmadConfig config;
  EXPECT_TRUE(cros_config_utils->GetRmadConfig(&config));
  EXPECT_TRUE(config.enabled);
  EXPECT_TRUE(config.has_cbi);
  EXPECT_EQ(config.ssfc.mask, kSsfcMask);

  const auto& component_type_configs = config.ssfc.component_type_configs;
  EXPECT_EQ(component_type_configs.size(), 1);
  EXPECT_EQ(component_type_configs[0].component_type, kSsfcComponentType);
  EXPECT_EQ(component_type_configs[0].default_value, kSsfcDefaultValue);

  const auto& probeable_components =
      component_type_configs[0].probeable_components;
  EXPECT_EQ(probeable_components.size(), 2);
  EXPECT_EQ(probeable_components.at(kSsfcIdentifier1), kSsfcValue1);
  EXPECT_EQ(probeable_components.at(kSsfcIdentifier2), kSsfcValue2);
}

TEST_F(CrosConfigUtilsImplTest, GetRmadConfig_Enabled_NoOptionalValues) {
  auto cros_config_utils = CreateCrosConfigUtils(true, true, false);

  RmadConfig config;
  EXPECT_TRUE(cros_config_utils->GetRmadConfig(&config));
  EXPECT_TRUE(config.enabled);
  EXPECT_TRUE(config.has_cbi);
  EXPECT_EQ(config.ssfc.mask, 0);

  const auto& component_type_configs = config.ssfc.component_type_configs;
  EXPECT_EQ(component_type_configs.size(), 1);
  EXPECT_EQ(component_type_configs[0].component_type, kUndefinedComponentType);
  EXPECT_EQ(component_type_configs[0].default_value, 0);

  const auto& probeable_components =
      component_type_configs[0].probeable_components;
  EXPECT_EQ(probeable_components.size(), 2);
  EXPECT_EQ(probeable_components.at(kSsfcIdentifier1), kSsfcValue1);
  EXPECT_EQ(probeable_components.at(kSsfcIdentifier2), kSsfcValue2);
}

TEST_F(CrosConfigUtilsImplTest, GetRmadConfig_Disabled) {
  auto cros_config_utils = CreateCrosConfigUtils(true, false);

  RmadConfig config;
  EXPECT_TRUE(cros_config_utils->GetRmadConfig(&config));
  EXPECT_FALSE(config.enabled);
  EXPECT_FALSE(config.has_cbi);
  EXPECT_EQ(config.ssfc.mask, 0);
  EXPECT_EQ(config.ssfc.component_type_configs.size(), 0);
}

TEST_F(CrosConfigUtilsImplTest, GetModelName_Success) {
  auto cros_config_utils = CreateCrosConfigUtils();

  std::string model_name;
  EXPECT_TRUE(cros_config_utils->GetModelName(&model_name));
  EXPECT_EQ(model_name, kModelName);
}

TEST_F(CrosConfigUtilsImplTest, GetCustomLabelTag_Success) {
  auto cros_config_utils = CreateCrosConfigUtils();

  std::string custom_label_tag;
  EXPECT_TRUE(cros_config_utils->GetCustomLabelTag(&custom_label_tag));
  EXPECT_EQ(custom_label_tag, kCustomLabelTag);
}

TEST_F(CrosConfigUtilsImplTest, GetSkuId_Success) {
  auto cros_config_utils = CreateCrosConfigUtils();

  uint64_t sku_id;
  EXPECT_TRUE(cros_config_utils->GetSkuId(&sku_id));
  EXPECT_EQ(sku_id, kSkuId);
}

TEST_F(CrosConfigUtilsImplTest, GetSkuIdList_Success) {
  auto cros_config_utils = CreateCrosConfigUtils();

  std::vector<uint64_t> sku_id_list;
  EXPECT_TRUE(cros_config_utils->GetSkuIdList(&sku_id_list));
  EXPECT_EQ(sku_id_list, kTargetSkuIdList);
}

TEST_F(CrosConfigUtilsImplTest, GetCustomLabelTagList_Success) {
  auto cros_config_utils = CreateCrosConfigUtils();

  std::vector<std::string> custom_label_tag_list;
  EXPECT_TRUE(cros_config_utils->GetCustomLabelTagList(&custom_label_tag_list));
  EXPECT_EQ(custom_label_tag_list, kTargetCustomLabelTagList);
}

TEST_F(CrosConfigUtilsImplTest, GetEmptyCustomLabelTagList_Success) {
  auto cros_config_utils = CreateCrosConfigUtils(false);

  std::vector<std::string> custom_label_tag_list;
  EXPECT_TRUE(cros_config_utils->GetCustomLabelTagList(&custom_label_tag_list));
  EXPECT_TRUE(custom_label_tag_list.empty());
}

TEST_F(CrosConfigUtilsImplTest, IsCustomLabel_True) {
  auto cros_config_utils = CreateCrosConfigUtils();

  EXPECT_TRUE(cros_config_utils->IsCustomLabel());
}

TEST_F(CrosConfigUtilsImplTest, IsCustomLabel_False) {
  auto cros_config_utils = CreateCrosConfigUtils(false);

  EXPECT_FALSE(cros_config_utils->IsCustomLabel());
}

}  // namespace rmad
