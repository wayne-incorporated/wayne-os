// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/arc_property_util.h"

#include <memory>
#include <tuple>
#include <utility>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <brillo/files/file_util.h>
#include <cdm_oemcrypto/proto_bindings/client_information.pb.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <testing/gtest/include/gtest/gtest.h>

using ::testing::_;
using ::testing::ByMove;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::StartsWith;

namespace arc {
namespace {

constexpr char kCrosConfigPropertiesPath[] = "/arc/build-properties";

class ArcPropertyUtilTest : public testing::Test {
 public:
  ArcPropertyUtilTest() = default;
  ~ArcPropertyUtilTest() override = default;
  ArcPropertyUtilTest(const ArcPropertyUtilTest&) = delete;
  ArcPropertyUtilTest& operator=(const ArcPropertyUtilTest&) = delete;

  void SetUp() override {
    ASSERT_TRUE(dir_.CreateUniqueTempDir());
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::MockBus(options);
    cdm_factory_daemon_object_proxy_ = new dbus::MockObjectProxy(
        bus_.get(), cdm_oemcrypto::kCdmFactoryDaemonServiceName,
        dbus::ObjectPath(cdm_oemcrypto::kCdmFactoryDaemonServicePath));
  }

 protected:
  const base::FilePath& GetTempDir() const { return dir_.GetPath(); }

  brillo::FakeCrosConfig* config() { return &config_; }

  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> cdm_factory_daemon_object_proxy_;

 private:
  brillo::FakeCrosConfig config_;
  base::ScopedTempDir dir_;
};

TEST_F(ArcPropertyUtilTest, TestPropertyExpansions) {
  config()->SetString("/arc/build-properties", "brand", "alphabet");

  std::string expanded;
  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.a=line1\nro.b={brand}\nro.c=line3\nro.d={brand} {brand}", config(),
      /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.a=line1\nro.b=alphabet\nro.c=line3\nro.d=alphabet alphabet\n",
            expanded);
}

TEST_F(ArcPropertyUtilTest, TestPropertyExpansionsUnmatchedBrace) {
  config()->SetString("/arc/build-properties", "brand", "alphabet");

  std::string expanded;
  EXPECT_FALSE(ExpandPropertyContentsForTesting(
      "ro.a=line{1\nro.b=line}2\nro.c=line3", config(), /*debuggable=*/false,
      &expanded));
}

TEST_F(ArcPropertyUtilTest, TestPropertyExpansionsRecursive) {
  config()->SetString("/arc/build-properties", "brand", "alphabet");
  config()->SetString("/arc/build-properties", "model", "{brand} soup");

  std::string expanded;
  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.a={model}", config(), /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.a=alphabet soup\n", expanded);
}

TEST_F(ArcPropertyUtilTest, TestPropertyExpansionsMissingProperty) {
  config()->SetString("/arc/build-properties", "model", "{brand} soup");

  std::string expanded;

  EXPECT_FALSE(ExpandPropertyContentsForTesting(
      "ro.a={missing-property}", config(), /*debuggable=*/false, &expanded));
  EXPECT_FALSE(ExpandPropertyContentsForTesting(
      "ro.a={model}", config(), /*debuggable=*/false, &expanded));
}

// Verify that ro.product.board gets copied to ro.oem.key1 as well.
TEST_F(ArcPropertyUtilTest, TestPropertyExpansionBoard) {
  config()->SetString("/arc/build-properties", "board", "testboard");

  std::string expanded;
  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.product.board={board}", config(), /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.product.board=testboard\nro.oem.key1=testboard\n", expanded);
}

TEST_F(ArcPropertyUtilTest, TestPropertyExpansionDebuggable) {
  std::string expanded;
  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.debuggable=0", config(), /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.debuggable=0\n", expanded);

  EXPECT_TRUE(ExpandPropertyContentsForTesting(
      "ro.debuggable=1", config(), /*debuggable=*/false, &expanded));
  EXPECT_EQ("ro.debuggable=0\n", expanded);

  EXPECT_TRUE(ExpandPropertyContentsForTesting("ro.debuggable=0", config(),
                                               /*debuggable*/ true, &expanded));
  EXPECT_EQ("ro.debuggable=1\n", expanded);

  EXPECT_TRUE(ExpandPropertyContentsForTesting("ro.debuggable=1", config(),
                                               /*debuggable*/ true, &expanded));
  EXPECT_EQ("ro.debuggable=1\n", expanded);
}

// Non-ro property should do simple truncation.
TEST_F(ArcPropertyUtilTest, TestNonRoPropertyTruncation) {
  std::string truncated;
  EXPECT_TRUE(TruncateAndroidPropertyForTesting(
      "property.name="
      "012345678901234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901",
      &truncated));
  EXPECT_EQ(
      "property.name=0123456789012345678901234567890123456789"
      "012345678901234567890123456789012345678901234567890",
      truncated);
}

// ro property should not do any truncation.
TEST_F(ArcPropertyUtilTest, TestRoPropertyTruncation) {
  std::string truncated;
  EXPECT_TRUE(TruncateAndroidPropertyForTesting(
      "ro.property.name="
      "012345678901234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901",
      &truncated));
  EXPECT_EQ(
      "ro.property.name="
      "012345678901234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901",
      truncated);
}

// Tests that ExpandPropertyFile works as intended when no property expantion
// is needed.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_NoExpansion) {
  constexpr const char kValidProp[] = "ro.foo=bar\nro.baz=boo";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));

  const base::FilePath dest = GetTempDir().Append("new.prop");
  EXPECT_TRUE(ExpandPropertyFileForTesting(path, dest, config()));
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest, &content));
  EXPECT_EQ(std::string(kValidProp) + "\n", content);
}

// Tests that ExpandPropertyFile works as intended when property expantion
// is needed.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_Expansion) {
  config()->SetString(kCrosConfigPropertiesPath, "k1", "v1");
  config()->SetString(kCrosConfigPropertiesPath, "k2", "v2");

  constexpr const char kValidProp[] = "ro.foo={k1}\nro.baz={k2}";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));

  const base::FilePath dest = GetTempDir().Append("new.prop");
  EXPECT_TRUE(ExpandPropertyFileForTesting(path, dest, config()));
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest, &content));
  EXPECT_EQ("ro.foo=v1\nro.baz=v2\n", content);
}

// Tests that ExpandPropertyFile works as intended when nested property
// expantion is needed.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_NestedExpansion) {
  config()->SetString(kCrosConfigPropertiesPath, "k1", "{k2}");
  config()->SetString(kCrosConfigPropertiesPath, "k2", "v2");

  constexpr const char kValidProp[] = "ro.foo={k1}\nro.baz={k2}";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));

  const base::FilePath dest = GetTempDir().Append("new.prop");
  EXPECT_TRUE(ExpandPropertyFileForTesting(path, dest, config()));
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest, &content));
  EXPECT_EQ("ro.foo=v2\nro.baz=v2\n", content);
}

// Test that ExpandPropertyFile handles the case where a property is not found.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_CannotExpand) {
  constexpr const char kValidProp[] =
      "ro.foo={nonexistent-property}\nro.baz=boo\n";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));
  const base::FilePath dest = GetTempDir().Append("new.prop");
  EXPECT_FALSE(ExpandPropertyFileForTesting(path, dest, config()));
}

// Test that ExpandPropertyFile handles the case where the input file is not
// found.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_NoSourceFile) {
  EXPECT_FALSE(ExpandPropertyFileForTesting(base::FilePath("/nonexistent"),
                                            base::FilePath("/nonexistent2"),
                                            config()));
}

// Test that ExpandPropertyFile handles the case where the output file cannot
// be written.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFile_CannotWrite) {
  constexpr const char kValidProp[] = "ro.foo=bar\nro.baz=boo\n";
  base::FilePath path;
  ASSERT_TRUE(CreateTemporaryFileInDir(GetTempDir(), &path));
  base::WriteFile(path, kValidProp, strlen(kValidProp));
  EXPECT_FALSE(ExpandPropertyFileForTesting(
      path, base::FilePath("/nonexistent2"), config()));
}

struct TestExpander {
  const base::FilePath* source_dir{nullptr};
  const base::FilePath* dest_dir{nullptr};
  bool single_file{false};

  bool Expand() {
    return ExpandPropertyFiles(*source_dir, *dest_dir, single_file,
                               /*hw_oemcrypto_support=*/false,
                               /*include_soc_props=*/false,
                               /*debuggable=*/false, /*bus=*/nullptr);
  }
};

TEST_F(ArcPropertyUtilTest, ExpandPropertyFilesSourceAndDestNotFound) {
  EXPECT_FALSE(ExpandPropertyFiles(base::FilePath("/nonexistent1"),
                                   base::FilePath("/nonexistent2"),
                                   /*single_file=*/false,
                                   /*hw_oemcrypto_support=*/false,
                                   /*include_soc_props=*/false,
                                   /*debuggable=*/false, nullptr));
}

TEST_F(ArcPropertyUtilTest, ExpandPropertyFiles) {
  // Both source and dest exist, but the source directory is empty.
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_dir));

  TestExpander expander{&source_dir, &dest_dir};

  EXPECT_FALSE(expander.Expand());

  // Add default.prop to the source, but not build.prop.
  base::FilePath default_prop = source_dir.Append("default.prop");
  // Add a non-ro property to make sure that the property is NOT filetered out
  // when not in the "append" mode.
  constexpr const char kDefaultProp[] = "dalvik.a=b\nro.foo=bar\n";
  base::WriteFile(default_prop, kDefaultProp, strlen(kDefaultProp));
  EXPECT_FALSE(expander.Expand());

  // Add build.prop too. The call should not succeed still.
  base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "ro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));
  EXPECT_FALSE(expander.Expand());

  // Add vendor_build.prop too. Then the call should succeed.
  base::FilePath vendor_build_prop = source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "ro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));
  EXPECT_TRUE(expander.Expand());

  // Verify all dest files are there.
  EXPECT_TRUE(base::PathExists(dest_dir.Append("default.prop")));
  EXPECT_TRUE(base::PathExists(dest_dir.Append("build.prop")));
  EXPECT_TRUE(base::PathExists(dest_dir.Append("vendor_build.prop")));

  // Verify their content.
  std::string content;
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("default.prop"), &content));
  EXPECT_EQ(std::string(kDefaultProp) + "\n", content);
  EXPECT_TRUE(base::ReadFileToString(dest_dir.Append("build.prop"), &content));
  EXPECT_EQ(std::string(kBuildProp) + "\n", content);
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("vendor_build.prop"), &content));
  EXPECT_EQ(std::string(kVendorBuildProp) + "\n", content);

  // Expand it again, verify the previous result is cleared.
  EXPECT_TRUE(expander.Expand());
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("default.prop"), &content));
  EXPECT_EQ(std::string(kDefaultProp) + "\n", content);

  // If default.prop does not exist in the source path, it should still process
  // the other files, while also ensuring that default.prop is removed from the
  // destination path.
  brillo::DeleteFile(dest_dir.Append("default.prop"));

  EXPECT_TRUE(expander.Expand());

  EXPECT_TRUE(base::ReadFileToString(dest_dir.Append("build.prop"), &content));
  EXPECT_EQ(std::string(kBuildProp) + "\n", content);
  EXPECT_TRUE(
      base::ReadFileToString(dest_dir.Append("vendor_build.prop"), &content));
  EXPECT_EQ(std::string(kVendorBuildProp) + "\n", content);

  // Finally, test the case where source is valid but the dest is not.
  dest_dir = base::FilePath("/nonexistent");
  EXPECT_FALSE(expander.Expand());
}

TEST_F(ArcPropertyUtilTest,
       ExpandPropertyFiles_SingleFile_SourceAndDestNotFound) {
  EXPECT_FALSE(ExpandPropertyFiles(base::FilePath("/nonexistent1"),
                                   base::FilePath("/nonexistent2"),
                                   /*single_file=*/true,
                                   /*hw_oemcrypto_support=*/false,
                                   /*include_soc_props=*/false,
                                   /*debuggable=*/false, nullptr));
}

TEST_F(ArcPropertyUtilTest, ExpandPropertyFiles_SingleFile) {
  // Both source and dest exist, but the source directory is empty.
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_prop_file;
  ASSERT_TRUE(
      base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_prop_file));
  dest_prop_file = dest_prop_file.Append("combined.prop");
  TestExpander expander{&source_dir, &dest_prop_file};
  expander.single_file = true;
  EXPECT_FALSE(expander.Expand());

  // Add default.prop to the source, but not build.prop.
  const base::FilePath default_prop = source_dir.Append("default.prop");
  // Add a non-ro property to make sure that the property is filetered out when
  // in the "append" mode.
  constexpr const char kDefaultPropNonRo[] = "dalvik.a=b\n";
  constexpr const char kDefaultProp[] = "ro.foo=bar\n";
  base::WriteFile(default_prop,
                  base::StringPrintf("%s%s", kDefaultPropNonRo, kDefaultProp));
  EXPECT_FALSE(expander.Expand());

  // Add build.prop too. The call should not succeed still.
  const base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "ro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));
  EXPECT_FALSE(expander.Expand());

  // Add vendor_build.prop too. Then the call should succeed.
  const base::FilePath vendor_build_prop =
      source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "ro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));
  EXPECT_TRUE(expander.Expand());

  // Add other optional files too. Then the call should succeed.
  const base::FilePath system_ext_build_prop =
      source_dir.Append("system_ext_build.prop");
  constexpr const char kSystemExtBuildProp[] = "ro.c=d\n";
  base::WriteFile(system_ext_build_prop, kSystemExtBuildProp,
                  strlen(kSystemExtBuildProp));
  EXPECT_TRUE(expander.Expand());

  const base::FilePath odm_build_prop = source_dir.Append("odm_build.prop");
  constexpr const char kOdmBuildProp[] = "ro.e=f\n";
  base::WriteFile(odm_build_prop, kOdmBuildProp, strlen(kOdmBuildProp));
  EXPECT_TRUE(expander.Expand());

  const base::FilePath product_build_prop =
      source_dir.Append("product_build.prop");
  constexpr const char kProductBuildProp[] = "ro.g=h\n";
  base::WriteFile(product_build_prop, kProductBuildProp,
                  strlen(kProductBuildProp));
  EXPECT_TRUE(expander.Expand());

  // Verify only one dest file exists.
  EXPECT_FALSE(
      base::PathExists(dest_prop_file.DirName().Append("default.prop")));
  EXPECT_FALSE(base::PathExists(dest_prop_file.DirName().Append("build.prop")));
  EXPECT_FALSE(
      base::PathExists(dest_prop_file.DirName().Append("vendor_build.prop")));
  EXPECT_FALSE(base::PathExists(
      dest_prop_file.DirName().Append("system_ext_build.prop")));
  EXPECT_FALSE(
      base::PathExists(dest_prop_file.DirName().Append("odm_build.prop")));
  EXPECT_FALSE(
      base::PathExists(dest_prop_file.DirName().Append("product_build.prop")));
  EXPECT_TRUE(base::PathExists(dest_prop_file));

  // Verify the content.
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  // Don't include kDefaultPropNonRo since that one should be filtered out.
  EXPECT_EQ(base::StringPrintf("%s%s%s%s%s%s", kDefaultProp, kBuildProp,
                               kSystemExtBuildProp, kVendorBuildProp,
                               kOdmBuildProp, kProductBuildProp),
            content);

  // Expand it again, verify the previous result is cleared.
  EXPECT_TRUE(expander.Expand());
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ(base::StringPrintf("%s%s%s%s%s%s", kDefaultProp, kBuildProp,
                               kSystemExtBuildProp, kVendorBuildProp,
                               kOdmBuildProp, kProductBuildProp),
            content);

  // If optional ones e.g. default.prop does not exist in the source path, it
  // should still process the other files.
  brillo::DeleteFile(source_dir.Append("default.prop"));
  brillo::DeleteFile(source_dir.Append("odm_build.prop"));
  EXPECT_TRUE(expander.Expand());
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ(base::StringPrintf("%s%s%s%s", kBuildProp, kSystemExtBuildProp,
                               kVendorBuildProp, kProductBuildProp),
            content);

  // Finally, test the case where source is valid but the dest is not.
  dest_prop_file = base::FilePath("/nonexistent");
  EXPECT_FALSE(expander.Expand());
}

// Verify that comments and non ro. properties are not written.
TEST_F(ArcPropertyUtilTest, ExpandPropertyFiles_SingleFile_NonRo) {
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_dir));

  const base::FilePath default_prop = source_dir.Append("default.prop");
  constexpr const char kDefaultProp[] = "###\ndalvik.foo=bar\nro.foo=bar\n";
  base::WriteFile(default_prop, kDefaultProp, strlen(kDefaultProp));

  const base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "###\ndalvik.baz=boo\nro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));

  const base::FilePath vendor_build_prop =
      source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "###\ndalvik.a=b\nro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));

  const base::FilePath dest_prop_file = dest_dir.Append("combined.prop");
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, false,
                                  false, false, nullptr));

  // Verify the content.
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ("ro.foo=bar\nro.baz=boo\nro.a=b\n", content);
}

// Verify that the CDM properties received from cdm-oemcrypto over D-Bus are
// written to the properties file.
TEST_F(ArcPropertyUtilTest, TestAddingCdmProperties) {
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_dir));

  base::FilePath default_prop = source_dir.Append("default.prop");
  constexpr const char kDefaultProp[] = "ro.foo=bar\n";
  base::WriteFile(default_prop, kDefaultProp, strlen(kDefaultProp));

  base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "ro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));

  base::FilePath vendor_build_prop = source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "ro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));

  base::FilePath product_build_prop = source_dir.Append("product_build.prop");
  constexpr const char kProductBuildProp[] = "ro.c=d\n";
  base::WriteFile(product_build_prop, kProductBuildProp,
                  strlen(kProductBuildProp));

  EXPECT_CALL(*bus_, GetObjectProxy(_, _))
      .WillOnce(Return(cdm_factory_daemon_object_proxy_.get()));

  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(response.get());
  chromeos::cdm::ClientInformation client_info;
  constexpr char kManufacturer[] = "fake_manufacturer";
  constexpr char kMake[] = "fake_make";
  constexpr char kModel[] = "fake_model";
  client_info.set_manufacturer(kManufacturer);
  client_info.set_make(kMake);
  client_info.set_model(kModel);
  writer.AppendProtoAsArrayOfBytes(client_info);
  EXPECT_CALL(*cdm_factory_daemon_object_proxy_,
              CallMethodAndBlockWithErrorDetails(_, _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  const base::FilePath dest_prop_file = dest_dir.Append("combined.prop");
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, true, false,
                                  false, bus_));

  // Verify the content.
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ(std::string() + kDefaultProp + kBuildProp + kVendorBuildProp +
                kProductBuildProp + "ro.vendor.cdm.manufacturer=" +
                kManufacturer + "\nro.vendor.cdm.model=" + kModel +
                "\nro.vendor.cdm.device=" + kMake + "\n",
            content);
}

// Verify that a failure reading the CDM properties from cdm-oemcrypto over
// D-Bus is handled properly and doesn't change the properties file.
TEST_F(ArcPropertyUtilTest, TestAddingCdmProperties_DbusFailure) {
  base::FilePath source_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &source_dir));
  base::FilePath dest_dir;
  ASSERT_TRUE(base::CreateTemporaryDirInDir(GetTempDir(), "test", &dest_dir));

  base::FilePath default_prop = source_dir.Append("default.prop");
  constexpr const char kDefaultProp[] = "ro.foo=bar\n";
  base::WriteFile(default_prop, kDefaultProp, strlen(kDefaultProp));

  base::FilePath build_prop = source_dir.Append("build.prop");
  constexpr const char kBuildProp[] = "ro.baz=boo\n";
  base::WriteFile(build_prop, kBuildProp, strlen(kBuildProp));

  base::FilePath vendor_build_prop = source_dir.Append("vendor_build.prop");
  constexpr const char kVendorBuildProp[] = "ro.a=b\n";
  base::WriteFile(vendor_build_prop, kVendorBuildProp,
                  strlen(kVendorBuildProp));

  base::FilePath product_build_prop = source_dir.Append("product_build.prop");
  constexpr const char kProductBuildProp[] = "ro.c=d\n";
  base::WriteFile(product_build_prop, kProductBuildProp,
                  strlen(kProductBuildProp));

  EXPECT_CALL(*bus_, GetObjectProxy(_, _))
      .WillOnce(Return(cdm_factory_daemon_object_proxy_.get()));

  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  EXPECT_CALL(*cdm_factory_daemon_object_proxy_,
              CallMethodAndBlockWithErrorDetails(_, _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  const base::FilePath dest_prop_file = dest_dir.Append("combined.prop");
  EXPECT_TRUE(ExpandPropertyFiles(source_dir, dest_prop_file, true, true, false,
                                  false, bus_));

  // Verify the content.
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(dest_prop_file, &content));
  EXPECT_EQ(std::string() + kDefaultProp + kBuildProp + kVendorBuildProp +
                kProductBuildProp,
            content);
}

TEST_F(ArcPropertyUtilTest, AppendX86SocProperties) {
  int case_no = 0;

  for (auto& testcase :
       {std::tuple<const char*, const char*>{
            "nomatch\nmodel name\t: Intel(R) Core(TM) i5-10510U CPU @ 999GHz\n",
            "ro.soc.manufacturer=Intel\nro.soc.model=i5-10510U\n"},
        {"xyz\nmodel name\t\t: Intel(R) Core(TM) i7-920 CPU @ 2.67GHz\nabc\n",
         "ro.soc.manufacturer=Intel\nro.soc.model=i7-920\n"},
        {"nomatch\nnomatch\nnomatch\n", ""},

        // For an Asuka board.
        {"model name\t: Intel(R) Celeron(R) CPU 3855U @ 1.60GHz\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=3855U\n"},

        // For a Bob board. Note additional space around model name.
        {"model name\t: Intel(R) Celeron(R) CPU  N3060  @ 1.60GHz\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=N3060\n"},

        // Apparently starting from 11th-gen Intel i#'s, we see the gen no. is
        // called out explicitly.

        // For a Volteer (copano) board.
        {"model name\t: 11th Gen Intel(R) Core(TM) i3-1110G4 @ 1.80GHz\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=i3-1110G4\n"},

        // Many Brya boards use 12th-gen Intels, which actually end the model
        // name line with the important part (the actual ID), without a clock
        // freq. following.
        {"model name\t: 12th Gen Intel(R) Core(TM) i3-1215U\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=i3-1215U\n"},
        {"model name\t: 12th Gen Intel(R) Core(TM) i5-1250P\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=i5-1250P\n"},

        // For a Brya board (skolas).
        {"model name\t: 13th Gen Intel(R) Core(TM) i7-1365U\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=i7-1365U\n"},

        // For a Brya board (skolas).
        {"model name\t: 13th Gen Intel(R) CoreT i7-1370P\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=i7-1370P\n"},

        // For a Brya (anahera) board.
        {"model name\t: Intel(R) Celeron(R) 7305\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=7305\n"},

        // For a Brya (redrix) board. Note missing C in "Core".
        {"model name\t: 12th Gen Intel(R) ore(TM) i5-1245U\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=i5-1245U\n"},

        // For a Brya (primus) board.
        {"model name\t: Intel(R) Pentium(R) Gold 8505\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=8505\n"},

        // For a Dedede board (beetley). "CPU" is absent.
        {"model name\t: Intel(R) Celeron(R) N4500 @ 1.10GHz\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=N4500\n"},

        // For a Dedede board (blipper).
        {"model name\t: Intel(R) Pentium(R) Silver N6000 @ 1.10GHz\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=N6000\n"},

        // For a Dedede board (kled).
        {"model name\t: Intel(R) Pentium(R) CPU 6405U @ 2.40GHz\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=6405U\n"},

        // For a Zork board.
        {"line1\n"
         "model name\t: AMD Ryzen 3 3250C 15W with Radeon Graphics\n"
         "line3\n",
         "ro.soc.manufacturer=AMD\n"
         "ro.soc.model=Ryzen 3 3250C\n"},

        // For a Zork board. (includes dirinboz, ezkinil, and morphius devices)
        {"model name\t: AMD 3015Ce with Radeon Graphics\n",
         "ro.soc.manufacturer=AMD\n"
         "ro.soc.model=3015Ce\n"},

        // For a Skyrim (whiterun) board.
        {"model name\t: AMD Athlon Silver 7120C with Radeon Graphics\n",
         "ro.soc.manufacturer=AMD\n"
         "ro.soc.model=7120C\n"},

        // For a Zork board (morphius).
        {"model name\t: AMD Athlon Gold 3150C with Radeon Graphics\n",
         "ro.soc.manufacturer=AMD\n"
         "ro.soc.model=3150C\n"},

        // For a Zork board (morphius).
        {"model name\t: AMD Ryzen 5 3500C with Radeon Vega Mobile Gfx\n",
         "ro.soc.manufacturer=AMD\n"
         "ro.soc.model=Ryzen 5 3500C\n"},

        // For a Grunt board.
        {"model name\t: AMD A4-9120C RADEON R4, 5 COMPUTE CORES 2C+3G\n",
         "ro.soc.manufacturer=AMD\n"
         "ro.soc.model=A4-9120C\n"},

        // For a Grunt board (careena).
        {"model name\t: AMD A6-9220C RADEON R5, 5 COMPUTE CORES 2C+3G\n",
         "ro.soc.manufacturer=AMD\n"
         "ro.soc.model=A6-9220C\n"},

        // For a Guybrush board (nipperkin).
        {"model name\t: AMD Ryzen 5 5625C with Radeon Graphics\n",
         "ro.soc.manufacturer=AMD\n"
         "ro.soc.model=Ryzen 5 5625C\n"},

        // For an Octopus board (blooguard).
        {"model name\t: Intel(R) Pentium(R) Silver N5000 CPU @ 1.10GHz\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=N5000\n"},

        // For a Nissa board.
        {"model name\t: Intel(R) N100\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=N100\n"},

        // For a Nissa board.
        {"model name\t: Intel(R) Core(TM) i3-N305\n",
         "ro.soc.manufacturer=Intel\n"
         "ro.soc.model=i3-N305\n"},

        // For an Octopus board.
        {"model name: Intel(R) Celeron(R) N4000 CPU @ 1.10GHz\n",
         "ro.soc.manufacturer=Intel\nro.soc.model=N4000\n"},

        // CPU for some VMs. See b/256650882.
        {"model name: Intel(R) Xeon(R) CPU @ 2.80GHz\n",
         "ro.soc.manufacturer=Intel\nro.soc.model=Unknown-Xeon\n"},

        // For pre-release Intel CPUs. See b/248974069. This is so we don't get
        // Tast failures that are not actionable.
        {"model name: Genuine Intel(R) 0000\n",
         "ro.soc.manufacturer=Intel\nro.soc.model=0000-FixMe\n"}}) {
    base::StringPiece cpuinfo = std::get<0>(testcase);
    base::StringPiece expected = std::get<1>(testcase);
    auto cpuinfo_path =
        GetTempDir().Append(base::StringPrintf("cpuinfo%d", case_no++));

    ASSERT_TRUE(base::WriteFile(cpuinfo_path, cpuinfo));

    // Make sure the file is opened read-only by turning off the writable perms.
    ASSERT_EQ(chmod(cpuinfo_path.value().c_str(), 0444), 0);

    std::string actual;
    AppendX86SocProperties(cpuinfo_path, &actual);

    // Without the trailing `<< actual`, EXPECT_EQ treats `actual` as binary
    // and truncates it.
    EXPECT_EQ(expected, actual) << actual;
  }
}

TEST_F(ArcPropertyUtilTest, AppendX86SocPropertiesDoesNotOverwrite) {
  auto cpuinfo_path = GetTempDir().Append("cpuinfo");

  ASSERT_TRUE(base::WriteFile(cpuinfo_path,
                              "model name : Intel(R) Core(TM) i7-5200U CPU\n"));

  std::string dest = "xyz=123\n";
  AppendX86SocProperties(cpuinfo_path, &dest);
  EXPECT_THAT(dest, StartsWith("xyz=123\nro.soc."));
}

TEST_F(ArcPropertyUtilTest, AppendX86SocPropertiesPentiumWithSpaceInModel) {
  // Make sure we don't support model names with spaces, rather than match them.
  auto cpuinfo_path = GetTempDir().Append("cpuinfo");

  ASSERT_TRUE(base::WriteFile(
      cpuinfo_path, "model name : Intel(R) Pentium(R) Gold N1000 SecondEd\n"));

  std::string dest;
  AppendX86SocProperties(cpuinfo_path, &dest);
  EXPECT_EQ(dest, "");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesNoMatch) {
  auto socinfo_devices_dir = GetTempDir();
  auto soc0_path = socinfo_devices_dir.Append("soc0");
  auto machine_path = soc0_path.Append("machine");
  auto family_path = soc0_path.Append("family");

  ASSERT_TRUE(base::CreateDirectory(soc0_path));
  ASSERT_TRUE(base::WriteFile(machine_path, "unknown486\n"));
  ASSERT_TRUE(base::WriteFile(family_path, "unknownFamily\n"));

  std::string dest = "4=2+2\n";
  AppendArmSocProperties(socinfo_devices_dir, config(), &dest);
  EXPECT_EQ(dest, "4=2+2\n");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesMatch) {
  auto socinfo_devices_dir = GetTempDir();
  auto soc0_path = socinfo_devices_dir.Append("soc0");
  auto machine_path = soc0_path.Append("machine");
  auto family_path = soc0_path.Append("family");

  ASSERT_TRUE(base::CreateDirectory(soc0_path));
  ASSERT_TRUE(base::WriteFile(machine_path, "SC7180\n"));
  ASSERT_TRUE(base::WriteFile(family_path, "Snapdragon\n"));

  // Make sure the file is opened read-only by turning off the writable perms.
  ASSERT_EQ(chmod(machine_path.value().c_str(), 0444), 0);
  ASSERT_EQ(chmod(family_path.value().c_str(), 0444), 0);

  std::string dest = "jkl=aoe\n";
  AppendArmSocProperties(socinfo_devices_dir, config(), &dest);
  EXPECT_EQ(dest,
            "jkl=aoe\n"
            "ro.soc.manufacturer=Qualcomm\n"
            "ro.soc.model=SC7180\n");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesSymlink) {
  auto sysfs_dir = GetTempDir();
  auto devices_dir = sysfs_dir.Append("devices");
  auto soc0_path = devices_dir.Append("soc0");
  auto machine_path = soc0_path.Append("machine");
  auto family_path = soc0_path.Append("family");
  auto bus_dir = sysfs_dir.Append("bus");
  auto socinfo_dir = bus_dir.Append("soc");
  auto socinfo_devices_dir = bus_dir.Append("devices");
  auto socinfo_soc0_path = socinfo_devices_dir.Append("soc0");

  // Try to replicate something akin to the real structure of sysfs, which has
  // symlinks. This helps confirm we aren't using "safe" functions to read.
  ASSERT_TRUE(base::CreateDirectory(devices_dir));
  ASSERT_TRUE(base::CreateDirectory(soc0_path));
  ASSERT_TRUE(base::WriteFile(machine_path, "SC7180\n"));
  ASSERT_TRUE(base::WriteFile(family_path, "Snapdragon\n"));
  ASSERT_TRUE(base::CreateDirectory(bus_dir));
  ASSERT_TRUE(base::CreateDirectory(socinfo_dir));
  ASSERT_TRUE(base::CreateDirectory(socinfo_devices_dir));
  ASSERT_TRUE(base::CreateSymbolicLink(soc0_path, socinfo_soc0_path));

  // Make sure the file is opened read-only by turning off the writable perms.
  ASSERT_EQ(chmod(machine_path.value().c_str(), 0444), 0);

  std::string dest = "symlinks=fun\n";
  AppendArmSocProperties(socinfo_devices_dir, config(), &dest);
  EXPECT_EQ(dest,
            "symlinks=fun\n"
            "ro.soc.manufacturer=Qualcomm\n"
            "ro.soc.model=SC7180\n");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesTwo) {
  auto socinfo_devices_dir = GetTempDir();
  auto soc0_path = socinfo_devices_dir.Append("soc0");
  auto soc_id0_path = soc0_path.Append("soc_id");
  auto family0_path = soc0_path.Append("family");
  auto soc1_path = socinfo_devices_dir.Append("soc1");
  auto soc_id1_path = soc1_path.Append("soc_id");
  auto machine1_path = soc1_path.Append("machine");
  auto family1_path = soc1_path.Append("family");

  // soc0 will exist, but _not_ have a machine file. It will represent the
  // generic version of the driver that directly exposes the firmware.
  ASSERT_TRUE(base::CreateDirectory(soc0_path));
  ASSERT_TRUE(base::WriteFile(soc_id0_path, "jep106:0070:7180\n"));
  ASSERT_TRUE(base::WriteFile(family0_path, "jep106:0070\n"));

  // soc1 will be exposing a "nicer" SoC-specific driver.
  ASSERT_TRUE(base::CreateDirectory(soc1_path));
  ASSERT_TRUE(base::WriteFile(soc_id1_path, "425\n"));
  ASSERT_TRUE(base::WriteFile(machine1_path, "SC7180\n"));
  ASSERT_TRUE(base::WriteFile(family1_path, "Snapdragon\n"));

  // Make sure the file is opened read-only by turning off the writable perms.
  ASSERT_EQ(chmod(soc_id1_path.value().c_str(), 0444), 0);
  ASSERT_EQ(chmod(machine1_path.value().c_str(), 0444), 0);
  ASSERT_EQ(chmod(family1_path.value().c_str(), 0444), 0);

  std::string dest = "one=two\n";
  AppendArmSocProperties(socinfo_devices_dir, config(), &dest);
  EXPECT_EQ(dest,
            "one=two\n"
            "ro.soc.manufacturer=Qualcomm\n"
            "ro.soc.model=SC7180\n");
}

TEST_F(ArcPropertyUtilTest, AppendX86SocPropertiesCannotOpenCpuinfo) {
  auto cpuinfo_path = GetTempDir().Append("cpuinfo.nothere");

  std::string dest;
  AppendX86SocProperties(cpuinfo_path, &dest);
  EXPECT_EQ(dest, "");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesCannotOpenMachineFile) {
  auto temp_dir = GetTempDir();
  auto socinfo_path = temp_dir.Append("directory.nothere");

  std::string dest;
  AppendArmSocProperties(socinfo_path, config(), &dest);
  EXPECT_EQ(dest, "");
}

TEST_F(ArcPropertyUtilTest, AppendArmSocPropertiesHardCodedPlatformMapping) {
  auto temp_dir = GetTempDir();
  auto socinfo_path = temp_dir.Append("directory.nothere");

  config()->SetString("/identity", "platform-name", "Kukui");
  std::string dest;
  AppendArmSocProperties(socinfo_path, config(), &dest);

  EXPECT_THAT(dest, HasSubstr("ro.soc.manufacturer=Mediatek\n"));
  EXPECT_THAT(dest, HasSubstr("ro.soc.model=MT8183\n"));
}

}  // namespace
}  // namespace arc
