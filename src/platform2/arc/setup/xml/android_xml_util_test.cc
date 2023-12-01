// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/xml/android_xml_util.h"

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <gtest/gtest.h>

#include "arc/setup/xml/android_binary_xml_tokenizer_test_util.h"

namespace arc {

namespace {

bool FindLineCallback(std::string* out_prop, const std::string& line) {
  if (line != "string_to_find")
    return false;
  *out_prop = "FOUND";
  return true;
}

}  // namespace

TEST(AndroidXmlUtilTest, TestGetFingerprintAndSdkVersionFromPackagesXmlText) {
  // Tests that GetFingerprintAndSdkVersionFromPackagesXml works for text XML.
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::FilePath packages_file =
      temp_directory.GetPath().Append("packages.xml");

  // Create a new file and read it.
  ASSERT_TRUE(base::WriteFile(
      packages_file,
      "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
      "<packages>\n"
      "  <version sdkVersion=\"25\" databaseVersion=\"3\" fingerprint=\"f1\">\n"
      "  <version volumeUuid=\"primary_physical\" "
      "sdkVersion=\"25\" databaseVersion=\"25\" fingerprint=\"f2\">\n"
      "</packages>"));
  std::string fingerprint;
  std::string sdk_version;
  EXPECT_TRUE(GetFingerprintAndSdkVersionFromPackagesXml(
      packages_file, &fingerprint, &sdk_version));
  EXPECT_EQ("f1", fingerprint);
  EXPECT_EQ("25", sdk_version);

  ASSERT_TRUE(base::WriteFile(
      packages_file,
      // Reverse the order of the version elements.
      "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
      "<packages>\n"
      "  <version volumeUuid=\"primary_physical\" "
      "sdkVersion=\"25\" databaseVersion=\"25\" fingerprint=\"f2\">\n"
      "  <version sdkVersion=\"25\" databaseVersion=\"3\" fingerprint=\"f1\">\n"
      "</packages>"));
  fingerprint.clear();
  sdk_version.clear();
  EXPECT_TRUE(GetFingerprintAndSdkVersionFromPackagesXml(
      packages_file, &fingerprint, &sdk_version));
  EXPECT_EQ("f1", fingerprint);
  EXPECT_EQ("25", sdk_version);

  // Test invalid <version>s.
  ASSERT_TRUE(base::WriteFile(
      packages_file,
      // "external" version only.
      "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
      "<packages>\n"
      "  <version volumeUuid=\"primary_physical\" "
      "sdkVersion=\"25\" databaseVersion=\"25\" fingerprint=\"f2\">\n"
      "</packages>"));
  EXPECT_FALSE(GetFingerprintAndSdkVersionFromPackagesXml(
      packages_file, &fingerprint, &sdk_version));

  ASSERT_TRUE(base::WriteFile(
      packages_file,
      // No sdkVersion.
      "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
      "<packages>\n"
      "  <version databaseVersion=\"3\" fingerprint=\"f1\">\n"
      "</packages>"));
  EXPECT_FALSE(GetFingerprintAndSdkVersionFromPackagesXml(
      packages_file, &fingerprint, &sdk_version));

  ASSERT_TRUE(base::WriteFile(
      packages_file,
      // No databaseVersion.
      "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
      "<packages>\n"
      "  <version sdkVersion=\"25\" fingerprint=\"f1\">\n"
      "</packages>"));
  EXPECT_FALSE(GetFingerprintAndSdkVersionFromPackagesXml(
      packages_file, &fingerprint, &sdk_version));

  ASSERT_TRUE(base::WriteFile(
      packages_file,
      // No fingerprint.
      "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
      "<packages>\n"
      "  <version sdkVersion=\"25\" databaseVersion=\"3\">\n"
      "</packages>"));
  EXPECT_FALSE(GetFingerprintAndSdkVersionFromPackagesXml(
      packages_file, &fingerprint, &sdk_version));

  ASSERT_TRUE(base::WriteFile(
      packages_file,
      // No valid fingerprint.
      "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
      "<packages>\n"
      "  <version sdkVersion=\"25\" databaseVersion=\"3\" fingerprint=\"X>\n"
      "</packages>"));
  EXPECT_FALSE(GetFingerprintAndSdkVersionFromPackagesXml(
      packages_file, &fingerprint, &sdk_version));

  ASSERT_TRUE(base::WriteFile(
      packages_file,
      // No <version> elements.
      "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
      "<packages/>\n"));
  EXPECT_FALSE(GetFingerprintAndSdkVersionFromPackagesXml(
      packages_file, &fingerprint, &sdk_version));

  ASSERT_TRUE(base::WriteFile(packages_file,
                              // Empty file.
                              ""));
  EXPECT_FALSE(GetFingerprintAndSdkVersionFromPackagesXml(
      packages_file, &fingerprint, &sdk_version));
}

TEST(AndroidXmlUtilTest, TestGetFingerprintAndSdkVersionFromBinaryPackagesXml) {
  using Token = AndroidBinaryXmlTokenizer::Token;
  using Type = AndroidBinaryXmlTokenizer::Type;

  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::FilePath packages_file =
      temp_directory.GetPath().Append("packages.xml");

  AndroidBinaryXmlWriter writer;
  ASSERT_TRUE(writer.Init(packages_file));

  // <version> with volumeUuid should be ignored.
  // <version
  ASSERT_TRUE(writer.WriteToken(Token::kStartTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));
  // volumeUuid="primary_physical"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kString));
  ASSERT_TRUE(writer.WriteInternedString("volumeUuid"));
  ASSERT_TRUE(writer.WriteString("primary_physical"));
  // sdkVersion="20"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kInt));
  ASSERT_TRUE(writer.WriteInternedString("sdkVersion"));
  ASSERT_TRUE(writer.WriteInt32(20));
  // databaseVersion="3"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kInt));
  ASSERT_TRUE(writer.WriteInternedString("databaseVersion"));
  ASSERT_TRUE(writer.WriteInt32(3));
  // fingerprint="fingerprint-volumeuuid"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kString));
  ASSERT_TRUE(writer.WriteInternedString("fingerprint"));
  ASSERT_TRUE(writer.WriteString("fingerprint-volumeuuid"));
  // />
  ASSERT_TRUE(writer.WriteToken(Token::kEndTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));

  // <version> without sdkVersion should be ignored.
  // <version
  ASSERT_TRUE(writer.WriteToken(Token::kStartTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));
  // databaseVersion="3"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kInt));
  ASSERT_TRUE(writer.WriteInternedString("databaseVersion"));
  ASSERT_TRUE(writer.WriteInt32(3));
  // fingerprint="fingerprint-nosdkversion"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kString));
  ASSERT_TRUE(writer.WriteInternedString("fingerprint"));
  ASSERT_TRUE(writer.WriteString("fingerprint-nosdkversion"));
  // />
  ASSERT_TRUE(writer.WriteToken(Token::kEndTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));

  // <version> without databaseVesrion should be ignored.
  // <version
  ASSERT_TRUE(writer.WriteToken(Token::kStartTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));
  // sdkVersion="20"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kInt));
  ASSERT_TRUE(writer.WriteInternedString("sdkVersion"));
  ASSERT_TRUE(writer.WriteInt32(20));
  // fingerprint="fingerprint-nodatabaseversion"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kString));
  ASSERT_TRUE(writer.WriteInternedString("fingerprint"));
  ASSERT_TRUE(writer.WriteString("fingerprint-nodatabaseversion"));
  // />
  ASSERT_TRUE(writer.WriteToken(Token::kEndTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));

  // <version> without fingerprint should be ignored.
  // <version
  ASSERT_TRUE(writer.WriteToken(Token::kStartTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));
  // sdkVersion="20"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kInt));
  ASSERT_TRUE(writer.WriteInternedString("sdkVersion"));
  ASSERT_TRUE(writer.WriteInt32(20));
  // databaseVersion="3"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kInt));
  ASSERT_TRUE(writer.WriteInternedString("databaseVersion"));
  ASSERT_TRUE(writer.WriteInt32(3));
  // />
  ASSERT_TRUE(writer.WriteToken(Token::kEndTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));

  // This is the <version> tag we want.
  // <version
  ASSERT_TRUE(writer.WriteToken(Token::kStartTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));
  // sdkVersion="30"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kInt));
  ASSERT_TRUE(writer.WriteInternedString("sdkVersion"));
  ASSERT_TRUE(writer.WriteInt32(30));
  // databaseVersion="3"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kInt));
  ASSERT_TRUE(writer.WriteInternedString("databaseVersion"));
  ASSERT_TRUE(writer.WriteInt32(3));
  // fingerprint="fingerprint-ok"
  ASSERT_TRUE(writer.WriteToken(Token::kAttribute, Type::kString));
  ASSERT_TRUE(writer.WriteInternedString("fingerprint"));
  ASSERT_TRUE(writer.WriteString("fingerprint-ok"));
  // />
  ASSERT_TRUE(writer.WriteToken(Token::kEndTag, Type::kNull));
  ASSERT_TRUE(writer.WriteInternedString("version"));

  std::string fingerprint;
  std::string sdk_version;
  EXPECT_TRUE(GetFingerprintAndSdkVersionFromBinaryPackagesXml(
      packages_file, &fingerprint, &sdk_version));
  EXPECT_EQ("fingerprint-ok", fingerprint);
  EXPECT_EQ("30", sdk_version);
}

TEST(AndroidXmlUtilTest,
     TestGetFingerprintAndSdkVersionFromBinaryPackagesXmlWithFileR) {
  // Tests GetFingerprintAndSdkVersionFromBinaryPackagesXml() with packages.xml
  // generated by Android R.
  const char* src_dir = getenv("SRC");
  ASSERT_NE(src_dir, nullptr);
  base::FilePath test_file = base::FilePath(src_dir)
                                 .AppendASCII("testdata")
                                 .AppendASCII("packages_binary_r.xml");

  std::string fingerprint;
  std::string sdk_version;
  EXPECT_TRUE(GetFingerprintAndSdkVersionFromBinaryPackagesXml(
      test_file, &fingerprint, &sdk_version));
  EXPECT_EQ(
      "google/hatch/hatch_cheets:11/R102-14650.0.0/8375693:user/release-keys",
      fingerprint);
  EXPECT_EQ("30", sdk_version);
}

TEST(AndroidXmlUtilTest, TestFindLine) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::FilePath file = temp_directory.GetPath().Append("test.file");

  // Create a new prop file and read it.
  ASSERT_TRUE(base::WriteFile(file, "string_to_find"));
  std::string v;
  EXPECT_TRUE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
  EXPECT_EQ("FOUND", v);

  // Test with multi-line files.
  v.clear();
  ASSERT_TRUE(base::WriteFile(file, "string_to_find\nline"));
  EXPECT_TRUE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
  EXPECT_EQ("FOUND", v);
  v.clear();
  ASSERT_TRUE(base::WriteFile(file, "line\nstring_to_find\nline"));
  EXPECT_TRUE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
  EXPECT_EQ("FOUND", v);
  v.clear();
  ASSERT_TRUE(base::WriteFile(file, "line\nstring_to_find"));
  EXPECT_TRUE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
  EXPECT_EQ("FOUND", v);
  v.clear();
  ASSERT_TRUE(base::WriteFile(file, "line\nstring_to_find\n"));
  EXPECT_TRUE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
  EXPECT_EQ("FOUND", v);

  // Test without the target string.
  ASSERT_TRUE(base::WriteFile(file, "string_to_findX"));
  EXPECT_FALSE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
  ASSERT_TRUE(base::WriteFile(file, "string_to_fin"));
  EXPECT_FALSE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
  ASSERT_TRUE(base::WriteFile(file, "string_to_fin\nd"));
  EXPECT_FALSE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
  ASSERT_TRUE(base::WriteFile(file, "s\ntring_to_find"));
  EXPECT_FALSE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
  ASSERT_TRUE(base::WriteFile(file, ""));
  EXPECT_FALSE(FindLine(file, base::BindRepeating(&FindLineCallback, &v)));
}

}  // namespace arc
