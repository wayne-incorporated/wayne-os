// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/certificate_file.h"

#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::_;

namespace shill {

class CertificateFileTest : public testing::Test {
 public:
  CertificateFileTest() = default;

  void SetUp() override {
    CHECK(temp_dir_.CreateUniqueTempDir());
    certificate_directory_ = temp_dir_.GetPath().Append("certificates");
    certificate_file_.set_root_directory(certificate_directory_);
  }

 protected:
  static const char kDERData[];
  static const char kPEMData[];

  std::string ExtractHexData(const std::string& pem_data) {
    return CertificateFile::ExtractHexData(pem_data);
  }
  const base::FilePath& GetOutputFile() {
    return certificate_file_.output_file_;
  }
  const base::FilePath& GetRootDirectory() {
    return certificate_file_.root_directory_;
  }
  const char* GetPEMHeader() { return CertificateFile::kPEMHeader; }
  const char* GetPEMFooter() { return CertificateFile::kPEMFooter; }

  CertificateFile certificate_file_;
  base::ScopedTempDir temp_dir_;
  base::FilePath certificate_directory_;
};

const char CertificateFileTest::kDERData[] =
    "This does not have to be a real certificate "
    "since we are not testing its validity.";
const char CertificateFileTest::kPEMData[] =
    "VGhpcyBkb2VzIG5vdCBoYXZlIHRvIGJlIGEgcmVhbCBjZXJ0aWZpY2F0ZSBzaW5j\n"
    "ZSB3ZSBhcmUgbm90IHRlc3RpbmcgaXRzIHZhbGlkaXR5Lgo=\n";

TEST_F(CertificateFileTest, Construction) {
  EXPECT_TRUE(GetRootDirectory() == certificate_directory_);
  EXPECT_FALSE(base::PathExists(GetRootDirectory()));
  EXPECT_TRUE(GetOutputFile().empty());
}

TEST_F(CertificateFileTest, CreatePEMFromStrings) {
  // Create a formatted PEM file from the inner HEX data.
  const std::vector<std::string> kPEMVector0{kPEMData};
  base::FilePath outfile0 = certificate_file_.CreatePEMFromStrings(kPEMVector0);
  EXPECT_FALSE(outfile0.empty());
  EXPECT_TRUE(base::PathExists(outfile0));
  EXPECT_TRUE(certificate_directory_.IsParent(outfile0));
  std::string file_string0;
  EXPECT_TRUE(base::ReadFileToString(outfile0, &file_string0));
  auto expected_output0 = base::StringPrintf("%s\n%s%s\n", GetPEMHeader(),
                                             kPEMData, GetPEMFooter());
  EXPECT_EQ(expected_output0, file_string0);

  // Create a formatted PEM file from formatted PEM.
  const std::vector<std::string> kPEMVector1{expected_output0, kPEMData};
  base::FilePath outfile1 = certificate_file_.CreatePEMFromStrings(kPEMVector1);
  EXPECT_FALSE(outfile1.empty());
  EXPECT_TRUE(base::PathExists(outfile1));
  EXPECT_FALSE(base::PathExists(outfile0));  // Old file is deleted.
  std::string file_string1;
  EXPECT_TRUE(base::ReadFileToString(outfile1, &file_string1));
  auto expected_output1 = base::StringPrintf("%s%s", expected_output0.c_str(),
                                             expected_output0.c_str());
  EXPECT_EQ(expected_output1, file_string1);

  // Fail to create a PEM file.  Old file should not have been deleted.
  const std::vector<std::string> kPEMVector2{kPEMData, ""};
  base::FilePath outfile2 = certificate_file_.CreatePEMFromStrings(kPEMVector2);
  EXPECT_TRUE(outfile2.empty());
  EXPECT_TRUE(base::PathExists(outfile1));
}

TEST_F(CertificateFileTest, ExtractHexData) {
  EXPECT_EQ("", ExtractHexData(""));
  EXPECT_EQ("foo\n", ExtractHexData("foo"));
  EXPECT_EQ("foo\nbar\n", ExtractHexData("foo\r\n\t\n bar\n"));
  EXPECT_EQ("", ExtractHexData(base::StringPrintf(
                    "%s\nfoo\nbar\n%s\n", GetPEMFooter(), GetPEMHeader())));
  EXPECT_EQ("", ExtractHexData(base::StringPrintf(
                    "%s\nfoo\nbar\n%s\n", GetPEMHeader(), GetPEMHeader())));
  EXPECT_EQ(
      "", ExtractHexData(base::StringPrintf("%s\nfoo\nbar\n", GetPEMHeader())));
  EXPECT_EQ(
      "", ExtractHexData(base::StringPrintf("foo\nbar\n%s\n", GetPEMFooter())));
  EXPECT_EQ("foo\nbar\n",
            ExtractHexData(base::StringPrintf("%s\nfoo\nbar\n%s\n",
                                              GetPEMHeader(), GetPEMFooter())));
  EXPECT_EQ("bar\n",
            ExtractHexData(base::StringPrintf("foo\n%s\nbar\n%s\nbaz\n",
                                              GetPEMHeader(), GetPEMFooter())));
}

TEST_F(CertificateFileTest, Destruction) {
  base::FilePath outfile;
  {
    CertificateFile certificate_file;
    certificate_file.set_root_directory(temp_dir_.GetPath());
    outfile = certificate_file.CreatePEMFromStrings({kPEMData});
    EXPECT_TRUE(base::PathExists(outfile));
  }
  // The output file should be deleted when certificate_file goes out-of-scope.
  EXPECT_FALSE(base::PathExists(outfile));
}

}  // namespace shill
