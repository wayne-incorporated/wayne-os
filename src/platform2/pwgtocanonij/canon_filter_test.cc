// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "pwgtocanonij/canon_filter.h"

#include <stdlib.h>

#include <memory>
#include <utility>

#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace canonij {

namespace {

// Extract the raster data from buffer and store in rasterData.  Return true on
// success or false if there was an error.
bool GetRasterData(const std::string& buffer, std::string& rasterData) {
  // The raster data begins directly after the end tag of the SendData
  // operation.  Additionally, the size of the raster data is part of the
  // SendData operation.  This will look for the size, and look for the ending
  // tag after that point.
  const std::string beginSizeTag("<ivec:datasize>");
  const std::string endSizeTag("</ivec:datasize>");
  const std::string endElementTag("</cmd>");

  // Find out how many bytes of raster data are in the output.
  auto startOfSize = buffer.find(beginSizeTag);
  if (startOfSize == std::string::npos) {
    return false;
  }
  startOfSize += beginSizeTag.size();
  auto endOfSize = buffer.find(endSizeTag, startOfSize);
  if (endOfSize == std::string::npos) {
    return false;
  }
  auto sizeString = buffer.substr(startOfSize, endOfSize - startOfSize);
  unsigned rasterSize = 0;
  if (!base::StringToUint(sizeString, &rasterSize)) {
    return false;
  }

  // Find out where the raster data starts.
  auto startOfData = buffer.find(endElementTag, startOfSize);
  if (startOfData == std::string::npos) {
    return false;
  }
  startOfData += endElementTag.size();

  // Make sure buffer is large enough to copy from.
  if (buffer.size() - startOfData < rasterSize) {
    return false;
  }

  // Copy raster data into output param.
  rasterData.resize(rasterSize);
  memcpy(rasterData.data(), buffer.data() + startOfData, rasterSize);
  return true;
}

// Returns true if needle is found in haystack, else returns false.
bool Contains(std::string_view haystack, std::string_view needle) {
  return haystack.find(needle) != std::string_view::npos;
}

}  // namespace

class CanonFilterTest : public testing::Test {
 protected:
  CanonFilterTest() {
    // Create a temporary directory for our filter and our tests.
    base::ScopedTempDir testDir;
    CHECK(testDir.CreateUniqueTempDir());
    testDirPath_ = testDir.GetPath();

    // Get the path to our test PWG file and create a SafeFD to pass to our
    // filter.
    base::FilePath basePath;
    CHECK(base::GetCurrentDirectory(&basePath));
    base::FilePath pwgPath = basePath.Append(pwgRasterPath_);
    auto result = brillo::SafeFD::Root().first.OpenExistingFile(
        base::FilePath(pwgPath), O_RDONLY | O_CLOEXEC);
    CHECK(!brillo::SafeFD::IsError(result.second));

    filter_ = std::make_unique<CanonFilter>("1", std::move(result.first),
                                            std::move(testDir));
  }

  base::File GetTempFile() {
    return CreateAndOpenTemporaryFileInDir(testDirPath_, &tmpFilePath_);
  }

  const char* ppdPath_ = "./test-data/example.ppd";
  const char* badPpdPath_ = "./test-data/example-bad.ppd";
  const char* pwgRasterPath_ = "./test-data/test.pwgraster";

  base::FilePath tmpFilePath_;
  base::FilePath testDirPath_;
  std::unique_ptr<CanonFilter> filter_;
};

TEST_F(CanonFilterTest, RunWithDefaultOptions) {
  // Test when the user does not provide any command line args.  In this case,
  // all the default values from the PPD should be used.
  setenv("PPD", ppdPath_, 1);

  base::File output = GetTempFile();
  ASSERT_TRUE(output.IsValid());
  filter_->SetOutputForTesting(output.GetPlatformFile());

  EXPECT_TRUE(filter_->Run(""));
  EXPECT_TRUE(output.Flush());

  // Open our PWG raster input file separately so we can compare it to the
  // generated output.
  const base::FilePath pwgRasterFilePath(pwgRasterPath_);
  base::File input(pwgRasterFilePath,
                   base::File::FLAG_OPEN | base::File::FLAG_READ);
  ASSERT_TRUE(input.IsValid());
  base::File::Info inputInfo;
  ASSERT_TRUE(input.GetInfo(&inputInfo));
  const int64_t expectedRasterSize = inputInfo.size;
  std::string expectedRasterData;
  EXPECT_TRUE(base::ReadFileToString(pwgRasterFilePath, &expectedRasterData));
  EXPECT_EQ(expectedRasterData.size(), expectedRasterSize);

  std::string buffer;
  EXPECT_TRUE(base::ReadFileToString(tmpFilePath_, &buffer));
  EXPECT_GT(buffer.size(), expectedRasterSize);

  // Look for all of our XML tags along with the default options from our PPD.
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>StartJob</ivec:operation>"));
  EXPECT_TRUE(
      Contains(buffer, "<ivec:operation>SetConfiguration</ivec:operation>"));
  EXPECT_TRUE(
      Contains(buffer, "<ivec:papersize>iso_a4_210x297mm</ivec:papersize>"));
  EXPECT_TRUE(Contains(buffer, "<ivec:papertype>stationery</ivec:papertype>"));
  EXPECT_TRUE(
      Contains(buffer, "<ivec:borderlessprint>OFF</ivec:borderlessprint>"));
  EXPECT_TRUE(
      Contains(buffer, "<ivec:printcolormode>color</ivec:printcolormode>"));
  EXPECT_TRUE(Contains(buffer, "<ivec:duplexprint>OFF</ivec:duplexprint>"));
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>SendData</ivec:operation>"));
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>EndJob</ivec:operation>"));

  std::string actualRasterData;
  EXPECT_TRUE(GetRasterData(buffer, actualRasterData));

  EXPECT_EQ(actualRasterData.size(), expectedRasterSize);
  EXPECT_EQ(memcmp(expectedRasterData.c_str(), actualRasterData.c_str(),
                   expectedRasterSize),
            0);
}

TEST_F(CanonFilterTest, RunWithCustomOptions) {
  // Test when the user does not provide any command line args.  In this case,
  // all the default values from the PPD should be used.
  setenv("PPD", ppdPath_, 1);

  base::File output = GetTempFile();
  ASSERT_TRUE(output.IsValid());
  filter_->SetOutputForTesting(output.GetPlatformFile());

  EXPECT_TRUE(filter_->Run(
      "PageSize=4x6.bl MediaType=photo ColorModel=Gray Duplex=DuplexTumble"));
  EXPECT_TRUE(output.Flush());

  // Open our PWG raster input file separately so we can compare it to the
  // generated output.
  const base::FilePath pwgRasterFilePath(pwgRasterPath_);
  base::File input(pwgRasterFilePath,
                   base::File::FLAG_OPEN | base::File::FLAG_READ);
  ASSERT_TRUE(input.IsValid());
  base::File::Info inputInfo;
  ASSERT_TRUE(input.GetInfo(&inputInfo));
  const int64_t expectedRasterSize = inputInfo.size;
  std::string expectedRasterData;
  EXPECT_TRUE(base::ReadFileToString(pwgRasterFilePath, &expectedRasterData));
  EXPECT_EQ(expectedRasterData.size(), expectedRasterSize);

  std::string buffer;
  EXPECT_TRUE(base::ReadFileToString(tmpFilePath_, &buffer));
  EXPECT_GT(buffer.size(), expectedRasterSize);

  // Look for all of our XML tags along with the default options from our PPD.
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>StartJob</ivec:operation>"));
  EXPECT_TRUE(
      Contains(buffer, "<ivec:operation>SetConfiguration</ivec:operation>"));
  EXPECT_TRUE(
      Contains(buffer, "<ivec:papersize>na_index-4x6_4x6in</ivec:papersize>"));
  EXPECT_TRUE(Contains(
      buffer, "<ivec:papertype>custom-media-type-canon-19</ivec:papertype>"));
  EXPECT_TRUE(
      Contains(buffer, "<ivec:borderlessprint>ON</ivec:borderlessprint>"));
  EXPECT_TRUE(Contains(
      buffer, "<ivec:printcolormode>monochrome</ivec:printcolormode>"));
  EXPECT_TRUE(Contains(buffer, "<ivec:duplexprint>ON</ivec:duplexprint>"));
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>SendData</ivec:operation>"));
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>EndJob</ivec:operation>"));

  std::string actualRasterData;
  EXPECT_TRUE(GetRasterData(buffer, actualRasterData));

  EXPECT_EQ(actualRasterData.size(), expectedRasterSize);
  EXPECT_EQ(memcmp(expectedRasterData.c_str(), actualRasterData.c_str(),
                   expectedRasterSize),
            0);
}

TEST_F(CanonFilterTest, Cancel) {
  // Test that Run only produces the EndJob tag if the job gets canceled.

  setenv("PPD", ppdPath_, 1);

  base::File output = GetTempFile();
  ASSERT_TRUE(output.IsValid());
  filter_->SetOutputForTesting(output.GetPlatformFile());

  raise(SIGTERM);

  EXPECT_TRUE(filter_->Run(""));
  EXPECT_TRUE(output.Flush());

  // Clear the SIGTERM signal so it won't affect the rest of the tests
  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGTERM);
  int sig;
  EXPECT_EQ(sigwait(&sigset, &sig), 0);

  std::string buffer;
  EXPECT_TRUE(base::ReadFileToString(tmpFilePath_, &buffer));
  EXPECT_GT(buffer.size(), 0);

  // We should have the end job tag but nothing else.
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>EndJob</ivec:operation>"));
  EXPECT_FALSE(Contains(buffer, "<ivec:operation>StartJob</ivec:operation>"));
  EXPECT_FALSE(
      Contains(buffer, "<ivec:operation>SetConfiguration</ivec:operation>"));
  EXPECT_FALSE(Contains(buffer, "<ivec:operation>SendData</ivec:operation>"));
}

TEST_F(CanonFilterTest, CancelDuringPageWrite) {
  // Test that Run produces correct output when canceled while writing a page.

  setenv("PPD", ppdPath_, 1);

  base::File output = GetTempFile();
  ASSERT_TRUE(output.IsValid());
  filter_->SetOutputForTesting(output.GetPlatformFile());
  // Set an arbitrary number to account for the ShouldCancel calls during setup
  // and a few lines while writing a page.  Not *completely* arbitrary, though,
  // since it has to be in sync with the datasize used below.
  filter_->SetCancelCountdownForTesting(10);

  EXPECT_TRUE(filter_->Run(""));
  EXPECT_TRUE(output.Flush());

  std::string buffer;
  EXPECT_TRUE(base::ReadFileToString(tmpFilePath_, &buffer));
  EXPECT_GT(buffer.size(), 0);

  // We should have all of our tags since the cancellation happened after we
  // started writing page data.
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>EndJob</ivec:operation>"));
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>StartJob</ivec:operation>"));
  EXPECT_TRUE(
      Contains(buffer, "<ivec:operation>SetConfiguration</ivec:operation>"));
  EXPECT_TRUE(Contains(buffer, "<ivec:operation>SendData</ivec:operation>"));
  // Furthermore, make sure the the datasize looks as expected.  This number
  // comes from the input raster file (bytes per line, number of lines) and the
  // number of times that ShouldCancel gets called based on our countdown
  // above.  This is a little brittle since it requires knowing ShouldCancel
  // gets called 'x' number of times before we start writing page data, but if
  // that ever changes in the code this test will fail and we can just update
  // it.
  EXPECT_TRUE(Contains(buffer, "<ivec:datasize>1800</ivec:datasize>"));
}

TEST_F(CanonFilterTest, NoPpdEnvVar) {
  unsetenv("PPD");
  EXPECT_FALSE(filter_->Run(""));
}

TEST_F(CanonFilterTest, NonexistentPpd) {
  setenv("PPD", "file-does-not-exist.nope", 1);
  EXPECT_FALSE(filter_->Run(""));
}

TEST_F(CanonFilterTest, WriteErrorDuringRun) {
  // Test output error during Run.
  setenv("PPD", ppdPath_, 1);
  base::File output = GetTempFile();
  EXPECT_TRUE(output.IsValid());
  output.Close();
  EXPECT_TRUE(base::SetPosixFilePermissions(tmpFilePath_, 0));
  output.Initialize(tmpFilePath_,
                    base::File::FLAG_READ | base::File::FLAG_OPEN);
  filter_->SetOutputForTesting(output.GetPlatformFile());

  EXPECT_FALSE(filter_->Run(""));
}

TEST_F(CanonFilterTest, RunBadPpd) {
  // Test a bad PPD during Run.

  setenv("PPD", badPpdPath_, 1);

  base::File output = GetTempFile();
  ASSERT_TRUE(output.IsValid());
  filter_->SetOutputForTesting(output.GetPlatformFile());

  EXPECT_FALSE(filter_->Run(""));
}

}  // namespace canonij
