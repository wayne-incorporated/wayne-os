// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <utility>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <base/files/scoped_temp_dir.h>
#include <base/files/file_util.h>
#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/debugd/dbus-constants.h>

#include "debugd/src/cups_tool.h"

namespace debugd {

namespace {

constexpr base::StringPiece kMinimalPPDContent(R"PPD(*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageVersion: English
*LanguageEncoding: ISOLatin1
*PCFileName: "SAMPLE.PPD"
*Product: "(Sample)"
*PSVersion: "(1) 1"
*ModelName: "Sample"
*ShortNickName: "Sample"
*NickName: "Sample"
*Manufacturer: "Sample"
*OpenUI *PageSize: PickOne
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595.20 841.68]>>setpagedevice"
*CloseUI: *PageSize
*OpenUI *PageRegion: PickOne
*DefaultPageRegion: A4
*PageRegion A4/A4: "<</PageRegion[595.20 841.68]>>setpagedevice"
*CloseUI: *PageRegion
*DefaultImageableArea: A4
*ImageableArea A4/A4: "8.40 8.40 586.80 833.28"
*DefaultPaperDimension: A4
*PaperDimension A4/A4: "595.20 841.68"
)PPD");

}  // namespace

class FakeLpTools : public LpTools {
 public:
  FakeLpTools() { CHECK(ppd_dir_.CreateUniqueTempDir()); }

  int Lpadmin(const ProcessWithOutput::ArgList& arg_list,
              bool inherit_usergroups,
              const base::EnvironmentMap& env,
              const std::vector<uint8_t>* std_input) override {
    return lpadmin_result_;
  }

  // Return 1 if lpstat_output_ is empty, else populate output (if non-null) and
  // return 0.
  int Lpstat(const ProcessWithOutput::ArgList& arg_list,
             std::string* output) override {
    if (lpstat_output_.empty()) {
      return 1;
    }

    if (output != nullptr) {
      *output = lpstat_output_;
    }

    return 0;
  }

  int CupsTestPpd(const std::vector<uint8_t>&) const override {
    return cupstestppd_result_;
  }

  int CupsUriHelper(const std::string& uri) const override {
    return urihelper_result_;
  }

  int RunAsUser(const std::string& user,
                const std::string& group,
                const std::string& command,
                const std::string& seccomp_policy,
                const ProcessWithOutput::ArgList& arg_list,
                const std::vector<uint8_t>* std_input = nullptr,
                bool inherit_usergroups = false,
                const base::EnvironmentMap& env = {},
                std::string* out = nullptr) const override {
    return runasuser_result_;
  }

  const base::FilePath& GetCupsPpdDir() const override {
    return ppd_dir_.GetPath();
  }

  int Chown(const std::string& path, uid_t owner, gid_t group) const override {
    return chown_result_;
  }

  // The following methods allow the user to setup the fake object to return the
  // desired results.

  void SetLpstatOutput(const std::string& data) { lpstat_output_ = data; }

  void SetCupsTestPPDResult(int result) { cupstestppd_result_ = result; }

  void SetCupsUriHelperResult(int result) { urihelper_result_ = result; }

  void SetRunAsUserResult(int result) { runasuser_result_ = result; }

  void SetChownResult(int result) { chown_result_ = result; }

  void SetLpadminResult(int result) { lpadmin_result_ = result; }

  // Create some valid output for lpstat based on printerName
  void CreateValidLpstatOutput(const std::string& printerName) {
    const std::string lpstatOutput = base::StringPrintf(
        R"(printer %s is idle.
  Form mounted:
  Content types: any
  Printer types: unknown
  Description: %s
  Alerts: none
  Connection: direct
  Interface: %s/%s.ppd
  On fault: no alert
  After fault: continue
  Users allowed:
    (all)
  Forms allowed:
    (none)
  Banner required
  Charset sets:
    (none)
  Default pitch:
  Default page size:
  Default port settings:
  )",
        printerName.c_str(), printerName.c_str(),
        ppd_dir_.GetPath().value().c_str(), printerName.c_str());

    SetLpstatOutput(lpstatOutput);
  }

 private:
  std::string lpstat_output_;
  base::ScopedTempDir ppd_dir_;
  int cupstestppd_result_{0};
  int urihelper_result_{0};
  int runasuser_result_{0};
  int chown_result_{0};
  int lpadmin_result_{0};
};

TEST(CupsToolTest, RetrievePpd) {
  // Test the case where everything works as expected.

  // Create a fake lp tools object and configure it so we know what results we
  // should expect from CupsTool.
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();

  const std::string printerName("test-printer");
  lptools->CreateValidLpstatOutput(printerName);
  const base::FilePath& ppdDir = lptools->GetCupsPpdDir();
  const base::FilePath ppdPath = ppdDir.Append(printerName + ".ppd");

  // Create our ppd file that will get read by CupsTool
  const std::vector<uint8_t> ppdContents = {'T', 'e', 's', 't', ' ', 'd', 'a',
                                            't', 'a', ' ', 'i', 'n', ' ', 'P',
                                            'P', 'D', ' ', 'f', 'i', 'l', 'e'};
  ASSERT_TRUE(base::WriteFile(ppdPath, ppdContents));

  CupsTool cupsTool;
  cupsTool.SetLpToolsForTesting(std::move(lptools));

  std::vector<uint8_t> retrievedData = cupsTool.RetrievePpd(printerName);

  EXPECT_THAT(ppdContents, testing::ContainerEq(retrievedData));
}

TEST(CupsToolTest, EmptyFile) {
  // Test the case where the PPD file is empty.

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();

  const std::string printerName("test-printer");
  lptools->CreateValidLpstatOutput(printerName);
  const base::FilePath& ppdDir = lptools->GetCupsPpdDir();
  const base::FilePath ppdPath = ppdDir.Append(printerName + ".ppd");

  // Create an empty ppd file that will get read by CupsTool
  const std::string ppdContents("");
  ASSERT_TRUE(base::WriteFile(ppdPath, ppdContents));

  CupsTool cupsTool;
  cupsTool.SetLpToolsForTesting(std::move(lptools));
  const std::vector<uint8_t> retrievedData = cupsTool.RetrievePpd(printerName);

  EXPECT_TRUE(retrievedData.empty());
}

TEST(CupsToolTest, PpdFileDoesNotExist) {
  // Test the case where lpstat works as expected, but the PPD file does not
  // exist.

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();

  const std::string printerName("test-printer");
  lptools->CreateValidLpstatOutput(printerName);

  CupsTool cupsTool;
  cupsTool.SetLpToolsForTesting(std::move(lptools));

  const std::vector<uint8_t> retrievedPpd = cupsTool.RetrievePpd(printerName);

  EXPECT_TRUE(retrievedPpd.empty());
}

TEST(CupsToolTest, LpstatError) {
  // Test the case where there is an error running lpstat

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();

  // Since we have not specified the lpstat output, our fake object will return
  // an error from running lpstat.

  CupsTool cupsTool;
  cupsTool.SetLpToolsForTesting(std::move(lptools));

  const std::vector<uint8_t> retrievedPpd = cupsTool.RetrievePpd("printer");

  EXPECT_TRUE(retrievedPpd.empty());
}

TEST(CupsToolTest, LpstatNoPrinter) {
  // Test the case where lpstat runs but doesn't return the printer we are
  // looking for.

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();

  const std::string printerName("test-printer");
  lptools->SetLpstatOutput("lpstat data not containing our printer name");

  CupsTool cupsTool;
  cupsTool.SetLpToolsForTesting(std::move(lptools));

  const std::vector<uint8_t> retrievedPpd = cupsTool.RetrievePpd(printerName);

  EXPECT_TRUE(retrievedPpd.empty());
}

TEST(CupsToolTest, InvalidPPDTooSmall) {
  std::vector<uint8_t> empty_ppd;

  CupsTool cups;
  EXPECT_EQ(
      cups.AddManuallyConfiguredPrinter("test", "ipp://", "en", empty_ppd),
      CupsResult::CUPS_INVALID_PPD);
}

TEST(CupsToolTest, InvalidPPDBadGzip) {
  // Make the PPD look like it's gzipped.
  std::vector<uint8_t> bad_ppd(kMinimalPPDContent.begin(),
                               kMinimalPPDContent.end());
  bad_ppd[0] = 0x1f;
  bad_ppd[1] = 0x8b;

  CupsTool cups;
  EXPECT_EQ(cups.AddManuallyConfiguredPrinter("test", "ipp://", "en", bad_ppd),
            CupsResult::CUPS_INVALID_PPD);
}

TEST(CupsToolTest, InvalidPPDBadContents) {
  // Corrupt a valid PPD so it won't validate.
  std::vector<uint8_t> bad_ppd(kMinimalPPDContent.begin(),
                               kMinimalPPDContent.end());
  bad_ppd[0] = 'X';
  bad_ppd[1] = 'Y';
  bad_ppd[2] = 'Z';

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsTestPPDResult(4);  // Typical failure exit code.

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddManuallyConfiguredPrinter("test", "ipp://", "en", bad_ppd),
            CupsResult::CUPS_INVALID_PPD);
}

TEST(CupsToolTest, ManualMissingURI) {
  std::vector<uint8_t> good_ppd(kMinimalPPDContent.begin(),
                                kMinimalPPDContent.end());

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsTestPPDResult(0);  // Successful validation.

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddManuallyConfiguredPrinter("test", "", "en", good_ppd),
            CupsResult::CUPS_BAD_URI);
}

TEST(CupsToolTest, ManualMissingName) {
  std::vector<uint8_t> good_ppd(kMinimalPPDContent.begin(),
                                kMinimalPPDContent.end());

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsTestPPDResult(0);    // Successful validation.
  lptools->SetCupsUriHelperResult(0);  // URI validated.

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddManuallyConfiguredPrinter(
                "", "ipp://127.0.0.1:631/ipp/print", "en", good_ppd),
            CupsResult::CUPS_FATAL);
}

TEST(CupsToolTest, ManualUnknownError) {
  std::vector<uint8_t> good_ppd(kMinimalPPDContent.begin(),
                                kMinimalPPDContent.end());

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsTestPPDResult(0);    // Successful validation.
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(1);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddManuallyConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en", good_ppd),
            CupsResult::CUPS_LPADMIN_FAILURE);
}

TEST(CupsToolTest, ManualInvalidPpdDuringLpadmin) {
  std::vector<uint8_t> good_ppd(kMinimalPPDContent.begin(),
                                kMinimalPPDContent.end());

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsTestPPDResult(0);    // Successful validation.
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(5);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddManuallyConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en", good_ppd),
            CupsResult::CUPS_INVALID_PPD);
}

TEST(CupsToolTest, ManualNotAutoConf) {
  std::vector<uint8_t> good_ppd(kMinimalPPDContent.begin(),
                                kMinimalPPDContent.end());

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsTestPPDResult(0);    // Successful validation.
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(9);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddManuallyConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en", good_ppd),
            CupsResult::CUPS_FATAL);
}

TEST(CupsToolTest, ManualUnhandledError) {
  std::vector<uint8_t> good_ppd(kMinimalPPDContent.begin(),
                                kMinimalPPDContent.end());

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsTestPPDResult(0);    // Successful validation.
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(100);      // Error code without CUPS equivalent.

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddManuallyConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en", good_ppd),
            CupsResult::CUPS_FATAL);
}

TEST(CupsToolTest, AutoMissingURI) {
  CupsTool cups;
  EXPECT_EQ(cups.AddAutoConfiguredPrinter("test", "", "en"),
            CupsResult::CUPS_FATAL);
}

TEST(CupsToolTest, AutoMissingName) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(
      cups.AddAutoConfiguredPrinter("", "ipp://127.0.0.1:631/ipp/print", "en"),
      CupsResult::CUPS_FATAL);
}

TEST(CupsToolTest, AutoUnreasonableUri) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(-1);  // Unreasonable URI.

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(
      cups.AddAutoConfiguredPrinter("", "ipp://127.0.0.1:631/ipp/print", "en"),
      CupsResult::CUPS_BAD_URI);
}

TEST(CupsToolTest, AddAutoConfiguredPrinter) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_SUCCESS);
}

TEST(CupsToolTest, AutoUnknwonError) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(1);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_AUTOCONF_FAILURE);
}

TEST(CupsToolTest, AutoFatalError) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(2);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_FATAL);
}

TEST(CupsToolTest, AutoIoError) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(3);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_IO_ERROR);
}

TEST(CupsToolTest, AutoMemoryAllocError) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(4);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_MEMORY_ALLOC_ERROR);
}

TEST(CupsToolTest, AutoInvalidPpd) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(5);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_FATAL);
}

TEST(CupsToolTest, AutoServerUnreachable) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(6);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_FATAL);
}

TEST(CupsToolTest, AutoPrinterUnreachable) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(7);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_PRINTER_UNREACHABLE);
}

TEST(CupsToolTest, AutoPrinterWrongResponse) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(8);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_PRINTER_WRONG_RESPONSE);
}

TEST(CupsToolTest, AutoPrinterNotAutoConf) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetCupsUriHelperResult(0);  // URI validated.
  lptools->SetLpadminResult(9);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  EXPECT_EQ(cups.AddAutoConfiguredPrinter(
                "test", "ipp://127.0.0.1:631/ipp/print", "en"),
            CupsResult::CUPS_PRINTER_NOT_AUTOCONF);
}

TEST(CupsToolTest, FoomaticPPD) {
  // Make the PPD look like it has a foomatic-rip filter.
  constexpr base::StringPiece kFoomaticLine(
      R"foo(*cupsFilter: "application/vnd.cups-pdf 0 foomatic-rip")foo");
  std::vector<uint8_t> foomatic_ppd(kMinimalPPDContent.begin(),
                                    kMinimalPPDContent.end());
  std::copy(kFoomaticLine.begin(), kFoomaticLine.end(),
            std::back_inserter(foomatic_ppd));

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetRunAsUserResult(0);
  lptools->SetChownResult(0);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));
  EXPECT_EQ(
      cups.AddManuallyConfiguredPrinter("test", "ipp://", "en", foomatic_ppd),
      CupsResult::CUPS_SUCCESS);
}

TEST(CupsToolTest, FoomaticError) {
  // Make the PPD look like it has a foomatic-rip filter.
  constexpr base::StringPiece kFoomaticLine(
      R"foo(*cupsFilter: "application/vnd.cups-pdf 0 foomatic-rip")foo");
  std::vector<uint8_t> foomatic_ppd(kMinimalPPDContent.begin(),
                                    kMinimalPPDContent.end());
  std::copy(kFoomaticLine.begin(), kFoomaticLine.end(),
            std::back_inserter(foomatic_ppd));

  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();
  lptools->SetRunAsUserResult(0);
  lptools->SetChownResult(-1);

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));
  EXPECT_EQ(
      cups.AddManuallyConfiguredPrinter("test", "ipp://", "en", foomatic_ppd),
      CupsResult::CUPS_INVALID_PPD);
}

TEST(CupsToolTest, RemovePrinter) {
  std::unique_ptr<FakeLpTools> lptools = std::make_unique<FakeLpTools>();

  CupsTool cups;
  cups.SetLpToolsForTesting(std::move(lptools));

  // Our FakeLpTools always returns 0 for lpadmin calls, so we expect this to
  // pass.
  EXPECT_EQ(cups.RemovePrinter("printer-name"), true);
}

}  // namespace debugd
