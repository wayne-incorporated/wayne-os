// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Tool to manipulate CUPS.
#include "debugd/src/cups_tool.h"

#include <pwd.h>
#include <signal.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/environment.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/files/safe_fd.h>
#include <chromeos/dbus/debugd/dbus-constants.h>

#include "debugd/src/constants.h"
#include "debugd/src/process_with_output.h"
#include "debugd/src/sandboxed_process.h"

namespace debugd {

namespace {

constexpr char kPdfContent[] = R"(%PDF-1.0
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000052 00000 n 
0000000101 00000 n 
trailer<</Size 4/Root 1 0 R>>
startxref
147
%EOF)";

constexpr char kGzipCommand[] = "/bin/gzip";
constexpr char kFoomaticCommand[] = "/usr/bin/foomatic-rip";

constexpr char kLpadminUser[] = "lpadmin";
constexpr char kLpadminGroup[] = "lpadmin";

constexpr base::StringPiece kLpstatInterfaceLinePrefix("Interface: ");

// Minimum size of a plausible PPD.  Determined by gzipping a minimal PPD
// accepted by cupstestppd and rounding down.
constexpr size_t kMinimumPPDSize = 200;

// Runs cupstestppd on |ppd_content| returns the result code.  0 is the expected
// success code. Verify the foomatic command is valid if the PPD uses the
// foomatic-rip filter.
int TestPPD(const LpTools& lp_tools, const std::vector<uint8_t>& ppd_data) {
  if (ppd_data.size() < kMinimumPPDSize) {
    LOG(ERROR) << "PPD is too small";
    return 1;
  }
  std::vector<uint8_t> ppd_content = ppd_data;
  if (ppd_content[0] == 0x1f && ppd_content[1] == 0x8b) {  // gzip header
    std::string out;
    int ret = lp_tools.RunAsUser(kLpadminUser, kLpadminGroup, kGzipCommand, "",
                                 {"-cfd"}, &ppd_content, false, {}, &out);
    if (ret || out.empty()) {
      LOG(ERROR) << "gzip failed";
      return ret ? ret : 1;
    }
    ppd_content.assign(out.begin(), out.end());
  }
  int ret = lp_tools.CupsTestPpd(ppd_content);
  // Check if the foomatic-rip cups filter is present in the PPD file.
  constexpr uint8_t kFoomaticRip[] = "foomatic-rip\"";
  // Subtract 1 to exclude the null terminator.
  if (!ret && std::search(ppd_content.begin(), ppd_content.end(),
                          std::begin(kFoomaticRip),
                          std::end(kFoomaticRip) - 1) != ppd_content.end()) {
    base::ScopedTempDir tmp;
    if (!tmp.CreateUniqueTempDir()) {
      PLOG(ERROR) << "Could not create temporary directory";
      return 1;
    }
    base::FilePath ppd_file = tmp.GetPath().Append("ppd.ppd");
    if (!base::WriteFile(ppd_file, ppd_content)) {
      PLOG(ERROR) << "Could not write to file";
      return 1;
    }
    if (lp_tools.Chown(tmp.GetPath().MaybeAsASCII(),
                       getpwnam(kLpadminUser)->pw_uid, -1)) {
      PLOG(ERROR) << "Could not set directory ownership ("
                  << tmp.GetPath().MaybeAsASCII() << ")";
      return 1;
    }
    auto env = base::Environment::Create();
    env->SetVar("FOOMATIC_VERIFY_MODE", "true");
    env->SetVar("PATH", "/bin:/usr/bin:/usr/libexec/cups/filter");
    env->SetVar("PPD", ppd_file.MaybeAsASCII());
    const std::vector<uint8_t> kPdf(std::begin(kPdfContent),
                                    std::end(kPdfContent));
    ret = lp_tools.RunAsUser(
        kLpadminUser, kLpadminGroup, kFoomaticCommand, "",
        {"1" /*jobID*/, "chronos" /*user*/, "Untitled" /*title*/,
         "1" /*copies*/, "" /*options*/},
        &kPdf);
  }
  return ret;
}

// Translates a return code from lpadmin to a CupsResult value.
CupsResult LpadminReturnCodeToCupsResult(int return_code, bool autoconf) {
  if (return_code != 0)
    LOG(WARNING) << "lpadmin failed: " << return_code;

  switch (return_code) {
    case 0:  // OK
      return CupsResult::CUPS_SUCCESS;
    case 1:  // UNKNOWN_ERROR
      return (autoconf ? CupsResult::CUPS_AUTOCONF_FAILURE
                       : CupsResult::CUPS_LPADMIN_FAILURE);
    case 2:  // WRONG_PARAMETERS
      return CupsResult::CUPS_FATAL;
    case 3:  // IO_ERROR
      return CupsResult::CUPS_IO_ERROR;
    case 4:  // MEMORY_ALLOC_ERROR
      return CupsResult::CUPS_MEMORY_ALLOC_ERROR;
    case 5:  // INVALID_PPD_FILE
      return (autoconf ? CupsResult::CUPS_FATAL : CupsResult::CUPS_INVALID_PPD);
    case 6:  // SERVER_UNREACHABLE
      return CupsResult::CUPS_FATAL;
    case 7:  // PRINTER_UNREACHABLE
      return CupsResult::CUPS_PRINTER_UNREACHABLE;
    case 8:  // PRINTER_WRONG_RESPONSE
      return CupsResult::CUPS_PRINTER_WRONG_RESPONSE;
    case 9:  // PRINTER_NOT_AUTOCONFIGURABLE
      return (autoconf ? CupsResult::CUPS_PRINTER_NOT_AUTOCONF
                       : CupsResult::CUPS_FATAL);
    default:
      // unexpected return code
      return CupsResult::CUPS_FATAL;
  }
}

// Checks whether the scheme for the given |uri| is one of the required schemes
// for IPP Everywhere.
bool IppEverywhereURI(const std::string& uri) {
  static const char* const kValidSchemes[] = {"ipp://", "ipps://", "ippusb://"};
  for (const char* scheme : kValidSchemes) {
    if (base::StartsWith(uri, scheme, base::CompareCase::INSENSITIVE_ASCII))
      return true;
  }

  return false;
}

}  // namespace

void CupsTool::SetLpToolsForTesting(std::unique_ptr<LpTools> lptools) {
  lp_tools_ = std::move(lptools);
}

// Invokes lpadmin with arguments to configure a new printer using '-m
// everywhere'.
int32_t CupsTool::AddAutoConfiguredPrinter(const std::string& name,
                                           const std::string& uri,
                                           const std::string& language) {
  if (!IppEverywhereURI(uri)) {
    LOG(WARNING) << "IPP, IPPS or IPPUSB required for IPP Everywhere: " << uri;
    return CupsResult::CUPS_FATAL;
  }

  if (!CupsTool::UriSeemsReasonable(uri)) {
    LOG(WARNING) << "Invalid URI: " << uri;
    return CupsResult::CUPS_BAD_URI;
  }

  if (name.empty()) {
    LOG(WARNING) << "Missing printer name";
    return CupsResult::CUPS_FATAL;
  }

  const bool is_ippusb =
      base::StartsWith(uri, "ippusb://", base::CompareCase::INSENSITIVE_ASCII);
  LOG(INFO) << "Adding auto-configured printer " << name << " at " << uri
            << " with language " << language;
  const int result =
      lp_tools_->Lpadmin({"-v", uri, "-p", name, "-m", "everywhere", "-E"},
                         is_ippusb, {{"CROS_CUPS_LANGUAGE", language}});
  return LpadminReturnCodeToCupsResult(result, /*autoconf=*/true);
}

int32_t CupsTool::AddManuallyConfiguredPrinter(
    const std::string& name,
    const std::string& uri,
    const std::string& language,
    const std::vector<uint8_t>& ppd_contents) {
  if (TestPPD(*lp_tools_.get(), ppd_contents) != EXIT_SUCCESS) {
    LOG(ERROR) << "PPD failed validation";
    return CupsResult::CUPS_INVALID_PPD;
  }

  if (!CupsTool::UriSeemsReasonable(uri)) {
    LOG(WARNING) << "Invalid URI: " << uri;
    return CupsResult::CUPS_BAD_URI;
  }

  if (name.empty()) {
    LOG(WARNING) << "Missing printer name";
    return CupsResult::CUPS_FATAL;
  }

  LOG(INFO) << "Adding manual printer " << name << " at " << uri
            << " with language " << language;
  const int result =
      lp_tools_->Lpadmin({"-v", uri, "-p", name, "-P", "-", "-E"}, false,
                         {{"CROS_CUPS_LANGUAGE", language}}, &ppd_contents);
  return LpadminReturnCodeToCupsResult(result, /*autoconf=*/false);
}

// Invokes lpadmin with -x to delete a printer.
bool CupsTool::RemovePrinter(const std::string& name) {
  LOG(INFO) << "Removing printer " << name;
  return lp_tools_->Lpadmin({"-x", name}) == EXIT_SUCCESS;
}

std::vector<uint8_t> CupsTool::RetrievePpd(const std::string& name) {
  LOG(INFO) << "Retrieve PPD for printer " << name;
  std::string lpstatOutput;
  if ((lp_tools_->Lpstat({"-l", "-p", name.c_str()}, &lpstatOutput) !=
       EXIT_SUCCESS) ||
      lpstatOutput.empty()) {
    LOG(ERROR) << "Unable to perform lpstat for " << name;
    return {};
  }

  // Parse output from lpstat and look for the Interface line, which contains
  // the path to the PPD
  std::vector<std::string> lines = base::SplitString(
      lpstatOutput, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto& line : lines) {
    if (base::StartsWith(line, kLpstatInterfaceLinePrefix)) {
      std::string pathToPpd(line.substr(kLpstatInterfaceLinePrefix.length()));
      base::TrimWhitespaceASCII(pathToPpd, base::TRIM_ALL, &pathToPpd);
      const base::FilePath filePath(pathToPpd);

      // Get just the filename from the lpstat path and build a new path with
      // the known cups PPD directory.  Doing it this way for security reasons -
      // making sure we use a known good directory and not trusting the output
      // from lpstat.
      const base::FilePath ppdPath =
          lp_tools_->GetCupsPpdDir().Append(filePath.BaseName());

      // Use SafeFD to read the file - more secure than just using file utils.
      auto [ppdFd, err1] = brillo::SafeFD::Root().first.OpenExistingFile(
          ppdPath, O_RDONLY | O_CLOEXEC);
      if (brillo::SafeFD::IsError(err1)) {
        LOG(ERROR) << "Unable to open " << ppdPath << ": "
                   << static_cast<int>(err1);
        return {};
      }

      auto [contents, err2] = ppdFd.ReadContents();
      if (brillo::SafeFD::IsError(err2)) {
        LOG(ERROR) << "Unable to read contents of " << ppdPath << ": "
                   << static_cast<int>(err2);
        return {};
      }

      if (contents.size() == 0) {
        LOG(ERROR) << "Empty PPD: " << ppdPath;
        return {};
      }

      return {contents.begin(), contents.end()};
    }
  }

  return {};
}

// Runs lpstat -l -r -v -a -p -o.
// -l shows a long listing of printers, classes, or jobs.
// -r shows whether the CUPS server is running.
// -v [printer(s)] shows the printers and what device they are attached to. If
//   no printers are specified then all printers are listed.
// -a [printer(s)] shows the accepting state of printer queues. If no printers
//   are specified then all printers are listed.
// -p [printer(s)] shows the printers and whether they are enabled for printing.
//   If no printers are specified then all printers are listed.
// -o [destination(s)] shows the jobs queued on the specified destinations.
//   If no destinations are specified all jobs are shown.
bool CupsTool::RunLpstat(std::string* output) {
  return lp_tools_->Lpstat({"-l", "-r", "-v", "-a", "-p", "-o"}, output) ==
         EXIT_SUCCESS;
}

// Tests a URI's visual similarity with an HTTP URI.
// This function observes a subset of RFC 3986 but is _not_ meant to serve
// as a general-purpose URI validator (prefer Chromium's GURL).
bool CupsTool::UriSeemsReasonable(const std::string& uri) {
  if (uri.empty()) {
    return false;
  }

  int cups_uri_helper_exit_code = lp_tools_->CupsUriHelper(uri);
  if (cups_uri_helper_exit_code == 0) {
    return true;
  }
  return false;
}

}  // namespace debugd
