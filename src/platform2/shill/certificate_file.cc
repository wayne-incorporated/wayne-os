// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/certificate_file.h"

#include <sys/stat.h>

#include <string>
#include <vector>

#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCrypto;
}  // namespace Logging

const char CertificateFile::kDefaultRootDirectory[] =
    RUNDIR "/certificate_export";
const char CertificateFile::kPEMHeader[] = "-----BEGIN CERTIFICATE-----";
const char CertificateFile::kPEMFooter[] = "-----END CERTIFICATE-----";

CertificateFile::CertificateFile() : root_directory_(kDefaultRootDirectory) {
  SLOG(2) << __func__;
}

CertificateFile::~CertificateFile() {
  SLOG(2) << __func__;
  if (!output_file_.empty()) {
    base::DeleteFile(output_file_);
  }
}

base::FilePath CertificateFile::CreatePEMFromStrings(
    const std::vector<std::string>& pem_contents) {
  std::vector<std::string> pem_output;
  for (const auto& content : pem_contents) {
    const auto hex_data = ExtractHexData(content);
    if (hex_data.empty()) {
      return base::FilePath();
    }
    pem_output.push_back(base::StringPrintf("%s\n%s%s\n", kPEMHeader,
                                            hex_data.c_str(), kPEMFooter));
  }
  return WriteFile(base::JoinString(pem_output, ""));
}

// static
std::string CertificateFile::ExtractHexData(const base::StringPiece pem_data) {
  bool found_header = false;
  bool found_footer = false;
  const auto input_lines = base::SplitString(
      pem_data, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  std::vector<std::string> output_lines;
  for (const auto& input_line : input_lines) {
    std::string line;
    base::TrimWhitespaceASCII(input_line, base::TRIM_ALL, &line);
    if (base::StartsWith(line, kPEMHeader,
                         base::CompareCase::INSENSITIVE_ASCII)) {
      if (found_header) {
        LOG(ERROR) << "Found two PEM headers in a row.";
        return std::string();
      } else {
        found_header = true;
        output_lines.clear();
      }
    } else if (base::StartsWith(line, kPEMFooter,
                                base::CompareCase::INSENSITIVE_ASCII)) {
      if (!found_header) {
        LOG(ERROR) << "Found a PEM footer before header.";
        return std::string();
      } else {
        found_footer = true;
        break;
      }
    } else if (!line.empty()) {
      output_lines.push_back(line);
    }
  }
  if (found_header && !found_footer) {
    LOG(ERROR) << "Found PEM header but no footer.";
    return std::string();
  }
  DCHECK_EQ(found_header, found_footer);
  output_lines.push_back("");
  return base::JoinString(output_lines, "\n");
}

base::FilePath CertificateFile::WriteFile(const std::string& output_data) {
  if (!base::DirectoryExists(root_directory_)) {
    if (!base::CreateDirectory(root_directory_)) {
      LOG(ERROR) << "Unable to create parent directory  "
                 << root_directory_.value();
      return base::FilePath();
    }
    if (chmod(root_directory_.value().c_str(),
              S_IRWXU | S_IXGRP | S_IRGRP | S_IXOTH | S_IROTH)) {
      LOG(ERROR) << "Failed to set permissions on " << root_directory_.value();
      base::DeletePathRecursively(root_directory_);
      return base::FilePath();
    }
  }
  if (!output_file_.empty()) {
    base::DeleteFile(output_file_);
    output_file_ = base::FilePath();
  }

  base::FilePath output_file;
  if (!base::CreateTemporaryFileInDir(root_directory_, &output_file)) {
    LOG(ERROR) << "Unable to create output file.";
    return base::FilePath();
  }

  size_t written =
      base::WriteFile(output_file, output_data.c_str(), output_data.length());
  if (written != output_data.length()) {
    LOG(ERROR) << "Unable to write to output file.";
    return base::FilePath();
  }

  if (chmod(output_file.value().c_str(),
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) {
    LOG(ERROR) << "Failed to set permissions on " << output_file.value();
    base::DeleteFile(output_file);
    return base::FilePath();
  }
  output_file_ = output_file;
  return output_file_;
}

}  // namespace shill
