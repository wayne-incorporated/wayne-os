// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CERTIFICATE_FILE_H_
#define SHILL_CERTIFICATE_FILE_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/string_piece_forward.h>

namespace shill {

// Creates a scoped temporary file containing the DER or PEM
// equivalent of an input PEM-format certificate.  When this object
// is destroyed (or a different file is created from the same object)
// the previous temporary file is destroyed.
class CertificateFile {
 public:
  CertificateFile();
  CertificateFile(const CertificateFile&) = delete;
  CertificateFile& operator=(const CertificateFile&) = delete;

  virtual ~CertificateFile();

  // Write out a PEM file from an input vector of strings in PEM format.
  // Returns an empty path on failure.
  virtual base::FilePath CreatePEMFromStrings(
      const std::vector<std::string>& pem_contents);

  // Setters.
  void set_root_directory(const base::FilePath& root_directory) {
    root_directory_ = root_directory;
  }

  // Removes the non-empty lines between the PEM header and footer lines
  // in |pem_data|, removing all leading and trailing whitespace.  If
  // neither a header nor a footer appears, assume they were not provided
  // by the caller and return all non-empty lines.  Returns the resulting
  // inner portion on success, or an empty string otherwise.
  static std::string ExtractHexData(const base::StringPiece pem_data);

 private:
  friend class CertificateFileTest;

  // Default root directory to create output files.
  static const char kDefaultRootDirectory[];

  // Start and end strings for a PEM certificate.
  static const char kPEMHeader[];
  static const char kPEMFooter[];

  // Creates a temporary output file with |output_data| in it.  Returns the
  // path the output data on success or an empty FilePath otherwise.
  base::FilePath WriteFile(const std::string& output_data);

  // Root directory in which output new files will be created.
  base::FilePath root_directory_;

  // File path for the created temporary file.
  base::FilePath output_file_;
};

}  // namespace shill

#endif  // SHILL_CERTIFICATE_FILE_H_
