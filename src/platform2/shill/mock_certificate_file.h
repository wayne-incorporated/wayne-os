// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_CERTIFICATE_FILE_H_
#define SHILL_MOCK_CERTIFICATE_FILE_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/certificate_file.h"

namespace shill {

class MockCertificateFile : public CertificateFile {
 public:
  MockCertificateFile();
  MockCertificateFile(const MockCertificateFile&) = delete;
  MockCertificateFile& operator=(const MockCertificateFile&) = delete;

  ~MockCertificateFile() override;

  MOCK_METHOD(base::FilePath,
              CreatePEMFromStrings,
              (const std::vector<std::string>&),
              (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_CERTIFICATE_FILE_H_
