// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <libarc-attestation/lib/interface.h>

#include <base/logging.h>

namespace arc_attestation {

AndroidStatus ProvisionDkCert() {
  LOG(FATAL) << "Not implemented.";
  return AndroidStatus();
}

AndroidStatus GetDkCertChain(std::vector<std::string>& cert_out) {
  LOG(FATAL) << "Not implemented.";
  return AndroidStatus();
}

AndroidStatus SignWithP256Dk(const std::string& input, std::string& signature) {
  LOG(FATAL) << "Not implemented.";
  return AndroidStatus();
}

AndroidStatus QuoteCrOSBlob(const std::string& challenge, std::string& output) {
  LOG(FATAL) << "Not implemented.";
  return AndroidStatus();
}

}  // namespace arc_attestation
