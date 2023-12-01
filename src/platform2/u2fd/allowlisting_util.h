// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_ALLOWLISTING_UTIL_H_
#define U2FD_ALLOWLISTING_UTIL_H_

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <attestation/proto_bindings/interface.pb.h>
#include <policy/libpolicy.h>

namespace u2f {

// Utility to append allowlisting data to a U2F_REGISTER response.
class AllowlistingUtil {
 public:
  // Creates a new utility, which will make use of the specified function to
  // retrieve a certified copy of the G2F certificate.
  AllowlistingUtil(
      std::function<std::optional<attestation::GetCertifiedNvIndexReply>(int)>
          get_certified_g2f_cert);

  virtual ~AllowlistingUtil() = default;

  // Appends allowlisting data to the specified certificate. Returns true on
  // success. On failure, returns false, and does not modify |cert|.
  virtual bool AppendDataToCert(std::vector<uint8_t>* cert);

  // To use a mock policy provider in tests.
  void SetPolicyProviderForTest(
      std::unique_ptr<policy::PolicyProvider> provider);

 private:
  // Retrieves the 'certified' attestation data from attestationd, and writes
  // the relevant allowlisting data to |cert_prefix| and |signature|. Returns
  // true on success.
  bool GetCertifiedAttestationCert(int orig_cert_size,
                                   std::vector<uint8_t>* cert_prefix,
                                   std::vector<uint8_t>* signature);

  // Returns the device 'Directory API ID', or nullopt on failure.
  std::optional<std::string> GetDeviceId();

  std::function<std::optional<attestation::GetCertifiedNvIndexReply>(int)>
      get_certified_g2f_cert_;

  std::unique_ptr<policy::PolicyProvider> policy_provider_;
};

}  // namespace u2f

#endif  // U2FD_ALLOWLISTING_UTIL_H_
