// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBARC_ATTESTATION_LIB_INTERFACE_H_
#define LIBARC_ATTESTATION_LIB_INTERFACE_H_

#include <string>
#include <vector>

#include <libarc-attestation/lib/export.h>

namespace arc_attestation {

class ARC_ATTESTATION_EXPORT AndroidStatus final {
 public:
  // These are error code specific to keymint, and they're to be kept in sync
  // with
  // hardware/interfaces/security/keymint/aidl/android/hardware/security/
  // keymint/ErrorCode.aidl
  // The codes that are used in this library is defined here, we duplicated the
  // code used from the Android codebase so as to prevent dependency from
  // Android code base which can complicate the build process for this library.
  enum class KeymintSpecificErrorCode { SECURE_HW_COMMUNICATION_FAILED = -49 };

  // These are error code used by Android's binder::Status class, and they're to
  // be kept in sync with frameworks/native/libs/binder/include/binder/Status.h
  // The codes that are used in this library is defined here, we duplicated the
  // code used from the Android codebase so as to prevent dependency from
  // Android code base which can complicate the build process for this library.
  enum class StatusCode { EX_SERVICE_SPECIFIC = -8, EX_NONE = 0 };

  AndroidStatus() = default;
  AndroidStatus(int32_t exception,
                int32_t error_code,
                const std::string& message)
      : exception_(exception), error_code_(error_code), message_(message) {}
  ~AndroidStatus() = default;

  int32_t get_exception() const { return exception_; }
  int32_t get_error_code() const { return error_code_; }
  std::string get_message() const { return message_; }

  // Returns true iff successful.
  bool is_ok() {
    return exception_ == static_cast<int32_t>(StatusCode::EX_NONE);
  }

  // Create an OK (successful) status.
  static AndroidStatus ok() { return AndroidStatus(); }

  // Create a status from a Keymint-specific error code.
  static AndroidStatus from_keymint_code(KeymintSpecificErrorCode code,
                                         const std::string& message = "") {
    return AndroidStatus(static_cast<int32_t>(StatusCode::EX_SERVICE_SPECIFIC),
                         static_cast<int32_t>(code), message);
  }

 private:
  int32_t exception_ = 0;
  int32_t error_code_ = 0;
  std::string message_;
};

// The following C-style APIs are not thread safe.

// ProvisionDkCert() will provision the Android Device Key.
AndroidStatus ARC_ATTESTATION_EXPORT ProvisionDkCert(bool blocking);

// GetDkCertChain() will retrieve the DK's certificate and its certificate
// chain.
AndroidStatus ARC_ATTESTATION_EXPORT
GetDkCertChain(std::vector<std::vector<uint8_t>>& cert_out);

// SignWithP256Dk will sign the specified data with the DK. The DK is an ECC
// with P256 curve.
AndroidStatus ARC_ATTESTATION_EXPORT SignWithP256Dk(
    const std::vector<uint8_t>& input, std::vector<uint8_t>& signature);

// QuoteCrOSBlob will provide the ChromeOS related blob so as to allow the
// server side to verify the client's version.
AndroidStatus ARC_ATTESTATION_EXPORT QuoteCrOSBlob(
    const std::vector<uint8_t>& challenge, std::vector<uint8_t>& output);

}  // namespace arc_attestation

#endif  // LIBARC_ATTESTATION_LIB_INTERFACE_H_
