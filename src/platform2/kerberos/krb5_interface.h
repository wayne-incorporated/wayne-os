// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_KRB5_INTERFACE_H_
#define KERBEROS_KRB5_INTERFACE_H_

#include <string>

#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace base {
class FilePath;
}

namespace kerberos {

class Krb5Interface {
 public:
  Krb5Interface() = default;
  Krb5Interface(const Krb5Interface&) = delete;
  Krb5Interface& operator=(const Krb5Interface&) = delete;

  virtual ~Krb5Interface() = default;

  // Ticket-granting-ticket status, see GetTgtStatus().
  struct TgtStatus {
    // For how many seconds the ticket is still valid.
    int64_t validity_seconds = 0;

    // For how many seconds the ticket can be renewed.
    int64_t renewal_seconds = 0;

    constexpr TgtStatus() = default;

    constexpr TgtStatus(int64_t validity_seconds, int64_t renewal_seconds)
        : validity_seconds(validity_seconds),
          renewal_seconds(renewal_seconds) {}

    bool operator==(const TgtStatus& other) const {
      return validity_seconds == other.validity_seconds &&
             renewal_seconds == other.renewal_seconds;
    }
    bool operator!=(const TgtStatus& other) const { return !(*this == other); }
  };

  // Gets a Kerberos ticket-granting-ticket for the given |principal_name|
  // (user@REALM.COM). |password| is the password for the Kerberos account.
  // |krb5cc_path| is the file path where the Kerberos credential cache (i.e.
  // the TGT) is written to. |krb5conf_path| is the path to a Kerberos
  // configuration file (krb5.conf).
  [[nodiscard]] virtual ErrorType AcquireTgt(
      const std::string& principal_name,
      const std::string& password,
      const base::FilePath& krb5cc_path,
      const base::FilePath& krb5conf_path) = 0;

  // Renews an existing Kerberos ticket-granting-ticket for the given
  // |principal_name| (user@REALM.COM). |krb5cc_path| is the file path of the
  // Kerberos credential cache. |krb5conf_path| is the path to a Kerberos
  // configuration file (krb5.conf).
  [[nodiscard]] virtual ErrorType RenewTgt(
      const std::string& principal_name,
      const base::FilePath& krb5cc_path,
      const base::FilePath& krb5conf_path) = 0;

  // Gets some stats about the ticket-granting-ticket in the credential cache
  // at |krb5cc_path|.
  [[nodiscard]] virtual ErrorType GetTgtStatus(
      const base::FilePath& krb5cc_path, TgtStatus* status) = 0;

  // Validates the Kerberos configuration data |krb5conf|. If the config has
  // syntax errors or uses non-allowlisted options, returns ERROR_BAD_CONFIG
  // and fills |error_info| with error information.
  [[nodiscard]] virtual ErrorType ValidateConfig(
      const std::string& krb5conf, ConfigErrorInfo* error_info) = 0;
};

}  // namespace kerberos

#endif  // KERBEROS_KRB5_INTERFACE_H_
