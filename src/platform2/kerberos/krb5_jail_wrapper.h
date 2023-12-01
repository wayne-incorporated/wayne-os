// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_KRB5_JAIL_WRAPPER_H_
#define KERBEROS_KRB5_JAIL_WRAPPER_H_

#include <memory>
#include <string>
#include <utility>

#include <libminijail.h>
#include <scoped_minijail.h>

#include "kerberos/krb5_interface.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace base {
class FilePath;
}

namespace kerberos {

// Wraps all calls to a Krb5Interface in a minijail that changes the user to
// kerberosd-exec.
class Krb5JailWrapper : public Krb5Interface {
 public:
  explicit Krb5JailWrapper(std::unique_ptr<Krb5Interface> krb5);
  Krb5JailWrapper(const Krb5JailWrapper&) = delete;
  Krb5JailWrapper& operator=(const Krb5JailWrapper&) = delete;

  ~Krb5JailWrapper() override;

  // Krb5Interface:
  ErrorType AcquireTgt(const std::string& principal_name,
                       const std::string& password,
                       const base::FilePath& krb5cc_path,
                       const base::FilePath& krb5conf_path) override;

  // Krb5Interface:
  ErrorType RenewTgt(const std::string& principal_name,
                     const base::FilePath& krb5cc_path,
                     const base::FilePath& krb5conf_path) override;

  // Krb5Interface:
  ErrorType GetTgtStatus(const base::FilePath& krb5cc_path,
                         TgtStatus* status) override;

  // Krb5Interface:
  ErrorType ValidateConfig(const std::string& krb5conf,
                           ConfigErrorInfo* error_info) override;

  // If |disabled|, will not setuid to kerberosd-exec. This is needed in some
  // environments where setuid is not permitted.
  static void DisableChangeUserForTesting(bool disabled);

 private:
  // Inner interface where calls are forwarded to after they've been jailed.
  std::unique_ptr<Krb5Interface> krb5_;
};

}  // namespace kerberos

#endif  // KERBEROS_KRB5_JAIL_WRAPPER_H_
