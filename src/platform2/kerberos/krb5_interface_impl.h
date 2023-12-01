// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_KRB5_INTERFACE_IMPL_H_
#define KERBEROS_KRB5_INTERFACE_IMPL_H_

#include <string>

#include "kerberos/config_parser.h"
#include "kerberos/krb5_interface.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace base {
class FilePath;
}

namespace kerberos {

class Krb5InterfaceImpl : public Krb5Interface {
 public:
  Krb5InterfaceImpl();
  Krb5InterfaceImpl(const Krb5InterfaceImpl&) = delete;
  Krb5InterfaceImpl& operator=(const Krb5InterfaceImpl&) = delete;

  ~Krb5InterfaceImpl() override;

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

 private:
  ConfigParser config_parser_;
};

}  // namespace kerberos

#endif  // KERBEROS_KRB5_INTERFACE_IMPL_H_
