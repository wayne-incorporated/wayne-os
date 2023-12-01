// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_FAKE_KRB5_INTERFACE_H_
#define KERBEROS_FAKE_KRB5_INTERFACE_H_

#include <string>
#include <utility>

#include <base/compiler_specific.h>

#include "kerberos/krb5_interface.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace base {
class FilePath;
}

namespace kerberos {

class FakeKrb5Interface : public Krb5Interface {
 public:
  FakeKrb5Interface();
  FakeKrb5Interface(const FakeKrb5Interface&) = delete;
  FakeKrb5Interface& operator=(const FakeKrb5Interface&) = delete;

  ~FakeKrb5Interface() override;

  // Krb5Interface:
  // Returns ERROR_BAD_PASSWORD if |password| is empty. Otherwise, returns
  // |acquire_tgt_error_| and writes a file at |krb5cc_path|.
  ErrorType AcquireTgt(const std::string& principal_name,
                       const std::string& password,
                       const base::FilePath& krb5cc_path,
                       const base::FilePath& krb5conf_path) override;

  // Krb5Interface:
  // Returns |renew_tgt_error_|.
  ErrorType RenewTgt(const std::string& principal_name,
                     const base::FilePath& krb5cc_path,
                     const base::FilePath& krb5conf_path) override;

  // Krb5Interface:
  // Returns |get_tgt_status_error_|.
  ErrorType GetTgtStatus(const base::FilePath& krb5cc_path,
                         TgtStatus* status) override;

  // Krb5Interface:
  ErrorType ValidateConfig(const std::string& krb5conf,
                           ConfigErrorInfo* error_info) override;

  //
  // Testing interface.
  //

  // Sets the error that AcquireTgt() returns.
  void set_acquire_tgt_error(ErrorType error) { acquire_tgt_error_ = error; }

  // Sets the error that RenewTgt() returns.
  void set_renew_tgt_error(ErrorType error) { renew_tgt_error_ = error; }

  // Sets the error that GetTgtStatus() returns.
  void set_get_tgt_status_error(ErrorType error) {
    get_tgt_status_error_ = error;
  }

  // Sets the error that ValidateConfig() returns.
  void set_validate_config_error(ErrorType error) {
    validate_config_error_ = error;
  }

  // Sets the expected password for AcquireTgt. If not empty, ERROR_BAD_PASSWORD
  // is returned on mismatch.
  void set_expected_password(const std::string& expected_password) {
    expected_password_ = expected_password;
  }

  // Sets the status that GetTgtStatus returns.
  void set_tgt_status(TgtStatus status) { tgt_status_ = std::move(status); }

  // Sets the error info that ValidateConfig returns.
  void set_config_error_info(ConfigErrorInfo error_info) {
    error_info_ = std::move(error_info);
  }

  // Call counts for the corresponding methods.
  int acquire_tgt_call_count() const { return acquire_tgt_call_count_; }
  int renew_tgt_call_count() const { return renew_tgt_call_count_; }
  int get_get_tgt_status_call_count() const {
    return get_tgt_status_call_count_;
  }
  int get_validate_config_call_count_() const {
    return validate_config_call_count_;
  }

 private:
  std::string expected_password_;

  ErrorType acquire_tgt_error_ = ERROR_NONE;
  ErrorType renew_tgt_error_ = ERROR_NONE;
  ErrorType get_tgt_status_error_ = ERROR_NONE;
  ErrorType validate_config_error_ = ERROR_NONE;

  int acquire_tgt_call_count_ = 0;
  int renew_tgt_call_count_ = 0;
  int get_tgt_status_call_count_ = 0;
  int validate_config_call_count_ = 0;

  TgtStatus tgt_status_;
  ConfigErrorInfo error_info_;
};

}  // namespace kerberos

#endif  // KERBEROS_FAKE_KRB5_INTERFACE_H_
