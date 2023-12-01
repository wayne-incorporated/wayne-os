// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/fake_krb5_interface.h"

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <krb5.h>

namespace kerberos {
namespace {

// Fake Kerberos credential cache.
constexpr char kFakeKrb5cc[] = "I'm authenticated, trust me!";

void WriteFakeTgt(const base::FilePath& krb5cc_path) {
  const int size = strlen(kFakeKrb5cc);
  CHECK(base::WriteFile(krb5cc_path, kFakeKrb5cc, strlen(kFakeKrb5cc)) == size);
}

}  // namespace

FakeKrb5Interface::FakeKrb5Interface() = default;

FakeKrb5Interface::~FakeKrb5Interface() = default;

ErrorType FakeKrb5Interface::AcquireTgt(const std::string& principal_name,
                                        const std::string& password,
                                        const base::FilePath& krb5cc_path,
                                        const base::FilePath& krb5conf_path) {
  acquire_tgt_call_count_++;
  if (password.empty())
    return ERROR_BAD_PASSWORD;

  if (!expected_password_.empty() && password != expected_password_)
    return ERROR_BAD_PASSWORD;

  WriteFakeTgt(krb5cc_path);
  return acquire_tgt_error_;
}

ErrorType FakeKrb5Interface::RenewTgt(const std::string& principal_name,
                                      const base::FilePath& krb5cc_path,
                                      const base::FilePath& krb5conf_path) {
  renew_tgt_call_count_++;
  WriteFakeTgt(krb5cc_path);
  return renew_tgt_error_;
}

ErrorType FakeKrb5Interface::GetTgtStatus(const base::FilePath& krb5cc_path,
                                          TgtStatus* status) {
  get_tgt_status_call_count_++;
  *status = tgt_status_;
  return get_tgt_status_error_;
}

ErrorType FakeKrb5Interface::ValidateConfig(const std::string& krb5conf,
                                            ConfigErrorInfo* error_info) {
  validate_config_call_count_++;
  *error_info = error_info_;
  return validate_config_error_;
}

}  // namespace kerberos
