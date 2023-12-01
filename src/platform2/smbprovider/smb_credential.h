// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_SMB_CREDENTIAL_H_
#define SMBPROVIDER_SMB_CREDENTIAL_H_

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <libpasswordprovider/password.h>

namespace smbprovider {

struct SmbCredential {
  std::string workgroup;
  std::string username;
  std::unique_ptr<password_provider::Password> password;
  base::FilePath password_file;

  SmbCredential() = default;
  SmbCredential(const std::string& workgroup,
                const std::string& username,
                std::unique_ptr<password_provider::Password> password,
                const base::FilePath& password_file = {})
      : workgroup(workgroup),
        username(username),
        password(std::move(password)),
        password_file(password_file) {}

  SmbCredential(SmbCredential&& other) = default;
  SmbCredential(const SmbCredential&) = delete;
  SmbCredential& operator=(const SmbCredential&) = delete;

  SmbCredential& operator=(SmbCredential&& other) = default;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_SMB_CREDENTIAL_H_
