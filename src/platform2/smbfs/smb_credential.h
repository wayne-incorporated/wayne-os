// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_SMB_CREDENTIAL_H_
#define SMBFS_SMB_CREDENTIAL_H_

#include <memory>
#include <string>
#include <utility>

#include <libpasswordprovider/password.h>

namespace smbfs {

struct SmbCredential {
  std::string workgroup;
  std::string username;
  std::unique_ptr<password_provider::Password> password;

  SmbCredential(const std::string& workgroup,
                const std::string& username,
                std::unique_ptr<password_provider::Password> password)
      : workgroup(workgroup),
        username(username),
        password(std::move(password)) {}

  SmbCredential() = delete;
  SmbCredential(const SmbCredential&) = delete;
  SmbCredential& operator=(const SmbCredential&) = delete;
};

}  // namespace smbfs

#endif  // SMBFS_SMB_CREDENTIAL_H_
