// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This provides some utility functions to do with chaps isolate support.

#include "chaps/isolate.h"

#include <grp.h>
#include <pwd.h>

#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>

using base::FilePath;
using brillo::SecureBlob;
using std::string;

namespace chaps {

namespace {

const char kIsolateFilePath[] = "/var/lib/chaps/isolates/";

}  // namespace

IsolateCredentialManager::IsolateCredentialManager() {}

IsolateCredentialManager::~IsolateCredentialManager() {}

bool IsolateCredentialManager::GetCurrentUserIsolateCredential(
    SecureBlob* isolate_credential) {
  CHECK(isolate_credential);

  const uid_t uid = getuid();
  long buf_len = sysconf(_SC_GETPW_R_SIZE_MAX);  // NOLINT(runtime/int)
  if (buf_len < 0)
    buf_len = 4096;
  passwd pwd_buf;
  passwd* pwd = nullptr;
  std::vector<char> buf(buf_len);
  if (getpwuid_r(uid, &pwd_buf, buf.data(), buf_len, &pwd) || !pwd) {
    PLOG(ERROR) << "Failed to get user information for current user.";
    return false;
  }

  return GetUserIsolateCredential(pwd->pw_name, isolate_credential);
}

bool IsolateCredentialManager::GetUserIsolateCredential(
    const string& user, SecureBlob* isolate_credential) {
  CHECK(isolate_credential);

  string credential_string;
  const FilePath credential_file = FilePath(kIsolateFilePath).Append(user);
  if (!base::PathExists(credential_file) ||
      !base::ReadFileToString(credential_file, &credential_string)) {
    LOG(INFO) << "Failed to find or read isolate credential for user " << user;
    return false;
  }
  const SecureBlob new_isolate_credential(credential_string);
  if (new_isolate_credential.size() != kIsolateCredentialBytes) {
    LOG(ERROR) << "Isolate credential invalid for user " << user;
    return false;
  }

  *isolate_credential = new_isolate_credential;
  return true;
}

bool IsolateCredentialManager::SaveIsolateCredential(
    const string& user, const SecureBlob& isolate_credential) {
  CHECK_EQ(kIsolateCredentialBytes, isolate_credential.size());

  // Look up user information.
  long buf_len = sysconf(_SC_GETPW_R_SIZE_MAX);  // NOLINT(runtime/int)
  if (buf_len < 0)
    buf_len = 4096;
  passwd pwd_buf;
  passwd* pwd = nullptr;
  std::vector<char> buf(buf_len);
  if (getpwnam_r(user.c_str(), &pwd_buf, buf.data(), buf_len, &pwd) || !pwd) {
    LOG(ERROR) << "Failed to get user information.";
    return false;
  }

  // Write the isolate credential file.
  const FilePath isolate_cred_file = FilePath(kIsolateFilePath).Append(user);
  int bytes_written =
      base::WriteFile(isolate_cred_file,
                      reinterpret_cast<const char*>(isolate_credential.data()),
                      kIsolateCredentialBytes);
  if (bytes_written != static_cast<int>(kIsolateCredentialBytes)) {
    LOG(ERROR) << "Failed to create isolate file for user " << user;
    return false;
  }

  // Change permissions to be readable by (and only by) the user.
  if (chmod(isolate_cred_file.value().c_str(), S_IRUSR)) {
    LOG(ERROR) << "Failed to change permissions of isolate file.";
    return false;
  }
  if (chown(isolate_cred_file.value().c_str(), pwd->pw_uid, pwd->pw_gid)) {
    LOG(ERROR) << "Failed to change ownership of isolate file.";
    return false;
  }

  return true;
}

}  // namespace chaps
