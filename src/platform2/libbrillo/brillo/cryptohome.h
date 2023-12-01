
// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_CRYPTOHOME_H_
#define LIBBRILLO_BRILLO_CRYPTOHOME_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/no_destructor.h>
#include <base/types/strong_alias.h>
#include <brillo/brillo_export.h>
#include <brillo/secure_blob.h>

namespace brillo {
namespace cryptohome {
namespace home {

// Types that define the types of "username" values that cryptohome uses to
// manage user identities. This corresponds to the identifier that a user uses
// to log into a machine, which will usually look something like an email
// address. However, it is important to note that to cryptohome these are just
// opaque identifiers.
//
// There is also an additional related type of "obfuscated username". This is a
// sanitized version of the username which obfuscates any PII in the base
// username and is the name which will be used in actual paths (e.g. the user's
// homedir).
//
// Fundamentally both of these values are just strings, but by defining strong
// alias types for them we make it much more difficult to accidentally use the
// wrong type in the wrong context (e.g. passing the real username into a
// function expecting the obfuscated one).
using Username = base::StrongAlias<class UsernameTag, std::string>;
using ObfuscatedUsername =
    base::StrongAlias<class ObfuscatedUsernameTag, std::string>;

// The standard username for a guest user.
BRILLO_EXPORT const Username& GetGuestUsername();

// Returns the common prefix under which the mount points for user homes are
// created.
BRILLO_EXPORT base::FilePath GetUserPathPrefix();

// Returns the common prefix under which the mount points for root homes are
// created.
BRILLO_EXPORT base::FilePath GetRootPathPrefix();

// Returns the path at which the user home for |username| will be mounted.
// Returns "" for failures.
BRILLO_EXPORT base::FilePath GetUserPath(const Username& username);

// Returns the path at which the user home for |hashed_username| will be
// mounted. Useful when you already have the username hashed.
// Returns "" for failures.
BRILLO_EXPORT base::FilePath GetHashedUserPath(
    const ObfuscatedUsername& hashed_username);

// Returns the path at which the root home for |username| will be mounted.
// Returns "" for failures.
BRILLO_EXPORT base::FilePath GetRootPath(const Username& username);

// Returns the path at which the daemon |daemon| should store per-user data.
// This function returns '/run/daemon-stores/<daemon-name>/<hash>' which is
// the preferred place to store per-user data.
// See https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md
// for more details.
BRILLO_EXPORT base::FilePath GetDaemonStorePath(const Username& username,
                                                const std::string& daemon);

// Checks whether |sanitized| has the format of a sanitized username.
BRILLO_EXPORT bool IsSanitizedUserName(const std::string& sanitized);

// Returns a sanitized form of |username|. For x != y, SanitizeUserName(x) !=
// SanitizeUserName(y).
BRILLO_EXPORT ObfuscatedUsername SanitizeUserName(const Username& username);

// Returns a sanitized form of |username| with the salt provided. For x != y,
// SanitizeUserName(x) != SanitizeUserName(y).
BRILLO_EXPORT ObfuscatedUsername
SanitizeUserNameWithSalt(const Username& username, const SecureBlob& salt);

// Overrides the common prefix under which the mount points for user homes are
// created. This is used for testing only.
BRILLO_EXPORT void SetUserHomePrefix(const std::string& prefix);

// Deprecated. Prefer `FakeSystemSaltLoader`.
BRILLO_EXPORT void SetSystemSalt(std::string* salt);

// Deprecated. Prefer `FakeSystemSaltLoader`.
BRILLO_EXPORT std::string* GetSystemSalt();

// Deprecated. Prefer `SystemSaltLoader::GetInstance().EnsureLoaded()`.
BRILLO_EXPORT bool EnsureSystemSaltIsLoaded();

// Helper for loading the system salt value from disk.
class BRILLO_EXPORT SystemSaltLoader {
 public:
  // Returns the global singleton instance. If there's none, automatically
  // creates one with the default parameters.
  // TODO(b/260721017): Don't create the default instance automatically.
  static SystemSaltLoader* GetInstance();

  // Creates an instance that loads salt from the default file path. Also
  // initializes the global singleton returned by `GetInstance()`.
  SystemSaltLoader();

  SystemSaltLoader(const SystemSaltLoader&) = delete;
  SystemSaltLoader& operator=(const SystemSaltLoader&) = delete;

  virtual ~SystemSaltLoader();

  // Attempts to load the salt unless it was already done. Returns false if the
  // loading failed.
  bool EnsureLoaded();
  // Returns the salt, or an empty string if it wasn't loaded.
  const std::string& value() const;

  // TODO(b/254864841): Remove once `GetSystemSalt()` is removed.
  std::string* value_or_override();
  // TODO(b/254864841): Remove once `SetSystemSalt()` is removed.
  void override_value_for_testing(std::string* new_value);

 protected:
  explicit SystemSaltLoader(base::FilePath file_path);

  const base::FilePath file_path_;
  std::string value_;

 private:
  // TODO(b/254864841): Remove once `GetSystemSalt()` and `SetSystemSalt()` are
  // removed.
  std::string* value_override_for_testing_ = nullptr;
};

}  // namespace home
}  // namespace cryptohome
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_CRYPTOHOME_H_
