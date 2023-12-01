// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_PATH_SERVICE_H_
#define AUTHPOLICY_PATH_SERVICE_H_

#include <map>
#include <string>

namespace authpolicy {

enum class Path {
  // Invalid path, not set, triggers a DCHECK in PathService::Get().
  INVALID,

  // Base directories.
  TEMP_DIR,          // Files here are wiped on authpolicyd restart.
  STATE_DIR,         // Files here are persistent and globally accessible.
  RUN_DIR,           // Files here are wiped on reboot.
  DAEMON_STORE_DIR,  // Files here are persistent in the user's cryptohome and
                     // hence accessible only for the logged-in user.

  // Samba directories.
  SAMBA_DIR,
  SAMBA_LOCK_DIR,
  SAMBA_CACHE_DIR,
  SAMBA_STATE_DIR,
  SAMBA_PRIVATE_DIR,
  GPO_LOCAL_DIR,  // Location of downloaded GPOs.

  // Configuration files.
  CONFIG_DAT,        // Authpolicy configuration.
  USER_SMB_CONF,     // Samba configuration for user account.
  DEVICE_SMB_CONF,   // Samba configuration for device/machine account.
  USER_KRB5_CONF,    // Kerberos configuration for user account.
  DEVICE_KRB5_CONF,  // Kerberos configuration for device/machine account.

  // Credential cache paths.
  USER_CREDENTIAL_CACHE,
  DEVICE_CREDENTIAL_CACHE,

  // Machine credentials. Authpolicy uses EITHER password OR keytab. Newly
  // enrolled devices use passwords, older devices use keytabs.
  MACHINE_PASS,       // Current machine password.
  PREV_MACHINE_PASS,  // Previous machine password.
  NEW_MACHINE_PASS,   // New machine password.
  MACHINE_KEYTAB,     // Kerberos machine keytab file.

  // Files that are wiped on reboot.
  FLAGS_DEFAULT_LEVEL,  // File with flags default level (as integer), see
                        // AuthPolicyFlags::DefaultLevel.
  AUTH_DATA_CACHE,      // Cached authentication data.

  // Samba/Kerberos/parser executables.
  KINIT,
  KLIST,
  KPASSWD,
  NET,
  SMBCLIENT,
  PARSER,

  // Seccomp filter policies.
  KINIT_SECCOMP,
  KLIST_SECCOMP,
  KPASSWD_SECCOMP,
  NET_ADS_SECCOMP,
  PARSER_SECCOMP,
  SMBCLIENT_SECCOMP,

  // Misc.
  DEBUG_FLAGS,  // File with debug flags, see AuthPolicyFlags.
  KRB5_TRACE,   // kinit and kpasswd trace log.
};

// Simple path service.
class PathService {
 public:
  // Calls Initialize().
  PathService();
  PathService(const PathService&) = delete;
  PathService& operator=(const PathService&) = delete;
  virtual ~PathService();

  // Retrieves the file or directory path for the given |path_key|.
  const std::string& Get(Path path_key) const;

 protected:
  // Calls Initialize() if |initialize| is true.
  explicit PathService(bool initialize);

  // Should be called at some point during construction to initialize all paths.
  // Derived classes can override paths by specifying a constuctor that calls
  // PathService(false), inserts paths and then calls Initialize() to initialize
  // paths not set yet.
  void Initialize();

  // Inserts |path| at key |path_key| into |path_map_| if the key is not
  // already set.
  void Insert(Path path_key, const std::string& path);

 private:
  std::map<Path, std::string> paths_;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_PATH_SERVICE_H_
