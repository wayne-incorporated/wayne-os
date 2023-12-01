// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/path_service.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>

namespace authpolicy {
namespace {

// Base directories.
const char kAuthPolicyTempDir[] = "/tmp/authpolicyd";
const char kAuthPolicyStateDir[] = "/var/lib/authpolicyd";
const char kAuthPolicyRunDir[] = "/run/authpolicyd";
const char kAuthPolicyDaemonStoreDir[] = "/run/daemon-store/authpolicyd";

// Relative Samba directories.
const char kSambaDir[] = "/samba";
const char kLockDir[] = "/lock";
const char kCacheDir[] = "/cache";
const char kStateDir[] = "/state";
const char kPrivateDir[] = "/private";
const char kGpoCacheDir[] = "/gpo_cache";

// Configuration files.
const char kConfig[] = "/config.dat";
const char kUserSmbConf[] = "/smb_user.conf";
const char kDeviceSmbConf[] = "/smb_device.conf";
const char kUserKrb5Conf[] = "/krb5_user.conf";
const char kDeviceKrb5Conf[] = "/krb5_device.conf";

// Credential caches.
const char kUserCredentialCache[] = "/krb5cc_user";
const char kDeviceCredentialCache[] = "/krb5cc_device";

// Machine credentials.
const char kMachinePass[] = "/machine_pass";
const char kPrevMachinePass[] = "/prev_machine_pass";
const char kNewMachinePass[] = "/new_machine_pass";
const char kMachineKeyTab[] = "/krb5_machine.keytab";

// Files that are wiped on reboot.
const char kFlagsDefaultLevel[] = "/flags_default_level";
const char kAuthDataCache[] = "/auth_data";

// Executables.
const char kKInitPath[] = "/usr/bin/kinit";
const char kKListPath[] = "/usr/bin/klist";
const char kKPasswdPath[] = "/usr/bin/kpasswd";
const char kNetPath[] = "/usr/bin/net";
const char kParserPath[] = "/usr/sbin/authpolicy_parser";
const char kSmbClientPath[] = "/usr/bin/smbclient";

// Seccomp filters.
const char kKInitSeccompFilterPath[] = "/usr/share/policy/samba-seccomp.policy";
const char kKListSeccompFilterPath[] = "/usr/share/policy/klist-seccomp.policy";
const char kKPasswdSeccompFilterPath[] =
    "/usr/share/policy/samba-seccomp.policy";
const char kNetAdsSeccompFilterPath[] =
    "/usr/share/policy/samba-seccomp.policy";
const char kParserSeccompFilterPath[] =
    "/usr/share/policy/authpolicy_parser-seccomp.policy";
const char kSmbClientSeccompFilterPath[] =
    "/usr/share/policy/samba-seccomp.policy";

// Debug flags.
const char kDebugFlagsPath[] = "/etc/authpolicyd_flags";
// Kerberos trace logs (kinit, kpasswd).
const char kKrb5Trace[] = "/krb5_trace";

}  // namespace

PathService::PathService() : PathService(true) {}

PathService::PathService(bool initialize) {
  if (initialize)
    Initialize();
}

PathService::~PathService() {}

void PathService::Initialize() {
  // Set paths. Note: Won't override paths that are already set by a more
  // derived version of this method.
  Insert(Path::TEMP_DIR, kAuthPolicyTempDir);
  Insert(Path::STATE_DIR, kAuthPolicyStateDir);
  Insert(Path::RUN_DIR, kAuthPolicyRunDir);
  Insert(Path::DAEMON_STORE_DIR, kAuthPolicyDaemonStoreDir);

  const std::string& temp_dir = Get(Path::TEMP_DIR);
  const std::string& state_dir = Get(Path::STATE_DIR);
  const std::string& run_dir = Get(Path::RUN_DIR);

  Insert(Path::SAMBA_DIR, temp_dir + kSambaDir);

  const std::string& samba_dir = Get(Path::SAMBA_DIR);

  Insert(Path::SAMBA_LOCK_DIR, samba_dir + kLockDir);
  Insert(Path::SAMBA_CACHE_DIR, samba_dir + kCacheDir);
  Insert(Path::SAMBA_STATE_DIR, samba_dir + kStateDir);
  Insert(Path::SAMBA_PRIVATE_DIR, samba_dir + kPrivateDir);
  Insert(Path::GPO_LOCAL_DIR, samba_dir + kCacheDir + kGpoCacheDir);

  Insert(Path::CONFIG_DAT, state_dir + kConfig);
  Insert(Path::USER_SMB_CONF, temp_dir + kUserSmbConf);
  Insert(Path::DEVICE_SMB_CONF, temp_dir + kDeviceSmbConf);
  Insert(Path::USER_KRB5_CONF, temp_dir + kUserKrb5Conf);
  Insert(Path::DEVICE_KRB5_CONF, temp_dir + kDeviceKrb5Conf);

  // Credential caches have to be in a place writable for authpolicyd-exec!
  Insert(Path::USER_CREDENTIAL_CACHE, samba_dir + kUserCredentialCache);
  Insert(Path::DEVICE_CREDENTIAL_CACHE, samba_dir + kDeviceCredentialCache);

  Insert(Path::MACHINE_PASS, state_dir + kMachinePass);
  Insert(Path::PREV_MACHINE_PASS, state_dir + kPrevMachinePass);
  Insert(Path::NEW_MACHINE_PASS, state_dir + kNewMachinePass);
  Insert(Path::MACHINE_KEYTAB, state_dir + kMachineKeyTab);

  Insert(Path::FLAGS_DEFAULT_LEVEL, run_dir + kFlagsDefaultLevel);
  Insert(Path::AUTH_DATA_CACHE, run_dir + kAuthDataCache);

  Insert(Path::KINIT, kKInitPath);
  Insert(Path::KLIST, kKListPath);
  Insert(Path::KPASSWD, kKPasswdPath);
  Insert(Path::NET, kNetPath);
  Insert(Path::PARSER, kParserPath);
  Insert(Path::SMBCLIENT, kSmbClientPath);

  Insert(Path::KINIT_SECCOMP, kKInitSeccompFilterPath);
  Insert(Path::KLIST_SECCOMP, kKListSeccompFilterPath);
  Insert(Path::KPASSWD_SECCOMP, kKPasswdSeccompFilterPath);
  Insert(Path::NET_ADS_SECCOMP, kNetAdsSeccompFilterPath);
  Insert(Path::PARSER_SECCOMP, kParserSeccompFilterPath);
  Insert(Path::SMBCLIENT_SECCOMP, kSmbClientSeccompFilterPath);

  Insert(Path::DEBUG_FLAGS, kDebugFlagsPath);
  // Trace has to be in a place writable for authpolicyd-exec!
  Insert(Path::KRB5_TRACE, samba_dir + kKrb5Trace);
}

const std::string& PathService::Get(Path path_key) const {
  auto iter = paths_.find(path_key);
  DCHECK(iter != paths_.end());
  return iter->second;
}

void PathService::Insert(Path path_key, const std::string& path) {
  paths_.insert(std::make_pair(path_key, path));
}

}  // namespace authpolicy
