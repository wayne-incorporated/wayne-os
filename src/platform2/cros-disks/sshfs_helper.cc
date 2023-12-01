// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/sshfs_helper.h"

#include <algorithm>
#include <utility>

#include <base/base64.h>
#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "cros-disks/fuse_mounter.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"
#include "cros-disks/sandboxed_process.h"
#include "cros-disks/uri.h"

namespace cros_disks {

namespace {

constexpr char kUserName[] = "fuse-sshfs";
constexpr char kHelperTool[] = "/usr/bin/sshfs";
constexpr char kType[] = "sshfs";

constexpr char kOptionIdentityFile[] = "IdentityFile";
constexpr char kOptionIdentityBase64[] = "IdentityBase64";
constexpr char kOptionUserKnownHostsFile[] = "UserKnownHostsFile";
constexpr char kOptionUserKnownHostsBase64[] = "UserKnownHostsBase64";
constexpr char kOptionHostName[] = "HostName";
constexpr char kOptionPort[] = "Port";

constexpr char kIdentityFile[] = "id";
constexpr char kUserKnownHostsFile[] = "known_hosts";

// 64KiB is the maximum packet size allowed by sshfs
// and vsock vhost driver (VIRTIO_VSOCK_MAX_PKT_BUF_SIZE)
constexpr char kSshfsVsockPacketSize[] = "65536";

OwnerUser ResolveSshfsUser(const Platform* platform) {
  OwnerUser user;
  PCHECK(platform->GetUserAndGroupId(kUserName, &user.uid, &user.gid));
  return user;
}

MountError WriteConfigurationFile(const Platform* platform,
                                  const OwnerUser& owner,
                                  const base::FilePath& path,
                                  const std::string& b64_data) {
  std::string data;
  if (!base::Base64Decode(b64_data, &data)) {
    LOG(ERROR) << "Invalid base64 value for " << quote(path);
    return MountError::kInvalidMountOptions;
  }

  if (platform->WriteFile(path.value(), data.c_str(), data.size()) !=
      static_cast<int>(data.size())) {
    PLOG(ERROR) << "Cannot write file " << quote(path);
    return MountError::kInsufficientPermissions;
  }

  if (!platform->SetPermissions(path.value(), 0600) ||
      !platform->SetOwnership(path.value(), owner.uid, owner.gid)) {
    PLOG(ERROR) << "Cannot change owner of file " << quote(path);
    return MountError::kInsufficientPermissions;
  }

  return MountError::kSuccess;
}

bool IsSupportedScheme(const std::string& scheme) {
  return scheme == "sftp" || scheme == "sshfs";
}

}  // namespace

SshfsHelper::SshfsHelper(const Platform* platform,
                         brillo::ProcessReaper* process_reaper,
                         base::FilePath working_dir)
    : FUSEMounterHelper(platform,
                        process_reaper,
                        kType,
                        /* nosymfollow= */ true,
                        &sandbox_factory_),
      sandbox_factory_(platform,
                       SandboxedExecutable{base::FilePath(kHelperTool)},
                       ResolveSshfsUser(platform),
                       /* has_network_access= */ true),
      working_dir_(std::move(working_dir)) {}

SshfsHelper::~SshfsHelper() = default;

bool SshfsHelper::CanMount(const std::string& source,
                           const std::vector<std::string>& params,
                           base::FilePath* suggested_name) const {
  const Uri uri = Uri::Parse(source);
  if (!uri.valid() || !IsSupportedScheme(uri.scheme()))
    return false;

  if (uri.path().empty()) {
    *suggested_name = base::FilePath(uri.scheme());
  } else {
    std::string path = uri.path();
    std::replace(path.begin(), path.end(), '/', '$');
    std::replace(path.begin(), path.end(), '.', '_');
    *suggested_name = base::FilePath(path);
  }
  return true;
}

MountError SshfsHelper::ConfigureSandbox(const std::string& source,
                                         const base::FilePath& target_path,
                                         std::vector<std::string> params,
                                         SandboxedProcess* sandbox) const {
  const Uri uri = Uri::Parse(source);
  if (!uri.valid() || uri.path().empty()) {
    LOG(ERROR) << "Invalid source " << quote(source);
    return MountError::kInvalidDevicePath;
  }
  if (uri.scheme() == "sshfs") {
    return ConfigureSandboxSshfs(uri, params, sandbox);
  } else if (uri.scheme() == "sftp") {
    return ConfigureSandboxSftpVsock(uri, sandbox);
  } else {
    LOG(ERROR) << "Invalid source " << quote(source);
    return MountError::kInvalidDevicePath;
  }
}

MountError SshfsHelper::ConfigureSandboxSshfs(const Uri& uri,
                                              std::vector<std::string> params,
                                              SandboxedProcess* sandbox) const {
  std::string b64_identity;
  if (!GetParamValue(params, kOptionIdentityBase64, &b64_identity) ||
      b64_identity.empty()) {
    LOG(ERROR) << "Missing required parameter " << kOptionIdentityBase64;
    return MountError::kInvalidMountOptions;
  }
  std::string b64_known_hosts;
  if (!GetParamValue(params, kOptionUserKnownHostsBase64, &b64_known_hosts) ||
      b64_known_hosts.empty()) {
    LOG(ERROR) << "Missing required parameter " << kOptionUserKnownHostsBase64;
    return MountError::kInvalidMountOptions;
  }

  std::string path;

  // TODO(dats): Consider plumbing hooks that would allow removing this
  // directory after unmount.
  if (!platform()->CreateTemporaryDirInDir(working_dir_.value(), "sshfs-",
                                           &path)) {
    PLOG(ERROR) << "Cannot create temporary directory inside "
                << quote(working_dir_);
    return MountError::kInsufficientPermissions;
  }
  base::FilePath working_dir(path);
  base::FilePath identity_file = working_dir.Append(kIdentityFile);
  base::FilePath known_hosts_file = working_dir.Append(kUserKnownHostsFile);

  MountError error = WriteConfigurationFile(
      platform(), sandbox_factory_.run_as(), identity_file, b64_identity);
  if (error != MountError::kSuccess) {
    return error;
  }
  error = WriteConfigurationFile(platform(), sandbox_factory_.run_as(),
                                 known_hosts_file, b64_known_hosts);
  if (error != MountError::kSuccess) {
    return error;
  }

  // We retain group ownership on the directory to allow potential cleanup
  // of its contents.
  if (!platform()->SetPermissions(working_dir.value(), 0770) ||
      !platform()->SetOwnership(working_dir.value(),
                                sandbox_factory_.run_as().uid, getgid())) {
    LOG(ERROR) << "Cannot set proper ownership of working directory "
               << quote(working_dir);
    return MountError::kInsufficientPermissions;
  }

  if (!sandbox->BindMount(working_dir.value(), working_dir.value(), false,
                          false)) {
    LOG(ERROR) << "Cannot bind working directory " << quote(working_dir);
    return MountError::kInternalError;
  }

  std::vector<std::string> options = {
      "KbdInteractiveAuthentication=no",
      "PasswordAuthentication=no",
      "BatchMode=yes",
      "follow_symlinks",
      "cache=no",
  };

  SetParamValue(&options, "uid", base::NumberToString(kChronosUID));
  SetParamValue(&options, "gid", base::NumberToString(kChronosAccessGID));
  SetParamValue(&options, kOptionIdentityFile, identity_file.value());
  SetParamValue(&options, kOptionUserKnownHostsFile, known_hosts_file.value());

  std::string value;
  if (GetParamValue(params, kOptionHostName, &value)) {
    SetParamValue(&options, kOptionHostName, value);
  }
  if (GetParamValue(params, kOptionPort, &value)) {
    SetParamValue(&options, kOptionPort, value);
  }

  sandbox->AddArgument(uri.path());

  std::string option_string;
  if (!JoinParamsIntoOptions(options, &option_string)) {
    return MountError::kInvalidMountOptions;
  }
  sandbox->AddArgument("-o");
  sandbox->AddArgument(option_string);
  return MountError::kSuccess;
}

MountError SshfsHelper::ConfigureSandboxSftpVsock(
    const Uri& uri, SandboxedProcess* sandbox) const {
  // sftp doesn't use the hostname but there has to be one otherwise sshfs
  // complains. And the path is always empty because we run sftp-server where
  // we want to serve files from.
  sandbox->AddArgument("localhost:");
  std::vector<std::string> options = {"BatchMode=yes", "follow_symlinks",
                                      "cache=no", "vsock=" + uri.path()};
  SetParamValue(&options, "uid", base::NumberToString(kChronosUID));
  SetParamValue(&options, "gid", base::NumberToString(kChronosAccessGID));
  // Use the maximum packet size to improve file transfer performance
  SetParamValue(&options, "max_read", kSshfsVsockPacketSize);
  SetParamValue(&options, "max_write", kSshfsVsockPacketSize);
  std::string option_string;
  if (!JoinParamsIntoOptions(options, &option_string)) {
    return MountError::kInvalidMountOptions;
  }
  sandbox->AddArgument("-o");
  sandbox->AddArgument(option_string);
  return MountError::kSuccess;
}

}  // namespace cros_disks
