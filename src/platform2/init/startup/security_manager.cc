// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/startup/security_manager.h"

#include <fcntl.h>
#include <sys/ioctl.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <crypto/random.h>
#include <linux/loadpin.h>
#include <openssl/sha.h>

#include "init/startup/platform_impl.h"

namespace {

constexpr char kSysKernelSecurity[] = "sys/kernel/security";

constexpr char kDevNull[] = "dev/null";
constexpr char kLoadPinVerity[] = "loadpin/dm-verity";
// During CrOS build phases, this file will be produced and baked into the
// rootfs. Specifically during the DLC build flows.
constexpr char kTrustedDlcVerityDigests[] =
    "opt/google/dlc/_trusted_verity_digests";

// Path to the security fs file for configuring process management security
// policies in the chromiumos LSM (used for kernel version <= 4.4).
// TODO(mortonm): Remove this and the corresponding lines in
// add_process_mgmt_policy when all devices have been updated/backported to
// get the SafeSetID LSM functionality.
constexpr char kProcessMgmtPolicies[] =
    "chromiumos/process_management_policies/add_whitelist_policy";
constexpr char kProcessMgmtPoliciesDir[] =
    "usr/share/cros/startup/process_management_policies";
constexpr char kProcessMgmtPoliciesDirGID[] =
    "usr/share/cros/startup/gid_process_management_policies";
constexpr char kSafeSetIDProcessMgmtPolicies[] = "safesetid";

constexpr char kLsmInodePolicies[] =
    "sys/kernel/security/chromiumos/inode_security_policies";

constexpr char kSysKeyLogFile[] = "run/create_system_key.log";
constexpr char kNoEarlyKeyFile[] = ".no_early_system_key";
constexpr char kSysKeyBackupFile[] = "unencrypted/preserve/system.key";
constexpr int kKeySize = SHA256_DIGEST_LENGTH;

const std::array<const char*, 5> kSymlinkExceptions = {
    "var/cache/echo", "var/cache/vpd", "var/lib/timezone", "var/log", "home",
};
constexpr char kSymlinkExceptionsDir[] =
    "usr/share/cros/startup/symlink_exceptions";
constexpr char kFifoExceptionsDir[] = "usr/share/cros/startup/fifo_exceptions";
constexpr char kVar[] = "var";

}  // namespace

namespace startup {

// Project-specific process management policies. Projects may add policies by
// adding a file under usr/share/cros/startup/process_management_policies/
// for UID's and under /usr/share/cros/startup/gid_process_management_policies/
// for GID's, whose contents are one or more lines specifying a parent ID
// and a child UID that the parent can use for the purposes of process
// management. There should be one line for every mapping that is to be put in
// the allow list. Lines in the file should use the following format:
// <UID>:<UID> or <GID>:<GID>
//
// For example, if the 'shill' user needs to use 'dhcp', 'openvpn' and 'ipsec'
// and 'syslog' for process management, the file would look like:
// 20104:224
// 20104:217
// 20104:212
// 20104:202
//
// AccumulatePolicyFiles takes in all the files contained in the policy_dir
// reads their contents, copies and appends them to a file determined by
// output_file.
//
// The parameter gid_policies indicates whether the policies are for GIDs, used
// for selecting the correct file
bool AccumulatePolicyFiles(const base::FilePath& root,
                           const base::FilePath& output_file,
                           const base::FilePath& policy_dir,
                           bool gid) {
  if (!base::PathExists(output_file)) {
    // securityfs files are located elsewhere, return.
    return true;
  }

  if (!base::DirectoryExists(policy_dir)) {
    LOG(WARNING) << "Can't configure process management security. "
                 << policy_dir << " not found.";
    return false;
  }

  const base::FilePath pmp =
      root.Append(kSysKernelSecurity).Append(kProcessMgmtPolicies);
  bool pmp_exists = base::PathExists(pmp);
  base::FileEnumerator enumerator(policy_dir, false,
                                  base::FileEnumerator::FileType::FILES);
  std::vector<std::string> combined_policy;
  for (base::FilePath file = enumerator.Next(); !file.empty();
       file = enumerator.Next()) {
    std::string file_str;
    if (!base::ReadFileToString(file, &file_str)) {
      PLOG(WARNING) << "Can't read policy file " << file;
      continue;
    }
    std::vector<std::string> split_files = base::SplitString(
        file_str, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    split_files.erase(std::remove_if(split_files.begin(), split_files.end(),
                                     [&](const std::string line) {
                                       return base::StartsWith(line, "#");
                                     }),
                      split_files.end());
    combined_policy.push_back(base::JoinString(split_files, "\n"));
  }

  std::string combined_policy_str = base::JoinString(combined_policy, "\n");
  combined_policy_str.append("\n");

  if (pmp_exists) {
    // Don't record GID policies into kProcessMgmtPolicies.
    if (!gid) {
      if (!base::WriteFile(pmp, combined_policy_str)) {
        PLOG(ERROR) << pmp << ": Failed to write file";
      }
    }
  } else {
    if (!base::WriteFile(output_file, combined_policy_str)) {
      PLOG(ERROR) << output_file << ": Failed to write to file";
    }
  }
  return true;
}

// Determine where securityfs files are placed.
// No inputs, checks for which securityfs file paths exist
// and accumulates files for securityfs.
bool ConfigureProcessMgmtSecurity(const base::FilePath& root) {
  // For UID relevant files.

  const base::FilePath policies_dir =
      root.Append(kSysKernelSecurity).Append(kSafeSetIDProcessMgmtPolicies);
  // Path to the securityfs file for configuring process management security
  // policies, for UIDs, in the SafeSetID LSM (used for kernel version >= 5.9).
  const base::FilePath uid_mgmt_policies =
      policies_dir.Append("uid_allowlist_policy");
  // Path to the securityfs file for configuring process management security
  // policies in the SafeSetID LSM (used for kernel version >= 4.14)
  const base::FilePath mgmt_policies = policies_dir.Append("whitelist_policy");
  const base::FilePath pmpd = root.Append(kProcessMgmtPoliciesDir);

  // For GID relevant files.
  const base::FilePath gid_mgmt_policies =
      root.Append(kSafeSetIDProcessMgmtPolicies).Append("gid_allowlist_policy");
  const base::FilePath pmp_gid = root.Append(kProcessMgmtPoliciesDirGID);

  return AccumulatePolicyFiles(root, uid_mgmt_policies, pmpd, false) &&
         AccumulatePolicyFiles(root, mgmt_policies, pmpd, false) &&
         AccumulatePolicyFiles(root, gid_mgmt_policies, pmp_gid, true);
}

bool SetupLoadPinVerityDigests(const base::FilePath& root, Platform* platform) {
  const auto loadpin_verity =
      root.Append(kSysKernelSecurity).Append(kLoadPinVerity);
  const auto trusted_dlc_digests = root.Append(kTrustedDlcVerityDigests);
  const auto dev_null = root.Append(kDevNull);
  // Only try loading the trusted dm-verity root digests if:
  //   1. LoadPin dm-verity attribute is supported.
  //   2a. Trusted list of DLC dm-verity root digest file exists.
  //   2b. Otherwise, we must feed LoadPin with an invalid digests file.

  // Open (write) the LoadPin dm-verity attribute file.
  constexpr auto kWriteFlags = O_WRONLY | O_NOFOLLOW | O_CLOEXEC;
  auto fd = platform->Open(loadpin_verity, kWriteFlags);
  if (!fd.is_valid()) {
    // This means LoadPin dm-verity attribute is not supported.
    // No further action is required.
    if (errno == ENOENT) {
      return true;
    }
    // TODO(kimjae): Need to somehow handle this failure, as this still means
    // later a digest can get fed into LoadPin.
    PLOG(WARNING) << "Failed to open LoadPin verity file.";
    return false;
  }

  // Open (read) the trusted digest file in rootfs.
  constexpr auto kReadFlags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
  auto digests_fd = platform->Open(trusted_dlc_digests, kReadFlags);
  if (!digests_fd.is_valid()) {
    if (errno != ENOENT) {
      PLOG(WARNING) << "Failed to open trusted DLC verity digests file.";
      // NOTE: Do not return here, so invalid digests get fed into LoadPin.
    }
    // Any failure in loading/parsing will block subsequent feeds into LoadPin.
    digests_fd = platform->Open(dev_null, kReadFlags);
    if (!digests_fd.is_valid()) {
      PLOG(WARNING) << "Failed to open " << dev_null.value() << ".";
      return false;
    }
  }

  // Write trusted digests or /dev/null into LoadPin.
  int arg1 = digests_fd.get();
  int ret =
      platform->Ioctl(fd.get(), LOADPIN_IOC_SET_TRUSTED_VERITY_DIGESTS, &arg1);
  if (ret != 0) {
    PLOG(WARNING) << "Unable to setup trusted DLC verity digests";
  }
  // On success or failure:
  // Subsequent `ioctl` on loadpin/dm-verity should fail as the trusted
  // dm-verity root digest list is not empty or invalid digest file descriptor
  // is fed into LoadPin.
  return ret == 0;
}

bool BlockSymlinkAndFifo(const base::FilePath& root, const std::string& path) {
  base::FilePath base = root.Append(kLsmInodePolicies);
  base::FilePath sym = base.Append("block_symlink");
  base::FilePath fifo = base.Append("block_fifo");
  bool ret = true;
  if (!base::WriteFile(sym, path)) {
    PLOG(WARNING) << "Failed to write to block_symlink for " << path;
    ret = false;
  }
  if (!base::WriteFile(fifo, path)) {
    PLOG(WARNING) << "Failed to write to block_fifo for " << path;
    ret = false;
  }
  return ret;
}

// Generates a system key in test images, before the normal mount-encrypted.
// This allows us to soft-clear the TPM in integration tests w/o accidentally
// wiping encstateful after a reboot.
void CreateSystemKey(const base::FilePath& root,
                     const base::FilePath& stateful,
                     Platform* platform) {
  base::FilePath log_file = root.Append(kSysKeyLogFile);
  base::FilePath no_early = stateful.Append(kNoEarlyKeyFile);
  base::FilePath backup = stateful.Append(kSysKeyBackupFile);
  base::FilePath empty;

  base::WriteFile(log_file, "");

  if (base::PathExists(no_early)) {
    bool status;
    status = base::AppendToFile(log_file,
                                "Opt not to create a system key in advance.");
    return;
  }

  base::AppendToFile(log_file,
                     "Checking if a system key already exists in NVRAM...\n");
  std::string output;
  std::vector<std::string> mnt_enc_info = {"info"};
  int status = platform->MountEncrypted(mnt_enc_info, &output);
  if (status == 0) {
    base::AppendToFile(log_file, output.append("\n"));
    if (output.find("NVRAM: available.") != std::string::npos) {
      base::AppendToFile(log_file, "There is already a system key in NVRAM.\n");
      return;
    }
  }

  base::AppendToFile(log_file,
                     "No system key found in NVRAM. Start creating one.\n");

  // Generates 32-byte random key material and backs it up.
  unsigned char buf[kKeySize];
  crypto::RandBytes(buf, kKeySize);
  const char* buf_ptr = reinterpret_cast<const char*>(&buf);
  if (base::WriteFile(backup, buf_ptr, kKeySize) < kKeySize) {
    base::AppendToFile(log_file,
                       "Failed to generate or back up system key material.\n");
    return;
  }

  // Persists system key.
  std::vector<std::string> mnt_enc_set = {"set", backup.value()};
  status = platform->MountEncrypted(mnt_enc_set, &output);
  if (status == 0) {
    base::AppendToFile(log_file, output);
    base::AppendToFile(log_file, "Successfully created a system key.");
  }
}

bool AllowSymlink(const base::FilePath& root, const std::string& path) {
  base::FilePath sym = root.Append(kLsmInodePolicies).Append("allow_symlink");
  return base::WriteFile(sym, path);
}

bool AllowFifo(const base::FilePath& root, const std::string& path) {
  base::FilePath fifo = root.Append(kLsmInodePolicies).Append("allow_fifo");
  return base::WriteFile(fifo, path);
}

void SymlinkExceptions(const base::FilePath& root) {
  // Generic symlink exceptions.
  for (auto d_it = kSymlinkExceptions.begin(); d_it != kSymlinkExceptions.end();
       d_it++) {
    base::FilePath d = root.Append(*d_it);
    if (!base::CreateDirectory(d)) {
      PLOG(WARNING) << "mkdir failed for " << d.value();
    }
    if (!base::SetPosixFilePermissions(d, 0755)) {
      PLOG(WARNING) << "Failed to set permissions for " << d.value();
    }
    AllowSymlink(root, d.value());
  }
}

// Project-specific exceptions. Projects may add exceptions by
// adding a file under excepts_dir whose contents contains a list
// of paths (one per line) for which an exception should be made.
// File name should use the following format:
// <project-name>-{symlink|fifo}-exceptions.txt
void ExceptionsProjectSpecific(const base::FilePath& root,
                               const base::FilePath& config_dir,
                               bool (*callback)(const base::FilePath& root,
                                                const std::string& path)) {
  if (base::DirectoryExists(config_dir)) {
    base::FileEnumerator iter(config_dir, false,
                              base::FileEnumerator::FileType::FILES);
    for (base::FilePath path_file = iter.Next(); !path_file.empty();
         path_file = iter.Next()) {
      if (!base::PathExists(path_file)) {
        continue;
      }
      std::string contents;
      if (!base::ReadFileToString(path_file, &contents)) {
        PLOG(WARNING) << "Can't open exceptions file " << path_file.value();
        continue;
      }
      std::vector<std::string> files = base::SplitString(
          contents, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
      for (const auto& path : files) {
        if (path.find("#") == 0) {
          continue;
        } else {
          base::FilePath p(path);
          if (!base::CreateDirectory(p)) {
            PLOG(WARNING) << "mkdir failed for " << path;
          }
          if (!base::SetPosixFilePermissions(p, 0755)) {
            PLOG(WARNING) << "Failed to set permissions for " << path;
          }
          callback(root, path);
        }
      }
    }
  }
}

// Set up symlink traversal and FIFO blocking policy, and project
// specific symlink and FIFO exceptions.
void ConfigureFilesystemExceptions(const base::FilePath& root) {
  // Set up symlink traversal and FIFO blocking policy for /var, which may
  // reside on a separate file system than /mnt/stateful_partition. Block
  // symlink traversal and opening of FIFOs by default, but allow exceptions
  // in the few instances where they are used intentionally.
  BlockSymlinkAndFifo(root, root.Append(kVar).value());
  SymlinkExceptions(root);
  // Project-specific symlink exceptions. Projects may add exceptions by
  // adding a file under /usr/share/cros/startup/symlink_exceptions/ whose
  // contents contains a list of paths (one per line) for which an exception
  // should be made. File name should use the following format:
  // <project-name>-symlink-exceptions.txt
  base::FilePath sym_excepts = root.Append(kSymlinkExceptionsDir);
  ExceptionsProjectSpecific(root, sym_excepts, &AllowSymlink);

  // Project-specific FIFO exceptions. Projects may add exceptions by adding
  // a file under /usr/share/cros/startup/fifo_exceptions/ whose contents
  // contains a list of paths (one per line) for which an exception should be
  // made. File name should use the following format:
  // <project-name>-fifo-exceptions.txt
  base::FilePath fifo_excepts = root.Append(kFifoExceptionsDir);
  ExceptionsProjectSpecific(root, fifo_excepts, &AllowFifo);
}

}  // namespace startup
