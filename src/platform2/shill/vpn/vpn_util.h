// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_VPN_UTIL_H_
#define SHILL_VPN_VPN_UTIL_H_

#include <sys/types.h>

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/version.h>

#include "shill/net/process_manager.h"

namespace shill {

// An interface to wrap some constants and functions which are shared by
// multiple VPN classes.
class VPNUtil {
 public:
  // User and group we use to run external binaries. Defined in user/vpn and
  // group/vpn in chromiumos/overlays/eclass-overlay/profiles/base/accounts
  // folder.
  static constexpr char kVPNUser[] = "vpn";
  static constexpr char kVPNGroup[] = "vpn";
  // TODO(191627520): gid should ideally be looked up at runtime.
  static constexpr gid_t kVPNGid = 20174;

  VPNUtil(const VPNUtil&) = delete;
  VPNUtil& operator=(const VPNUtil&) = delete;
  virtual ~VPNUtil() = default;

  static std::unique_ptr<VPNUtil> New();

  // Returns whether the current kernel version >= |minimum_version|.
  static bool CheckKernelVersion(const base::Version& minimum_version);

  // Constructs a MinijailOptions object which contains the common options used
  // by VPN clients:
  // - |user| and |group| are set to "vpn".
  // - |inherit_supplementary_groups| are set to true.
  static ProcessManager::MinijailOptions BuildMinijailOptions(uint64_t capmask);

  // Writes |contents| into file with path |filename|, changes the group of this
  // file to "vpn", and makes this file group-readable. Note that although shill
  // does not have CAP_CHOWN, the owner of a file may change the group of the
  // file to any group of which that owner is a member, so we can change the
  // group to "vpn" here since "shill" is a member of "vpn".
  virtual bool WriteConfigFile(const base::FilePath& filename,
                               const std::string& contents) const = 0;

  // Creates a directory at |directory_path|, changes its group owner to "vpn",
  // and makes it group-accessible (rwx).
  virtual bool PrepareConfigDirectory(
      const base::FilePath& directory_path) const = 0;

  // Writes |contents| into an anonymous file created by memfd_create(), and
  // returns its fd and the file path. Returns an invalid ScopedFD on failure.
  // Compared with the WriteConfigFile() function above, the file created by
  // this function has the following properties:
  // - Its path is in the form of `/proc/self/fd/{fd}`, and thus is accessible
  //   by the current process and the child processes forked by the current one,
  //   if the child process inherits the fd table of the current process.
  // - When all the fds (including fds owned by the parent process and child
  //   processes) pointing to this file are closed, the file will be removed
  //   automatically, and thus the caller does not need to delete the file
  //   explicitly. This guarantees that the file will disappear even if shill
  //   crashes.
  // Also see the man page for memfd_create() for more details.
  virtual std::pair<base::ScopedFD, base::FilePath> WriteAnonymousConfigFile(
      const std::string& contents) const = 0;

  // Creates a scoped temp directory under |parent_path|, changes its group to
  // "vpn", and give it group RWX permission. This directory can be used to
  // share the config files between shill and the vpn process, or as the run
  // directory for the vpn process. If failed, returns an invalid ScopedTmpDir.
  virtual base::ScopedTempDir CreateScopedTempDir(
      const base::FilePath& parent_path) const = 0;

 protected:
  VPNUtil() = default;
};

}  // namespace shill

#endif  // SHILL_VPN_VPN_UTIL_H_
