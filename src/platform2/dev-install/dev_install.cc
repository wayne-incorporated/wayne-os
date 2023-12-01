// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dev-install/dev_install.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <istream>
#include <string>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/key_value_store.h>
#include <brillo/process/process.h>
#include <vboot/crossystem.h>

namespace dev_install {

namespace {

// The root path that we install our dev packages into.
constexpr char kUsrLocal[] = "/usr/local";

// The Portage config path as a subdir under the various roots.
constexpr char kPortageConfigSubdir[] = "etc/portage";

// Where binpkgs are saved as a subdir under the various roots.
constexpr char kBinpkgSubdir[] = "portage/packages";

// File listing of packages we need for bootstrapping.
constexpr char kBootstrapListing[] =
    "/usr/share/dev-install/bootstrap.packages";

// Directory of rootfs provided packages.
constexpr char kRootfsProvidedDir[] = "/usr/share/dev-install/rootfs.provided";

// Path to lsb-release file.
constexpr char kLsbReleasePath[] = "/etc/lsb-release";

// The devserer URL for this developer build.
constexpr char kLsbChromeosDevserver[] = "CHROMEOS_DEVSERVER";

// The current OS version.
constexpr char kLsbChromeosReleaseVersion[] = "CHROMEOS_RELEASE_VERSION";

// Setting for the board name.
constexpr char kLsbChromeosReleaseBoard[] = "CHROMEOS_RELEASE_BOARD";

// The base URL of the repository holding our portage prebuilt binpkgs.
constexpr char kDefaultBinhostPrefix[] =
    "https://commondatastorage.googleapis.com/chromeos-dev-installer/board";

// Portage binpkgs append metadata to the end of the bzip2 file which makes
// bzip2 warn "trailing garbage after EOF ignored".  This is harmless, but
// can be confusing & noisy, so suppress it with -q.
constexpr char kBzip2Cmd[] = "bzip2 -q";
constexpr uint8_t kBzip2Magic[] = {0x42, 0x5a, 0x68};

// Similarly, use zstd's -f to ignore that trailing data.
constexpr char kZstdCmd[] = "zstd -f";
constexpr uint8_t kZstdMagic[] = {0x28, 0xb5, 0x2f, 0xfd};

}  // namespace

DevInstall::DevInstall()
    : reinstall_(false),
      uninstall_(false),
      yes_(false),
      only_bootstrap_(false),
      state_dir_(kUsrLocal),
      binhost_(""),
      binhost_version_(""),
      jobs_(0) {}

DevInstall::DevInstall(const std::string& binhost,
                       const std::string& binhost_version,
                       bool reinstall,
                       bool uninstall,
                       bool yes,
                       bool only_bootstrap,
                       uint32_t jobs)
    : reinstall_(reinstall),
      uninstall_(uninstall),
      yes_(yes),
      only_bootstrap_(only_bootstrap),
      state_dir_(kUsrLocal),
      binhost_(binhost),
      binhost_version_(binhost_version),
      jobs_(jobs) {}

bool DevInstall::IsDevMode() const {
  int value = ::VbGetSystemPropertyInt("cros_debug");
  return value == 1;
}

bool DevInstall::PromptUser(std::istream& input, const std::string& prompt) {
  if (yes_)
    return true;

  std::cout << prompt << "? (y/N) " << std::flush;

  std::string buffer;
  if (std::getline(input, buffer)) {
    return (buffer == "y" || buffer == "y\n");
  }
  return false;
}

// We have a custom DeletePath helper because we don't want to descend across
// mount points, and no base:: helper supports that.
bool DevInstall::DeletePath(const struct stat& base_stat,
                            const base::FilePath& dir) {
  base::FileEnumerator iter(dir, true,
                            base::FileEnumerator::FILES |
                                base::FileEnumerator::DIRECTORIES |
                                base::FileEnumerator::SHOW_SYM_LINKS);
  for (base::FilePath current = iter.Next(); !current.empty();
       current = iter.Next()) {
    const auto& info(iter.GetInfo());
    if (info.IsDirectory()) {
      // Abort if the dir is mounted.
      if (base_stat.st_dev != info.stat().st_dev) {
        LOG(ERROR) << "directory is mounted: " << current.value();
        return false;
      }

      // Clear the contents of this directory.
      if (!DeletePath(base_stat, current))
        return false;

      // Clear this directory itself.
      if (rmdir(current.value().c_str())) {
        PLOG(ERROR) << "deleting failed: " << current.value();
        return false;
      }
    } else {
      if (unlink(current.value().c_str())) {
        PLOG(ERROR) << "deleting failed: " << current.value();
        return false;
      }
    }
  }

  return true;
}

bool DevInstall::CreateMissingDirectory(const base::FilePath& dir) {
  if (!base::PathExists(dir)) {
    if (!base::CreateDirectory(dir) ||
        !base::SetPosixFilePermissions(dir, 0755)) {
      PLOG(ERROR) << "Creating " << dir.value() << " failed";
      return false;
    }
  }

  return true;
}

bool DevInstall::WriteFile(const base::FilePath& file,
                           const std::string& data) {
  if (base::WriteFile(file, data.c_str(), data.size()) != data.size()) {
    PLOG(ERROR) << "Could not write " << file.value();
    return false;
  }

  return true;
}

bool DevInstall::ClearStateDir(const base::FilePath& dir) {
  LOG(INFO) << "To clean up, we will run:\n  rm -rf /usr/local/\n"
            << "Any content you have stored in there will be deleted.";
  if (!PromptUser(std::cin, "Remove all installed packages now")) {
    LOG(INFO) << "Operation cancelled.";
    return false;
  }

  // Normally we'd use base::DeleteFile, but we don't want to traverse mounts.
  struct stat base_stat;
  if (stat(dir.value().c_str(), &base_stat)) {
    if (errno == ENOENT)
      return true;

    PLOG(ERROR) << "Could not access " << dir.value();
    return false;
  }

  bool success = DeletePath(base_stat, dir);
  if (success)
    LOG(INFO) << "Removed all installed packages.";
  else
    LOG(ERROR) << "Deleting " << dir.value() << " failed";
  return success;
}

bool DevInstall::InitializeStateDir(const base::FilePath& dir) {
  // Create this loop so uncompressed files in /usr/local/usr/ will be reachable
  // through /usr/local/.
  // Note: /usr/local is mount-binded onto the /mnt/stateful_partition/dev_mode
  // during chromeos_startup during boot for machines in dev_mode.
  const base::FilePath usr = dir.Append("usr");
  if (!base::PathExists(usr)) {
    // Create /usr/local/usr -> . symlink.
    if (!base::CreateSymbolicLink(base::FilePath("."), usr)) {
      PLOG(ERROR) << "Creating " << usr.value() << " failed";
      return false;
    }
  }

  // Setup a /tmp space for random scripts to rely on.
  const base::FilePath tmp = dir.Append("tmp");
  if (!base::PathExists(tmp)) {
    // Can't use base::SetPosixFilePermissions as that blocks +t mode.
    if (!base::CreateDirectory(tmp) || chmod(tmp.value().c_str(), 01777)) {
      PLOG(ERROR) << "Creating " << tmp.value() << " failed";
      return false;
    }
  }

  const base::FilePath local = usr.Append("local");
  if (!base::PathExists(local)) {
    // Create /usr/local/usr/local -> . symlink.
    if (!base::CreateSymbolicLink(base::FilePath("."), local)) {
      PLOG(ERROR) << "Creating " << local.value() << " failed";
      return false;
    }
  }

  // Set up symlinks for etc/{group,passwd}, so that packages can look up users
  // and groups correctly.
  const base::FilePath etc = usr.Append("etc");
  if (!CreateMissingDirectory(etc))
    return false;

  // Create /usr/local/etc/group -> /etc/group symlink.
  const base::FilePath group = etc.Append("group");
  if (!base::PathExists(group)) {
    if (!base::CreateSymbolicLink(base::FilePath("/etc/group"), group)) {
      PLOG(ERROR) << "Creating " << group.value() << " failed";
      return false;
    }
  }

  // Create /usr/local/etc/passwd -> /etc/passwd symlink.
  const base::FilePath passwd = etc.Append("passwd");
  if (!base::PathExists(passwd)) {
    if (!base::CreateSymbolicLink(base::FilePath("/etc/passwd"), passwd)) {
      PLOG(ERROR) << "Creating " << passwd.value() << " failed";
      return false;
    }
  }

  return true;
}

bool DevInstall::LoadRuntimeSettings(const base::FilePath& lsb_release) {
  brillo::KeyValueStore store;
  if (!store.Load(lsb_release)) {
    PLOG(WARNING) << "Could not read " << kLsbReleasePath;
    return true;
  }

  if (!store.GetString(kLsbChromeosDevserver, &devserver_url_))
    devserver_url_.clear();

  if (store.GetString(kLsbChromeosReleaseBoard, &board_)) {
    size_t pos = board_.find("-signed-");
    if (pos != std::string::npos)
      board_.erase(pos);
  } else {
    board_.clear();
  }

  // If --binhost_version wasn't specified, calculate it.
  if (binhost_version_.empty()) {
    store.GetString(kLsbChromeosReleaseVersion, &binhost_version_);
  }

  return true;
}

void DevInstall::InitializeBinhost() {
  if (!binhost_.empty())
    return;

  if (!devserver_url_.empty()) {
    LOG(INFO) << "Devserver URL set to: " << devserver_url_;
    if (PromptUser(std::cin, "Use it as the binhost")) {
      binhost_ = devserver_url_ + "/static/pkgroot/" + board_ + "/packages";
      return;
    }
  }

  binhost_ = std::string(kDefaultBinhostPrefix) + "/" + board_ + "/" +
             binhost_version_ + "/packages";
}

std::string DevInstall::DetectCompression(const base::FilePath& pkg) {
  char bytes[4];
  if (ReadFile(pkg, bytes, sizeof(bytes)) == -1) {
    // TODO(vapier): Switch this to zstd by 2022 Q4.
    PLOG(WARNING) << "Unable to detect compression; assuming bzip2";
    return kBzip2Cmd;
  }

  if (memcmp(bytes, kZstdMagic, sizeof(kZstdMagic)) == 0) {
    return kZstdCmd;
  } else if (memcmp(bytes, kBzip2Magic, sizeof(kBzip2Magic)) == 0) {
    return kBzip2Cmd;
  } else {
    // TODO(vapier): Switch this to zstd by 2022 Q4.
    LOG(WARNING) << "Unknown magic signature; assuming bzip2";
    return kBzip2Cmd;
  }
}

bool DevInstall::DownloadAndInstallBootstrapPackage(
    const std::string& package) {
  const std::string url(binhost_ + "/" + package + ".tbz2");
  const base::FilePath binpkg_dir = state_dir_.Append(kBinpkgSubdir);
  const base::FilePath pkg = binpkg_dir.Append(package + ".tbz2");
  const base::FilePath pkgdir = pkg.DirName();

  if (!CreateMissingDirectory(pkgdir))
    return false;

  LOG(INFO) << "Downloading " << url;
  brillo::ProcessImpl curl;
  curl.SetSearchPath(true);
  curl.AddArg("curl");
  curl.AddArg("--fail");
  curl.AddStringOption("-o", pkg.value());
  curl.AddArg(url);
  if (curl.Run() != 0) {
    LOG(ERROR) << "Could not download package";
    return false;
  }

  LOG(INFO) << "Unpacking " << pkg.value();
  brillo::ProcessImpl tar;
  tar.SetSearchPath(true);
  tar.AddArg("tar");
  tar.AddStringOption("-C", state_dir_.value());
  tar.AddStringOption("-I", DetectCompression(pkg));
  tar.AddArg("-xkf");
  tar.AddArg(pkg.value());
  if (tar.Run() != 0) {
    LOG(ERROR) << "Could not extract package";
    return false;
  }

  return true;
}

bool DevInstall::DownloadAndInstallBootstrapPackages(
    const base::FilePath& listing) {
  std::string data;
  if (!base::ReadFileToString(listing, &data)) {
    PLOG(ERROR) << "Unable to read " << listing.value();
    return false;
  }

  std::vector<std::string> lines = base::SplitString(
      data, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  if (lines.empty()) {
    LOG(ERROR) << "Bootstrap package set is empty!";
    return false;
  }
  for (const std::string& line : lines) {
    if (!DownloadAndInstallBootstrapPackage(line))
      return false;
  }

  // The python ebuilds set up symlinks in pkg_postinst, but we don't run those
  // phases (we just run untar above).  Plus that logic depends on eselect that
  // we currently stub out.  Hand create the symlinks https://crbug.com/955147.
  const base::FilePath python = state_dir_.Append("usr/bin/python");
  if (!base::PathExists(python)) {
    if (!base::CreateSymbolicLink(base::FilePath("python-wrapper"), python)) {
      PLOG(ERROR) << "Creating " << python.value() << " failed";
      return false;
    }
  }
  const base::FilePath python2 = state_dir_.Append("usr/bin/python2");
  if (!base::PathExists(python2)) {
    if (!base::CreateSymbolicLink(base::FilePath("python2.7"), python2)) {
      PLOG(ERROR) << "Creating " << python2.value() << " failed";
      return false;
    }
  }
  const base::FilePath python3 = state_dir_.Append("usr/bin/python3");
  if (!base::PathExists(python3)) {
    if (!base::CreateSymbolicLink(base::FilePath("python3.6"), python3)) {
      PLOG(ERROR) << "Creating " << python3.value() << " failed";
      return false;
    }
  }

  return true;
}

bool DevInstall::ConfigurePortage() {
  const base::FilePath portage_dir = state_dir_.Append(kPortageConfigSubdir);
  const base::FilePath profile_dir = portage_dir.Append("make.profile");

  // Copy emerge configuration to /usr/local.
  if (!CreateMissingDirectory(profile_dir))
    return false;

  // Point our local profile to the rootfs one.  This allows us to stack.
  const base::FilePath parent_path = profile_dir.Append("parent");
  const std::string parent_data{"/etc/portage/make.profile\n"};
  if (!WriteFile(parent_path, parent_data))
    return false;

  // Install the package.provided entries for the rootfs.
  const base::FilePath provided_path = profile_dir.Append("package.provided");
  if (!CreateMissingDirectory(provided_path))
    return false;
  const base::FilePath rootfs_provided{kRootfsProvidedDir};
  base::FileEnumerator profile_iter(rootfs_provided, false,
                                    base::FileEnumerator::FILES);
  for (base::FilePath current = profile_iter.Next(); !current.empty();
       current = profile_iter.Next()) {
    const base::FilePath sym = provided_path.Append(current.BaseName());
    if (!base::CreateSymbolicLink(current, sym)) {
      PLOG(ERROR) << "Creating " << sym.value() << " failed";
      return false;
    }
  }

  // Create the directories defined in the portage config files. Permissions are
  // consistent with the other directories in /usr/local, which is a bind mount
  // for /mnt/stateful_partition/dev_image.
  //
  // We set ROOT in make.conf as portage ignores it in profile make.defaults.
  const base::FilePath make_conf_path = portage_dir.Append("make.conf");
  const std::string make_conf_data{"ROOT=\"" + state_dir_.value() +
                                   "\"\n"
                                   "PORTAGE_BINHOST=\"" +
                                   binhost_ + "\"\n"};
  if (!WriteFile(make_conf_path, make_conf_data))
    return false;

  // Hack in LD_LIBRARY_PATH within portage env.  Otherwise builds will filter
  // it out which breaks python as it can't find its libs in /usr/local.  This
  // only shows up on base images as those won't have ldconfig run since the
  // rootfs is read-only.  See https://crbug.com/1065727 for examples.
  //
  // The path we search for will be:
  // /usr/local/ (state_dir_)
  //   lib*/python*/site-packages/portage/ (internal python packages dir)
  //     package/ebuild/_config/special_env_vars.py
  //
  // We do this manually because base::FileEnumerator is unable to handle
  // symlink loops which we have in /usr/local by design.
  bool found_file = false;
  base::FileEnumerator lib_iter(state_dir_, false,
                                base::FileEnumerator::DIRECTORIES, "lib*");
  for (auto lib_current = lib_iter.Next(); !lib_current.empty();
       lib_current = lib_iter.Next()) {
    base::FileEnumerator python_iter(
        lib_current, false, base::FileEnumerator::DIRECTORIES, "python3.*");
    for (auto python_current = python_iter.Next(); !python_current.empty();
         python_current = python_iter.Next()) {
      const auto current = python_current.Append(
          "site-packages/portage/package/ebuild/_config/special_env_vars.py");
      if (!base::PathExists(current)) {
        LOG(WARNING) << "Portage file does not exist: " << current.value();
        continue;
      }

      found_file = true;
      LOG(INFO) << "Hacking portage file for dev-install " << current.value();

      // Load the file into memory.
      std::string data;
      if (!base::ReadFileToString(current, &data)) {
        PLOG(ERROR) << "Unable to read " << current.value();
        return false;
      }

      // Split it into lines.
      auto lines = base::SplitStringPiece(data, "\n", base::KEEP_WHITESPACE,
                                          base::SPLIT_WANT_ALL);
      if (lines.empty()) {
        LOG(ERROR) << "Portage internal file is empty: " << current.value();
        return false;
      }

      // Replace the one line that we need.
      const char kSearch[] = "environ_whitelist = []";
      const char kReplace[] = "environ_whitelist = ['LD_LIBRARY_PATH']";
      bool found_line = false;
      for (auto& line : lines) {
        if (line == kSearch) {
          found_line = true;
          line = kReplace;
        }
      }
      if (!found_line) {
        LOG(WARNING) << current.value() << ": Unable to find line to modify!";
      }

      // Write it back out.
      data = base::JoinString(lines, "\n");
      if (!base::WriteFile(current, data.data(), data.size())) {
        LOG(ERROR) << "Unable to write " << current.value();
        return false;
      }
    }
  }
  if (!found_file) {
    LOG(WARNING) << "Unable to locate internal portage special_env_vars.py!";
    LOG(WARNING) << "`emerge` might not work on your device; trying anyways.";
  }

  return true;
}

bool DevInstall::InstallExtraPackages() {
  if (!PromptUser(std::cin, "Install virtual/target-os-dev package now")) {
    LOG(INFO) << "You can install virtual/target-os-dev later by running:\n"
              << "emerge virtual/target-os-dev";
    return true;
  }

  brillo::ProcessImpl emerge;
  emerge.SetSearchPath(true);
  emerge.AddArg("emerge");
  int jobs = jobs_;
  if (jobs == 0)
    jobs = std::max(1L, sysconf(_SC_NPROCESSORS_ONLN) - 1);
  emerge.AddArg("--jobs=" + std::to_string(jobs));
  emerge.AddArg("virtual/target-os-dev");
  if (emerge.Run() != 0) {
    LOG(ERROR) << "Could not install virtual/target-os-dev";
    return false;
  }

  return true;
}

int DevInstall::Run() {
  // Only run if dev mode is enabled.
  if (!IsDevMode()) {
    LOG(ERROR) << "Chrome OS is not in developer mode";
    return 2;
  }

  // Handle reinstall & uninstall operations.
  if (reinstall_ || uninstall_) {
    if (!ClearStateDir(state_dir_))
      return 1;
    if (uninstall_)
      return 0;

    LOG(INFO) << "Reinstalling dev state";
  }

  // See if the system has been initialized already.
  const base::FilePath portage_dir = state_dir_.Append(kPortageConfigSubdir);
  if (base::DirectoryExists(portage_dir)) {
    LOG(ERROR) << "Directory " << portage_dir.value() << " exists.";
    LOG(ERROR) << "Did you mean dev_install --reinstall?";
    return 4;
  }

  // Initialize the base set of paths before we install any packages.
  if (!InitializeStateDir(state_dir_))
    return 5;

  // Load the settings from the active device.
  if (!LoadRuntimeSettings(base::FilePath(kLsbReleasePath)))
    return 6;

  // Parses flags to return the binhost or if none set, use the default binhost
  // set up from installation.
  InitializeBinhost();
  LOG(INFO) << "Using binhost: " << binhost_;

  // Bootstrap the setup.
  LOG(INFO) << "Starting installation of developer packages.";
  LOG(INFO) << "First, we download the necessary files.";
  if (!DownloadAndInstallBootstrapPackages(base::FilePath(kBootstrapListing)))
    return 7;

  if (only_bootstrap_) {
    LOG(INFO) << "Done installing bootstrap packages. Enjoy!";
    return 0;
  }

  LOG(INFO) << "Developer packages initialized; configuring portage.";
  if (!ConfigurePortage())
    return 8;

  LOG(INFO) << "Installing additional optional packages.";
  if (!InstallExtraPackages())
    return 9;

  LOG(INFO) << "Done! Enjoy! Or not, you choose!";
  return 0;
}

}  // namespace dev_install
