// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEV_INSTALL_DEV_INSTALL_H_
#define DEV_INSTALL_DEV_INSTALL_H_

#include <sys/stat.h>

#include <istream>
#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace dev_install {

class DevInstall {
 public:
  DevInstall();
  DevInstall(const std::string& binhost,
             const std::string& binhost_version,
             bool reinstall,
             bool uninstall,
             bool yes,
             bool only_bootstrap,
             uint32_t jobs);
  DevInstall(const DevInstall&) = delete;
  DevInstall& operator=(const DevInstall&) = delete;

  // Run the dev_install routine.
  int Run();

  // Whether the system is currently in dev mode.
  virtual bool IsDevMode() const;

  // Prompts the user.
  virtual bool PromptUser(std::istream& input, const std::string& prompt);

  // Delete a path recursively on the same mount point.
  virtual bool DeletePath(const struct stat& base_stat,
                          const base::FilePath& dir);

  // Create a directory if it doesn't yet exist, and chmod it to 0755.
  bool CreateMissingDirectory(const base::FilePath& dir);

  // Write the data to the file.
  bool WriteFile(const base::FilePath& file, const std::string& data);

  // Clear the /usr/local state.
  virtual bool ClearStateDir(const base::FilePath& dir);

  // Initialize the /usr/local state.
  virtual bool InitializeStateDir(const base::FilePath& dir);

  // Load any runtime state we'll use later on.
  bool LoadRuntimeSettings(const base::FilePath& lsb_release);

  // Initialize binhost_ setting from other settings.
  void InitializeBinhost();

  // Detect the compression format used by |pkg|.
  std::string DetectCompression(const base::FilePath& pkg);

  // Download & manually install the bootstrap packages.
  virtual bool DownloadAndInstallBootstrapPackage(const std::string& package);
  virtual bool DownloadAndInstallBootstrapPackages(
      const base::FilePath& listing);

  // Configure the portage tooling state.
  virtual bool ConfigurePortage();

  // Install the extra set of packages.
  virtual bool InstallExtraPackages();

  // Unittest helpers.
  void SetReinstallForTest(bool reinstall) { reinstall_ = reinstall; }
  void SetUninstallForTest(bool uninstall) { uninstall_ = uninstall; }
  void SetYesForTest(bool yes) { yes_ = yes; }
  void SetStateDirForTest(const base::FilePath& dir) { state_dir_ = dir; }
  void SetBootstrapForTest(bool bootstrap) { only_bootstrap_ = bootstrap; }
  std::string GetDevserverUrlForTest() { return devserver_url_; }
  std::string GetBoardForTest() { return board_; }
  std::string GetBinhostVersionForTest() { return binhost_version_; }

 private:
  bool reinstall_;
  bool uninstall_;
  bool yes_;
  bool only_bootstrap_;
  base::FilePath state_dir_;
  std::string binhost_;
  std::string binhost_version_;
  int jobs_;
  // The URL to the devserver for local developer builds.
  std::string devserver_url_;
  // The active board for calculating default binhost.
  std::string board_;
};

}  // namespace dev_install

#endif  // DEV_INSTALL_DEV_INSTALL_H_
