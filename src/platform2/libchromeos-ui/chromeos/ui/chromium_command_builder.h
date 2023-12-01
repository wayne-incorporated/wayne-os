// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBCHROMEOS_UI_CHROMEOS_UI_CHROMIUM_COMMAND_BUILDER_H_
#define LIBCHROMEOS_UI_CHROMEOS_UI_CHROMIUM_COMMAND_BUILDER_H_

#include <sys/types.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/time/time.h>
#include <brillo/brillo_export.h>

namespace chromeos {
namespace ui {

// ChromiumCommandBuilder facilitates building a command line for running a
// Chromium-derived binary and performing related setup.
class BRILLO_EXPORT ChromiumCommandBuilder {
 public:
  typedef std::map<std::string, std::string> StringMap;
  typedef std::vector<std::string> StringVector;

  // Name of user account used to run the binary.
  static const char kUser[];

  // Location of the file containing newline-separated USE flags that were set
  // when the system was built.
  static const char kUseFlagsPath[];

  // Location of the file containing .info files describing Pepper plugins.
  static const char kPepperPluginsPath[];

  // Location of the lsb-release file describing the system image.
  static const char kLsbReleasePath[];

  // Location of the user-writable target of the /etc/localtime symlink.
  static const char kTimeZonePath[];

  // Default zoneinfo file used if the time zone hasn't been explicitly set.
  static const char kDefaultZoneinfoPath[];

  // Names of Chromium flags (without "--" prefixes) that need to be merged due
  // to containing lists of comma-separated values.
  static const char kVmoduleFlag[];
  static const char kEnableFeaturesFlag[];
  static const char kDisableFeaturesFlag[];
  static const char kEnableBlinkFeaturesFlag[];
  static const char kDisableBlinkFeaturesFlag[];

  // Cros-config path for identity.
  static const char kCrosConfigIdentityPath[];

  // Cros-config name for the platform name attribute in the identity path.
  static const char kCrosConfigPlatformName[];

  ChromiumCommandBuilder();
  ChromiumCommandBuilder(const ChromiumCommandBuilder&) = delete;
  ChromiumCommandBuilder& operator=(const ChromiumCommandBuilder&) = delete;

  ~ChromiumCommandBuilder();

  uid_t uid() const { return uid_; }
  gid_t gid() const { return gid_; }
  bool is_chrome_os_hardware() const { return is_chrome_os_hardware_; }
  bool is_developer_end_user() const { return is_developer_end_user_; }
  bool is_test_build() const { return is_test_build_; }
  const StringMap& environment_variables() const {
    return environment_variables_;
  }
  const StringVector& arguments() const { return arguments_; }

  void set_base_path_for_testing(const base::FilePath& path) {
    base_path_for_testing_ = path;
  }

  // Performs just the basic initialization needed before UseFlagIsSet() can be
  // used. Returns true on success.
  bool Init();

  // Determines the environment variables and arguments that should be set for
  // all Chromium-derived binaries and updates |environment_variables_| and
  // |arguments_| accordingly. Also creates necessary directories, sets resource
  // limits, etc.
  //
  // Returns true on success.
  bool SetUpChromium();

  // Reads a user-supplied file requesting modifications to the current set of
  // arguments. The following directives are supported:
  //
  //   # This is a comment.
  //     Lines beginning with '#' are skipped.
  //
  //   --some-flag=some-value
  //     Calls AddArg("--some-flag=some-value").
  //
  //   !--flag-prefix
  //     Removes all arguments beginning with "--flag-prefix".
  //
  //   vmodule=foo=1
  //     Prepends a "foo=1" entry to the --vmodule flag.
  //
  //   enable-features=foo
  //     Appends a "foo" entry to the --enable-features flag.
  //
  //   NAME=VALUE
  //     Calls AddEnvVar("NAME", "VALUE").
  //
  // Any flags beginning with prefixes in |disallowed_prefixes| are disregarded.
  // Returns true on success.
  bool ApplyUserConfig(const base::FilePath& path,
                       const std::set<std::string>& disallowed_prefixes);

  // Returns true if a USE flag named |flag| was set when the system image was
  // built (and additionally listed in the libchromeos-use-flags ebuild so it
  // will be included in the file at kUseFlagsPath).
  bool UseFlagIsSet(const std::string& flag) const;

  // Adds an environment variable to |environment_variables_|. Note that this
  // method does not call setenv(); it is the caller's responsibility to
  // actually export the variables.
  void AddEnvVar(const std::string& name, const std::string& value);

  // Returns the value of an environment variable previously added via
  // AddEnvVar(). Crashes if the variable isn't set. Note that this method does
  // not call getenv().
  std::string ReadEnvVar(const std::string& name) const;

  // Adds a command-line argument. For --vmodule, --enable-features, or
  // --enable-blink-features flags (which contain lists of values that must be
  // merged), use the following dedicated methods instead.
  void AddArg(const std::string& arg);

  // Prepends |pattern| to the --vmodule flag in |arguments_|.
  void AddVmodulePattern(const std::string& pattern);

  // Appends |feature_name| to the --enable-features or --disable-features flag
  // in |arguments_|.
  void AddFeatureEnableOverride(const std::string& feature_name);
  void AddFeatureDisableOverride(const std::string& feature_name);

  // Appends |feature_name| to the --enable-blink-features or
  // --disable-blink-features flag in |arguments_|.
  void AddBlinkFeatureEnableOverride(const std::string& feature_name);
  void AddBlinkFeatureDisableOverride(const std::string& feature_name);

 private:
  // Converts absolute path |path| into a base::FilePath, rooting it under
  // |base_path_for_testing_| if it's non-empty.
  base::FilePath GetPath(const std::string& path) const;

  // Removes arguments beginning with |prefix| from |arguments_|.
  void DeleteArgsWithPrefix(const std::string& prefix);

  // Adds an entry to a flag containing a list of values. For example, for a
  // flag like "--my-list=foo,bar", |flag_name| would be "my-list",
  // |entry_separator| would be ",", and |new_entry| would be "foo" or "bar". If
  // |prepend| is true, |new_entry| will be prepended before existing values;
  // otherwise it will be appended after them.
  void AddListFlagEntry(const std::string& flag_name,
                        const std::string& entry_separator,
                        const std::string& new_entry,
                        bool prepend);

  // Checks if an ASAN build was requested, doing appropriate initialization and
  // returning true if so. Called by InitChromium().
  bool SetUpASAN();

  // Reads .info files in |pepper_plugins_path_| and adds the appropriate
  // arguments to |arguments_|. Called by InitChromium().
  void SetUpPepperPlugins();

  // Add UI- and compositing-related flags to |arguments_|.
  void AddUiFlags();

  // Path under which files are created when running in a test.
  base::FilePath base_path_for_testing_;

  // UID and GID of the user used to run the binary.
  uid_t uid_ = 0;
  gid_t gid_ = 0;

  // USE flags that were set when the system was built.
  std::set<std::string> use_flags_;

  // True if official Chrome OS hardware is being used.
  bool is_chrome_os_hardware_ = false;

  // True if this is a developer system, per the is_developer_end_user command.
  bool is_developer_end_user_ = false;

  // True if this is a test build, per CHROMEOS_RELEASE_TRACK in
  // /etc/lsb-release.
  bool is_test_build_ = false;

  // Data in /etc/lsb-release.
  std::string lsb_data_;

  // Creation time of /etc/lsb-release.
  base::Time lsb_release_time_;

  // Environment variables that the caller should export before starting the
  // executable.
  StringMap environment_variables_;

  // Command-line arguments that the caller should pass to the executable.
  StringVector arguments_;

  // Index in |arguments_| of list-based flags (e.g. --vmodule,
  // --enable-features), keyed by base flag name (e.g. "vmodule",
  // "enable-features"). Flags that have not been set are not included.
  std::map<std::string, int> list_argument_indexes_;
};

}  // namespace ui
}  // namespace chromeos

#endif  // LIBCHROMEOS_UI_CHROMEOS_UI_CHROMIUM_COMMAND_BUILDER_H_
