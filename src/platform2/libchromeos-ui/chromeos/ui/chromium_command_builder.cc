// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/ui/chromium_command_builder.h"

#include <sys/resource.h>

#include <algorithm>
#include <cstdarg>
#include <ctime>

#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/userdb_utils.h>
#include <cros_config/cros_config.h>

#include "chromeos/ui/util.h"

namespace chromeos {
namespace ui {

namespace {

// Location where GPU debug information is bind-mounted.
const char kDebugfsGpuPath[] = "/run/debugfs_gpu";

// Name of the release track field.
constexpr char kChromeosReleaseTrack[] = "CHROMEOS_RELEASE_TRACK";

// Prefix for test builds.
constexpr char kTestPrefix[] = "test";

// Returns the value associated with |key| in |pairs| or an empty string if the
// key isn't present. If the value is encapsulated in single or double quotes,
// they are removed.
std::string LookUpInStringPairs(const base::StringPairs& pairs,
                                const std::string& key) {
  for (size_t i = 0; i < pairs.size(); ++i) {
    if (key != pairs[i].first)
      continue;

    // Strip quotes.
    std::string value = pairs[i].second;
    if (value.size() >= 2U &&
        ((value[0] == '"' && value[value.size() - 1] == '"') ||
         (value[0] == '\'' && value[value.size() - 1] == '\'')))
      value = value.substr(1, value.size() - 2);

    return value;
  }
  return std::string();
}

// Returns true if |name| matches /^[A-Z][_A-Z0-9]+$/.
bool IsEnvironmentVariableName(const std::string& name) {
  if (name.empty() || !(name[0] >= 'A' && name[0] <= 'Z'))
    return false;
  for (size_t i = 1; i < name.size(); ++i) {
    char ch = name[i];
    if (ch != '_' && !(ch >= '0' && ch <= '9') && !(ch >= 'A' && ch <= 'Z'))
      return false;
  }
  return true;
}

// Splits |full|, a comma-separated list of values used for a flag like
// --vmodule or --enable-features.
std::vector<std::string> SplitFlagValues(const std::string& full) {
  return base::SplitString(full, ",", base::TRIM_WHITESPACE,
                           base::SPLIT_WANT_NONEMPTY);
}

// Returns true if |lsb_data| has a field called "CHROMEOS_RELEASE_TRACK",
// and its value starts with "test".
bool IsTestBuild(const std::string& lsb_data) {
  for (const auto& field : base::SplitStringPiece(
           lsb_data, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    std::vector<base::StringPiece> tokens = base::SplitStringPiece(
        field, "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    if (tokens.size() == 2 && tokens[0] == kChromeosReleaseTrack)
      return base::StartsWith(tokens[1], kTestPrefix);
  }
  return false;
}

// Returns true if |str| has prefix in |prefixes|.
bool HasPrefix(const std::string& str, const std::set<std::string>& prefixes) {
  for (const auto& prefix : prefixes) {
    if (base::StartsWith(str, prefix, base::CompareCase::SENSITIVE))
      return true;
  }
  return false;
}

}  // namespace

const char ChromiumCommandBuilder::kUser[] = "chronos";
const char ChromiumCommandBuilder::kUseFlagsPath[] = "/etc/ui_use_flags.txt";
const char ChromiumCommandBuilder::kLsbReleasePath[] = "/etc/lsb-release";
const char ChromiumCommandBuilder::kTimeZonePath[] =
    "/var/lib/timezone/localtime";
const char ChromiumCommandBuilder::kDefaultZoneinfoPath[] =
    "/usr/share/zoneinfo/US/Pacific";
const char ChromiumCommandBuilder::kPepperPluginsPath[] =
    "/opt/google/chrome/pepper";
const char ChromiumCommandBuilder::kVmoduleFlag[] = "vmodule";
const char ChromiumCommandBuilder::kEnableFeaturesFlag[] = "enable-features";
const char ChromiumCommandBuilder::kDisableFeaturesFlag[] = "disable-features";
const char ChromiumCommandBuilder::kEnableBlinkFeaturesFlag[] =
    "enable-blink-features";
const char ChromiumCommandBuilder::kDisableBlinkFeaturesFlag[] =
    "disable-blink-features";
const char ChromiumCommandBuilder::kCrosConfigIdentityPath[] = "/identity";
const char ChromiumCommandBuilder::kCrosConfigPlatformName[] = "platform-name";

ChromiumCommandBuilder::ChromiumCommandBuilder() = default;

ChromiumCommandBuilder::~ChromiumCommandBuilder() = default;

bool ChromiumCommandBuilder::Init() {
  if (!brillo::userdb::GetUserInfo(kUser, &uid_, &gid_))
    return false;

  // Read the list of USE flags that were set at build time.
  std::string data;
  if (!base::ReadFileToString(GetPath(kUseFlagsPath), &data)) {
    PLOG(ERROR) << "Unable to read " << kUseFlagsPath;
    return false;
  }
  std::vector<std::string> lines = base::SplitString(
      data, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  for (size_t i = 0; i < lines.size(); ++i) {
    if (!lines[i].empty() && lines[i][0] != '#')
      use_flags_.insert(lines[i]);
  }

  base::CommandLine cl(base::FilePath("crossystem"));
  cl.AppendArg("mainfw_type");
  std::string output;
  if (base::GetAppOutput(cl, &output)) {
    base::TrimWhitespaceASCII(output, base::TRIM_TRAILING, &output);
    is_chrome_os_hardware_ = (output != "nonchrome");
  }

  is_developer_end_user_ = base::GetAppOutput(
      base::CommandLine(base::FilePath("is_developer_end_user")), &output);

  // Provide /etc/lsb-release contents and timestamp so that they are available
  // to Chrome immediately without requiring a blocking file read.
  const base::FilePath lsb_path(GetPath(kLsbReleasePath));
  base::File::Info info;
  if (!base::ReadFileToString(lsb_path, &lsb_data_) ||
      !base::GetFileInfo(lsb_path, &info)) {
    LOG(ERROR) << "Unable to read or stat " << kLsbReleasePath;
    return false;
  }
  lsb_release_time_ = info.creation_time;
  is_test_build_ = IsTestBuild(lsb_data_);
  return true;
}

bool ChromiumCommandBuilder::SetUpChromium() {
  AddEnvVar("USER", kUser);
  AddEnvVar("LOGNAME", kUser);
  AddEnvVar("SHELL", "/bin/sh");
  AddEnvVar("PATH", "/bin:/usr/bin");
  AddEnvVar("XDG_RUNTIME_DIR", "/run/chrome");

  const base::FilePath data_dir(GetPath("/home").Append(kUser));
  AddEnvVar("DATA_DIR", data_dir.value());
  if (!util::EnsureDirectoryExists(data_dir, uid_, gid_, 0755))
    return false;

  AddEnvVar("LSB_RELEASE", lsb_data_);
  AddEnvVar("LSB_RELEASE_TIME",
            base::NumberToString(lsb_release_time_.ToTimeT()));

  // By default, libdbus treats all warnings as fatal errors. That's too strict.
  AddEnvVar("DBUS_FATAL_WARNINGS", "0");

  // Prevent Flash asserts from crashing the plugin process.
  AddEnvVar("DONT_CRASH_ON_ASSERT", "1");

  // Create the target for the /etc/localtime symlink. This allows the Chromium
  // process to change the time zone.
  const base::FilePath time_zone_symlink(GetPath(kTimeZonePath));
  CHECK(util::EnsureDirectoryExists(time_zone_symlink.DirName(), uid_, gid_,
                                    0755));
  if (!base::PathExists(time_zone_symlink)) {
    // base::PathExists() dereferences symlinks, so make sure that there's not a
    // dangling symlink there before we create a new link.
    base::DeleteFile(time_zone_symlink);
    PCHECK(base::CreateSymbolicLink(base::FilePath(kDefaultZoneinfoPath),
                                    time_zone_symlink));
  }

  // Increase soft limit of file descriptors to 2048 (default is 1024).
  // Increase hard limit of file descriptors to 16384 (default is 4096).
  // Some offline websites using IndexedDB are particularly hungry for
  // descriptors, so the default is insufficient. See crbug.com/251385.
  // Native GPU memory buffer requires a FD per texture. See crbug.com/629521.
  struct rlimit limit;
  limit.rlim_cur = 2048;
  limit.rlim_max = 16384;
  if (setrlimit(RLIMIT_NOFILE, &limit) < 0)
    PLOG(ERROR) << "Setting max FDs with setrlimit() failed";

  // Increase the limits of mlockable memory so that Chrome may mlock text
  // pages that have been copied into memory that can be backed by huge pages.
  limit.rlim_cur = 256 * 1024 * 1024;
  limit.rlim_max = 256 * 1024 * 1024;
  if (setrlimit(RLIMIT_MEMLOCK, &limit) < 0)
    PLOG(ERROR) << "Setting memlock limit failed";

  // Disable sandboxing as it causes crashes in ASAN: crbug.com/127536
  bool disable_sandbox = false;
  disable_sandbox |= SetUpASAN();
  if (disable_sandbox)
    AddArg("--no-sandbox");

  SetUpPepperPlugins();
  AddUiFlags();

  if (UseFlagIsSet("passive_event_listeners"))
    AddArg("--passive-listeners-default=true");

  AddArg("--enable-logging");
  AddArg("--log-level=1");
  AddArg("--use-cras");
  AddArg("--enable-wayland-server");

  return true;
}

bool ChromiumCommandBuilder::ApplyUserConfig(
    const base::FilePath& path,
    const std::set<std::string>& disallowed_prefixes) {
  std::string data;
  if (!base::ReadFileToString(path, &data)) {
    PLOG(WARNING) << "Unable to read " << path.value();
    return false;
  }

  bool has_vmodule_flag = false;

  std::vector<std::string> lines = base::SplitString(
      data, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  for (size_t i = 0; i < lines.size(); ++i) {
    std::string line;
    base::TrimWhitespaceASCII(lines[i], base::TRIM_ALL, &line);
    if (line.empty() || line[0] == '#')
      continue;

    if (line[0] == '!' && line.size() > 1) {
      DeleteArgsWithPrefix(line.substr(1, line.size() - 1));
      continue;
    }

    base::StringPairs pairs;
    base::SplitStringIntoKeyValuePairs(line, '=', '\n', &pairs);
    if (pairs.size() != 1U) {
      if (!HasPrefix(line, disallowed_prefixes))
        AddArg(line);
      continue;
    }

    // Everything else takes the form "name=value".
    const std::string& name = pairs[0].first;
    const std::string& value = pairs[0].second;

    // Bare "vmodule" and "enable-features" directives were used up until
    // November 2017; we continue supporting them for backwards compatibility
    // with existing configs and developer behavior.
    if (name == kVmoduleFlag || name == std::string("--") + kVmoduleFlag) {
      has_vmodule_flag = true;
      for (const auto& pattern : SplitFlagValues(value))
        AddVmodulePattern(pattern);
    } else if (name == kEnableFeaturesFlag ||
               name == std::string("--") + kEnableFeaturesFlag) {
      for (const auto& feature : SplitFlagValues(value))
        AddFeatureEnableOverride(feature);
    } else if (name == std::string("--") + kDisableFeaturesFlag) {
      for (const auto& feature : SplitFlagValues(value))
        AddFeatureDisableOverride(feature);
    } else if (name == std::string("--") + kEnableBlinkFeaturesFlag) {
      for (const auto& feature : SplitFlagValues(value))
        AddBlinkFeatureEnableOverride(feature);
    } else if (name == std::string("--") + kDisableBlinkFeaturesFlag) {
      for (const auto& feature : SplitFlagValues(value))
        AddBlinkFeatureDisableOverride(feature);
    } else if (IsEnvironmentVariableName(name)) {
      AddEnvVar(name, value);
    } else if (!HasPrefix(line, disallowed_prefixes)) {
      AddArg(line);
    }
  }

  if (has_vmodule_flag) {
    LOG(WARNING) << "--vmodule detected. Note that Ash Chrome on ChromeOS "
                    "defaults to use build-time VLOG so --vmodule is ignored. "
                    "To use --vmodule, Please make sure your chrome is built "
                    "with `use_runtime_vlog = true` gn arg.";
  }

  return true;
}

bool ChromiumCommandBuilder::UseFlagIsSet(const std::string& flag) const {
  return use_flags_.count(flag) > 0;
}

void ChromiumCommandBuilder::AddEnvVar(const std::string& name,
                                       const std::string& value) {
  environment_variables_[name] = value;
}

std::string ChromiumCommandBuilder::ReadEnvVar(const std::string& name) const {
  StringMap::const_iterator it = environment_variables_.find(name);
  CHECK(it != environment_variables_.end()) << name << " hasn't been set";
  return it->second;
}

void ChromiumCommandBuilder::AddArg(const std::string& arg) {
  // Check that we're not trying to add multiple copies of list-value flags
  // (since they wouldn't be handled correctly by Chrome).
  if (DCHECK_IS_ON()) {
    for (const auto& it : list_argument_indexes_) {
      DCHECK(!base::StartsWith(arg,
                               base::StringPrintf("--%s=", it.first.c_str()),
                               base::CompareCase::SENSITIVE))
          << "Must use Add*Pattern() for " << arg;
    }
  }

  arguments_.push_back(arg);
}

void ChromiumCommandBuilder::AddVmodulePattern(const std::string& pattern) {
  // Chrome's code for handling --vmodule applies the first matching pattern.
  // Prepend patterns here so that more-specific later patterns will override
  // more-general earlier ones.
  AddListFlagEntry(kVmoduleFlag, ",", pattern, true /* prepend */);
}

void ChromiumCommandBuilder::AddFeatureEnableOverride(
    const std::string& feature_name) {
  AddListFlagEntry(kEnableFeaturesFlag, ",", feature_name, false /* prepend */);
}

void ChromiumCommandBuilder::AddFeatureDisableOverride(
    const std::string& feature_name) {
  AddListFlagEntry(kDisableFeaturesFlag, ",", feature_name,
                   false /* prepend */);
}

void ChromiumCommandBuilder::AddBlinkFeatureEnableOverride(
    const std::string& feature_name) {
  AddListFlagEntry(kEnableBlinkFeaturesFlag, ",", feature_name,
                   false /* prepend */);
}

void ChromiumCommandBuilder::AddBlinkFeatureDisableOverride(
    const std::string& feature_name) {
  AddListFlagEntry(kDisableBlinkFeaturesFlag, ",", feature_name,
                   false /* prepend */);
}

base::FilePath ChromiumCommandBuilder::GetPath(const std::string& path) const {
  return util::GetReparentedPath(path, base_path_for_testing_);
}

void ChromiumCommandBuilder::DeleteArgsWithPrefix(const std::string& prefix) {
  size_t num_copied = 0;
  for (size_t src_index = 0; src_index < arguments_.size(); ++src_index) {
    // Preserve arguments that don't have the prefix.
    if (arguments_[src_index].find(prefix) != 0) {
      arguments_[num_copied] = arguments_[src_index];
      num_copied++;
      continue;
    }

    // Drop the argument by not copying it.

    // Shift saved indexes if needed.
    auto list_it = list_argument_indexes_.begin();
    while (list_it != list_argument_indexes_.end()) {
      if (list_it->second == src_index) {
        // If the list argument itself was deleted, then remove it from the map.
        list_argument_indexes_.erase(list_it++);
      } else {
        // Otherwise, decrement the index if it was after the deleted arg.
        if (list_it->second > src_index)
          list_it->second--;
        ++list_it;
      }
    }
  }
  arguments_.resize(num_copied);
}

void ChromiumCommandBuilder::AddListFlagEntry(
    const std::string& flag_name,
    const std::string& entry_separator,
    const std::string& new_entry,
    bool prepend) {
  if (new_entry.empty())
    return;

  const std::string flag_prefix =
      base::StringPrintf("--%s=", flag_name.c_str());

  const auto& it = list_argument_indexes_.find(flag_name);
  const int index = (it != list_argument_indexes_.end()) ? it->second : -1;

  if (index < 0) {
    AddArg(flag_prefix + new_entry);
    list_argument_indexes_[flag_name] = arguments_.size() - 1;
  } else if (prepend) {
    const std::string old = arguments_[index];
    DCHECK_EQ(old.substr(0, flag_prefix.size()), flag_prefix);
    arguments_[index] =
        flag_prefix + new_entry + entry_separator +
        old.substr(flag_prefix.size(), old.size() - flag_prefix.size());
  } else {
    arguments_[index] += entry_separator + new_entry;
  }
}

bool ChromiumCommandBuilder::SetUpASAN() {
  if (!UseFlagIsSet("asan"))
    return false;

  // Make glib use system malloc.
  AddEnvVar("G_SLICE", "always-malloc");

  // Make nss use system malloc.
  AddEnvVar("NSS_DISABLE_ARENA_FREE_LIST", "1");

  // Make nss skip dlclosing dynamically loaded modules, which would result in
  // "obj:*" in backtraces.
  AddEnvVar("NSS_DISABLE_UNLOAD", "1");

  // Make ASAN output to the file because Chrome stderr is /dev/null now
  // (crbug.com/156308).
  AddEnvVar("ASAN_OPTIONS",
            "log_path=/var/log/chrome/asan_log:detect_odr_violation=0");

  return true;
}

void ChromiumCommandBuilder::SetUpPepperPlugins() {
  std::vector<std::string> register_plugins;

  base::FileEnumerator enumerator(GetPath(kPepperPluginsPath),
                                  false /* recursive */,
                                  base::FileEnumerator::FILES);
  while (true) {
    const base::FilePath path = enumerator.Next();
    if (path.empty())
      break;

    if (path.Extension() != ".info")
      continue;

    std::string data;
    if (!base::ReadFileToString(path, &data)) {
      PLOG(ERROR) << "Unable to read " << path.value();
      continue;
    }

    // .info files are full of shell junk like #-prefixed comments, so don't
    // check that SplitStringIntoKeyValuePairs() successfully parses every line.
    base::StringPairs pairs;
    base::SplitStringIntoKeyValuePairs(data, '=', '\n', &pairs);

    const std::string file_name = LookUpInStringPairs(pairs, "FILE_NAME");
    const std::string plugin_name = LookUpInStringPairs(pairs, "PLUGIN_NAME");
    const std::string version = LookUpInStringPairs(pairs, "VERSION");

    if (file_name.empty()) {
      LOG(ERROR) << "Missing FILE_NAME in " << path.value();
      continue;
    }

    const std::string description = LookUpInStringPairs(pairs, "DESCRIPTION");
    const std::string mime_types = LookUpInStringPairs(pairs, "MIME_TYPES");

    std::string plugin_string = file_name;
    if (!plugin_name.empty()) {
      plugin_string += "#" + plugin_name;
      if (!description.empty()) {
        plugin_string += "#" + description;
        if (!version.empty()) {
          plugin_string += "#" + version;
        }
      }
    }
    plugin_string += ";" + mime_types;
    register_plugins.push_back(plugin_string);
  }

  if (!register_plugins.empty()) {
    std::sort(register_plugins.begin(), register_plugins.end());
    AddArg("--register-pepper-plugins=" +
           base::JoinString(register_plugins, ","));
  }
}

void ChromiumCommandBuilder::AddUiFlags() {
  // On boards with ARM NEON support, force libvpx to use the NEON-optimized
  // code paths. Remove once http://crbug.com/161834 is fixed.
  // This is needed because libvpx cannot check cpuinfo within the sandbox.
  if (UseFlagIsSet("neon"))
    AddEnvVar("VPX_SIMD_CAPS", "0xf");

  if (UseFlagIsSet("edge_touch_filtering"))
    AddArg("--edge-touch-filtering");

  if (UseFlagIsSet("native_gpu_memory_buffers"))
    AddArg("--enable-native-gpu-memory-buffers");

  if (UseFlagIsSet("disable_cros_video_decoder"))
    AddArg("--platform-disallows-chromeos-direct-video-decoder");

  if (UseFlagIsSet("arc_disable_cros_video_decoder"))
    AddFeatureDisableOverride("ArcVideoDecoder");

  // TODO(dcastagna): Get rid of the following code once the proper
  // configuration will be chosen at runtime on DRM atomic boards.
  if (UseFlagIsSet("drm_atomic")) {
    AddArg("--enable-webgl-image-chromium");
    AddFeatureEnableOverride("Pepper3DImageChromium");
  }

  if (UseFlagIsSet("big_little"))
    AddArg("--num-raster-threads=2");

  AddArg(std::string("--gpu-sandbox-failures-fatal=") +
         (is_chrome_os_hardware() &&
                  !UseFlagIsSet("gpu_sandbox_failures_not_fatal")
              ? "yes"
              : "no"));

  if (UseFlagIsSet("gpu_sandbox_allow_sysv_shm"))
    AddArg("--gpu-sandbox-allow-sysv-shm");

  if (UseFlagIsSet("gpu_sandbox_start_early"))
    AddArg("--gpu-sandbox-start-early");

  if (UseFlagIsSet("video_capture_use_gpu_memory_buffer"))
    AddArg("--video-capture-use-gpu-memory-buffer");

  if (UseFlagIsSet("disable_spectre_variant2_mitigation"))
    AddFeatureDisableOverride("SpectreVariant2Mitigation");

  // Disable Floss if the Floss USE flag was not set.
  if (!UseFlagIsSet("floss"))
    AddFeatureDisableOverride("FlossIsAvailable");

  // The display controller on SC7280 uses multiple planes when the screen
  // resolution is sufficiently wide, and we can run out of planes to display
  // the cursor on its own plane (e.g. if a 4k display is plugged in). Thus in
  // these cases, we default to the software cursor.
  // TODO(b/273509565): Remove this workaround when Chrome migrates off the
  // legacy cursor API and can properly test modesets with the cursor plane.
  brillo::CrosConfig cros_config;
  std::string platform_name;
  if (cros_config.GetString(kCrosConfigIdentityPath, kCrosConfigPlatformName,
                            &platform_name)) {
    if (platform_name == "Herobrine") {
      AddArg("--sw-cursor-on-wide-displays");
    }
  }

  // Allow Chrome to access GPU memory information despite /sys/kernel/debug
  // being owned by debugd. This limits the security attack surface versus
  // leaving the whole debug directory world-readable: http://crbug.com/175828
  // (Only do this if we're running as root, i.e. not in a test.)
  const base::FilePath debugfs_gpu_path(GetPath(kDebugfsGpuPath));
  if (getuid() == 0 && !base::DirectoryExists(debugfs_gpu_path)) {
    if (base::CreateDirectory(debugfs_gpu_path)) {
      util::Run("mount", "-o", "bind", "/sys/kernel/debug/dri/0",
                kDebugfsGpuPath, nullptr);
    } else {
      PLOG(ERROR) << "Unable to create " << kDebugfsGpuPath;
    }
  }
}

}  // namespace ui
}  // namespace chromeos
