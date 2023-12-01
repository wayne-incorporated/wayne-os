/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_RELOADABLE_CONFIG_FILE_H_
#define CAMERA_COMMON_RELOADABLE_CONFIG_FILE_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_path_watcher.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/scoped_refptr.h>
#include <base/synchronization/lock.h>
#include <base/task/sequenced_task_runner.h>
#include <base/values.h>

#include "cros-camera/common.h"
#include "cros-camera/export.h"

namespace cros {

// An abstraction for a JSON-based config file. ReloadableConfigFile by default
// loads the config from a given default path, which usually resides in the root
// filesystem and is read-only. ReloadableConfigFile can be further configured
// to monitor an override config file and it will reload new configs from the
// override config file when the file content changes.
class CROS_CAMERA_EXPORT ReloadableConfigFile {
 public:
  struct Options {
    // The path to the default config file. The config is read from
    // |default_config_file_path| first if the path exists.
    base::FilePath default_config_file_path;

    // The path to the override config file. |override_config_file_path| will be
    // actively monitored at run-time, and we will overwrite the existing
    // |options_| values with the ones present in the override config file. The
    // config in the override file doesn't have to include all the options and
    // it can update only a subset of the options.
    base::FilePath override_config_file_path = base::FilePath();
  };

  using OptionsUpdateCallback =
      base::RepeatingCallback<void(const base::Value::Dict&)>;

  explicit ReloadableConfigFile(const Options& options);
  ReloadableConfigFile(const ReloadableConfigFile& other) = delete;
  ReloadableConfigFile& operator=(const ReloadableConfigFile& other) = delete;
  ~ReloadableConfigFile();

  // Set the callback to be called when the config file changes. |callback|
  // will either be called synchronously before this returns, or be called on
  // the sequence that the constructor of this ReloadableConfigFile is called.
  void SetCallback(OptionsUpdateCallback callback);

  // Stops the file path watcher for the override config file. By default the
  // watcher is destructed along with the ReloadableConfigFile instance.
  void StopOverrideFileWatcher();

  void UpdateOption(std::string key, base::Value value);
  base::Value::Dict CloneJsonValues() const;
  bool IsValid() const;

 private:
  void ReadConfigFileLocked(const base::FilePath& file_path);
  void WriteConfigFileLocked(const base::FilePath& file_path);
  void OnConfigFileUpdated(const base::FilePath& file_path, bool error);

  OptionsUpdateCallback options_update_callback_ = base::NullCallback();

  // The default config file path. Usually this points to the device-specific
  // tuning file shipped with the OS image.
  base::FilePath default_config_file_path_;
  // The override config file path. The override config is used to override the
  // default config at run-time for development or debugging purposes.
  base::FilePath override_config_file_path_;
  std::unique_ptr<base::FilePathWatcher> override_file_path_watcher_;
  scoped_refptr<base::SequencedTaskRunner> file_path_watcher_runner_;

  base::Lock options_lock_;
  std::optional<base::Value::Dict> json_values_ GUARDED_BY(options_lock_);
};

// Helper functions to look up |key| in |json_values| and, if key exists, load
// the corresponding value into |output|. Returns true if |output| is loaded
// with the value found, false otherwise.
CROS_CAMERA_EXPORT bool LoadIfExist(const base::Value::Dict& json_values,
                                    const char* key,
                                    float* output);
CROS_CAMERA_EXPORT bool LoadIfExist(const base::Value::Dict& json_values,
                                    const char* key,
                                    int* output);
CROS_CAMERA_EXPORT bool LoadIfExist(const base::Value::Dict& json_values,
                                    const char* key,
                                    bool* output);

template <typename T>
bool LoadIfExist(const base::Value::Dict& json_values,
                 const char* key,
                 std::vector<T>* output) {
  static_assert(std::is_same<T, float>::value ||
                std::is_same<T, double>::value || std::is_same<T, int>::value);
  auto value = json_values.FindList(key);
  if (!output) {
    LOGF(ERROR) << "output cannot be nullptr";
    return false;
  }
  if (!value) {
    return false;
  }
  output->clear();
  for (const auto& v : *value) {
    if (std::is_same<T, double>::value || std::is_same<T, float>::value) {
      output->push_back(v.GetDouble());
    } else if (std::is_same<T, int>::value) {
      output->push_back(v.GetInt());
    }
  }
  return true;
}

}  // namespace cros

#endif  // CAMERA_COMMON_RELOADABLE_CONFIG_FILE_H_
