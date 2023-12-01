// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_PREFS_H_
#define POWER_MANAGER_COMMON_PREFS_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/compiler_specific.h>
#include <base/functional/callback_forward.h>
#include <base/observer_list.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

namespace power_manager {

class PrefsObserver;

// Interface for reading and writing preferences.
class PrefsInterface {
 public:
  virtual ~PrefsInterface() = default;

  // Adds or removes an observer.
  virtual void AddObserver(PrefsObserver* observer) = 0;
  virtual void RemoveObserver(PrefsObserver* observer) = 0;

  // Reads settings and returns true on success.
  virtual bool GetString(const std::string& name, std::string* value) = 0;
  virtual bool GetInt64(const std::string& name, int64_t* value) = 0;
  virtual bool GetDouble(const std::string& name, double* value) = 0;
  virtual bool GetBool(const std::string& name, bool* value) = 0;

  // Writes settings (possibly asynchronously, although any deferred
  // changes will be reflected in Get*() calls).
  virtual void SetString(const std::string& name, const std::string& value) = 0;
  virtual void SetInt64(const std::string& name, int64_t value) = 0;
  virtual void SetDouble(const std::string& name, double value) = 0;
  virtual void SetBool(const std::string& name, bool value) = 0;

  // Reads non-power settings that are part of one of the PrefsSourceInterfaces.
  // These settings cannot be modified via the PrefsInterface.
  virtual bool GetExternalString(const std::string& path,
                                 const std::string& name,
                                 std::string* value) = 0;
};

class PrefsSourceInterface;

using PrefsSourceInterfaceVector =
    std::vector<std::unique_ptr<PrefsSourceInterface>>;

// Result of a pref file read operation.
struct PrefReadResult {
  std::string value;        // The value that was read.
  std::string source_desc;  // Where |value| came from, for logging.
};

// Interface for readable sources of preferences.
class PrefsSourceInterface {
 public:
  virtual ~PrefsSourceInterface() = default;

  // Gets a description of this source suitable for logging.
  virtual std::string GetDescription() const = 0;

  // Reads a pref named |name| from this source into the given string.
  virtual bool ReadPrefString(const std::string& name,
                              std::string* value_out) = 0;

  // Reads non-power setting |name| from the |path| location into the given
  // string.
  virtual bool ReadExternalString(const std::string& path,
                                  const std::string& name,
                                  std::string* value_out) = 0;
};

// Interface for readable and writable storage of preferences.
class PrefsStoreInterface : public PrefsSourceInterface {
 public:
  // Callback type for Watch(). |name| refers to the updated preference.
  using ChangeCallback = base::RepeatingCallback<void(const std::string& name)>;

  // Writes a pref named |name| to this store.
  virtual bool WritePrefString(const std::string& name,
                               const std::string& value) = 0;

  // Starts watching for changes in this store and call |callback| with changes.
  // If called multiple times, only the last callback will be notified.
  // Returns true on success.
  virtual bool Watch(const ChangeCallback& callback) = 0;
};

// PrefsInterface implementation that reads and writes prefs from/to disk and
// from libcros_config and cros_ec.
// Multiple directories are supported; this allows a default set of prefs
// to be placed on the readonly root partition and a second set of
// prefs under /var to be overlaid and changed at runtime.
//
// Default pref read priority when using GetDefaultStore() and
// GetDefaultSources() is in decreasing order: read-write directory, cros_ec,
// libcros_config, read-only directories.
class Prefs : public PrefsInterface {
 public:
  // Helper class for tests.
  class TestApi {
   public:
    explicit TestApi(Prefs* prefs);
    TestApi(const TestApi&) = delete;
    TestApi& operator=(const TestApi&) = delete;

    ~TestApi() = default;

    void set_write_interval(base::TimeDelta interval) {
      prefs_->write_interval_ = interval;
    }

    // Calls HandleWritePrefsTimeout().  Returns false if the timeout
    // wasn't set.
    bool TriggerWriteTimeout();

   private:
    Prefs* prefs_;  // weak
  };

  Prefs();
  Prefs(const Prefs&) = delete;
  Prefs& operator=(const Prefs&) = delete;

  ~Prefs() override;

  // Returns the default writable store of prefs, to be passed to Init().
  static std::unique_ptr<PrefsStoreInterface> GetDefaultStore();

  // Returns the default sources where prefs are stored, to be passed to Init().
  static PrefsSourceInterfaceVector GetDefaultSources();

  // Initialize the preference store and sources. The |store| takes highest
  // precedence when reading preferences, followed by the |sources|, in order.
  // The |store| is also used to write preferences and watched for changes.
  bool Init(std::unique_ptr<PrefsStoreInterface> store,
            PrefsSourceInterfaceVector sources);

  // PrefsInterface implementation:
  void AddObserver(PrefsObserver* observer) override;
  void RemoveObserver(PrefsObserver* observer) override;
  bool GetString(const std::string& name, std::string* value) override;
  bool GetInt64(const std::string& name, int64_t* value) override;
  bool GetDouble(const std::string& name, double* value) override;
  bool GetBool(const std::string& name, bool* value) override;
  void SetString(const std::string& name, const std::string& value) override;
  void SetInt64(const std::string& name, int64_t value) override;
  void SetDouble(const std::string& name, double value) override;
  void SetBool(const std::string& name, bool value) override;
  bool GetExternalString(const std::string& path,
                         const std::string& name,
                         std::string* value) override;

 private:
  // Handle changes to pref values in |pref_store_|.
  void HandlePrefChanged(const std::string& name);

  // Reads string values of pref given by |name| from all the sources in
  // |pref_sources_| in order, where they exist.  Strips them of whitespace.
  // Stores each read result in |results|.
  // If |read_all| is true, it will attempt to read from all pref paths.
  // Otherwise it will return after successfully reading one pref source.
  void GetPrefResults(const std::string& name,
                      bool read_all,
                      std::vector<PrefReadResult>* results);

  // Calls WritePrefs() immediately if prefs haven't been written to disk
  // recently.  Otherwise, schedules HandleWritePrefsTimeout() if it isn't
  // already scheduled.
  void ScheduleWrite();

  // Writes |prefs_to_write_| to |pref_store_|, updates |last_write_time_|,
  // and clears |prefs_to_write_|.
  void WritePrefs();

  // The pref store is the highest precedence source of pref values and the
  // writable sink for preferences.
  std::unique_ptr<PrefsStoreInterface> pref_store_;

  // List of pref sources to read from, in order of precedence.
  // A value read from the first path will be used instead of values from the
  // other paths.
  PrefsSourceInterfaceVector pref_sources_;

  base::ObserverList<PrefsObserver> observers_;

  // Calls WritePrefs().
  base::OneShotTimer write_prefs_timer_;

  // Last time at which WritePrefs() was called.
  base::TimeTicks last_write_time_;

  // Minimum time between prefs getting written to disk.
  base::TimeDelta write_interval_;

  // Map from name to stringified value of prefs that need to be written to
  // the first path in |pref_paths_|.
  std::map<std::string, std::string> prefs_to_write_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_PREFS_H_
