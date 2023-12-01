// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef FEATURED_FEATURE_LIBRARY_H_
#define FEATURED_FEATURE_LIBRARY_H_

#include "featured/c_feature_library.h"  // for enums
#include "featured/feature_export.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/location.h>
#include <base/memory/scoped_refptr.h>
#include <base/memory/weak_ptr.h>
#include <base/synchronization/lock.h>
#include <base/task/task_runner.h>
#include <base/thread_annotations.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <featured/proto_bindings/featured.pb.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

namespace feature {

// This character is not allowed in trial names so it makes for a good
// separator. Context: FeatureList::IsValidFeatureOrFieldTrialName().
// NOTE: If a trial name contains "," because it was not validated, the
// separator will be escaped when writing the active trial file.
constexpr char kTrialGroupSeparator[] = ",";

class FEATURE_EXPORT PlatformFeaturesInterface {
 public:
  using IsEnabledCallback = base::OnceCallback<void(bool)>;
  // Asynchronously determine whether the given feature is enabled, using the
  // specified default value if Chrome doesn't define a value for the feature
  // or the dbus call fails.
  // If you have multiple related features you wish to look up, you MUST look
  // them all up in the same call using GetParamsAndEnabled{,Blocking} -- if you
  // look them up across multiple calls, chrome may have restarted in between
  // calls, giving inconsistent state.
  // DO NOT CACHE the result of this call across chrome restarts, as it may
  // change -- for example, when a user logs in or out or when they apply
  // changes to chrome://flags.
  // To determine when to refetch after a chrome restart, use
  // ListenForRefetchNeeded(), or just re-fetch each time you use the experiment
  // value.
  // NOTE: As of 2021-12, Chrome only retrieves finch seeds after a first reboot
  // (e.g. when logging in). So, if you need to run an experiment before this it
  // should be set up as a client-side trial.
  virtual void IsEnabled(const VariationsFeature& feature,
                         IsEnabledCallback callback) = 0;

  // Like IsEnabled(), but blocks up to timeout_ms to wait for the dbus call to
  // finish.
  // If you have multiple related features you wish to look up, you MUST look
  // them all up in the same call using GetParamsAndEnabled{,Blocking} -- if you
  // look them up across multiple calls, chrome may have restarted in between
  // calls, giving inconsistent state.
  // DO NOT CACHE the result of this call across chrome restarts, as it may
  // change -- for example, when a user logs in or out or when they apply
  // changes to chrome://flags.
  // To determine when to refetch after a chrome restart, use
  // ListenForRefetchNeeded(), or just re-fetch each time you use the experiment
  // value.
  // NOTE: As of 2021-12, Chrome only retrieves finch seeds after a first reboot
  // (e.g. when logging in). So, if you need to run an experiment before this it
  // should be set up as a client-side trial.
  // Does *not* block waiting for the service to be available, so may have
  // spurious fallbacks to the default value that could be avoided with
  // IsEnabled(), especially soon after Chrome starts.
  // TODO(b/236009983): Fix this.
  virtual bool IsEnabledBlockingWithTimeout(const VariationsFeature& feature,
                                            int timeout_ms) = 0;

  // Like IsEnabled(), but blocks waiting for the dbus call to finish.
  // If you have multiple related features you wish to look up, you MUST look
  // them all up in the same call using GetParamsAndEnabled{,Blocking} -- if you
  // look them up across multiple calls, chrome may have restarted in between
  // calls, giving inconsistent state.
  // DO NOT CACHE the result of this call across chrome restarts, as it may
  // change -- for example, when a user logs in or out or when they apply
  // changes to chrome://flags.
  // To determine when to refetch after a chrome restart, use
  // ListenForRefetchNeeded(), or just re-fetch each time you use the experiment
  // value.
  // NOTE: As of 2021-12, Chrome only retrieves finch seeds after a first reboot
  // (e.g. when logging in). So, if you need to run an experiment before this it
  // should be set up as a client-side trial.
  // Does *not* block waiting for the service to be available, so may have
  // spurious fallbacks to the default value that could be avoided with
  // IsEnabled(), especially soon after Chrome starts.
  // TODO(b/236009983): Fix this.
  bool IsEnabledBlocking(const VariationsFeature& feature) {
    return IsEnabledBlockingWithTimeout(feature,
                                        dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  }

  struct ParamsResultEntry {
   public:
    // Whether the feature is enabled or disabled.
    bool enabled;
    // If non-nullopt, gives the key/value pairs for any parameters, as
    // determined by chromium.
    // If this is empty, callers should fall back to hard-coded default values
    // for all parameters.
    std::map<std::string, std::string> params;
  };
  // Mapping the feature name to its ParamsResultEntry struct.
  using ParamsResult = std::map<std::string, ParamsResultEntry>;
  using GetParamsCallback = base::OnceCallback<void(ParamsResult)>;
  // Asynchronously get the parameters for a given set of related features, as
  // well as a boolean representing whether each feature is enabled.
  // Gives back nullopt if the lookup fails.
  // If you have multiple related features you wish to look up, you MUST look
  // them all up in the same call -- if you look them up across multiple calls,
  // chrome may have restarted in between calls, giving inconsistent state.
  // DO NOT CACHE the result of this call across chrome restarts, as it may
  // change -- for example, when a user logs in or out or when they apply
  // changes to chrome://flags.
  // To determine when to refetch after a chrome restart, use
  // ListenForRefetchNeeded(), or just re-fetch each time you use the experiment
  // value.
  // NOTE: As of 2021-12, Chrome only retrieves finch seeds after a first reboot
  // (e.g. when logging in). So, if you need to run an experiment before this it
  // should be set up as a client-side trial.
  virtual void GetParamsAndEnabled(
      const std::vector<const VariationsFeature*>& features,
      GetParamsCallback callback) = 0;
  // Like GetParamsAndEnabled(), but blocks waiting for the dbus call to finish.
  // If you have multiple related features you wish to look up, you MUST look
  // them all up in the same call -- if you look them up across multiple calls,
  // chrome may have restarted in between calls, giving inconsistent state.
  // DO NOT CACHE the result of this call across chrome restarts, as it may
  // change -- for example, when a user logs in or out or when they apply
  // changes to chrome://flags.
  // To determine when to refetch after a chrome restart, use
  // ListenForRefetchNeeded(), or just re-fetch each time you use the experiment
  // value.
  // NOTE: As of 2021-12, Chrome only retrieves finch seeds after a first reboot
  // (e.g. when logging in). So, if you need to run an experiment before this it
  // should be set up as a client-side trial.
  // Does *not* block waiting for the service to be available, so may have
  // spurious fallbacks to the default value that could be avoided with
  // GetParamsAndEnabled(), especially soon after Chrome starts.
  // TODO(b/236009983): Fix this.
  virtual ParamsResult GetParamsAndEnabledBlocking(
      const std::vector<const VariationsFeature*>& features) = 0;

  // ListenForRefetchNeeded registers |signal_callback| to run whenever it is
  // required to refetch feature state (that is, whenever chrome restarts).
  // In particular, in order to respect chrome://flags state, you must either
  // listen to this signal and refetch feature state when |signal_callback| runs
  // OR you must re-fetch each time you use the experiment value.
  //
  // |signal_callback| will be called in the origin thread, when the
  // state must be re-fetched. As it's called in the origin thread,
  // |signal_callback| can safely reference objects in the origin thread.
  //
  // |attached_callback| is called when the signal handler registration succeeds
  // or fails, with a boolean indicating that the process is successfully
  // listening or has failed to listen.
  virtual void ListenForRefetchNeeded(
      base::RepeatingCallback<void(void)> signal_callback,
      base::OnceCallback<void(bool)> attached_callback) = 0;

 protected:
  virtual ~PlatformFeaturesInterface() = default;
};

class FEATURE_EXPORT PlatformFeatures : public PlatformFeaturesInterface {
 public:
  PlatformFeatures(const PlatformFeatures&) = delete;
  PlatformFeatures& operator=(const PlatformFeatures&) = delete;

  // Creates and initializes the global instance based on the provided |bus|.
  // The global instance will be initialized to |nullptr| on failure to create
  // an ObjectProxy.
  //
  // Note: The initialized global instance will live until process exit.
  [[nodiscard]] static bool Initialize(scoped_refptr<dbus::Bus> bus);

  // Returns the global instance which may be null if not initialized.
  static PlatformFeatures* Get();

  void IsEnabled(const VariationsFeature& feature,
                 IsEnabledCallback callback) override;

  bool IsEnabledBlockingWithTimeout(const VariationsFeature& feature,
                                    int timeout_ms) override;

  void GetParamsAndEnabled(
      const std::vector<const VariationsFeature*>& features,
      GetParamsCallback callback) override;

  ParamsResult GetParamsAndEnabledBlocking(
      const std::vector<const VariationsFeature*>& features) override;

  void ListenForRefetchNeeded(
      base::RepeatingCallback<void(void)> signal_callback,
      base::OnceCallback<void(bool)> attached_callback) override;

  static void ShutdownForTesting();

 private:
  friend class FeatureLibraryTest;

  FRIEND_TEST(FeatureLibraryTest, CheckFeatureIdentity);
  FRIEND_TEST(FeatureLibraryTest, RecordSingleActiveTrial);
  FRIEND_TEST(FeatureLibraryTest, RecordMultipleActiveTrials);
  FRIEND_TEST(FeatureLibraryTest, RecordDuplicateActiveTrialOnlyOnce);
  FRIEND_TEST(FeatureLibraryTest, EscapeTrialNameWithSeparator);
  FRIEND_TEST(FeatureLibraryTest, EscapeTrialNameWithForwardSlash);

  explicit PlatformFeatures(scoped_refptr<dbus::Bus> bus,
                            dbus::ObjectProxy* chrome_proxy,
                            dbus::ObjectProxy* feature_proxy);

  ~PlatformFeatures() override;

  static void InitializeForTesting(scoped_refptr<dbus::Bus> bus,
                                   dbus::ObjectProxy* chrome_proxy,
                                   dbus::ObjectProxy* feature_proxy);

  // Callback that is invoked for IsEnabled() when WaitForServiceToBeAvailable()
  // finishes.
  void OnWaitForServiceIsEnabled(const VariationsFeature& feature,
                                 IsEnabledCallback callback,
                                 bool available);

  // Callback that is invoked when chrome_proxy_->CallMethod() finishes.
  void HandleIsEnabledResponse(const VariationsFeature& feature,
                               IsEnabledCallback callback,
                               dbus::Response* response);

  // Creates the default response for GetParamsAndEnabled{,Blocking}()
  ParamsResult CreateDefaultGetParamsAndEnabledResponse(
      const std::vector<const VariationsFeature*>& features);

  // Callback that is invoked for GetParamsAndEnabled() when
  // WaitForServiceToBeAvailable() finishes.
  void OnWaitForServiceGetParams(
      const std::vector<const VariationsFeature*>& feature,
      GetParamsCallback callback,
      bool available);

  // Callback that is invoked when chrome_proxy_->CallMethod() finishes.
  void HandleGetParamsResponse(
      const std::vector<const VariationsFeature*>& features,
      GetParamsCallback callback,
      dbus::Response* response);

  // Encoding side of both HandleGetParamsResponse and
  // GetParamsAndEnabledBlocking.
  void EncodeGetParamsArgument(
      dbus::MessageWriter* writer,
      const std::vector<const VariationsFeature*>& features);

  // Decoding side of both HandleGetParamsResponse and
  // GetParamsAndEnabledBlocking.
  ParamsResult ParseGetParamsResponse(
      dbus::Response* response,
      const std::vector<const VariationsFeature*>& features);

  // Verify that we have only ever seen |feature| with this same address.
  // Used to prevent defining the same feature with distinct default values.
  bool CheckFeatureIdentity(const VariationsFeature& feature)
      LOCKS_EXCLUDED(lock_);

  static void OnConnectedCallback(
      base::OnceCallback<void(bool)> attached_callback,
      const std::string& interface,
      const std::string& signal,
      bool success);

  // This lock protects the global instance variable.
  static base::Lock& GetInstanceLock();

  // Used only for testing. Modifies what directory active trial files are
  // written to.
  void SetActiveTrialFileDirectoryForTesting(const base::FilePath& dir);

  // Creates a new active trial file of the format `TrialName,GroupName` to the
  // directory specified by `active_trial_file_dir_`, where TrialName and
  // GroupName are escaped versions, by url encoding, of the actual trial name
  // and group name, separated by kTrialGroupSeparator. Alphanumerics and -._~
  // will not be escaped. The created file is empty since all necessary metadata
  // is provided in the filename.
  //
  // Chrome may list these files to determine which trials are active, in order
  // to mark them as active in UMA.
  //
  // NOTE: If the active trial file already exists, the existing file will not
  // be overwritten or modified.
  //
  // For testing, callers can change what directory these files are created in
  // with SetActiveTrialFileDirectoryForTesting().
  void RecordActiveTrial(const featured::FeatureOverride& trial);

  scoped_refptr<dbus::Bus> bus_;
  // An object proxy used for communicating with ash-chrome.
  dbus::ObjectProxy* chrome_proxy_;

  // An object proxy used for listening to the "RefetchFeatureState" signal.
  dbus::ObjectProxy* feature_proxy_;

  // Map that keeps track of seen features, to ensure a single feature is
  // only defined once. This verification is only done in builds with DCHECKs
  // enabled.
  base::Lock lock_;
  std::map<std::string, const VariationsFeature*> feature_identity_tracker_
      GUARDED_BY(lock_);

  // Directory where active trial files are written.
  base::FilePath active_trial_file_dir_;

  base::WeakPtrFactory<PlatformFeatures> weak_ptr_factory_{this};
};
}  // namespace feature

#endif  // FEATURED_FEATURE_LIBRARY_H_
