// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FINGERPRINT_MANAGER_H_
#define CRYPTOHOME_FINGERPRINT_MANAGER_H_

#include <memory>
#include <string>
#include "cryptohome/username.h"

#include <biod/biod_proxy/biometrics_manager_proxy_base.h>

namespace cryptohome {

inline constexpr char kCrosFpBiometricsManagerRelativePath[] =
    "/CrosFpBiometricsManager";
inline constexpr int kMaxFingerprintRetries = 5;

enum class FingerprintScanStatus {
  SUCCESS = 0,
  FAILED_RETRY_ALLOWED = 1,
  FAILED_RETRY_NOT_ALLOWED = 2,
};

// FingerprintManager talks to Biometrics Daemon for starting/stopping
// fingerprint auth sessions, and receiving fingerprint auth results.
//
// This class is intended to be used only on a single thread / task runner only.
// Response callbacks will also be run on the same thread / task runner.
class FingerprintManager {
 public:
  using StartSessionCallback = base::OnceCallback<void(bool success)>;
  using ResultCallback = base::OnceCallback<void(FingerprintScanStatus status)>;
  using SignalCallback =
      base::RepeatingCallback<void(FingerprintScanStatus result)>;

  // Factory method. Returns nullptr if Biometrics Daemon is not in a good
  // state or if the device does not have fingerprint support.
  static std::unique_ptr<FingerprintManager> Create(
      const scoped_refptr<dbus::Bus>& bus, const dbus::ObjectPath& path);

  FingerprintManager();
  virtual ~FingerprintManager();

  const ObfuscatedUsername& GetCurrentUser();

  // Returns a weak pointer to this instance. Used when creating callbacks.
  base::WeakPtr<FingerprintManager> GetWeakPtr();

  // Starts fingerprint auth session asynchronously, and sets the user if auth
  // session started successfully.
  // |auth_session_start_client_callback| will be called with true if auth
  // session started successfully, or called with false otherwise.
  //
  // One auth session may serve multiple fingerprint-related calls, e.g.
  // multiple CheckKey() calls with KEY_TYPE_FINGERPRINT, until one of the
  // following occurs:
  // 1. One fingerprint scan succeeds, or a non-recoverable error occurs.
  //    |state_| will be set to AUTH_SESSION_LOCKED.
  // 2. Max retry count reached for the current auth session. |state_| will be
  //    set to AUTH_SESSION_LOCKED.
  // 3. EndAuthSession() is called, e.g. user decides to cancel operation
  //    through UI.
  virtual void StartAuthSessionAsyncForUser(
      const ObfuscatedUsername& user,
      StartSessionCallback auth_session_start_client_callback);

  // Tells Biometrics Daemon to end fingerprint auth session and resets all
  // states.
  virtual void EndAuthSession();

  virtual bool HasAuthSessionForUser(const ObfuscatedUsername& user);

  // Sets the callback for a fingerprint scan. Must be called after
  // StartAuthSessionAsyncForUser. |auth_scan_done_callback| will be
  // called with the status of a fingerprint match, once biod sends it.
  virtual void SetAuthScanDoneCallback(ResultCallback auth_scan_done_callback);

  // Sets the repeating callback for fingerprint scan results. The callback will
  // be called when converting incoming biod fingerprint scan signals to
  // outgoing cryptohome signals.
  virtual void SetSignalCallback(SignalCallback signal_callback);

  // For testing.
  void SetProxy(biod::BiometricsManagerProxyBase* proxy);

 private:
  friend class FingerprintManagerPeer;

  enum class State {
    NO_AUTH_SESSION = 0,
    AUTH_SESSION_OPEN = 1,
    // A fatal error occurred, or max retry count reached, but auth
    // session is not cancelled yet.
    AUTH_SESSION_LOCKED = 2,
  };

  // Class for properly finish processing an AuthScanDone signal.
  class AuthScanDoneResourceManager {
   public:
    explicit AuthScanDoneResourceManager(
        FingerprintManager* fingerprint_manager)
        : fingerprint_manager_(fingerprint_manager) {}

    ~AuthScanDoneResourceManager() {
      // If auth session is still open, then we are waiting for retry, so keep
      // |current_user_|.
      if (fingerprint_manager_->state_ != State::AUTH_SESSION_OPEN)
        fingerprint_manager_->current_user_->clear();
    }

   private:
    FingerprintManager* fingerprint_manager_;
  };

  // Initializes the underlying dbus object proxy for BiometricsDaemon, and
  // connects to relevant dbus signals. Returns false if failing to get the
  // dbus object proxy (e.g. if biod is not in a good state or the device does
  // not have fingerprint support).
  [[nodiscard]] bool Initialize(const scoped_refptr<dbus::Bus>& bus,
                                const dbus::ObjectPath& path);

  // Callback for connecting to biod's AuthScanDoneSignal.
  void OnAuthScanDoneSignalConnected(const std::string& interface,
                                     const std::string& signal,
                                     bool success);

  // Signal handler biod::kBiometricsManagerAuthScanDoneSignal.
  // Parses the auth scan result from biod, compares the matched user to
  // |current_user_|, and calls |auth_scan_done_callback_|.
  void OnAuthScanDone(dbus::Signal* signal);

  // Internal wrapper around the client's callback for starting auth session
  // asynchronously. If auth session starts successfully, set |current_user_|
  // before running the client's callback.
  void SetUserAndRunClientCallback(
      StartSessionCallback auth_session_start_client_callback,
      const ObfuscatedUsername& user,
      bool success);

  // Calculates the retry count left in the current auth session, and run
  // |auth_scan_done_callback_|.
  void ProcessRetry();

  // Run |auth_scan_done_callback_| with FAILED_RETRY_NOT_ALLOWED.
  void ProcessFailed();

  void Reset();

  // The default BiometricsManagerProxyBase object.
  std::unique_ptr<biod::BiometricsManagerProxyBase> default_proxy_;
  // The actual BiometricsManagerProxyBase object used in this class.
  // Can be overridden for testing.
  biod::BiometricsManagerProxyBase* proxy_;
  bool connected_to_auth_scan_done_signal_;
  ResultCallback auth_scan_done_callback_;
  SignalCallback signal_callback_;
  State state_ = State::NO_AUTH_SESSION;
  // The username tied to the current auth session.
  ObfuscatedUsername current_user_;
  // The number of retries left in the current auth session.
  int retry_left_ = 0;
  base::WeakPtrFactory<FingerprintManager> weak_factory_;
  base::PlatformThreadId mount_thread_id_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_FINGERPRINT_MANAGER_H_
