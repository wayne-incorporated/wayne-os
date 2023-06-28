// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_SESSION_MANAGER_IMPL_H_
#define LOGIN_MANAGER_SESSION_MANAGER_IMPL_H_

#include "login_manager/session_manager_interface.h"

#include <stdint.h>
#include <stdlib.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/ref_counted.h>
#include <base/time/tick_clock.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/errors/error.h>
#include <chromeos/dbus/service_constants.h>
#include <libpasswordprovider/password_provider.h>

#include "login_manager/arc_sideload_status_interface.h"
#include "login_manager/container_manager_interface.h"
#include "login_manager/dbus_adaptors/org.chromium.SessionManagerInterface.h"
#include "login_manager/device_local_account_manager.h"
#include "login_manager/device_policy_service.h"
#include "login_manager/key_generator.h"
#include "login_manager/login_screen_storage.h"
#include "login_manager/policy_service.h"
#include "login_manager/regen_mitigator.h"
#include "login_manager/server_backed_state_key_generator.h"

class Crossystem;
class InstallAttributesReader;

namespace dbus {
class Bus;
class ObjectProxy;
class Response;
}  // namespace dbus

namespace login_manager {
class DeviceLocalAccountManager;
class InitDaemonController;
class KeyGenerator;
class LoginMetrics;
class NssUtil;
class PolicyDescriptor;
class PolicyKey;
class ProcessManagerServiceInterface;
class StartArcMiniContainerRequest;
class SystemUtils;
class UpgradeArcContainerRequest;
class UserPolicyServiceFactory;
class VpdProcess;

// Enable further isolation of the user session (including the browser process
// tree), beyond merely running as user 'chronos'.
constexpr bool __attribute__((unused)) IsolateUserSession() {
  return USE_USER_SESSION_ISOLATION;
}

// Implements the DBus SessionManagerInterface.
//
// All signatures used in the methods of the ownership API are
// SHA1 with RSA encryption.
class SessionManagerImpl
    : public SessionManagerInterface,
      public KeyGenerator::Delegate,
      public PolicyService::Delegate,
      public org::chromium::SessionManagerInterfaceInterface {
 public:
  enum class RestartJobMode : uint32_t {
    kGuest = 0,
    kUserless,
  };

  // Payloads for SessionStateChanged DBus signal.
  static const char kStarted[];
  static const char kStopping[];
  static const char kStopped[];

  // Path to flag file indicating that a user has logged in since last boot.
  static const char kLoggedInFlag[];

  // Path to magic file that will trigger device wiping on next boot.
  static const char kResetFile[];

  // File containing the path to the updated TPM firmware binary.
  static const char kTPMFirmwareUpdateLocationFile[];

  // Flag file indicating SRK ROCA vulnerability status.
  static const char kTPMFirmwareUpdateSRKVulnerableROCAFile[];

  // Flag file indicating a request to update TPM firmware after reboot.
  static const char kTPMFirmwareUpdateRequestFlagFile[];

  // Flag file that signals to mount_encrypted that we're requesting it to
  // preserve the encrypted stateful file system across a TPM reset.
  static const char kStatefulPreservationRequestFile[];

  // Name of impulse emitted when user session starts.
  static const char kStartUserSessionImpulse[];

  // Name of the impulse emitted when the shill profile should be loaded for a
  // user session.
  static const char kLoadShillProfileImpulse[];

  // Android container messages.
  static const char kStartArcInstanceImpulse[];
  static const char kStopArcInstanceImpulse[];
  static const char kContinueArcBootImpulse[];
  static const char kArcBootedImpulse[];

  // Lock screen state messages.
  static const char kScreenLockedImpulse[];
  static const char kScreenUnlockedImpulse[];

  // How much time we must wait before killing the containers.
  static const base::TimeDelta kContainerTimeout;

  // How much time to wait for the key generator job to stop before killing it.
  static const base::TimeDelta kKeyGenTimeout;

  // How much time to give the browser to shutdown cleanly before killing it.
  static const base::TimeDelta kBrowserTimeout;

  // Time window before or after suspend/resume in which the session should be
  // ended if Chrome crashes. This is done as a precaution to avoid showing an
  // unlocked screen if the crash made Chrome fail to lock the screen:
  // https://crbug.com/867970
  static const base::TimeDelta kCrashBeforeSuspendInterval;
  static const base::TimeDelta kCrashAfterSuspendInterval;

  // The Delegate interface performs actions on behalf of SessionManagerImpl.
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Asks Chrome to lock the screen asynchronously.
    virtual void LockScreen() = 0;

    // Asks powerd to restart the device. |description| will be logged by powerd
    // to explain the reason for the restart.
    virtual void RestartDevice(const std::string& description) = 0;
  };

  // Ownership of raw pointer arguments remains with the caller.
  SessionManagerImpl(Delegate* delegate,
                     std::unique_ptr<InitDaemonController> init_controller,
                     const scoped_refptr<dbus::Bus>& bus,
                     KeyGenerator* key_gen,
                     ServerBackedStateKeyGenerator* state_key_generator,
                     ProcessManagerServiceInterface* manager,
                     LoginMetrics* metrics,
                     NssUtil* nss,
                     base::Optional<base::FilePath> ns_path,
                     SystemUtils* utils,
                     Crossystem* crossystem,
                     VpdProcess* vpd_process,
                     PolicyKey* owner_key,
                     ContainerManagerInterface* android_container,
                     InstallAttributesReader* install_attributes_reader,
                     dbus::ObjectProxy* powerd_proxy,
                     dbus::ObjectProxy* system_clock_proxy,
                     dbus::ObjectProxy* debugd_proxy,
                     ArcSideloadStatusInterface* arc_sideload_status);
  SessionManagerImpl(const SessionManagerImpl&) = delete;
  SessionManagerImpl& operator=(const SessionManagerImpl&) = delete;

  ~SessionManagerImpl() override;

  // Tests can call these before Initialize() to inject their own objects.
  void SetPolicyServicesForTesting(
      std::unique_ptr<DevicePolicyService> device_policy,
      std::unique_ptr<UserPolicyServiceFactory> user_policy_factory,
      std::unique_ptr<DeviceLocalAccountManager> device_local_account_manager);
  void SetTickClockForTesting(std::unique_ptr<base::TickClock> clock);
  void SetUiLogSymlinkPathForTesting(const base::FilePath& path);
  void SetLoginScreenStorageForTesting(
      std::unique_ptr<LoginScreenStorage> login_screen_storage);

  // SessionManagerInterface implementation.
  // Should set up policy stuff; if false DIE.
  bool Initialize() override;
  void Finalize() override;
  bool StartDBusService() override;

  void AnnounceSessionStoppingIfNeeded() override;
  void AnnounceSessionStopped() override;
  bool ShouldEndSession(std::string* reason_out) override;
  std::vector<std::string> GetFeatureFlags() override {
    return device_policy_->GetFeatureFlags();
  }

  // Starts a 'Powerwash' of the device by touching a flag file, then
  // rebooting to allow early-boot code to wipe parts of stateful we
  // need wiped. Have a look at /src/platform2/init/chromeos_startup
  // for the gory details.
  void InitiateDeviceWipe(const std::string& reason) override;

  //////////////////////////////////////////////////////////////////////////////
  // Methods exposed via RPC are defined below.

  // org::chromium::SessionManagerInterfaceInterface implementation.
  void EmitLoginPromptVisible() override;
  void EmitAshInitialized() override;
  bool EnableChromeTesting(
      brillo::ErrorPtr* error,
      bool in_force_relaunch,
      const std::vector<std::string>& in_extra_arguments,
      const std::vector<std::string>& in_extra_environment_variables,
      std::string* out_filepath) override;
  bool SaveLoginPassword(brillo::ErrorPtr* error,
                         const base::ScopedFD& in_password_fd) override;
  bool LoginScreenStorageStore(brillo::ErrorPtr* error,
                               const std::string& in_key,
                               const std::vector<uint8_t>& in_metadata,
                               uint64_t in_value_size,
                               const base::ScopedFD& in_value_fd) override;
  bool LoginScreenStorageRetrieve(
      brillo::ErrorPtr* error,
      const std::string& in_key,
      uint64_t* out_value_size,
      brillo::dbus_utils::FileDescriptor* out_value_fd) override;
  bool LoginScreenStorageListKeys(brillo::ErrorPtr* error,
                                  std::vector<std::string>* out_keys) override;
  void LoginScreenStorageDelete(const std::string& in_key) override;
  bool StartSession(brillo::ErrorPtr* error,
                    const std::string& in_account_id,
                    const std::string& in_unique_identifier) override;
  void StopSession(const std::string& in_unique_identifier) override;
  void StopSessionWithReason(uint32_t reason) override;
  bool StartBrowserDataMigration(brillo::ErrorPtr* error,
                                 const std::string& in_account_id) override;

  bool LoadShillProfile(brillo::ErrorPtr* error,
                        const std::string& in_account_id) override;

  // Interface for storing and retrieving policy.
  // TODO(crbug.com/765644): Remove 'Ex', see bug description.
  void StorePolicyEx(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response,
      const std::vector<uint8_t>& in_descriptor_blob,
      const std::vector<uint8_t>& in_policy_blob) override;
  void StoreUnsignedPolicyEx(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response,
      const std::vector<uint8_t>& in_descriptor_blob,
      const std::vector<uint8_t>& in_policy_blob) override;
  bool RetrievePolicyEx(brillo::ErrorPtr* error,
                        const std::vector<uint8_t>& in_descriptor_blob,
                        std::vector<uint8_t>* out_policy_blob) override;
  bool ListStoredComponentPolicies(
      brillo::ErrorPtr* error,
      const std::vector<uint8_t>& in_descriptor_blob,
      std::vector<std::string>* out_component_ids) override;

  std::string RetrieveSessionState() override;
  std::map<std::string, std::string> RetrieveActiveSessions() override;
  void RetrievePrimarySession(std::string* out_username,
                              std::string* out_sanitized_username) override;
  bool IsGuestSessionActive() override;

  void HandleSupervisedUserCreationStarting() override;
  void HandleSupervisedUserCreationFinished() override;

  bool LockScreen(brillo::ErrorPtr* error) override;
  void HandleLockScreenShown() override;
  void HandleLockScreenDismissed() override;
  bool IsScreenLocked() override;

  bool RestartJob(brillo::ErrorPtr* error,
                  const base::ScopedFD& in_cred_fd,
                  const std::vector<std::string>& in_argv,
                  uint32_t mode) override;

  bool StartDeviceWipe(brillo::ErrorPtr* error) override;
  bool StartRemoteDeviceWipe(
      brillo::ErrorPtr* error,
      const std::vector<uint8_t>& in_signed_command) override;
  void ClearForcedReEnrollmentVpd(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response)
      override;
  bool StartTPMFirmwareUpdate(brillo::ErrorPtr* error,
                              const std::string& update_mode) override;
  void SetFlagsForUser(const std::string& in_account_id,
                       const std::vector<std::string>& in_flags) override;
  void SetFeatureFlagsForUser(
      const std::string& in_account_id,
      const std::vector<std::string>& in_feature_flags,
      const std::map<std::string, std::string>& in_origin_list_flags) override;

  void GetServerBackedStateKeys(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          std::vector<std::vector<uint8_t>>>> response) override;

  bool InitMachineInfo(brillo::ErrorPtr* error,
                       const std::string& in_data) override;
  bool StartArcMiniContainer(brillo::ErrorPtr* error,
                             const std::vector<uint8_t>& in_request) override;
  bool UpgradeArcContainer(brillo::ErrorPtr* error,
                           const std::vector<uint8_t>& in_request) override;
  bool StopArcInstance(brillo::ErrorPtr* error,
                       const std::string& account_id,
                       bool should_backup_log) override;
  bool SetArcCpuRestriction(brillo::ErrorPtr* error,
                            uint32_t in_restriction_state) override;
  bool EmitArcBooted(brillo::ErrorPtr* error,
                     const std::string& in_account_id) override;
  bool GetArcStartTimeTicks(brillo::ErrorPtr* error,
                            int64_t* out_start_time) override;
  void EnableAdbSideload(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response)
      override;
  void QueryAdbSideload(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response)
      override;

  // PolicyService::Delegate implementation:
  void OnPolicyPersisted(bool success) override;
  void OnKeyPersisted(bool success) override;

  // KeyGenerator::Delegate implementation:
  void OnKeyGenerated(const std::string& username,
                      const base::FilePath& temp_key_file) override;

  void SetSystemClockLastSyncInfoRetryDelayForTesting(
      const base::TimeDelta& delay) {
    system_clock_last_sync_info_retry_delay_ = delay;
  }

  void SetPasswordProviderForTesting(
      std::unique_ptr<password_provider::PasswordProviderInterface>
          password_provider) {
    password_provider_ = std::move(password_provider);
  }

 private:
  class DBusService;

  // Holds the state related to one of the signed in users.
  struct UserSession;

  using UserSessionMap = std::map<std::string, std::unique_ptr<UserSession>>;

  // Called when powerd announces that a suspend/resume cycle is beginning or
  // ending.
  void OnSuspendImminent(dbus::Signal* signal);
  void OnSuspendDone(dbus::Signal* signal);

  // Called when the tlsdated service becomes initially available.
  void OnSystemClockServiceAvailable(bool service_available);

  // Request the LastSyncInfo from tlsdated daemon.
  void GetSystemClockLastSyncInfo();

  // The response to LastSyncInfo request is processed here. If the time sync
  // was done then the state keys are generated, otherwise another LastSyncInfo
  // request is scheduled to be done later.
  void OnGotSystemClockLastSyncInfo(dbus::Response* response);

  // Given a policy key stored at temp_key_file, pulls it off disk,
  // validates that it is a correctly formed key pair, and ensures it is
  // stored for the future in the provided user's NSSDB.
  void ImportValidateAndStoreGeneratedKey(const std::string& username,
                                          const base::FilePath& temp_key_file);

  // Normalizes an account ID in the case of a legacy email address.
  // Returns true on success, false otherwise. In case of an error,
  // brillo::Error instance is set to |error_out|.
  static bool NormalizeAccountId(const std::string& account_id,
                                 std::string* actual_account_id_out,
                                 brillo::ErrorPtr* error_out);

  bool AllSessionsAreIncognito();

  std::unique_ptr<UserSession> CreateUserSession(
      const std::string& username,
      const OptionalFilePath& ns_mnt_path,
      bool is_incognito,
      brillo::ErrorPtr* error);

  // Verifies whether unsigned policies are permitted to be stored.
  // Returns nullptr on success. Otherwise, an error that should be used in a
  // reply to the D-Bus method call is returned.
  brillo::ErrorPtr VerifyUnsignedPolicyStore();

  // Returns the appropriate PolicyService for the given |descriptor|. |storage|
  // is only set for some |descriptor|s. If set, it controls the lifetime of the
  // returned pointer. Returns nullptr and sets |error| if no PolicyService
  // could be found.
  PolicyService* GetPolicyService(const PolicyDescriptor& descriptor,
                                  std::unique_ptr<PolicyService>* storage,
                                  brillo::ErrorPtr* error);

  // Returns the appropriate PolicyService::KeyInstallFlags for the given
  // |descriptor|.
  int GetKeyInstallFlags(const PolicyDescriptor& descriptor);

  // Shared implementation of StorePolicyEx() and StoreUnsignedPolicyEx().
  void StorePolicyInternalEx(
      const std::vector<uint8_t>& descriptor_blob,
      const std::vector<uint8_t>& policy_blob,
      SignatureCheck signature_check,
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response);

  // Requests a reboot. Formats the actual reason string to name session_manager
  // as the source of the request.
  void RestartDevice(const std::string& reason);

  void EnableAdbSideloadCallbackAdaptor(
      brillo::dbus_utils::DBusMethodResponse<bool>* response,
      ArcSideloadStatusInterface::Status status,
      const char* error);
  void QueryAdbSideloadCallbackAdaptor(
      brillo::dbus_utils::DBusMethodResponse<bool>* response,
      ArcSideloadStatusInterface::Status status);

  void BackupArcBugReport(const std::string& account_id);
  void DeleteArcBugReportBackup(const std::string& account_id);

  // Returns true if at least one session is started.
  bool IsSessionStarted();

#if USE_CHEETS
  // Starts the Android container for ARC. If an error occurs, brillo::Error
  // instance is set to |error_out|.  After this succeeds, in case of ARC stop,
  // OnAndroidContainerStopped() is called.
  bool StartArcContainer(const std::vector<std::string>& env_vars,
                         brillo::ErrorPtr* error_out);

  // Creates environment variables passed to upstart for container upgrade.
  std::vector<std::string> CreateUpgradeArcEnvVars(
      const UpgradeArcContainerRequest& request,
      const std::string& account_id,
      pid_t pid);

  // Called when the container fails to continue booting.
  void OnContinueArcBootFailed();

  // Stops the ARC container with the given |reason|.
  bool StopArcInstanceInternal(ArcContainerStopReason reason);

  // Called when the Android container is stopped.
  void OnAndroidContainerStopped(pid_t pid, ArcContainerStopReason reason);
#endif

  bool session_started_ = false;
  bool session_stopping_ = false;
  bool screen_locked_ = false;
  bool supervised_user_creation_ongoing_ = false;
  bool system_clock_synchronized_ = false;
  std::string cookie_;

  // True if a SuspendImminent D-Bus signal was received from |powerd_proxy_|
  // but the corresponding SuspendDone signal hasn't been received yet.
  bool suspend_ongoing_ = false;

  // Time at which the last SuspendDone signal was received from
  // |powerd_proxy_|.
  base::TimeTicks last_suspend_done_time_;

  base::FilePath chrome_testing_path_;

  std::unique_ptr<InitDaemonController> init_controller_;

  base::TimeDelta system_clock_last_sync_info_retry_delay_;
  base::TimeTicks arc_start_time_;

  std::unique_ptr<base::TickClock> tick_clock_;
  scoped_refptr<dbus::Bus> bus_;
  org::chromium::SessionManagerInterfaceAdaptor adaptor_;
  std::unique_ptr<DBusService> dbus_service_;

  // Ownership of all of these raw pointers remains elsewhere.
  Delegate* delegate_;
  KeyGenerator* key_gen_;
  ServerBackedStateKeyGenerator* state_key_generator_;
  ProcessManagerServiceInterface* manager_;
  LoginMetrics* login_metrics_;
  NssUtil* nss_;
  base::Optional<base::FilePath> chrome_mount_ns_path_;
  SystemUtils* system_;
  Crossystem* crossystem_;
  VpdProcess* vpd_process_;
  PolicyKey* owner_key_;
  ContainerManagerInterface* android_container_;
  InstallAttributesReader* install_attributes_reader_;
  dbus::ObjectProxy* powerd_proxy_;
  dbus::ObjectProxy* system_clock_proxy_;
  dbus::ObjectProxy* debugd_proxy_;
  std::unique_ptr<DevicePolicyService> device_policy_;
  std::unique_ptr<UserPolicyServiceFactory> user_policy_factory_;
  std::unique_ptr<DeviceLocalAccountManager> device_local_account_manager_;

  std::unique_ptr<ArcSideloadStatusInterface> arc_sideload_status_;

  RegenMitigator mitigator_;

  // Callbacks passed to RequestServerBackedStateKeys() while
  // |system_clock_synchrononized_| was false. They will be run by
  // OnGotSystemClockLastSyncInfo() once the clock is synchronized.
  std::vector<ServerBackedStateKeyGenerator::StateKeyCallback>
      pending_state_key_callbacks_;

  // Map of the currently signed-in users to their state.
  UserSessionMap user_sessions_;

  // Primary user is the first non-incognito user.
  std::string primary_user_account_id_;

  // Path to symlink pointing at log file containing stdout and stderr for
  // session_manager and Chrome, e.g. "/var/log/ui/ui.LATEST".
  base::FilePath ui_log_symlink_path_;

  std::unique_ptr<password_provider::PasswordProviderInterface>
      password_provider_;

  std::unique_ptr<LoginScreenStorage> login_screen_storage_;

  base::WeakPtrFactory<SessionManagerImpl> weak_ptr_factory_;
};

}  // namespace login_manager
#endif  // LOGIN_MANAGER_SESSION_MANAGER_IMPL_H_
