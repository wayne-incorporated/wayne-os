// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/session_manager_impl.h"

#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>

#include <algorithm>
#include <iterator>
#include <locale>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include <base/base64.h>
#include <base/bind.h>
#include <base/callback_helpers.h>
#include <base/check.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/notreached.h>
#include <base/rand_util.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/threading/thread_task_runner_handle.h>
#include <base/time/default_tick_clock.h>
#include <base/time/time.h>
#include <brillo/cryptohome.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/dbus/utils.h>
#include <brillo/scoped_mount_namespace.h>
#include <chromeos/dbus/service_constants.h>
#include <crypto/scoped_nss_types.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <install_attributes/libinstallattributes.h>
#include <libpasswordprovider/password.h>
#include <libpasswordprovider/password_provider.h>

#include "bindings/chrome_device_policy.pb.h"
#include "bindings/device_management_backend.pb.h"
#include "login_manager/arc_sideload_status_interface.h"
#include "login_manager/blob_util.h"
#include "login_manager/browser_job.h"
#include "login_manager/crossystem.h"
#include "login_manager/dbus_util.h"
#include "login_manager/device_local_account_manager.h"
#include "login_manager/device_policy_service.h"
#include "login_manager/init_daemon_controller.h"
#include "login_manager/key_generator.h"
#include "login_manager/login_metrics.h"
#include "login_manager/nss_util.h"
#include "login_manager/policy_key.h"
#include "login_manager/policy_service.h"
#include "login_manager/process_manager_service_interface.h"
#include "login_manager/proto_bindings/arc.pb.h"
#include "login_manager/proto_bindings/login_screen_storage.pb.h"
#include "login_manager/proto_bindings/policy_descriptor.pb.h"
#include "login_manager/regen_mitigator.h"
#include "login_manager/secret_util.h"
#include "login_manager/system_utils.h"
#include "login_manager/user_policy_service_factory.h"
#include "login_manager/validator_utils.h"
#include "login_manager/vpd_process.h"

using base::FilePath;
using brillo::cryptohome::home::GetHashedUserPath;
using brillo::cryptohome::home::GetUserPath;
using brillo::cryptohome::home::kGuestUserName;
using brillo::cryptohome::home::SanitizeUserName;

namespace login_manager {  // NOLINT

constexpr char SessionManagerImpl::kStarted[] = "started";
constexpr char SessionManagerImpl::kStopping[] = "stopping";
constexpr char SessionManagerImpl::kStopped[] = "stopped";

constexpr char SessionManagerImpl::kLoggedInFlag[] =
    "/run/session_manager/logged_in";
constexpr char SessionManagerImpl::kResetFile[] =
    "/mnt/stateful_partition/factory_install_reset";

constexpr char SessionManagerImpl::kTPMFirmwareUpdateLocationFile[] =
    "/run/tpm_firmware_update_location";
constexpr char SessionManagerImpl::kTPMFirmwareUpdateSRKVulnerableROCAFile[] =
    "/run/tpm_firmware_update_srk_vulnerable_roca";
constexpr char SessionManagerImpl::kTPMFirmwareUpdateRequestFlagFile[] =
    "/mnt/stateful_partition/unencrypted/preserve/tpm_firmware_update_request";
constexpr char SessionManagerImpl::kStatefulPreservationRequestFile[] =
    "/mnt/stateful_partition/preservation_request";

constexpr char SessionManagerImpl::kStartUserSessionImpulse[] =
    "start-user-session";

constexpr char SessionManagerImpl::kLoadShillProfileImpulse[] =
    "load-shill-profile";

// ARC related impulse (systemd unit start or Upstart signal).
constexpr char SessionManagerImpl::kStartArcInstanceImpulse[] =
    "start-arc-instance";
constexpr char SessionManagerImpl::kStopArcInstanceImpulse[] =
    "stop-arc-instance";
constexpr char SessionManagerImpl::kContinueArcBootImpulse[] =
    "continue-arc-boot";
constexpr char SessionManagerImpl::kArcBootedImpulse[] = "arc-booted";

// Lock state related impulse (systemd unit start or Upstart signal).
constexpr char SessionManagerImpl::kScreenLockedImpulse[] = "screen-locked";
constexpr char SessionManagerImpl::kScreenUnlockedImpulse[] = "screen-unlocked";

// TODO(b:66919195): Optimize Android container shutdown time. It
// needs as long as 3s on kevin to perform graceful shutdown.
constexpr base::TimeDelta SessionManagerImpl::kContainerTimeout =
    base::TimeDelta::FromSeconds(3);

constexpr base::TimeDelta SessionManagerImpl::kKeyGenTimeout =
    base::TimeDelta::FromSeconds(1);

constexpr base::TimeDelta SessionManagerImpl::kBrowserTimeout =
    base::TimeDelta::FromSeconds(3);

constexpr base::TimeDelta SessionManagerImpl::kCrashBeforeSuspendInterval =
    base::TimeDelta::FromSeconds(5);
constexpr base::TimeDelta SessionManagerImpl::kCrashAfterSuspendInterval =
    base::TimeDelta::FromSeconds(5);

namespace {

// Because the cheets logs are huge, we set the D-Bus timeout to 1 minute.
const base::TimeDelta kBackupArcBugReportTimeout =
    base::TimeDelta::FromMinutes(1);

// The flag to pass to chrome to open a named socket for testing.
const char kTestingChannelFlag[] = "--testing-channel=NamedTestingInterface:";

// Device-local account state directory.
const char kDeviceLocalAccountStateDir[] = "/var/lib/device_local_accounts";

#if USE_CHEETS
// To launch ARC, certain amount of free disk space is needed.
// Path and the amount for the check.
constexpr char kArcDiskCheckPath[] = "/home";
constexpr int64_t kArcCriticalDiskFreeBytes = 64 << 20;  // 64MB

// To set the CPU limits of the Android container.
const char kCpuSharesFile[] =
    "/sys/fs/cgroup/cpu/session_manager_containers/cpu.shares";
const unsigned int kCpuSharesForeground = 1024;
const unsigned int kCpuSharesBackground = 64;
#endif

// The interval used to periodically check if time sync was done by tlsdated.
constexpr base::TimeDelta kSystemClockLastSyncInfoRetryDelay =
    base::TimeDelta::FromMilliseconds(1000);

// TPM firmware update modes.
constexpr char kTPMFirmwareUpdateModeFirstBoot[] = "first_boot";
constexpr char kTPMFirmwareUpdateModePreserveStateful[] = "preserve_stateful";
constexpr char kTPMFirmwareUpdateModeCleanup[] = "cleanup";

// Policy storage constants.
constexpr char kSigEncodeFailMessage[] = "Failed to retrieve policy data.";
constexpr char kParseDescriptorFailMessage[] =
    "Failed to parse policy descriptor.";
constexpr char kGetPolicyServiceFailMessage[] = "Failed to get policy service.";

// Default path of symlink to log file where stdout and stderr from
// session_manager and Chrome are redirected.
constexpr char kDefaultUiLogSymlinkPath[] = "/var/log/ui/ui.LATEST";

// A path of the directory that contains all the key-value pairs stored to the
// pesistent login screen storage.
const char kLoginScreenStoragePath[] = "/var/lib/login_screen_storage";

const char* ToSuccessSignal(bool success) {
  return success ? "success" : "failure";
}

#if USE_CHEETS
bool IsDevMode(SystemUtils* system) {
  // When GetDevModeState() returns UNKNOWN, return true.
  return system->GetDevModeState() != DevModeState::DEV_MODE_OFF;
}

bool IsInsideVm(SystemUtils* system) {
  // When GetVmState() returns UNKNOWN, return false.
  return system->GetVmState() == VmState::INSIDE_VM;
}
#endif

// Parses |descriptor_blob| into |descriptor| and validates it assuming the
// given |usage|. Returns true and sets |descriptor| on success. Returns false
// and sets |error| on failure.
bool ParseAndValidatePolicyDescriptor(
    const std::vector<uint8_t>& descriptor_blob,
    PolicyDescriptorUsage usage,
    PolicyDescriptor* descriptor,
    brillo::ErrorPtr* error) {
  DCHECK(descriptor);
  DCHECK(error);
  if (!descriptor->ParseFromArray(descriptor_blob.data(),
                                  descriptor_blob.size())) {
    *error = CreateError(DBUS_ERROR_INVALID_ARGS,
                         "PolicyDescriptor parsing failed.");
    return false;
  }

  if (!ValidatePolicyDescriptor(*descriptor, usage)) {
    *error = CreateError(DBUS_ERROR_INVALID_ARGS, "PolicyDescriptor invalid.");
    return false;
  }

  return true;
}

// Handles the result of an attempt to connect to a D-Bus signal, logging an
// error on failure.
void HandleDBusSignalConnected(const std::string& interface,
                               const std::string& signal,
                               bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to connect to D-Bus signal " << interface << "."
               << signal;
  }
}

// Replaces the log file that |symlink_path| (typically /var/log/ui/ui.LATEST)
// points to with a new file containing the same contents. This is used to
// disconnect Chrome's stderr and stdout after a user logs in:
// https://crbug.com/904850
void DisconnectLogFile(const base::FilePath& symlink_path) {
  base::FilePath log_path;
  if (!base::ReadSymbolicLink(symlink_path, &log_path))
    return;

  if (!log_path.IsAbsolute())
    log_path = symlink_path.DirName().Append(log_path);

  // Perform a basic safety check.
  if (log_path.DirName() != symlink_path.DirName()) {
    LOG(WARNING) << "Log file " << log_path.value() << " isn't in same "
                 << "directory as symlink " << symlink_path.value()
                 << "; not disconnecting it";
    return;
  }

  // Copy the contents to a temp file and then move it over the original path.
  base::FilePath temp_path;
  if (!base::CreateTemporaryFileInDir(log_path.DirName(), &temp_path)) {
    PLOG(WARNING) << "Failed to create temp file in "
                  << log_path.DirName().value();
    return;
  }
  if (!base::CopyFile(log_path, temp_path)) {
    PLOG(WARNING) << "Failed to copy " << log_path.value() << " to "
                  << temp_path.value();
    return;
  }

  // Try to to copy permissions so the new file isn't 0600, which makes it hard
  // to investigate issues on non-dev devices.
  int mode = 0;
  if (!base::GetPosixFilePermissions(log_path, &mode) ||
      !base::SetPosixFilePermissions(temp_path, mode)) {
    PLOG(WARNING) << "Failed to copy permissions from " << log_path.value()
                  << " to " << temp_path.value();
  }

  if (!base::ReplaceFile(temp_path, log_path, nullptr /* error */)) {
    PLOG(WARNING) << "Failed to rename " << temp_path.value() << " to "
                  << log_path.value();
  }
}

bool IsGuestMode(uint32_t mode) {
  return static_cast<SessionManagerImpl::RestartJobMode>(mode) ==
         SessionManagerImpl::RestartJobMode::kGuest;
}

bool IsGuestSession(const std::vector<std::string>& argv) {
  return base::Contains(argv, BrowserJobInterface::kGuestSessionFlag);
}

}  // namespace

// Tracks D-Bus service running.
// Create*Callback functions return a callback adaptor from given
// DBusMethodResponse. These cancel in-progress operations when the instance is
// deleted.
class SessionManagerImpl::DBusService {
 public:
  explicit DBusService(org::chromium::SessionManagerInterfaceAdaptor* adaptor)
      : adaptor_(adaptor), weak_ptr_factory_(this) {}
  DBusService(const DBusService&) = delete;
  DBusService& operator=(const DBusService&) = delete;

  ~DBusService() = default;

  bool Start(const scoped_refptr<dbus::Bus>& bus) {
    DCHECK(!dbus_object_);

    // Registers the SessionManagerInterface D-Bus methods and signals.
    dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
        nullptr, bus,
        org::chromium::SessionManagerInterfaceAdaptor::GetObjectPath());
    adaptor_->RegisterWithDBusObject(dbus_object_.get());
    dbus_object_->RegisterAndBlock();

    // Note that this needs to happen *after* all methods are exported
    // (http://crbug.com/331431).
    // This should pass dbus::Bus::REQUIRE_PRIMARY once on the new libchrome.
    return bus->RequestOwnershipAndBlock(kSessionManagerServiceName,
                                         dbus::Bus::REQUIRE_PRIMARY);
  }

  // Adaptor from DBusMethodResponse to PolicyService::Completion callback.
  PolicyService::Completion CreatePolicyServiceCompletionCallback(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response) {
    return base::Bind(&DBusService::HandlePolicyServiceCompletion,
                      weak_ptr_factory_.GetWeakPtr(), base::Passed(&response));
  }

  // Adaptor from DBusMethodResponse to
  // ServerBackedStateKeyGenerator::StateKeyCallback callback.
  ServerBackedStateKeyGenerator::StateKeyCallback CreateStateKeyCallback(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          std::vector<std::vector<uint8_t>>>> response) {
    return base::Bind(&DBusService::HandleStateKeyCallback,
                      weak_ptr_factory_.GetWeakPtr(), base::Passed(&response));
  }

 private:
  void HandlePolicyServiceCompletion(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response,
      brillo::ErrorPtr error) {
    if (error) {
      response->ReplyWithError(error.get());
      return;
    }

    response->Return();
  }

  void HandleStateKeyCallback(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          std::vector<std::vector<uint8_t>>>> response,
      const std::vector<std::vector<uint8_t>>& state_key) {
    response->Return(std::move(state_key));
  }

  org::chromium::SessionManagerInterfaceAdaptor* const adaptor_;
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;

  base::WeakPtrFactory<DBusService> weak_ptr_factory_;
};

struct SessionManagerImpl::UserSession {
 public:
  UserSession(const std::string& username,
              const std::string& userhash,
              bool is_incognito,
              ScopedPK11SlotDescriptor desc,
              std::unique_ptr<PolicyService> policy_service)
      : username(username),
        userhash(userhash),
        is_incognito(is_incognito),
        descriptor(std::move(desc)),
        policy_service(std::move(policy_service)) {}
  ~UserSession() {}

  const std::string username;
  const std::string userhash;
  const bool is_incognito;
  ScopedPK11SlotDescriptor descriptor;
  std::unique_ptr<PolicyService> policy_service;
};

SessionManagerImpl::SessionManagerImpl(
    Delegate* delegate,
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
    ArcSideloadStatusInterface* arc_sideload_status)
    : init_controller_(std::move(init_controller)),
      system_clock_last_sync_info_retry_delay_(
          kSystemClockLastSyncInfoRetryDelay),
      tick_clock_(std::make_unique<base::DefaultTickClock>()),
      bus_(bus),
      adaptor_(this),
      delegate_(delegate),
      key_gen_(key_gen),
      state_key_generator_(state_key_generator),
      manager_(manager),
      login_metrics_(metrics),
      nss_(nss),
      chrome_mount_ns_path_(ns_path),
      system_(utils),
      crossystem_(crossystem),
      vpd_process_(vpd_process),
      owner_key_(owner_key),
      android_container_(android_container),
      install_attributes_reader_(install_attributes_reader),
      powerd_proxy_(powerd_proxy),
      system_clock_proxy_(system_clock_proxy),
      debugd_proxy_(debugd_proxy),
      arc_sideload_status_(arc_sideload_status),
      mitigator_(key_gen),
      ui_log_symlink_path_(kDefaultUiLogSymlinkPath),
      password_provider_(
          std::make_unique<password_provider::PasswordProvider>()),
      login_screen_storage_(std::make_unique<LoginScreenStorage>(
          base::FilePath(kLoginScreenStoragePath),
          std::make_unique<secret_util::SharedMemoryUtil>())),
      weak_ptr_factory_(this) {
  DCHECK(delegate_);
}

SessionManagerImpl::~SessionManagerImpl() {
  device_policy_->set_delegate(nullptr);  // Could use WeakPtr instead?
}

void SessionManagerImpl::SetPolicyServicesForTesting(
    std::unique_ptr<DevicePolicyService> device_policy,
    std::unique_ptr<UserPolicyServiceFactory> user_policy_factory,
    std::unique_ptr<DeviceLocalAccountManager> device_local_account_manager) {
  device_policy_ = std::move(device_policy);
  user_policy_factory_ = std::move(user_policy_factory);
  device_local_account_manager_ = std::move(device_local_account_manager);
}

void SessionManagerImpl::SetTickClockForTesting(
    std::unique_ptr<base::TickClock> clock) {
  tick_clock_ = std::move(clock);
}

void SessionManagerImpl::SetUiLogSymlinkPathForTesting(
    const base::FilePath& path) {
  ui_log_symlink_path_ = path;
}

void SessionManagerImpl::SetLoginScreenStorageForTesting(
    std::unique_ptr<LoginScreenStorage> login_screen_storage) {
  login_screen_storage_ = std::move(login_screen_storage);
}

void SessionManagerImpl::AnnounceSessionStoppingIfNeeded() {
  if (session_started_) {
    session_stopping_ = true;
    DLOG(INFO) << "Emitting D-Bus signal SessionStateChanged: " << kStopping;
    adaptor_.SendSessionStateChangedSignal(kStopping);
  }
}

void SessionManagerImpl::AnnounceSessionStopped() {
  session_stopping_ = session_started_ = false;
  DLOG(INFO) << "Emitting D-Bus signal SessionStateChanged: " << kStopped;
  adaptor_.SendSessionStateChangedSignal(kStopped);
}

bool SessionManagerImpl::ShouldEndSession(std::string* reason_out) {
  auto set_reason = [&](const std::string& reason) {
    if (reason_out)
      *reason_out = reason;
  };

  if (screen_locked_) {
    set_reason("screen is locked");
    return true;
  }

  if (supervised_user_creation_ongoing_) {
    set_reason("supervised user creation ongoing");
    return true;
  }

  if (suspend_ongoing_) {
    set_reason("suspend ongoing");
    return true;
  }

  if (!last_suspend_done_time_.is_null()) {
    const base::TimeDelta time_since_suspend =
        tick_clock_->NowTicks() - last_suspend_done_time_;
    if (time_since_suspend <= kCrashAfterSuspendInterval) {
      set_reason("suspend completed recently");
      return true;
    }
  }

  set_reason("");
  return false;
}

bool SessionManagerImpl::Initialize() {
  key_gen_->set_delegate(this);

  powerd_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface,
      power_manager::kSuspendImminentSignal,
      base::Bind(&SessionManagerImpl::OnSuspendImminent,
                 weak_ptr_factory_.GetWeakPtr()),
      base::Bind(&HandleDBusSignalConnected));
  powerd_proxy_->ConnectToSignal(power_manager::kPowerManagerInterface,
                                 power_manager::kSuspendDoneSignal,
                                 base::Bind(&SessionManagerImpl::OnSuspendDone,
                                            weak_ptr_factory_.GetWeakPtr()),
                                 base::Bind(&HandleDBusSignalConnected));

  system_clock_proxy_->WaitForServiceToBeAvailable(
      base::Bind(&SessionManagerImpl::OnSystemClockServiceAvailable,
                 weak_ptr_factory_.GetWeakPtr()));

  // Note: If SetPolicyServicesForTesting has been called, all services have
  // already been set and initialized.
  if (!device_policy_) {
    device_policy_ = DevicePolicyService::Create(
        owner_key_, login_metrics_, &mitigator_, nss_, crossystem_,
        vpd_process_, install_attributes_reader_);
    // Thinking about combining set_delegate() with the 'else' block below and
    // moving it down? Note that device_policy_->Initialize() might call
    // OnKeyPersisted() on the delegate, so be sure it's safe.
    device_policy_->set_delegate(this);
    if (!device_policy_->Initialize())
      return false;

    DCHECK(!user_policy_factory_);
    user_policy_factory_ =
        std::make_unique<UserPolicyServiceFactory>(nss_, system_);

    device_local_account_manager_ = std::make_unique<DeviceLocalAccountManager>(
        base::FilePath(kDeviceLocalAccountStateDir), owner_key_),
    device_local_account_manager_->UpdateDeviceSettings(
        device_policy_->GetSettings());
    if (device_policy_->MayUpdateSystemSettings())
      device_policy_->UpdateSystemSettings(PolicyService::Completion());
  } else {
    device_policy_->set_delegate(this);
  }

  arc_sideload_status_->Initialize();

  return true;
}

void SessionManagerImpl::Finalize() {
  // Reset the SessionManagerDBusAdaptor first to ensure that it'll permit
  // any outstanding DBusMethodCompletion objects to be abandoned without
  // having been run (http://crbug.com/638774, http://crbug.com/725734).
  dbus_service_.reset();

  device_policy_->PersistAllPolicy();
  for (const auto& kv : user_sessions_) {
    if (kv.second)
      kv.second->policy_service->PersistAllPolicy();
  }

  // Before persisting policies check if `device_local_account_manager_` was
  // initialized. Note that if `Initialize()` fails it won't be initialized.
  if (device_local_account_manager_)
    device_local_account_manager_->PersistAllPolicy();

  // We want to stop all running containers and VMs.  Containers and VMs are
  // per-session and cannot persist across sessions.
  android_container_->RequestJobExit(
      ArcContainerStopReason::SESSION_MANAGER_SHUTDOWN);
  android_container_->EnsureJobExit(kContainerTimeout);

  arc_sideload_status_.reset();
}

bool SessionManagerImpl::StartDBusService() {
  DCHECK(!dbus_service_);
  auto dbus_service = std::make_unique<DBusService>(&adaptor_);
  if (!dbus_service->Start(bus_))
    return false;

  dbus_service_ = std::move(dbus_service);
  return true;
}

void SessionManagerImpl::EmitLoginPromptVisible() {
  login_metrics_->RecordStats("login-prompt-visible");
  adaptor_.SendLoginPromptVisibleSignal();
  init_controller_->TriggerImpulse("login-prompt-visible", {},
                                   InitDaemonController::TriggerMode::ASYNC);
}

void SessionManagerImpl::EmitAshInitialized() {
  init_controller_->TriggerImpulse("ash-initialized", {},
                                   InitDaemonController::TriggerMode::ASYNC);
}

bool SessionManagerImpl::EnableChromeTesting(
    brillo::ErrorPtr* error,
    bool in_force_relaunch,
    const std::vector<std::string>& in_test_arguments,
    const std::vector<std::string>& in_test_environment_variables,
    std::string* out_filepath) {
  // Check to see if we already have Chrome testing enabled.
  bool already_enabled = !chrome_testing_path_.empty();

  if (!already_enabled) {
    base::FilePath temp_file_path;  // So we don't clobber chrome_testing_path_;
    if (!system_->GetUniqueFilenameInWriteOnlyTempDir(&temp_file_path)) {
      *error = CreateError(dbus_error::kTestingChannelError,
                           "Could not create testing channel filename.");
      return false;
    }
    chrome_testing_path_ = temp_file_path;
  }

  if (!already_enabled || in_force_relaunch) {
    // Delete testing channel file if it already exists.
    system_->RemoveFile(chrome_testing_path_);

    // Add testing channel argument to arguments.
    std::string testing_argument = kTestingChannelFlag;
    testing_argument.append(chrome_testing_path_.value());
    std::vector<std::string> test_args = in_test_arguments;
    test_args.push_back(testing_argument);
    manager_->SetBrowserTestArgs(test_args);
    manager_->SetBrowserAdditionalEnvironmentalVariables(
        in_test_environment_variables);
    manager_->RestartBrowser();
  }
  *out_filepath = chrome_testing_path_.value();
  return true;
}

bool SessionManagerImpl::LoginScreenStorageListKeys(
    brillo::ErrorPtr* error, std::vector<std::string>* out_keys) {
  *out_keys = login_screen_storage_->ListKeys();
  return true;
}

void SessionManagerImpl::LoginScreenStorageDelete(const std::string& in_key) {
  login_screen_storage_->Delete(in_key);
}

bool SessionManagerImpl::StartSession(brillo::ErrorPtr* error,
                                      const std::string& in_account_id,
                                      const std::string& in_unique_identifier) {
  std::string actual_account_id;
  if (!NormalizeAccountId(in_account_id, &actual_account_id, error)) {
    DCHECK(*error);
    return false;
  }

  // Check if this user already started a session.
  if (user_sessions_.count(actual_account_id) > 0) {
    *error =
        CREATE_ERROR_AND_LOG(dbus_error::kSessionExists,
                             "Provided user id already started a session.");
    return false;
  }

  // Create a UserSession object for this user.
  const bool is_incognito = IsIncognitoAccountId(actual_account_id);
  const OptionalFilePath ns_mnt_path = is_incognito || IsolateUserSession()
                                           ? chrome_mount_ns_path_
                                           : base::nullopt;
  auto user_session =
      CreateUserSession(actual_account_id, ns_mnt_path, is_incognito, error);
  if (!user_session) {
    DCHECK(*error);
    return false;
  }

  // Check whether the current user is the owner, and if so make sure they are
  // whitelisted and have an owner key.
  bool user_is_owner = false;
  if (!device_policy_->CheckAndHandleOwnerLogin(user_session->username,
                                                user_session->descriptor.get(),
                                                &user_is_owner, error)) {
    DCHECK(*error);
    return false;
  }

  // If all previous sessions were incognito (or no previous sessions exist).
  bool is_first_real_user = AllSessionsAreIncognito() && !is_incognito;

  // Send each user login event to UMA (right before we start session
  // since the metrics library does not log events in guest mode).
  const DevModeState dev_mode_state = system_->GetDevModeState();
  if (dev_mode_state != DevModeState::DEV_MODE_UNKNOWN) {
    login_metrics_->SendLoginUserType(
        dev_mode_state != DevModeState::DEV_MODE_OFF, is_incognito,
        user_is_owner);
  }

  // Make sure that Chrome's stdout and stderr, which may contain log messages
  // with user-specific data, don't get saved after the first user logs in:
  // https://crbug.com/904850
  if (user_sessions_.empty())
    DisconnectLogFile(ui_log_symlink_path_);

  init_controller_->TriggerImpulse(kStartUserSessionImpulse,
                                   {"CHROMEOS_USER=" + actual_account_id},
                                   InitDaemonController::TriggerMode::ASYNC);
  LOG(INFO) << "Starting user session";
  manager_->SetBrowserSessionForUser(actual_account_id, user_session->userhash);
  session_started_ = true;
  user_sessions_[actual_account_id] = std::move(user_session);
  if (is_first_real_user) {
    DCHECK(primary_user_account_id_.empty());
    primary_user_account_id_ = actual_account_id;
  }
  DLOG(INFO) << "Emitting D-Bus signal SessionStateChanged: " << kStarted;
  adaptor_.SendSessionStateChangedSignal(kStarted);

  // Active Directory managed devices are not expected to have a policy key.
  // Don't create one for them.
  const bool is_active_directory =
      install_attributes_reader_->GetAttribute(
          InstallAttributesReader::kAttrMode) ==
      InstallAttributesReader::kDeviceModeEnterpriseAD;
  if (device_policy_->KeyMissing() && !is_active_directory &&
      !device_policy_->Mitigating() && is_first_real_user) {
    // This is the first sign-in on this unmanaged device.  Take ownership.
    key_gen_->Start(actual_account_id, ns_mnt_path);
  }

  DeleteArcBugReportBackup(actual_account_id);

  // Record that a login has successfully completed on this boot.
  system_->AtomicFileWrite(base::FilePath(kLoggedInFlag), "1");
  return true;
}

bool SessionManagerImpl::SaveLoginPassword(
    brillo::ErrorPtr* error, const base::ScopedFD& in_password_fd) {
  if (!secret_util::SaveSecretFromPipe(password_provider_.get(),
                                       in_password_fd)) {
    LOG(ERROR) << "Could not save password.";
    return false;
  }
  return true;
}

bool SessionManagerImpl::LoginScreenStorageStore(
    brillo::ErrorPtr* error,
    const std::string& in_key,
    const std::vector<uint8_t>& in_metadata,
    uint64_t in_value_size,
    const base::ScopedFD& in_value_fd) {
  LoginScreenStorageMetadata metadata;
  if (!metadata.ParseFromArray(in_metadata.data(), in_metadata.size())) {
    *error = CreateError(DBUS_ERROR_INVALID_ARGS, "metadata parsing failed.");
    return false;
  }

  if (!metadata.clear_on_session_exit() && !user_sessions_.empty()) {
    *error = CreateError(DBUS_ERROR_FAILED,
                         "can't store persistent login screen data while there "
                         "are active user sessions.");
    return false;
  }

  return login_screen_storage_->Store(error, in_key, metadata, in_value_size,
                                      in_value_fd);
}

bool SessionManagerImpl::LoginScreenStorageRetrieve(
    brillo::ErrorPtr* error,
    const std::string& in_key,
    uint64_t* out_value_size,
    brillo::dbus_utils::FileDescriptor* out_value_fd) {
  base::ScopedFD value_fd;
  bool success =
      login_screen_storage_->Retrieve(error, in_key, out_value_size, &value_fd);
  *out_value_fd = std::move(value_fd);
  return success;
}

void SessionManagerImpl::StopSession(const std::string& in_unique_identifier) {
  StopSessionWithReason(
      static_cast<uint32_t>(SessionStopReason::REQUEST_FROM_SESSION_MANAGER));
}

void SessionManagerImpl::StopSessionWithReason(uint32_t reason) {
  LOG(INFO) << "Stopping all sessions reason = " << reason;
  // Most calls to StopSession() will log the reason for the call.
  // If you don't see a log message saying the reason for the call, it is
  // likely a D-Bus message.
  manager_->ScheduleShutdown();
  // TODO(cmasone): re-enable these when we try to enable logout without exiting
  //                the session manager
  // browser_.job->StopSession();
  // user_policy_.reset();
  // session_started_ = false;

  password_provider_->DiscardPassword();
}

bool SessionManagerImpl::LoadShillProfile(brillo::ErrorPtr* error,
                                          const std::string& in_account_id) {
  LOG(INFO) << "LoadShillProfile() method called.";
  std::string actual_account_id;
  if (!NormalizeAccountId(in_account_id, &actual_account_id, error)) {
    DCHECK(*error);
    return false;
  }
  init_controller_->TriggerImpulse(kLoadShillProfileImpulse,
                                   {"CHROMEOS_USER=" + actual_account_id},
                                   InitDaemonController::TriggerMode::ASYNC);
  return true;
}

void SessionManagerImpl::StorePolicyEx(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response,
    const std::vector<uint8_t>& in_descriptor_blob,
    const std::vector<uint8_t>& in_policy_blob) {
  StorePolicyInternalEx(in_descriptor_blob, in_policy_blob,
                        SignatureCheck::kEnabled, std::move(response));
}

void SessionManagerImpl::StoreUnsignedPolicyEx(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response,
    const std::vector<uint8_t>& in_descriptor_blob,
    const std::vector<uint8_t>& in_policy_blob) {
  brillo::ErrorPtr error = VerifyUnsignedPolicyStore();
  if (error) {
    response->ReplyWithError(error.get());
    return;
  }
  StorePolicyInternalEx(in_descriptor_blob, in_policy_blob,
                        SignatureCheck::kDisabled, std::move(response));
}

bool SessionManagerImpl::RetrievePolicyEx(
    brillo::ErrorPtr* error,
    const std::vector<uint8_t>& in_descriptor_blob,
    std::vector<uint8_t>* out_policy_blob) {
  PolicyDescriptor descriptor;
  if (!ParseAndValidatePolicyDescriptor(in_descriptor_blob,
                                        PolicyDescriptorUsage::kRetrieve,
                                        &descriptor, error)) {
    LOG(ERROR) << kParseDescriptorFailMessage;
    *error =
        CreateError(dbus_error::kSigEncodeFail, kParseDescriptorFailMessage);
    return false;
  }

  std::unique_ptr<PolicyService> storage;
  PolicyService* policy_service = GetPolicyService(descriptor, &storage, error);
  if (!policy_service) {
    LOG(ERROR) << kGetPolicyServiceFailMessage;
    *error =
        CreateError(dbus_error::kSigEncodeFail, kGetPolicyServiceFailMessage);
    return false;
  }

  PolicyNamespace ns(descriptor.domain(), descriptor.component_id());

  if (!policy_service->Retrieve(ns, out_policy_blob)) {
    LOG(ERROR) << kSigEncodeFailMessage;
    *error = CreateError(dbus_error::kSigEncodeFail, kSigEncodeFailMessage);
    return false;
  }
  return true;
}

bool SessionManagerImpl::ListStoredComponentPolicies(
    brillo::ErrorPtr* error,
    const std::vector<uint8_t>& in_descriptor_blob,
    std::vector<std::string>* out_component_ids) {
  PolicyDescriptor descriptor;
  if (!ParseAndValidatePolicyDescriptor(in_descriptor_blob,
                                        PolicyDescriptorUsage::kList,
                                        &descriptor, error)) {
    return false;
  }

  std::unique_ptr<PolicyService> storage;
  PolicyService* policy_service = GetPolicyService(descriptor, &storage, error);
  if (!policy_service)
    return false;

  *out_component_ids = policy_service->ListComponentIds(descriptor.domain());
  return true;
}

std::string SessionManagerImpl::RetrieveSessionState() {
  if (!session_started_)
    return kStopped;
  if (session_stopping_)
    return kStopping;
  return kStarted;
}

std::map<std::string, std::string>
SessionManagerImpl::RetrieveActiveSessions() {
  std::map<std::string, std::string> result;
  for (const auto& entry : user_sessions_) {
    if (!entry.second)
      continue;
    result[entry.second->username] = entry.second->userhash;
  }
  return result;
}

void SessionManagerImpl::RetrievePrimarySession(
    std::string* out_username, std::string* out_sanitized_username) {
  out_username->clear();
  out_sanitized_username->clear();
  if (user_sessions_.count(primary_user_account_id_) > 0) {
    out_username->assign(user_sessions_[primary_user_account_id_]->username);
    out_sanitized_username->assign(
        user_sessions_[primary_user_account_id_]->userhash);
  }
}

bool SessionManagerImpl::IsGuestSessionActive() {
  return !user_sessions_.empty() && AllSessionsAreIncognito();
}

void SessionManagerImpl::HandleSupervisedUserCreationStarting() {
  supervised_user_creation_ongoing_ = true;
}

void SessionManagerImpl::HandleSupervisedUserCreationFinished() {
  supervised_user_creation_ongoing_ = false;
}

bool SessionManagerImpl::LockScreen(brillo::ErrorPtr* error) {
  if (!session_started_) {
    *error = CREATE_WARNING_AND_LOG(
        dbus_error::kSessionDoesNotExist,
        "Attempt to lock screen outside of user session.");
    return false;
  }
  // If all sessions are incognito, then locking is not allowed.
  if (AllSessionsAreIncognito()) {
    *error =
        CREATE_WARNING_AND_LOG(dbus_error::kSessionExists,
                               "Attempt to lock screen during Guest session.");
    return false;
  }
  if (!screen_locked_) {
    screen_locked_ = true;
    init_controller_->TriggerImpulse(kScreenLockedImpulse, {},
                                     InitDaemonController::TriggerMode::ASYNC);
    delegate_->LockScreen();
  }
  LOG(INFO) << "LockScreen() method called.";
  return true;
}

void SessionManagerImpl::HandleLockScreenShown() {
  LOG(INFO) << "HandleLockScreenShown() method called.";
  adaptor_.SendScreenIsLockedSignal();
}

bool SessionManagerImpl::StartBrowserDataMigration(
    brillo::ErrorPtr* error, const std::string& in_account_id) {
  std::string actual_account_id;
  if (!NormalizeAccountId(in_account_id, &actual_account_id, error)) {
    DCHECK(*error);
    return false;
  }

  auto iter = user_sessions_.find(actual_account_id);
  // Check if this user already started a session.
  if (iter == user_sessions_.end()) {
    *error = CREATE_ERROR_AND_LOG(
        dbus_error::kSessionDoesNotExist,
        "Provided user id does not have a session started.");
    return false;
  }

  if (actual_account_id != primary_user_account_id_) {
    *error =
        CREATE_ERROR_AND_LOG(dbus_error::kInvalidAccount,
                             "Migration should only happen for primary user.");
    return false;
  }

  manager_->SetBrowserDataMigrationArgsForUser(iter->second->userhash);
  return true;
}

void SessionManagerImpl::HandleLockScreenDismissed() {
  screen_locked_ = false;
  init_controller_->TriggerImpulse(kScreenUnlockedImpulse, {},
                                   InitDaemonController::TriggerMode::ASYNC);
  LOG(INFO) << "HandleLockScreenDismissed() method called.";
  adaptor_.SendScreenIsUnlockedSignal();
}

bool SessionManagerImpl::IsScreenLocked() {
  return screen_locked_;
}

bool SessionManagerImpl::RestartJob(brillo::ErrorPtr* error,
                                    const base::ScopedFD& in_cred_fd,
                                    const std::vector<std::string>& in_argv,
                                    uint32_t mode) {
  struct ucred ucred = {0};
  socklen_t len = sizeof(struct ucred);
  if (!in_cred_fd.is_valid() || getsockopt(in_cred_fd.get(), SOL_SOCKET,
                                           SO_PEERCRED, &ucred, &len) == -1) {
    PLOG(ERROR) << "Can't get peer creds";
    *error = CreateError(dbus_error::kGetPeerCredsFailed, strerror(errno));
    return false;
  }

  if (!manager_->IsBrowser(ucred.pid)) {
    *error = CREATE_ERROR_AND_LOG(dbus_error::kUnknownPid,
                                  "Provided pid is unknown.");
    return false;
  }

  if (IsGuestMode(mode) != IsGuestSession(in_argv)) {
    *error =
        CREATE_ERROR_AND_LOG(dbus_error::kInvalidParameter,
                             "in_argv doesn't match mode for guest session.");
    return false;
  }

  // To set "logged-in" state for BWSI mode.
  if (IsGuestMode(mode) && !StartSession(error, kGuestUserName, "")) {
    DCHECK(*error);
    return false;
  }

  if (!IsGuestMode(mode) && IsSessionStarted()) {
    *error =
        CREATE_ERROR_AND_LOG(dbus_error::kInvalidParameter,
                             "Requested to restart non-guest user session.");
    return false;
  }

  manager_->SetBrowserArgs(in_argv);
  manager_->RestartBrowser();
  return true;
}

bool SessionManagerImpl::StartDeviceWipe(brillo::ErrorPtr* error) {
  if (system_->Exists(base::FilePath(kLoggedInFlag))) {
    *error = CREATE_ERROR_AND_LOG(dbus_error::kSessionExists,
                                  "A user has already logged in this boot.");
    return false;
  }

  InitiateDeviceWipe("session_manager_dbus_request");
  return true;
}

bool SessionManagerImpl::StartRemoteDeviceWipe(
    brillo::ErrorPtr* error, const std::vector<uint8_t>& in_signed_command) {
  if (!device_policy_->ValidateRemoteDeviceWipeCommand(in_signed_command)) {
    *error = CreateError(dbus_error::kInvalidParameter,
                         "Remote wipe command validation failed, aborting.");
    return false;
  }

  InitiateDeviceWipe("remote_wipe_request");
  return true;
}

void SessionManagerImpl::ClearForcedReEnrollmentVpd(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response) {
  device_policy_->ClearForcedReEnrollmentFlags(
      dbus_service_->CreatePolicyServiceCompletionCallback(
          std::move(response)));
}

bool SessionManagerImpl::StartTPMFirmwareUpdate(
    brillo::ErrorPtr* error, const std::string& update_mode) {
  // Make sure |update_mode| is supported.
  if (update_mode != kTPMFirmwareUpdateModeFirstBoot &&
      update_mode != kTPMFirmwareUpdateModePreserveStateful &&
      update_mode != kTPMFirmwareUpdateModeCleanup) {
    *error =
        CREATE_ERROR_AND_LOG(dbus_error::kInvalidParameter, "Bad update mode.");
    return false;
  }

  // Verify that we haven't seen a user log in since boot.
  if (system_->Exists(base::FilePath(kLoggedInFlag))) {
    *error = CREATE_ERROR_AND_LOG(dbus_error::kSessionExists,
                                  "A user has already logged in since boot.");
    return false;
  }

  // For remotely managed devices, make sure the requested update mode matches
  // the admin-configured one in device policy.
  if (install_attributes_reader_->GetAttribute(
          InstallAttributesReader::kAttrMode) ==
      InstallAttributesReader::kDeviceModeEnterprise) {
    const enterprise_management::TPMFirmwareUpdateSettingsProto& settings =
        device_policy_->GetSettings().tpm_firmware_update_settings();
    std::set<std::string> allowed_modes;
    if (settings.allow_user_initiated_powerwash()) {
      allowed_modes.insert(kTPMFirmwareUpdateModeFirstBoot);
    }
    if (settings.allow_user_initiated_preserve_device_state()) {
      allowed_modes.insert(kTPMFirmwareUpdateModePreserveStateful);
    }

    // See whether the requested mode is allowed. Cleanup is permitted when at
    // least one of the actual modes are allowed.
    bool allowed = (update_mode == kTPMFirmwareUpdateModeCleanup)
                       ? !allowed_modes.empty()
                       : allowed_modes.count(update_mode) > 0;
    if (!allowed) {
      *error = CreateError(dbus_error::kNotAvailable,
                           "Policy doesn't allow TPM firmware update.");
      return false;
    }
  }

  // Validate that a firmware update is actually available to make sure
  // enterprise users can't abuse TPM firmware update to trigger powerwash.
  bool available = false;
  if (update_mode == kTPMFirmwareUpdateModeFirstBoot ||
      update_mode == kTPMFirmwareUpdateModePreserveStateful) {
    std::string update_location;
    available =
        system_->ReadFileToString(
            base::FilePath(kTPMFirmwareUpdateLocationFile), &update_location) &&
        update_location.size();
  } else if (update_mode == kTPMFirmwareUpdateModeCleanup) {
    available = system_->Exists(
        base::FilePath(kTPMFirmwareUpdateSRKVulnerableROCAFile));
  }

  if (!available) {
    *error =
        CREATE_ERROR_AND_LOG(dbus_error::kNotAvailable, "No update available.");
    return false;
  }

  // Put the update request into place.
  if (!system_->AtomicFileWrite(
          base::FilePath(kTPMFirmwareUpdateRequestFlagFile), update_mode)) {
    *error = CREATE_ERROR_AND_LOG(dbus_error::kNotAvailable,
                                  "Failed to persist update request.");
    return false;
  }

  if (update_mode == kTPMFirmwareUpdateModeFirstBoot ||
      update_mode == kTPMFirmwareUpdateModeCleanup) {
    InitiateDeviceWipe("tpm_firmware_update_" + update_mode);
  } else if (update_mode == kTPMFirmwareUpdateModePreserveStateful) {
    // This flag file indicates that encrypted stateful should be preserved.
    if (!system_->AtomicFileWrite(
            base::FilePath(kStatefulPreservationRequestFile), update_mode)) {
      *error = CREATE_ERROR_AND_LOG(dbus_error::kNotAvailable,
                                    "Failed to request stateful preservation.");
      return false;
    }

    if (crossystem_->VbSetSystemPropertyInt(Crossystem::kClearTpmOwnerRequest,
                                            1) != 0) {
      *error = CREATE_ERROR_AND_LOG(dbus_error::kNotAvailable,
                                    "Failed to request TPM clear.");
      return false;
    }

    RestartDevice("tpm_firmware_update " + update_mode);
  } else {
    NOTREACHED();
    return false;
  }

  return true;
}

void SessionManagerImpl::SetFlagsForUser(
    const std::string& in_account_id,
    const std::vector<std::string>& in_flags) {
  manager_->SetFlagsForUser(in_account_id, in_flags);
}

void SessionManagerImpl::SetFeatureFlagsForUser(
    const std::string& in_account_id,
    const std::vector<std::string>& in_feature_flags,
    const std::map<std::string, std::string>& in_origin_list_flags) {
  manager_->SetFeatureFlagsForUser(in_account_id, in_feature_flags,
                                   in_origin_list_flags);
}

void SessionManagerImpl::GetServerBackedStateKeys(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        std::vector<std::vector<uint8_t>>>> response) {
  DCHECK(dbus_service_);
  ServerBackedStateKeyGenerator::StateKeyCallback callback =
      dbus_service_->CreateStateKeyCallback(std::move(response));
  if (system_clock_synchronized_) {
    state_key_generator_->RequestStateKeys(callback);
  } else {
    pending_state_key_callbacks_.push_back(callback);
  }
}

void SessionManagerImpl::OnSuspendImminent(dbus::Signal* signal) {
  suspend_ongoing_ = true;

  // If Chrome crashed recently, it might've missed this SuspendImminent signal
  // and failed to lock the screen. Stop the session as a precaution:
  // https://crbug.com/867970
  const base::TimeTicks start_time = manager_->GetLastBrowserRestartTime();
  if (!start_time.is_null() &&
      tick_clock_->NowTicks() - start_time <= kCrashBeforeSuspendInterval) {
    LOG(INFO) << "Stopping session for suspend after recent browser restart";
    StopSessionWithReason(
        static_cast<uint32_t>(SessionStopReason::SUSPEND_AFTER_RESTART));
  }
}

void SessionManagerImpl::OnSuspendDone(dbus::Signal* signal) {
  suspend_ongoing_ = false;
  last_suspend_done_time_ = tick_clock_->NowTicks();
}

void SessionManagerImpl::OnSystemClockServiceAvailable(bool service_available) {
  if (!service_available) {
    LOG(ERROR) << "Failed to listen for tlsdated service start";
    return;
  }

  GetSystemClockLastSyncInfo();
}

void SessionManagerImpl::GetSystemClockLastSyncInfo() {
  dbus::MethodCall method_call(system_clock::kSystemClockInterface,
                               system_clock::kSystemLastSyncInfo);
  system_clock_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::Bind(&SessionManagerImpl::OnGotSystemClockLastSyncInfo,
                 weak_ptr_factory_.GetWeakPtr()));
}

void SessionManagerImpl::OnGotSystemClockLastSyncInfo(
    dbus::Response* response) {
  if (!response) {
    LOG(ERROR) << system_clock::kSystemClockInterface << "."
               << system_clock::kSystemLastSyncInfo << " request failed.";
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE,
        base::Bind(&SessionManagerImpl::GetSystemClockLastSyncInfo,
                   weak_ptr_factory_.GetWeakPtr()),
        system_clock_last_sync_info_retry_delay_);
    return;
  }

  dbus::MessageReader reader(response);
  bool network_synchronized = false;
  if (!reader.PopBool(&network_synchronized)) {
    LOG(ERROR) << system_clock::kSystemClockInterface << "."
               << system_clock::kSystemLastSyncInfo
               << " response lacks network-synchronized argument";
    return;
  }

  if (network_synchronized) {
    system_clock_synchronized_ = true;
    for (const auto& callback : pending_state_key_callbacks_)
      state_key_generator_->RequestStateKeys(callback);
    pending_state_key_callbacks_.clear();
  } else {
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE,
        base::Bind(&SessionManagerImpl::GetSystemClockLastSyncInfo,
                   weak_ptr_factory_.GetWeakPtr()),
        system_clock_last_sync_info_retry_delay_);
  }
}

bool SessionManagerImpl::InitMachineInfo(brillo::ErrorPtr* error,
                                         const std::string& in_data) {
  std::map<std::string, std::string> params;
  if (!ServerBackedStateKeyGenerator::ParseMachineInfo(in_data, &params)) {
    *error = CreateError(dbus_error::kInitMachineInfoFail, "Parse failure.");
    return false;
  }

  if (!state_key_generator_->InitMachineInfo(params)) {
    *error =
        CreateError(dbus_error::kInitMachineInfoFail, "Missing parameters.");
    return false;
  }
  return true;
}

bool SessionManagerImpl::StartArcMiniContainer(
    brillo::ErrorPtr* error, const std::vector<uint8_t>& in_request) {
#if USE_CHEETS
  StartArcMiniContainerRequest request;
  if (!request.ParseFromArray(in_request.data(), in_request.size())) {
    *error = CreateError(DBUS_ERROR_INVALID_ARGS,
                         "StartArcMiniContainerRequest parsing failed.");
    return false;
  }

  std::vector<std::string> env_vars = {
      base::StringPrintf("CHROMEOS_DEV_MODE=%d", IsDevMode(system_)),
      base::StringPrintf("CHROMEOS_INSIDE_VM=%d", IsInsideVm(system_)),
      base::StringPrintf("NATIVE_BRIDGE_EXPERIMENT=%d",
                         request.native_bridge_experiment()),
      base::StringPrintf("ARC_FILE_PICKER_EXPERIMENT=%d",
                         request.arc_file_picker_experiment()),
      base::StringPrintf("ARC_CUSTOM_TABS_EXPERIMENT=%d",
                         request.arc_custom_tabs_experiment()),
      base::StringPrintf("DISABLE_SYSTEM_DEFAULT_APP=%d",
                         request.disable_system_default_app()),
      base::StringPrintf("DISABLE_MEDIA_STORE_MAINTENANCE=%d",
                         request.disable_media_store_maintenance()),
      base::StringPrintf("DISABLE_DOWNLOAD_PROVIDER=%d",
                         request.disable_download_provider())};

  if (request.arc_generate_pai())
    env_vars.push_back("ARC_GENERATE_PAI=1");

  if (request.lcd_density() > 0) {
    env_vars.push_back(
        base::StringPrintf("ARC_LCD_DENSITY=%d", request.lcd_density()));
  }

  switch (request.play_store_auto_update()) {
    case StartArcMiniContainerRequest_PlayStoreAutoUpdate_AUTO_UPDATE_DEFAULT:
      break;
    case StartArcMiniContainerRequest_PlayStoreAutoUpdate_AUTO_UPDATE_ON:
      env_vars.emplace_back("PLAY_STORE_AUTO_UPDATE=1");
      break;
    case StartArcMiniContainerRequest_PlayStoreAutoUpdate_AUTO_UPDATE_OFF:
      env_vars.emplace_back("PLAY_STORE_AUTO_UPDATE=0");
      break;
    default:
      NOTREACHED() << "Unhandled play store auto-update mode: "
                   << request.play_store_auto_update() << ".";
  }

  switch (request.dalvik_memory_profile()) {
    case StartArcMiniContainerRequest_DalvikMemoryProfile_MEMORY_PROFILE_DEFAULT:
      break;
    case StartArcMiniContainerRequest_DalvikMemoryProfile_MEMORY_PROFILE_4G:
      env_vars.emplace_back("DALVIK_MEMORY_PROFILE=4G");
      break;
    case StartArcMiniContainerRequest_DalvikMemoryProfile_MEMORY_PROFILE_8G:
      env_vars.emplace_back("DALVIK_MEMORY_PROFILE=8G");
      break;
    case StartArcMiniContainerRequest_DalvikMemoryProfile_MEMORY_PROFILE_16G:
      env_vars.emplace_back("DALVIK_MEMORY_PROFILE=16G");
      break;
    default:
      NOTREACHED() << "Unhandled dalvik_memory_profle: "
                   << request.dalvik_memory_profile() << ".";
  }

  if (!StartArcContainer(env_vars, error)) {
    DCHECK(*error);
    return false;
  }
  return true;
#else
  *error = CreateError(dbus_error::kNotAvailable, "ARC not supported.");
  return false;
#endif  // !USE_CHEETS
}

bool SessionManagerImpl::UpgradeArcContainer(
    brillo::ErrorPtr* error, const std::vector<uint8_t>& in_request) {
#if USE_CHEETS
  // Stop the existing instance if it fails to continue to boot an existing
  // container. Using Unretained() is okay because the closure will be called
  // before this function returns. If container was not running, this is no op.
  base::ScopedClosureRunner scoped_runner(base::Bind(
      &SessionManagerImpl::OnContinueArcBootFailed, base::Unretained(this)));

  UpgradeArcContainerRequest request;
  if (!request.ParseFromArray(in_request.data(), in_request.size())) {
    *error = CreateError(DBUS_ERROR_INVALID_ARGS,
                         "UpgradeArcContainerRequest parsing failed.");
    return false;
  }

  pid_t pid = 0;
  if (!android_container_->GetContainerPID(&pid)) {
    *error = CREATE_ERROR_AND_LOG(dbus_error::kArcContainerNotFound,
                                  "Failed to find mini-container for upgrade.");
    return false;
  }
  LOG(INFO) << "Android container is running with PID " << pid;

  // |arc_start_time_| is initialized when the container is upgraded (rather
  // than when the mini-container starts) since we are interested in measuring
  // time from when the user logs in until the system is ready to be interacted
  // with.
  arc_start_time_ = tick_clock_->NowTicks();

  // To upgrade the ARC mini-container, a certain amount of disk space is
  // needed under /home. We first check it.
  if (system_->AmountOfFreeDiskSpace(base::FilePath(kArcDiskCheckPath)) <
      kArcCriticalDiskFreeBytes) {
    *error = CREATE_ERROR_AND_LOG(dbus_error::kLowFreeDisk,
                                  "Low free disk under /home");
    StopArcInstanceInternal(ArcContainerStopReason::LOW_DISK_SPACE);
    ignore_result(scoped_runner.Release());
    return false;
  }

  std::string account_id;
  if (!NormalizeAccountId(request.account_id(), &account_id, error)) {
    DCHECK(*error);
    return false;
  }
  if (user_sessions_.count(account_id) == 0) {
    // This path can be taken if a forged D-Bus message for starting a full
    // (stateful) container is sent to session_manager before the actual
    // user's session has started. Do not remove the |account_id| check to
    // prevent such a container from starting on login screen.
    *error = CREATE_ERROR_AND_LOG(dbus_error::kSessionDoesNotExist,
                                  "Provided user ID does not have a session.");
    return false;
  }

  android_container_->SetStatefulMode(StatefulMode::STATEFUL);
  auto env_vars = CreateUpgradeArcEnvVars(request, account_id, pid);
  const base::TimeTicks arc_continue_boot_impulse_time = base::TimeTicks::Now();
  if (init_controller_->TriggerImpulse(
          kContinueArcBootImpulse, env_vars,
          InitDaemonController::TriggerMode::SYNC)) {
    login_metrics_->SendArcContinueBootImpulseTime(
        base::TimeTicks::Now() - arc_continue_boot_impulse_time);
  } else {
    *error = CREATE_ERROR_AND_LOG(dbus_error::kEmitFailed,
                                  "Emitting continue-arc-boot impulse failed.");

    BackupArcBugReport(account_id);
    return false;
  }

  login_metrics_->StartTrackingArcUseTime();

  ignore_result(scoped_runner.Release());
  DeleteArcBugReportBackup(account_id);

  return true;
#else
  *error = CreateError(dbus_error::kNotAvailable, "ARC not supported.");
  return false;
#endif  // !USE_CHEETS
}

bool SessionManagerImpl::StopArcInstance(brillo::ErrorPtr* error,
                                         const std::string& account_id,
                                         bool should_backup_log) {
#if USE_CHEETS
  if (should_backup_log && !account_id.empty()) {
    std::string actual_account_id;
    if (!NormalizeAccountId(account_id, &actual_account_id, error)) {
      DCHECK(*error);
      return false;
    }

    BackupArcBugReport(actual_account_id);
  }

  if (!StopArcInstanceInternal(ArcContainerStopReason::USER_REQUEST)) {
    *error = CREATE_ERROR_AND_LOG(dbus_error::kContainerShutdownFail,
                                  "Error getting Android container pid.");
    return false;
  }

  return true;
#else
  *error = CreateError(dbus_error::kNotAvailable, "ARC not supported.");
  return false;
#endif  // USE_CHEETS
}

bool SessionManagerImpl::SetArcCpuRestriction(brillo::ErrorPtr* error,
                                              uint32_t in_restriction_state) {
#if USE_CHEETS
  std::string shares_out;
  switch (static_cast<ContainerCpuRestrictionState>(in_restriction_state)) {
    case CONTAINER_CPU_RESTRICTION_FOREGROUND:
      shares_out = std::to_string(kCpuSharesForeground);
      break;
    case CONTAINER_CPU_RESTRICTION_BACKGROUND:
      shares_out = std::to_string(kCpuSharesBackground);
      break;
    default:
      *error = CREATE_ERROR_AND_LOG(dbus_error::kArcCpuCgroupFail,
                                    "Invalid CPU restriction state specified.");
      return false;
  }
  if (base::WriteFile(base::FilePath(kCpuSharesFile), shares_out.c_str(),
                      shares_out.length()) != shares_out.length()) {
    *error =
        CREATE_ERROR_AND_LOG(dbus_error::kArcCpuCgroupFail,
                             "Error updating Android container's cgroups.");
    return false;
  }
  return true;
#else
  *error = CreateError(dbus_error::kNotAvailable, "ARC not supported.");
  return false;
#endif
}

bool SessionManagerImpl::EmitArcBooted(brillo::ErrorPtr* error,
                                       const std::string& in_account_id) {
#if USE_CHEETS
  std::vector<std::string> env_vars;
  if (!in_account_id.empty()) {
    std::string actual_account_id;
    if (!NormalizeAccountId(in_account_id, &actual_account_id, error)) {
      DCHECK(*error);
      return false;
    }
    env_vars.emplace_back("CHROMEOS_USER=" + actual_account_id);
  }

  init_controller_->TriggerImpulse(kArcBootedImpulse, env_vars,
                                   InitDaemonController::TriggerMode::ASYNC);
  return true;
#else
  *error = CreateError(dbus_error::kNotAvailable, "ARC not supported.");
  return false;
#endif
}

bool SessionManagerImpl::GetArcStartTimeTicks(brillo::ErrorPtr* error,
                                              int64_t* out_start_time) {
#if USE_CHEETS
  if (arc_start_time_.is_null()) {
    *error = CreateError(dbus_error::kNotStarted, "ARC is not started yet.");
    return false;
  }
  *out_start_time = arc_start_time_.ToInternalValue();
  return true;
#else
  *error = CreateError(dbus_error::kNotAvailable, "ARC not supported.");
  return false;
#endif  // !USE_CHEETS
}

void SessionManagerImpl::EnableAdbSideloadCallbackAdaptor(
    brillo::dbus_utils::DBusMethodResponse<bool>* response,
    ArcSideloadStatusInterface::Status status,
    const char* error) {
  if (error != nullptr) {
    brillo::ErrorPtr dbus_error = CreateError(DBUS_ERROR_FAILED, error);
    response->ReplyWithError(dbus_error.get());
    return;
  }

  if (status == ArcSideloadStatusInterface::Status::NEED_POWERWASH) {
    brillo::ErrorPtr dbus_error = CreateError(DBUS_ERROR_NOT_SUPPORTED, error);
    response->ReplyWithError(dbus_error.get());
    return;
  }

  response->Return(status == ArcSideloadStatusInterface::Status::ENABLED);
}

void SessionManagerImpl::EnableAdbSideload(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response) {
  if (system_->Exists(base::FilePath(kLoggedInFlag))) {
    auto error = CREATE_ERROR_AND_LOG(
        dbus_error::kSessionExists,
        "EnableAdbSideload is not allowed once a user logged in this boot.");
    response->ReplyWithError(error.get());
    return;
  }

  arc_sideload_status_->EnableAdbSideload(base::Bind(
      &SessionManagerImpl::EnableAdbSideloadCallbackAdaptor,
      weak_ptr_factory_.GetWeakPtr(), base::Owned(response.release())));
}

void SessionManagerImpl::QueryAdbSideloadCallbackAdaptor(
    brillo::dbus_utils::DBusMethodResponse<bool>* response,
    ArcSideloadStatusInterface::Status status) {
  if (status == ArcSideloadStatusInterface::Status::NEED_POWERWASH) {
    brillo::ErrorPtr dbus_error =
        CreateError(DBUS_ERROR_NOT_SUPPORTED, "Need powerwash");
    response->ReplyWithError(dbus_error.get());
    return;
  }
  response->Return(status == ArcSideloadStatusInterface::Status::ENABLED);
}

void SessionManagerImpl::QueryAdbSideload(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response) {
  arc_sideload_status_->QueryAdbSideload(base::Bind(
      &SessionManagerImpl::QueryAdbSideloadCallbackAdaptor,
      weak_ptr_factory_.GetWeakPtr(), base::Owned(response.release())));
}

void SessionManagerImpl::OnPolicyPersisted(bool success) {
  device_local_account_manager_->UpdateDeviceSettings(
      device_policy_->GetSettings());
  adaptor_.SendPropertyChangeCompleteSignal(ToSuccessSignal(success));
}

void SessionManagerImpl::OnKeyPersisted(bool success) {
  adaptor_.SendSetOwnerKeyCompleteSignal(ToSuccessSignal(success));
}

void SessionManagerImpl::OnKeyGenerated(const std::string& username,
                                        const base::FilePath& temp_key_file) {
  ImportValidateAndStoreGeneratedKey(username, temp_key_file);
}

void SessionManagerImpl::ImportValidateAndStoreGeneratedKey(
    const std::string& username, const base::FilePath& temp_key_file) {
  DLOG(INFO) << "Processing generated key at " << temp_key_file.value();
  std::string key;

  // The temp key file will only exist in the user's mount namespace.
  OptionalFilePath ns_mnt_path =
      user_sessions_[username]->descriptor->ns_mnt_path;
  std::unique_ptr<brillo::ScopedMountNamespace> ns_mnt;
  if (ns_mnt_path) {
    ns_mnt = brillo::ScopedMountNamespace::CreateFromPath(ns_mnt_path.value());
  }
  base::ReadFileToString(temp_key_file, &key);
  PLOG_IF(WARNING, !base::DeleteFile(temp_key_file))
      << "Can't delete " << temp_key_file.value();
  ns_mnt.reset();

  device_policy_->ValidateAndStoreOwnerKey(
      username, StringToBlob(key), user_sessions_[username]->descriptor.get());
}

void SessionManagerImpl::InitiateDeviceWipe(const std::string& reason) {
  // The log string must not be confused with other clobbers-state parameters.
  // Sanitize by replacing all non-alphanumeric characters with underscores and
  // clamping size to 50 characters.
  std::string sanitized_reason(reason.substr(0, 50));
  std::locale locale("C");
  std::replace_if(
      sanitized_reason.begin(), sanitized_reason.end(),
      [&locale](const std::string::value_type character) {
        return !std::isalnum(character, locale);
      },
      '_');
  const base::FilePath reset_path(kResetFile);
  system_->AtomicFileWrite(reset_path,
                           "fast safe keepimg reason=" + sanitized_reason);
  RestartDevice(sanitized_reason);
}

// static
bool SessionManagerImpl::NormalizeAccountId(const std::string& account_id,
                                            std::string* actual_account_id_out,
                                            brillo::ErrorPtr* error_out) {
  if (ValidateAccountId(account_id, actual_account_id_out)) {
    DCHECK(!actual_account_id_out->empty());
    return true;
  }

  // TODO(alemate): adjust this error message after ChromeOS will stop using
  // email as cryptohome identifier.
  *error_out =
      CREATE_ERROR_AND_LOG(dbus_error::kInvalidAccount,
                           "Provided email address is not valid.  ASCII only.");
  DCHECK(actual_account_id_out->empty());
  return false;
}

bool SessionManagerImpl::AllSessionsAreIncognito() {
  size_t incognito_count = 0;
  for (UserSessionMap::const_iterator it = user_sessions_.begin();
       it != user_sessions_.end(); ++it) {
    if (it->second)
      incognito_count += it->second->is_incognito;
  }
  return incognito_count == user_sessions_.size();
}

std::unique_ptr<SessionManagerImpl::UserSession>
SessionManagerImpl::CreateUserSession(const std::string& username,
                                      const OptionalFilePath& ns_mnt_path,
                                      bool is_incognito,
                                      brillo::ErrorPtr* error) {
  std::unique_ptr<PolicyService> user_policy =
      user_policy_factory_->Create(username);
  if (!user_policy) {
    LOG(ERROR) << "User policy failed to initialize.";
    *error = CreateError(dbus_error::kPolicyInitFail, "Can't create session.");
    return nullptr;
  }

  ScopedPK11SlotDescriptor desc(
      nss_->OpenUserDB(GetUserPath(username), ns_mnt_path));

  if (!desc->slot) {
    LOG(ERROR) << "Could not open the current user's NSS database.";
    *error = CreateError(dbus_error::kNoUserNssDb, "Can't create session.");
    return nullptr;
  }

  return std::make_unique<UserSession>(username, SanitizeUserName(username),
                                       is_incognito, std::move(desc),
                                       std::move(user_policy));
}

brillo::ErrorPtr SessionManagerImpl::VerifyUnsignedPolicyStore() {
  // Unsigned policy store D-Bus call is allowed only in enterprise_ad mode.
  if (install_attributes_reader_->GetAttribute(
          InstallAttributesReader::kAttrMode) !=
      InstallAttributesReader::kDeviceModeEnterpriseAD) {
    return CREATE_ERROR_AND_LOG(dbus_error::kPolicySignatureRequired,
                                "Device mode doesn't permit unsigned policy.");
  }

  return nullptr;
}

PolicyService* SessionManagerImpl::GetPolicyService(
    const PolicyDescriptor& descriptor,
    std::unique_ptr<PolicyService>* storage,
    brillo::ErrorPtr* error) {
  DCHECK(storage);
  DCHECK(error);
  PolicyService* policy_service = nullptr;
  switch (descriptor.account_type()) {
    case ACCOUNT_TYPE_DEVICE: {
      policy_service = device_policy_.get();
      break;
    }
    case ACCOUNT_TYPE_USER: {
      UserSessionMap::const_iterator it =
          user_sessions_.find(descriptor.account_id());
      policy_service = it != user_sessions_.end()
                           ? it->second->policy_service.get()
                           : nullptr;
      break;
    }
    case ACCOUNT_TYPE_SESSIONLESS_USER: {
      // Special case, different lifetime management than all other cases
      // (unique_ptr vs plain ptr). TODO(crbug.com/771638): Clean this up when
      // the bug is fixed and sessionless users are handled differently.
      *storage = user_policy_factory_->CreateForHiddenUserHome(
          descriptor.account_id());
      policy_service = storage->get();
      break;
    }
    case ACCOUNT_TYPE_DEVICE_LOCAL_ACCOUNT: {
      policy_service = device_local_account_manager_->GetPolicyService(
          descriptor.account_id());
      break;
    }
  }
  if (policy_service)
    return policy_service;

  // Error case
  const std::string message =
      base::StringPrintf("Cannot get policy service for account type %i",
                         static_cast<int>(descriptor.account_type()));
  LOG(ERROR) << message;
  *error = CreateError(dbus_error::kGetServiceFail, message);
  return nullptr;
}

int SessionManagerImpl::GetKeyInstallFlags(const PolicyDescriptor& descriptor) {
  switch (descriptor.account_type()) {
    case ACCOUNT_TYPE_DEVICE: {
      int flags = PolicyService::KEY_ROTATE;
      if (!session_started_)
        flags |= PolicyService::KEY_INSTALL_NEW | PolicyService::KEY_CLOBBER;
      return flags;
    }
    case ACCOUNT_TYPE_USER:
      return PolicyService::KEY_INSTALL_NEW | PolicyService::KEY_ROTATE;
    case ACCOUNT_TYPE_SESSIONLESS_USER: {
      // Only supports retrieval, not storage.
      NOTREACHED();
      return PolicyService::KEY_NONE;
    }
    case ACCOUNT_TYPE_DEVICE_LOCAL_ACCOUNT:
      return PolicyService::KEY_NONE;
  }
}

void SessionManagerImpl::StorePolicyInternalEx(
    const std::vector<uint8_t>& descriptor_blob,
    const std::vector<uint8_t>& policy_blob,
    SignatureCheck signature_check,
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response) {
  brillo::ErrorPtr error;
  PolicyDescriptor descriptor;
  if (!ParseAndValidatePolicyDescriptor(descriptor_blob,
                                        PolicyDescriptorUsage::kStore,
                                        &descriptor, &error)) {
    response->ReplyWithError(error.get());
    return;
  }

  std::unique_ptr<PolicyService> storage;
  PolicyService* policy_service =
      GetPolicyService(descriptor, &storage, &error);
  if (!policy_service) {
    response->ReplyWithError(error.get());
    return;
  }

  int key_flags = GetKeyInstallFlags(descriptor);
  PolicyNamespace ns(descriptor.domain(), descriptor.component_id());

  // If the blob is empty, delete the policy.
  DCHECK(dbus_service_);
  if (policy_blob.empty()) {
    if (!policy_service->Delete(ns, signature_check)) {
      auto error =
          CreateError(dbus_error::kDeleteFail, "Failed to delete policy");
      response->ReplyWithError(error.get());
      return;
    }
    response->Return();
  } else {
    policy_service->Store(ns, policy_blob, key_flags, signature_check,
                          dbus_service_->CreatePolicyServiceCompletionCallback(
                              std::move(response)));
  }
}

void SessionManagerImpl::RestartDevice(const std::string& reason) {
  delegate_->RestartDevice("session_manager (" + reason + ")");
}

void SessionManagerImpl::BackupArcBugReport(const std::string& account_id) {
  if (user_sessions_.count(account_id) == 0) {
    LOG(ERROR) << "Cannot back up ARC bug report for inactive user.";
    return;
  }

  const base::TimeTicks arc_bug_report_backup_time = base::TimeTicks::Now();

  dbus::MethodCall method_call(debugd::kDebugdInterface,
                               debugd::kBackupArcBugReport);
  dbus::MessageWriter writer(&method_call);

  writer.AppendString(account_id);

  std::unique_ptr<dbus::Response> response(debugd_proxy_->CallMethodAndBlock(
      &method_call, kBackupArcBugReportTimeout.InMilliseconds()));

  if (response) {
    login_metrics_->SendArcBugReportBackupTime(base::TimeTicks::Now() -
                                               arc_bug_report_backup_time);
  } else {
    LOG(ERROR) << "Error contacting debugd to back up ARC bug report.";
  }
}

void SessionManagerImpl::DeleteArcBugReportBackup(
    const std::string& account_id) {
  dbus::MethodCall method_call(debugd::kDebugdInterface,
                               debugd::kDeleteArcBugReportBackup);
  dbus::MessageWriter writer(&method_call);

  writer.AppendString(account_id);

  std::unique_ptr<dbus::Response> response(debugd_proxy_->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT));

  if (!response) {
    LOG(ERROR) << "Error contacting debugd to delete ARC bug report backup.";
  }
}

bool SessionManagerImpl::IsSessionStarted() {
  return !user_sessions_.empty();
}

#if USE_CHEETS
bool SessionManagerImpl::StartArcContainer(
    const std::vector<std::string>& env_vars, brillo::ErrorPtr* error_out) {
  init_controller_->TriggerImpulse(kStartArcInstanceImpulse, env_vars,
                                   InitDaemonController::TriggerMode::ASYNC);

  // Pass in the same environment variables that were passed to arc-setup
  // (through init, above) into the container invocation as environment values.
  // When the container is started with run_oci, this allows for it to correctly
  // propagate some information (such as the CHROMEOS_USER) to the hooks so it
  // can set itself up.
  if (!android_container_->StartContainer(
          env_vars, base::Bind(&SessionManagerImpl::OnAndroidContainerStopped,
                               weak_ptr_factory_.GetWeakPtr()))) {
    // Failed to start container. Thus, trigger stop-arc-instance impulse
    // manually for cleanup.
    init_controller_->TriggerImpulse(kStopArcInstanceImpulse, {},
                                     InitDaemonController::TriggerMode::SYNC);
    *error_out = CREATE_ERROR_AND_LOG(dbus_error::kContainerStartupFail,
                                      "Starting Android container failed.");
    return false;
  }

  pid_t pid = 0;
  android_container_->GetContainerPID(&pid);
  LOG(INFO) << "Started Android container with PID " << pid;
  return true;
}

std::vector<std::string> SessionManagerImpl::CreateUpgradeArcEnvVars(
    const UpgradeArcContainerRequest& request,
    const std::string& account_id,
    pid_t pid) {
  // Only allow for managed account if the policies allow it.
  bool is_adb_sideloading_allowed_for_request =
      !request.is_account_managed() ||
      request.is_managed_adb_sideloading_allowed();

  std::vector<std::string> env_vars = {
      base::StringPrintf("CHROMEOS_DEV_MODE=%d", IsDevMode(system_)),
      base::StringPrintf("CHROMEOS_INSIDE_VM=%d", IsInsideVm(system_)),
      "CHROMEOS_USER=" + account_id,
      base::StringPrintf("DISABLE_BOOT_COMPLETED_BROADCAST=%d",
                         request.skip_boot_completed_broadcast()),
      base::StringPrintf("CONTAINER_PID=%d", pid),
      "DEMO_SESSION_APPS_PATH=" + request.demo_session_apps_path(),
      base::StringPrintf("IS_DEMO_SESSION=%d", request.is_demo_session()),
      base::StringPrintf("MANAGEMENT_TRANSITION=%d",
                         request.management_transition()),
      base::StringPrintf("ENABLE_ADB_SIDELOAD=%d",
                         arc_sideload_status_->IsAdbSideloadAllowed() &&
                             is_adb_sideloading_allowed_for_request)};

  switch (request.packages_cache_mode()) {
    case UpgradeArcContainerRequest_PackageCacheMode_SKIP_SETUP_COPY_ON_INIT:
      env_vars.emplace_back("SKIP_PACKAGES_CACHE_SETUP=1");
      env_vars.emplace_back("COPY_PACKAGES_CACHE=1");
      break;
    case UpgradeArcContainerRequest_PackageCacheMode_COPY_ON_INIT:
      env_vars.emplace_back("SKIP_PACKAGES_CACHE_SETUP=0");
      env_vars.emplace_back("COPY_PACKAGES_CACHE=1");
      break;
    case UpgradeArcContainerRequest_PackageCacheMode_DEFAULT:
      env_vars.emplace_back("SKIP_PACKAGES_CACHE_SETUP=0");
      env_vars.emplace_back("COPY_PACKAGES_CACHE=0");
      break;
    default:
      NOTREACHED() << "Wrong packages cache mode: "
                   << request.packages_cache_mode() << ".";
  }

  if (request.skip_gms_core_cache()) {
    env_vars.emplace_back("SKIP_GMS_CORE_CACHE_SETUP=1");
  } else {
    env_vars.emplace_back("SKIP_GMS_CORE_CACHE_SETUP=0");
  }

  DCHECK(request.has_locale());
  env_vars.emplace_back("LOCALE=" + request.locale());

  std::string preferred_languages;
  for (int i = 0; i < request.preferred_languages_size(); ++i) {
    if (i != 0)
      preferred_languages += ",";
    preferred_languages += request.preferred_languages(i);
  }
  env_vars.emplace_back("PREFERRED_LANGUAGES=" + preferred_languages);

  return env_vars;
}

void SessionManagerImpl::OnContinueArcBootFailed() {
  LOG(ERROR) << "Failed to continue ARC boot. Stopping the container.";
  StopArcInstanceInternal(ArcContainerStopReason::UPGRADE_FAILURE);
}

bool SessionManagerImpl::StopArcInstanceInternal(
    ArcContainerStopReason reason) {
  pid_t pid;
  if (!android_container_->GetContainerPID(&pid))
    return false;

  android_container_->RequestJobExit(reason);
  android_container_->EnsureJobExit(kContainerTimeout);
  return true;
}

void SessionManagerImpl::OnAndroidContainerStopped(
    pid_t pid, ArcContainerStopReason reason) {
  if (reason == ArcContainerStopReason::CRASH) {
    LOG(ERROR) << "Android container with PID " << pid << " crashed";
  } else {
    LOG(INFO) << "Android container with PID " << pid << " stopped";
  }

  login_metrics_->StopTrackingArcUseTime();
  if (!init_controller_->TriggerImpulse(
          kStopArcInstanceImpulse, {},
          InitDaemonController::TriggerMode::SYNC)) {
    LOG(ERROR) << "Emitting stop-arc-instance impulse failed.";
  }

  adaptor_.SendArcInstanceStoppedSignal(static_cast<uint32_t>(reason));
}
#endif  // USE_CHEETS
}  // namespace login_manager
