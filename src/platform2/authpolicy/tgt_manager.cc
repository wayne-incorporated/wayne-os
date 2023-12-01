// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/tgt_manager.h"

#include <algorithm>
#include <tuple>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>

#include "authpolicy/anonymizer.h"
#include "authpolicy/authpolicy_flags.h"
#include "authpolicy/authpolicy_metrics.h"
#include "authpolicy/constants.h"
#include "authpolicy/jail_helper.h"
#include "authpolicy/log_colors.h"
#include "authpolicy/platform_helper.h"
#include "authpolicy/process_executor.h"
#include "authpolicy/samba_helper.h"
#include "bindings/authpolicy_containers.pb.h"

namespace authpolicy {

namespace {

// Requested TGT lifetimes in the kinit command. Format is 1d2h3m. If a server
// has a lower maximum lifetimes, the lifetimes of the TGT are capped.
const char kRequestedTgtValidityLifetime[] = "1d";
const char kRequestedTgtRenewalLifetime[] = "7d";

// Don't try to renew TGTs more often than this interval.
const int kMinTgtRenewDelaySeconds = 300;
static_assert(kMinTgtRenewDelaySeconds > 0, "");

// Fraction of the TGT validity lifetime to schedule automatic TGT renewal. For
// instance, if the TGT is valid for another 1000 seconds and the factor is 0.8,
// the TGT would be renewed after 800 seconds. Must be strictly between 0 and 1.
constexpr float kTgtRenewValidityLifetimeFraction = 0.8f;
static_assert(kTgtRenewValidityLifetimeFraction > 0.0f, "");
static_assert(kTgtRenewValidityLifetimeFraction < 1.0f, "");

// Size limit for GetKerberosFiles (1 MB).
const size_t kKrb5FileSizeLimit = 1024 * 1024;

// Invalid/unset file descriptor.
constexpr int kInvalidFd = -1;

// Encryption types for Kerberos configuration
constexpr char kEncTypesAES[] =
    "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96";
constexpr char kEncTypesRC4[] = "rc4-hmac";

// Kerberos configuration file data.
const char kKrb5ConfData[] =
    "[libdefaults]\n"
    "\tdefault_tgs_enctypes = %s\n"
    "\tdefault_tkt_enctypes = %s\n"
    "\tpermitted_enctypes = %s\n"
    // Prune weak ciphers from the above list. With current settings it’s a
    // no-op, but still.
    "\tallow_weak_crypto = false\n"
    // This flag allows for authentication forwarding without requiring the user
    // to enter a password again. (see
    // https://tools.ietf.org/html/rfc4120#section-2.6)
    "\tforwardable = true\n"
    // Default is 300 seconds, but we might add a policy for that in the future.
    "\tclockskew = 300\n"
    // Required for password change.
    "\tdefault_realm = %s\n";
const char kKrb5RealmData[] =
    "[realms]\n"
    "\t%s = {\n"
    "\t\tkdc = [%s]\n"
    "\t\tkpasswd_server = [%s]\n"
    "\t}\n";

// Env variable to trace debug info of kinit and kpasswd.
const char kKrb5TraceEnvKey[] = "KRB5_TRACE";

// Maximum kinit tries.
const int kKinitMaxTries = 60;
// Wait interval between two kinit tries.
constexpr base::TimeDelta kKinitRetryWait = base::Seconds(1);

// Keys for interpreting kinit, klist and kpasswd output.
const char kKeyBadPrincipal[] =
    "not found in Kerberos database while getting initial credentials";
const char kKeyBadPrincipal2[] =
    "Client not found in Kerberos database getting initial ticket";
const char kKeyBadPassword[] =
    "Preauthentication failed while getting initial credentials";
const char kKeyBadPassword2[] =
    "Password incorrect while getting initial credentials";
const char kKeyBadPassword3[] =
    "Preauthentication failed getting initial ticket";
const char kKeyPasswordExpiredStdout[] =
    "Password expired.  You must change it now.";
const char kKeyPasswordRejectedStdout[] = "Password change rejected";
const char kCannotReadPasswordStderr[] =
    "Cannot read password while getting initial credentials";
const char kKeyCannotResolve[] =
    "Cannot resolve network address for KDC in realm";
const char kKeyCannotContactKDC[] = "Cannot contact any KDC";
const char kKeyCannotFindKDC[] = "Cannot find KDC";
const char kKeyNoCredentialsCache[] = "No credentials cache found";
const char kKeyTicketExpired[] = "Ticket expired while renewing credentials";
const char kKeyEncTypeNotSupported[] = "KDC has no support for encryption type";

// Nice marker for TGT renewal related logs, for easy grepping.
const char kTgtRenewalHeader[] = "TGT RENEWAL - ";

// Returns true if the given principal is a machine principal.
bool IsMachine(const std::string& principal) {
  return Contains(principal, "$@");
}

// Reads the file at |path| into |data|. Returns |ERROR_LOCAL_IO| if the file
// could not be read.
[[nodiscard]] ErrorType ReadFile(const base::FilePath& path,
                                 std::string* data) {
  data->clear();
  if (!base::ReadFileToStringWithMaxSize(path, data, kKrb5FileSizeLimit)) {
    PLOG(ERROR) << "Failed to read '" << path.value() << "'";
    data->clear();
    return ERROR_LOCAL_IO;
  }
  return ERROR_NONE;
}

// Formats a time delta in 1h 2m 3s format.
std::string FormatTimeDelta(int delta_seconds) {
  int h = delta_seconds / 3600;
  int m = (delta_seconds / 60) % 60;
  int s = delta_seconds % 60;

  std::string str;
  if (h > 0)
    str += base::StringPrintf("%ih", h);
  if (h > 0 || m > 0)
    str += base::StringPrintf("%s%im", str.size() > 0 ? " " : "", m);
  str += base::StringPrintf("%s%is", str.size() > 0 ? " " : "", s);
  return str;
}

std::ostream& operator<<(std::ostream& os,
                         const protos::TgtLifetime& lifetime) {
  os << "(valid for " << FormatTimeDelta(lifetime.validity_seconds())
     << ", renewable for " << FormatTimeDelta(lifetime.renewal_seconds())
     << ")";
  return os;
}

// In case kinit failed, checks the output and returns appropriate error codes.
[[nodiscard]] ErrorType GetKinitError(const ProcessExecutor& kinit_cmd,
                                      bool is_machine_principal) {
  DCHECK_NE(0, kinit_cmd.GetExitCode());
  const std::string& kinit_out = kinit_cmd.GetStdout();
  const std::string& kinit_err = kinit_cmd.GetStderr();

  if (Contains(kinit_err, kKeyCannotContactKDC)) {
    LOG(ERROR) << "kinit failed - failed to contact KDC";
    return ERROR_CONTACTING_KDC_FAILED;
  }
  if (Contains(kinit_err, kKeyBadPrincipal)) {
    LOG(ERROR) << "kinit failed - bad "
               << (is_machine_principal ? "machine" : "user") << " name";
    return is_machine_principal ? ERROR_BAD_MACHINE_NAME : ERROR_BAD_USER_NAME;
  }
  if (Contains(kinit_err, kKeyBadPassword) ||
      Contains(kinit_err, kKeyBadPassword2)) {
    LOG(ERROR) << "kinit failed - bad password";
    return ERROR_BAD_PASSWORD;
  }
  // Check both stderr and stdout here since any kinit error in the change-
  // password-workflow would otherwise be interpreted as 'password expired'.
  if (Contains(kinit_out, kKeyPasswordExpiredStdout) &&
      Contains(kinit_err, kCannotReadPasswordStderr)) {
    if (Contains(kinit_out, kKeyPasswordRejectedStdout)) {
      LOG(ERROR) << "kinit failed - password rejected";
      return ERROR_PASSWORD_REJECTED;
    } else {
      LOG(ERROR) << "kinit failed - password expired";
      return ERROR_PASSWORD_EXPIRED;
    }
  }
  if (Contains(kinit_err, kKeyCannotResolve)) {
    LOG(ERROR) << "kinit failed - cannot resolve KDC realm";
    return ERROR_NETWORK_PROBLEM;
  }
  if (Contains(kinit_err, kKeyNoCredentialsCache)) {
    LOG(ERROR) << "kinit failed - no credentials cache found";
    return ERROR_NO_CREDENTIALS_CACHE_FOUND;
  }
  if (Contains(kinit_err, kKeyTicketExpired)) {
    LOG(ERROR) << "kinit failed - ticket expired";
    return ERROR_KERBEROS_TICKET_EXPIRED;
  }
  if (Contains(kinit_err, kKeyEncTypeNotSupported)) {
    LOG(ERROR) << "kinit failed - KDC does not support encryption type";
    return ERROR_KDC_DOES_NOT_SUPPORT_ENCRYPTION_TYPE;
  }
  LOG(ERROR) << "kinit failed with exit code " << kinit_cmd.GetExitCode();
  return ERROR_KINIT_FAILED;
}

// In case klist failed, checks the output and returns appropriate error codes.
[[nodiscard]] ErrorType GetKListError(const ProcessExecutor& klist_cmd) {
  DCHECK_NE(0, klist_cmd.GetExitCode());
  const std::string& klist_out = klist_cmd.GetStdout();
  const std::string& klist_err = klist_cmd.GetStderr();

  if (Contains(klist_err, kKeyNoCredentialsCache)) {
    LOG(ERROR) << "klist failed - no credentials cache found";
    return ERROR_NO_CREDENTIALS_CACHE_FOUND;
  }

  // Test the return value of klist -s. The command returns 1 if the TGT is
  // invalid and 0 otherwise. Does not print anything.
  const std::vector<std::string>& args = klist_cmd.GetArgs();
  if (klist_out.empty() && klist_err.empty() &&
      std::find(args.begin(), args.end(), "-s") != args.end()) {
    LOG(ERROR) << "klist failed - ticket expired";
    return ERROR_KERBEROS_TICKET_EXPIRED;
  }

  LOG(ERROR) << "klist failed with exit code " << klist_cmd.GetExitCode();
  return ERROR_KLIST_FAILED;
}

// In case kpasswd failed, checks the output and returns appropriate error
// codes.
[[nodiscard]] ErrorType GetKPasswdError(const ProcessExecutor& kpasswd_cmd,
                                        bool is_machine_principal) {
  DCHECK_NE(0, kpasswd_cmd.GetExitCode());
  const std::string& kpasswd_err = kpasswd_cmd.GetStderr();

  if (Contains(kpasswd_err, kKeyCannotContactKDC) ||
      Contains(kpasswd_err, kKeyCannotFindKDC)) {
    LOG(ERROR) << "kpasswd failed - failed to contact KDC";
    return ERROR_CONTACTING_KDC_FAILED;
  }
  if (Contains(kpasswd_err, kKeyBadPrincipal2)) {
    LOG(ERROR) << "kpasswd failed - bad "
               << (is_machine_principal ? "machine" : "user") << " name";
    return is_machine_principal ? ERROR_BAD_MACHINE_NAME : ERROR_BAD_USER_NAME;
  }
  if (Contains(kpasswd_err, kKeyBadPassword3)) {
    LOG(ERROR) << "kpasswd failed - bad password";
    return ERROR_BAD_PASSWORD;
  }
  if (Contains(kpasswd_err, kKeyPasswordRejectedStdout)) {
    LOG(ERROR) << "kpasswd failed - password rejected";
    return ERROR_PASSWORD_REJECTED;
  }

  LOG(ERROR) << "kpasswd failed with exit code " << kpasswd_cmd.GetExitCode();
  return ERROR_KPASSWD_FAILED;
}

std::string GetEncryptionTypesString(KerberosEncryptionTypes encryption_types) {
  switch (encryption_types) {
    case ENC_TYPES_ALL:
      return base::StringPrintf("%s %s", kEncTypesAES, kEncTypesRC4);
    case ENC_TYPES_STRONG:
      return kEncTypesAES;
    case ENC_TYPES_LEGACY:
      return kEncTypesRC4;
    case ENC_TYPES_COUNT:
      NOTREACHED() << "Not a valid encryption type and will default to strong.";
      return kEncTypesAES;
  }
}

}  // namespace

TgtManager::TgtManager(const PathService* path_service,
                       AuthPolicyMetrics* metrics,
                       const protos::DebugFlags* flags,
                       const JailHelper* jail_helper,
                       Anonymizer* anonymizer,
                       Delegate* delegate,
                       Path config_path,
                       Path credential_cache_path)
    : paths_(path_service),
      metrics_(metrics),
      flags_(flags),
      jail_helper_(jail_helper),
      anonymizer_(anonymizer),
      delegate_(delegate),
      config_path_(config_path),
      credential_cache_path_(credential_cache_path) {}

TgtManager::~TgtManager() {
  // Do a best-effort cleanup.
  base::DeleteFile(base::FilePath(paths_->Get(config_path_)));
  base::DeleteFile(base::FilePath(paths_->Get(credential_cache_path_)));

  // Note that the destructor of `tgt_renewal_callback_` does not cancel.
  tgt_renewal_callback_.Cancel();
}

void TgtManager::SetPrincipal(const std::string& principal) {
  principal_ = principal;
  is_machine_principal_ = IsMachine(principal);
}

void TgtManager::Reset() {
  principal_.clear();
  is_machine_principal_ = false;
  realm_.clear();
  kdc_ip_.clear();
  kinit_retry_ = false;
  encryption_types_ = ENC_TYPES_STRONG;
  EnableTgtAutoRenewal(false);
}

ErrorType TgtManager::AcquireTgtWithPassword(int password_fd) {
  return AcquireTgt(password_fd, Path::INVALID);
}

ErrorType TgtManager::AcquireTgtWithKeytab(Path keytab_path) {
  return AcquireTgt(kInvalidFd, keytab_path);
}

ErrorType TgtManager::AcquireTgt(int password_fd, Path keytab_path) {
  // Either password or keytab.
  DCHECK((password_fd != kInvalidFd) ^ (keytab_path != Path::INVALID));

  // Make sure we have the info we need.
  DCHECK(!principal_.empty());
  DCHECK(!realm_.empty());

  // Call kinit to get the Kerberos ticket-granting-ticket.
  ProcessExecutor kinit_cmd(
      {paths_->Get(Path::KINIT), principal_, kValidityLifetimeParam,
       kRequestedTgtValidityLifetime, kRenewalLifetimeParam,
       kRequestedTgtRenewalLifetime});
  if (keytab_path != Path::INVALID) {
    kinit_cmd.PushArg(kUseKeytabParam);
    kinit_cmd.SetEnv(kKrb5KTEnvKey, kFilePrefix + paths_->Get(keytab_path));
  }
  ErrorType error = RunKinit(&kinit_cmd, password_fd);
  if (error == ERROR_CONTACTING_KDC_FAILED) {
    LOG(WARNING) << "Retrying kinit without KDC IP config in the krb5.conf";
    kdc_ip_.clear();
    error = RunKinit(&kinit_cmd, password_fd);
  }

  // Don't retry again.
  kinit_retry_ = false;

  // If it worked, re-trigger the TGT renewal task.
  if (error == ERROR_NONE && tgt_autorenewal_enabled_)
    UpdateTgtAutoRenewal();

  // Trigger signal if files changed.
  MaybeTriggerKerberosFilesChanged();

  return error;
}

ErrorType TgtManager::GetKerberosFiles(KerberosFiles* files) {
  files->clear_krb5cc();
  files->clear_krb5conf();

  ErrorType error;
  std::string krb5cc;
  {
    // Note: The krb5cc is readable only by authpolicyd-exec.
    ScopedSwitchToSavedUid switch_scope;
    base::FilePath krb5cc_path(paths_->Get(credential_cache_path_));
    if (!base::PathExists(krb5cc_path))
      return ERROR_NONE;
    error = ReadFile(krb5cc_path, &krb5cc);
    if (error != ERROR_NONE)
      return error;
  }

  std::string krb5conf;
  base::FilePath krb5conf_path(paths_->Get(config_path_));
  error = ReadFile(krb5conf_path, &krb5conf);
  if (error != ERROR_NONE)
    return error;

  files->mutable_krb5cc()->assign(krb5cc.begin(), krb5cc.end());
  files->mutable_krb5conf()->assign(krb5conf.begin(), krb5conf.end());
  return ERROR_NONE;
}

void TgtManager::SetKerberosFilesChangedCallback(
    const base::RepeatingClosure& callback) {
  kerberos_files_changed_ = callback;
}

void TgtManager::EnableTgtAutoRenewal(bool enabled) {
  if (tgt_autorenewal_enabled_ != enabled) {
    tgt_autorenewal_enabled_ = enabled;
    UpdateTgtAutoRenewal();
  }
}

ErrorType TgtManager::RenewTgt() {
  // kinit -R renews the TGT.
  ProcessExecutor kinit_cmd({paths_->Get(Path::KINIT), kRenewParam});
  ErrorType error = RunKinit(&kinit_cmd, kInvalidFd);

  // No matter if it worked or not, reschedule auto-renewal. We might be offline
  // and want to try again later.
  UpdateTgtAutoRenewal();

  // Trigger signal if files changed.
  MaybeTriggerKerberosFilesChanged();

  // Let the delegate do its thing.
  delegate_->OnTgtRenewed();

  return error;
}

ErrorType TgtManager::GetTgtLifetime(protos::TgtLifetime* lifetime) {
  // Check local file first before calling klist -s, since that would respond
  // ERROR_KERBEROS_TICKET_EXPIRED instead of ERROR_NO_CREDENTIALS_CACHE_FOUND.
  if (!base::PathExists(base::FilePath(paths_->Get(credential_cache_path_)))) {
    LOG(ERROR) << "GetTgtLifetime failed - no credentials cache found";
    return ERROR_NO_CREDENTIALS_CACHE_FOUND;
  }

  // Call klist -s to find out whether the TGT is still valid.
  {
    ProcessExecutor klist_cmd({paths_->Get(Path::KLIST), kSetExitStatusParam,
                               kCredentialCacheParam,
                               paths_->Get(credential_cache_path_)});
    if (!jail_helper_->SetupJailAndRun(&klist_cmd, Path::KLIST_SECCOMP,
                                       TIMER_KLIST)) {
      return GetKListError(klist_cmd);
    }
  }

  // Now that we know the TGT is valid, call klist again (without -s) and parse
  // the output to get the TGT lifetime.
  {
    ProcessExecutor klist_cmd({paths_->Get(Path::KLIST), kCredentialCacheParam,
                               paths_->Get(credential_cache_path_)});
    if (!jail_helper_->SetupJailAndRun(&klist_cmd, Path::KLIST_SECCOMP,
                                       TIMER_KLIST)) {
      return GetKListError(klist_cmd);
    }

    // Parse the output to find the lifetime. Enclose in a sandbox for security
    // considerations.
    ProcessExecutor parse_cmd({paths_->Get(Path::PARSER), kCmdParseTgtLifetime,
                               SerializeFlags(*flags_)});
    parse_cmd.SetInputString(klist_cmd.GetStdout());
    if (!jail_helper_->SetupJailAndRun(&parse_cmd, Path::PARSER_SECCOMP,
                                       TIMER_NONE)) {
      LOG(ERROR) << "authpolicy_parser parse_tgt_lifetime failed with "
                 << "exit code " << parse_cmd.GetExitCode();
      return ERROR_PARSE_FAILED;
    }
    if (!lifetime->ParseFromString(parse_cmd.GetStdout())) {
      LOG(ERROR) << "Failed to parse TGT lifetime protobuf from string";
      return ERROR_PARSE_FAILED;
    }
    return ERROR_NONE;
  }
}

ErrorType TgtManager::ChangePassword(const std::string& old_password,
                                     const std::string& new_password) {
  // Write configuration.
  ErrorType error = WriteKrb5Conf();
  if (error != ERROR_NONE)
    return error;

  // Write passwords to pipe.
  base::ScopedFD password_fd = WriteStringToPipe(
      old_password + "\n" + new_password + "\n" + new_password);
  if (!password_fd.is_valid())
    return ERROR_LOCAL_IO;

  // Setup and run kpasswd command.
  DCHECK(!principal_.empty());
  ProcessExecutor kpasswd_cmd({paths_->Get(Path::KPASSWD), principal_});
  kpasswd_cmd.SetInputFile(password_fd.get());
  kpasswd_cmd.SetEnv(kKrb5ConfEnvKey, kFilePrefix + paths_->Get(config_path_));
  SetupKrb5Trace(&kpasswd_cmd);
  if (!jail_helper_->SetupJailAndRun(&kpasswd_cmd, Path::KPASSWD_SECCOMP,
                                     TIMER_KPASSWD)) {
    OutputKrb5Trace();
    return GetKPasswdError(kpasswd_cmd, is_machine_principal_);
  }
  return ERROR_NONE;
}

bool TgtManager::Backup(protos::TgtState* state) {
  // Read the TGT first since it can fail.
  // Note: The krb5cc is readable only by authpolicyd-exec.
  std::string krb5cc;
  {
    ScopedSwitchToSavedUid switch_scope;
    base::FilePath krb5cc_path(paths_->Get(credential_cache_path_));
    if (!base::ReadFileToStringWithMaxSize(krb5cc_path, &krb5cc,
                                           kKrb5FileSizeLimit)) {
      PLOG(ERROR)
          << "TGT backup failed to read Kerberos credential cache from '"
          << krb5cc_path.value() << "'";
      return false;
    }
  }

  // Store data in the state blob.
  DCHECK(state);
  state->set_realm(realm_);
  state->set_kdc_ip(kdc_ip_);
  state->set_principal(principal_);
  state->set_krb5cc(krb5cc);
  return true;
}

bool TgtManager::Restore(const protos::TgtState& state) {
  // Verify state.
  if (!state.has_realm() || !state.has_kdc_ip() || !state.has_principal() ||
      !state.has_krb5cc()) {
    LOG(ERROR) << "TGT restore failed, invalid state";
    return false;
  }

  // Write TGT first since it can fail.
  // Note: The krb5cc is writeable only by authpolicyd-exec.
  {
    ScopedSwitchToSavedUid switch_scope;
    const base::FilePath krb5cc_path(paths_->Get(credential_cache_path_));
    const int size = static_cast<int>(state.krb5cc().size());
    if (base::WriteFile(krb5cc_path, state.krb5cc().data(), size) != size) {
      PLOG(ERROR) << "TGT restore failed to write Kerberos credential cache to "
                  << krb5cc_path.value();
      return false;
    }
  }

  realm_ = state.realm();
  kdc_ip_ = state.kdc_ip();
  SetPrincipal(state.principal());

  // Do a best effort restoring the config. It is needed e.g. for
  // GetKerberosFiles(). Don't exit here since we'd be in an undefined state.
  // Even if this fails here, it'll eventually recover since many instances
  // write the config.
  std::ignore = WriteKrb5Conf();

  // Trigger files changed signal.
  kerberos_files_dirty_ = true;
  MaybeTriggerKerberosFilesChanged();

  return true;
}

ErrorType TgtManager::RunKinit(ProcessExecutor* kinit_cmd,
                               int password_fd) const {
  // Write configuration.
  ErrorType error = WriteKrb5Conf();
  if (error != ERROR_NONE)
    return error;

  // Set Kerberos credential cache and configuration file paths.
  kinit_cmd->SetEnv(kKrb5CCEnvKey, paths_->Get(credential_cache_path_));
  kinit_cmd->SetEnv(kKrb5ConfEnvKey, kFilePrefix + paths_->Get(config_path_));

  error = ERROR_NONE;
  const int max_tries = (kinit_retry_ ? kKinitMaxTries : 1);
  int tries, failed_tries = 0;
  for (tries = 1; tries <= max_tries; ++tries) {
    // Sleep between subsequent tries (probably a propagation issue).
    if (tries > 1 && !kinit_retry_sleep_disabled_for_testing_) {
      base::PlatformThread::Sleep(kKinitRetryWait);
    }
    SetupKrb5Trace(kinit_cmd);

    // Set password as input. Duplicate it in any case since we don't know
    // whether we'll have to rerun.
    base::ScopedFD password_dup;
    if (password_fd != kInvalidFd) {
      password_dup = DuplicatePipe(password_fd);
      if (!password_dup.is_valid()) {
        error = ERROR_LOCAL_IO;
        break;
      }
      kinit_cmd->SetInputFile(password_dup.get());
    }

    if (jail_helper_->SetupJailAndRun(kinit_cmd, Path::KINIT_SECCOMP,
                                      TIMER_KINIT)) {
      error = ERROR_NONE;
      break;
    }

    failed_tries++;
    OutputKrb5Trace();
    error = GetKinitError(*kinit_cmd, is_machine_principal_);

    // If kinit fails because credentials are not propagated yet, these are
    // the error types you get.
    if (error != ERROR_BAD_USER_NAME && error != ERROR_BAD_MACHINE_NAME &&
        error != ERROR_BAD_PASSWORD) {
      break;
    }
  }
  metrics_->Report(METRIC_KINIT_FAILED_TRY_COUNT, failed_tries);

  // If there was no error, assume that the Kerberos credential cache changed.
  if (error == ERROR_NONE)
    kerberos_files_dirty_ = true;

  return error;
}

ErrorType TgtManager::WriteKrb5Conf() const {
  const std::string enc_types = GetEncryptionTypesString(encryption_types_);
  std::string data =
      base::StringPrintf(kKrb5ConfData, enc_types.c_str(), enc_types.c_str(),
                         enc_types.c_str(), realm_.c_str());
  if (!kdc_ip_.empty()) {
    data += base::StringPrintf(kKrb5RealmData, realm_.c_str(), kdc_ip_.c_str(),
                               kdc_ip_.c_str());
  }
  const base::FilePath krbconf_path(paths_->Get(config_path_));

  // Only set kerberos_files_dirty_ if the config data has actually changed.
  // Otherwise, the KerberosFilesChanged signal gets triggered way too often,
  // causing the krb5cc in Chrome to reset all the time.
  std::string prev_data;
  if (!base::ReadFileToStringWithMaxSize(krbconf_path, &prev_data,
                                         kKrb5FileSizeLimit) ||
      data != prev_data) {
    const int data_size = static_cast<int>(data.size());
    if (base::WriteFile(krbconf_path, data.data(), data_size) != data_size) {
      LOG(ERROR) << "Failed to write krb5 conf file '" << krbconf_path.value()
                 << "'";
      return ERROR_LOCAL_IO;
    }
    kerberos_files_dirty_ = true;
  }

  return ERROR_NONE;
}

void TgtManager::SetupKrb5Trace(ProcessExecutor* krb5_cmd) const {
  if (!flags_->trace_krb5())
    return;
  const std::string& trace_path = paths_->Get(Path::KRB5_TRACE);
  {
    // Delete krb5 trace file (must be done as authpolicyd-exec).
    ScopedSwitchToSavedUid switch_scope;
    if (!base::DeleteFile(base::FilePath(trace_path))) {
      LOG(WARNING) << "Failed to delete krb5 trace file";
    }
  }
  krb5_cmd->SetEnv(kKrb5TraceEnvKey, trace_path);
}

void TgtManager::OutputKrb5Trace() const {
  if (!flags_->trace_krb5())
    return;
  const std::string& trace_path = paths_->Get(Path::KRB5_TRACE);
  std::string trace;
  {
    // Read krb5 trace file (must be done as authpolicyd-exec).
    ScopedSwitchToSavedUid switch_scope;
    if (!base::ReadFileToString(base::FilePath(trace_path), &trace))
      trace = "<failed to read>";
  }
  LogLongString(kColorKrb5Trace, "Krb5 trace: ", trace, anonymizer_);
}

void TgtManager::UpdateTgtAutoRenewal() {
  // Cancel an existing callback if there is any.
  if (!tgt_renewal_callback_.IsCancelled())
    tgt_renewal_callback_.Cancel();

  if (tgt_autorenewal_enabled_) {
    // Find out how long the TGT is valid.
    protos::TgtLifetime lifetime;
    ErrorType error = GetTgtLifetime(&lifetime);
    if (error == ERROR_NONE && lifetime.validity_seconds() > 0) {
      if (lifetime.validity_seconds() >= lifetime.renewal_seconds()) {
        // If we TGT got renewed a lot and/or is not renewable, the validity
        // lifetime is bounded by the renewal lifetime.
        LOG(WARNING) << kTgtRenewalHeader << "TGT cannot be renewed anymore "
                     << lifetime;
      } else {
        // Trigger the renewal somewhere in the validity lifetime of the TGT.
        int delay_seconds = static_cast<int>(lifetime.validity_seconds() *
                                             kTgtRenewValidityLifetimeFraction);

        // Make sure we don't trigger excessively often in case the renewal
        // fails and we're getting close to the end of the validity lifetime.
        delay_seconds = std::max(delay_seconds, kMinTgtRenewDelaySeconds);

        LOG(INFO) << kTgtRenewalHeader << "Scheduling renewal in "
                  << FormatTimeDelta(delay_seconds) << " " << lifetime;

        tgt_renewal_callback_.Reset(
            base::BindOnce(&TgtManager::AutoRenewTgt, base::Unretained(this)));
        base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
            FROM_HERE, tgt_renewal_callback_.callback(),
            base::Seconds(delay_seconds));
      }
    } else if (error == ERROR_KERBEROS_TICKET_EXPIRED) {
      // Expiry is the most likely error, print a nice message.
      LOG(WARNING) << kTgtRenewalHeader << "TGT expired, reinitializing "
                   << "requires credentials";
    }
  }
}

void TgtManager::AutoRenewTgt() {
  LOG(INFO) << kTgtRenewalHeader << "Running scheduled TGT renewal";
  ErrorType error = RenewTgt();
  if (error == ERROR_NONE)
    LOG(INFO) << kTgtRenewalHeader << "Succeeded";
  else
    LOG(ERROR) << kTgtRenewalHeader << "Failed with error " << error;
  metrics_->ReportError(ERROR_OF_AUTO_TGT_RENEWAL, error);
}

void TgtManager::MaybeTriggerKerberosFilesChanged() {
  if (kerberos_files_dirty_ && !kerberos_files_changed_.is_null())
    kerberos_files_changed_.Run();
  kerberos_files_dirty_ = false;
}

}  // namespace authpolicy
