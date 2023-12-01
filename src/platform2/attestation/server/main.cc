// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>
#include <unistd.h>

#include <cstdlib>
#include <memory>
#include <optional>
#include <string>

#include <attestation/proto_bindings/google_key.pb.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/cryptohome.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/secure_blob.h>
#include <brillo/syslog_logging.h>
#include <brillo/userdb_utils.h>
#include <dbus/attestation/dbus-constants.h>
#include <libhwsec-foundation/profiling/profiling.h>
#include <libhwsec-foundation/vpd_reader/vpd_reader_impl.h>
#include <libhwsec-foundation/tpm_error/tpm_error_uma_reporter.h>
#include <libminijail.h>
#include <scoped_minijail.h>

#include "attestation/server/attestation_service.h"
#include "attestation/server/dbus_service.h"
#include "attestation/server/google_keys.h"

namespace {

const uid_t kRootUID = 0;
const char kAttestationUser[] = "attestation";
const char kAttestationGroup[] = "attestation";
const char kAttestationSeccompPath[] =
    "/usr/share/policy/attestationd-seccomp.policy";
constexpr char kGoogleKeysPath[] = "/run/attestation/google_keys.data";

namespace vpd_key {

constexpr char kAttestedDeviceId[] = "attested_device_id";

}

namespace env {
static const char kAttestationBasedEnrollmentDataFile[] = "ABE_DATA_FILE";
}  // namespace env

// Returns the contents of the attestation-based enrollment data file.
std::string ReadAbeDataFileContents() {
  std::string data;

  const char* abe_data_file =
      std::getenv(env::kAttestationBasedEnrollmentDataFile);
  if (!abe_data_file) {
    return data;
  }

  base::FilePath file_path(abe_data_file);
  if (!base::ReadFileToString(file_path, &data)) {
    LOG(FATAL) << "Could not read attestation-based enterprise enrollment data"
                  " in: "
               << file_path.value();
  }

  return data;
}

std::optional<attestation::GoogleKeys> ReadGoogleKeysIfExists() {
  base::FilePath file_path(kGoogleKeysPath);
  std::string data;
  if (!base::ReadFileToString(file_path, &data)) {
    return {};
  }
  LOG(INFO) << "Found key set to be injected.";
  attestation::DefaultGoogleRsaPublicKeySet default_key_set;
  if (!default_key_set.ParseFromString(data)) {
    LOG(WARNING) << "Failed ot parse google keys to be injected.";
    return {};
  }
  return attestation::GoogleKeys(default_key_set);
}

bool GetAttestationEnrollmentData(const std::string& abe_data_hex,
                                  brillo::SecureBlob* abe_data) {
  abe_data->clear();
  if (abe_data_hex.empty())
    return true;  // no data is ok.
  // The data must be a valid 32-byte hex string.
  return brillo::SecureBlob::HexStringToSecureBlob(abe_data_hex, abe_data) &&
         abe_data->size() == 32;
}

void InitMinijailSandbox() {
  uid_t attestation_uid;
  gid_t attestation_gid;
  CHECK(brillo::userdb::GetUserInfo(kAttestationUser, &attestation_uid,
                                    &attestation_gid))
      << "Error getting attestation uid and gid.";
  CHECK_EQ(getuid(), kRootUID) << "AttestationDaemon not initialized as root.";

  ScopedMinijail j(minijail_new());
  minijail_set_seccomp_filter_tsync(j.get());
  minijail_no_new_privs(j.get());
  minijail_use_seccomp_filter(j.get());
  minijail_parse_seccomp_filters(j.get(), kAttestationSeccompPath);
  minijail_change_user(j.get(), kAttestationUser);
  minijail_change_group(j.get(), kAttestationGroup);
  minijail_inherit_usergroups(j.get());
  minijail_enter(j.get());

  CHECK_EQ(getuid(), attestation_uid)
      << "AttestationDaemon was not able to drop to attestation user.";
  CHECK_EQ(getgid(), attestation_gid)
      << "AttestationDaemon was not able to drop to attestation group.";
}

}  // namespace

using brillo::dbus_utils::AsyncEventSequencer;

class AttestationDaemon : public brillo::DBusServiceDaemon {
 public:
  AttestationDaemon(brillo::SecureBlob abe_data,
                    std::string attested_device_id,
                    std::optional<attestation::GoogleKeys> google_keys)
      : brillo::DBusServiceDaemon(attestation::kAttestationServiceName),
        abe_data_(std::move(abe_data)),
        attestation_service_(&abe_data_, attested_device_id) {
    if (google_keys) {
      attestation_service_.set_google_keys(*google_keys);
    }
  }
  AttestationDaemon(const AttestationDaemon&) = delete;
  AttestationDaemon& operator=(const AttestationDaemon&) = delete;

 protected:
  int OnInit() override {
    int result = brillo::DBusServiceDaemon::OnInit();
    if (result != EX_OK) {
      LOG(ERROR) << "Error starting attestation dbus daemon.";
      return result;
    }
    attestation_service_.Initialize();
    return EX_OK;
  }

  void RegisterDBusObjectsAsync(AsyncEventSequencer* sequencer) override {
    dbus_service_.reset(
        new attestation::DBusService(bus_, &attestation_service_));
    dbus_service_->Register(sequencer->GetHandler("Register() failed.", true));
  }

 private:
  brillo::SecureBlob abe_data_;
  attestation::AttestationService attestation_service_;
  std::unique_ptr<attestation::DBusService> dbus_service_;
};

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int flags = brillo::kLogToSyslog;
  if (cl->HasSwitch("log_to_stderr")) {
    flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(flags);

  // Set TPM metrics client ID.
  hwsec_foundation::SetTpmMetricsClientID(
      hwsec_foundation::TpmMetricsClientID::kAttestation);

  // read whole abe_data_file before we init minijail.
  std::string abe_data_hex = ReadAbeDataFileContents();
  // Reads the system salt before we init minijail.
  if (!brillo::cryptohome::home::EnsureSystemSaltIsLoaded()) {
    LOG(FATAL) << "Failed to ensure system salt to be loaded into memory.";
  }

  PLOG_IF(FATAL, daemon(0, 0) == -1) << "Failed to daemonize";
  brillo::SecureBlob abe_data;
  if (!GetAttestationEnrollmentData(abe_data_hex, &abe_data)) {
    LOG(ERROR) << "Invalid attestation-based enterprise enrollment data.";
  }

  hwsec_foundation::VpdReaderImpl vpd_reader;
  std::optional<std::string> attested_device_id =
      vpd_reader.Get(vpd_key::kAttestedDeviceId);
  if (!attested_device_id.has_value()) {
    LOG(INFO) << "No ADID found.";
#if USE_TPM2_SIMULATOR
    constexpr char kFakeAttestedDeviceId[] = "fake_attested_device_id_";
    LOG(INFO) << "Setting ADID to " << kFakeAttestedDeviceId
              << " for simulator.";
    attested_device_id = "fake_attested_device_id_";
#endif
  }

  AttestationDaemon daemon(abe_data, attested_device_id.value_or(""),
                           ReadGoogleKeysIfExists());
  LOG(INFO) << "Attestation Daemon Started.";
  InitMinijailSandbox();

  // Start profiling.
  hwsec_foundation::SetUpProfiling();

  return daemon.Run();
}
