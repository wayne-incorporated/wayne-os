/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * This tool will attempt to mount or create the encrypted stateful partition,
 * and the various bind mountable subdirectories.
 *
 */
#define _FILE_OFFSET_BITS 64
#define CHROMEOS_ENVIRONMENT

#include <fcntl.h>
#include <sys/time.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/flag_helper.h>
#include <brillo/secure_blob.h>
#include <brillo/syslog_logging.h>
#include <vboot/crossystem.h>
#include <vboot/tlcl.h>

#include "cryptohome/mount_encrypted/encrypted_fs.h"
#include "cryptohome/mount_encrypted/encryption_key.h"
#include "cryptohome/mount_encrypted/mount_encrypted.h"
#include "cryptohome/mount_encrypted/mount_encrypted_metrics.h"
#include "cryptohome/mount_encrypted/tpm.h"
#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/encrypted_container_factory.h"

#include "cryptohome/storage/encrypted_container/filesystem_key.h"

#define PROP_SIZE 64

#if DEBUG_ENABLED
struct timeval tick = {};
struct timeval tick_start = {};
#endif

using mount_encrypted::paths::cryptohome::kTpmOwned;

namespace {
constexpr char kBioCryptoInitPath[] = "/usr/bin/bio_crypto_init";
constexpr char kBioTpmSeedSalt[] = "biod";
constexpr char kBioTpmSeedTmpDir[] = "/run/bio_crypto_init";
constexpr char kBioTpmSeedFile[] = "seed";
constexpr char kHibermanPath[] = "/usr/sbin/hiberman";
constexpr char kHibermanTpmSeedSalt[] = "hiberman";
constexpr char kHibermanTpmSeedTmpDir[] = "/run/hiberman";
constexpr char kHibermanTpmSeedFile[] = "tpm_seed";
constexpr char kFeaturedTpmSeedSalt[] = "featured";
constexpr char kFeaturedTpmSeedTmpDir[] = "/run/featured_seed";
constexpr char kFeaturedTpmSeedFile[] = "tpm_seed";
constexpr char kOldTpmOwnershipStateFile[] =
    "mnt/stateful_partition/.tpm_owned";
static const uid_t kBiodUid = 282;
static const gid_t kBiodGid = 282;
static const uid_t kHibermanUid = 20184;
static const gid_t kHibermanGid = 20184;
static const uid_t kRootUid = 0;
static const gid_t kRootGid = 0;

constexpr char kNvramExport[] = "/tmp/lockbox.nvram";
constexpr char kMountEncryptedMetricsPath[] =
    "/run/mount_encrypted/metrics.mount-encrypted";
}  // namespace

static result_code get_system_property(const char* prop,
                                       char* buf,
                                       size_t length) {
  int rc = VbGetSystemPropertyString(prop, buf, length);
  LOG(INFO) << "Got System Property '" << prop
            << "': " << ((rc == 0) ? buf : "FAIL");

  return rc == 0 ? RESULT_SUCCESS : RESULT_FAIL_FATAL;
}

static int has_chromefw(void) {
  static int state = -1;
  char fw[PROP_SIZE];

  /* Cache the state so we don't have to perform the query again. */
  if (state != -1)
    return state;

  if (get_system_property("mainfw_type", fw, sizeof(fw)) != RESULT_SUCCESS)
    state = 0;
  else
    state = strcmp(fw, "nonchrome") != 0;
  return state;
}

static bool shall_use_tpm_for_system_key() {
  if (!USE_TPM_INSECURE_FALLBACK) {
    return true;
  }

  if (has_chromefw()) {
    return true;
  }

  /* Don't use tpm for system key if we are using runtime TPM selection. */
  if (USE_TPM_DYNAMIC) {
    return false;
  }

  /* Assume we have tpm for system_key when we are using vtpm tpm2 simulator. */
  return USE_TPM2_SIMULATOR && USE_VTPM_PROXY;
}

static result_code report_info(mount_encrypted::EncryptedFs* encrypted_fs,
                               const base::FilePath& rootdir) {
  mount_encrypted::Tpm tpm;

  printf("TPM: %s\n", tpm.available() ? "yes" : "no");
  if (tpm.available()) {
    bool owned = false;
    printf("TPM Owned: %s\n", tpm.IsOwned(&owned) == RESULT_SUCCESS
                                  ? (owned ? "yes" : "no")
                                  : "fail");
  }
  printf("ChromeOS: %s\n", has_chromefw() ? "yes" : "no");
  printf("TPM2: %s\n", tpm.is_tpm2() ? "yes" : "no");
  if (shall_use_tpm_for_system_key()) {
    brillo::SecureBlob system_key;
    auto loader = mount_encrypted::SystemKeyLoader::Create(&tpm, rootdir);
    result_code rc = loader->Load(&system_key);
    if (rc != RESULT_SUCCESS) {
      printf("NVRAM: missing.\n");
    } else {
      printf("NVRAM: available.\n");
    }
  } else {
    printf("NVRAM: not present\n");
  }
  // Report info from the encrypted mount.
  encrypted_fs->ReportInfo();

  return RESULT_SUCCESS;
}

// Reads key material from the file |key_material_file|, creates a system key
// using the material, and persists the system key in NVRAM.
//
// This function only supports TPM 2.0 and should be called ONLY for testing
// purposes.
//
// Doesn't take ownership of |platform|.
// Return code indicates if every thing is successful.
static result_code set_system_key(const base::FilePath& rootdir,
                                  const char* key_material_file,
                                  cryptohome::Platform* platform) {
  if (!key_material_file) {
    LOG(ERROR) << "Key material file not provided.";
    return RESULT_FAIL_FATAL;
  }

  mount_encrypted::Tpm tpm;
  if (!tpm.is_tpm2()) {
    LOG(WARNING) << "Custom system key is not supported in TPM 1.2.";
    return RESULT_FAIL_FATAL;
  }

  brillo::SecureBlob key_material;
  if (!platform->ReadFileToSecureBlob(base::FilePath(key_material_file),
                                      &key_material)) {
    LOG(ERROR) << "Failed to read custom system key material from file "
               << key_material_file;
    return RESULT_FAIL_FATAL;
  }

  auto loader = mount_encrypted::SystemKeyLoader::Create(&tpm, rootdir);

  result_code rc = loader->Initialize(key_material, nullptr);
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to initialize system key NV space contents.";
    return rc;
  }

  rc = loader->Persist();
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to persist custom system key material in NVRAM.";
    return rc;
  }

  return RESULT_SUCCESS;
}

/* Exports NVRAM contents to tmpfs for use by install attributes */
void nvram_export(const brillo::SecureBlob& contents) {
  int fd;
  LOG(INFO) << "Export NVRAM contents";
  fd = open(kNvramExport, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    PLOG(ERROR) << "open(nvram_export)";
    return;
  }
  if (write(fd, contents.data(), contents.size()) != contents.size()) {
    // Don't leave broken files around
    unlink(kNvramExport);
  }
  close(fd);
}

bool SendSecretToTmpFile(const mount_encrypted::EncryptionKey& key,
                         const std::string& salt,
                         const base::FilePath& tmp_dir,
                         const std::string& filename,
                         uid_t user_id,
                         gid_t group_id,
                         cryptohome::Platform* platform) {
  brillo::SecureBlob tpm_seed = key.GetDerivedSystemKey(salt);
  if (tpm_seed.empty()) {
    LOG(ERROR) << "TPM Seed provided for " << filename << " is empty";
    return false;
  }

  if (!platform->SafeCreateDirAndSetOwnershipAndPermissions(
          tmp_dir,
          /* mode=700 */ S_IRUSR | S_IWUSR | S_IXUSR, user_id, group_id)) {
    PLOG(ERROR) << "Failed to CreateDir or SetOwnershipAndPermissions of "
                << tmp_dir;
    return false;
  }

  auto file = tmp_dir.Append(filename);
  if (!platform->WriteStringToFileAtomic(file, tpm_seed.to_string(),
                                         /* mode=600 */ S_IRUSR | S_IWUSR)) {
    PLOG(ERROR) << "Failed to write TPM seed to tmpfs file " << filename;
    return false;
  }

  if (!platform->SetOwnership(file, user_id, group_id, true)) {
    PLOG(ERROR) << "Failed to change ownership/perms of tmpfs file "
                << filename;
    // Remove the file as it contains the tpm seed with incorrect owner.
    PLOG_IF(ERROR, !base::DeleteFile(file)) << "Unable to remove file!";
    return false;
  }

  return true;
}

// Send a secret derived from the system key to the biometric managers, if
// available, via a tmpfs file which will be read by bio_crypto_init. The tmpfs
// directory will be created if it doesn't exist.
bool SendSecretToBiodTmpFile(const mount_encrypted::EncryptionKey& key,
                             cryptohome::Platform* platform) {
  // If there isn't a bio-sensor, don't bother.
  if (!base::PathExists(base::FilePath(kBioCryptoInitPath))) {
    LOG(INFO)
        << "There is no bio_crypto_init binary, so skip sending TPM seed.";
    return true;
  }

  return SendSecretToTmpFile(key, std::string(kBioTpmSeedSalt),
                             base::FilePath(kBioTpmSeedTmpDir), kBioTpmSeedFile,
                             kBiodUid, kBiodGid, platform);
}

// Send a secret derived from the system key to hiberman, if available, via a
// tmpfs file which will be read by hiberman. The tmpfs directory will be
// created if it doesn't exist.
bool SendSecretToHibermanTmpFile(const mount_encrypted::EncryptionKey& key,
                                 cryptohome::Platform* platform) {
  if (!base::PathExists(base::FilePath(kHibermanPath))) {
    LOG(INFO) << "There is no hiberman binary, so skip sending TPM seed.";
    return true;
  }

  return SendSecretToTmpFile(key, std::string(kHibermanTpmSeedSalt),
                             base::FilePath(kHibermanTpmSeedTmpDir),
                             kHibermanTpmSeedFile, kHibermanUid, kHibermanGid,
                             platform);
}

// Send a secret derived from the system key to featured, if available, via a
// tmpfs file which will be read by featured. The tmpfs directory will be
// created if it doesn't exist.
bool SendSecretToFeaturedTmpFile(const mount_encrypted::EncryptionKey& key,
                                 cryptohome::Platform* platform) {
  return SendSecretToTmpFile(key, std::string(kFeaturedTpmSeedSalt),
                             base::FilePath(kFeaturedTpmSeedTmpDir),
                             kFeaturedTpmSeedFile, kRootUid, kRootGid,
                             platform);
}

// Originally .tpm_owned file is located in /mnt/stateful_partition. Since the
// directory can only be written by root, .tpm_owned won't be able to get
// touched by tpm_managerd if we run it in minijail. Therefore, we need to
// migrate the files from /mnt/stateful_partition to the files into
// /mnt/stateful_partition/unencrypted/tpm_manager. The migration is written
// here since mount-encrypted is started before tpm_managerd.
bool migrate_tpm_owership_state_file() {
  auto dirname = base::FilePath(kTpmOwned).DirName();
  if (!base::CreateDirectory(dirname)) {
    LOG(ERROR) << "Failed to create dir for TPM pwnership state file.";
    return false;
  }

  if (base::PathExists(base::FilePath(kOldTpmOwnershipStateFile))) {
    LOG(INFO) << kOldTpmOwnershipStateFile << " exists. "
              << "Moving it to " << kTpmOwned;
    return base::Move(base::FilePath(kOldTpmOwnershipStateFile),
                      base::FilePath((kTpmOwned)));
  }
  return true;
}

static result_code mount_encrypted_partition(
    mount_encrypted::EncryptedFs* encrypted_fs,
    const base::FilePath& rootdir,
    cryptohome::Platform* platform,
    bool safe_mount) {
  result_code rc;

  mount_encrypted::ScopedMountEncryptedMetricsSingleton scoped_metrics(
      kMountEncryptedMetricsPath);

  // For the mount operation at boot, return RESULT_FAIL_FATAL to trigger
  // chromeos_startup do the stateful wipe.
  rc = encrypted_fs->CheckStates();
  if (rc != RESULT_SUCCESS)
    return rc;

  if (!migrate_tpm_owership_state_file()) {
    LOG(ERROR) << "Failed to migrate tpm owership state file to" << kTpmOwned;
  }

  mount_encrypted::Tpm tpm;
  auto loader = mount_encrypted::SystemKeyLoader::Create(&tpm, rootdir);
  mount_encrypted::EncryptionKey key(loader.get(), rootdir);
  if (shall_use_tpm_for_system_key() && safe_mount) {
    if (!tpm.available()) {
      // The TPM should be available before we load the system_key.
      LOG(ERROR) << "TPM not available.";
      // We shouldn't continue to load the system_key.
      return RESULT_FAIL_FATAL;
    }
    rc = key.LoadChromeOSSystemKey();
  } else {
    rc = key.SetInsecureFallbackSystemKey();
  }
  mount_encrypted::MountEncryptedMetrics::Get()->ReportSystemKeyStatus(
      key.system_key_status());
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  rc = key.LoadEncryptionKey();
  mount_encrypted::MountEncryptedMetrics::Get()->ReportEncryptionKeyStatus(
      key.encryption_key_status());
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  /* Log errors during sending seed to biod, but don't stop execution. */
  if (has_chromefw()) {
    LOG_IF(ERROR, !SendSecretToBiodTmpFile(key, platform))
        << "Failed to send TPM secret to biod.";
    LOG_IF(ERROR, !SendSecretToHibermanTmpFile(key, platform))
        << "Failed to send TPM secret to hiberman.";
    LOG_IF(ERROR, !SendSecretToFeaturedTmpFile(key, platform))
        << "Failed to send TPM secret to featured.";
  } else {
    LOG(ERROR) << "Failed to load system key, biod, hiberman, and featured "
                  "won't get a TPM seed.";
  }

  cryptohome::FileSystemKey encryption_key;
  encryption_key.fek = key.encryption_key();
  rc = encrypted_fs->Setup(encryption_key, key.is_fresh());
  if (rc == RESULT_SUCCESS) {
    /* Only check the lockbox when we are using TPM for system key. */
    if (shall_use_tpm_for_system_key()) {
      bool lockbox_valid = false;
      if (loader->CheckLockbox(&lockbox_valid) == RESULT_SUCCESS) {
        mount_encrypted::NvramSpace* lockbox_space = tpm.GetLockboxSpace();
        if (lockbox_valid && lockbox_space->is_valid()) {
          LOG(INFO) << "Lockbox is valid, exporting.";
          nvram_export(lockbox_space->contents());
        }
      } else {
        LOG(ERROR) << "Lockbox validity check error.";
      }
    }
  }

  LOG(INFO) << "Done.";

  // Continue boot.
  return rc;
}

static void print_usage(const char process_name[]) {
  fprintf(stderr, "Usage: %s [info|finalize|umount|set|mount]\n", process_name);
}

int main(int argc, const char* argv[]) {
  DEFINE_bool(unsafe, false, "mount encrypt partition with well known secret.");
  brillo::FlagHelper::Init(argc, argv, "mount-encrypted");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  logging::SetLogItems(false,   // process ID
                       false,   // thread ID
                       true,    // timestamp
                       false);  // tickcount

  auto commandline = base::CommandLine::ForCurrentProcess();
  auto args = commandline->GetArgs();

  char* rootdir_env = getenv("MOUNT_ENCRYPTED_ROOT");
  base::FilePath rootdir = base::FilePath(rootdir_env ? rootdir_env : "/");
  cryptohome::Platform platform;
  cryptohome::EncryptedContainerFactory encrypted_container_factory(&platform);
  brillo::DeviceMapper device_mapper;
  brillo::LogicalVolumeManager lvm;
  auto encrypted_fs = mount_encrypted::EncryptedFs::Generate(
      rootdir, &platform, &device_mapper, &lvm, &encrypted_container_factory);

  if (!encrypted_fs) {
    LOG(ERROR) << "Failed to create encrypted fs handler.";
    return RESULT_FAIL_FATAL;
  }

  LOG(INFO) << "Starting.";

  if (args.size() >= 1) {
    if (args[0] == "umount") {
      return encrypted_fs->Teardown();
    } else if (args[0] == "info") {
      // Report info from the encrypted mount.
      return report_info(encrypted_fs.get(), rootdir);
    } else if (args[0] == "set") {
      return set_system_key(rootdir, args.size() >= 2 ? args[1].c_str() : NULL,
                            &platform);
    } else if (args[0] == "mount") {
      return mount_encrypted_partition(encrypted_fs.get(), rootdir, &platform,
                                       !FLAGS_unsafe);
    } else {
      print_usage(argv[0]);
      return RESULT_FAIL_FATAL;
    }
  }

  // default operation is mount encrypted partition.
  return mount_encrypted_partition(encrypted_fs.get(), rootdir, &platform,
                                   !FLAGS_unsafe);
}
