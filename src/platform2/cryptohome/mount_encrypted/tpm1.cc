// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mount_encrypted/tpm.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <type_traits>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/file_utils.h>
#include <brillo/process/process.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <vboot/tpm1_tss_constants.h>

#include "cryptohome/mount_encrypted/mount_encrypted.h"
#include "cryptohome/mount_encrypted/mount_encrypted_metrics.h"

namespace mount_encrypted {
namespace {

const uint32_t kLockboxSaltOffset = 0x5;

// Attributes for the encstatful NVRAM space. Ideally, we'd set
// TPM_NV_PER_OWNERWRITE so the space gets automatically destroyed when the TPM
// gets cleared. That'd mean we'd have to recreate the NVRAM space on next boot
// though, which requires TPM ownership. Taking ownership is notoriously slow,
// so we can't afford to do this. Instead, we keep the space allocated and
// detect TPM clear to regenerate the system key.
const uint32_t kAttributes = TPM_NV_PER_WRITE_STCLEAR | TPM_NV_PER_READ_STCLEAR;

const uint32_t kAttributesMask =
    TPM_NV_PER_READ_STCLEAR | TPM_NV_PER_AUTHREAD | TPM_NV_PER_OWNERREAD |
    TPM_NV_PER_PPREAD | TPM_NV_PER_GLOBALLOCK | TPM_NV_PER_WRITE_STCLEAR |
    TPM_NV_PER_WRITEDEFINE | TPM_NV_PER_WRITEALL | TPM_NV_PER_AUTHWRITE |
    TPM_NV_PER_OWNERWRITE | TPM_NV_PER_PPWRITE;

// Key derivation labels.
const char kLabelSystemKey[] = "system_key";
const char kLabelLockboxMAC[] = "lockbox_mac";

// This is the well-known secret (SHA-1 hash of 20 zero bytes) that TrouSerS
// sets by default when taking ownership. We use the same value here to simplify
// the logic in cryptohomed.
const uint8_t kWellKnownSecret[TPM_AUTH_DATA_LEN] = {
    0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
    0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f,
};

// This struct defines the memory layout of the NVRAM area. Member sizes are
// chosen taking layout into consideration.
struct EncStatefulArea {
  enum class Flag {
    // The |lockbox_mac| field is valid and contains a MAC of the lockbox NVRAM
    // area contents.
    kLockboxMacValid = 0,
    // We are expecting another TPM clear to take place for which preservation
    // will be allowed. This is used to handle the TPM clear following a TPM
    // firmware update.
    kAnticipatingTPMClear = 1,
  };

  static constexpr uint32_t kMagic = 0x54504d31;

  static constexpr size_t kVersionShift = 8;
  static constexpr uint32_t kVersionMask = (1 << kVersionShift) - 1;

  static constexpr uint32_t kCurrentVersion = 1;

  uint32_t magic;
  uint32_t ver_flags;
  uint8_t key_material[DIGEST_LENGTH];
  uint8_t lockbox_mac[DIGEST_LENGTH];

  bool is_valid() const {
    return magic == kMagic && (ver_flags & kVersionMask) == kCurrentVersion;
  }

  static uint32_t flag_value(Flag flag) {
    return (1 << (static_cast<size_t>(flag) + kVersionShift));
  }

  bool test_flag(Flag flag) const { return ver_flags & flag_value(flag); }
  void set_flag(Flag flag) { ver_flags |= flag_value(flag); }
  void clear_flag(Flag flag) { ver_flags &= ~flag_value(flag); }

  result_code Init(const brillo::SecureBlob& new_key_material) {
    magic = kMagic;
    ver_flags = kCurrentVersion;

    size_t key_material_size = new_key_material.size();
    if (key_material_size != sizeof(key_material)) {
      LOG(ERROR) << "Invalid key material size " << key_material_size;
      return RESULT_FAIL_FATAL;
    }
    memcpy(key_material, new_key_material.data(), key_material_size);

    memset(lockbox_mac, 0, sizeof(lockbox_mac));
    return RESULT_SUCCESS;
  }

  brillo::SecureBlob DeriveKey(const std::string& label) const {
    return hwsec_foundation::HmacSha256(
        brillo::SecureBlob(key_material, key_material + sizeof(key_material)),
        brillo::Blob(label.data(), label.data() + label.size()));
  }
};

// We're using casts to map the EncStatefulArea struct to NVRAM contents, so
// make sure to keep this a POD type.
static_assert(std::is_pod<EncStatefulArea>(),
              "EncStatefulArea must be a POD type");

// Make sure that the EncStatefulArea struct fits the encstateful NVRAM space.
static_assert(kEncStatefulSize >= sizeof(EncStatefulArea),
              "EncStatefulArea must fit within encstateful NVRAM space");

}  // namespace

const uint8_t* kOwnerSecret = kWellKnownSecret;
const size_t kOwnerSecretSize = sizeof(kWellKnownSecret);

// System key loader implementation for TPM1 systems. This supports two
// different sources of obtaining system key material: A dedicated NVRAM space
// (called the "encstateful NVRAM space" below) and the "salt" in the lockbox
// space. We prefer the former if it is available.
class Tpm1SystemKeyLoader : public SystemKeyLoader {
 public:
  Tpm1SystemKeyLoader(Tpm* tpm, const base::FilePath& rootdir)
      : tpm_(tpm), rootdir_(rootdir) {}
  Tpm1SystemKeyLoader(const Tpm1SystemKeyLoader&) = delete;
  Tpm1SystemKeyLoader& operator=(const Tpm1SystemKeyLoader&) = delete;

  result_code Load(brillo::SecureBlob* key) override;
  result_code Initialize(const brillo::SecureBlob& key_material,
                         brillo::SecureBlob* derived_system_key) override;
  result_code Persist() override;
  void Lock() override;
  result_code SetupTpm() override;
  result_code GenerateForPreservation(brillo::SecureBlob* previous_key,
                                      brillo::SecureBlob* fresh_key) override;
  result_code CheckLockbox(bool* valid) override;
  bool UsingLockboxKey() override;

 private:
  // Gets a pointer to the EncStatefulArea structure backed by NVRAM.
  result_code LoadEncStatefulArea(const EncStatefulArea** area);

  // Loads the key from the encstateful NVRAM space.
  result_code LoadEncStatefulKey(brillo::SecureBlob* key);

  // Loads the key from the lockbox NVRAM space.
  result_code LoadLockboxKey(brillo::SecureBlob* key);

  // Define the encstateful space if it is not defined yet, or re-define it if
  // its attributes are bad, or the PCR binding is not correct. If necessary,
  // takes TPM ownership, which is necessary for defining the space.
  result_code PrepareEncStatefulSpace();

  // Prunes the stale files from the last TPM ownership.
  result_code PruneOwnershipStateFilesIfNotOwned();

  enum class EncStatefulSpaceValidity {
    // The space is not defined, too short, or attributes are bad.
    kInvalid,
    // The space has valid content.
    kValid,
    // The space is defined but no valid content.
    kWritable,
  };
  // Validates the encstateful space is defined with correct parameters.
  result_code IsEncStatefulSpaceProperlyDefined(
      EncStatefulSpaceValidity* validity);

  // Obtains and formats TPM version info as key-value pairs.
  std::string FormatVersionInfo();

  // Obtains and formats IFX field upgrade status as key-value pairs.
  std::string FormatIFXFieldUpgradeInfo();

  // Check whether a TPM firmware update is pending. Returns true if there is an
  // update, false if no pending update and on errors.
  bool IsTPMFirmwareUpdatePending();

  Tpm* tpm_ = nullptr;
  base::FilePath rootdir_;

  // Provisional space contents that get initialized by Generate() and written
  // to the NVRAM space by Persist();
  std::unique_ptr<brillo::SecureBlob> provisional_contents_;

  // Whether we're using the lockbox salt as system key.
  bool using_lockbox_key_ = false;
};

// TPM cases:
//  - does not exist at all (disabled in test firmware or non-chrome device).
//  - exists (below).
//
// TPM ownership cases:
//  - unowned (OOBE):
//    - expect modern lockbox.
//  - owned: depends on NVRAM area (below).
//
// NVRAM area cases:
//  - no NVRAM area at all:
//    - interrupted install (cryptohome has the TPM password)
//    - ancient device (cr48, cryptohome has thrown away TPM password)
//    - broken device (cryptohome has thrown away/never had TPM password)
//      - must expect worst-case: no lockbox ever.
//  - defined NVRAM area, but not written to ("Finalized"); interrupted OOBE.
//  - written ("Finalized") NVRAM area.
//
// In case of success: (NVRAM area found and used)
//  - *system_key populated with NVRAM area entropy.
// In case of failure: (NVRAM missing or error)
//  - *system_key untouched.
result_code Tpm1SystemKeyLoader::Load(brillo::SecureBlob* system_key) {
  EncStatefulSpaceValidity space_validity = EncStatefulSpaceValidity::kInvalid;
  result_code rc = IsEncStatefulSpaceProperlyDefined(&space_validity);
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  // Prefer the encstateful space if it is set up correctly.
  if (space_validity == EncStatefulSpaceValidity::kValid) {
    // Only load the key if we are sure that we have generated a fresh key after
    // the last TPM clear. After a clear, the TPM has no owner. In unowned state
    // we rely on a flag we store persistently in the TPM to indicate whether we
    // have generated a key already (note that the TPM automatically clears the
    // flag on TPM clear).
    bool system_key_initialized = false;
    rc = tpm_->HasSystemKeyInitializedFlag(&system_key_initialized);
    if (rc != RESULT_SUCCESS) {
      return rc;
    }

    if (system_key_initialized) {
      rc = LoadEncStatefulKey(system_key);
      if (rc == RESULT_SUCCESS) {
        return RESULT_SUCCESS;
      }
    }
  } else {
    // The lockbox NVRAM space is created by cryptohomed and only valid after
    // TPM ownership has been established.
    bool owned = false;
    result_code rc = tpm_->IsOwned(&owned);
    if (rc != RESULT_SUCCESS) {
      LOG(ERROR) << "Failed to determine TPM ownership.";
      return rc;
    }

    if (owned) {
      rc = LoadLockboxKey(system_key);
      if (rc == RESULT_SUCCESS) {
        using_lockbox_key_ = true;
        return RESULT_SUCCESS;
      }
    }
  }

  return RESULT_FAIL_FATAL;
}

result_code Tpm1SystemKeyLoader::Initialize(
    const brillo::SecureBlob& key_material,
    brillo::SecureBlob* derived_system_key) {
  provisional_contents_ =
      std::make_unique<brillo::SecureBlob>(sizeof(EncStatefulArea));
  EncStatefulArea* area =
      reinterpret_cast<EncStatefulArea*>(provisional_contents_->data());

  result_code rc = area->Init(key_material);
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  if (derived_system_key) {
    *derived_system_key = area->DeriveKey(kLabelSystemKey);
  }

  return RESULT_SUCCESS;
}

result_code Tpm1SystemKeyLoader::Persist() {
  CHECK(provisional_contents_);

  result_code rc = PrepareEncStatefulSpace();
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to preapare encstateful space.";
    return rc;
  }

  NvramSpace* encstateful_space = tpm_->GetEncStatefulSpace();
  rc = encstateful_space->Write(*provisional_contents_);
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to write NVRAM area";
    return rc;
  }

  rc = tpm_->SetSystemKeyInitializedFlag();
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to create placeholder delegation entry.";
    return rc;
  }

  using_lockbox_key_ = false;
  return RESULT_SUCCESS;
}

void Tpm1SystemKeyLoader::Lock() {
  NvramSpace* encstateful_space = tpm_->GetEncStatefulSpace();
  if (!encstateful_space->is_valid()) {
    return;
  }

  if (encstateful_space->WriteLock() != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to write-lock NVRAM area.";
  }
  if (encstateful_space->ReadLock() != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to read-lock NVRAM area.";
  }
}

result_code Tpm1SystemKeyLoader::SetupTpm() {
  return PrepareEncStatefulSpace();
}

result_code Tpm1SystemKeyLoader::PrepareEncStatefulSpace() {
  EncStatefulSpaceValidity space_validity = EncStatefulSpaceValidity::kInvalid;
  result_code rc = IsEncStatefulSpaceProperlyDefined(&space_validity);
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  bool owned = false;
  rc = tpm_->IsOwned(&owned);
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Can't determine TPM ownership.";
    return RESULT_FAIL_FATAL;
  }

  // The encryptied stateful space is prepared iff the TPM is owned and has
  // valid space.
  if (owned && space_validity != EncStatefulSpaceValidity::kInvalid) {
    return RESULT_SUCCESS;
  }

  // We need to take ownership and redefine the space.
  LOG(INFO) << "Redefining encrypted stateful space.";

  if (!owned) {
    result_code rc = PruneOwnershipStateFilesIfNotOwned();
    if (rc != RESULT_SUCCESS) {
      LOG(ERROR) << "Failed to prune ownership state files.";
      return rc;
    }

    const base::TimeTicks take_ownerhip_start_time = base::TimeTicks::Now();
    rc = tpm_->TakeOwnership();
    if (rc != RESULT_SUCCESS) {
      LOG(ERROR) << "Failed to ensure TPM ownership.";
      return rc;
    }
    MountEncryptedMetrics::Get()->ReportTimeToTakeTpmOwnership(
        base::TimeTicks::Now() - take_ownerhip_start_time);
  } else {
    const base::FilePath tpm_owned_path =
        rootdir_.AppendASCII(paths::cryptohome::kTpmOwned);
    if (base::PathExists(tpm_owned_path)) {
      LOG(ERROR)
          << "Unable to define space because TPM is already fully initialized.";
      return RESULT_FAIL_FATAL;
    }
  }

  uint32_t pcr_selection = (1 << kPCRBootMode);
  rc = tpm_->GetEncStatefulSpace()->Define(kAttributes, sizeof(EncStatefulArea),
                                           pcr_selection);
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to define encrypted stateful NVRAM space.";
    return rc;
  }

  return RESULT_SUCCESS;
}

result_code Tpm1SystemKeyLoader::PruneOwnershipStateFilesIfNotOwned() {
  bool owned = false;
  result_code rc = tpm_->IsOwned(&owned);
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Can't determine TPM ownership.";
    return RESULT_FAIL_FATAL;
  }

  // If it's owned already, it is not necessary to clean up the files.
  if (owned) {
    return RESULT_SUCCESS;
  }

  // Reset ownership state files to make them consistent with TPM ownership.
  base::FilePath tpm_status_path =
      rootdir_.AppendASCII(paths::cryptohome::kTpmStatus);
  base::FilePath tpm_owned_path =
      rootdir_.AppendASCII(paths::cryptohome::kTpmOwned);
  base::FilePath shall_initialize_path =
      rootdir_.AppendASCII(paths::cryptohome::kShallInitialize);
  base::FilePath attestation_database_path =
      rootdir_.AppendASCII(paths::cryptohome::kAttestationDatabase);
  if (!base::DeleteFile(tpm_status_path) || !base::DeleteFile(tpm_owned_path) ||
      !brillo::SyncFileOrDirectory(tpm_status_path.DirName(), true, false) ||
      !brillo::WriteToFileAtomic(shall_initialize_path, nullptr, 0, 0644) ||
      !brillo::SyncFileOrDirectory(shall_initialize_path.DirName(), true,
                                   false) ||
      !base::DeleteFile(attestation_database_path)) {
    PLOG(ERROR) << "Failed to update ownership state files.";
    return RESULT_FAIL_FATAL;
  }

  return RESULT_SUCCESS;
}

result_code Tpm1SystemKeyLoader::GenerateForPreservation(
    brillo::SecureBlob* previous_key, brillo::SecureBlob* fresh_key) {
  // Determine whether we may preserve the encryption key that was in use before
  // the TPM got cleared. Preservation is allowed if either (1) a TPM firmware
  // update is pending and has been requested for installation or (2) we've
  // taken a note in NVRAM space flags to anticipate a TPM clear. Condition (2)
  // covers the TPM clear that follows installation of the firmware update. We'd
  // prefer to handle that case by testing whether we actually just went through
  // an update, but there's no trustworthy post-factum signal to tell us.
  const EncStatefulArea* area = nullptr;
  bool tpm_firmware_update_pending = false;
  result_code rc = LoadEncStatefulArea(&area);
  if (rc != RESULT_SUCCESS ||
      !area->test_flag(EncStatefulArea::Flag::kAnticipatingTPMClear)) {
    tpm_firmware_update_pending = IsTPMFirmwareUpdatePending();
    if (!tpm_firmware_update_pending) {
      return RESULT_FAIL_FATAL;
    }
  }

  // Load the previous system key.
  rc = LoadEncStatefulKey(previous_key);
  if (rc != RESULT_SUCCESS) {
    rc = LoadLockboxKey(previous_key);
    if (rc != RESULT_SUCCESS) {
      return RESULT_FAIL_FATAL;
    }
  }

  // Generate new encstateful contents.
  provisional_contents_ =
      std::make_unique<brillo::SecureBlob>(sizeof(EncStatefulArea));
  EncStatefulArea* provisional_area =
      reinterpret_cast<EncStatefulArea*>(provisional_contents_->data());

  const auto key_material =
      hwsec_foundation::CreateSecureRandomBlob(DIGEST_LENGTH);
  rc = provisional_area->Init(key_material);
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  // Set the flag to anticipate another TPM clear for the case where we're
  // preserving for the installation of a TPM firmware update.
  if (tpm_firmware_update_pending) {
    provisional_area->set_flag(EncStatefulArea::Flag::kAnticipatingTPMClear);
  }

  // We need to leave the TPM in a state with owner auth available. However,
  // when preserving the state of the system, we must guarantee lockbox
  // integrity. To achieve lockbox tamper evidence, we store a MAC of the
  // lockbox space in the encstateful space, which gets locked to prevent
  // further manipulation in Lock(). We can thus re-check lockbox contents are
  // legit at next reboot by verifying the MAC.
  provisional_area->set_flag(EncStatefulArea::Flag::kLockboxMacValid);
  NvramSpace* lockbox_space = tpm_->GetLockboxSpace();
  if (lockbox_space->is_valid()) {
    brillo::SecureBlob mac = hwsec_foundation::HmacSha256(
        provisional_area->DeriveKey(kLabelLockboxMAC),
        lockbox_space->contents());
    memcpy(provisional_area->lockbox_mac, mac.data(), mac.size());
  }

  *fresh_key = provisional_area->DeriveKey(kLabelSystemKey);
  using_lockbox_key_ = false;
  return RESULT_SUCCESS;
}

result_code Tpm1SystemKeyLoader::LoadEncStatefulArea(
    const EncStatefulArea** area) {
  NvramSpace* space = tpm_->GetEncStatefulSpace();
  if (!space->is_valid()) {
    LOG(ERROR) << "Invalid encstateful space.";
    return RESULT_FAIL_FATAL;
  }

  *area = reinterpret_cast<const EncStatefulArea*>(space->contents().data());
  if (!(*area)->is_valid()) {
    LOG(ERROR) << "Invalid encstateful contents.";
    return RESULT_FAIL_FATAL;
  }

  return RESULT_SUCCESS;
}

result_code Tpm1SystemKeyLoader::LoadEncStatefulKey(
    brillo::SecureBlob* system_key) {
  const EncStatefulArea* area = nullptr;
  result_code rc = LoadEncStatefulArea(&area);
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  *system_key = area->DeriveKey(kLabelSystemKey);
  return RESULT_SUCCESS;
}

result_code Tpm1SystemKeyLoader::LoadLockboxKey(
    brillo::SecureBlob* system_key) {
  brillo::SecureBlob key_material;
  NvramSpace* lockbox_space = tpm_->GetLockboxSpace();
  const brillo::SecureBlob& lockbox_contents = lockbox_space->contents();
  if (!lockbox_space->is_valid()) {
    return RESULT_FAIL_FATAL;
  } else if (lockbox_contents.size() == kLockboxSizeV1) {
    key_material = lockbox_contents;
  } else if (kLockboxSaltOffset + DIGEST_LENGTH <= lockbox_contents.size()) {
    const uint8_t* begin = lockbox_contents.data() + kLockboxSaltOffset;
    key_material.assign(begin, begin + DIGEST_LENGTH);
  } else {
    LOG(INFO) << "Impossibly small NVRAM area size (" << lockbox_contents.size()
              << ").";
    return RESULT_FAIL_FATAL;
  }

  *system_key = hwsec_foundation::Sha256(key_material);
  return RESULT_SUCCESS;
}

result_code Tpm1SystemKeyLoader::IsEncStatefulSpaceProperlyDefined(
    EncStatefulSpaceValidity* validity) {
  *validity = EncStatefulSpaceValidity::kInvalid;

  NvramSpace* encstateful_space = tpm_->GetEncStatefulSpace();
  if (!encstateful_space->is_valid() && !encstateful_space->is_writable()) {
    LOG(ERROR) << "encstateful space is neither valid nor writable.";
    return RESULT_SUCCESS;
  }
  if (encstateful_space->contents().size() < sizeof(EncStatefulArea)) {
    LOG(ERROR) << "encstateful space contents too short.";
    return RESULT_SUCCESS;
  }

  uint32_t attributes;
  result_code rc = encstateful_space->GetAttributes(&attributes);
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  if ((attributes & kAttributesMask) != kAttributes) {
    LOG(ERROR) << "Bad encstateful space attributes.";
    return rc;
  }

  uint32_t pcr_selection = (1 << kPCRBootMode);
  bool pcr_binding_correct = false;
  rc = encstateful_space->CheckPCRBinding(pcr_selection, &pcr_binding_correct);
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Bad encstateful PCR binding.";
    return rc;
  }
  if (!pcr_binding_correct) {
    LOG(ERROR) << "Incorrect PCR binding.";
    return RESULT_SUCCESS;
  }

  // At this point, the space is confirmed to be defined with correct attributes
  // and PCR binding. `NvramSpace` should returns either `is_valid()` or
  // `is_writable()` to be true by design; for they are translated from one enum
  // variable.
  DCHECK_NE(encstateful_space->is_valid(), encstateful_space->is_writable());
  if (encstateful_space->is_valid()) {
    *validity = EncStatefulSpaceValidity::kValid;
  } else {
    *validity = EncStatefulSpaceValidity::kWritable;
  }

  return RESULT_SUCCESS;
}

std::string Tpm1SystemKeyLoader::FormatVersionInfo() {
  uint32_t vendor;
  uint64_t firmware_version;
  std::vector<uint8_t> vendor_specific;
  if (!tpm_->GetVersionInfo(&vendor, &firmware_version, &vendor_specific)) {
    return std::string();
  }

  return base::StringPrintf(
      "vendor %08x\nfirmware_version %016" PRIx64 "\nvendor_specific %s",
      vendor, firmware_version,
      base::HexEncode(vendor_specific.data(), vendor_specific.size()).c_str());
}

std::string Tpm1SystemKeyLoader::FormatIFXFieldUpgradeInfo() {
  TPM_IFX_FIELDUPGRADEINFO info;
  if (!tpm_->GetIFXFieldUpgradeInfo(&info)) {
    return std::string();
  }

  auto format_fw_pkg = [](const TPM_IFX_FIRMWAREPACKAGE& firmware_package,
                          const char* prefix) {
    return base::StringPrintf(
        "%s_package_id %08x\n"
        "%s_version %08x\n"
        "%s_stale_version %08x\n",
        prefix, firmware_package.FwPackageIdentifier, prefix,
        firmware_package.Version, prefix, firmware_package.StaleVersion);
  };

  return base::StringPrintf(
      "max_data_size %u\n"
      "%s"
      "%s"
      "%s"
      "status %04x\n"
      "%s"
      "field_upgrade_counter %u\n",
      info.wMaxDataSize,
      format_fw_pkg(info.sBootloaderFirmwarePackage, "bootloader").c_str(),
      format_fw_pkg(info.sFirmwarePackages[0], "fw0").c_str(),
      format_fw_pkg(info.sFirmwarePackages[1], "fw1").c_str(),
      info.wSecurityModuleStatus,
      format_fw_pkg(info.sProcessFirmwarePackage, "process_fw").c_str(),
      info.wFieldUpgradeCounter);
}

bool Tpm1SystemKeyLoader::IsTPMFirmwareUpdatePending() {
  // Make sure a TPM firmware upgrade has been requested.
  if (!base::PathExists(rootdir_.AppendASCII(paths::kFirmwareUpdateRequest))) {
    LOG(ERROR) << "TPM firmware update wasn't requested.";
    return false;
  }

  // Obtain version and upgrade status information to pass to the locator tool.
  std::string version_info = FormatVersionInfo();
  std::string ifx_field_upgrade_info = FormatIFXFieldUpgradeInfo();
  if (version_info.empty() || ifx_field_upgrade_info.empty()) {
    return false;
  }

  // Launch the update locator script.
  brillo::ProcessImpl tpm_firmware_update_locator;
  tpm_firmware_update_locator.SetCloseUnusedFileDescriptors(true);
  tpm_firmware_update_locator.RedirectUsingPipe(STDOUT_FILENO, false);
  tpm_firmware_update_locator.AddArg(
      rootdir_.AppendASCII(paths::kFirmwareUpdateLocator).value());
  tpm_firmware_update_locator.AddArg(version_info);
  tpm_firmware_update_locator.AddArg(ifx_field_upgrade_info);
  if (!tpm_firmware_update_locator.Start()) {
    LOG(ERROR) << "Failed to start update locator child process";
    return false;
  }

  // Read the output.
  {
    base::File pipe(tpm_firmware_update_locator.GetPipe(STDOUT_FILENO));
    char update_location[PATH_MAX];
    int bytes_read =
        pipe.ReadAtCurrentPos(update_location, sizeof(update_location));
    if (bytes_read <= 0) {
      LOG(ERROR) << "Failed to read update location from pipe.";
      return false;
    }

    // Check that the update location file exists.
    char* newline_pos = strchr(update_location, '\n');
    if (newline_pos) {
      *newline_pos = '\0';
    }
    base::FilePath update_path(update_location);
    LOG(INFO) << "Checking whether "
              << rootdir_.AppendASCII(paths::kFirmwareDir) << " is a parent of "
              << update_path;
    if (!rootdir_.AppendASCII(paths::kFirmwareDir).IsParent(update_path) ||
        !base::PathExists(update_path)) {
      LOG(ERROR) << "Failure locating TPM firmware update file.";
      return false;
    }
  }

  // Make sure the locator script terminated cleanly.
  if (tpm_firmware_update_locator.Wait() != 0) {
    LOG(ERROR) << "TPM firmware update locator utility failed.";
    return false;
  }

  return true;
}

result_code Tpm1SystemKeyLoader::CheckLockbox(bool* valid) {
  *valid = false;

  result_code rc = PruneOwnershipStateFilesIfNotOwned();
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  EncStatefulSpaceValidity space_validity = EncStatefulSpaceValidity::kInvalid;
  rc = IsEncStatefulSpaceProperlyDefined(&space_validity);
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  if (space_validity == EncStatefulSpaceValidity::kValid) {
    // Check whether the encstateful space contains a valid lockbox MAC. Check
    // the actual lockbox contents against the MAC, reset the lockbox space to
    // invalid so subsequent code won't use it (specifically, the lockbox space
    // won't get exported for OS consumption).
    //
    // This addresses the scenario where the TPM is left in unowned state or
    // owned with the well-known password after preservation. The requirement is
    // that the lockbox contents may only change at full device reset (e.g.
    // implying stateful file system loss). However, stateful preservation
    // carries over state, so it needs to ensure the lockbox stays locked. Due
    // to the TPM state, the lockbox space could get redefined and thus written
    // to after preservation. The MAC check here doesn't disallow this, but it
    // ensures tamper-evidence: Modified lockbox contents will cause MAC
    // validation failure, so the lockbox will be considered invalid. Note that
    // attempts at adjusting the MAC to match tampered lockbox contents are
    // prevented by locking the encstateful space after boot.
    const EncStatefulArea* area = nullptr;
    rc = LoadEncStatefulArea(&area);
    switch (rc) {
      case RESULT_SUCCESS:
        if (area->test_flag(EncStatefulArea::Flag::kLockboxMacValid)) {
          NvramSpace* lockbox_space = tpm_->GetLockboxSpace();
          if (lockbox_space->is_valid()) {
            brillo::SecureBlob mac = hwsec_foundation::HmacSha256(
                area->DeriveKey(kLabelLockboxMAC), lockbox_space->contents());
            *valid = brillo::SecureMemcmp(area->lockbox_mac, mac.data(),
                                          mac.size()) == 0;
            return RESULT_SUCCESS;
          }
        }
        break;
      case RESULT_FAIL_FATAL:
        // Encstateful contents invalid, so lockbox MAC doesn't apply.
        break;
      default:
        return rc;
    }
  }

  // In case there is no encstateful space, the lockbox space is only valid once
  // tpm manager has initialized TPM with random password and recreated the
  // space.
  *valid = base::PathExists(rootdir_.AppendASCII(paths::cryptohome::kTpmOwned));
  return RESULT_SUCCESS;
}

bool Tpm1SystemKeyLoader::UsingLockboxKey() {
  return using_lockbox_key_;
}

std::unique_ptr<SystemKeyLoader> SystemKeyLoader::Create(
    Tpm* tpm, const base::FilePath& rootdir) {
  return std::make_unique<Tpm1SystemKeyLoader>(tpm, rootdir);
}

}  // namespace mount_encrypted
