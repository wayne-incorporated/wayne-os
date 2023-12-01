// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Interface used by "mount-encrypted" to interface with the TPM.

#ifndef CRYPTOHOME_MOUNT_ENCRYPTED_TPM_H_
#define CRYPTOHOME_MOUNT_ENCRYPTED_TPM_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <vboot/tlcl.h>

#include "cryptohome/mount_encrypted/mount_encrypted.h"

namespace mount_encrypted {
const uint32_t kLockboxSizeV1 = 0x2c;
const uint32_t kLockboxSizeV2 = 0x45;

#if USE_TPM2
const uint32_t kLockboxIndex = 0x800004;
const uint32_t kEncStatefulIndex = 0x800005;
const uint32_t kEncStatefulSize = 40;
#else
const uint32_t kLockboxIndex = 0x20000004;
const uint32_t kEncStatefulIndex = 0x20000005;
const uint32_t kEncStatefulSize = 72;
#endif

const uint32_t kPCRBootMode = 0;

// Secret used for owner authorization. This is used for taking ownership and in
// TPM commands that require owner authorization. Currently, only the TPM 1.2
// implementation uses owner authorization for some of its operations. The
// constants are nullptr and zero, respectively, for TPM 2.0.
extern const uint8_t* kOwnerSecret;
extern const size_t kOwnerSecretSize;

// Path constants. Note that these don't carry the / root prefix because the
// actual path gets constructed relative to a rootdir (which is a temporary
// directory in tests, the actual root directory for production).
namespace paths {
inline constexpr char kFirmwareUpdateRequest[] =
    "mnt/stateful_partition/unencrypted/preserve/tpm_firmware_update_request";
inline constexpr char kFirmwareDir[] = "lib/firmware/tpm";
inline constexpr char kFirmwareUpdateLocator[] =
    "usr/sbin/tpm-firmware-locate-update";

namespace cryptohome {
inline constexpr char kTpmOwned[] =
    "mnt/stateful_partition/unencrypted/tpm_manager/tpm_owned";
inline constexpr char kTpmStatus[] = "mnt/stateful_partition/.tpm_status";
inline constexpr char kShallInitialize[] =
    "home/.shadow/.can_attempt_ownership";
inline constexpr char kAttestationDatabase[] =
    "mnt/stateful_partition/unencrypted/preserve/attestation.epb";
}  // namespace cryptohome
}  // namespace paths

class Tpm;

class NvramSpace {
 public:
  NvramSpace(Tpm* tpm, uint32_t index);

  enum class Status {
    kUnknown,   // Not accessed yet.
    kAbsent,    // Not defined.
    kWritable,  // Defined but the content is not written (TPM1.2 only).
    kValid,     // Present and read was successful.
    kTpmError,  // Error accessing the space.
  };

  Status status() const { return status_; }
  bool is_valid() const { return status() == Status::kValid; }
  bool is_writable() const { return status() == Status::kWritable; }
  const brillo::SecureBlob& contents() const { return contents_; }

  // Resets the space so that it appears invalid. Doesn't update the TPM.
  void Reset();

  // Retrieves the space attributes.
  result_code GetAttributes(uint32_t* attributes);

  // Attempts to read the NVRAM space.
  result_code Read(uint32_t size);

  // Writes to the NVRAM space.
  result_code Write(const brillo::SecureBlob& contents);

  // Sets the read lock on the space.
  result_code ReadLock();

  // Sets write lock on the space.
  result_code WriteLock();

  // Attempt to define the space with the given attributes and size.
  result_code Define(uint32_t attributes,
                     uint32_t size,
                     uint32_t pcr_selection);

  // Check whether the space is bound to the specified PCR selection.
  result_code CheckPCRBinding(uint32_t pcr_selection, bool* match);

 private:
  // Reads space definition parameters from the TPM.
  result_code GetSpaceInfo();

  // Get the binding policy for the current PCR values of the given PCR
  // selection.
  result_code GetPCRBindingPolicy(uint32_t pcr_selection,
                                  std::vector<uint8_t>* policy);

  Tpm* tpm_;
  uint32_t index_;

  // Cached copy of NVRAM space attributes.
  uint32_t attributes_;

  // Cached copy of the auth policy.
  std::vector<uint8_t> auth_policy_;

  // Cached copy of the data as read from the space.
  brillo::SecureBlob contents_;

  // Cached indicator reflecting the status of the space in the TPM.
  Status status_ = Status::kUnknown;
};

// Encapsulates high-level TPM state and the motions needed to open and close
// the TPM library.
class Tpm {
 public:
  Tpm();
  Tpm(const Tpm&) = delete;
  Tpm& operator=(const Tpm&) = delete;

  ~Tpm();

  bool available() const { return available_; }
  bool is_tpm2() const { return is_tpm2_; }

  result_code IsOwned(bool* owned);

  result_code GetRandomBytes(uint8_t* buffer, int wanted);

  // Returns the PCR value for PCR |index|, possibly from the cache.
  result_code ReadPCR(uint32_t index, std::vector<uint8_t>* value);

  // Returns TPM version info.
  bool GetVersionInfo(uint32_t* vendor,
                      uint64_t* firmware_version,
                      std::vector<uint8_t>* vendor_specific);

  // Returns Infineon-specific field upgrade status.
  bool GetIFXFieldUpgradeInfo(TPM_IFX_FIELDUPGRADEINFO* field_upgrade_info);

  // Returns the initialized lockbox NVRAM space.
  NvramSpace* GetLockboxSpace();

  // Get the initialized encrypted stateful space.
  NvramSpace* GetEncStatefulSpace();

  // Take TPM ownership using an all-zeros password.
  result_code TakeOwnership();

  // Set a flag in the TPM to indicate that the system key has been
  // re-initialized after the last TPM clear. The TPM automatically clears the
  // flag as a side effect of the TPM clear operation.
  result_code SetSystemKeyInitializedFlag();

  // Check the system key initialized flag.
  result_code HasSystemKeyInitializedFlag(bool* flag_value);

 private:
  bool available_ = false;
  bool is_tpm2_ = false;

  bool ownership_checked_ = false;
  bool owned_ = false;

#if !USE_TPM2
  bool initialized_flag_checked_ = false;
  bool initialized_flag_ = false;
#endif  // !USE_TPM2

  std::map<uint32_t, std::vector<uint8_t>> pcr_values_;

  std::unique_ptr<NvramSpace> lockbox_space_;
  std::unique_ptr<NvramSpace> encstateful_space_;
};

// The interface used by the key handling logic to access the system key. The
// system key is used to wrap the actual data encryption key.
//
// System keys must have these properties:
//  1. The system key can only be accessed in the current boot mode, i.e.
//     switching to developer mode blocks access or destroys the system key.
//  2. A fresh system key must be generated after clearing the TPM. This can be
//     achieved either by arranging a TPM clear to drop the key or by detecting
//     a TPM clear an generating a fresh key.
//  3. The key should ideally not be accessible for reading after early boot.
//  4. Because mounting the encrypted stateful file system is on the critical
//     boot path, loading the system key must be reasonably fast.
//  5. Fresh keys can be generated with reasonable cost. Costly operations such
//     as taking TPM ownership after each TPM clear to set up fresh NVRAM spaces
//     do not fly performance-wise. The file system encryption key logic has a
//     fallback path to dump its key without protection by a system key until
//     the latter becomes available, but that's a risk that should ideally be
//     avoided.
class SystemKeyLoader {
 public:
  virtual ~SystemKeyLoader() = default;

  // Create a system key loader suitable for the system.
  static std::unique_ptr<SystemKeyLoader> Create(Tpm* tpm,
                                                 const base::FilePath& rootdir);

  // Load the encryption key from TPM NVRAM. Returns true if successful and
  // fills in key, false if the key is not available or there is an error.
  virtual result_code Load(brillo::SecureBlob* key) = 0;

  // Initializes system key NV space contents using |key_material|.
  // The size of |key_material| must equal DIGEST_LENGTH. If
  // |derived_system_key| is not null, stores the derived system key into it.
  //
  // This function does not store the contents in NVRAM yet.
  //
  // Returns RESULT_SUCCESS if successful or RESULT_FAIL_FATAL otherwise.
  virtual result_code Initialize(const brillo::SecureBlob& key_material,
                                 brillo::SecureBlob* derived_system_key) = 0;

  // Persist a previously generated system key in NVRAM. This may not be
  // possible in case the TPM is not in a state where the NVRAM spaces can be
  // manipulated.
  virtual result_code Persist() = 0;

  // Lock the system key to prevent further manipulation.
  virtual void Lock() = 0;

  // Set up the TPM to allow generation of a system key. This is an expensive
  // operation that can take dozens of seconds depending on hardware so this
  // can't be used routinely.
  virtual result_code SetupTpm() = 0;

  // Checks whether the system is eligible for encryption key preservation. If
  // so, sets up a new system key to wrap the existing encryption key. On
  // success, |previous_key| and |fresh_key| will be filled in. Returns false if
  // the system is not eligible or there is an error.
  virtual result_code GenerateForPreservation(
      brillo::SecureBlob* previous_key, brillo::SecureBlob* fresh_key) = 0;

  // Checks whether the lockbox space contents are considered valid.
  virtual result_code CheckLockbox(bool* valid) = 0;

  // Whether the lockbox salt is used as the system key.
  virtual bool UsingLockboxKey() = 0;
};

// A SystemKeyLoader implementation backed by a fixed system key supplied at
// construction time.
class FixedSystemKeyLoader : public SystemKeyLoader {
 public:
  explicit FixedSystemKeyLoader(const brillo::SecureBlob& key) : key_(key) {}
  virtual ~FixedSystemKeyLoader() = default;

  result_code Load(brillo::SecureBlob* key) override {
    *key = key_;
    return RESULT_SUCCESS;
  }
  result_code Initialize(const brillo::SecureBlob& key_material,
                         brillo::SecureBlob* derived_system_key) override {
    return RESULT_FAIL_FATAL;
  }
  result_code Persist() override { return RESULT_FAIL_FATAL; }
  void Lock() override {}
  result_code SetupTpm() override { return RESULT_FAIL_FATAL; }
  result_code GenerateForPreservation(brillo::SecureBlob* previous_key,
                                      brillo::SecureBlob* fresh_key) override {
    return RESULT_FAIL_FATAL;
  }
  result_code CheckLockbox(bool* valid) override { return RESULT_FAIL_FATAL; }
  bool UsingLockboxKey() override { return false; }

 private:
  brillo::SecureBlob key_;
};

}  // namespace mount_encrypted
#endif  // CRYPTOHOME_MOUNT_ENCRYPTED_TPM_H_
