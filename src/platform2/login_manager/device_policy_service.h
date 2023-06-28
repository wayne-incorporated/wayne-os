// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_DEVICE_POLICY_SERVICE_H_
#define LOGIN_MANAGER_DEVICE_POLICY_SERVICE_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/gtest_prod_util.h>
#include <base/macros.h>
#include <base/memory/ref_counted.h>
#include <crypto/scoped_nss_types.h>

#include "login_manager/crossystem.h"
#include "login_manager/nss_util.h"
#include "login_manager/owner_key_loss_mitigator.h"
#include "login_manager/policy_service.h"
#include "login_manager/vpd_process.h"

class InstallAttributesReader;

namespace crypto {
class RSAPrivateKey;
}

namespace enterprise_management {
class ChromeDeviceSettingsProto;
class PolicyFetchResponse;
}  // namespace enterprise_management

namespace login_manager {
class KeyGenerator;
class LoginMetrics;
class NssUtil;
class OwnerKeyLossMitigator;

// A policy service specifically for device policy, adding in a few helpers for
// generating a new key for the device owner, handling key loss mitigation,
// storing owner properties etc.
class DevicePolicyService : public PolicyService {
 public:
  ~DevicePolicyService() override;

  // Instantiates a regular (non-testing) device policy service instance.
  static std::unique_ptr<DevicePolicyService> Create(
      PolicyKey* owner_key,
      LoginMetrics* metrics,
      OwnerKeyLossMitigator* mitigator,
      NssUtil* nss,
      Crossystem* crossystem,
      VpdProcess* vpd_process,
      InstallAttributesReader* install_attributes_reader);

  // Checks whether the given |current_user| is the device owner. The result of
  // the check is returned in |is_owner|. If so, it is validated that the device
  // policy settings are set up appropriately:
  // - If |current_user| has the owner key, put them on the login allowlist.
  // - If policy claims |current_user| is the device owner but they don't appear
  //   to have the owner key, run key mitigation.
  // Returns true on success. Fills in |error| upon encountering an error.
  virtual bool CheckAndHandleOwnerLogin(const std::string& current_user,
                                        PK11SlotDescriptor* module,
                                        bool* is_owner,
                                        brillo::ErrorPtr* error);

  // Ensures that the public key in |pub_key| is legitimately paired with a
  // private key held by the current user, signs and stores some
  // ownership-related metadata, and then stores this key off as the new
  // device owner key. Returns true if successful, false otherwise
  virtual bool ValidateAndStoreOwnerKey(const std::string& current_user,
                                        const std::vector<uint8_t>& pub_key,
                                        PK11SlotDescriptor* module);

  // Checks whether the key is missing.
  virtual bool KeyMissing();

  // Checks whether key loss is being mitigated.
  virtual bool Mitigating();

  // Loads policy key and policy blob from disk. Returns true if at least the
  // key can be loaded (policy may not be present yet, which is OK).
  virtual bool Initialize();

  // Given info about whether we were able to load the Owner key and the
  // device policy, report the state of these files via |metrics_|.
  virtual void ReportPolicyFileMetrics(bool key_success, bool policy_success);

  // Gets feature flags specified in device settings to pass to Chrome on
  // startup.
  virtual std::vector<std::string> GetFeatureFlags();

  // Returns the currently active device settings.
  const enterprise_management::ChromeDeviceSettingsProto& GetSettings();

  // Returns whether system settings can be updated by checking that PolicyKey
  // is populated and the device is running on Chrome OS firmware.
  virtual bool MayUpdateSystemSettings();

  // Updates the system settings flags in NVRAM and in VPD. A failure in NVRAM
  // update is not considered a fatal error because new functionality relies on
  // VPD when checking the settings. The old code is using NVRAM however, which
  // means we have to update that memory too. Returns whether VPD process
  // started succesfully and is running in a separate process. In this case,
  // |vpd_process_| is responsible for running |completion|; otherwise,
  // OnPolicyPersisted() is.
  virtual bool UpdateSystemSettings(const Completion& completion);

  // Sets the block_devmode and check_enrollment flags in the VPD to 0
  // in the background. Also set block_devmode=0 in system properties.
  // If the update VPD process could be started in the background
  // |vpd_process_| is responsible for running |completion|;
  // otherwise, the completion is run with an error.
  virtual void ClearForcedReEnrollmentFlags(const Completion& completion);

  // Validates the remote device wipe command received from the server.
  virtual bool ValidateRemoteDeviceWipeCommand(
      const std::vector<uint8_t>& in_signed_command);

  // PolicyService:
  bool Store(const PolicyNamespace& ns,
             const std::vector<uint8_t>& policy_blob,
             int key_flags,
             SignatureCheck signature_check,
             const Completion& completion) override;
  void PersistPolicy(const PolicyNamespace& ns,
                     const Completion& completion) override;

  static const char kPolicyDir[];
  static const char kSerialRecoveryFlagFile[];

  // Format of this string is documented in device_management_backend.proto.
  static const char kDevicePolicyType[];
  static const char kExtensionPolicyType[];
  static const char kRemoteCommandPolicyType[];

 private:
  friend class DevicePolicyServiceTest;
  friend class MockDevicePolicyService;
  FRIEND_TEST_ALL_PREFIXES(DevicePolicyServiceTest, GivenUserIsOwner);
  FRIEND_TEST_ALL_PREFIXES(DevicePolicyServiceTest,
                           PersistPolicyMultipleNamespaces);

  // Takes ownership of |policy_store|.
  DevicePolicyService(const base::FilePath& policy_dir,
                      PolicyKey* owner_key,
                      LoginMetrics* metrics,
                      OwnerKeyLossMitigator* mitigator,
                      NssUtil* nss,
                      Crossystem* crossystem,
                      VpdProcess* vpd_process,
                      InstallAttributesReader* install_attributes_reader);
  DevicePolicyService(const DevicePolicyService&) = delete;
  DevicePolicyService& operator=(const DevicePolicyService&) = delete;

  // Returns true if |policy| allows arbitrary new users to sign in.
  // Only exposed for testing.
  static bool PolicyAllowsNewUsers(
      const enterprise_management::PolicyFetchResponse& policy);

  // Returns true if |current_user| is listed in |policy| as the device owner.
  // Returns false if not, or if that cannot be determined.
  static bool GivenUserIsOwner(
      const enterprise_management::PolicyFetchResponse& policy,
      const std::string& current_user);

  // Given the private half of the owner keypair, this call allowlists
  // |current_user| and sets a property indicating
  // |current_user| is the owner in the current policy and schedules a
  // PersistPolicy().
  // Returns false on failure.
  bool StoreOwnerProperties(const std::string& current_user,
                            crypto::RSAPrivateKey* signing_key);

  // Checks the user's NSS database to see if they have the private key.
  // Returns a pointer to it if so.
  // On failure, returns nullptr, with |error| set appropriately.
  // |error| can be nullptr, if caller doesn't need it.
  std::unique_ptr<crypto::RSAPrivateKey> GetOwnerKeyForGivenUser(
      const std::vector<uint8_t>& key,
      PK11SlotDescriptor* module,
      brillo::ErrorPtr* error);

  // Helper to return the policy store for the Chrome domain.
  PolicyStore* GetChromeStore();

  // Returns the device_id from PolicyData.
  std::string GetDeviceId();

  // Returns enterprise mode from |install_attributes_reader_|.
  const std::string& GetEnterpriseMode();

  // Returns whether the store is resilent. To be used for testing only.
  bool IsChromeStoreResilientForTesting();

  OwnerKeyLossMitigator* mitigator_;
  NssUtil* nss_;
  Crossystem* crossystem_;                              // Owned by the caller.
  VpdProcess* vpd_process_;                             // Owned by the caller.
  InstallAttributesReader* install_attributes_reader_;  // Owned by the caller.

  // Cached copy of the decoded device settings. Decoding happens on first
  // access, the cache is cleared whenever a new policy gets installed via
  // Store().
  std::unique_ptr<enterprise_management::ChromeDeviceSettingsProto> settings_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_DEVICE_POLICY_SERVICE_H_
