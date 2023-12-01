// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_SERVICE_USERDATAAUTH_H_
#define CRYPTOHOME_SERVICE_USERDATAAUTH_H_

#include <memory>
#include <string>

#include <brillo/dbus/dbus_method_response.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/cryptohome/dbus-constants.h>

#include "cryptohome/userdataauth.h"
#include "dbus_adaptors/org.chromium.UserDataAuth.h"

namespace cryptohome {
class UserDataAuthAdaptor
    : public org::chromium::UserDataAuthInterfaceInterface,
      public org::chromium::UserDataAuthInterfaceAdaptor {
 public:
  explicit UserDataAuthAdaptor(scoped_refptr<dbus::Bus> bus,
                               brillo::dbus_utils::DBusObject* dbus_object,
                               UserDataAuth* service)
      : org::chromium::UserDataAuthInterfaceAdaptor(this),
        dbus_object_(dbus_object),
        service_(service) {
    service_->SetAuthFactorStatusUpdateCallback(base::BindRepeating(
        &UserDataAuthAdaptor::AuthFactorStatusUpdateCallback,
        base::Unretained(this)));
    service_->SetLowDiskSpaceCallback(base::BindRepeating(
        &UserDataAuthAdaptor::LowDiskSpaceCallback, base::Unretained(this)));
    service_->SetFingerprintScanResultCallback(
        base::BindRepeating(&UserDataAuthAdaptor::FingerprintScanResultCallback,
                            base::Unretained(this)));
    service_->SetPrepareAuthFactorProgressCallback(base::BindRepeating(
        &UserDataAuthAdaptor::PrepareAuthFactorProgressCallback,
        base::Unretained(this)));
  }
  UserDataAuthAdaptor(const UserDataAuthAdaptor&) = delete;
  UserDataAuthAdaptor& operator=(const UserDataAuthAdaptor&) = delete;

  void RegisterAsync() { RegisterWithDBusObject(dbus_object_); }

  // Interface overrides and related implementations
  // Note that the documentation for all of the methods below can be found in
  // either the DBus Introspection XML
  // (cryptohome/dbus_bindings/org.chromium.UserDataAuth.xml), or the protobuf
  // definition file (system_api/dbus/cryptohome/UserDataAuth.proto)
  void IsMounted(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                     user_data_auth::IsMountedReply>> response,
                 const user_data_auth::IsMountedRequest& in_request) override;
  void DoIsMounted(const Username& username,
                   std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                       user_data_auth::IsMountedReply>> response);

  void Unmount(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                   user_data_auth::UnmountReply>> response,
               const user_data_auth::UnmountRequest& in_request) override;
  void DoUnmount(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                     user_data_auth::UnmountReply>> response);

  void Remove(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                  user_data_auth::RemoveReply>> response,
              const user_data_auth::RemoveRequest& in_request) override;
  void DoRemove(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                    user_data_auth::RemoveReply>> response,
                const user_data_auth::RemoveRequest& in_request);

  void ListKeys(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                    user_data_auth::ListKeysReply>> response,
                const user_data_auth::ListKeysRequest& in_request) override;
  void DoListKeys(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                      user_data_auth::ListKeysReply>> response,
                  const user_data_auth::ListKeysRequest& in_request);

  void GetWebAuthnSecret(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetWebAuthnSecretReply>> response,
      const user_data_auth::GetWebAuthnSecretRequest& in_request) override;

  void DoGetWebAuthnSecret(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetWebAuthnSecretReply>> response,
      const user_data_auth::GetWebAuthnSecretRequest& in_request);

  void GetWebAuthnSecretHash(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetWebAuthnSecretHashReply>> response,
      const user_data_auth::GetWebAuthnSecretHashRequest& in_request) override;

  void DoGetWebAuthnSecretHash(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetWebAuthnSecretHashReply>> response,
      const user_data_auth::GetWebAuthnSecretHashRequest& in_request);

  void GetHibernateSecret(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetHibernateSecretReply>> response,
      const user_data_auth::GetHibernateSecretRequest& in_request) override;

  void DoGetHibernateSecret(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetHibernateSecretReply>> response,
      const user_data_auth::GetHibernateSecretRequest& in_request);

  void GetEncryptionInfo(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetEncryptionInfoReply>> response,
      const user_data_auth::GetEncryptionInfoRequest& in_request) override;

  void DoGetEncryptionInfo(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetEncryptionInfoReply>> response,
      const user_data_auth::GetEncryptionInfoRequest& in_request);

  void StartMigrateToDircrypto(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::StartMigrateToDircryptoReply>> response,
      const user_data_auth::StartMigrateToDircryptoRequest& in_request)
      override;

  void NeedsDircryptoMigration(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::NeedsDircryptoMigrationReply>> response,
      const user_data_auth::NeedsDircryptoMigrationRequest& in_request)
      override;
  void DoNeedsDircryptoMigration(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::NeedsDircryptoMigrationReply>> response,
      const user_data_auth::NeedsDircryptoMigrationRequest& in_request);

  void GetSupportedKeyPolicies(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetSupportedKeyPoliciesReply>> response,
      const user_data_auth::GetSupportedKeyPoliciesRequest& in_request)
      override;

  void GetAccountDiskUsage(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetAccountDiskUsageReply>> response,
      const user_data_auth::GetAccountDiskUsageRequest& in_request) override;
  void DoGetAccountDiskUsage(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetAccountDiskUsageReply>> response,
      const user_data_auth::GetAccountDiskUsageRequest& in_request);

  void StartAuthSession(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::StartAuthSessionReply>> response,
      const user_data_auth::StartAuthSessionRequest& in_request) override;

  void DoStartAuthSession(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::StartAuthSessionReply>> response,
      const user_data_auth::StartAuthSessionRequest& in_request);

  void InvalidateAuthSession(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InvalidateAuthSessionReply>> response,
      const user_data_auth::InvalidateAuthSessionRequest& in_request) override;

  void DoInvalidateAuthSession(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InvalidateAuthSessionReply>> response,
      const user_data_auth::InvalidateAuthSessionRequest& in_request);

  void ExtendAuthSession(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::ExtendAuthSessionReply>> response,
      const user_data_auth::ExtendAuthSessionRequest& in_request) override;

  void DoExtendAuthSession(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::ExtendAuthSessionReply>> response,
      const user_data_auth::ExtendAuthSessionRequest& in_request);

  void CreatePersistentUser(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::CreatePersistentUserReply>> response,
      const user_data_auth::CreatePersistentUserRequest& in_request) override;

  void DoCreatePersistentUser(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::CreatePersistentUserReply>> response,
      const user_data_auth::CreatePersistentUserRequest& in_request);

  void PrepareGuestVault(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PrepareGuestVaultReply>> response,
      const user_data_auth::PrepareGuestVaultRequest& in_request) override;

  void DoPrepareGuestVault(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PrepareGuestVaultReply>> response,
      const user_data_auth::PrepareGuestVaultRequest& in_request);

  void PrepareEphemeralVault(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PrepareEphemeralVaultReply>> response,
      const user_data_auth::PrepareEphemeralVaultRequest& in_request) override;

  void DoPrepareEphemeralVault(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PrepareEphemeralVaultReply>> response,
      const user_data_auth::PrepareEphemeralVaultRequest& in_request);

  void PreparePersistentVault(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PreparePersistentVaultReply>> response,
      const user_data_auth::PreparePersistentVaultRequest& in_request) override;

  void DoPreparePersistentVault(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PreparePersistentVaultReply>> response,
      const user_data_auth::PreparePersistentVaultRequest& in_request);

  void PrepareVaultForMigration(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PrepareVaultForMigrationReply>> response,
      const user_data_auth::PrepareVaultForMigrationRequest& in_request)
      override;

  void DoPrepareVaultForMigration(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PrepareVaultForMigrationReply>> response,
      const user_data_auth::PrepareVaultForMigrationRequest& in_request);

  void AddAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::AddAuthFactorReply>> response,
      const user_data_auth::AddAuthFactorRequest& in_request) override;

  void DoAddAuthFactor(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                           user_data_auth::AddAuthFactorReply>> response,
                       const user_data_auth::AddAuthFactorRequest& in_request);

  void UpdateAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::UpdateAuthFactorReply>> response,
      const user_data_auth::UpdateAuthFactorRequest& in_request) override;

  void DoUpdateAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::UpdateAuthFactorReply>> response,
      const user_data_auth::UpdateAuthFactorRequest& in_request);

  void UpdateAuthFactorMetadata(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::UpdateAuthFactorMetadataReply>> response,
      const user_data_auth::UpdateAuthFactorMetadataRequest& in_request)
      override;

  void DoUpdateAuthFactorMetadata(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::UpdateAuthFactorMetadataReply>> response,
      const user_data_auth::UpdateAuthFactorMetadataRequest& in_request);

  void RemoveAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::RemoveAuthFactorReply>> response,
      const user_data_auth::RemoveAuthFactorRequest& in_request) override;

  void DoRemoveAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::RemoveAuthFactorReply>> response,
      const user_data_auth::RemoveAuthFactorRequest& in_request);

  void ListAuthFactors(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::ListAuthFactorsReply>> response,
      const user_data_auth::ListAuthFactorsRequest& in_request) override;

  void DoListAuthFactors(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::ListAuthFactorsReply>> response,
      const user_data_auth::ListAuthFactorsRequest& in_request);

  void GetAuthFactorExtendedInfo(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetAuthFactorExtendedInfoReply>> response,
      const user_data_auth::GetAuthFactorExtendedInfoRequest& in_request)
      override;

  void DoGetAuthFactorExtendedInfo(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetAuthFactorExtendedInfoReply>> response,
      const user_data_auth::GetAuthFactorExtendedInfoRequest& in_request);

  void PrepareAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PrepareAuthFactorReply>> response,
      const user_data_auth::PrepareAuthFactorRequest& in_request) override;

  void DoPrepareAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::PrepareAuthFactorReply>> response,
      const user_data_auth::PrepareAuthFactorRequest& in_request);

  void TerminateAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::TerminateAuthFactorReply>> response,
      const user_data_auth::TerminateAuthFactorRequest& in_request) override;

  void DoTerminateAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::TerminateAuthFactorReply>> response,
      const user_data_auth::TerminateAuthFactorRequest& in_request);

  void AuthenticateAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::AuthenticateAuthFactorReply>> response,
      const user_data_auth::AuthenticateAuthFactorRequest& in_request) override;

  void DoAuthenticateAuthFactor(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::AuthenticateAuthFactorReply>> response,
      const user_data_auth::AuthenticateAuthFactorRequest& in_request);

  void GetAuthSessionStatus(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetAuthSessionStatusReply>> response,
      const user_data_auth::GetAuthSessionStatusRequest& in_request) override;

  void DoGetAuthSessionStatus(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetAuthSessionStatusReply>> response,
      const user_data_auth::GetAuthSessionStatusRequest& in_request);

  void GetRecoveryRequest(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetRecoveryRequestReply>> response,
      const user_data_auth::GetRecoveryRequestRequest& in_request) override;

  void DoGetRecoveryRequest(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetRecoveryRequestReply>> response,
      const user_data_auth::GetRecoveryRequestRequest& in_request);

  void CreateVaultKeyset(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::CreateVaultKeysetReply>> response,
      const user_data_auth::CreateVaultKeysetRequest& in_request) override;

  void DoCreateVaultKeyset(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::CreateVaultKeysetReply>> response,
      const user_data_auth::CreateVaultKeysetRequest& in_request);

  void ResetApplicationContainer(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::ResetApplicationContainerReply>> response,
      const user_data_auth::ResetApplicationContainerRequest& in_request)
      override;
  void DoResetApplicationContainer(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::ResetApplicationContainerReply>> response,
      const user_data_auth::ResetApplicationContainerRequest& in_request);

  // This is called by UserDataAuth to update the status of locked out users in
  // a passwordless login. This will create and send the signal.
  void AuthFactorStatusUpdateCallback(
      user_data_auth::AuthFactorWithStatus auth_factor_with_status,
      const std::string& broadcast_id);

  // This is called by UserDataAuth when it detects that it's running low on
  // disk space. All we do here is send the signal.
  void LowDiskSpaceCallback(uint64_t free_disk_space);

  // This is called by UserDataAuth for processing biod's fingerprint scan
  // signal AuthScanDone. All it does is to construct and send a signal.
  void FingerprintScanResultCallback(
      user_data_auth::FingerprintScanResult result);

  // This is called by UserDataAuth for processing an emitted signal from
  // a prepared AuthFactor. All we do here is send the signal.
  void PrepareAuthFactorProgressCallback(
      user_data_auth::PrepareAuthFactorProgress signal);

 private:
  brillo::dbus_utils::DBusObject* dbus_object_;

  // This is the object that holds most of the states that this adaptor uses,
  // it also contains most of the actual logics.
  // This object is owned by the parent dbus service daemon, and whose lifetime
  // will cover the entire lifetime of this class.
  UserDataAuth* service_;
};

class ArcQuotaAdaptor : public org::chromium::ArcQuotaInterface,
                        public org::chromium::ArcQuotaAdaptor {
 public:
  explicit ArcQuotaAdaptor(scoped_refptr<dbus::Bus> bus,
                           brillo::dbus_utils::DBusObject* dbus_object,
                           UserDataAuth* service)
      : org::chromium::ArcQuotaAdaptor(this),
        dbus_object_(dbus_object),
        service_(service) {
    // This is to silence the compiler's warning about unused fields. It will be
    // removed once we start to use it.
    (void)service_;
  }
  ArcQuotaAdaptor(const ArcQuotaAdaptor&) = delete;
  ArcQuotaAdaptor& operator=(const ArcQuotaAdaptor&) = delete;

  void RegisterAsync() { RegisterWithDBusObject(dbus_object_); }

  // Interface overrides and related implementations
  // Note that the documentation for all of the methods below can be found in
  // either the DBus Introspection XML
  // (cryptohome/dbus_bindings/org.chromium.UserDataAuth.xml), or the protobuf
  // definition file (system_api/dbus/cryptohome/UserDataAuth.proto)
  void GetArcDiskFeatures(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetArcDiskFeaturesReply>> response,
      const user_data_auth::GetArcDiskFeaturesRequest& in_request) override;
  void GetCurrentSpaceForArcUid(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetCurrentSpaceForArcUidReply>> response,
      const user_data_auth::GetCurrentSpaceForArcUidRequest& in_request)
      override;
  void GetCurrentSpaceForArcGid(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetCurrentSpaceForArcGidReply>> response,
      const user_data_auth::GetCurrentSpaceForArcGidRequest& in_request)
      override;
  void GetCurrentSpaceForArcProjectId(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetCurrentSpaceForArcProjectIdReply>> response,
      const user_data_auth::GetCurrentSpaceForArcProjectIdRequest& in_request)
      override;
  void SetMediaRWDataFileProjectId(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::SetMediaRWDataFileProjectIdReply>> response,
      const base::ScopedFD& in_fd,
      const user_data_auth::SetMediaRWDataFileProjectIdRequest& in_request)
      override;
  void SetMediaRWDataFileProjectInheritanceFlag(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::SetMediaRWDataFileProjectInheritanceFlagReply>>
          response,
      const base::ScopedFD& in_fd,
      const user_data_auth::SetMediaRWDataFileProjectInheritanceFlagRequest&
          in_request) override;

 private:
  brillo::dbus_utils::DBusObject* dbus_object_;

  // This is the object that holds most of the states that this adaptor uses,
  // it also contains most of the actual logics.
  // This object is owned by the parent dbus service daemon, and whose lifetime
  // will cover the entire lifetime of this class.
  UserDataAuth* service_;
};

class Pkcs11Adaptor : public org::chromium::CryptohomePkcs11InterfaceInterface,
                      public org::chromium::CryptohomePkcs11InterfaceAdaptor {
 public:
  explicit Pkcs11Adaptor(scoped_refptr<dbus::Bus> bus,
                         brillo::dbus_utils::DBusObject* dbus_object,
                         UserDataAuth* service)
      : org::chromium::CryptohomePkcs11InterfaceAdaptor(this),
        dbus_object_(dbus_object),
        service_(service) {
    // This is to silence the compiler's warning about unused fields. It will be
    // removed once we start to use it.
    (void)service_;
  }
  Pkcs11Adaptor(const Pkcs11Adaptor&) = delete;
  Pkcs11Adaptor& operator=(const Pkcs11Adaptor&) = delete;

  void RegisterAsync() { RegisterWithDBusObject(dbus_object_); }

  // Interface overrides and related implementations
  // Note that the documentation for all of the methods below can be found in
  // either the DBus Introspection XML
  // (cryptohome/dbus_bindings/org.chromium.UserDataAuth.xml), or the protobuf
  // definition file (system_api/dbus/cryptohome/UserDataAuth.proto)
  void Pkcs11IsTpmTokenReady(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::Pkcs11IsTpmTokenReadyReply>> response,
      const user_data_auth::Pkcs11IsTpmTokenReadyRequest& in_request) override;
  void DoPkcs11IsTpmTokenReady(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::Pkcs11IsTpmTokenReadyReply>> response,
      const user_data_auth::Pkcs11IsTpmTokenReadyRequest& in_request);

  void Pkcs11GetTpmTokenInfo(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::Pkcs11GetTpmTokenInfoReply>> response,
      const user_data_auth::Pkcs11GetTpmTokenInfoRequest& in_request) override;

  void Pkcs11Terminate(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::Pkcs11TerminateReply>> response,
      const user_data_auth::Pkcs11TerminateRequest& in_request) override;
  void DoPkcs11Terminate(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::Pkcs11TerminateReply>> response,
      const user_data_auth::Pkcs11TerminateRequest& in_request);

  void Pkcs11RestoreTpmTokens(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::Pkcs11RestoreTpmTokensReply>> response,
      const user_data_auth::Pkcs11RestoreTpmTokensRequest& in_request) override;
  void DoPkcs11RestoreTpmTokens(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::Pkcs11RestoreTpmTokensReply>> response,
      const user_data_auth::Pkcs11RestoreTpmTokensRequest& in_request);

 private:
  brillo::dbus_utils::DBusObject* dbus_object_;

  // This is the object that holds most of the states that this adaptor uses,
  // it also contains most of the actual logics.
  // This object is owned by the parent dbus service daemon, and whose lifetime
  // will cover the entire lifetime of this class.
  UserDataAuth* service_;
};

class InstallAttributesAdaptor
    : public org::chromium::InstallAttributesInterfaceInterface,
      public org::chromium::InstallAttributesInterfaceAdaptor {
 public:
  explicit InstallAttributesAdaptor(scoped_refptr<dbus::Bus> bus,
                                    brillo::dbus_utils::DBusObject* dbus_object,
                                    UserDataAuth* service)
      : org::chromium::InstallAttributesInterfaceAdaptor(this),
        dbus_object_(dbus_object),
        service_(service) {
    // This is to silence the compiler's warning about unused fields. It will be
    // removed once we start to use it.
    (void)service_;
  }
  InstallAttributesAdaptor(const InstallAttributesAdaptor&) = delete;
  InstallAttributesAdaptor& operator=(const InstallAttributesAdaptor&) = delete;

  void RegisterAsync() { RegisterWithDBusObject(dbus_object_); }

  // Interface overrides and related implementations
  void InstallAttributesGet(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InstallAttributesGetReply>> response,
      const user_data_auth::InstallAttributesGetRequest& in_request) override;
  void DoInstallAttributesGet(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InstallAttributesGetReply>> response,
      const user_data_auth::InstallAttributesGetRequest& in_request);
  void InstallAttributesSet(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InstallAttributesSetReply>> response,
      const user_data_auth::InstallAttributesSetRequest& in_request) override;
  void DoInstallAttributesSet(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InstallAttributesSetReply>> response,
      const user_data_auth::InstallAttributesSetRequest& in_request);
  void InstallAttributesFinalize(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InstallAttributesFinalizeReply>> response,
      const user_data_auth::InstallAttributesFinalizeRequest& in_request)
      override;
  void DoInstallAttributesFinalize(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InstallAttributesFinalizeReply>> response,
      const user_data_auth::InstallAttributesFinalizeRequest& in_request);
  void InstallAttributesGetStatus(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InstallAttributesGetStatusReply>> response,
      const user_data_auth::InstallAttributesGetStatusRequest& in_request)
      override;
  void DoInstallAttributesGetStatus(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::InstallAttributesGetStatusReply>> response,
      const user_data_auth::InstallAttributesGetStatusRequest& in_request);
  void GetFirmwareManagementParameters(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetFirmwareManagementParametersReply>> response,
      const user_data_auth::GetFirmwareManagementParametersRequest& in_request)
      override;
  void RemoveFirmwareManagementParameters(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::RemoveFirmwareManagementParametersReply>> response,
      const user_data_auth::RemoveFirmwareManagementParametersRequest&
          in_request) override;
  void SetFirmwareManagementParameters(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::SetFirmwareManagementParametersReply>> response,
      const user_data_auth::SetFirmwareManagementParametersRequest& in_request)
      override;

 private:
  brillo::dbus_utils::DBusObject* dbus_object_;

  // This is the object that holds most of the states that this adaptor uses,
  // it also contains most of the actual logics.
  // This object is owned by the parent dbus service daemon, and whose lifetime
  // will cover the entire lifetime of this class.
  UserDataAuth* service_;
};

class CryptohomeMiscAdaptor
    : public org::chromium::CryptohomeMiscInterfaceInterface,
      public org::chromium::CryptohomeMiscInterfaceAdaptor {
 public:
  explicit CryptohomeMiscAdaptor(scoped_refptr<dbus::Bus> bus,
                                 brillo::dbus_utils::DBusObject* dbus_object,
                                 UserDataAuth* service)
      : org::chromium::CryptohomeMiscInterfaceAdaptor(this),
        dbus_object_(dbus_object),
        service_(service) {
    // This is to silence the compiler's warning about unused fields. It will be
    // removed once we start to use it.
    (void)service_;
  }
  CryptohomeMiscAdaptor(const CryptohomeMiscAdaptor&) = delete;
  CryptohomeMiscAdaptor& operator=(const CryptohomeMiscAdaptor&) = delete;

  void RegisterAsync() { RegisterWithDBusObject(dbus_object_); }

  // Interface overrides and related implementations
  void GetSystemSalt(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetSystemSaltReply>> response,
      const user_data_auth::GetSystemSaltRequest& in_request) override;

  void UpdateCurrentUserActivityTimestamp(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::UpdateCurrentUserActivityTimestampReply>> response,
      const user_data_auth::UpdateCurrentUserActivityTimestampRequest&
          in_request) override;
  void DoUpdateCurrentUserActivityTimestamp(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::UpdateCurrentUserActivityTimestampReply>> response,
      const user_data_auth::UpdateCurrentUserActivityTimestampRequest&
          in_request);

  void GetSanitizedUsername(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetSanitizedUsernameReply>> response,
      const user_data_auth::GetSanitizedUsernameRequest& in_request) override;
  void GetLoginStatus(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetLoginStatusReply>> response,
      const user_data_auth::GetLoginStatusRequest& in_request) override;

  void LockToSingleUserMountUntilReboot(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::LockToSingleUserMountUntilRebootReply>> response,
      const user_data_auth::LockToSingleUserMountUntilRebootRequest& in_request)
      override;
  void GetRsuDeviceId(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          user_data_auth::GetRsuDeviceIdReply>> response,
      const user_data_auth::GetRsuDeviceIdRequest& in_request) override;

 private:
  brillo::dbus_utils::DBusObject* dbus_object_;

  // This is the object that holds most of the states that this adaptor uses,
  // it also contains most of the actual logics.
  // This object is owned by the parent dbus service daemon, and whose lifetime
  // will cover the entire lifetime of this class.
  UserDataAuth* service_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_SERVICE_USERDATAAUTH_H_
