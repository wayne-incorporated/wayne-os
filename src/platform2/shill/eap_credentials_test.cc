// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>

#include "shill/eap_credentials.h"

#include <string>
#include <utility>
#include <vector>

#include <base/stl_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include <libpasswordprovider/fake_password_provider.h>
#include <libpasswordprovider/password.h>
#include <libpasswordprovider/password_provider.h>
#include <libpasswordprovider/password_provider_test_utils.h>

#include "shill/mock_certificate_file.h"
#include "shill/mock_log.h"
#include "shill/mock_metrics.h"
#include "shill/store/fake_store.h"
#include "shill/store/key_value_store.h"
#include "shill/store/mock_pkcs11_slot_getter.h"
#include "shill/store/pkcs11_util.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/technology.h"

using testing::_;
using testing::AnyNumber;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;
using testing::WithArg;

namespace shill {

class EapCredentialsTest : public testing::Test {
 public:
  EapCredentialsTest() = default;
  ~EapCredentialsTest() override = default;

 protected:
  void PopulateSupplicantProperties() {
    eap_.PopulateSupplicantProperties(&certificate_file_, &params_);
  }

  void SetAnonymousIdentity(const std::string& anonymous_identity) {
    eap_.anonymous_identity_ = anonymous_identity;
  }
  void SetCACertPEM(const std::vector<std::string>& ca_cert_pem) {
    eap_.ca_cert_pem_ = ca_cert_pem;
  }
  void SetCertId(const std::string& cert_id) { eap_.cert_id_ = cert_id; }
  void SetCACertId(const std::string& ca_cert_id) {
    eap_.ca_cert_id_ = ca_cert_id;
  }
  void SetEap(const std::string& eap) { eap_.eap_ = eap; }
  void SetIdentity(const std::string& identity) { eap_.identity_ = identity; }
  void SetInnerEap(const std::string& inner_eap) {
    eap_.inner_eap_ = inner_eap;
  }
  void SetTLSVersionMax(const std::string& tls_version_max) {
    eap_.tls_version_max_ = tls_version_max;
  }
  void SetKeyId(const std::string& key_id) { eap_.key_id_ = key_id; }
  const std::string& GetPassword() { return eap_.password_; }
  void SetPassword(const std::string& password) { eap_.password_ = password; }
  void SetPin(const std::string& pin) { eap_.pin_ = pin; }
  void SetUseProactiveKeyCaching(bool use_proactive_key_caching) {
    eap_.use_proactive_key_caching_ = use_proactive_key_caching;
  }
  void SetSubjectAlternativeNameMatch(
      std::vector<std::string> altsubject_match_list) {
    eap_.subject_alternative_name_match_list_ = altsubject_match_list;
  }
  void SetDomainSuffixMatch(std::vector<std::string> domain_suffix_match_list) {
    eap_.domain_suffix_match_list_ = domain_suffix_match_list;
  }
  void SetUseSystemCAs(bool use_system_cas) {
    eap_.use_system_cas_ = use_system_cas;
  }
  void SetUseLoginPassword(bool use_login_password) {
    eap_.use_login_password_ = use_login_password;
  }
  bool IsReset() {
    return eap_.anonymous_identity_.empty() && eap_.cert_id_.empty() &&
           eap_.identity_.empty() && eap_.key_id_.empty() &&
           eap_.password_.empty() && eap_.pin_.empty() &&
           eap_.ca_cert_id_.empty() && eap_.ca_cert_pem_.empty() &&
           eap_.eap_.empty() && eap_.inner_eap_.empty() &&
           eap_.tls_version_max_.empty() && eap_.subject_match_.empty() &&
           eap_.subject_alternative_name_match_list_.empty() &&
           eap_.domain_suffix_match_list_.empty() &&
           eap_.use_system_cas_ == true &&
           eap_.use_proactive_key_caching_ == false &&
           eap_.use_login_password_ == false;
  }

  const std::string& GetKeyManagement() { return eap_.key_management_; }
  bool SetEapPassword(const std::string& password, Error* error) {
    return eap_.SetEapPassword(password, error);
  }

  void SaveLoginPassword(const std::string& password_str) {
    eap_.password_provider_ =
        std::make_unique<password_provider::FakePasswordProvider>();

    auto password = password_provider::test::CreatePassword(password_str);
    ASSERT_TRUE(password);

    eap_.password_provider_->SavePassword(*password);
  }

  EapCredentials eap_;
  MockCertificateFile certificate_file_;
  MockPkcs11SlotGetter slot_getter_;
  KeyValueStore params_;
};

TEST_F(EapCredentialsTest, PropertyStore) {
  PropertyStore store;
  eap_.InitPropertyStore(&store);
  const std::string kIdentity("Cross-Eyed Mary");
  Error error;
  store.SetStringProperty(kEapIdentityProperty, kIdentity, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kIdentity, eap_.identity());
}

TEST_F(EapCredentialsTest, Connectable) {
  // Empty EAP credentials should not make a 802.1x network connectable.
  EXPECT_FALSE(eap_.IsConnectable());

  // Identity alone is not enough.
  SetIdentity("Steel Monkey");
  EXPECT_FALSE(eap_.IsConnectable());

  // Set a password.
  SetPassword("Angry Tapir");

  // Empty "EAP" parameter is treated like "not EAP-TLS", and connectable.
  EXPECT_TRUE(eap_.IsConnectable());

  // Some other non-TLS EAP type.
  SetEap("DodgeBall");
  EXPECT_TRUE(eap_.IsConnectable());

  // EAP-TLS requires certificate parameters, and cares not for passwords.
  SetEap("TLS");
  EXPECT_FALSE(eap_.IsConnectable());

  // Clearing the password won't help.
  SetPassword("");
  EXPECT_FALSE(eap_.IsConnectable());

  // A cert-id + key-id isn't sufficient.
  SetCertId("client-cert-id");
  SetKeyId("client-key-id");
  EXPECT_FALSE(eap_.IsConnectable());

  // We need a PIN for the key id in addition.
  SetPin("pin");
  EXPECT_TRUE(eap_.IsConnectable());

  // If we clear the "EAP" property, a password is required but a client
  // cert is not.
  SetCertId("");
  EXPECT_FALSE(eap_.IsConnectable());

  SetEap("");
  SetPassword("Angry Tapir");
  EXPECT_TRUE(eap_.IsConnectable());
}

TEST_F(EapCredentialsTest, ConnectableUsingPassphrase) {
  EXPECT_FALSE(eap_.IsConnectableUsingPassphrase());

  // No password.
  SetIdentity("TestIdentity");
  EXPECT_FALSE(eap_.IsConnectableUsingPassphrase());

  // Success.
  SetPassword("TestPassword");
  EXPECT_TRUE(eap_.IsConnectableUsingPassphrase());

  // Clear identity.
  SetIdentity("");
  EXPECT_FALSE(eap_.IsConnectableUsingPassphrase());
}

TEST_F(EapCredentialsTest, IsEapAuthenticationProperty) {
  EXPECT_TRUE(EapCredentials::IsEapAuthenticationProperty(
      kEapAnonymousIdentityProperty));
  EXPECT_TRUE(EapCredentials::IsEapAuthenticationProperty(kEapCertIdProperty));
  EXPECT_TRUE(
      EapCredentials::IsEapAuthenticationProperty(kEapIdentityProperty));
  EXPECT_TRUE(EapCredentials::IsEapAuthenticationProperty(kEapKeyIdProperty));
  EXPECT_TRUE(EapCredentials::IsEapAuthenticationProperty(kEapKeyMgmtProperty));
  EXPECT_TRUE(
      EapCredentials::IsEapAuthenticationProperty(kEapPasswordProperty));
  EXPECT_TRUE(EapCredentials::IsEapAuthenticationProperty(kEapPinProperty));
  EXPECT_TRUE(EapCredentials::IsEapAuthenticationProperty(
      kEapUseLoginPasswordProperty));

  // It's easier to test that this function returns TRUE in every situation
  // that it should, than to test all the cases it should return FALSE in.
  EXPECT_FALSE(EapCredentials::IsEapAuthenticationProperty(kEapCaCertProperty));
  EXPECT_FALSE(
      EapCredentials::IsEapAuthenticationProperty(kEapCaCertIdProperty));
  EXPECT_FALSE(
      EapCredentials::IsEapAuthenticationProperty(kEapCaCertPemProperty));
  EXPECT_FALSE(EapCredentials::IsEapAuthenticationProperty(kEapMethodProperty));
  EXPECT_FALSE(
      EapCredentials::IsEapAuthenticationProperty(kEapPhase2AuthProperty));
  EXPECT_FALSE(EapCredentials::IsEapAuthenticationProperty(
      kEapRemoteCertificationProperty));
  EXPECT_FALSE(
      EapCredentials::IsEapAuthenticationProperty(kEapSubjectMatchProperty));
  EXPECT_FALSE(EapCredentials::IsEapAuthenticationProperty(
      kEapUseProactiveKeyCachingProperty));
  EXPECT_FALSE(
      EapCredentials::IsEapAuthenticationProperty(kEapUseSystemCasProperty));
}

TEST_F(EapCredentialsTest, LoadAndSave) {
  FakeStore store;
  const std::string kId("storage-id");
  const std::string kIdentity("Purple Onion");
  store.SetCryptedString(kId, /*deprecated_key=*/"",
                         EapCredentials::kStorageCredentialEapIdentity,
                         kIdentity);
  const std::string kManagement("Shave and a Haircut");
  store.SetString(kId, EapCredentials::kStorageEapKeyManagement, kManagement);
  const std::string kPassword("Two Bits");
  store.SetCryptedString(kId, /*deprecated_key=*/"",
                         EapCredentials::kStorageCredentialEapPassword,
                         kPassword);

  eap_.Load(&store, kId);
  Mock::VerifyAndClearExpectations(&store);

  EXPECT_EQ(kIdentity, eap_.identity());
  EXPECT_EQ(kManagement, eap_.key_management());
  EXPECT_EQ(kPassword, GetPassword());

  // Save with save_credentials=false.
  store.DeleteGroup(kId);
  eap_.Save(&store, kId, /*save_credentials=*/false);
  std::string management;
  EXPECT_TRUE(store.GetString(kId, EapCredentials::kStorageEapKeyManagement,
                              &management));
  EXPECT_EQ(management, kManagement);
  // Authentication properties are deleted from the store if they are empty,
  // so we expect the fields that we haven't set to be deleted.
  EXPECT_FALSE(store.GetString(
      kId, EapCredentials::kStorageCredentialEapIdentity, nullptr));
  EXPECT_FALSE(store.GetString(
      kId, EapCredentials::kStorageCredentialEapPassword, nullptr));

  // Save with save_credentials=true.
  store.DeleteGroup(kId);
  eap_.Save(&store, kId, /*save_credentials=*/true);
  EXPECT_TRUE(store.GetString(kId, EapCredentials::kStorageEapKeyManagement,
                              &management));
  EXPECT_EQ(management, kManagement);
  std::string identity, password;
  EXPECT_TRUE(store.GetString(
      kId, EapCredentials::kStorageCredentialEapIdentity, &identity));
  EXPECT_EQ(identity, kIdentity);
  EXPECT_TRUE(store.GetString(
      kId, EapCredentials::kStorageCredentialEapPassword, &password));
  EXPECT_EQ(password, kPassword);
}

TEST_F(EapCredentialsTest, Load) {
  const std::vector<std::string> kCaCertPem{"first line", "second line"};
  const std::string kMethod("TTLS");
  const std::string kInnerMethod("auth=AnotherMethod");
  const std::string kIdentity("Red Fruit");
  const std::string kPassword("One Time Password");
  const std::string kSubjectNameMatch("domain1.com");
  const std::vector<std::string> kAlternativeNameMatchList{"domain2.com",
                                                           "domain3.com"};
  const std::vector<std::string> kDomainSuffixMatchList{"domain4.com",
                                                        "domain5.com"};

  KeyValueStore store;
  store.Set(kEapCaCertPemProperty, kCaCertPem);
  store.Set(kEapMethodProperty, kMethod);
  store.Set(kEapPhase2AuthProperty, kInnerMethod);
  store.Set(kEapIdentityProperty, kIdentity);
  store.Set(kEapPasswordProperty, kPassword);
  store.Set(kEapSubjectMatchProperty, kSubjectNameMatch);
  store.Set(kEapSubjectAlternativeNameMatchProperty, kAlternativeNameMatchList);
  store.Set(kEapDomainSuffixMatchProperty, kDomainSuffixMatchList);
  eap_.Load(store);

  EXPECT_EQ(kMethod, eap_.method());
  EXPECT_EQ(kInnerMethod, eap_.inner_method());
  EXPECT_EQ(kIdentity, eap_.identity());
  EXPECT_EQ(kPassword, eap_.password_);
  EXPECT_EQ(kCaCertPem, eap_.ca_cert_pem());
  EXPECT_EQ(kSubjectNameMatch, eap_.subject_match());
  EXPECT_EQ(kAlternativeNameMatchList,
            eap_.subject_alternative_name_match_list());
  EXPECT_EQ(kDomainSuffixMatchList, eap_.domain_suffix_match_list());
  // Other fields keep their default value.
  EXPECT_TRUE(eap_.anonymous_identity_.empty());
  EXPECT_TRUE(eap_.cert_id_.empty());
  EXPECT_TRUE(eap_.key_id_.empty());
  EXPECT_TRUE(eap_.pin_.empty());
  EXPECT_TRUE(eap_.ca_cert_id_.empty());
  EXPECT_TRUE(eap_.tls_version_max_.empty());
  EXPECT_TRUE(eap_.use_system_cas());
  EXPECT_FALSE(eap_.use_proactive_key_caching_);
  EXPECT_FALSE(eap_.use_login_password_);

  EapCredentials eap2;
  eap2.Load(eap_);
  EXPECT_EQ(eap_.method(), eap2.method());
  EXPECT_EQ(eap_.inner_method(), eap2.inner_method());
  EXPECT_EQ(eap_.identity(), eap2.identity());
  EXPECT_EQ(eap_.password_, eap2.password_);
  EXPECT_EQ(eap_.ca_cert_pem(), eap2.ca_cert_pem());
  EXPECT_EQ(eap_.subject_match(), eap2.subject_match());
  EXPECT_EQ(eap_.subject_alternative_name_match_list(),
            eap2.subject_alternative_name_match_list());
  EXPECT_EQ(eap_.domain_suffix_match_list(), eap2.domain_suffix_match_list());
  EXPECT_EQ(eap_.anonymous_identity_, eap2.anonymous_identity_);
  EXPECT_EQ(eap_.cert_id_, eap2.cert_id_);
  EXPECT_EQ(eap_.key_id_, eap2.key_id_);
  EXPECT_EQ(eap_.pin_, eap2.pin_);
  EXPECT_EQ(eap_.ca_cert_id_, eap2.ca_cert_id_);
  EXPECT_EQ(eap_.tls_version_max_, eap2.tls_version_max_);
  EXPECT_EQ(eap_.use_system_cas(), eap2.use_system_cas());
  EXPECT_EQ(eap_.use_proactive_key_caching_, eap2.use_proactive_key_caching_);
  EXPECT_EQ(eap_.use_login_password_, eap2.use_login_password_);
}

TEST_F(EapCredentialsTest, Load_UserSlot) {
  FakeStore store;
  const std::string kId("storage-id");
  const std::string kCertId("1:AAAAAAAA");
  const std::string kOutdatedCertId("2:AAAAAAAA");

  // CertID and KeyID are expected to be equal.
  store.SetString(kId, EapCredentials::kStorageEapCertID, kOutdatedCertId);
  store.SetString(kId, EapCredentials::kStorageEapKeyID, kOutdatedCertId);
  store.SetInt(kId, EapCredentials::kStorageEapSlot, pkcs11::kUser);

  // Expect invalid certificate and key ID to be corrected.
  eap_.SetEapSlotGetter(&slot_getter_);
  EXPECT_CALL(slot_getter_,
              GetPkcs11SlotIdWithRetries(pkcs11::Slot::kUser, _, _))
      .WillOnce(WithArg<1>([](base::OnceCallback<void(CK_SLOT_ID)> callback) {
        std::move(callback).Run(1);
      }));
  eap_.Load(&store, kId);

  EXPECT_EQ(eap_.cert_id_, kCertId);
  EXPECT_EQ(eap_.key_id_, kCertId);
}

TEST_F(EapCredentialsTest, Load_SystemSlot) {
  FakeStore store;
  const std::string kId("storage-id");
  const std::string kCertId("0:AAAAAAAA");
  const std::string kOutdatedCertId("2:AAAAAAAA");

  // CertID and KeyID are expected to be equal.
  store.SetString(kId, EapCredentials::kStorageEapCertID, kOutdatedCertId);
  store.SetString(kId, EapCredentials::kStorageEapKeyID, kOutdatedCertId);
  store.SetInt(kId, EapCredentials::kStorageEapSlot, pkcs11::kSystem);

  // Expect invalid certificate and key ID to be corrected.
  eap_.SetEapSlotGetter(&slot_getter_);
  EXPECT_CALL(slot_getter_,
              GetPkcs11SlotIdWithRetries(pkcs11::Slot::kSystem, _, _))
      .WillOnce(WithArg<1>([](base::OnceCallback<void(CK_SLOT_ID)> callback) {
        std::move(callback).Run(0);
      }));
  eap_.Load(&store, kId);

  EXPECT_EQ(eap_.cert_id_, kCertId);
  EXPECT_EQ(eap_.key_id_, kCertId);
}

TEST_F(EapCredentialsTest, SaveAndLoad_Pkcs11Id) {
  FakeStore store;
  const std::string kCertId("1:AAAAAAAA");
  eap_.cert_id_ = kCertId;
  const std::string kKeyId("1:AAAAAAAA");
  eap_.key_id_ = kKeyId;
  const std::string kId("storage-id");

  eap_.SetEapSlotGetter(&slot_getter_);
  EXPECT_CALL(slot_getter_, GetPkcs11SlotId(pkcs11::Slot::kUser))
      .WillOnce(Return(1));
  eap_.Save(&store, kId, /*save_credentials=*/true);

  // Clear the values.
  eap_.cert_id_ = "";
  eap_.key_id_ = "";

  eap_.SetEapSlotGetter(&slot_getter_);
  EXPECT_CALL(slot_getter_,
              GetPkcs11SlotIdWithRetries(pkcs11::Slot::kUser, _, _))
      .WillOnce(WithArg<1>([](base::OnceCallback<void(CK_SLOT_ID)> callback) {
        std::move(callback).Run(1);
      }));
  eap_.Load(&store, kId);

  EXPECT_EQ(eap_.cert_id_, kCertId);
  EXPECT_EQ(eap_.key_id_, kKeyId);
}

TEST_F(EapCredentialsTest, OutputConnectionMetrics) {
  Error unused_error;
  SetEap(kEapMethodPEAP);
  SetInnerEap(kEapPhase2AuthPEAPMSCHAPV2);

  MockMetrics metrics;
  EXPECT_CALL(metrics, SendEnumToUMA(Metrics::kMetricNetworkEapOuterProtocol,
                                     Technology(Technology::kWiFi),
                                     Metrics::kEapOuterProtocolPeap));
  EXPECT_CALL(metrics, SendEnumToUMA(Metrics::kMetricNetworkEapInnerProtocol,
                                     Technology(Technology::kWiFi),
                                     Metrics::kEapInnerProtocolPeapMschapv2));
  eap_.OutputConnectionMetrics(&metrics, Technology::kWiFi);
}

TEST_F(EapCredentialsTest, PopulateSupplicantProperties) {
  SetIdentity("testidentity");
  SetPin("xxxx");
  PopulateSupplicantProperties();
  // Test that only non-empty 802.1x properties are populated.
  EXPECT_TRUE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapIdentity));
  EXPECT_FALSE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapKeyId));
  EXPECT_FALSE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapCaCert));

  // Test that CA path is set by default.
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyCaPath));

  // Test that hardware-backed security arguments are not set, since
  // neither key-id nor cert-id were set.
  EXPECT_FALSE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapPin));
  EXPECT_FALSE(
      params_.Contains<uint32_t>(WPASupplicant::kNetworkPropertyEngine));
  EXPECT_FALSE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEngineId));

  // Test EAP version translation.  The "phase1" supplicant parameter is
  // normally empty, but it will contain a "tls_disable" flag if this
  // service requests an old TLS version.
  EXPECT_FALSE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapOuterEap));

  SetTLSVersionMax("1.2");
  PopulateSupplicantProperties();
  EXPECT_FALSE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapOuterEap));

  SetTLSVersionMax("1.0");
  PopulateSupplicantProperties();
  EXPECT_TRUE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapOuterEap));
  std::string phase1 =
      params_.Get<std::string>(WPASupplicant::kNetworkPropertyEapOuterEap);
  EXPECT_EQ(std::string::npos, phase1.find("disable_tlsv1_0=1"));
  EXPECT_NE(std::string::npos, phase1.find("disable_tlsv1_1=1"));
  EXPECT_NE(std::string::npos, phase1.find("disable_tlsv1_2=1"));

  SetDomainSuffixMatch({"domain1.com", "domain2.com"});
  PopulateSupplicantProperties();
  std::string domain_suffix_match_list = params_.Get<std::string>(
      WPASupplicant::kNetworkPropertyEapDomainSuffixMatch);
  EXPECT_EQ("domain1.com;domain2.com", domain_suffix_match_list);
}

// Test that invalid domains in EAP.DomainSuffixMatch are filtered out.
TEST_F(EapCredentialsTest, DomainSuffixMatch) {
  SetDomainSuffixMatch(
      {"domain1.com", "domain2-.com", "domain3", "domain4.com"});
  PopulateSupplicantProperties();
  std::string domain_suffix_match_list = params_.Get<std::string>(
      WPASupplicant::kNetworkPropertyEapDomainSuffixMatch);
  EXPECT_EQ("domain1.com;domain4.com", domain_suffix_match_list);

  // Expect that if shill doesn't set the value for domain_suffix_match, the
  // parameter is not set to the wpa_supplicant.
  params_.Clear();
  SetDomainSuffixMatch({""});
  PopulateSupplicantProperties();
  EXPECT_FALSE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapDomainSuffixMatch));
}

TEST_F(EapCredentialsTest, ValidDomainSuffixMatch) {
  EXPECT_TRUE(EapCredentials::ValidDomainSuffixMatch("com"));
  EXPECT_TRUE(EapCredentials::ValidDomainSuffixMatch("example.com"));
  EXPECT_TRUE(EapCredentials::ValidDomainSuffixMatch("a.b.c.example.com"));
  EXPECT_TRUE(EapCredentials::ValidDomainSuffixMatch("sub-domain.example.com"));
  EXPECT_TRUE(
      EapCredentials::ValidDomainSuffixMatch("1subdomain2.examp7e.com"));
  // False because length = 0.
  EXPECT_FALSE(EapCredentials::ValidDomainSuffixMatch(""));
  // False because starts with hyphen.
  EXPECT_FALSE(EapCredentials::ValidDomainSuffixMatch("-example.com"));
  // False because ends with hyphen.
  EXPECT_FALSE(EapCredentials::ValidDomainSuffixMatch("example-.com"));
  // False because unsupported character.
  EXPECT_FALSE(EapCredentials::ValidDomainSuffixMatch("exam;ple.com"));
  // False because of numerical character in top level domain.
  EXPECT_FALSE(EapCredentials::ValidDomainSuffixMatch("example.com2"));
  // Invalid because label size > 63 characters.
  const std::string invalid_label(64, 'a');
  EXPECT_FALSE(EapCredentials::ValidDomainSuffixMatch(invalid_label + ".com"));
  // Invalid because label size is 0.
  EXPECT_FALSE(EapCredentials::ValidDomainSuffixMatch("..com2"));
}

TEST_F(EapCredentialsTest, PopulateSupplicantPropertiesNoSystemCAs) {
  SetIdentity("testidentity");
  SetUseSystemCAs(false);
  PopulateSupplicantProperties();
  // Test that CA path is not set if use_system_cas is explicitly false.
  EXPECT_FALSE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyCaPath));
}

TEST_F(EapCredentialsTest,
       PopulateSupplicantPropertiesProactiveKeyCachingDisabledByDefault) {
  SetIdentity("testidentity");
  PopulateSupplicantProperties();

  ASSERT_TRUE(params_.Contains<uint32_t>(
      WPASupplicant::kNetworkPropertyEapProactiveKeyCaching));

  const uint32_t kProactiveKeyCachingDisabled(0);

  EXPECT_EQ(kProactiveKeyCachingDisabled,
            params_.Get<uint32_t>(
                WPASupplicant::kNetworkPropertyEapProactiveKeyCaching));
}

TEST_F(EapCredentialsTest,
       PopulateSupplicantPropertiesEnableProactiveKeyCaching) {
  SetIdentity("testidentity");
  SetUseProactiveKeyCaching(true);
  PopulateSupplicantProperties();

  ASSERT_TRUE(params_.Contains<uint32_t>(
      WPASupplicant::kNetworkPropertyEapProactiveKeyCaching));

  const uint32_t kProactiveKeyCachingEnabled(1);

  EXPECT_EQ(kProactiveKeyCachingEnabled,
            params_.Get<uint32_t>(
                WPASupplicant::kNetworkPropertyEapProactiveKeyCaching));
}

TEST_F(EapCredentialsTest,
       PopulateSupplicantPropertiesDisableProactiveKeyCaching) {
  SetIdentity("testidentity");
  SetUseProactiveKeyCaching(false);
  PopulateSupplicantProperties();

  ASSERT_TRUE(params_.Contains<uint32_t>(
      WPASupplicant::kNetworkPropertyEapProactiveKeyCaching));

  const uint32_t kProactiveKeyCachingDisabled(0);

  EXPECT_EQ(kProactiveKeyCachingDisabled,
            params_.Get<uint32_t>(
                WPASupplicant::kNetworkPropertyEapProactiveKeyCaching));
}

TEST_F(EapCredentialsTest, PopulateSupplicantPropertiesUsingHardwareAuth) {
  SetIdentity("testidentity");
  SetKeyId("key_id");
  SetPin("xxxx");
  SetEap("PEAP");
  PopulateSupplicantProperties();
  // Test that EAP engine parameters are not set if the authentication type
  // is not one that accepts a client certificate.
  EXPECT_FALSE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapPin));
  EXPECT_FALSE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapKeyId));
  EXPECT_FALSE(
      params_.Contains<uint32_t>(WPASupplicant::kNetworkPropertyEngine));
  EXPECT_FALSE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEngineId));

  // Test that EAP engine parameters are set if key_id is set and the
  // authentication type accepts a client certificate.
  params_.Clear();
  SetEap("TLS");
  PopulateSupplicantProperties();
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapPin));
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapKeyId));
  EXPECT_TRUE(
      params_.Contains<uint32_t>(WPASupplicant::kNetworkPropertyEngine));
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEngineId));

  // An empty EAP parameter should be considered to be possibly "TLS".
  params_.Clear();
  SetEap("");
  PopulateSupplicantProperties();
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapPin));
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapKeyId));
  EXPECT_TRUE(
      params_.Contains<uint32_t>(WPASupplicant::kNetworkPropertyEngine));
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEngineId));

  // Test that EAP engine parameters are set if ca_cert_id is set even if the
  // authentication type does not accept a client certificate.  However,
  // the client key id should not be provided.
  params_.Clear();
  SetEap("PEAP");
  SetCACertId("certid");
  PopulateSupplicantProperties();
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapPin));
  EXPECT_FALSE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapKeyId));
  EXPECT_TRUE(
      params_.Contains<uint32_t>(WPASupplicant::kNetworkPropertyEngine));
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEngineId));
  EXPECT_TRUE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapCaCertId));
}

TEST_F(EapCredentialsTest, PopulateSupplicantPropertiesPEM) {
  const std::vector<std::string> kPemCert{"-pem-certificate-here-"};
  SetCACertPEM(kPemCert);
  const std::string kPEMCertfile("/tmp/pem-cert");
  base::FilePath pem_cert(kPEMCertfile);
  EXPECT_CALL(certificate_file_, CreatePEMFromStrings(kPemCert))
      .WillOnce(Return(pem_cert));

  PopulateSupplicantProperties();
  EXPECT_TRUE(
      params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapCaCert));
  if (params_.Contains<std::string>(WPASupplicant::kNetworkPropertyEapCaCert)) {
    EXPECT_EQ(kPEMCertfile, params_.Get<std::string>(
                                WPASupplicant::kNetworkPropertyEapCaCert));
  }
}

TEST_F(EapCredentialsTest, Reset) {
  EXPECT_TRUE(IsReset());
  EXPECT_TRUE(GetKeyManagement().empty());
  SetAnonymousIdentity("foo");
  SetCACertId("foo");
  SetCACertPEM(std::vector<std::string>{"foo"});
  SetCertId("foo");
  SetEap("foo");
  SetIdentity("foo");
  SetInnerEap("foo");
  SetKeyId("foo");
  SetPassword("foo");
  SetPin("foo");
  SetUseSystemCAs(false);
  SetUseProactiveKeyCaching(true);
  SetUseLoginPassword(false);
  SetSubjectAlternativeNameMatch(std::vector<std::string>{"foo"});
  SetDomainSuffixMatch(std::vector<std::string>{"foo"});
  eap_.SetKeyManagement("foo", nullptr);
  EXPECT_FALSE(IsReset());
  EXPECT_FALSE(GetKeyManagement().empty());
  eap_.Reset();
  EXPECT_TRUE(IsReset());
  EXPECT_FALSE(GetKeyManagement().empty());
}

TEST_F(EapCredentialsTest, SetKeyManagement) {
  const std::string kKeyManagement0("foo");
  eap_.SetKeyManagement(kKeyManagement0, nullptr);
  EXPECT_EQ(kKeyManagement0, GetKeyManagement());

  const std::string kKeyManagement1("bar");
  eap_.SetKeyManagement(kKeyManagement1, nullptr);
  EXPECT_EQ(kKeyManagement1, GetKeyManagement());

  // We should not be able to set the key management to an empty string.
  eap_.SetKeyManagement("", nullptr);
  EXPECT_EQ(kKeyManagement1, GetKeyManagement());
}

// Custom property setters should return false, and make no changes, if
// the new value is the same as the old value.
TEST_F(EapCredentialsTest, CustomSetterNoopChange) {
  // SetEapKeyManagement
  {
    const std::string kKeyManagement("foo");
    Error error;
    // Set to known value.
    EXPECT_TRUE(eap_.SetKeyManagement(kKeyManagement, &error));
    EXPECT_TRUE(error.IsSuccess());
    // Set to same value.
    EXPECT_FALSE(eap_.SetKeyManagement(kKeyManagement, &error));
    EXPECT_TRUE(error.IsSuccess());
  }

  // SetEapPassword
  {
    const std::string kPassword("foo");
    Error error;
    // Set to known value.
    EXPECT_TRUE(SetEapPassword(kPassword, &error));
    EXPECT_TRUE(error.IsSuccess());
    // Set to same value.
    EXPECT_FALSE(SetEapPassword(kPassword, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
}

TEST_F(EapCredentialsTest, GetPassword) {
  const std::string kPassword("foo");
  Error error;
  EXPECT_TRUE(SetEapPassword(kPassword, &error));
  EXPECT_TRUE(error.IsSuccess());
  std::string set_password = eap_.GetEapPassword(&error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kPassword, set_password);
}

TEST_F(EapCredentialsTest, GetEmptyPassword) {
  Error error;
  std::string set_password = eap_.GetEapPassword(&error);
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_TRUE(set_password.empty());
}

TEST_F(EapCredentialsTest, GetPasswordEmptyForLoginPassword) {
  SetUseLoginPassword(true);
  Error error;
  std::string password = eap_.GetEapPassword(&error);
  EXPECT_TRUE(password.empty());
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_TRUE(password.empty());
}

TEST_F(EapCredentialsTest, TestUseLoginPassword) {
  const std::string kPasswordStr("thepassword");
  SaveLoginPassword(kPasswordStr);

  SetUseLoginPassword(true);
  PopulateSupplicantProperties();

  EXPECT_TRUE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapCaPassword));
  std::string used_password =
      params_.Get<std::string>(WPASupplicant::kNetworkPropertyEapCaPassword);
  EXPECT_EQ(used_password, kPasswordStr);
}

TEST_F(EapCredentialsTest, TestDontUseLoginPassword) {
  const std::string kPasswordStr("thepassword");
  SaveLoginPassword(kPasswordStr);

  SetUseLoginPassword(false);
  PopulateSupplicantProperties();

  EXPECT_FALSE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapCaPassword));
}

TEST_F(EapCredentialsTest, TestSubjectAlternativeNameMatchTranslation) {
  const std::vector<std::string> subject_alternative_name_match_list(
      {"{\"Type\":\"EMAIL\",\"Value\":\"my_email_1\"}",
       "{\"Type\":\"EMAIL\",\"Value\":\"my_email_2\"}",
       "{\"Type\":\"EMAIL\",\"Value\":\"my;email\"}",
       "{\"Type\":\"DNS\",\"Value\":\"my_dns\"}",
       "{\"Type\":\"URI\",\"Value\":\"my_uri\"}"});
  std::string expected_translated =
      "EMAIL:my_email_1;EMAIL:my_email_2;EMAIL:my;email;DNS:my_dns;URI:my_uri";
  std::optional<std::string> altsubject_match =
      EapCredentials::TranslateSubjectAlternativeNameMatch(
          subject_alternative_name_match_list);
  EXPECT_TRUE(altsubject_match.has_value());
  EXPECT_EQ(altsubject_match.value(), expected_translated);
}

TEST_F(EapCredentialsTest, TestSubjectAlternativeNameMatchTranslationFailure) {
  const std::vector<std::string> subject_alternative_name_match_list(
      {"{\"TYPE\":\"EMAIL\",\"Value\":\"my;email\"}"});
  std::optional<std::string> altsubject_match =
      EapCredentials::TranslateSubjectAlternativeNameMatch(
          subject_alternative_name_match_list);
  EXPECT_FALSE(altsubject_match.has_value());
}

TEST_F(EapCredentialsTest, TestEapInnerAuthMschapv2NoRetryFlag) {
  // If no EAP inner auth is set, no additional  mschapv2_retry flag is added.
  SetInnerEap("");
  PopulateSupplicantProperties();
  EXPECT_FALSE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapInnerEap));

  // If an EAP inner auth different than MSCHPAV2 is set, also expect no change.
  SetInnerEap("auth=MD5");
  PopulateSupplicantProperties();
  EXPECT_TRUE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapInnerEap));
  {
    const std::string inner_eap =
        params_.Get<std::string>(WPASupplicant::kNetworkPropertyEapInnerEap);
    EXPECT_EQ(inner_eap, "auth=MD5");
  }

  // If EAP inner auth is set to MSCHAPV2, the flag should be added.
  SetInnerEap("auth=MSCHAPV2");
  PopulateSupplicantProperties();
  EXPECT_TRUE(params_.Contains<std::string>(
      WPASupplicant::kNetworkPropertyEapInnerEap));
  {
    const std::string inner_eap =
        params_.Get<std::string>(WPASupplicant::kNetworkPropertyEapInnerEap);
    EXPECT_EQ(inner_eap, "auth=MSCHAPV2 mschapv2_retry=0");
  }
}

}  // namespace shill
