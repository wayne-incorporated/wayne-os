// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/passpoint_credentials.h"

#include <limits>
#include <string>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/shill/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/error.h"
#include "shill/metrics.h"
#include "shill/profile.h"
#include "shill/refptr_types.h"
#include "shill/store/key_value_store.h"
#include "shill/supplicant/wpa_supplicant.h"

namespace shill {

namespace {
std::vector<std::string> toStringList(std::vector<uint64_t> list) {
  std::vector<std::string> out;
  for (uint64_t value : list) {
    out.push_back(base::NumberToString(value));
  }
  return out;
}
}  // namespace

class PasspointCredentialsTest : public ::testing::Test {
 public:
  PasspointCredentialsTest() = default;
  ~PasspointCredentialsTest() override = default;
};

TEST_F(PasspointCredentialsTest, CreateChecksMatchDomains) {
  const std::string kValidFQDN1("example.com");
  const std::string kValidFQDN2("example.net");
  const Strings kValidFQDNs{kValidFQDN1, kValidFQDN2};
  const std::string kInvalidDomain("-foo.com");
  const Strings kInvalidDomains{kInvalidDomain};
  const std::string kUser("test-user");
  const std::string kPassword("test-password");
  KeyValueStore properties;
  Error error;

  // No domain fails
  auto [creds1, result1] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds1, nullptr);
  EXPECT_EQ(result1, Metrics::kPasspointProvisioningNoOrInvalidFqdn);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);

  // Invalid domain fails
  error.Reset();
  properties.Set(kPasspointCredentialsDomainsProperty, kInvalidDomains);
  auto [creds2, result2] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds2, nullptr);
  EXPECT_EQ(result2, Metrics::kPasspointProvisioningNoOrInvalidFqdn);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);

  // No realm or invalid realm fails
  error.Reset();
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  auto [creds3, result3] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds3, nullptr);
  EXPECT_EQ(result3, Metrics::kPasspointProvisioningNoOrInvalidRealm);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);

  // Invalid realm fails
  error.Reset();
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kInvalidDomain);
  auto [creds4, result4] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds4, nullptr);
  EXPECT_EQ(result4, Metrics::kPasspointProvisioningNoOrInvalidRealm);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);
}

TEST_F(PasspointCredentialsTest, CreateChecksEapCredentials) {
  const std::string kValidFQDN("example.com");
  const Strings kValidFQDNs{kValidFQDN};
  const std::string kInvalidDomain("-bar.com");
  const std::string kUser("test-user");
  const std::string kPassword("test-password");
  const std::string kMethodTTLS(kEapMethodTTLS);
  const std::string kSubjectNameMatch("domain1.com");
  const std::vector<std::string> kCaCertPem{"pem first line",
                                            "pem second line"};
  const std::vector<std::string> kAlternativeNameMatchList{"domain2.com",
                                                           "domain3.com"};
  const std::vector<std::string> kDomainSuffixMatchList{"domain4.com",
                                                        "domain5.com"};
  const std::vector<std::string> kInvalidOis{"1122", "notanumber"};
  KeyValueStore properties;
  Error error;

  // No EAP credentials fails.
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  auto [creds1, result1] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds1, nullptr);
  EXPECT_EQ(result1, Metrics::kPasspointProvisioningInvalidEapProperties);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);

  // Invalid EAP method
  error.Reset();
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kEapCaCertPemProperty, kCaCertPem);
  // The following properties are enough to create a connectable EAP set.
  properties.Set(kEapMethodProperty, std::string(kEapMethodPEAP));
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  auto [creds2, result2] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds2, nullptr);
  EXPECT_EQ(result2, Metrics::kPasspointProvisioningInvalidEapMethod);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);

  // Invalid inner EAP method with TTLS
  error.Reset();
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kEapCaCertPemProperty, kCaCertPem);
  properties.Set(kEapMethodProperty, kMethodTTLS);
  properties.Set(kEapPhase2AuthProperty, std::string(kEapPhase2AuthTTLSMD5));
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  auto [creds3, result3] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds3, nullptr);
  EXPECT_EQ(result3, Metrics::kPasspointProvisioningInvalidEapProperties);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);

  // No CA cert and only a subject name match.
  error.Reset();
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kEapMethodProperty, kMethodTTLS);
  properties.Set(kEapPhase2AuthProperty,
                 std::string(kEapPhase2AuthTTLSMSCHAPV2));
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  properties.Set(kEapSubjectMatchProperty, kSubjectNameMatch);
  auto [creds4, result4] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds4, nullptr);
  EXPECT_EQ(result4, Metrics::kPasspointProvisioningInvalidEapProperties);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);

  // Incorrect home OIs
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kPasspointCredentialsHomeOIsProperty, kInvalidOis);
  properties.Set(kEapMethodProperty, kMethodTTLS);
  properties.Set(kEapPhase2AuthProperty,
                 std::string(kEapPhase2AuthTTLSMSCHAPV2));
  properties.Set(kEapCaCertPemProperty, kCaCertPem);
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  auto [creds6, result6] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds6, nullptr);
  EXPECT_EQ(result6,
            Metrics::kPasspointProvisioningInvalidOrganizationIdentifier);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);

  // Incorrect required home OIs
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kPasspointCredentialsRequiredHomeOIsProperty, kInvalidOis);
  properties.Set(kEapMethodProperty, kMethodTTLS);
  properties.Set(kEapPhase2AuthProperty,
                 std::string(kEapPhase2AuthTTLSMSCHAPV2));
  properties.Set(kEapCaCertPemProperty, kCaCertPem);
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  auto [creds7, result7] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds7, nullptr);
  EXPECT_EQ(result7,
            Metrics::kPasspointProvisioningInvalidOrganizationIdentifier);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);

  // Incorrect roaming consortia OIs
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kPasspointCredentialsRoamingConsortiaProperty, kInvalidOis);
  properties.Set(kEapMethodProperty, kMethodTTLS);
  properties.Set(kEapPhase2AuthProperty,
                 std::string(kEapPhase2AuthTTLSMSCHAPV2));
  properties.Set(kEapCaCertPemProperty, kCaCertPem);
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  auto [creds8, result8] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_EQ(creds8, nullptr);
  EXPECT_EQ(result8,
            Metrics::kPasspointProvisioningInvalidOrganizationIdentifier);
  EXPECT_EQ(error.type(), Error::kInvalidArguments);
}

TEST_F(PasspointCredentialsTest, Create) {
  const std::string kValidFQDN("example.com");
  const Strings kValidFQDNs{kValidFQDN};
  const std::string kInvalidDomain("-abc.com");
  const std::string kUser("test-user");
  const std::string kPassword("test-password");
  const std::string kMethodTLS(kEapMethodTLS);
  const std::string kMethodTTLS(kEapMethodTTLS);
  const std::vector<uint64_t> kOIs{0x123456789, 0x1045985432,
                                   std::numeric_limits<uint64_t>::min(),
                                   std::numeric_limits<uint64_t>::max()};
  const std::vector<uint64_t> kRoamingConsortia{123456789, 321645987,
                                                9876453120};
  const std::vector<std::string> kCaCertPem{"pem first line",
                                            "pem second line"};
  const std::string kPackageName("com.foo.bar");
  const std::string kFriendlyName("My Service Provider");
  const std::string kExpirationTime = "1906869600000";
  const int64_t kExpirationTimeValue = 1906869600000;
  const std::string kCertId("cert-id");
  const std::string kKeyId("key-id");
  const std::string kSubjectNameMatch("domain1.com");
  const std::vector<std::string> kAlternativeNameMatchList{"domain2.com",
                                                           "domain3.com"};
  const std::vector<std::string> kDomainSuffixMatchList{"domain4.com",
                                                        "domain5.com"};

  KeyValueStore properties;
  Error error;

  // Verify Passpoint+EAP-TLS with CA cert
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kPasspointCredentialsHomeOIsProperty, toStringList(kOIs));
  properties.Set(kPasspointCredentialsRequiredHomeOIsProperty,
                 toStringList(kOIs));
  properties.Set(kPasspointCredentialsRoamingConsortiaProperty,
                 toStringList(kRoamingConsortia));
  properties.Set(kPasspointCredentialsMeteredOverrideProperty, true);
  properties.Set(kPasspointCredentialsAndroidPackageNameProperty, kPackageName);
  properties.Set(kEapMethodProperty, kMethodTLS);
  properties.Set(kEapCaCertPemProperty, kCaCertPem);
  properties.Set(kEapCertIdProperty, kCertId);
  properties.Set(kEapKeyIdProperty, kKeyId);
  properties.Set(kEapPinProperty, std::string("111111"));
  properties.Set(kEapIdentityProperty, kUser);

  auto [creds1, result1] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);

  EXPECT_NE(nullptr, creds1);
  EXPECT_EQ(kValidFQDNs, creds1->domains());
  EXPECT_EQ(kValidFQDN, creds1->realm());
  EXPECT_EQ(kOIs, creds1->home_ois());
  EXPECT_EQ(kOIs, creds1->required_home_ois());
  EXPECT_EQ(kRoamingConsortia, creds1->roaming_consortia());
  EXPECT_TRUE(creds1->metered_override());
  EXPECT_EQ(kPackageName, creds1->android_package_name());
  EXPECT_EQ(std::string(), creds1->friendly_name());
  EXPECT_EQ(std::numeric_limits<int64_t>::min(),
            creds1->expiration_time_milliseconds());
  EXPECT_TRUE(creds1->eap().IsConnectable());
  EXPECT_FALSE(creds1->eap().use_system_cas());
  EXPECT_EQ(result1, Metrics::kPasspointProvisioningSuccess);

  // Verify Passpoint+EAP-TTLS with CA cert
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kPasspointCredentialsHomeOIsProperty, toStringList(kOIs));
  properties.Set(kPasspointCredentialsRequiredHomeOIsProperty,
                 toStringList(kOIs));
  properties.Set(kPasspointCredentialsRoamingConsortiaProperty,
                 toStringList(kRoamingConsortia));
  properties.Set(kPasspointCredentialsMeteredOverrideProperty, true);
  properties.Set(kPasspointCredentialsAndroidPackageNameProperty, kPackageName);
  properties.Set(kPasspointCredentialsFriendlyNameProperty, kFriendlyName);
  properties.Set(kPasspointCredentialsExpirationTimeMillisecondsProperty,
                 kExpirationTime);
  properties.Set(kEapMethodProperty, kMethodTTLS);
  properties.Set(kEapPhase2AuthProperty,
                 std::string(kEapPhase2AuthTTLSMSCHAPV2));
  properties.Set(kEapCaCertPemProperty, kCaCertPem);
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  EXPECT_FALSE(creds1->eap().use_system_cas());

  auto [creds2, result2] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_NE(nullptr, creds2);
  EXPECT_EQ(kValidFQDNs, creds2->domains());
  EXPECT_EQ(kValidFQDN, creds2->realm());
  EXPECT_EQ(kOIs, creds2->home_ois());
  EXPECT_EQ(kOIs, creds2->required_home_ois());
  EXPECT_EQ(kRoamingConsortia, creds2->roaming_consortia());
  EXPECT_TRUE(creds2->metered_override());
  EXPECT_EQ(kPackageName, creds2->android_package_name());
  EXPECT_EQ(kFriendlyName, creds2->friendly_name());
  EXPECT_EQ(kExpirationTimeValue, creds2->expiration_time_milliseconds());
  EXPECT_TRUE(creds2->eap().IsConnectable());
  EXPECT_EQ(result2, Metrics::kPasspointProvisioningSuccess);

  // Verify Passpoint+EAP-TTLS without CA cert and with altname match list
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kPasspointCredentialsHomeOIsProperty, toStringList(kOIs));
  properties.Set(kPasspointCredentialsRequiredHomeOIsProperty,
                 toStringList(kOIs));
  properties.Set(kPasspointCredentialsRoamingConsortiaProperty,
                 toStringList(kRoamingConsortia));
  properties.Set(kPasspointCredentialsMeteredOverrideProperty, true);
  properties.Set(kPasspointCredentialsAndroidPackageNameProperty, kPackageName);
  properties.Set(kEapMethodProperty, kMethodTTLS);
  properties.Set(kEapPhase2AuthProperty,
                 std::string(kEapPhase2AuthTTLSMSCHAPV2));
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  properties.Set(kEapSubjectAlternativeNameMatchProperty,
                 kAlternativeNameMatchList);

  auto [creds3, result3] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_NE(nullptr, creds3);
  EXPECT_EQ(kValidFQDNs, creds3->domains());
  EXPECT_EQ(kValidFQDN, creds3->realm());
  EXPECT_EQ(kOIs, creds3->home_ois());
  EXPECT_EQ(kOIs, creds3->required_home_ois());
  EXPECT_EQ(kRoamingConsortia, creds3->roaming_consortia());
  EXPECT_TRUE(creds3->metered_override());
  EXPECT_EQ(kPackageName, creds3->android_package_name());
  EXPECT_TRUE(creds3->eap().IsConnectable());
  EXPECT_TRUE(creds3->eap().use_system_cas());
  EXPECT_EQ(result3, Metrics::kPasspointProvisioningSuccess);

  // Verify Passpoint+EAP-TTLS without CA cert and with subject alternative name
  // match list.
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kPasspointCredentialsHomeOIsProperty, toStringList(kOIs));
  properties.Set(kPasspointCredentialsRequiredHomeOIsProperty,
                 toStringList(kOIs));
  properties.Set(kPasspointCredentialsRoamingConsortiaProperty,
                 toStringList(kRoamingConsortia));
  properties.Set(kPasspointCredentialsMeteredOverrideProperty, true);
  properties.Set(kPasspointCredentialsAndroidPackageNameProperty, kPackageName);
  properties.Set(kEapMethodProperty, kMethodTTLS);
  properties.Set(kEapPhase2AuthProperty,
                 std::string(kEapPhase2AuthTTLSMSCHAPV2));
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  properties.Set(kEapSubjectAlternativeNameMatchProperty,
                 kAlternativeNameMatchList);

  auto [creds4, result4] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_NE(nullptr, creds4);
  EXPECT_EQ(kValidFQDNs, creds4->domains());
  EXPECT_EQ(kValidFQDN, creds4->realm());
  EXPECT_EQ(kOIs, creds4->home_ois());
  EXPECT_EQ(kOIs, creds4->required_home_ois());
  EXPECT_EQ(kRoamingConsortia, creds4->roaming_consortia());
  EXPECT_TRUE(creds4->metered_override());
  EXPECT_EQ(kPackageName, creds4->android_package_name());
  EXPECT_TRUE(creds4->eap().IsConnectable());
  EXPECT_TRUE(creds4->eap().use_system_cas());
  EXPECT_EQ(result4, Metrics::kPasspointProvisioningSuccess);

  // Verify Passpoint+EAP-TTLS without CA cert and with domain suffix name match
  // list.
  properties.Clear();
  properties.Set(kPasspointCredentialsDomainsProperty, kValidFQDNs);
  properties.Set(kPasspointCredentialsRealmProperty, kValidFQDN);
  properties.Set(kPasspointCredentialsHomeOIsProperty, toStringList(kOIs));
  properties.Set(kPasspointCredentialsRequiredHomeOIsProperty,
                 toStringList(kOIs));
  properties.Set(kPasspointCredentialsRoamingConsortiaProperty,
                 toStringList(kRoamingConsortia));
  properties.Set(kPasspointCredentialsMeteredOverrideProperty, true);
  properties.Set(kPasspointCredentialsAndroidPackageNameProperty, kPackageName);
  properties.Set(kEapMethodProperty, kMethodTTLS);
  properties.Set(kEapPhase2AuthProperty,
                 std::string(kEapPhase2AuthTTLSMSCHAPV2));
  properties.Set(kEapIdentityProperty, kUser);
  properties.Set(kEapPasswordProperty, kPassword);
  properties.Set(kEapDomainSuffixMatchProperty, kDomainSuffixMatchList);

  auto [creds5, result5] =
      PasspointCredentials::CreatePasspointCredentials(properties, &error);
  EXPECT_NE(nullptr, creds5);
  EXPECT_EQ(kValidFQDNs, creds5->domains());
  EXPECT_EQ(kValidFQDN, creds5->realm());
  EXPECT_EQ(kOIs, creds5->home_ois());
  EXPECT_EQ(kOIs, creds5->required_home_ois());
  EXPECT_EQ(kRoamingConsortia, creds5->roaming_consortia());
  EXPECT_TRUE(creds5->metered_override());
  EXPECT_EQ(kPackageName, creds5->android_package_name());
  EXPECT_TRUE(creds5->eap().IsConnectable());
  EXPECT_TRUE(creds5->eap().use_system_cas());
  EXPECT_EQ(result5, Metrics::kPasspointProvisioningSuccess);
}

TEST_F(PasspointCredentialsTest, ToSupplicantProperties) {
  const std::vector<std::string> domains{"blue-sp.example.com",
                                         "green-sp.example.com"};
  const std::string realm("blue-sp.example.com");
  const std::vector<uint64_t> home_ois{0x1234, 0x5678};
  const std::vector<uint64_t> required_home_ois{0xabcd, 0xcdef};
  const std::vector<uint64_t> roaming_consortia{0x11111111, 0x22222222};
  const std::string username = "test-user";

  PasspointCredentialsRefPtr creds = new PasspointCredentials(
      "an_id", domains, realm, home_ois, required_home_ois, roaming_consortia,
      /*metered_override=*/false, "app_package_name", "My Passpoint Provider",
      0);

  // Add the minimal set of EAP properties
  KeyValueStore eap_store;
  eap_store.Set<std::string>(kEapMethodProperty, kEapMethodTTLS);
  eap_store.Set<std::string>(kEapIdentityProperty, username);
  eap_store.Set<std::string>(kEapPasswordProperty, "test-password");
  creds->eap_.Load(eap_store);

  KeyValueStore properties;
  EXPECT_TRUE(creds->ToSupplicantProperties(&properties));

  EXPECT_EQ(domains, properties.Get<std::vector<std::string>>(
                         WPASupplicant::kCredentialsPropertyDomain));
  EXPECT_EQ(realm, properties.Get<std::string>(
                       WPASupplicant::kCredentialsPropertyRealm));
  // We expect the EAP method to be set, this is mandatory for supplicant to
  // perform matches. Right now the value is unknown because the EAP properties
  // can't be set with the constructor.
  EXPECT_TRUE(
      properties.Contains<std::string>(WPASupplicant::kNetworkPropertyEapEap));
  EXPECT_EQ("001234,005678", properties.Get<std::string>(
                                 WPASupplicant::kCredentialsPropertyHomeOIs));
  EXPECT_EQ("00ABCD,00CDEF",
            properties.Get<std::string>(
                WPASupplicant::kCredentialsPropertyRequiredHomeOIs));
  EXPECT_EQ("0011111111,0022222222",
            properties.Get<std::string>(
                WPASupplicant::kCredentialsPropertyRoamingConsortiums));
  EXPECT_EQ(username, properties.Get<std::string>(
                          WPASupplicant::kCredentialsPropertyUsername));

  creds = new PasspointCredentials(
      "an_id", domains, realm, home_ois, required_home_ois, roaming_consortia,
      /*metered_override=*/false, "app_package_name", "My Passpoint Provider",
      0);

  // EAP method and authentication is missing, it will be rejected.
  properties.Clear();
  EXPECT_FALSE(creds->ToSupplicantProperties(&properties));

  // Now the required EAP fields (method and credentials) are available.
  eap_store.Clear();
  eap_store.Set<std::string>(kEapMethodProperty, kEapMethodTLS);
  eap_store.Set<std::string>(kEapCertIdProperty, "0:a_cert_id");
  eap_store.Set<std::string>(kEapKeyIdProperty, "0:a_key_id");
  eap_store.Set<std::string>(kEapIdentityProperty, username);
  creds->eap_.Load(eap_store);

  properties.Clear();
  EXPECT_TRUE(creds->ToSupplicantProperties(&properties));

  EXPECT_EQ(domains, properties.Get<std::vector<std::string>>(
                         WPASupplicant::kCredentialsPropertyDomain));
  EXPECT_EQ(realm, properties.Get<std::string>(
                       WPASupplicant::kCredentialsPropertyRealm));
  EXPECT_EQ("001234,005678", properties.Get<std::string>(
                                 WPASupplicant::kCredentialsPropertyHomeOIs));
  EXPECT_EQ("0011111111,0022222222",
            properties.Get<std::string>(
                WPASupplicant::kCredentialsPropertyRoamingConsortiums));
  EXPECT_EQ(username, properties.Get<std::string>(
                          WPASupplicant::kCredentialsPropertyUsername));
}

TEST_F(PasspointCredentialsTest, EncodeOI) {
  // OUI (24-bit).
  // Even count of digits.
  EXPECT_EQ("506F9A", PasspointCredentials::EncodeOI(0x506F9A));
  // Odd count of digits
  EXPECT_EQ("0B69FE", PasspointCredentials::EncodeOI(0xB69FE));

  // OUI-36 (36-bit).
  // Even count of digits.
  EXPECT_EQ("123456789A", PasspointCredentials::EncodeOI(0x123456789A));
  // Odd count of digits
  EXPECT_EQ("0123456789", PasspointCredentials::EncodeOI(0x123456789));

  // 0s padding for OUI (24-bit).
  EXPECT_EQ("00ABCD", PasspointCredentials::EncodeOI(0xABCD));
  // 0s padding for OUI-36 (36-bit).
  EXPECT_EQ("0009ABCDEF", PasspointCredentials::EncodeOI(0x9ABCDEF));

  EXPECT_EQ("123456789ABCDEF0",
            PasspointCredentials::EncodeOI(0x123456789ABCDEF0));
  EXPECT_EQ("FFFFFFFFFFFFFFFF", PasspointCredentials::EncodeOI(
                                    std::numeric_limits<uint64_t>::max()));
  EXPECT_EQ("000000", PasspointCredentials::EncodeOI(
                          std::numeric_limits<uint64_t>::min()));
}

TEST_F(PasspointCredentialsTest, EncodeOIList) {
  const std::vector<uint64_t> empty;
  const std::vector<uint64_t> one_value{0x80fc};
  const std::vector<uint64_t> two_values{0x0, 0x123abc};
  const std::vector<uint64_t> three_values{0x123456789abcdef0, 0x96,
                                           0xbf0ac789};

  EXPECT_EQ("", PasspointCredentials::EncodeOIList(empty));
  EXPECT_EQ("0080FC", PasspointCredentials::EncodeOIList(one_value));
  EXPECT_EQ("000000,123ABC", PasspointCredentials::EncodeOIList(two_values));
  EXPECT_EQ("123456789ABCDEF0,000096,00BF0AC789",
            PasspointCredentials::EncodeOIList(three_values));
}

}  // namespace shill
