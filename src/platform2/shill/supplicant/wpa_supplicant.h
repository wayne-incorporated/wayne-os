// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_WPA_SUPPLICANT_H_
#define SHILL_SUPPLICANT_WPA_SUPPLICANT_H_

#include <string>

#include "shill/store/key_value_store.h"

namespace shill {

class WPASupplicant {
 public:
  static constexpr char kAuthModeWPAPSK[] = "WPA-PSK";
  static constexpr char kAuthModeWPA2PSK[] = "WPA2-PSK";
  static constexpr char kAuthModeBothPSK[] = "WPA2-PSK+WPA-PSK";
  static constexpr char kAuthModeFTPSK[] = "FT-PSK";
  static constexpr char kAuthModeEAPPrefix[] = "EAP-";
  static constexpr char kAuthModeFTEAP[] = "FT-EAP";
  static constexpr char kAuthModeInactive[] = "INACTIVE";
  static constexpr char kAuthModeUnknown[] = "UNKNOWN";
  static constexpr char kBSSPropertyAge[] = "Age";
  static constexpr char kBSSPropertyBSSID[] = "BSSID";
  static constexpr char kBSSPropertyFrequency[] = "Frequency";
  static constexpr char kBSSPropertyIEs[] = "IEs";
  static constexpr char kBSSPropertyMode[] = "Mode";
  static constexpr char kBSSPropertyRates[] = "Rates";
  static constexpr char kBSSPropertySSID[] = "SSID";
  static constexpr char kBSSPropertySignal[] = "Signal";
  // Location of the system root CA certificates.
  static constexpr char kCaPath[] = "/etc/ssl/certs";
  static constexpr char kCurrentBSSNull[] = "/";
  static constexpr char kDBusAddr[] = "fi.w1.wpa_supplicant1";
  static constexpr char kDBusPath[] = "/fi/w1/wpa_supplicant1";
  static constexpr char kDebugLevelDebug[] = "debug";
  static constexpr char kDebugLevelError[] = "error";
  static constexpr char kDebugLevelExcessive[] = "excessive";
  static constexpr char kDebugLevelInfo[] = "info";
  static constexpr char kDebugLevelMsgDump[] = "msgdump";
  static constexpr char kDebugLevelWarning[] = "warning";
  static constexpr char kDriverNL80211[] = "nl80211";
  static constexpr char kDriverWired[] = "wired";
  static constexpr char kEAPParameterAlertUnknownCA[] = "unknown CA";
  static constexpr char kEAPParameterFailure[] = "failure";
  static constexpr char kEAPParameterSuccess[] = "success";
  static constexpr char kEAPRequestedParameterPin[] = "PIN";
  static constexpr char kEAPStatusAcceptProposedMethod[] =
      "accept proposed method";
  static constexpr char kEAPStatusCompletion[] = "completion";
  static constexpr char kEAPStatusLocalTLSAlert[] = "local TLS alert";
  static constexpr char kEAPStatusParameterNeeded[] = "eap parameter needed";
  static constexpr char kEAPStatusRemoteCertificateVerification[] =
      "remote certificate verification";
  static constexpr char kEAPStatusRemoteTLSAlert[] = "remote TLS alert";
  static constexpr char kEAPStatusStarted[] = "started";
  static constexpr char kEnginePKCS11[] = "pkcs11";
  static constexpr char kErrorNetworkUnknown[] =
      "fi.w1.wpa_supplicant1.NetworkUnknown";
  static constexpr char kErrorInterfaceExists[] =
      "fi.w1.wpa_supplicant1.InterfaceExists";
  static constexpr char kInterfacePropertyAddress[] = "Address";
  static constexpr char kInterfacePropertyAssocStatusCode[] = "AssocStatusCode";
  static constexpr char kInterfacePropertyAuthStatusCode[] = "AuthStatusCode";
  static constexpr char kInterfacePropertyCapabilities[] = "Capabilities";
  static constexpr char kInterfacePropertyConfigFile[] = "ConfigFile";
  static constexpr char kInterfacePropertyCreate[] = "Create";
  static constexpr char kInterfacePropertyCurrentAuthMode[] = "CurrentAuthMode";
  static constexpr char kInterfacePropertyCurrentBSS[] = "CurrentBSS";
  static constexpr char kInterfacePropertyDepth[] = "depth";
  static constexpr char kInterfacePropertyDisconnectReason[] =
      "DisconnectReason";
  static constexpr char kInterfacePropertyDriver[] = "Driver";
  static constexpr char kInterfacePropertyName[] = "Ifname";
  static constexpr char kInterfacePropertyRoamTime[] = "RoamTime";
  static constexpr char kInterfacePropertyRoamComplete[] = "RoamComplete";
  static constexpr char kInterfacePropertySessionLength[] = "SessionLength";
  static constexpr char kInterfacePropertyState[] = "State";
  static constexpr char kInterfacePropertySubject[] = "subject";
  static constexpr char kInterfacePropertyType[] = "Type";
  static constexpr char kInterfacePropertyTypeAP[] = "ap";
  static constexpr char kInterfacePropertyTypeStation[] = "sta";
  static constexpr char kInterfaceState4WayHandshake[] = "4way_handshake";
  static constexpr char kInterfaceStateAssociated[] = "associated";
  static constexpr char kInterfaceStateAssociating[] = "associating";
  static constexpr char kInterfaceStateAuthenticating[] = "authenticating";
  static constexpr char kInterfaceStateCompleted[] = "completed";
  static constexpr char kInterfaceStateDisconnected[] = "disconnected";
  static constexpr char kInterfaceStateGroupHandshake[] = "group_handshake";
  static constexpr char kInterfaceStateInactive[] = "inactive";
  static constexpr char kInterfaceStateInterfaceDisabled[] =
      "interface_disabled";
  static constexpr char kInterfaceStateScanning[] = "scanning";
  static constexpr char kKeyManagementIeee8021X[] = "IEEE8021X";
  static constexpr char kKeyManagementFTEAP[] = "FT-EAP";
  static constexpr char kKeyManagementFTPSK[] = "FT-PSK";
  static constexpr char kKeyManagementFTSAE[] = "FT-SAE";
  static constexpr char kKeyManagementWPAEAP[] = "WPA-EAP";
  static constexpr char kKeyManagementWPAEAPSHA256[] = "WPA-EAP-SHA256";
  static constexpr char kKeyManagementWPAPSK[] = "WPA-PSK";
  static constexpr char kKeyManagementWPAPSKSHA256[] = "WPA-PSK-SHA256";
  static constexpr char kKeyManagementSAE[] = "SAE";
  static constexpr char kKeyManagementMethodPrefixEAP[] = "wpa-eap";
  static constexpr char kKeyManagementMethodSuffixEAP[] = "-eap";
  static constexpr char kKeyManagementMethodSuffixPSK[] = "-psk";
  static constexpr char kKeyManagementMethodSuffixPSKSHA256[] = "-psk-sha256";
  static constexpr char kKeyManagementMethodSuiteB[] = "-suite-b";
  static constexpr char kKeyManagementMethodSuffixEAPSHA256[] = "-eap-sha256";
  static constexpr char kKeyManagementMethodSAE[] = "sae";
  static constexpr char kKeyManagementNone[] = "NONE";
  static constexpr char kNetworkBgscanMethodLearn[] = "learn";
  // None is not a real method name, but we interpret 'none' as a request that
  // no background scan parameter should be supplied to wpa_supplicant.
  static constexpr char kNetworkBgscanMethodNone[] = "none";
  static constexpr char kNetworkBgscanMethodSimple[] = "simple";
  static constexpr char kNetworkCipherGroup[] = "group";
  static constexpr char kNetworkCipherPairwise[] = "pairwise";
  static constexpr char kNetworkCipherSuiteCCMP[] = "CCMP";
  static constexpr char kNetworkCipherSuiteTKIP[] = "TKIP";
  static constexpr char kNetworkModeInfrastructure[] = "infrastructure";
  static constexpr char kNetworkModeAdHoc[] = "ad-hoc";
  static constexpr char kNetworkModeAccessPoint[] = "ap";
  static constexpr char kNetworkModeMesh[] = "mesh";
  static constexpr char kNetworkModeP2P[] = "p2p";
  static constexpr char kNetworkPropertyBgscan[] = "bgscan";
  static constexpr char kNetworkPropertyBSSID[] = "bssid";
  static constexpr char kNetworkPropertyBSSIDAccept[] = "bssid_accept";
  static constexpr char kNetworkPropertyCaPath[] = "ca_path";
  static constexpr char kNetworkPropertyDisableVHT[] = "disable_vht";
  static constexpr char kNetworkPropertyEapIdentity[] = "identity";
  static constexpr char kNetworkPropertyEapKeyManagement[] = "key_mgmt";
  static constexpr char kNetworkPropertyEapEap[] = "eap";
  static constexpr char kNetworkPropertyEapOuterEap[] = "phase1";
  static constexpr char kNetworkPropertyEapInnerEap[] = "phase2";
  static constexpr char kNetworkPropertyEapAnonymousIdentity[] =
      "anonymous_identity";
  static constexpr char kNetworkPropertyEapProactiveKeyCaching[] =
      "proactive_key_caching";
  static constexpr char kNetworkPropertyEapCaCert[] = "ca_cert";
  static constexpr char kNetworkPropertyEapCaPassword[] = "password";
  static constexpr char kNetworkPropertyEapCertId[] = "cert_id";
  static constexpr char kNetworkPropertyEapKeyId[] = "key_id";
  static constexpr char kNetworkPropertyEapCaCertId[] = "ca_cert_id";
  static constexpr char kNetworkPropertyEapPin[] = "pin";
  static constexpr char kNetworkPropertyEapSubjectMatch[] = "subject_match";
  static constexpr char kNetworkPropertyEapSubjectAlternativeNameMatch[] =
      "altsubject_match";
  static constexpr char kNetworkPropertyEapDomainSuffixMatch[] =
      "domain_suffix_match";
  static constexpr char kNetworkPropertyEapolFlags[] = "eapol_flags";
  static constexpr char kNetworkPropertyEngine[] = "engine";
  static constexpr char kNetworkPropertyEngineId[] = "engine_id";
  static constexpr char kNetworkPropertyFrequency[] = "frequency";
  static constexpr char kNetworkPropertyIeee80211w[] = "ieee80211w";
  static constexpr char kNetworkPropertyMACAddrPolicy[] = "mac_addr";
  static constexpr char kNetworkPropertyMACAddrValue[] = "mac_value";
  static constexpr char kNetworkPropertyMode[] = "mode";
  static constexpr char kNetworkPropertyScanSSID[] = "scan_ssid";
  static constexpr char kNetworkPropertySSID[] = "ssid";
  static constexpr char kPropertyAuthAlg[] = "auth_alg";
  static constexpr char kPropertyPreSharedKey[] = "psk";
  static constexpr char kPropertyPrivacy[] = "Privacy";
  static constexpr char kPropertyRSN[] = "RSN";
  static constexpr char kPropertyScanAllowRoam[] = "AllowRoam";
  static constexpr char kPropertyScanSSIDs[] = "SSIDs";
  static constexpr char kPropertyScanType[] = "Type";
  static constexpr char kPropertySecurityProtocol[] = "proto";
  static constexpr char kPropertyWEPKey[] = "wep_key";
  static constexpr char kPropertyWEPTxKeyIndex[] = "wep_tx_keyidx";
  static constexpr char kPropertyWPA[] = "WPA";
  static constexpr char kScanTypeActive[] = "active";
  static constexpr char kSecurityAuthAlg[] = "OPEN SHARED";
  static constexpr char kSecurityMethodPropertyKeyManagement[] = "KeyMgmt";
  static constexpr char kSecurityModeRSN[] = "RSN";
  static constexpr char kSecurityModeWPA[] = "WPA";
  static constexpr char kStationPropertyAddress[] = "Address";
  static constexpr char kStationPropertyAID[] = "AID";

  static constexpr char kSignalChangeProperty[] = "SignalChange";
  static constexpr char kSignalChangePropertyRSSI[] = "rssi";
  static constexpr char kSignalChangePropertyNoise[] = "noise";
  static constexpr char kSignalChangePropertyChannelFrequency[] = "frequency";
  static constexpr char kSignalChangePropertyChannelWidth[] = "width";
  static constexpr char kSignalChangePropertyCenterFreq1[] = "center-frq1";
  static constexpr char kSignalChangePropertyCenterFreq2[] = "center-frq2";
  static constexpr char kSignalChangePropertyAverageRSSI[] = "avg-rssi";
  static constexpr char kSignalChangePropertyRxBytes[] = "rx-bytes";
  static constexpr char kSignalChangePropertyTxBytes[] = "tx-bytes";
  static constexpr char kSignalChangePropertyRxPackets[] = "rx-packets";
  static constexpr char kSignalChangePropertyTxPackets[] = "tx-packets";
  static constexpr char kSignalChangePropertyBeacons[] = "beacons";
  static constexpr char kSignalChangePropertyRxSpeed[] = "linkrxspeed";
  static constexpr char kSignalChangePropertyTxSpeed[] = "linktxspeed";
  static constexpr char kSignalChangePropertyRetries[] = "retries";
  static constexpr char kSignalChangePropertyRetriesFailed[] = "retries-failed";
  static constexpr char kSignalChangePropertyLastAckRSSI[] = "last-ack-rssi";
  static constexpr char kSignalChangePropertyFCSErrors[] = "fcs-errors";
  static constexpr char kSignalChangePropertyBeaconLosses[] = "beacon-losses";
  static constexpr char kSignalChangePropertyExpectedThroughput[] =
      "expected-throughput";
  static constexpr char kSignalChangePropertyRxDropMisc[] = "rx-drop-misc";
  static constexpr char kSignalChangePropertyRxMPDUS[] = "rx-mpdus";
  static constexpr char kSignalChangePropertyRxHEMCS[] = "rx-he-mcs";
  static constexpr char kSignalChangePropertyTxHEMCS[] = "tx-he-mcs";
  static constexpr char kSignalChangePropertyRxVHTMCS[] = "rx-vht-mcs";
  static constexpr char kSignalChangePropertyTxVHTMCS[] = "tx-vht-mcs";
  static constexpr char kSignalChangePropertyRxMCS[] = "rx-mcs";
  static constexpr char kSignalChangePropertyTxMCS[] = "tx-mcs";
  static constexpr char kSignalChangePropertyRxHENSS[] = "rx-he-nss";
  static constexpr char kSignalChangePropertyTxHENSS[] = "tx-he-nss";
  static constexpr char kSignalChangePropertyRxVHTNSS[] = "rx-vht-nss";
  static constexpr char kSignalChangePropertyTxVHTNSS[] = "tx-vht-nss";
  static constexpr char kSignalChangePropertyAverageBeaconRSSI[] =
      "avg-beacon-rssi";
  static constexpr char kSignalChangePropertyAverageAckRSSI[] = "avg-ack-rssi";
  static constexpr char kSignalChangePropertyInactiveTime[] = "inactive-time";
  static constexpr char kSignalChangePropertyRxGI[] = "rx-guard-interval";
  static constexpr char kSignalChangePropertyTxGI[] = "tx-guard-interval";
  static constexpr char kSignalChangePropertyRxDCM[] = "rx-dcm";
  static constexpr char kSignalChangePropertyTxDCM[] = "tx-dcm";

  static constexpr char kCredentialsPropertyDomain[] = "domain";
  static constexpr char kCredentialsPropertyPassword[] = "password";
  static constexpr char kCredentialsPropertyRealm[] = "realm";
  static constexpr char kCredentialsPropertyHomeOIs[] = "home_ois";
  static constexpr char kCredentialsPropertyRequiredHomeOIs[] =
      "required_home_ois";
  static constexpr char kCredentialsPropertyRoamingConsortiums[] =
      "roaming_consortiums";
  static constexpr char kCredentialsPropertyUsername[] = "username";
  static constexpr char kCredentialsMatchType[] = "type";
  static constexpr char kCredentialsMatchTypeHome[] = "home";
  static constexpr char kCredentialsMatchTypeRoaming[] = "roaming";
  static constexpr char kCredentialsMatchTypeUnknown[] = "unknown";

  static constexpr char kInterfaceCapabilityMaxScanSSID[] = "MaxScanSSID";

  static constexpr char kFlagDisableEapTLS1p1[] = "tls_disable_tlsv1_1=1";
  static constexpr char kFlagDisableEapTLS1p2[] = "tls_disable_tlsv1_2=1";
  static constexpr char kFlagInnerEapAuthMSCHAPV2[] = "auth=MSCHAPV2";
  static constexpr char kFlagInnerEapNoMSCHAPV2Retry[] = "mschapv2_retry=0";

  static constexpr uint32_t kDefaultEngine = 1;
  static constexpr uint32_t kNetworkIeee80211wDisabled = 0;
  static constexpr uint32_t kNetworkIeee80211wEnabled = 1;
  static constexpr uint32_t kNetworkIeee80211wRequired = 2;
  static constexpr uint32_t kNetworkModeInfrastructureInt = 0;
  static constexpr uint32_t kNetworkModeAdHocInt = 1;
  static constexpr uint32_t kNetworkModeAccessPointInt = 2;
  static constexpr uint32_t kDefaultMaxSSIDsPerScan = 4;
  // A maximum value to which MaxScanSSID capability should be clipped - the
  // value is aligned with limit in WPA Supplicant (see WPAS_MAX_SCAN_SSIDS
  // there).
  static constexpr uint32_t kMaxMaxSSIDsPerScan = 16;

  static constexpr uint32_t kProactiveKeyCachingDisabled = 0;
  static constexpr uint32_t kProactiveKeyCachingEnabled = 1;

  static constexpr char kSupplicantConfPath[] = SHIMDIR "/wpa_supplicant.conf";

  static constexpr int32_t kMACAddrPolicyHardware = 0;
  static constexpr int32_t kMACAddrPolicyFullRandom = 1;
  static constexpr int32_t kMACAddrPolicyOUIRandom = 2;
  static constexpr int32_t kMACAddrPolicyPersistentRandom = 3;

  static constexpr char kChannelWidth20MHznoHT[] = "20 MHz (no HT)";
  static constexpr char kChannelWidth20MHz[] = "20 MHz";
  static constexpr char kChannelWidth40MHz[] = "40 MHz";
  static constexpr char kChannelWidth80MHz[] = "80 MHz";
  static constexpr char kChannelWidth80p80MHz[] = "80+80 MHz";
  static constexpr char kChannelWidth160MHz[] = "160 MHz";

  static constexpr uint32_t kGuardInterval_0_4 = 1u;
  static constexpr uint32_t kGuardInterval_0_8 = 2u;
  static constexpr uint32_t kGuardInterval_1_6 = 3u;
  static constexpr uint32_t kGuardInterval_3_2 = 4u;

  // Retrieve the |subject| and |depth| of an a remote certifying entity,
  // as contained the the |properties| to a Certification event from
  // wpa_supplicant.  Returns true if an |subject| and |depth| were
  // extracted successfully, false otherwise.
  static bool ExtractRemoteCertification(const KeyValueStore& properties,
                                         std::string* subject,
                                         uint32_t* depth);
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_WPA_SUPPLICANT_H_
