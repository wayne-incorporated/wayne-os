// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/ikev2_driver.h"

#include <array>
#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <base/version.h>
#include <chromeos/dbus/shill/dbus-constants.h>

#include "shill/error.h"
#include "shill/ipconfig.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/vpn/ipsec_connection.h"
#include "shill/vpn/vpn_provider.h"
#include "shill/vpn/vpn_service.h"

namespace shill {

namespace {

constexpr base::TimeDelta kConnectTimeout = base::Seconds(30);

std::unique_ptr<IPsecConnection::Config> MakeIPsecConfig(
    const KeyValueStore& args, const EapCredentials& eap_credentials) {
  auto config = std::make_unique<IPsecConnection::Config>();

  config->ike_version = IPsecConnection::Config::IKEVersion::kV2;
  config->remote = args.Lookup<std::string>(kProviderHostProperty, "");
  config->local_id = args.GetOptionalValueWithoutEmpty<std::string>(
      kIKEv2LocalIdentityProperty);
  config->remote_id = args.GetOptionalValueWithoutEmpty<std::string>(
      kIKEv2RemoteIdentityProperty);
  config->ca_cert_pem_strings =
      args.GetOptionalValueWithoutEmpty<Strings>(kIKEv2CaCertPemProperty);

  const std::string auth_type =
      args.Lookup<std::string>(kIKEv2AuthenticationTypeProperty, "");
  if (auth_type == kIKEv2AuthenticationTypePSK) {
    config->psk =
        args.GetOptionalValueWithoutEmpty<std::string>(kIKEv2PskProperty);
    if (!config->psk.has_value()) {
      LOG(ERROR) << "Auth type is PSK but no PSK value found.";
      return nullptr;
    }
  } else if (auth_type == kIKEv2AuthenticationTypeCert) {
    config->client_cert_id = args.GetOptionalValueWithoutEmpty<std::string>(
        kIKEv2ClientCertIdProperty);
    config->client_cert_slot = args.GetOptionalValueWithoutEmpty<std::string>(
        kIKEv2ClientCertSlotProperty);
    if (!config->client_cert_id.has_value() ||
        !config->client_cert_slot.has_value()) {
      LOG(ERROR) << "Auth type is cert but empty cert id or slot found.";
      return nullptr;
    }
  } else if (auth_type == kIKEv2AuthenticationTypeEAP) {
    if (eap_credentials.method() != kEapMethodMSCHAPV2) {
      LOG(ERROR) << "Only MSCHAPv2 is supported for EAP in IKEv2 VPN.";
      return nullptr;
    }

    Error err;
    config->xauth_user = eap_credentials.identity();
    config->xauth_password = eap_credentials.GetEapPassword(&err);
    if (err.IsFailure()) {
      LOG(ERROR) << err;
      return nullptr;
    }
  } else {
    LOG(ERROR) << "Invalid auth type: " << auth_type;
    return nullptr;
  }

  return config;
}

void ReportConnectionEndReason(Metrics* metrics,
                               Service::ConnectFailure failure) {
  metrics->SendEnumToUMA(Metrics::kMetricVpnIkev2EndReason,
                         Metrics::ConnectFailureToServiceErrorEnum(failure));
}

}  // namespace

const VPNDriver::Property IKEv2Driver::kProperties[] = {
    {kIKEv2AuthenticationTypeProperty, 0},
    {kIKEv2CaCertPemProperty, Property::kArray},
    {kIKEv2ClientCertIdProperty, 0},
    {kIKEv2ClientCertSlotProperty, 0},
    {kIKEv2PskProperty, Property::kCredential | Property::kWriteOnly},
    {kIKEv2LocalIdentityProperty, Property::kCredential},
    {kIKEv2RemoteIdentityProperty, Property::kCredential},
    {kProviderHostProperty, 0},
    {kProviderTypeProperty, 0},
};

// static
bool IKEv2Driver::IsSupported() {
  // IKEv2 is currently supported on kernel version >= 4.19, due to the
  // availability of XFRM interface.
  return VPNUtil::CheckKernelVersion(base::Version("4.19"));
}

IKEv2Driver::IKEv2Driver(Manager* manager, ProcessManager* process_manager)
    : VPNDriver(manager,
                process_manager,
                VPNType::kIKEv2,
                kProperties,
                std::size(kProperties),
                /*use_eap=*/true) {}

IKEv2Driver::~IKEv2Driver() {}

base::TimeDelta IKEv2Driver::ConnectAsync(EventHandler* handler) {
  event_handler_ = handler;

  dispatcher()->PostTask(FROM_HERE,
                         base::BindOnce(&IKEv2Driver::StartIPsecConnection,
                                        weak_factory_.GetWeakPtr()));

  return kConnectTimeout;
}

void IKEv2Driver::StartIPsecConnection() {
  if (ipsec_connection_) {
    LOG(ERROR) << "The previous IPsecConnection is still running.";
    NotifyServiceOfFailure(Service::kFailureInternal);
    return;
  }

  auto callbacks = std::make_unique<IPsecConnection::Callbacks>(
      base::BindRepeating(&IKEv2Driver::OnIPsecConnected,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&IKEv2Driver::OnIPsecFailure, weak_factory_.GetWeakPtr()),
      base::BindOnce(&IKEv2Driver::OnIPsecStopped, weak_factory_.GetWeakPtr()));
  auto ipsec_config = MakeIPsecConfig(*const_args(), *eap_credentials());
  if (!ipsec_config) {
    LOG(ERROR) << "Failed to generate IPsec config";
    NotifyServiceOfFailure(Service::kFailureInternal);
    return;
  }

  ipsec_connection_ = CreateIPsecConnection(
      std::move(ipsec_config), std::move(callbacks), manager()->device_info(),
      manager()->dispatcher(), process_manager());

  ipsec_connection_->Connect();
}

std::unique_ptr<VPNConnection> IKEv2Driver::CreateIPsecConnection(
    std::unique_ptr<IPsecConnection::Config> config,
    std::unique_ptr<VPNConnection::Callbacks> callbacks,
    DeviceInfo* device_info,
    EventDispatcher* dispatcher,
    ProcessManager* process_manager) {
  return std::make_unique<IPsecConnection>(
      std::move(config), std::move(callbacks), /*l2tp_connection=*/nullptr,
      device_info, dispatcher, process_manager);
}

void IKEv2Driver::Disconnect() {
  event_handler_ = nullptr;
  ReportConnectionEndReason(metrics(), Service::kFailureDisconnect);
  if (!ipsec_connection_) {
    LOG(ERROR) << "Disconnect() called but IPsecConnection is not running";
    return;
  }
  if (!ipsec_connection_->IsConnectingOrConnected()) {
    LOG(ERROR) << "Disconnect() called but IPsecConnection is in "
               << ipsec_connection_->state() << " state";
    return;
  }
  ipsec_connection_->Disconnect();
}

std::unique_ptr<IPConfig::Properties> IKEv2Driver::GetIPv4Properties() const {
  if (ipv4_properties_ == nullptr) {
    return nullptr;
  }
  return std::make_unique<IPConfig::Properties>(*ipv4_properties_);
}

std::unique_ptr<IPConfig::Properties> IKEv2Driver::GetIPv6Properties() const {
  if (ipv6_properties_ == nullptr) {
    return nullptr;
  }
  return std::make_unique<IPConfig::Properties>(*ipv6_properties_);
}

void IKEv2Driver::OnConnectTimeout() {
  LOG(INFO) << "Connect timeout";
  if (!ipsec_connection_) {
    LOG(ERROR)
        << "OnConnectTimeout() called but IPsecConnection is not running";
    return;
  }
  if (!ipsec_connection_->IsConnectingOrConnected()) {
    LOG(ERROR) << "OnConnectTimeout() called but IPsecConnection is in "
               << ipsec_connection_->state() << " state";
    return;
  }
  ipsec_connection_->Disconnect();
  NotifyServiceOfFailure(Service::kFailureConnect);
}

// TODO(b/210064468): Check if charon can handle these events.
void IKEv2Driver::OnBeforeSuspend(ResultCallback callback) {
  if (ipsec_connection_ && ipsec_connection_->IsConnectingOrConnected()) {
    ipsec_connection_->Disconnect();
    NotifyServiceOfFailure(Service::kFailureDisconnect);
  }
  std::move(callback).Run(Error(Error::kSuccess));
}

// TODO(b/210064468): Check if charon can handle these events.
void IKEv2Driver::OnDefaultPhysicalServiceEvent(
    DefaultPhysicalServiceEvent event) {
  if (!ipsec_connection_ || !ipsec_connection_->IsConnectingOrConnected()) {
    return;
  }
  switch (event) {
    case kDefaultPhysicalServiceUp:
      return;
    case kDefaultPhysicalServiceDown:
      ipsec_connection_->Disconnect();
      NotifyServiceOfFailure(Service::kFailureDisconnect);
      return;
    case kDefaultPhysicalServiceChanged:
      ipsec_connection_->Disconnect();
      NotifyServiceOfFailure(Service::kFailureDisconnect);
      return;
    default:
      NOTREACHED();
  }
}

void IKEv2Driver::NotifyServiceOfFailure(Service::ConnectFailure failure) {
  LOG(ERROR) << "Driver failure due to "
             << Service::ConnectFailureToString(failure);
  if (event_handler_) {
    // Only reports metrics when |event_handler_| exists to ensure reporting
    // only once for each connection.
    ReportConnectionEndReason(metrics(), failure);
    event_handler_->OnDriverFailure(failure, Service::kErrorDetailsNone);
    event_handler_ = nullptr;
  }
}

void IKEv2Driver::OnIPsecConnected(
    const std::string& link_name,
    int interface_index,
    std::unique_ptr<IPConfig::Properties> ipv4_properties,
    std::unique_ptr<IPConfig::Properties> ipv6_properties) {
  if (!event_handler_) {
    LOG(ERROR) << "OnIPsecConnected() triggered in illegal service state";
    return;
  }
  ReportConnectionMetrics();
  ipv4_properties_ = std::move(ipv4_properties);
  ipv6_properties_ = std::move(ipv6_properties);
  event_handler_->OnDriverConnected(link_name, interface_index);
}

void IKEv2Driver::OnIPsecFailure(Service::ConnectFailure failure) {
  NotifyServiceOfFailure(failure);
}

void IKEv2Driver::OnIPsecStopped() {
  ipsec_connection_ = nullptr;
}

KeyValueStore IKEv2Driver::GetProvider(Error* error) {
  KeyValueStore props = VPNDriver::GetProvider(error);

  // If the corresponding credential field is empty for an authentication type,
  // set kPassphraseRequiredProperty field to true.
  bool passphrase_required = false;
  const std::string auth_type =
      const_args()->Lookup<std::string>(kIKEv2AuthenticationTypeProperty, "");
  if (auth_type == kIKEv2AuthenticationTypePSK) {
    const std::string psk =
        const_args()->Lookup<std::string>(kIKEv2PskProperty, "");
    passphrase_required = psk.empty();
  } else if (auth_type == kIKEv2AuthenticationTypeEAP) {
    passphrase_required = !eap_credentials()->IsConnectableUsingPassphrase();
  }
  props.Set<bool>(kPassphraseRequiredProperty, passphrase_required);

  return props;
}

void IKEv2Driver::ReportConnectionMetrics() {
  metrics()->SendEnumToUMA(Metrics::kMetricVpnDriver, Metrics::kVpnDriverIKEv2);

  Metrics::VpnIpsecAuthenticationType auth_type_metrics =
      Metrics::kVpnIpsecAuthenticationTypeUnknown;
  const std::string auth_type_str =
      const_args()->Lookup<std::string>(kIKEv2AuthenticationTypeProperty, "");
  if (auth_type_str == kIKEv2AuthenticationTypePSK) {
    auth_type_metrics = Metrics::kVpnIpsecAuthenticationTypePsk;
  } else if (auth_type_str == kIKEv2AuthenticationTypeEAP) {
    auth_type_metrics = Metrics::kVpnIpsecAuthenticationTypeEap;
  } else if (auth_type_str == kIKEv2AuthenticationTypeCert) {
    auth_type_metrics = Metrics::kVpnIpsecAuthenticationTypeCertificate;
  } else {
    // We have checked the auth type before connection, but it is still possible
    // to reach here if the properties are changed right before the connection
    // is established. Still reports this case to keep the numbers consistent.
    LOG(ERROR) << "Unexpected auth type: " << auth_type_str;
  }
  metrics()->SendEnumToUMA(Metrics::kMetricVpnIkev2AuthenticationType,
                           auth_type_metrics);

  // To access the methods only defined in the inherited class. The cast will
  // only fail in unit tests.
  const auto* conn = dynamic_cast<IPsecConnection*>(ipsec_connection_.get());
  if (conn) {
    // Cipher suite for IKE.
    metrics()->SendEnumToUMA(Metrics::kMetricVpnIkeEncryptionAlgorithm,
                             VPNType::kIKEv2, conn->ike_encryption_algo());
    metrics()->SendEnumToUMA(Metrics::kMetricVpnIkeIntegrityAlgorithm,
                             VPNType::kIKEv2, conn->ike_integrity_algo());
    metrics()->SendEnumToUMA(Metrics::kMetricVpnIkeDHGroup, VPNType::kIKEv2,
                             conn->ike_dh_group());

    // Cipher suite for ESP.
    metrics()->SendEnumToUMA(Metrics::kMetricVpnEspEncryptionAlgorithm,
                             VPNType::kIKEv2, conn->esp_encryption_algo());
    metrics()->SendEnumToUMA(Metrics::kMetricVpnEspIntegrityAlgorithm,
                             VPNType::kIKEv2, conn->esp_integrity_algo());
  }
}

}  // namespace shill
