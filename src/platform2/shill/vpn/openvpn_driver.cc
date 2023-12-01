// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/openvpn_driver.h"

#include <arpa/inet.h>

#include <iterator>
#include <limits>
#include <utility>

#include <base/check.h>
#include <base/containers/fixed_flat_map.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/certificate_file.h"
#include "shill/device_info.h"
#include "shill/error.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/net/process_manager.h"
#include "shill/net/sockets.h"
#include "shill/rpc_task.h"
#include "shill/virtual_device.h"
#include "shill/vpn/openvpn_management_server.h"
#include "shill/vpn/vpn_provider.h"
#include "shill/vpn/vpn_service.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kVPN;
}  // namespace Logging

namespace {

constexpr char kChromeOSReleaseName[] = "CHROMEOS_RELEASE_NAME";
constexpr char kChromeOSReleaseVersion[] = "CHROMEOS_RELEASE_VERSION";
constexpr char kOpenVPNForeignOptionPrefix[] = "foreign_option_";
constexpr char kOpenVPNIfconfigLocal[] = "ifconfig_local";
constexpr char kOpenVPNIfconfigNetmask[] = "ifconfig_netmask";
constexpr char kOpenVPNIfconfigRemote[] = "ifconfig_remote";
constexpr char kOpenVPNIfconfigIPv6Local[] = "ifconfig_ipv6_local";
constexpr char kOpenVPNIfconfigIPv6Netbits[] = "ifconfig_ipv6_netbits";
constexpr char kOpenVPNRedirectGateway[] = "redirect_gateway";
constexpr char kOpenVPNRouteOptionPrefix[] = "route_";
constexpr char kOpenVPNRouteNetGateway[] = "route_net_gateway";
constexpr char kOpenVPNRouteVPNGateway[] = "route_vpn_gateway";
constexpr char kOpenVPNTunMTU[] = "tun_mtu";

// Typically OpenVPN will set environment variables for IPv4 like:
//   route_net_gateway=<existing default LAN gateway>
//   route_vpn_gateway=10.8.0.1
//   route_gateway_1=10.8.0.1
//   route_netmask_1=255.255.255.0
//   route_network_1=192.168.10.0
// This example shows a split include route of 192.168.10.0/24, and
// 10.8.0.1 is the ifconfig_remote (remote peer) address.
//
// For IPv6, they will be like:
//   ifconfig_ipv6_local: fdfd::1000
//   ifconfig_ipv6_netbits: 64
//   ifconfig_ipv6_remote: fdfd::1
//   route_ipv6_gateway_1: fdfd::1
//   route_ipv6_network_1: ::/3
// Different from IPv4, for a route entry, there are only two variables for it
// in IPv6, and the network variable will be a prefix string.

constexpr char kOpenVPNRouteNetworkPrefix[] = "network_";
constexpr char kOpenVPNRouteNetmaskPrefix[] = "netmask_";
constexpr char kOpenVPNRouteGatewayPrefix[] = "gateway_";
constexpr char kOpenVPNRouteIPv6NetworkPrefix[] = "ipv6_network_";
constexpr char kOpenVPNRouteIPv6GatewayPrefix[] = "ipv6_gateway_";

constexpr char kDefaultPKCS11Provider[] = "libchaps.so";

// Some configurations pass the netmask in the ifconfig_remote property.
// This is due to some servers not explicitly indicating that they are using
// a "broadcast mode" network instead of peer-to-peer.  See
// http://crbug.com/241264 for an example of this issue.
constexpr char kSuspectedNetmaskPrefix[] = "255.";

constexpr char kOpenVPNPath[] = "/usr/sbin/openvpn";
constexpr char kOpenVPNScript[] = SHIMDIR "/openvpn-script";

// Directory where OpenVPN configuration files are exported while the
// process is running.
constexpr char kDefaultOpenVPNConfigurationDirectory[] =
    RUNDIR "/openvpn_config";

}  // namespace

// static
const VPNDriver::Property OpenVPNDriver::kProperties[] = {
    {kOpenVPNAuthNoCacheProperty, 0},
    {kOpenVPNAuthProperty, 0},
    {kOpenVPNAuthRetryProperty, 0},
    {kOpenVPNAuthUserPassProperty, 0},
    {kOpenVPNCipherProperty, 0},
    {kOpenVPNClientCertIdProperty, Property::kCredential},
    {kOpenVPNCompLZOProperty, 0},
    {kOpenVPNCompNoAdaptProperty, 0},
    {kOpenVPNCompressProperty, 0},
    {kOpenVPNExtraHostsProperty, Property::kArray},
    {kOpenVPNIgnoreDefaultRouteProperty, 0},
    {kOpenVPNKeyDirectionProperty, 0},
    {kOpenVPNNsCertTypeProperty, 0},
    {kOpenVPNOTPProperty,
     Property::kEphemeral | Property::kCredential | Property::kWriteOnly},
    {kOpenVPNPasswordProperty, Property::kCredential | Property::kWriteOnly},
    {kOpenVPNPinProperty, Property::kCredential},
    {kOpenVPNPortProperty, 0},
    {kOpenVPNProtoProperty, 0},
    {kOpenVPNPushPeerInfoProperty, 0},
    {kOpenVPNRemoteCertEKUProperty, 0},
    {kOpenVPNRemoteCertKUProperty, 0},
    {kOpenVPNRemoteCertTLSProperty, 0},
    {kOpenVPNRenegSecProperty, 0},
    {kOpenVPNServerPollTimeoutProperty, 0},
    {kOpenVPNShaperProperty, 0},
    {kOpenVPNStaticChallengeProperty, 0},
    {kOpenVPNTLSAuthContentsProperty, 0},
    {kOpenVPNTLSRemoteProperty, 0},
    {kOpenVPNTLSVersionMinProperty, 0},
    {kOpenVPNTokenProperty,
     Property::kEphemeral | Property::kCredential | Property::kWriteOnly},
    {kOpenVPNUserProperty, 0},
    {kProviderHostProperty, 0},
    {kProviderTypeProperty, 0},
    {kOpenVPNCaCertPemProperty, Property::kArray},
    {kOpenVPNExtraCertPemProperty, Property::kArray},
    {kOpenVPNPingExitProperty, 0},
    {kOpenVPNPingProperty, 0},
    {kOpenVPNPingRestartProperty, 0},
    {kOpenVPNTLSAuthProperty, 0},
    {kOpenVPNVerbProperty, 0},
    {kOpenVPNVerifyHashProperty, 0},
    {kOpenVPNVerifyX509NameProperty, 0},
    {kOpenVPNVerifyX509TypeProperty, 0},
    {kVPNMTUProperty, 0},
};

OpenVPNDriver::OpenVPNDriver(Manager* manager, ProcessManager* process_manager)
    : VPNDriver(manager,
                process_manager,
                VPNType::kOpenVPN,
                kProperties,
                std::size(kProperties)),
      management_server_(new OpenVPNManagementServer(this)),
      certificate_file_(new CertificateFile()),
      extra_certificates_file_(new CertificateFile()),
      lsb_release_file_(kLSBReleaseFile),
      openvpn_config_directory_(kDefaultOpenVPNConfigurationDirectory),
      pid_(0),
      vpn_util_(VPNUtil::New()) {}

OpenVPNDriver::~OpenVPNDriver() {
  Cleanup();
}

void OpenVPNDriver::FailService(Service::ConnectFailure failure,
                                base::StringPiece error_details) {
  SLOG(2) << __func__ << "(" << error_details << ")";
  Cleanup();
  if (event_handler_) {
    event_handler_->OnDriverFailure(failure, error_details);
    event_handler_ = nullptr;
  }
}

void OpenVPNDriver::Cleanup() {
  // Disconnecting the management interface will terminate the openvpn
  // process. Ensure this is handled robustly by first unregistering
  // the callback for OnOpenVPNDied, and then terminating and reaping
  // the process with StopProcess().
  if (pid_) {
    process_manager()->UpdateExitCallback(pid_, base::DoNothing());
  }
  management_server_->Stop();
  if (!tls_auth_file_.empty()) {
    base::DeleteFile(tls_auth_file_);
    tls_auth_file_.clear();
  }
  if (!openvpn_config_file_.empty()) {
    base::DeleteFile(openvpn_config_file_);
    openvpn_config_file_.clear();
  }
  rpc_task_.reset();
  params_.clear();
  ipv4_properties_ = nullptr;
  ipv6_properties_ = nullptr;
  if (pid_) {
    process_manager()->StopProcessAndBlock(pid_);
    pid_ = 0;
  }

  if (!interface_name_.empty()) {
    manager()->device_info()->DeleteInterface(interface_index_);
    interface_name_.clear();
    interface_index_ = -1;
  }
}

// static
std::string OpenVPNDriver::JoinOptions(
    const std::vector<std::vector<std::string>>& options, char separator) {
  std::vector<std::string> option_strings;
  for (const auto& option : options) {
    std::vector<std::string> quoted_option;
    for (const auto& argument : option) {
      if (argument.find(' ') != std::string::npos ||
          argument.find('\t') != std::string::npos ||
          argument.find('"') != std::string::npos ||
          argument.find(separator) != std::string::npos) {
        std::string quoted_argument(argument);
        const char separator_chars[] = {separator, '\0'};
        base::ReplaceChars(argument, separator_chars, " ", &quoted_argument);
        base::ReplaceChars(quoted_argument, "\\", "\\\\", &quoted_argument);
        base::ReplaceChars(quoted_argument, "\"", "\\\"", &quoted_argument);
        quoted_option.push_back("\"" + quoted_argument + "\"");
      } else {
        quoted_option.push_back(argument);
      }
    }
    option_strings.push_back(base::JoinString(quoted_option, " "));
  }
  return base::JoinString(option_strings, std::string{separator});
}

bool OpenVPNDriver::WriteConfigFile(
    const std::vector<std::vector<std::string>>& options,
    base::FilePath* config_file) {
  if (!vpn_util_->PrepareConfigDirectory(openvpn_config_directory_)) {
    LOG(ERROR) << "Unable to setup OpenVPN config directory.";
    return false;
  }

  std::string contents = JoinOptions(options, '\n');
  contents.push_back('\n');
  if (!base::CreateTemporaryFileInDir(openvpn_config_directory_, config_file) ||
      !vpn_util_->WriteConfigFile(*config_file, contents)) {
    LOG(ERROR) << "Unable to setup OpenVPN config file.";
    return false;
  }

  return true;
}

bool OpenVPNDriver::SpawnOpenVPN() {
  SLOG(2) << __func__ << "(" << interface_name_ << ")";

  std::vector<std::vector<std::string>> options;
  Error error;
  pid_t openvpn_pid;
  InitOptions(&options, &error);
  if (error.IsFailure()) {
    return false;
  }
  LOG(INFO) << "OpenVPN process options: " << JoinOptions(options, ',');
  if (!WriteConfigFile(options, &openvpn_config_file_)) {
    return false;
  }

  // TODO(quiche): This should be migrated to use ExternalTask.
  // (crbug.com/246263).
  CHECK(!pid_);

  const std::vector<std::string> args = GetCommandLineArgs();
  LOG(INFO) << "OpenVPN command line args: " << base::JoinString(args, " ");

  // OpenSSL compatibility settings.
  // TODO(crbug.com/1047146): Drop these stop-gaps after addressing the
  // underlying problems described in the bug.
  const std::map<std::string, std::string> kEnv = {
      {"OPENSSL_CONF", "/etc/ssl/openssl.cnf.compat"},
      {"OPENSSL_CHROMIUM_SKIP_TRUSTED_PURPOSE_CHECK", "1"},
      {"OPENSSL_CHROMIUM_GENERATE_METRICS", "1"},
  };

  ProcessManager::MinijailOptions minijail_options;
  minijail_options.user = "vpn";
  minijail_options.group = "vpn";
  minijail_options.capmask = 0;
  minijail_options.inherit_supplementary_groups = true;
  openvpn_pid = process_manager()->StartProcessInMinijail(
      FROM_HERE, base::FilePath(kOpenVPNPath), args, kEnv, minijail_options,
      base::BindOnce(&OpenVPNDriver::OnOpenVPNDied, base::Unretained(this)));
  if (openvpn_pid == -1) {
    LOG(ERROR) << "Minijail couldn't run our child process";
    return false;
  }

  pid_ = openvpn_pid;
  return true;
}

void OpenVPNDriver::OnOpenVPNDied(int exit_status) {
  SLOG(2) << __func__ << "(" << pid_ << ", " << exit_status << ")";
  pid_ = 0;
  FailService(Service::kFailureInternal, Service::kErrorDetailsNone);
  // TODO(petkov): Figure if we need to restart the connection.
}

void OpenVPNDriver::GetLogin(std::string* /*user*/, std::string* /*password*/) {
  NOTREACHED();
}

void OpenVPNDriver::Notify(const std::string& reason,
                           const std::map<std::string, std::string>& dict) {
  LOG(INFO) << "IP configuration received: " << reason;
  // We only registered "--up" script so this should be the only
  // reason we get notified here. Note that "--up-restart" is set
  // so we will get notification also upon reconnection.
  if (reason != "up") {
    LOG(DFATAL) << "Unexpected notification reason";
    return;
  }
  // On restart/reconnect, update the existing dict, and generate IP
  // configurations from it.
  for (const auto& [k, v] : dict) {
    params_[k] = v;
  }
  auto props = ParseIPConfiguration(
      params_,
      const_args()->Contains<std::string>(kOpenVPNIgnoreDefaultRouteProperty));
  ipv4_properties_ = std::move(props.ipv4_props);
  ipv6_properties_ = std::move(props.ipv6_props);
  if (!ipv4_properties_ && !ipv6_properties_) {
    FailService(Service::kFailureConnect, "No valid IP config");
    return;
  }
  ReportConnectionMetrics();
  if (event_handler_) {
    event_handler_->OnDriverConnected(interface_name_, interface_index_);
  } else {
    LOG(DFATAL) << "Missing service callback";
  }
}

std::unique_ptr<IPConfig::Properties> OpenVPNDriver::GetIPv4Properties() const {
  if (ipv4_properties_ == nullptr) {
    return nullptr;
  }
  return std::make_unique<IPConfig::Properties>(*ipv4_properties_);
}

std::unique_ptr<IPConfig::Properties> OpenVPNDriver::GetIPv6Properties() const {
  if (ipv6_properties_ == nullptr) {
    return nullptr;
  }
  return std::make_unique<IPConfig::Properties>(*ipv6_properties_);
}

// static
std::unique_ptr<IPConfig::Properties> OpenVPNDriver::CreateIPProperties(
    IPAddress::Family family,
    const std::string& local,
    const std::string& peer,
    int prefix,
    bool default_route,
    const RouteOptions& routes) {
  const int max_prefix = IPAddress::GetMaxPrefixLength(family);
  auto properties = std::make_unique<IPConfig::Properties>();
  properties->method = kTypeVPN;
  properties->address_family = family;
  properties->address = local;
  if (prefix == 0) {
    properties->subnet_prefix = max_prefix;
  } else {
    properties->subnet_prefix = prefix;
  }
  // L3 VPN doesn't need gateway. Set it to default to skip RTA_GATEWAY when
  // installing routes.
  if (family == IPAddress::kFamilyIPv4) {
    properties->gateway = "0.0.0.0";
  } else if (family == IPAddress::kFamilyIPv6) {
    properties->gateway = "::";
  }

  properties->default_route = default_route;
  if (!peer.empty()) {
    // --topology net30 or p2p will set ifconfig_remote

    // Setting a point-to-point address in the kernel will create a route
    // in RT_TABLE_MAIN instead of our per-device table.  To avoid this,
    // create an explicit host route here, and clear
    // |properties->peer_address.|
    properties->inclusion_list.push_back(
        base::StringPrintf("%s/%d", peer.c_str(), max_prefix));
  } else if (properties->subnet_prefix != max_prefix) {
    // --topology subnet will set ifconfig_netmask instead
    const auto network_addr = IPAddress::CreateFromStringAndPrefix(
        properties->address, properties->subnet_prefix,
        properties->address_family);
    if (!network_addr.has_value()) {
      LOG(WARNING) << "Error obtaining network address for "
                   << properties->address;
    } else {
      const std::string prefix = base::StringPrintf(
          "%s/%d", network_addr->GetNetworkPart().ToString().c_str(),
          properties->subnet_prefix);
      properties->inclusion_list.push_back(prefix);
    }
  }

  // Ignore |route.gateway|.  If it's wrong, it can cause the kernel to
  // refuse to add the route.  If it's correct, it has no effect anyway.
  for (const auto& route_map : routes) {
    const IPConfig::Route& route = route_map.second;
    if (route.host.empty() || route.gateway.empty()) {
      LOG(WARNING) << "Ignoring incomplete route: " << route_map.first;
      continue;
    }
    properties->inclusion_list.push_back(
        base::StringPrintf("%s/%d", route.host.c_str(), route.prefix));
  }

  if (properties->inclusion_list.empty() && properties->default_route) {
    LOG(WARNING) << "No routes provided for " << family;
  }

  return properties;
}

// static
OpenVPNDriver::IPProperties OpenVPNDriver::ParseIPConfiguration(
    const std::map<std::string, std::string>& configuration,
    bool ignore_redirect_gateway) {
  // Values parsed from |configuration|.
  ForeignOptions foreign_options;
  int mtu = 0;
  std::string ipv4_local;
  std::string ipv4_peer;
  int ipv4_prefix = 0;
  bool ipv4_redirect_gateway = false;
  RouteOptions ipv4_routes;
  std::string ipv6_local;
  int ipv6_prefix = 0;
  RouteOptions ipv6_routes;

  for (const auto& configuration_map : configuration) {
    const std::string& key = configuration_map.first;
    const std::string& value = configuration_map.second;
    SLOG(2) << "Processing: " << key << " -> " << value;
    if (base::EqualsCaseInsensitiveASCII(key, kOpenVPNIfconfigLocal)) {
      ipv4_local = value;
    } else if (base::EqualsCaseInsensitiveASCII(key, kOpenVPNIfconfigNetmask)) {
      ipv4_prefix =
          IPAddress::GetPrefixLengthFromMask(IPAddress::kFamilyIPv4, value);
    } else if (base::EqualsCaseInsensitiveASCII(key, kOpenVPNIfconfigRemote)) {
      if (base::StartsWith(value, kSuspectedNetmaskPrefix,
                           base::CompareCase::INSENSITIVE_ASCII)) {
        LOG(WARNING) << "Option " << key << " value " << value
                     << " looks more like a netmask than a peer address; "
                     << "assuming it is the former.";
        // In this situation, the "peer_address" value will be left
        // unset and Connection::UpdateFromIPConfig() will treat the
        // interface as if it were a broadcast-style network.  The
        // kernel will, automatically set the peer address equal to
        // the local address.
        ipv4_prefix =
            IPAddress::GetPrefixLengthFromMask(IPAddress::kFamilyIPv4, value);
      } else {
        ipv4_peer = value;
      }
    } else if (base::EqualsCaseInsensitiveASCII(key, kOpenVPNRedirectGateway)) {
      if (ignore_redirect_gateway) {
        LOG(INFO) << "Ignoring default route parameter as requested by "
                  << "configuration.";
      } else {
        ipv4_redirect_gateway = true;
      }
    } else if (base::EqualsCaseInsensitiveASCII(key,
                                                kOpenVPNIfconfigIPv6Local)) {
      ipv6_local = value;
    } else if (base::EqualsCaseInsensitiveASCII(key,
                                                kOpenVPNIfconfigIPv6Netbits)) {
      if (!base::StringToInt(value, &ipv6_prefix)) {
        LOG(ERROR) << "IPv6 netbits ignored, value=" << value;
      }
    } else if (base::EqualsCaseInsensitiveASCII(key, kOpenVPNTunMTU)) {
      if (!base::StringToInt(value, &mtu)) {
        LOG(ERROR) << "Failed to parse MTU " << value;
      }
    } else if (base::StartsWith(key, kOpenVPNForeignOptionPrefix,
                                base::CompareCase::INSENSITIVE_ASCII)) {
      const auto suffix = key.substr(strlen(kOpenVPNForeignOptionPrefix));
      int order = 0;
      if (base::StringToInt(suffix, &order)) {
        foreign_options[order] = value;
      } else {
        LOG(ERROR) << "Ignored unexpected foreign option suffix: " << suffix;
      }
    } else if (base::EqualsCaseInsensitiveASCII(key, kOpenVPNRouteNetGateway) ||
               base::EqualsCaseInsensitiveASCII(key, kOpenVPNRouteVPNGateway)) {
      // These options are unused.  Catch them here so that they don't
      // get passed to ParseRouteOption().
    } else if (base::StartsWith(key, kOpenVPNRouteOptionPrefix,
                                base::CompareCase::INSENSITIVE_ASCII)) {
      const std::string trimmed_key =
          key.substr(strlen(kOpenVPNRouteOptionPrefix));
      if (!ParseIPv4RouteOption(trimmed_key, value, &ipv4_routes) &&
          !ParseIPv6RouteOption(trimmed_key, value, &ipv6_routes)) {
        LOG(WARNING) << "Route option ignored: " << key;
      }
    } else {
      SLOG(2) << "Key ignored.";
    }
  }

  std::vector<std::string> search_domains;
  std::vector<std::string> dns_servers;
  if (!foreign_options.empty()) {
    ParseForeignOptions(foreign_options, &search_domains, &dns_servers);
  } else {
    LOG(INFO) << "No foreign option provided";
  }

  const bool has_ipv4 = !ipv4_local.empty();
  const bool has_ipv6 = !ipv6_local.empty();
  if (mtu != 0) {
    const int min_mtu =
        has_ipv6 ? IPConfig::kMinIPv6MTU : IPConfig::kMinIPv4MTU;
    if (mtu < min_mtu) {
      LOG(ERROR) << "MTU value " << mtu << " ignored";
      mtu = 0;
    }
  }

  // Notes on `redirect-gateway`:
  //
  // In openvpn configuration, the user can add a `ipv6` flag to the
  // `redirect-gateway` option to indicate a default route for IPv6, but in the
  // context of environment variables passed from openvpn, `redirect-gateway` is
  // an IPv4-only option: for IPv6, openvpn client will translate it into routes
  // and set them in the variables. So at the server side, suppose there is no
  // route configured directly, there are 4 cases:
  // - No `redirect-gateway`: indicates no default route for both v4 and v6;
  //   openvpn client will set neither `redirect-gateway` nor routes in env
  //   variables.
  // - `redirect-gateway (def1)?`: indicates IPv4-only default route; openvpn
  //   client will set only `redirect-gateway` but no route in env variables.
  // - `redirect-gateway ipv6 !ipv4`: indicates IPv6-only default route; openvpn
  //   client will set only routes (for IPv6) but no `redirect-gateway` in env
  //   variables.
  // - `redirect-gateway ipv6`: indicates default route for both v4 and v6;
  //   openvpn client will set both `redirect-gateway` and routes (for IPv6) in
  //   env variables.
  std::unique_ptr<IPConfig::Properties> ipv4_props, ipv6_props;
  if (has_ipv4) {
    ipv4_props =
        CreateIPProperties(IPAddress::kFamilyIPv4, ipv4_local, ipv4_peer,
                           ipv4_prefix, ipv4_redirect_gateway, ipv4_routes);
    ipv4_props->blackhole_ipv6 = ipv4_redirect_gateway && !has_ipv6;
    ipv4_props->domain_search = search_domains;
    // For DNS servers, ideally we want put v4 servers here and v6 servers below
    // given the current IPConfig structure. Having a merged list in both
    // objects should have no real impact, and this issue will be resolved by
    // the latter IPConfig refactor.
    ipv4_props->dns_servers = dns_servers;
    ipv4_props->mtu = mtu;
  }
  if (has_ipv6) {
    ipv6_props =
        CreateIPProperties(IPAddress::kFamilyIPv6, ipv6_local, /*peer=*/"",
                           ipv6_prefix, /*default_route=*/false, ipv6_routes);
    // We probably want a blackhole_ipv4 here, but that cannot be done easily at
    // the routing layer now, and IPv6-only OpenVPN should be rare.
    ipv6_props->domain_search = search_domains;
    ipv6_props->dns_servers = dns_servers;
    ipv6_props->mtu = mtu;
  }
  return {
      .ipv4_props = std::move(ipv4_props),
      .ipv6_props = std::move(ipv6_props),
  };
}

namespace {
bool ParseForeignOption(const std::string& option,
                        std::vector<std::string>* domain_search,
                        std::vector<std::string>* dns_servers) {
  SLOG(2) << __func__ << "(" << option << ")";
  const auto tokens = base::SplitString(option, " ", base::TRIM_WHITESPACE,
                                        base::SPLIT_WANT_ALL);
  if (tokens.size() != 3 ||
      !base::EqualsCaseInsensitiveASCII(tokens[0], "dhcp-option")) {
    return false;
  }
  if (base::EqualsCaseInsensitiveASCII(tokens[1], "domain")) {
    domain_search->push_back(tokens[2]);
    return true;
  } else if (base::EqualsCaseInsensitiveASCII(tokens[1], "dns")) {
    dns_servers->push_back(tokens[2]);
    return true;
  }
  return false;
}
}  // namespace

// static
void OpenVPNDriver::ParseForeignOptions(const ForeignOptions& options,
                                        std::vector<std::string>* domain_search,
                                        std::vector<std::string>* dns_servers) {
  domain_search->clear();
  dns_servers->clear();
  for (const auto& option_map : options) {
    if (!ParseForeignOption(option_map.second, domain_search, dns_servers)) {
      LOG(INFO) << "Ignore foreign option " << option_map.second;
    }
  }
}

// static
IPConfig::Route* OpenVPNDriver::GetRouteOptionEntry(const std::string& prefix,
                                                    const std::string& key,
                                                    RouteOptions* routes) {
  int order = 0;
  if (!base::StartsWith(key, prefix, base::CompareCase::INSENSITIVE_ASCII) ||
      !base::StringToInt(key.substr(prefix.size()), &order)) {
    return nullptr;
  }
  return &(*routes)[order];
}

// static
bool OpenVPNDriver::ParseIPv4RouteOption(const std::string& key,
                                         const std::string& value,
                                         RouteOptions* routes) {
  // IPv4 uses route_{network,netmask,gateway}_<index>
  IPConfig::Route* route =
      GetRouteOptionEntry(kOpenVPNRouteNetworkPrefix, key, routes);
  if (route) {
    route->host = value;
    return true;
  }
  route = GetRouteOptionEntry(kOpenVPNRouteNetmaskPrefix, key, routes);
  if (route) {
    route->prefix =
        IPAddress::GetPrefixLengthFromMask(IPAddress::kFamilyIPv4, value);
    return true;
  }
  route = GetRouteOptionEntry(kOpenVPNRouteGatewayPrefix, key, routes);
  if (route) {
    route->gateway = value;
    return true;
  }
  return false;
}

// static
bool OpenVPNDriver::ParseIPv6RouteOption(const std::string& key,
                                         const std::string& value,
                                         RouteOptions* routes) {
  // IPv6 uses route_ipv6_{network,gateway}_<index>
  IPConfig::Route* route =
      GetRouteOptionEntry(kOpenVPNRouteIPv6NetworkPrefix, key, routes);
  if (route) {
    auto addr = IPAddress::CreateFromPrefixString(value);
    if (!addr.has_value()) {
      return false;
    }
    route->host = addr->ToString();
    route->prefix = addr->prefix();
    return true;
  }
  route = GetRouteOptionEntry(kOpenVPNRouteIPv6GatewayPrefix, key, routes);
  if (route) {
    route->gateway = value;
    return true;
  }
  return false;
}

// static
bool OpenVPNDriver::SplitPortFromHost(base::StringPiece host,
                                      std::string* name,
                                      std::string* port) {
  const auto tokens =
      base::SplitString(host, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  int port_number = 0;
  if (tokens.size() != 2 || tokens[0].empty() || tokens[1].empty() ||
      !base::IsAsciiDigit(tokens[1][0]) ||
      !base::StringToInt(tokens[1], &port_number) ||
      port_number > std::numeric_limits<uint16_t>::max()) {
    return false;
  }
  *name = tokens[0];
  *port = tokens[1];
  return true;
}

base::TimeDelta OpenVPNDriver::ConnectAsync(EventHandler* handler) {
  event_handler_ = handler;
  if (!manager()->device_info()->CreateTunnelInterface(base::BindOnce(
          &OpenVPNDriver::OnLinkReady, weak_factory_.GetWeakPtr()))) {
    dispatcher()->PostTask(
        FROM_HERE,
        base::BindOnce(&OpenVPNDriver::FailService, weak_factory_.GetWeakPtr(),
                       Service::kFailureInternal,
                       "Could not create tunnel interface."));
    return kTimeoutNone;
  }
  return kConnectTimeout;
}

void OpenVPNDriver::OnLinkReady(const std::string& link_name,
                                int interface_index) {
  if (!event_handler_) {
    LOG(ERROR) << "event_handler_ is not set";
    return;
  }
  interface_name_ = link_name;
  interface_index_ = interface_index;
  rpc_task_.reset(new RpcTask(control_interface(), this));
  if (!SpawnOpenVPN()) {
    FailService(Service::kFailureInternal, Service::kErrorDetailsNone);
  }
}

void OpenVPNDriver::InitOptions(std::vector<std::vector<std::string>>* options,
                                Error* error) {
  const auto vpnhost = args()->Lookup<std::string>(kProviderHostProperty, "");
  if (vpnhost.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "VPN host not specified.");
    return;
  }
  AppendOption("client", options);
  AppendOption("tls-client", options);

  AppendRemoteOption(vpnhost, options);
  if (args()->Contains<std::vector<std::string>>(kOpenVPNExtraHostsProperty)) {
    for (const auto& host :
         args()->Get<std::vector<std::string>>(kOpenVPNExtraHostsProperty)) {
      AppendRemoteOption(host, options);
    }
  }
  AppendOption("mark", "1280",
               options);  // 0x500: source type = 5 (Built-in VPN)
  AppendOption("nobind", options);
  AppendOption("persist-key", options);
  AppendOption("persist-tun", options);

  if (interface_name_.empty()) {
    LOG(DFATAL) << "Tunnel interface name needs to be set before connecting.";
    Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                          "Invalid tunnel interface");
    return;
  }
  AppendOption("dev", interface_name_, options);
  AppendOption("dev-type", "tun", options);

  InitLoggingOptions(options);

  AppendValueOption(kVPNMTUProperty, "mtu", options);
  AppendValueOption(kOpenVPNProtoProperty, "proto", options);
  AppendValueOption(kOpenVPNPortProperty, "port", options);
  AppendValueOption(kOpenVPNTLSAuthProperty, "tls-auth", options);
  {
    const auto contents =
        args()->Lookup<std::string>(kOpenVPNTLSAuthContentsProperty, "");
    if (!contents.empty()) {
      if (!vpn_util_->PrepareConfigDirectory(openvpn_config_directory_) ||
          !base::CreateTemporaryFileInDir(openvpn_config_directory_,
                                          &tls_auth_file_) ||
          !vpn_util_->WriteConfigFile(tls_auth_file_, contents)) {
        Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                              "Unable to setup tls-auth file.");
        return;
      }
      AppendOption("tls-auth", tls_auth_file_.value(), options);
    }
  }

  if (args()->Contains<std::string>(kOpenVPNTLSVersionMinProperty)) {
    AppendOption("tls-version-min",
                 args()->Get<std::string>(kOpenVPNTLSVersionMinProperty),
                 options);
  }

  const auto tls_remote =
      args()->Lookup<std::string>(kOpenVPNTLSRemoteProperty, "");
  if (!tls_remote.empty()) {
    AppendOption("verify-x509-name", tls_remote, "name-prefix", options);
  }

  AppendValueOption(kOpenVPNCipherProperty, "cipher", options);
  AppendValueOption(kOpenVPNAuthProperty, "auth", options);
  AppendFlag(kOpenVPNAuthNoCacheProperty, "auth-nocache", options);
  AppendValueOption(kOpenVPNAuthRetryProperty, "auth-retry", options);
  AppendFlag(kOpenVPNCompLZOProperty, "comp-lzo", options);
  AppendFlag(kOpenVPNCompNoAdaptProperty, "comp-noadapt", options);
  AppendValueOption(kOpenVPNCompressProperty, "compress", options);
  AppendFlag(kOpenVPNPushPeerInfoProperty, "push-peer-info", options);
  AppendValueOption(kOpenVPNRenegSecProperty, "reneg-sec", options);
  AppendValueOption(kOpenVPNShaperProperty, "shaper", options);
  AppendValueOption(kOpenVPNServerPollTimeoutProperty, "server-poll-timeout",
                    options);

  if (!InitCAOptions(options, error)) {
    return;
  }

  // Additional remote certificate verification options.
  InitCertificateVerifyOptions(options);
  if (!InitExtraCertOptions(options, error)) {
    return;
  }

  // Client-side ping support.
  AppendValueOption(kOpenVPNPingProperty, "ping", options);
  AppendValueOption(kOpenVPNPingExitProperty, "ping-exit", options);
  AppendValueOption(kOpenVPNPingRestartProperty, "ping-restart", options);

  AppendValueOption(kOpenVPNNsCertTypeProperty, "ns-cert-type", options);

  InitClientAuthOptions(options);
  InitPKCS11Options(options);

  // TLS support.
  auto remote_cert_tls =
      args()->Lookup<std::string>(kOpenVPNRemoteCertTLSProperty, "");
  if (remote_cert_tls.empty()) {
    remote_cert_tls = "server";
  }
  if (remote_cert_tls != "none") {
    AppendOption("remote-cert-tls", remote_cert_tls, options);
  }

  AppendValueOption(kOpenVPNKeyDirectionProperty, "key-direction", options);
  AppendValueOption(kOpenVPNRemoteCertEKUProperty, "remote-cert-eku", options);
  AppendDelimitedValueOption(kOpenVPNRemoteCertKUProperty, "remote-cert-ku",
                             ' ', options);

  if (!InitManagementChannelOptions(options, error)) {
    return;
  }

  // Setup openvpn-script options and RPC information required to send back
  // Layer 3 configuration.
  AppendOption("setenv", kRpcTaskServiceVariable,
               rpc_task_->GetRpcConnectionIdentifier().value(), options);
  AppendOption("setenv", kRpcTaskPathVariable,
               rpc_task_->GetRpcIdentifier().value(), options);
  AppendOption("script-security", "2", options);
  AppendOption("up", kOpenVPNScript, options);
  AppendOption("up-restart", options);

  // Disable openvpn handling since we do route+ifconfig work.
  AppendOption("route-noexec", options);
  AppendOption("ifconfig-noexec", options);
}

bool OpenVPNDriver::InitCAOptions(
    std::vector<std::vector<std::string>>* options, Error* error) {
  std::vector<std::string> ca_cert_pem;
  if (args()->Contains<std::vector<std::string>>(kOpenVPNCaCertPemProperty)) {
    ca_cert_pem =
        args()->Get<std::vector<std::string>>(kOpenVPNCaCertPemProperty);
  }
  if (ca_cert_pem.empty()) {
    // Use default CAs if no CA certificate is provided.
    AppendOption("ca", kDefaultCACertificates, options);
    return true;
  }

  const base::FilePath certfile =
      certificate_file_->CreatePEMFromStrings(ca_cert_pem);
  if (certfile.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Unable to extract PEM CA certificates.");
    return false;
  }
  AppendOption("ca", certfile.value(), options);
  return true;
}

void OpenVPNDriver::InitCertificateVerifyOptions(
    std::vector<std::vector<std::string>>* options) {
  AppendValueOption(kOpenVPNVerifyHashProperty, "verify-hash", options);
  const auto x509_name =
      args()->Lookup<std::string>(kOpenVPNVerifyX509NameProperty, "");
  if (!x509_name.empty()) {
    const auto x509_type =
        args()->Lookup<std::string>(kOpenVPNVerifyX509TypeProperty, "");
    if (x509_type.empty()) {
      AppendOption("verify-x509-name", x509_name, options);
    } else {
      AppendOption("verify-x509-name", x509_name, x509_type, options);
    }
  }
}

bool OpenVPNDriver::InitExtraCertOptions(
    std::vector<std::vector<std::string>>* options, Error* error) {
  if (!args()->Contains<std::vector<std::string>>(
          kOpenVPNExtraCertPemProperty)) {
    // It's okay for this parameter to be unspecified.
    return true;
  }

  const auto extra_certs =
      args()->Get<std::vector<std::string>>(kOpenVPNExtraCertPemProperty);
  if (extra_certs.empty()) {
    // It's okay for this parameter to be empty.
    return true;
  }

  const base::FilePath certfile =
      extra_certificates_file_->CreatePEMFromStrings(extra_certs);
  if (certfile.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Unable to extract extra PEM CA certificates.");
    return false;
  }

  AppendOption("extra-certs", certfile.value(), options);
  return true;
}

void OpenVPNDriver::InitPKCS11Options(
    std::vector<std::vector<std::string>>* options) {
  const auto id = args()->Lookup<std::string>(kOpenVPNClientCertIdProperty, "");
  if (!id.empty()) {
    AppendOption("pkcs11-providers", kDefaultPKCS11Provider, options);
    AppendOption("pkcs11-id", id, options);
  }
}

void OpenVPNDriver::InitClientAuthOptions(
    std::vector<std::vector<std::string>>* options) {
  // If the AuthUserPass property is set, or the User property is non-empty, or
  // a client cert was not provided, specify user-password client
  // authentication.
  if (args()->Contains<std::string>(kOpenVPNAuthUserPassProperty) ||
      !args()->Lookup<std::string>(kOpenVPNUserProperty, "").empty() ||
      args()->Lookup<std::string>(kOpenVPNClientCertIdProperty, "").empty()) {
    AppendOption("auth-user-pass", options);
  }
}

bool OpenVPNDriver::InitManagementChannelOptions(
    std::vector<std::vector<std::string>>* options, Error* error) {
  if (!management_server_->Start(&sockets_, options)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                          "Unable to setup management channel.");
    return false;
  }
  // If there's a connected default service already, allow the openvpn client to
  // establish connection as soon as it's started. Otherwise, hold the client
  // until an underlying service connects and OnDefaultServiceChanged is
  // invoked.
  if (manager()->IsConnected()) {
    management_server_->ReleaseHold();
  }
  return true;
}

void OpenVPNDriver::InitLoggingOptions(
    std::vector<std::vector<std::string>>* options) {
  AppendOption("syslog", options);

  const auto verb = args()->Lookup<std::string>(kOpenVPNVerbProperty, "");
  if (!verb.empty()) {
    AppendOption("verb", verb, options);
    return;
  }

  if (SLOG_IS_ON(VPN, 6)) {
    // Maximum output:
    // --verb 9 enables PKCS11 debug, TCP stream, link read/write
    // --verb 8 enables event waits, scheduler, tls_session
    AppendOption("verb", "9", options);
  } else if (SLOG_IS_ON(VPN, 5)) {
    // --verb 7 enables data channel encryption keys, routing,
    // pkcs11 actions, pings, push/pull debug
    AppendOption("verb", "7", options);
  } else if (SLOG_IS_ON(VPN, 4)) {
    // --verb 6 enables tcp/udp reads/writes (short), tun/tap reads/writes
    // --verb 5 enables printing 'R' or 'W' per packet to stdout
    AppendOption("verb", "6", options);
  } else if (SLOG_IS_ON(VPN, 3)) {
    // --verb 4 enables logging packet drops, options
    AppendOption("verb", "4", options);
  } else if (SLOG_IS_ON(VPN, 0)) {
    // --verb 3 is the old default for `ff_debug +vpn`
    AppendOption("verb", "3", options);
  }
}

void OpenVPNDriver::AppendOption(
    base::StringPiece option, std::vector<std::vector<std::string>>* options) {
  options->push_back({std::string(option)});
}

void OpenVPNDriver::AppendOption(
    base::StringPiece option,
    base::StringPiece value,
    std::vector<std::vector<std::string>>* options) {
  options->push_back({std::string(option), std::string(value)});
}

void OpenVPNDriver::AppendOption(
    base::StringPiece option,
    base::StringPiece value0,
    base::StringPiece value1,
    std::vector<std::vector<std::string>>* options) {
  options->push_back(
      {std::string(option), std::string(value0), std::string(value1)});
}

void OpenVPNDriver::AppendRemoteOption(
    base::StringPiece host, std::vector<std::vector<std::string>>* options) {
  std::string host_name, host_port;
  if (SplitPortFromHost(host, &host_name, &host_port)) {
    DCHECK(!host_name.empty());
    DCHECK(!host_port.empty());
    AppendOption("remote", host_name, host_port, options);
  } else {
    AppendOption("remote", host, options);
  }
}

bool OpenVPNDriver::AppendValueOption(
    base::StringPiece property,
    base::StringPiece option,
    std::vector<std::vector<std::string>>* options) {
  const auto value = args()->Lookup<std::string>(property, "");
  if (!value.empty()) {
    AppendOption(option, value, options);
    return true;
  }
  return false;
}

bool OpenVPNDriver::AppendDelimitedValueOption(
    const std::string& property,
    const std::string& option,
    char delimiter,
    std::vector<std::vector<std::string>>* options) {
  const auto value = args()->Lookup<std::string>(property, "");
  if (!value.empty()) {
    auto parts = base::SplitString(value, std::string{delimiter},
                                   base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    parts.insert(parts.begin(), option);
    options->push_back(parts);
    return true;
  }
  return false;
}

bool OpenVPNDriver::AppendFlag(const std::string& property,
                               const std::string& option,
                               std::vector<std::vector<std::string>>* options) {
  if (args()->Contains<std::string>(property)) {
    AppendOption(option, options);
    return true;
  }
  return false;
}

void OpenVPNDriver::Disconnect() {
  SLOG(2) << __func__;
  Cleanup();
  event_handler_ = nullptr;
}

void OpenVPNDriver::OnConnectTimeout() {
  Service::ConnectFailure failure =
      management_server_->state() == OpenVPNManagementServer::kStateResolve
          ? Service::kFailureDNSLookup
          : Service::kFailureConnect;
  FailService(failure, Service::kErrorDetailsNone);
}

void OpenVPNDriver::OnReconnecting(ReconnectReason reason) {
  LOG(INFO) << __func__ << "(" << reason << ")";
  if (!event_handler_) {
    LOG(ERROR) << "event_handler_ is not set";
    return;
  }
  base::TimeDelta timeout = GetReconnectTimeout(reason);
  event_handler_->OnDriverReconnecting(timeout);
}

// static
base::TimeDelta OpenVPNDriver::GetReconnectTimeout(ReconnectReason reason) {
  switch (reason) {
    case kReconnectReasonOffline:
      return kReconnectOfflineTimeout;
    case kReconnectReasonTLSError:
      return kReconnectTLSErrorTimeout;
    default:
      return kConnectTimeout;
  }
}

KeyValueStore OpenVPNDriver::GetProvider(Error* error) {
  SLOG(2) << __func__;
  KeyValueStore props = VPNDriver::GetProvider(error);
  props.Set<bool>(
      kPassphraseRequiredProperty,
      args()->Lookup<std::string>(kOpenVPNPasswordProperty, "").empty() &&
          args()->Lookup<std::string>(kOpenVPNTokenProperty, "").empty());
  return props;
}

std::vector<std::string> OpenVPNDriver::GetCommandLineArgs() {
  SLOG(2) << __func__ << "(" << lsb_release_file_.value() << ")";
  std::vector<std::string> args = {"--config", openvpn_config_file_.value()};
  std::string contents;
  if (!base::ReadFileToString(lsb_release_file_, &contents)) {
    LOG(ERROR) << "Unable to read the lsb-release file: "
               << lsb_release_file_.value();
    return args;
  }
  const auto lines = base::SplitString(contents, "\n", base::TRIM_WHITESPACE,
                                       base::SPLIT_WANT_ALL);
  for (const auto& line : lines) {
    const size_t assign = line.find('=');
    if (assign == std::string::npos) {
      continue;
    }
    const auto key = line.substr(0, assign);
    const auto value = line.substr(assign + 1);
    if (key == kChromeOSReleaseName) {
      args.push_back("--setenv");
      args.push_back("UV_PLAT");
      args.push_back(value);
    } else if (key == kChromeOSReleaseVersion) {
      args.push_back("--setenv");
      args.push_back("UV_PLAT_REL");
      args.push_back(value);
    }
    // Other LSB release values are irrelevant.
  }
  return args;
}

void OpenVPNDriver::OnDefaultPhysicalServiceEvent(
    DefaultPhysicalServiceEvent event) {
  if (!event_handler_)
    return;

  // When this happens, it means the service is connecting but the management
  // server and the OpenVPN client have not been started yet. We don't need to
  // do anything in this case:
  // 1) For the service-down event, a new started client will be automatically
  //    on hold and we will check if the default service is connected before
  //    releasing the hold (see InitManagementChannelOptions()), and then the
  //    following service-up event will release the hold.
  // 2) For the other two events, it will just set up the VPN connection on the
  //    new physical service.
  if (!management_server_->IsStarted()) {
    LOG(INFO) << "Default physical service event comes before management "
                 "server starts.";
    return;
  }

  switch (event) {
    case kDefaultPhysicalServiceUp:
      management_server_->ReleaseHold();
      event_handler_->OnDriverReconnecting(
          GetReconnectTimeout(kReconnectReasonOffline));
      break;
    case kDefaultPhysicalServiceDown:
      management_server_->Hold();
      management_server_->Restart();
      event_handler_->OnDriverReconnecting(kTimeoutNone);
      break;
    case kDefaultPhysicalServiceChanged:
      // Ask the management server to reconnect immediately.
      management_server_->ReleaseHold();
      management_server_->Restart();
      event_handler_->OnDriverReconnecting(
          GetReconnectTimeout(kReconnectReasonOffline));
      break;
    default:
      NOTREACHED();
  }
}

void OpenVPNDriver::ReportConnectionMetrics() {
  metrics()->SendEnumToUMA(Metrics::kMetricVpnDriver,
                           Metrics::kVpnDriverOpenVpn);

  if (args()->Contains<std::vector<std::string>>(kOpenVPNCaCertPemProperty) &&
      !args()
           ->Get<std::vector<std::string>>(kOpenVPNCaCertPemProperty)
           .empty()) {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnRemoteAuthenticationType,
        Metrics::kVpnRemoteAuthenticationTypeOpenVpnCertificate);
  } else {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnRemoteAuthenticationType,
        Metrics::kVpnRemoteAuthenticationTypeOpenVpnDefault);
  }

  bool has_user_authentication = false;
  if (args()->Lookup<std::string>(kOpenVPNTokenProperty, "") != "") {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnUserAuthenticationType,
        Metrics::kVpnUserAuthenticationTypeOpenVpnUsernameToken);
    has_user_authentication = true;
  }
  if (args()->Lookup<std::string>(kOpenVPNOTPProperty, "") != "") {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnUserAuthenticationType,
        Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePasswordOtp);
    has_user_authentication = true;
  }
  if (args()->Lookup<std::string>(kOpenVPNAuthUserPassProperty, "") != "" ||
      args()->Lookup<std::string>(kOpenVPNUserProperty, "") != "") {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnUserAuthenticationType,
        Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePassword);
    has_user_authentication = true;
  }
  if (args()->Lookup<std::string>(kOpenVPNClientCertIdProperty, "") != "") {
    metrics()->SendEnumToUMA(
        Metrics::kMetricVpnUserAuthenticationType,
        Metrics::kVpnUserAuthenticationTypeOpenVpnCertificate);
    has_user_authentication = true;
  }
  if (!has_user_authentication) {
    metrics()->SendEnumToUMA(Metrics::kMetricVpnUserAuthenticationType,
                             Metrics::kVpnUserAuthenticationTypeOpenVpnNone);
  }
}

void OpenVPNDriver::ReportCipherMetrics(const std::string& cipher) {
  static constexpr auto str2enum =
      base::MakeFixedFlatMap<base::StringPiece, Metrics::VpnOpenVPNCipher>({
          {"BF-CBC", Metrics::kVpnOpenVPNCipher_BF_CBC},
          {"AES-256-GCM", Metrics::kVpnOpenVPNCipher_AES_256_GCM},
          {"AES-128-GCM", Metrics::kVpnOpenVPNCipher_AES_128_GCM},
      });
  Metrics::VpnOpenVPNCipher metric = Metrics::kVpnOpenVPNCipherUnknown;
  const auto it = str2enum.find(cipher);
  if (it != str2enum.end()) {
    metric = it->second;
  }

  metrics()->SendEnumToUMA(Metrics::kMetricVpnOpenVPNCipher, metric);
}

}  // namespace shill
