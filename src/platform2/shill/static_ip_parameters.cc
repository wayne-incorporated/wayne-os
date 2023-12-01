// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/static_ip_parameters.h"

#include <string>
#include <vector>

#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/error.h"
#include "shill/logging.h"
#include "shill/net/ip_address.h"
#include "shill/network/network_config.h"
#include "shill/store/property_accessor.h"
#include "shill/store/property_store.h"
#include "shill/store/store_interface.h"

namespace shill {

namespace {

constexpr char kConfigKeyPrefix[] = "StaticIP.";

struct Property {
  enum class Type {
    kInt32,
    kString,
    // Properties of type "Strings" are stored as a comma-separated list in the
    // control interface and in the profile, but are stored as a vector of
    // strings in the IPConfig properties.
    kStrings
  };

  const char* name;
  Type type;
};

constexpr Property kProperties[] = {
    {kAddressProperty, Property::Type::kString},
    {kGatewayProperty, Property::Type::kString},
    {kMtuProperty, Property::Type::kInt32},
    {kNameServersProperty, Property::Type::kStrings},
    {kSearchDomainsProperty, Property::Type::kStrings},
    {kPrefixlenProperty, Property::Type::kInt32},
    {kIncludedRoutesProperty, Property::Type::kStrings},
    {kExcludedRoutesProperty, Property::Type::kStrings},
};

// Converts the StaticIPParameters from KeyValueStore to NetworkConfig.
// Errors are ignored if any value is not valid.
NetworkConfig KeyValuesToNetworkConfig(const KeyValueStore& kvs) {
  NetworkConfig ret;
  if (kvs.Contains<std::string>(kAddressProperty)) {
    const int prefix = kvs.Lookup<int32_t>(kPrefixlenProperty, 0);
    const std::string addr = kvs.Get<std::string>(kAddressProperty);
    ret.ipv4_address_cidr =
        base::StrCat({addr, "/", base::NumberToString(prefix)});
  }
  ret.ipv4_route.gateway = kvs.GetOptionalValue<std::string>(kGatewayProperty);
  ret.ipv4_route.included_route_prefixes =
      kvs.GetOptionalValue<Strings>(kIncludedRoutesProperty);
  ret.ipv4_route.excluded_route_prefixes =
      kvs.GetOptionalValue<Strings>(kExcludedRoutesProperty);
  ret.mtu = kvs.GetOptionalValue<int32_t>(kMtuProperty);
  ret.dns_servers = kvs.GetOptionalValue<Strings>(kNameServersProperty);
  ret.dns_search_domains =
      kvs.GetOptionalValue<Strings>(kSearchDomainsProperty);

  // TODO(b/232177767): Currently this is only used by VPN. Check that if the
  // Network class can make this decision by itself after finishing the
  // refactor.
  if (ret.ipv4_route.included_route_prefixes.has_value()) {
    ret.ipv4_default_route = false;
  }

  return ret;
}

}  // namespace

KeyValueStore StaticIPParameters::NetworkConfigToKeyValues(
    const NetworkConfig& props) {
  KeyValueStore kvs;
  if (props.ipv4_address_cidr.has_value()) {
    const auto addr = IPAddress::CreateFromPrefixString(
        props.ipv4_address_cidr.value(), IPAddress::kFamilyIPv4);
    if (addr.has_value()) {
      kvs.Set<std::string>(kAddressProperty, addr->ToString());
      kvs.Set<int32_t>(kPrefixlenProperty, addr->prefix());
    } else {
      LOG(ERROR) << "props does not have a valid IPv4 address in CIDR "
                 << props.ipv4_address_cidr.value();
    }
  }

  kvs.SetFromOptionalValue<std::string>(kGatewayProperty,
                                        props.ipv4_route.gateway);
  kvs.SetFromOptionalValue<int32_t>(kMtuProperty, props.mtu);
  kvs.SetFromOptionalValue<Strings>(kNameServersProperty, props.dns_servers);
  kvs.SetFromOptionalValue<Strings>(kSearchDomainsProperty,
                                    props.dns_search_domains);
  kvs.SetFromOptionalValue<Strings>(kIncludedRoutesProperty,
                                    props.ipv4_route.included_route_prefixes);
  kvs.SetFromOptionalValue<Strings>(kExcludedRoutesProperty,
                                    props.ipv4_route.excluded_route_prefixes);

  return kvs;
}

StaticIPParameters::StaticIPParameters() = default;

StaticIPParameters::~StaticIPParameters() = default;

void StaticIPParameters::PlumbPropertyStore(PropertyStore* store) {
  // Register KeyValueStore for both static ip parameters.
  store->RegisterDerivedKeyValueStore(
      kStaticIPConfigProperty,
      KeyValueStoreAccessor(
          new CustomAccessor<StaticIPParameters, KeyValueStore>(
              this, &StaticIPParameters::GetStaticIPConfig,
              &StaticIPParameters::SetStaticIP)));
}

bool StaticIPParameters::Load(const StoreInterface* storage,
                              const std::string& storage_id) {
  KeyValueStore args;
  for (const auto& property : kProperties) {
    const std::string name(std::string(kConfigKeyPrefix) + property.name);
    switch (property.type) {
      case Property::Type::kInt32: {
        int32_t value;
        if (storage->GetInt(storage_id, name, &value)) {
          args.Set<int32_t>(property.name, value);
        } else {
          args.Remove(property.name);
        }
      } break;
      case Property::Type::kString: {
        std::string value;
        if (storage->GetString(storage_id, name, &value)) {
          args.Set<std::string>(property.name, value);
        } else {
          args.Remove(property.name);
        }
      } break;
      case Property::Type::kStrings: {
        // Name servers field is stored in storage as comma separated string.
        // Keep it as is to be backward compatible.
        std::string value;
        if (storage->GetString(storage_id, name, &value)) {
          std::vector<std::string> string_list = base::SplitString(
              value, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
          args.Set<Strings>(property.name, string_list);
        } else {
          args.Remove(property.name);
        }
      } break;
      default:
        NOTIMPLEMENTED();
        break;
    }
  }
  return SetStaticIP(args, nullptr);
}

void StaticIPParameters::Save(StoreInterface* storage,
                              const std::string& storage_id) {
  const auto args = NetworkConfigToKeyValues(config_);
  for (const auto& property : kProperties) {
    const std::string name(std::string(kConfigKeyPrefix) + property.name);
    bool property_exists = false;
    switch (property.type) {
      case Property::Type::kInt32:
        if (args.Contains<int32_t>(property.name)) {
          property_exists = true;
          storage->SetInt(storage_id, name, args.Get<int32_t>(property.name));
        }
        break;
      case Property::Type::kString:
        if (args.Contains<std::string>(property.name)) {
          property_exists = true;
          storage->SetString(storage_id, name,
                             args.Get<std::string>(property.name));
        }
        break;
      case Property::Type::kStrings:
        if (args.Contains<Strings>(property.name)) {
          property_exists = true;
          // Name servers field is stored in storage as comma separated string.
          // Keep it as is to be backward compatible.
          storage->SetString(
              storage_id, name,
              base::JoinString(args.Get<Strings>(property.name), ","));
        }
        break;
      default:
        NOTIMPLEMENTED();
        break;
    }
    if (!property_exists) {
      storage->DeleteKey(storage_id, name);
    }
  }
}

KeyValueStore StaticIPParameters::GetStaticIPConfig(Error* /*error*/) {
  return NetworkConfigToKeyValues(config_);
}

bool StaticIPParameters::SetStaticIP(const KeyValueStore& value,
                                     Error* /*error*/) {
  const auto current_args = NetworkConfigToKeyValues(config_);
  if (current_args == value) {
    return false;
  }
  config_ = KeyValuesToNetworkConfig(value);
  return true;
}

void StaticIPParameters::Reset() {
  config_ = NetworkConfig();
}

}  // namespace shill
