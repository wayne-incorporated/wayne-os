// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/vpn_driver.h"

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/store/property_accessor.h"
#include "shill/store/property_store.h"
#include "shill/store/store_interface.h"
#include "shill/vpn/vpn_provider.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kVPN;
}  // namespace Logging

// TODO(crbug.com/1084279) Migrate back to storing property names after crypto
// code is removed.
const char VPNDriver::kCredentialPrefix[] = "Credential.";

VPNDriver::VPNDriver(Manager* manager,
                     ProcessManager* process_manager,
                     VPNType vpn_type,
                     const Property* properties,
                     size_t property_count,
                     bool use_eap)
    : manager_(manager),
      process_manager_(process_manager),
      vpn_type_(vpn_type),
      properties_(properties),
      property_count_(property_count) {
  for (size_t i = 0; i < property_count_; i++) {
    const auto flags = properties_[i].flags;
    const bool isReadOnly = flags & Property::kReadOnly;
    const bool isWriteOnly = flags & Property::kWriteOnly;
    CHECK(!(isReadOnly && isWriteOnly));
  }
  if (use_eap) {
    eap_credentials_.reset(new EapCredentials());
  }
}

VPNDriver::~VPNDriver() = default;

bool VPNDriver::Load(const StoreInterface* storage,
                     const std::string& storage_id) {
  SLOG(2) << __func__;
  for (size_t i = 0; i < property_count_; i++) {
    if ((properties_[i].flags & Property::kEphemeral)) {
      continue;
    }
    const auto& property = properties_[i].property;
    if (properties_[i].flags & Property::kArray) {
      CHECK(!(properties_[i].flags & Property::kCredential))
          << "Property cannot be both an array and a credential";
      std::vector<std::string> value;
      if (storage->GetStringList(storage_id, property, &value)) {
        args_.Set<Strings>(property, value);
      } else {
        args_.Remove(property);
      }
    } else {
      std::string value;
      bool loaded = (properties_[i].flags & Property::kCredential)
                        ? storage->GetCryptedString(
                              storage_id, property,
                              std::string(kCredentialPrefix) + property, &value)
                        : storage->GetString(storage_id, property, &value);
      if (loaded) {
        args_.Set<std::string>(property, value);
      } else {
        args_.Remove(property);
      }
    }
  }

  if (eap_credentials_) {
    eap_credentials_->Load(storage, storage_id);
  }

  return true;
}

void VPNDriver::MigrateDeprecatedStorage(StoreInterface* storage,
                                         const std::string& storage_id) {
  SLOG(2) << __func__;
  // Migrate from ROT47 to plaintext.
  // TODO(crbug.com/1084279) Migrate back to not using kCredentialPrefix once
  // ROT47 migration is complete.
  for (size_t i = 0; i < property_count_; i++) {
    if (!(properties_[i].flags & Property::kCredential)) {
      continue;
    }

    CHECK(!(properties_[i].flags & Property::kArray))
        << "Property cannot be both an array and a credential";
    const auto& deprecated_key = properties_[i].property;
    const auto credentials_key =
        std::string(kCredentialPrefix) + deprecated_key;

    if (storage->DeleteKey(storage_id, deprecated_key)) {
      const auto& value = args_.Get<std::string>(properties_[i].property);
      storage->SetString(storage_id, credentials_key, value);
    }
  }
}

bool VPNDriver::Save(StoreInterface* storage,
                     const std::string& storage_id,
                     bool save_credentials) {
  SLOG(2) << __func__;
  for (size_t i = 0; i < property_count_; i++) {
    if ((properties_[i].flags & Property::kEphemeral)) {
      continue;
    }
    bool credential = (properties_[i].flags & Property::kCredential);
    const auto& property = properties_[i].property;
    if (properties_[i].flags & Property::kArray) {
      CHECK(!credential) << "Property cannot be both an array and a credential";
      if (!args_.Contains<Strings>(property)) {
        storage->DeleteKey(storage_id, property);
        continue;
      }
      Strings value = args_.Get<Strings>(property);
      storage->SetStringList(storage_id, property, value);
    } else {
      std::string storage_key = property;
      if (credential) {
        storage_key = std::string(kCredentialPrefix) + storage_key;
      }

      if (!args_.Contains<std::string>(property) ||
          (credential && !save_credentials)) {
        storage->DeleteKey(storage_id, storage_key);
        continue;
      }
      const auto& value = args_.Get<std::string>(property);
      storage->SetString(storage_id, storage_key, value);
    }
  }

  if (eap_credentials_) {
    eap_credentials_->Save(storage, storage_id, save_credentials);
  }

  return true;
}

void VPNDriver::UnloadCredentials() {
  SLOG(2) << __func__;
  for (size_t i = 0; i < property_count_; i++) {
    if ((properties_[i].flags &
         (Property::kEphemeral | Property::kCredential))) {
      args_.Remove(properties_[i].property);
    }
  }

  if (eap_credentials_) {
    eap_credentials_->Reset();
  }
}

void VPNDriver::InitPropertyStore(PropertyStore* store) {
  SLOG(2) << __func__;
  for (size_t i = 0; i < property_count_; i++) {
    if (properties_[i].flags & Property::kReadOnly) {
      continue;
    }
    if (properties_[i].flags & Property::kArray) {
      store->RegisterDerivedStrings(
          properties_[i].property,
          StringsAccessor(new CustomMappedAccessor<VPNDriver, Strings, size_t>(
              this, &VPNDriver::ClearMappedStringsProperty,
              &VPNDriver::GetMappedStringsProperty,
              &VPNDriver::SetMappedStringsProperty, i)));
    } else {
      store->RegisterDerivedString(
          properties_[i].property,
          StringAccessor(
              new CustomMappedAccessor<VPNDriver, std::string, size_t>(
                  this, &VPNDriver::ClearMappedStringProperty,
                  &VPNDriver::GetMappedStringProperty,
                  &VPNDriver::SetMappedStringProperty, i)));
    }
  }

  store->RegisterDerivedKeyValueStore(
      kProviderProperty,
      KeyValueStoreAccessor(new CustomAccessor<VPNDriver, KeyValueStore>(
          this, &VPNDriver::GetProvider, nullptr)));

  if (eap_credentials_) {
    eap_credentials_->InitPropertyStore(store);
  }
}

void VPNDriver::ClearMappedStringProperty(const size_t& index, Error* error) {
  CHECK(index < property_count_);
  if (args_.Contains<std::string>(properties_[index].property)) {
    args_.Remove(properties_[index].property);
  } else {
    error->Populate(Error::kNotFound, "Property is not set");
  }
}

void VPNDriver::ClearMappedStringsProperty(const size_t& index, Error* error) {
  CHECK(index < property_count_);
  if (args_.Contains<Strings>(properties_[index].property)) {
    args_.Remove(properties_[index].property);
  } else {
    error->Populate(Error::kNotFound, "Property is not set");
  }
}

std::string VPNDriver::GetMappedStringProperty(const size_t& index,
                                               Error* error) {
  // Provider properties are set via SetProperty calls to "Provider.XXX",
  // however, they are retrieved via a GetProperty call, which returns all
  // properties in a single "Provider" dict.  Therefore, none of the individual
  // properties in the kProperties are available for enumeration in
  // GetProperties.  Instead, they are retrieved via GetProvider below.
  error->Populate(Error::kInvalidArguments,
                  "Provider properties are not read back in this manner");
  return std::string();
}

Strings VPNDriver::GetMappedStringsProperty(const size_t& index, Error* error) {
  // Provider properties are set via SetProperty calls to "Provider.XXX",
  // however, they are retrieved via a GetProperty call, which returns all
  // properties in a single "Provider" dict.  Therefore, none of the individual
  // properties in the kProperties are available for enumeration in
  // GetProperties.  Instead, they are retrieved via GetProvider below.
  error->Populate(Error::kInvalidArguments,
                  "Provider properties are not read back in this manner");
  return Strings();
}

bool VPNDriver::SetMappedStringProperty(const size_t& index,
                                        const std::string& value,
                                        Error* error) {
  CHECK(index < property_count_);
  if (args_.Contains<std::string>(properties_[index].property) &&
      args_.Get<std::string>(properties_[index].property) == value) {
    return false;
  }
  args_.Set<std::string>(properties_[index].property, value);
  return true;
}

bool VPNDriver::SetMappedStringsProperty(const size_t& index,
                                         const Strings& value,
                                         Error* error) {
  CHECK(index < property_count_);
  if (args_.Contains<Strings>(properties_[index].property) &&
      args_.Get<Strings>(properties_[index].property) == value) {
    return false;
  }
  args_.Set<Strings>(properties_[index].property, value);
  return true;
}

KeyValueStore VPNDriver::GetProvider(Error* error) {
  SLOG(2) << __func__;
  const auto provider_prefix = std::string(kProviderProperty) + ".";
  KeyValueStore provider_properties;

  for (size_t i = 0; i < property_count_; i++) {
    if ((properties_[i].flags & Property::kWriteOnly)) {
      continue;
    }
    const std::string prop = properties_[i].property;

    // Chomp off leading "Provider." from properties that have this prefix.
    std::string chopped_prop;
    if (base::StartsWith(prop, provider_prefix,
                         base::CompareCase::INSENSITIVE_ASCII)) {
      chopped_prop = prop.substr(provider_prefix.length());
    } else {
      chopped_prop = prop;
    }

    if (properties_[i].flags & Property::kArray) {
      if (!args_.Contains<Strings>(prop)) {
        continue;
      }
      Strings value = args_.Get<Strings>(prop);
      provider_properties.Set<Strings>(chopped_prop, value);
    } else {
      if (!args_.Contains<std::string>(prop)) {
        continue;
      }
      const auto& value = args_.Get<std::string>(prop);
      provider_properties.Set<std::string>(chopped_prop, value);
    }
  }

  return provider_properties;
}

void VPNDriver::OnBeforeSuspend(ResultCallback callback) {
  // Nothing to be done in the general case, so immediately report success.
  std::move(callback).Run(Error(Error::kSuccess));
}

void VPNDriver::OnAfterResume() {}

void VPNDriver::OnDefaultPhysicalServiceEvent(
    DefaultPhysicalServiceEvent event) {}

std::string VPNDriver::GetHost() const {
  return args_.Lookup<std::string>(kProviderHostProperty, "");
}

ControlInterface* VPNDriver::control_interface() const {
  return manager_->control_interface();
}

EventDispatcher* VPNDriver::dispatcher() const {
  return manager_->dispatcher();
}

Metrics* VPNDriver::metrics() const {
  return manager_->metrics();
}

}  // namespace shill
