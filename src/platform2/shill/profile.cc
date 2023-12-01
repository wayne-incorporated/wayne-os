// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/profile.h"

#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/dbus/shill/dbus-constants.h>

#include "shill/adaptor_interfaces.h"
#include "shill/dbus/dbus_control.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/service.h"
#include "shill/store/key_file_store.h"
#include "shill/store/pkcs11_slot_getter.h"
#include "shill/store/property_accessor.h"
#include "shill/store/stub_storage.h"
#include "shill/wifi/passpoint_credentials.h"

namespace shill {

// static
const char Profile::kUserProfileListPathname[] = RUNDIR "/loaded_profile_list";

Profile::Profile(Manager* manager,
                 const Identifier& name,
                 const base::FilePath& storage_directory,
                 bool connect_to_rpc)
    : manager_(manager),
      properties_(kAlwaysOnVpnModeOff, kDefaultAlwaysOnVpnService),
      store_(base::BindRepeating(&Profile::OnPropertyChanged,
                                 base::Unretained(this))),
      name_(name),
      slot_getter_(new Pkcs11SlotGetter(name_.user_hash)) {
  if (connect_to_rpc)
    adaptor_ = manager->control_interface()->CreateProfileAdaptor(this);

  // kCheckPortalListProperty: Registered in DefaultProfile
  store_.RegisterConstString(kNameProperty, &name_.identifier);
  store_.RegisterConstString(kUserHashProperty, &name_.user_hash);

  // kPortalURLProperty: Registered in DefaultProfile

  HelpRegisterConstDerivedRpcIdentifiers(kServicesProperty,
                                         &Profile::EnumerateAvailableServices);
  HelpRegisterConstDerivedStrings(kEntriesProperty, &Profile::EnumerateEntries);

  HelpRegisterDerivedString(kAlwaysOnVpnModeProperty,
                            &Profile::DBusGetAlwaysOnVpnMode,
                            &Profile::DBusSetAlwaysOnVpnMode);
  HelpRegisterDerivedRpcIdentifier(kAlwaysOnVpnServiceProperty,
                                   &Profile::DBusGetAlwaysOnVpnService,
                                   &Profile::DBusSetAlwaysOnVpnService);

  if (name.user.empty()) {
    // Subtle: Profile is only directly instantiated for user
    // profiles. And user profiles must have a non-empty
    // |name.user|. So we want to CHECK here. But Profile is also the
    // base class for DefaultProfile. So a CHECK here would cause us
    // to abort whenever we attempt to instantiate a DefaultProfile.
    //
    // Instead, we leave |persistent_profile_path_| unintialized. One
    // of two things will happen: a) we become a DefaultProfile, and
    // the DefaultProfile ctor sets |persistent_profile_path_|, or b)
    // we really are destined to be a user Profile. In the latter
    // case, our |name| argument was invalid,
    // |persistent_profile_path_| is never set, and we CHECK for an
    // empty |persistent_profile_path_| in InitStorage().
    //
    // TODO(quiche): Clean this up. crbug.com/527553
  } else {
    persistent_profile_path_ = GetFinalStoragePath(storage_directory, name);
  }
}

Profile::~Profile() = default;

void Profile::OnPropertyChanged(base::StringPiece /*name*/) {
  manager()->OnProfileChanged(this);
}

bool Profile::InitStorage(InitStorageOption storage_option, Error* error) {
  CHECK(!persistent_profile_path_.empty());
  std::unique_ptr<StoreInterface> storage =
      CreateStore(persistent_profile_path_, slot_getter_.get());
  bool already_exists = !storage->IsEmpty();
  if (!already_exists && storage_option != kCreateNew &&
      storage_option != kCreateOrOpenExisting) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kNotFound,
        base::StringPrintf("Profile storage for %s:%s does not already exist",
                           name_.user.c_str(), name_.identifier.c_str()));
    return false;
  } else if (already_exists && storage_option != kOpenExisting &&
             storage_option != kCreateOrOpenExisting) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kAlreadyExists,
        base::StringPrintf("Profile storage for %s:%s already exists",
                           name_.user.c_str(), name_.identifier.c_str()));
    return false;
  }
  if (!storage->Open()) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInternalError,
        base::StringPrintf("Could not open profile storage for %s:%s",
                           name_.user.c_str(), name_.identifier.c_str()));
    if (already_exists) {
      // The profile contents are corrupt, or we do not have access to
      // this file.  Move this file out of the way so a future open attempt
      // will succeed, assuming the failure reason was the former.
      storage->MarkAsCorrupted();
    }
    return false;
  }
  if (!already_exists) {
    // Add a descriptive header to the profile so even if nothing is stored
    // to it, it still has some content.  Completely empty keyfiles are not
    // valid for reading.
    storage->SetHeader(base::StringPrintf("Profile %s:%s", name_.user.c_str(),
                                          name_.identifier.c_str()));
  }
  storage_ = std::move(storage);
  properties_.Load(storage_.get());
  manager_->OnProfileStorageInitialized(this);
  return true;
}

void Profile::InitStubStorage() {
  storage_ = std::make_unique<StubStorage>();
}

bool Profile::RemoveStorage(Error* error) {
  CHECK(!storage_.get());
  CHECK(!persistent_profile_path_.empty());

  if (!base::DeleteFile(persistent_profile_path_)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        base::StringPrintf("Could not remove path %s",
                           persistent_profile_path_.value().c_str()));
    return false;
  }

  return true;
}

std::string Profile::GetFriendlyName() const {
  return (name_.user.empty() ? "" : name_.user + "/") + name_.identifier;
}

const RpcIdentifier& Profile::GetRpcIdentifier() const {
  static RpcIdentifier null_identifier;
  if (!adaptor_) {
    return null_identifier;
  }
  return adaptor_->GetRpcIdentifier();
}

void Profile::SetStorageForTest(std::unique_ptr<StoreInterface> storage) {
  storage_ = std::move(storage);
}

bool Profile::AdoptService(const ServiceRefPtr& service) {
  if (service->profile() == this) {
    return false;
  }
  service->SetEapSlotGetter(slot_getter_.get());
  service->SetProfile(this);
  return service->Save(storage_.get()) && storage_->Flush();
}

bool Profile::AbandonService(const ServiceRefPtr& service) {
  if (service->profile() == this) {
    service->SetProfile(nullptr);
    service->SetEapSlotGetter(nullptr);
  }
  storage_->DeleteGroup(service->GetStorageIdentifier());
  storage_->PKCS11DeleteGroup(service->GetStorageIdentifier());
  return storage_->Flush();
}

bool Profile::UpdateService(const ServiceRefPtr& service) {
  return service->Save(storage_.get()) && storage_->Flush();
}

bool Profile::LoadService(const ServiceRefPtr& service) {
  if (!ContainsService(service))
    return false;
  service->SetEapSlotGetter(slot_getter_.get());
  bool ret = service->Load(storage_.get());
  service->MigrateDeprecatedStorage(storage_.get());
  return ret;
}

bool Profile::ConfigureService(const ServiceRefPtr& service) {
  if (!LoadService(service))
    return false;
  service->SetProfile(this);
  return true;
}

bool Profile::ConfigureDevice(const DeviceRefPtr& device) {
  return device->Load(storage_.get());
}

bool Profile::ContainsService(const ServiceConstRefPtr& service) {
  return service->IsLoadableFrom(*storage_);
}

void Profile::DeleteEntry(const std::string& entry_name, Error* error) {
  if (!storage_->ContainsGroup(entry_name)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kNotFound,
        base::StringPrintf("Entry %s does not exist in profile",
                           entry_name.c_str()));
    return;
  }
  if (!manager_->HandleProfileEntryDeletion(this, entry_name)) {
    // If HandleProfileEntryDeletion() returns succeeds, DeleteGroup()
    // has already been called when AbandonService was called.
    // Otherwise, we need to delete the group ourselves.
    storage_->DeleteGroup(entry_name);
  }
  Save();
}

ServiceRefPtr Profile::GetServiceFromEntry(const std::string& entry_name,
                                           Error* error) {
  if (!storage_->ContainsGroup(entry_name)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kNotFound,
        base::StringPrintf("Entry %s does not exist in profile",
                           entry_name.c_str()));
    return nullptr;
  }

  // Lookup the service entry from the registered services.
  ServiceRefPtr service = manager_->GetServiceWithStorageIdentifierFromProfile(
      this, entry_name, error);
  if (service) {
    return service;
  }

  // Load the service entry to a temporary service.
  return manager_->CreateTemporaryServiceFromProfile(this, entry_name, error);
}

bool Profile::IsValidIdentifierToken(const std::string& token) {
  if (token.empty()) {
    return false;
  }
  for (auto chr : token) {
    if (!base::IsAsciiAlpha(chr) && !base::IsAsciiDigit(chr)) {
      return false;
    }
  }
  return true;
}

// static
bool Profile::ParseIdentifier(const std::string& raw, Identifier* parsed) {
  if (raw.empty()) {
    return false;
  }
  if (raw[0] == '~') {
    // Format: "~user/identifier".
    size_t slash = raw.find('/');
    if (slash == std::string::npos) {
      return false;
    }
    std::string user(raw.begin() + 1, raw.begin() + slash);
    std::string identifier(raw.begin() + slash + 1, raw.end());
    if (!IsValidIdentifierToken(user) || !IsValidIdentifierToken(identifier)) {
      return false;
    }
    parsed->user = user;
    parsed->identifier = identifier;
    return true;
  }

  // Format: "identifier".
  if (!IsValidIdentifierToken(raw)) {
    return false;
  }
  parsed->user = "";
  parsed->identifier = raw;
  return true;
}

// static
std::string Profile::IdentifierToString(const Identifier& name) {
  if (name.user.empty()) {
    // Format: "identifier".
    return name.identifier;
  }

  // Format: "~user/identifier".
  return base::StringPrintf("~%s/%s", name.user.c_str(),
                            name.identifier.c_str());
}

// static
std::vector<Profile::Identifier> Profile::LoadUserProfileList(
    const base::FilePath& path) {
  std::vector<Identifier> profile_identifiers;
  std::string profile_data;
  if (!base::ReadFileToString(path, &profile_data)) {
    return profile_identifiers;
  }

  const auto profile_lines = base::SplitString(
      profile_data, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  for (const auto& line : profile_lines) {
    if (line.empty()) {
      // This will be the case on the last line, so let's not complain about it.
      continue;
    }
    size_t space = line.find(' ');
    if (space == std::string::npos || space == 0) {
      LOG(ERROR) << "Invalid line found in " << path.value() << ": " << line;
      continue;
    }
    std::string name(line.begin(), line.begin() + space);
    Identifier identifier;
    if (!ParseIdentifier(name, &identifier) || identifier.user.empty()) {
      LOG(ERROR) << "Invalid profile name found in " << path.value() << ": "
                 << name;
      continue;
    }
    identifier.user_hash = std::string(line.begin() + space + 1, line.end());
    profile_identifiers.push_back(identifier);
  }

  return profile_identifiers;
}

// static
bool Profile::SaveUserProfileList(const base::FilePath& path,
                                  const std::vector<ProfileRefPtr>& profiles) {
  std::vector<std::string> lines;
  for (const auto& profile : profiles) {
    Identifier& id = profile->name_;
    if (id.user.empty()) {
      continue;
    }
    lines.push_back(base::StringPrintf(
        "%s %s\n", IdentifierToString(id).c_str(), id.user_hash.c_str()));
  }
  std::string content = base::JoinString(lines, "");
  size_t ret = base::WriteFile(path, content.c_str(), content.length());
  return ret == content.length();
}

bool Profile::MatchesIdentifier(const Identifier& name) const {
  return name.user == name_.user && name.identifier == name_.identifier;
}

bool Profile::GetAlwaysOnVpnSettings(std::string* mode, RpcIdentifier* id) {
  DCHECK(mode);
  DCHECK(id);

  Error error;
  if (!store().GetStringProperty(kAlwaysOnVpnModeProperty, mode, &error)) {
    return false;
  }
  if (!store().GetRpcIdentifierProperty(kAlwaysOnVpnServiceProperty, id,
                                        &error) ||
      !id->IsValid()) {
    return false;
  }
  return true;
}

void Profile::ClearAlwaysOnVpn() {
  properties_.always_on_vpn_mode = kAlwaysOnVpnModeOff;
  properties_.always_on_vpn_service.clear();
}

std::string Profile::DBusGetAlwaysOnVpnMode(Error* /*error*/) {
  return properties_.always_on_vpn_mode;
}

bool Profile::DBusSetAlwaysOnVpnMode(const std::string& mode, Error* error) {
  if (mode != kAlwaysOnVpnModeOff && mode != kAlwaysOnVpnModeBestEffort &&
      mode != kAlwaysOnVpnModeStrict) {
    // Invalid mode
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "invalid always-on VPN mode");
    return false;
  }
  properties_.always_on_vpn_mode = mode;
  Save();
  return true;
}

RpcIdentifier Profile::DBusGetAlwaysOnVpnService(Error* error) {
  ServiceRefPtr service = manager()->GetServiceWithStorageIdentifier(
      properties_.always_on_vpn_service);
  if (service == nullptr) {
    return DBusControl::NullRpcIdentifier();
  }
  return service->GetRpcIdentifier();
}

bool Profile::DBusSetAlwaysOnVpnService(const RpcIdentifier& id, Error* error) {
  ServiceRefPtr service = manager()->GetServiceWithRpcIdentifier(id);
  if (service == nullptr) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotFound,
                          "service not found");
    return false;
  }
  if (service->technology() != Technology::kVPN) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "not a VPN service");
    return false;
  }
  properties_.always_on_vpn_service = service->GetStorageIdentifier();
  Save();
  return true;
}

bool Profile::Save() {
  properties_.Save(storage_.get());
  return storage_->Flush();
}

RpcIdentifiers Profile::EnumerateAvailableServices(Error* error) {
  // We should return the Manager's service list if this is the active profile.
  if (manager_->IsActiveProfile(this)) {
    return manager_->EnumerateAvailableServices(error);
  }
  return RpcIdentifiers();
}

std::vector<std::string> Profile::EnumerateEntries(Error* /*error*/) {
  std::vector<std::string> service_groups;

  // Filter this list down to only entries that correspond
  // to a technology.  (wifi_*, etc)
  for (const auto& group : storage_->GetGroups()) {
    if (TechnologyFromStorageGroup(group) != Technology::kUnknown)
      service_groups.push_back(group);
  }

  return service_groups;
}

bool Profile::AdoptCredentials(const PasspointCredentialsRefPtr& credentials) {
  if (credentials->profile() == this) {
    return false;
  }
  credentials->SetEapSlotGetter(slot_getter_.get());
  credentials->SetProfile(this);
  return credentials->Save(storage_.get()) && storage_->Flush();
}

bool Profile::UpdateDevice(const DeviceRefPtr& device) {
  return false;
}

void Profile::HelpRegisterConstDerivedRpcIdentifiers(
    base::StringPiece name, RpcIdentifiers (Profile::*get)(Error* error)) {
  store_.RegisterDerivedRpcIdentifiers(
      name, RpcIdentifiersAccessor(new CustomAccessor<Profile, RpcIdentifiers>(
                this, get, nullptr)));
}

void Profile::HelpRegisterConstDerivedStrings(base::StringPiece name,
                                              Strings (Profile::*get)(Error*)) {
  store_.RegisterDerivedStrings(
      name, StringsAccessor(
                new CustomAccessor<Profile, Strings>(this, get, nullptr)));
}

void Profile::HelpRegisterDerivedRpcIdentifier(
    base::StringPiece name,
    RpcIdentifier (Profile::*get)(Error*),
    bool (Profile::*set)(const RpcIdentifier&, Error*)) {
  store_.RegisterDerivedRpcIdentifier(
      name, RpcIdentifierAccessor(
                new CustomAccessor<Profile, RpcIdentifier>(this, get, set)));
}

void Profile::HelpRegisterDerivedString(
    base::StringPiece name,
    std::string (Profile::*get)(Error* error),
    bool (Profile::*set)(const std::string&, Error*)) {
  store_.RegisterDerivedString(
      name,
      StringAccessor(new CustomAccessor<Profile, std::string>(this, get, set)));
}

// static
base::FilePath Profile::GetFinalStoragePath(const base::FilePath& storage_dir,
                                            const Identifier& profile_name) {
  base::FilePath base_path;
  if (profile_name.user.empty()) {  // True for DefaultProfiles.
    base_path = storage_dir.Append(
        base::StringPrintf("%s.profile", profile_name.identifier.c_str()));
  } else {
    base_path = storage_dir.Append(
        base::StringPrintf("%s/%s.profile", profile_name.user.c_str(),
                           profile_name.identifier.c_str()));
  }

  // TODO(petkov): Validate the directory permissions, etc.

  return base_path;
}

Metrics* Profile::metrics() const {
  return manager_->metrics();
}

void Profile::Properties::Load(StoreInterface* storage) {
  std::string value;
  if (!storage->GetString(kStorageId, kAlwaysOnVpnModeProperty,
                          &always_on_vpn_mode)) {
    always_on_vpn_mode = kAlwaysOnVpnModeOff;
  }
  if (!storage->GetString(kStorageId, kAlwaysOnVpnServiceProperty,
                          &always_on_vpn_service)) {
    always_on_vpn_service = kDefaultAlwaysOnVpnService;
  }
}

void Profile::Properties::Save(StoreInterface* storage) {
  storage->SetString(kStorageId, kAlwaysOnVpnModeProperty, always_on_vpn_mode);
  storage->SetString(kStorageId, kAlwaysOnVpnServiceProperty,
                     always_on_vpn_service);
}

}  // namespace shill
