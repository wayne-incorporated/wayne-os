// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_PROFILE_H_
#define SHILL_PROFILE_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/string_piece.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/refptr_types.h"
#include "shill/store/pkcs11_slot_getter.h"
#include "shill/store/property_store.h"
#include "shill/store/store_interface.h"

namespace shill {

class Error;
class Manager;
class Metrics;
class ProfileAdaptorInterface;
class StoreInterface;

class Profile : public base::RefCounted<Profile> {
 public:
  enum InitStorageOption { kOpenExisting, kCreateNew, kCreateOrOpenExisting };
  struct Identifier {
    Identifier() = default;
    explicit Identifier(const std::string& i) : identifier(i) {}
    Identifier(const std::string& u, const std::string& i)
        : user(u), identifier(i) {}
    std::string user;  // Empty for global.
    std::string identifier;
    std::string user_hash;
  };

  // Set of Profile properties to be get/set via PropertyStore calls, provided
  // with helpers to read and save them to persistent storage.
  struct Properties {
    Properties(std::string mode, std::string service)
        : always_on_vpn_mode(mode), always_on_vpn_service(service) {}
    // Describes how the always-on VPN will be handled.
    std::string always_on_vpn_mode;
    // Identifier of the service automatically started when always-on VPN is
    // enabled.
    std::string always_on_vpn_service;

    // Loads properties values from the storage.
    void Load(StoreInterface* storage);
    // Stores properties values to the storage.
    void Save(StoreInterface* storage);
  };

  // Path to the cached list of inserted user profiles to be loaded at
  // startup.
  static const char kUserProfileListPathname[];

  Profile(Manager* manager,
          const Identifier& name,
          const base::FilePath& storage_directory,
          bool connect_to_rpc);
  Profile(const Profile&) = delete;
  Profile& operator=(const Profile&) = delete;

  virtual ~Profile();

  // Set up persistent storage for this Profile.
  bool InitStorage(InitStorageOption storage_option, Error* error);

  // Set up stub storage for this Profile. The data will NOT be
  // persisted. In most cases, you should prefer InitStorage.
  void InitStubStorage();

  // Remove the persistent storage for this Profile.  It is an error to
  // do so while the underlying storage is open via InitStorage() or
  // SetStorageForTest().
  bool RemoveStorage(Error* error);

  virtual std::string GetFriendlyName() const;

  virtual const RpcIdentifier& GetRpcIdentifier() const;

  PropertyStore* mutable_store() { return &store_; }
  const PropertyStore& store() const { return store_; }

  // Set the storage inteface.  This is used for testing purposes.
  void SetStorageForTest(std::unique_ptr<StoreInterface> storage);

  // Begin managing the persistence of |service|.
  // Returns true if |service| is new to this profile and was added,
  // false if the |service| already existed.
  virtual bool AdoptService(const ServiceRefPtr& service);

  // Cease managing the persistence of the Service |service|.
  // Returns true if |service| was found and abandoned, or not found.
  // Returns false if can't be abandoned.
  virtual bool AbandonService(const ServiceRefPtr& service);

  // Clobbers persisted notion of |service| with data from |service|.
  // Returns true if |service| was found and updated, false if not found.
  virtual bool UpdateService(const ServiceRefPtr& service);

  // Ask |service| if it can configure itself from the profile.  If it can,
  // ask |service| to perform the configuration and return true.  If not,
  // return false.
  virtual bool LoadService(const ServiceRefPtr& service);

  // Perform LoadService() on |service|.  If this succeeds, change
  // the service to point at this profile and return true.  If not, return
  // false.
  virtual bool ConfigureService(const ServiceRefPtr& service);

  // Allow the device to configure itself from this profile.  Returns
  // true if the device succeeded in finding its configuration.  If not,
  // return false.
  virtual bool ConfigureDevice(const DeviceRefPtr& device);

  // Remove a named entry from the profile.  This includes detaching
  // any service that uses this profile entry.
  virtual void DeleteEntry(const std::string& entry_name, Error* error);

  // Return a service configured from the given profile entry.
  // Callers must not register the returned service with the Manager or connect
  // it since it might not be in the provider's service list.
  virtual ServiceRefPtr GetServiceFromEntry(const std::string& entry_name,
                                            Error* error);

  // Return whether |service| can configure itself from the profile.
  bool ContainsService(const ServiceConstRefPtr& service);

  RpcIdentifiers EnumerateAvailableServices(Error* error);
  std::vector<std::string> EnumerateEntries(Error* error);

  // Clobbers persisted notion of |device| with data from |device|. Returns true
  // if |device| was found and updated, false otherwise. The base implementation
  // always returns false -- currently devices are persisted only in
  // DefaultProfile.
  virtual bool UpdateDevice(const DeviceRefPtr& device);

  // Start managing the persistence of a set of Passpoint credentials.
  // Returns |true| if the set of credentials has been accepted by the
  // Profile, |false| otherwise (ie if the Profile already own it).
  virtual bool AdoptCredentials(const PasspointCredentialsRefPtr& credentials);

  // Write all in-memory state to disk via |storage_|.
  virtual bool Save();

  // Parses a profile identifier. There're two acceptable forms of the |raw|
  // identifier: "identifier" and "~user/identifier". Both "user" and
  // "identifier" must be suitable for use in a D-Bus object path. Returns true
  // on success.
  static bool ParseIdentifier(const std::string& raw, Identifier* parsed);

  // Returns the composite string identifier for a profile, as would have
  // been used in an argument to Manager::PushProfile() in creating this
  // profile.  It returns a string in the form "identifier", or
  // "~user/identifier" depending on whether this profile has a user
  // component.
  static std::string IdentifierToString(const Identifier& name);

  // Load a list of user profile identifiers from a cache file |path|.
  // The profiles themselves are not loaded.
  static std::vector<Identifier> LoadUserProfileList(
      const base::FilePath& path);

  // Save a list of user profile identifiers |profiles| to a cache file |path|.
  // Returns true if successful, false otherwise.
  static bool SaveUserProfileList(const base::FilePath& path,
                                  const std::vector<ProfileRefPtr>& profiles);

  // Returns whether |name| matches this Profile's |name_|.
  virtual bool MatchesIdentifier(const Identifier& name) const;

  // Returns the username component of the profile identifier.
  const std::string& GetUser() const { return name_.user; }

  // Returns the user_hash component of the profile identifier.
  const std::string& GetUserHash() const { return name_.user_hash; }

  // Returns the always-on VPN configuration.
  virtual bool GetAlwaysOnVpnSettings(std::string* mode, RpcIdentifier* id);

  // Clears the profile always-on VPN configuration.
  virtual void ClearAlwaysOnVpn();

  virtual StoreInterface* GetStorage() { return storage_.get(); }

  Pkcs11SlotGetter* GetSlotGetter() { return slot_getter_.get(); }

  // Returns a read-only copy of the backing storage of the profile.
  virtual const StoreInterface* GetConstStorage() const {
    return storage_.get();
  }

  virtual bool IsDefault() const { return false; }

 protected:
  // Storage group for user wide properties.
  static constexpr char kStorageId[] = "global";
  // Returns the persistent store file path for a Profile with the
  // given |storage_dir| and |profile_name|. Provided as a static
  // method, so that tests can use this logic without having to
  // instantiate a Profile.
  static base::FilePath GetFinalStoragePath(const base::FilePath& storage_dir,
                                            const Identifier& profile_name);

  Metrics* metrics() const;
  Manager* manager() const { return manager_; }
  StoreInterface* storage() { return storage_.get(); }

  const base::FilePath& persistent_profile_path() const {
    return persistent_profile_path_;
  }
  void set_persistent_profile_path(const base::FilePath& path) {
    persistent_profile_path_ = path;
  }

 private:
  friend class ManagerTest;
  friend class ProfileAdaptorInterface;
  friend class ShillProfileFuzz;
  FRIEND_TEST(ManagerTest, CreateDuplicateProfileWithMissingKeyfile);
  FRIEND_TEST(ManagerTest, RemoveProfile);
  FRIEND_TEST(ProfileTest, DeleteEntry);
  FRIEND_TEST(ProfileTest, GetStoragePath);
  FRIEND_TEST(ProfileTest, IsValidIdentifierToken);
  FRIEND_TEST(ProfileTest, GetServiceFromEntry);

  static constexpr char kDefaultAlwaysOnVpnService[] = "";

  static bool IsValidIdentifierToken(const std::string& token);

  void HelpRegisterConstDerivedRpcIdentifiers(
      base::StringPiece name, RpcIdentifiers (Profile::*get)(Error* error));
  void HelpRegisterConstDerivedStrings(base::StringPiece name,
                                       Strings (Profile::*get)(Error* error));
  void HelpRegisterDerivedRpcIdentifier(
      base::StringPiece name,
      RpcIdentifier (Profile::*get)(Error* error),
      bool (Profile::*set)(const RpcIdentifier&, Error*));
  void HelpRegisterDerivedString(base::StringPiece name,
                                 std::string (Profile::*get)(Error* error),
                                 bool (Profile::*set)(const std::string&,
                                                      Error*));
  void OnPropertyChanged(base::StringPiece name);
  std::string DBusGetAlwaysOnVpnMode(Error* error);
  bool DBusSetAlwaysOnVpnMode(const std::string& mode, Error* error);
  RpcIdentifier DBusGetAlwaysOnVpnService(Error* error);
  bool DBusSetAlwaysOnVpnService(const RpcIdentifier& id, Error* error);

  // Data members shared with subclasses via getter/setters above in the
  // protected: section
  Manager* manager_;
  base::FilePath persistent_profile_path_;

  // Properties to be get/set via PropertyStore calls.
  Properties properties_;

  // Shared with |adaptor_| via public getter.
  PropertyStore store_;

  // Properties to be gotten via PropertyStore calls.
  Identifier name_;

  // Allows to get PKCS#11 slot ID related to the profile.
  std::unique_ptr<Pkcs11SlotGetter> slot_getter_;

  // Allows this profile to be backed with on-disk storage.
  std::unique_ptr<StoreInterface> storage_;

  std::unique_ptr<ProfileAdaptorInterface> adaptor_;
};

}  // namespace shill

#endif  // SHILL_PROFILE_H_
