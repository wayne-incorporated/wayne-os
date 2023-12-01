// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USER_SESSION_USER_SESSION_MAP_H_
#define CRYPTOHOME_USER_SESSION_USER_SESSION_MAP_H_

#include <stddef.h>

#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/containers/flat_set.h>

#include "cryptohome/credential_verifier.h"
#include "cryptohome/user_session/user_session.h"
#include "cryptohome/username.h"

namespace cryptohome {

// Container for storing user session objects.
// Must be used on single thread and sequence only.
class UserSessionMap final {
 private:
  // Declared here in the beginning to allow us to reference the underlying
  // storage type when defining the iterator.
  using Storage = std::map<Username, std::unique_ptr<UserSession>>;

  // Iterator template that can act as both a regular and const iterator. This
  // wraps the underlying map iterator but exposes the underlying UserSession as
  // a UserSession& or const UserSession&, instead of as a reference to the
  // underlying unique_ptr<UserSession>.
  template <typename UserSessionType>
  class iterator_base {
   public:
    using value_type = std::pair<const Username&, UserSessionType&>;
    using iterator_category = std::forward_iterator_tag;
    using difference_type = Storage::difference_type;
    using pointer = value_type*;
    using reference = value_type&;

    iterator_base(const iterator_base& other) = default;
    iterator_base& operator=(const iterator_base& other) = default;

    iterator_base operator++(int) {
      iterator_base other(*this);
      ++(*this);
      return other;
    }

    iterator_base& operator++() {
      ++iter_;
      return *this;
    }

    value_type operator*() const {
      return value_type(iter_->first, *iter_->second);
    }

    bool operator==(const iterator_base& rhs) const {
      return iter_ == rhs.iter_;
    }
    bool operator!=(const iterator_base& rhs) const { return !(*this == rhs); }

   private:
    friend class UserSessionMap;
    explicit iterator_base(Storage::const_iterator iter) : iter_(iter) {}

    Storage::const_iterator iter_;
  };

 public:
  using iterator = iterator_base<UserSession>;
  using const_iterator = iterator_base<const UserSession>;

  // Class used to forward the registration of credential verifier to a specific
  // user's session, or in the case where that user's session does not (yet)
  // exist to hold on to them until such a session is added.
  class VerifierForwarder {
   public:
    // The stored verifiers, when they are captured within the forwarder.
    // Verifiers are stored by both label and type, with the latter being used
    // for label-less verifiers.
    struct VerifierStorage {
      std::map<std::string, std::unique_ptr<CredentialVerifier>> by_label;
      std::map<AuthFactorType, std::unique_ptr<CredentialVerifier>> by_type;
    };

    VerifierForwarder(Username account_id, UserSessionMap* user_session_map);
    VerifierForwarder(const VerifierForwarder&) = delete;
    VerifierForwarder& operator=(const VerifierForwarder&) = delete;
    ~VerifierForwarder();

    // Reports if a verifier already exists with the given label.
    bool HasVerifier(const std::string& label);

    // Add a new credential verifier using the verifier's label.
    void AddVerifier(std::unique_ptr<CredentialVerifier> verifier);

    // Remove the credential verifier with the given label or type.
    void RemoveVerifier(const std::string& label);
    void RemoveVerifier(AuthFactorType type);

    // Point the forwarder at a UserSession, resolving all outstanding verifier
    // registrations to it.
    void Resolve(UserSession* session);

    // Detach the forwarder from whatever user session it is attached to.
    //
    // Note that this does not extract any existing verifiers from whatever
    // session it is already attached to, and so you cannot use Detach+Resolve
    // to "move" verifiers between sessions. The expectation is that if a user
    // session is terminated then any new session would require fresh verifiers.
    void Detach();

   private:
    // The account ID this forwarder will forward to.
    const Username account_id_;
    // The user session map this forwarder is associated with. This is used to
    // remove the forwarder from the map's internal tracking on destruction.
    UserSessionMap* user_session_map_;
    // A variant containing either the underlying user session, the stored
    // verifiers to be added to the session upon creation. These are stored in a
    // variant because either the verifiers should be directly forwarded to the
    // session, or stored here in the forwarder, but never both.
    std::variant<UserSession*, VerifierStorage> forwarding_destination_;
  };

  UserSessionMap() = default;
  UserSessionMap(const UserSessionMap&) = delete;
  UserSessionMap& operator=(const UserSessionMap&) = delete;

  bool empty() const { return storage_.empty(); }
  size_t size() const { return storage_.size(); }

  iterator begin() { return iterator(storage_.begin()); }
  const_iterator begin() const { return const_iterator(storage_.begin()); }
  iterator end() { return iterator(storage_.end()); }
  const_iterator end() const { return const_iterator(storage_.end()); }

  // Adds the session for the given user. Returns false if the user already has
  // a session.
  bool Add(const Username& account_id, std::unique_ptr<UserSession> session);
  // Removes the session for the given user. Returns false if there was no
  // session for the user.
  bool Remove(const Username& account_id);
  // Returns a session for the given user, or null if there's none.
  UserSession* Find(const Username& account_id);
  const UserSession* Find(const Username& account_id) const;

 private:
  // The underlying UserSession storage.
  Storage storage_;

  // Track any live verifier forwarders. The forwarders will add themselves to
  // this map on construction and remove themselves upon destruction.
  std::map<Username, base::flat_set<VerifierForwarder*>> verifier_forwarders_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_USER_SESSION_USER_SESSION_MAP_H_
