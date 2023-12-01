// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_PENDING_ACTIVATION_STORE_H_
#define SHILL_CELLULAR_PENDING_ACTIVATION_STORE_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

namespace shill {

class StoreInterface;

// PendingActivationStore stores the network activation status for a
// particular SIM. Once an online payment for the activation of a 3GPP
// network is successful, the associated SIM is regarded as pending
// activation and stored in the persistent profile. Once shill knows that
// the activation associated with a particular SIM is successful, it is removed
// from the profile and the cellular service is marked as activated.
class PendingActivationStore {
 public:
  enum State : int {
    // This state indicates that information for a particular SIM was never
    // stored in this database.
    kStateUnknown,
    // This state indicates that an online payment has been made but the modem
    // has not yet been able to register with the network.
    kStatePending,
    // This state indicates that the modem has registered with the network but
    // the network has not yet confirmed that the service has been activated.
    // Currently, shill knows that activation has gone through, when a non-zero
    // MDN has been received OTA.
    kStateActivated,
    kStateMax,
  };

  enum IdentifierType {
    kIdentifierICCID,
    kIdentifierMEID,
  };

  // Constructor performs no initialization.
  PendingActivationStore();
  PendingActivationStore(const PendingActivationStore&) = delete;
  PendingActivationStore& operator=(const PendingActivationStore&) = delete;

  virtual ~PendingActivationStore();

  // Tries to open the underlying store interface from the given file path.
  // Returns false if it fails to open the file.
  //
  // If called more than once on the same instance, the file that was already
  // open will allways be flushed and closed, however it is not guaranteed that
  // the file will always be successfully reopened (technically it should, but
  // it is not guaranteed).
  virtual bool InitStorage(const base::FilePath& storage_path);

  // Returns the activation state for a SIM with the given identifier. A return
  // value of kStateUnknown indicates that the given identifier was not found.
  virtual State GetActivationState(IdentifierType type,
                                   const std::string& identifier) const;

  // Sets the activation state for the given identifier. If an entry for this
  // identifier was not found, a new entry will be created. Returns true on
  // success.
  virtual bool SetActivationState(IdentifierType type,
                                  const std::string& identifier,
                                  State state);

  // Removes the entry for the given identifier from the database. Returns true
  // if the operation was successful. If the identifier did not exist in the
  // database, returns false.
  virtual bool RemoveEntry(IdentifierType type, const std::string& identifier);

 private:
  friend class PendingActivationStoreTest;
  friend class CellularCapability3gppTest;
  FRIEND_TEST(PendingActivationStoreTest, FileInteractions);
  FRIEND_TEST(PendingActivationStoreTest, GetActivationState);
  FRIEND_TEST(PendingActivationStoreTest, RemoveEntry);
  FRIEND_TEST(PendingActivationStoreTest, SetActivationState);

  static const char kIccidGroupId[];
  static const char kMeidGroupId[];
  static const char kStorageFileName[];

  static std::string IdentifierTypeToGroupId(IdentifierType type);

  std::unique_ptr<StoreInterface> storage_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_PENDING_ACTIVATION_STORE_H_
