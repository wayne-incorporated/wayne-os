// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_STORE_INTERFACE_H_
#define SHILL_STORE_STORE_INTERFACE_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace shill {

class KeyValueStore;

// An interface to a persistent store implementation.
class StoreInterface {
 public:
  virtual ~StoreInterface() = default;

  // Returns true if the store doesn't exist or is empty.
  virtual bool IsEmpty() const = 0;

  // Opens the store. Returns true on success. The effects of
  // re-opening an open store are undefined. The effects of calling a
  // getter or setter on an unopened store are also undefined.
  virtual bool Open() = 0;

  // Closes the store and flushes it to persistent storage. Returns
  // true on success. Note that the store is considered closed even if
  // Close returns false. The effects of closing and already closed
  // store are undefined.
  virtual bool Close() = 0;

  // Flush current in-memory data to disk.
  virtual bool Flush() = 0;

  // Mark the underlying file store as corrupted, moving the data file
  // to a new filename.  This will prevent the file from being re-opened
  // the next time Open() is called.
  virtual bool MarkAsCorrupted() = 0;

  // Returns a set of all groups contained in the store.
  virtual std::set<std::string> GetGroups() const = 0;

  // Returns the names of all groups that contain the named |key|.
  virtual std::set<std::string> GetGroupsWithKey(
      const std::string& key) const = 0;

  // Returns the names of all groups that contain the named |properties|.
  // Only the Bool, Int and String properties are checked.
  virtual std::set<std::string> GetGroupsWithProperties(
      const KeyValueStore& properties) const = 0;

  // Returns true if the store contains |group|, false otherwise.
  virtual bool ContainsGroup(const std::string& group) const = 0;

  // Deletes |group|:|key|. Returns true on success. Attempting to either delete
  // from a group that doesn't exist or to delete a non-existent key from an
  // existing group will return false.
  virtual bool DeleteKey(const std::string& group, const std::string& key) = 0;

  // Deletes |group|. Returns true on success. Attempting to delete a
  // non-existent group will return false.
  virtual bool DeleteGroup(const std::string& group) = 0;

  // Sets a descriptive header on the key file.
  virtual bool SetHeader(const std::string& header) = 0;

  // Gets a string |value| associated with |group|:|key|. Returns true on
  // success and false on failure (including when |group|:|key| is not present
  // in the store).  It is not an error to pass NULL as |value| to simply
  // test for the presence of this value.
  virtual bool GetString(const std::string& group,
                         const std::string& key,
                         std::string* value) const = 0;

  // Associates |group|:|key| with a string |value|. Returns true on success,
  // false otherwise.
  virtual bool SetString(const std::string& group,
                         const std::string& key,
                         const std::string& value) = 0;

  // Gets a boolean |value| associated with |group|:|key|. Returns true on
  // success and false on failure (including when the |group|:|key| is not
  // present in the store).  It is not an error to pass NULL as |value| to
  // simply test for the presence of this value.

  virtual bool GetBool(const std::string& group,
                       const std::string& key,
                       bool* value) const = 0;

  // Associates |group|:|key| with a boolean |value|. Returns true on success,
  // false otherwise.
  virtual bool SetBool(const std::string& group,
                       const std::string& key,
                       bool value) = 0;

  // Gets a integer |value| associated with |group|:|key|. Returns true on
  // success and false on failure (including when the |group|:|key| is not
  // present in the store).  It is not an error to pass NULL as |value| to
  // simply test for the presence of this value.
  virtual bool GetInt(const std::string& group,
                      const std::string& key,
                      int* value) const = 0;

  // Associates |group|:|key| with an integer |value|. Returns true on success,
  // false otherwise.
  virtual bool SetInt(const std::string& group,
                      const std::string& key,
                      int value) = 0;

  // Gets a 64-bit unsigned integer |value| associated with |group|:|key|.
  // Returns true on success and false on failure (including when the
  // |group|:|key| is not present in the store).  It is not an error to
  // pass NULL as |value| to simply test for the presence of this value.
  virtual bool GetUint64(const std::string& group,
                         const std::string& key,
                         uint64_t* value) const = 0;

  // Associates |group|:|key| with a 64-bit unsigned integer |value|. Returns
  // true on success, false otherwise.
  virtual bool SetUint64(const std::string& group,
                         const std::string& key,
                         uint64_t value) = 0;

  // Gets a 64-bit signed integer |value| associated with |group|:|key|.
  // Returns true on success and false on failure (including when the
  // |group|:|key| is not present in the store).  It is not an error to
  // pass NULL as |value| to simply test for the presence of this value.
  virtual bool GetInt64(const std::string& group,
                        const std::string& key,
                        int64_t* value) const = 0;

  // Associates |group|:|key| with a 64-bit signed integer |value|. Returns
  // true on success, false otherwise.
  virtual bool SetInt64(const std::string& group,
                        const std::string& key,
                        int64_t value) = 0;

  // Gets a string list |value| associated with |group|:|key|. Returns true on
  // success and false on failure (including when |group|:|key| is not present
  // in the store).  It is not an error to pass NULL as |value| to simply test
  // for the presence of this value.
  virtual bool GetStringList(const std::string& group,
                             const std::string& key,
                             std::vector<std::string>* value) const = 0;

  // Associates |group|:|key| with a string list |value|. Returns true on
  // success, false otherwise.
  virtual bool SetStringList(const std::string& group,
                             const std::string& key,
                             const std::vector<std::string>& value) = 0;

  // Gets the string associated with |group|:|plaintext_key|. If that doesn't
  // exist, gets and decrypts string |value| associated with
  // |group|:|deprecated_key|. Returns true on success and false on failure
  // (including when neither |group|:|plaintext_key| nor
  // |group|:|deprecated_key| are present in the store).  It is not an error to
  // pass NULL as |value| to simply test for the presence of this value.
  //
  // For migration from ROT47 to plaintext. New use cases should use GetString.
  // TODO(crbug.com/1084279) Remove after migration is complete.
  virtual bool GetCryptedString(const std::string& group,
                                const std::string& deprecated_key,
                                const std::string& plaintext_key,
                                std::string* value) const = 0;

  // Sets the string associated with |group|:|deprecated_key| with an encrypted
  // value and sets |plaintext_key| with |value|. Returns true on success.
  // For ROT47 compatibility for rollback. See crbug.com/1120161 for details.
  virtual bool SetCryptedString(const std::string& group,
                                const std::string& deprecated_key,
                                const std::string& plaintext_key,
                                const std::string& value) = 0;

  // Gets a Stringmaps |value| associated with |group|:|key|. Returns true on
  // success and false on failure (including when |group|:|key| is not present
  // in the store). It is not an error to pass NULL as |value| to simply test
  // for the presence of this value.
  virtual bool GetStringmaps(
      const std::string& group,
      const std::string& key,
      std::vector<std::map<std::string, std::string>>* value) const = 0;

  // Associates |group|:|key| with a Stringmaps |value|. Returns true on
  // success, false otherwise.
  virtual bool SetStringmaps(
      const std::string& group,
      const std::string& key,
      const std::vector<std::map<std::string, std::string>>& value) = 0;

  // Gets a uint64_t list |value| associated with |group|:|key|. Returns true on
  // success and false on failure (including when |group|:|key| is not present
  // in the store).  It is not an error to pass NULL as |value| to simply test
  // for the presence of this value.
  virtual bool GetUint64List(const std::string& group,
                             const std::string& key,
                             std::vector<uint64_t>* value) const = 0;

  // Associates |group|:|key| with a uint64_t list |value|. Returns true on
  // success, false otherwise.
  virtual bool SetUint64List(const std::string& group,
                             const std::string& key,
                             const std::vector<uint64_t>& value) = 0;

  // The following functions behave similarly with their counterparts, but
  // store the string in PKCS11 store as hardware-wrapped CKO_DATA object
  // instead of in a key file.
  // The PKCS#11 slot used depends on whether the profile of the store is
  // tied to an active user session. If so, it will use the user slot,
  // otherwise system slot is used.
  virtual bool PKCS11SetString(const std::string& group,
                               const std::string& key,
                               const std::string& value) = 0;

  virtual bool PKCS11GetString(const std::string& group,
                               const std::string& key,
                               std::string* value) const = 0;

  virtual bool PKCS11DeleteGroup(const std::string& group) = 0;
};

}  // namespace shill

#endif  // SHILL_STORE_STORE_INTERFACE_H_
