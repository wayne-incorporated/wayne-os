// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_KEY_FILE_STORE_H_
#define SHILL_STORE_KEY_FILE_STORE_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <chaps/pkcs11/cryptoki.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/store/pkcs11_slot_getter.h"
#include "shill/store/store_interface.h"

namespace shill {

// A key file store implementation of the store interface. See
// https://specifications.freedesktop.org/desktop-entry-spec/latest/ar01s03.html
// for details of the key file format, and
// https://developer.gnome.org/glib/stable/glib-Key-value-file-parser.html
// for details of the GLib API that is being reimplemented here.
// This implementation does not support locales because we do not use locale
// strings and never have.
class KeyFileStore : public StoreInterface {
 public:
  // |slot_getter| is owned by the creator of the store and must outlives this
  // class.
  explicit KeyFileStore(const base::FilePath& path,
                        Pkcs11SlotGetter* slot_getter = nullptr);
  KeyFileStore(const KeyFileStore&) = delete;
  KeyFileStore& operator=(const KeyFileStore&) = delete;

  ~KeyFileStore() override;

  // Inherited from StoreInterface.
  bool IsEmpty() const override;
  bool Open() override;
  bool Close() override;
  bool Flush() override;
  bool MarkAsCorrupted() override;
  std::set<std::string> GetGroups() const override;
  std::set<std::string> GetGroupsWithKey(const std::string& key) const override;
  std::set<std::string> GetGroupsWithProperties(
      const KeyValueStore& properties) const override;
  bool ContainsGroup(const std::string& group) const override;
  bool DeleteKey(const std::string& group, const std::string& key) override;
  bool DeleteGroup(const std::string& group) override;
  bool SetHeader(const std::string& header) override;
  bool GetString(const std::string& group,
                 const std::string& key,
                 std::string* value) const override;
  bool SetString(const std::string& group,
                 const std::string& key,
                 const std::string& value) override;
  bool GetBool(const std::string& group,
               const std::string& key,
               bool* value) const override;
  bool SetBool(const std::string& group,
               const std::string& key,
               bool value) override;
  bool GetInt(const std::string& group,
              const std::string& key,
              int* value) const override;
  bool SetInt(const std::string& group,
              const std::string& key,
              int value) override;
  bool GetUint64(const std::string& group,
                 const std::string& key,
                 uint64_t* value) const override;
  bool SetUint64(const std::string& group,
                 const std::string& key,
                 uint64_t value) override;
  bool GetInt64(const std::string& group,
                const std::string& key,
                int64_t* value) const override;
  bool SetInt64(const std::string& group,
                const std::string& key,
                int64_t value) override;
  bool GetStringList(const std::string& group,
                     const std::string& key,
                     std::vector<std::string>* value) const override;
  bool SetStringList(const std::string& group,
                     const std::string& key,
                     const std::vector<std::string>& value) override;
  bool GetCryptedString(const std::string& group,
                        const std::string& deprecated_key,
                        const std::string& plaintext_key,
                        std::string* value) const override;
  bool SetCryptedString(const std::string& group,
                        const std::string& deprecated_key,
                        const std::string& plaintext_key,
                        const std::string& value) override;
  bool GetStringmaps(
      const std::string& group,
      const std::string& key,
      std::vector<std::map<std::string, std::string>>* value) const override;
  bool SetStringmaps(
      const std::string& group,
      const std::string& key,
      const std::vector<std::map<std::string, std::string>>& value) override;
  bool GetUint64List(const std::string& group,
                     const std::string& key,
                     std::vector<uint64_t>* value) const override;
  bool SetUint64List(const std::string& group,
                     const std::string& key,
                     const std::vector<uint64_t>& value) override;
  bool PKCS11SetString(const std::string& group,
                       const std::string& key,
                       const std::string& value) override;
  bool PKCS11GetString(const std::string& group,
                       const std::string& key,
                       std::string* value) const override;
  bool PKCS11DeleteGroup(const std::string& group) override;

 private:
  FRIEND_TEST(KeyFileStoreTest, OpenClose);
  FRIEND_TEST(KeyFileStoreTest, OpenFail);

  class KeyFile;

  static const char kCorruptSuffix[];

  bool DoesGroupMatchProperties(const std::string& group,
                                const KeyValueStore& properties) const;

  std::unique_ptr<KeyFile> key_file_;
  const base::FilePath path_;
  Pkcs11SlotGetter* slot_getter_;
};

// Creates a store, implementing StoreInterface, at the specified |path|.
std::unique_ptr<StoreInterface> CreateStore(
    const base::FilePath& path, Pkcs11SlotGetter* slot_getter = nullptr);

}  // namespace shill

#endif  // SHILL_STORE_KEY_FILE_STORE_H_
