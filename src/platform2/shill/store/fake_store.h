// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_FAKE_STORE_H_
#define SHILL_STORE_FAKE_STORE_H_

#include <map>
#include <set>
#include <string>
#include <vector>

#include <brillo/variant_dictionary.h>

#include "shill/store/key_value_store.h"
#include "shill/store/store_interface.h"

namespace shill {

// A Fake implementation of StoreInterface. Useful when a unit test
// for another class ("FooClass") a) does not need to FooClass's use
// of StoreInterface, and b) the FooClass test needs a functional
// store.
class FakeStore : public StoreInterface {
 public:
  FakeStore();
  FakeStore(const FakeStore&) = delete;
  FakeStore& operator=(const FakeStore&) = delete;

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

  void set_writes_fail(bool writes_fail) { writes_fail_ = writes_fail; }

 private:
  template <typename T>
  bool ReadSetting(const std::string& group,
                   const std::string& key,
                   T* out) const;
  template <typename T>
  bool WriteSetting(const std::string& group,
                    const std::string& key,
                    const T& new_value);

  std::map<std::string, brillo::VariantDictionary> group_name_to_settings_;
  std::map<std::string, std::map<std::string, std::string>> pkcs11_strings_;
  bool writes_fail_ = false;
};

}  // namespace shill

#endif  // SHILL_STORE_FAKE_STORE_H_
