// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_STUB_STORAGE_H_
#define SHILL_STORE_STUB_STORAGE_H_

#include <map>
#include <set>
#include <string>
#include <vector>

#include "shill/store/store_interface.h"

namespace shill {

// A stub implementation of StoreInterface.
class StubStorage : public StoreInterface {
 public:
  ~StubStorage() override = default;

  bool IsEmpty() const override { return true; }
  bool Open() override { return false; }
  bool Close() override { return false; }
  bool Flush() override { return false; }
  bool MarkAsCorrupted() override { return false; }
  std::set<std::string> GetGroups() const override { return {}; }
  std::set<std::string> GetGroupsWithKey(
      const std::string& key) const override {
    return {};
  }
  std::set<std::string> GetGroupsWithProperties(
      const KeyValueStore& properties) const override {
    return {};
  }
  bool ContainsGroup(const std::string& group) const override { return false; }
  bool DeleteKey(const std::string& group, const std::string& key) override {
    return false;
  }
  bool DeleteGroup(const std::string& group) override { return false; }
  bool SetHeader(const std::string& header) override { return false; }
  bool GetString(const std::string& group,
                 const std::string& key,
                 std::string* value) const override {
    return false;
  }
  bool SetString(const std::string& group,
                 const std::string& key,
                 const std::string& value) override {
    return false;
  }
  bool GetBool(const std::string& group,
               const std::string& key,
               bool* value) const override {
    return false;
  }
  bool SetBool(const std::string& group,
               const std::string& key,
               bool value) override {
    return false;
  }
  bool GetInt(const std::string& group,
              const std::string& key,
              int* value) const override {
    return false;
  }
  bool SetInt(const std::string& group,
              const std::string& key,
              int value) override {
    return false;
  }
  bool GetUint64(const std::string& group,
                 const std::string& key,
                 uint64_t* value) const override {
    return false;
  }
  bool SetUint64(const std::string& group,
                 const std::string& key,
                 uint64_t value) override {
    return false;
  }
  bool GetInt64(const std::string& group,
                const std::string& key,
                int64_t* value) const override {
    return false;
  }
  bool SetInt64(const std::string& group,
                const std::string& key,
                int64_t value) override {
    return false;
  }
  bool GetStringList(const std::string& group,
                     const std::string& key,
                     std::vector<std::string>* value) const override {
    return false;
  }
  bool SetStringList(const std::string& group,
                     const std::string& key,
                     const std::vector<std::string>& value) override {
    return false;
  }
  bool GetCryptedString(const std::string& group,
                        const std::string& deprecated_key,
                        const std::string& plaintext_key,
                        std::string* value) const override {
    return false;
  }
  bool SetCryptedString(const std::string& group,
                        const std::string& deprecated_key,
                        const std::string& plaintext_key,
                        const std::string& value) override {
    return false;
  }
  bool GetStringmaps(
      const std::string& group,
      const std::string& key,
      std::vector<std::map<std::string, std::string>>* value) const override {
    return false;
  }
  bool SetStringmaps(
      const std::string& group,
      const std::string& key,
      const std::vector<std::map<std::string, std::string>>& value) override {
    return false;
  }
  bool GetUint64List(const std::string& group,
                     const std::string& key,
                     std::vector<uint64_t>* value) const override {
    return false;
  }
  bool SetUint64List(const std::string& group,
                     const std::string& key,
                     const std::vector<uint64_t>& value) override {
    return false;
  }
  bool PKCS11SetString(const std::string& group,
                       const std::string& key,
                       const std::string& value) override {
    return false;
  }
  bool PKCS11GetString(const std::string& group,
                       const std::string& key,
                       std::string* value) const override {
    return false;
  }
  bool PKCS11DeleteGroup(const std::string& group) override { return false; }
};

}  // namespace shill

#endif  // SHILL_STORE_STUB_STORAGE_H_
