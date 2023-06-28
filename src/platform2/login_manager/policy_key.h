// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_POLICY_KEY_H_
#define LOGIN_MANAGER_POLICY_KEY_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/macros.h>

namespace crypto {
class RSAPrivateKey;
}  // namespace crypto

namespace login_manager {
class ChildJobInterface;
class NssUtil;
class SessionManagerService;
class SystemUtils;

// This class holds the device owner's public key.
//
// If there is an owner key on disk, we will load that key, and deny
// attempts to set a new key programmatically.  If there is no key
// present, we will allow the owner's key to be set programmatically,
// and will persist it to disk upon request.  Attempts to set the key
// before on-disk storage has been checked will be denied.
//
// Note: Changes in the format of the owner key might break rollback
// (go/rollback-data-restore). If possible, try to maintain backwards
// compatibility for four release cycles.
class PolicyKey {
 public:
  PolicyKey(const base::FilePath& key_file, NssUtil* nss);
  PolicyKey(const PolicyKey&) = delete;
  PolicyKey& operator=(const PolicyKey&) = delete;

  virtual ~PolicyKey();

  virtual bool Equals(const std::string& key_der) const;
  virtual bool VEquals(const std::vector<uint8_t>& key_der) const;
  virtual bool HaveCheckedDisk() const;
  virtual bool IsPopulated() const;

  // If |key_file_| exists, populate the object with the contents of the file.
  // If the file isn't there, that's ok.
  // Will return false if the file exists and there are errors reading it.
  // If this returns true, call IsPopulated() to tell whether or not data was
  // loaded off of disk.
  virtual bool PopulateFromDiskIfPossible();

  // Load key material from |public_key_der|.
  // We will _deny_ such an attempt if we have not yet checked disk for a key,
  // or if we have already successfully loaded a key from disk.
  virtual bool PopulateFromBuffer(const std::vector<uint8_t>& public_key_der);

  // Load key material from |pair|.
  // We will _deny_ such an attempt if we have not yet checked disk for a key,
  // or if we have already successfully loaded a key from disk.
  virtual bool PopulateFromKeypair(crypto::RSAPrivateKey* pair);

  // Persist |key_| to disk, at |key_file_|.
  // Calling this method before checking for a key on disk is an error.
  // Returns false if |key_file_| already exists, or if there's an error while
  // writing data.
  virtual bool Persist();

  // Load key material from |public_key_der|, as long as |sig| is a valid
  // signature over |public_key_der| with |key_|.
  // We will _deny_ such an attempt if we do not have a key loaded.
  // If you're trying to set a key for the first time, use PopulateFromBuffer()
  virtual bool Rotate(const std::vector<uint8_t>& public_key_der,
                      const std::vector<uint8_t>& signature);

  // THIS IS ONLY INTENDED TO BE USED WHEN THE CURRENTLY REGISTERED KEY HAS BEEN
  // COMPROMISED OR LOST AND WE ARE RECOVERING.
  // Load key material from |public_key_der| into key_.
  virtual bool ClobberCompromisedKey(
      const std::vector<uint8_t>& public_key_der);

  // Verify that |signature| is a valid sha1 w/ RSA signature over the data in
  // |data| with |key_|.
  // Returns false if the sig is invalid, or there's an error.
  virtual bool Verify(const std::vector<uint8_t>& data,
                      const std::vector<uint8_t>& signature);

  // Returned reference will be empty if we haven't populated |key_| yet.
  virtual const std::vector<uint8_t>& public_key_der() const { return key_; }

 private:
  const base::FilePath key_file_;
  bool have_checked_disk_ = false;
  bool have_replaced_ = false;
  std::vector<uint8_t> key_;
  NssUtil* nss_;
  std::unique_ptr<SystemUtils> utils_;
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_POLICY_KEY_H_
