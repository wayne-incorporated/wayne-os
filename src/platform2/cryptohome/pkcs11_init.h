// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Pkcs11Init - Class for handling PKCS #11 initialization.  Since the move to
// Chaps, this class does very little.  The loading / unloading of tokens is
// handled in mount.cc.

#ifndef CRYPTOHOME_PKCS11_INIT_H_
#define CRYPTOHOME_PKCS11_INIT_H_

#include <sys/types.h>

#include <string>

#include <base/files/file_path.h>
#include <chaps/pkcs11/cryptoki.h>

#include "cryptohome/username.h"

namespace cryptohome {

class Pkcs11Init {
 public:
  Pkcs11Init();
  Pkcs11Init(const Pkcs11Init&) = delete;
  Pkcs11Init& operator=(const Pkcs11Init&) = delete;

  virtual ~Pkcs11Init();

  virtual void GetTpmTokenInfo(std::string* OUT_label,
                               std::string* OUT_user_pin);

  virtual void GetTpmTokenInfoForUser(const Username& username,
                                      std::string* OUT_label,
                                      std::string* OUT_user_pin);

  // Returns the same label as GetTpmTokenInfoForUser.
  virtual std::string GetTpmTokenLabelForUser(const Username& username);

  // Gets the tpm token |slot| for the given |path|.  If no slot is found,
  // returns false.
  virtual bool GetTpmTokenSlotForPath(const base::FilePath& path,
                                      CK_SLOT_ID_PTR slot);

  // Check if the user's PKCS #11 token is valid.
  virtual bool IsUserTokenOK();

  // Check if the system PKCS #11 token is valid.
  virtual bool IsSystemTokenOK();

  static constexpr char kDefaultPin[] = "111111";
  static constexpr char kDefaultSystemLabel[] = "System TPM Token";
  static constexpr char kDefaultUserLabelPrefix[] = "User TPM Token ";

 private:
  // Returns true if a token in the given |slot_id| passes basic validity
  // checks. This includes checking if the |expected_label_prefix| matches the
  // actual token label.
  bool CheckTokenInSlot(CK_SLOT_ID slot_id,
                        const std::string& expected_label_prefix);
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_PKCS11_INIT_H_
