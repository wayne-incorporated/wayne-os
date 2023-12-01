// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SLOT_MANAGER_H_
#define CHAPS_SLOT_MANAGER_H_

#include <map>
#include <string>

#include <brillo/secure_blob.h>

#include "pkcs11/cryptoki.h"

namespace chaps {

typedef std::map<CK_MECHANISM_TYPE, CK_MECHANISM_INFO> MechanismMap;
typedef std::map<CK_MECHANISM_TYPE, CK_MECHANISM_INFO>::const_iterator
    MechanismMapIterator;

class Session;

// SlotManager is the interface for a slot manager. This component is
// responsible for maintaining a list of slots and slot information as well as
// maintaining a list of open sessions for each slot. See PKCS #11 v2.20: 6.3
// and 11.5 for details on PKCS #11 slots. See sections 6.7 and 11.6 for details
// on PKCS #11 sessions.
class SlotManager {
 public:
  virtual ~SlotManager() {}
  // Returns the total number of slots available. A slot is identified by zero-
  // based offset. I.e. If there are two slots, 0 and 1 are valid 'slot_id'
  // values. This method should be used to verify slot IDs are valid before
  // using the ID with other methods. This method is not const because
  // implementations may refresh internal slot information when this is called.
  virtual int GetSlotCount() = 0;
  virtual bool IsTokenAccessible(const brillo::SecureBlob& isolate_credential,
                                 int slot_id) const = 0;
  virtual bool IsTokenPresent(const brillo::SecureBlob& isolate_credential,
                              int slot_id) const = 0;
  virtual void GetSlotInfo(const brillo::SecureBlob& isolate_credential,
                           int slot_id,
                           CK_SLOT_INFO* slot_info) const = 0;
  virtual void GetTokenInfo(const brillo::SecureBlob& isolate_credential,
                            int slot_id,
                            CK_TOKEN_INFO* token_info) const = 0;
  virtual const MechanismMap* GetMechanismInfo(
      const brillo::SecureBlob& isolate_credential, int slot_id) const = 0;
  // Opens a new session with the token in the given slot. A token must be
  // present. A new and unique session identifier is returned.
  virtual int OpenSession(const brillo::SecureBlob& isolate_credential,
                          int slot_id,
                          bool is_read_only) = 0;
  virtual bool CloseSession(const brillo::SecureBlob& isolate_credential,
                            int session_id) = 0;
  virtual void CloseAllSessions(const brillo::SecureBlob& isolate_credential,
                                int slot_id) = 0;
  virtual bool GetSession(const brillo::SecureBlob& isolate_credential,
                          int session_id,
                          Session** session) const = 0;
};

}  // namespace chaps

#endif  // CHAPS_SLOT_MANAGER_H_
