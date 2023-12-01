// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_PROTO_CONVERSION_H_
#define CHAPS_PROTO_CONVERSION_H_

#include <chaps/proto_bindings/ck_structs.pb.h>

#include "chaps/pkcs11/cryptoki.h"

namespace chaps {

EXPORT_SPEC bool ProtoToMechanismInfo(const MechanismInfo& proto,
                                      CK_MECHANISM_INFO* out_info);
EXPORT_SPEC MechanismInfo MechanismInfoToProto(const CK_MECHANISM_INFO* info);

EXPORT_SPEC bool ProtoToSessionInfo(const SessionInfo& proto,
                                    CK_SESSION_INFO* out_info);
EXPORT_SPEC SessionInfo SessionInfoToProto(const CK_SESSION_INFO* info);

EXPORT_SPEC bool ProtoToSlotInfo(const SlotInfo& proto, CK_SLOT_INFO* out_info);
EXPORT_SPEC SlotInfo SlotInfoToProto(const CK_SLOT_INFO* info);

EXPORT_SPEC bool ProtoToTokenInfo(const TokenInfo& proto,
                                  CK_TOKEN_INFO* out_info);
EXPORT_SPEC TokenInfo TokenInfoToProto(const CK_TOKEN_INFO* info);

}  // namespace chaps

#endif  // CHAPS_PROTO_CONVERSION_H_
