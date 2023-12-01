// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_DBUS_BINDINGS_CONSTANTS_H_
#define CHAPS_DBUS_BINDINGS_CONSTANTS_H_

namespace chaps {
// chaps
inline constexpr char kChapsInterface[] = "org.chromium.Chaps";
inline constexpr char kChapsServicePath[] = "/org/chromium/Chaps";
inline constexpr char kChapsServiceName[] = "org.chromium.Chaps";
// Methods exposed by chaps.
inline constexpr char kOpenIsolateMethod[] = "OpenIsolate";
inline constexpr char kCloseIsolateMethod[] = "CloseIsolate";
inline constexpr char kLoadTokenMethod[] = "LoadToken";
inline constexpr char kUnloadTokenMethod[] = "UnloadToken";
inline constexpr char kGetTokenPathMethod[] = "GetTokenPath";
inline constexpr char kSetLogLevelMethod[] = "SetLogLevel";
inline constexpr char kGetSlotListMethod[] = "GetSlotList";
inline constexpr char kGetSlotInfoMethod[] = "GetSlotInfo";
inline constexpr char kGetTokenInfoMethod[] = "GetTokenInfo";
inline constexpr char kGetMechanismListMethod[] = "GetMechanismList";
inline constexpr char kGetMechanismInfoMethod[] = "GetMechanismInfo";
inline constexpr char kInitTokenMethod[] = "InitToken";
inline constexpr char kInitPINMethod[] = "InitPIN";
inline constexpr char kSetPINMethod[] = "SetPIN";
inline constexpr char kOpenSessionMethod[] = "OpenSession";
inline constexpr char kCloseSessionMethod[] = "CloseSession";
inline constexpr char kGetSessionInfoMethod[] = "GetSessionInfo";
inline constexpr char kGetOperationStateMethod[] = "GetOperationState";
inline constexpr char kSetOperationStateMethod[] = "SetOperationState";
inline constexpr char kLoginMethod[] = "Login";
inline constexpr char kLogoutMethod[] = "Logout";
inline constexpr char kCreateObjectMethod[] = "CreateObject";
inline constexpr char kCopyObjectMethod[] = "CopyObject";
inline constexpr char kDestroyObjectMethod[] = "DestroyObject";
inline constexpr char kGetObjectSizeMethod[] = "GetObjectSize";
inline constexpr char kGetAttributeValueMethod[] = "GetAttributeValue";
inline constexpr char kSetAttributeValueMethod[] = "SetAttributeValue";
inline constexpr char kFindObjectsInitMethod[] = "FindObjectsInit";
inline constexpr char kFindObjectsMethod[] = "FindObjects";
inline constexpr char kFindObjectsFinalMethod[] = "FindObjectsFinal";
inline constexpr char kEncryptInitMethod[] = "EncryptInit";
inline constexpr char kEncryptMethod[] = "Encrypt";
inline constexpr char kEncryptUpdateMethod[] = "EncryptUpdate";
inline constexpr char kEncryptFinalMethod[] = "EncryptFinal";
inline constexpr char kEncryptCancelMethod[] = "EncryptCancel";
inline constexpr char kDecryptInitMethod[] = "DecryptInit";
inline constexpr char kDecryptMethod[] = "Decrypt";
inline constexpr char kDecryptUpdateMethod[] = "DecryptUpdate";
inline constexpr char kDecryptFinalMethod[] = "DecryptFinal";
inline constexpr char kDecryptCancelMethod[] = "DecryptCancel";
inline constexpr char kDigestInitMethod[] = "DigestInit";
inline constexpr char kDigestMethod[] = "Digest";
inline constexpr char kDigestUpdateMethod[] = "DigestUpdate";
inline constexpr char kDigestKeyMethod[] = "DigestKey";
inline constexpr char kDigestFinalMethod[] = "DigestFinal";
inline constexpr char kDigestCancelMethod[] = "DigestCancel";
inline constexpr char kSignInitMethod[] = "SignInit";
inline constexpr char kSignMethod[] = "Sign";
inline constexpr char kSignUpdateMethod[] = "SignUpdate";
inline constexpr char kSignFinalMethod[] = "SignFinal";
inline constexpr char kSignCancelMethod[] = "SignCancel";
inline constexpr char kSignRecoverInitMethod[] = "SignRecoverInit";
inline constexpr char kSignRecoverMethod[] = "SignRecover";
inline constexpr char kVerifyInitMethod[] = "VerifyInit";
inline constexpr char kVerifyMethod[] = "Verify";
inline constexpr char kVerifyUpdateMethod[] = "VerifyUpdate";
inline constexpr char kVerifyFinalMethod[] = "VerifyFinal";
inline constexpr char kVerifyCancelMethod[] = "VerifyCancel";
inline constexpr char kVerifyRecoverInitMethod[] = "VerifyRecoverInit";
inline constexpr char kVerifyRecoverMethod[] = "VerifyRecover";
inline constexpr char kDigestEncryptUpdateMethod[] = "DigestEncryptUpdate";
inline constexpr char kDecryptDigestUpdateMethod[] = "DecryptDigestUpdate";
inline constexpr char kSignEncryptUpdateMethod[] = "SignEncryptUpdate";
inline constexpr char kDecryptVerifyUpdateMethod[] = "DecryptVerifyUpdate";
inline constexpr char kGenerateKeyMethod[] = "GenerateKey";
inline constexpr char kGenerateKeyPairMethod[] = "GenerateKeyPair";
inline constexpr char kWrapKeyMethod[] = "WrapKey";
inline constexpr char kUnwrapKeyMethod[] = "UnwrapKey";
inline constexpr char kDeriveKeyMethod[] = "DeriveKey";
inline constexpr char kSeedRandomMethod[] = "SeedRandom";
inline constexpr char kGenerateRandomMethod[] = "GenerateRandom";
}  // namespace chaps

#endif  // CHAPS_DBUS_BINDINGS_CONSTANTS_H_
