// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is GENERATED and do not modify it manually.
// To reproduce the generation process, run
// //src/platform2/libhwsec/overalls/gen_overalls.py with arguments as:
// --filter-by-usage

#ifndef LIBHWSEC_OVERALLS_MOCK_OVERALLS_H_
#define LIBHWSEC_OVERALLS_MOCK_OVERALLS_H_

#include <base/logging.h>
#include <gmock/gmock.h>
#include "libhwsec/overalls/overalls.h"

namespace hwsec {
namespace overalls {

class MockOveralls : public Overalls {
 public:
  MockOveralls() = default;
  ~MockOveralls() override = default;
  MOCK_METHOD3(Orspi_UnloadBlob_UINT32, void(UINT64*, UINT32*, BYTE*));
  MOCK_METHOD4(Orspi_UnloadBlob_UINT32_s,
               TSS_RESULT(UINT64*, UINT32*, BYTE*, UINT64));
  MOCK_METHOD3(Orspi_UnloadBlob_UINT16, void(UINT64*, UINT16*, BYTE*));
  MOCK_METHOD4(Orspi_UnloadBlob_UINT16_s,
               TSS_RESULT(UINT64*, UINT16*, BYTE*, UINT64));
  MOCK_METHOD4(Orspi_UnloadBlob_RSA_KEY_PARMS_s,
               TSS_RESULT(UINT64*, BYTE*, UINT64, TCPA_RSA_KEY_PARMS*));
  MOCK_METHOD3(Orspi_UnloadBlob_PCR_SELECTION,
               TSS_RESULT(UINT64*, BYTE*, TCPA_PCR_SELECTION*));
  MOCK_METHOD4(Orspi_UnloadBlob_PUBKEY_s,
               TSS_RESULT(UINT64*, BYTE*, UINT64, TCPA_PUBKEY*));
  MOCK_METHOD4(Orspi_UnloadBlob_KEY12_s,
               TSS_RESULT(UINT64*, BYTE*, UINT64, TPM_KEY12*));
  MOCK_METHOD3(Orspi_UnloadBlob_SYMMETRIC_KEY,
               TSS_RESULT(UINT64*, BYTE*, TCPA_SYMMETRIC_KEY*));
  MOCK_METHOD3(Orspi_UnloadBlob_IDENTITY_REQ,
               TSS_RESULT(UINT64*, BYTE*, TCPA_IDENTITY_REQ*));
  MOCK_METHOD3(Orspi_UnloadBlob_IDENTITY_PROOF,
               TSS_RESULT(UINT64*, BYTE*, TCPA_IDENTITY_PROOF*));
  MOCK_METHOD3(Orspi_UnloadBlob_CERTIFY_INFO,
               TSS_RESULT(UINT64*, BYTE*, TPM_CERTIFY_INFO*));
  MOCK_METHOD3(Orspi_UnloadBlob_TPM_DELEGATE_OWNER_BLOB,
               TSS_RESULT(UINT64*, BYTE*, TPM_DELEGATE_OWNER_BLOB*));
  MOCK_METHOD4(Orspi_UnloadBlob_TPM_DELEGATE_OWNER_BLOB_s,
               TSS_RESULT(UINT64*, BYTE*, UINT64, TPM_DELEGATE_OWNER_BLOB*));
  MOCK_METHOD4(Orspi_UnloadBlob_CAP_VERSION_INFO_s,
               TSS_RESULT(UINT64*, BYTE*, UINT64, TPM_CAP_VERSION_INFO*));
  MOCK_METHOD3(Orspi_UnloadBlob_NV_DATA_PUBLIC,
               TSS_RESULT(UINT64*, BYTE*, TPM_NV_DATA_PUBLIC*));
  MOCK_METHOD4(Orspi_UnloadBlob_NV_DATA_PUBLIC_s,
               TSS_RESULT(UINT64*, BYTE*, UINT64, TPM_NV_DATA_PUBLIC*));
  MOCK_METHOD4(Orspi_UnloadBlob_DA_INFO_s,
               TSS_RESULT(UINT64*, BYTE*, UINT64, TPM_DA_INFO*));
  MOCK_METHOD3(Orspi_LoadBlob_UINT32, void(UINT64*, UINT32, BYTE*));
  MOCK_METHOD3(Orspi_LoadBlob_UINT16, void(UINT64*, UINT16, BYTE*));
  MOCK_METHOD3(Orspi_LoadBlob_BYTE, void(UINT64*, BYTE, BYTE*));
  MOCK_METHOD3(Orspi_LoadBlob_RSA_KEY_PARMS,
               void(UINT64*, BYTE*, TCPA_RSA_KEY_PARMS*));
  MOCK_METHOD3(Orspi_LoadBlob_PCR_INFO_SHORT,
               void(UINT64*, BYTE*, TPM_PCR_INFO_SHORT*));
  MOCK_METHOD3(Orspi_LoadBlob_PUBKEY, void(UINT64*, BYTE*, TCPA_PUBKEY*));
  MOCK_METHOD3(Orspi_LoadBlob_KEY12, void(UINT64*, BYTE*, TPM_KEY12*));
  MOCK_METHOD3(Orspi_LoadBlob_SYM_CA_ATTESTATION,
               void(UINT64*, BYTE*, TCPA_SYM_CA_ATTESTATION*));
  MOCK_METHOD3(Orspi_LoadBlob_ASYM_CA_CONTENTS,
               void(UINT64*, BYTE*, TCPA_ASYM_CA_CONTENTS*));
  MOCK_METHOD3(Orspi_LoadBlob_MSA_COMPOSITE,
               void(UINT64*, BYTE*, TPM_MSA_COMPOSITE*));
  MOCK_METHOD8(
      Orspi_SymDecrypt,
      TSS_RESULT(UINT16, UINT16, BYTE*, BYTE*, BYTE*, UINT32, BYTE*, UINT32*));
  MOCK_METHOD5(Orspi_MGF1, TSS_RESULT(UINT32, UINT32, BYTE*, UINT32, BYTE*));
  MOCK_METHOD2(Orspi_Native_To_UNICODE, BYTE*(BYTE*, unsigned*));
  MOCK_METHOD1(Orspi_Error_String, char*(TSS_RESULT));
  MOCK_METHOD4(Ospi_SetAttribUint32,
               TSS_RESULT(TSS_HOBJECT, TSS_FLAG, TSS_FLAG, UINT32));
  MOCK_METHOD4(Ospi_GetAttribUint32,
               TSS_RESULT(TSS_HOBJECT, TSS_FLAG, TSS_FLAG, UINT32*));
  MOCK_METHOD5(Ospi_SetAttribData,
               TSS_RESULT(TSS_HOBJECT, TSS_FLAG, TSS_FLAG, UINT32, BYTE*));
  MOCK_METHOD5(Ospi_GetAttribData,
               TSS_RESULT(TSS_HOBJECT, TSS_FLAG, TSS_FLAG, UINT32*, BYTE**));
  MOCK_METHOD3(Ospi_ChangeAuth,
               TSS_RESULT(TSS_HOBJECT, TSS_HOBJECT, TSS_HPOLICY));
  MOCK_METHOD3(Ospi_GetPolicyObject,
               TSS_RESULT(TSS_HOBJECT, TSS_FLAG, TSS_HPOLICY*));
  MOCK_METHOD1(Ospi_Context_Create, TSS_RESULT(TSS_HCONTEXT*));
  MOCK_METHOD1(Ospi_Context_Close, TSS_RESULT(TSS_HCONTEXT));
  MOCK_METHOD2(Ospi_Context_Connect, TSS_RESULT(TSS_HCONTEXT, TSS_UNICODE*));
  MOCK_METHOD2(Ospi_Context_FreeMemory, TSS_RESULT(TSS_HCONTEXT, BYTE*));
  MOCK_METHOD2(Ospi_Context_GetDefaultPolicy,
               TSS_RESULT(TSS_HCONTEXT, TSS_HPOLICY*));
  MOCK_METHOD4(Ospi_Context_CreateObject,
               TSS_RESULT(TSS_HCONTEXT, TSS_FLAG, TSS_FLAG, TSS_HOBJECT*));
  MOCK_METHOD2(Ospi_Context_CloseObject, TSS_RESULT(TSS_HCONTEXT, TSS_HOBJECT));
  MOCK_METHOD2(Ospi_Context_GetTpmObject, TSS_RESULT(TSS_HCONTEXT, TSS_HTPM*));
  MOCK_METHOD5(Ospi_Context_LoadKeyByBlob,
               TSS_RESULT(TSS_HCONTEXT, TSS_HKEY, UINT32, BYTE*, TSS_HKEY*));
  MOCK_METHOD4(Ospi_Context_LoadKeyByUUID,
               TSS_RESULT(TSS_HCONTEXT, TSS_FLAG, TSS_UUID, TSS_HKEY*));
  MOCK_METHOD4(Ospi_Policy_SetSecret,
               TSS_RESULT(TSS_HPOLICY, TSS_FLAG, UINT32, BYTE*));
  MOCK_METHOD2(Ospi_Policy_AssignToObject,
               TSS_RESULT(TSS_HPOLICY, TSS_HOBJECT));
  MOCK_METHOD3(Ospi_TPM_CreateEndorsementKey,
               TSS_RESULT(TSS_HTPM, TSS_HKEY, TSS_VALIDATION*));
  MOCK_METHOD4(Ospi_TPM_GetPubEndorsementKey,
               TSS_RESULT(TSS_HTPM, TSS_BOOL, TSS_VALIDATION*, TSS_HKEY*));
  MOCK_METHOD3(Ospi_TPM_TakeOwnership,
               TSS_RESULT(TSS_HTPM, TSS_HKEY, TSS_HKEY));
  MOCK_METHOD9(Ospi_TPM_CollateIdentityRequest,
               TSS_RESULT(TSS_HTPM,
                          TSS_HKEY,
                          TSS_HKEY,
                          UINT32,
                          BYTE*,
                          TSS_HKEY,
                          TSS_ALGORITHM_ID,
                          UINT32*,
                          BYTE**));
  MOCK_METHOD8(
      Ospi_TPM_ActivateIdentity,
      TSS_RESULT(
          TSS_HTPM, TSS_HKEY, UINT32, BYTE*, UINT32, BYTE*, UINT32*, BYTE**));
  MOCK_METHOD3(Ospi_TPM_SetStatus, TSS_RESULT(TSS_HTPM, TSS_FLAG, TSS_BOOL));
  MOCK_METHOD3(Ospi_TPM_GetStatus, TSS_RESULT(TSS_HTPM, TSS_FLAG, TSS_BOOL*));
  MOCK_METHOD5(Ospi_TPM_FieldUpgrade,
               TSS_RESULT(TSS_HTPM, UINT32, BYTE*, UINT32*, BYTE**));
  MOCK_METHOD6(Ospi_TPM_GetCapability,
               TSS_RESULT(TSS_HTPM, TSS_FLAG, UINT32, BYTE*, UINT32*, BYTE**));
  MOCK_METHOD3(Ospi_TPM_GetRandom, TSS_RESULT(TSS_HTPM, UINT32, BYTE**));
  MOCK_METHOD3(Ospi_TPM_StirRandom, TSS_RESULT(TSS_HTPM, UINT32, BYTE*));
  MOCK_METHOD4(Ospi_TPM_Quote,
               TSS_RESULT(TSS_HTPM, TSS_HKEY, TSS_HPCRS, TSS_VALIDATION*));
  MOCK_METHOD7(
      Ospi_TPM_PcrExtend,
      TSS_RESULT(
          TSS_HTPM, UINT32, UINT32, BYTE*, TSS_PCR_EVENT*, UINT32*, BYTE**));
  MOCK_METHOD4(Ospi_TPM_PcrRead, TSS_RESULT(TSS_HTPM, UINT32, UINT32*, BYTE**));
  MOCK_METHOD5(
      Ospi_TPM_AuthorizeMigrationTicket,
      TSS_RESULT(TSS_HTPM, TSS_HKEY, TSS_MIGRATE_SCHEME, UINT32*, BYTE**));
  MOCK_METHOD2(Ospi_TPM_CMKApproveMA, TSS_RESULT(TSS_HTPM, TSS_HMIGDATA));
  MOCK_METHOD3(Ospi_TPM_CMKCreateTicket,
               TSS_RESULT(TSS_HTPM, TSS_HKEY, TSS_HMIGDATA));
  MOCK_METHOD3(Ospi_TPM_Delegate_AddFamily,
               TSS_RESULT(TSS_HTPM, BYTE, TSS_HDELFAMILY*));
  MOCK_METHOD6(Ospi_TPM_Delegate_CreateDelegation,
               TSS_RESULT(TSS_HOBJECT,
                          BYTE,
                          UINT32,
                          TSS_HPCRS,
                          TSS_HDELFAMILY,
                          TSS_HPOLICY));
  MOCK_METHOD2(Ospi_PcrComposite_SelectPcrIndex, TSS_RESULT(TSS_HPCRS, UINT32));
  MOCK_METHOD4(Ospi_PcrComposite_SetPcrValue,
               TSS_RESULT(TSS_HPCRS, UINT32, UINT32, BYTE*));
  MOCK_METHOD4(Ospi_PcrComposite_GetPcrValue,
               TSS_RESULT(TSS_HPCRS, UINT32, UINT32*, BYTE**));
  MOCK_METHOD2(Ospi_PcrComposite_SetPcrLocality, TSS_RESULT(TSS_HPCRS, UINT32));
  MOCK_METHOD2(Ospi_Key_LoadKey, TSS_RESULT(TSS_HKEY, TSS_HKEY));
  MOCK_METHOD1(Ospi_Key_UnloadKey, TSS_RESULT(TSS_HKEY));
  MOCK_METHOD3(Ospi_Key_GetPubKey, TSS_RESULT(TSS_HKEY, UINT32*, BYTE**));
  MOCK_METHOD3(Ospi_Key_CertifyKey,
               TSS_RESULT(TSS_HKEY, TSS_HKEY, TSS_VALIDATION*));
  MOCK_METHOD3(Ospi_Key_CreateKey, TSS_RESULT(TSS_HKEY, TSS_HKEY, TSS_HPCRS));
  MOCK_METHOD3(Ospi_Key_WrapKey, TSS_RESULT(TSS_HKEY, TSS_HKEY, TSS_HPCRS));
  MOCK_METHOD5(Ospi_Key_CMKCreateBlob,
               TSS_RESULT(TSS_HKEY, TSS_HKEY, TSS_HMIGDATA, UINT32*, BYTE**));
  MOCK_METHOD4(Ospi_Hash_Sign,
               TSS_RESULT(TSS_HHASH, TSS_HKEY, UINT32*, BYTE**));
  MOCK_METHOD3(Ospi_Hash_SetHashValue, TSS_RESULT(TSS_HHASH, UINT32, BYTE*));
  MOCK_METHOD4(Ospi_Data_Bind,
               TSS_RESULT(TSS_HENCDATA, TSS_HKEY, UINT32, BYTE*));
  MOCK_METHOD4(Ospi_Data_Unbind,
               TSS_RESULT(TSS_HENCDATA, TSS_HKEY, UINT32*, BYTE**));
  MOCK_METHOD5(Ospi_Data_Seal,
               TSS_RESULT(TSS_HENCDATA, TSS_HKEY, UINT32, BYTE*, TSS_HPCRS));
  MOCK_METHOD4(Ospi_Data_Unseal,
               TSS_RESULT(TSS_HENCDATA, TSS_HKEY, UINT32*, BYTE**));
  MOCK_METHOD3(Ospi_NV_DefineSpace,
               TSS_RESULT(TSS_HNVSTORE, TSS_HPCRS, TSS_HPCRS));
  MOCK_METHOD1(Ospi_NV_ReleaseSpace, TSS_RESULT(TSS_HNVSTORE));
  MOCK_METHOD4(Ospi_NV_WriteValue,
               TSS_RESULT(TSS_HNVSTORE, UINT32, UINT32, BYTE*));
  MOCK_METHOD4(Ospi_NV_ReadValue,
               TSS_RESULT(TSS_HNVSTORE, UINT32, UINT32*, BYTE**));
  MOCK_METHOD2(Ospi_Context_SecureFreeMemory, TSS_RESULT(TSS_HCONTEXT, BYTE*));
};

}  // namespace overalls
}  // namespace hwsec

#endif  // LIBHWSEC_OVERALLS_MOCK_OVERALLS_H_
