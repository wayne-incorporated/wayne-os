// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is GENERATED and do not modify it manually.
// To reproduce the generation process, run
// //src/platform2/libhwsec/overalls/gen_overalls.py with arguments as:
// --filter-by-usage

#ifndef LIBHWSEC_OVERALLS_OVERALLS_H_
#define LIBHWSEC_OVERALLS_OVERALLS_H_

#include <trousers/trousers.h>
#include <trousers/tss.h>

#include "libhwsec/tss_utils/extended_apis.h"

namespace hwsec {
namespace overalls {

// |Overalls| wraps trousers API (including Tspi and Trspi family), with the
// wrapper API name being the trousers API names of which the first "T" replaced
// by "O". For example, |Overalls::Ospi_Context_Create| calls
// |Tspi_Context_Create|.
//
// The purpose of this wrapper class is to make trousers APIs to be mock-able so
// we can enable the callers of trouser to be unittested in googletest
// framework.
class Overalls {
 public:
  Overalls() = default;
  virtual ~Overalls() = default;
  virtual void Orspi_UnloadBlob_UINT32(UINT64* offset,
                                       UINT32* out,
                                       BYTE* blob) {
    return Trspi_UnloadBlob_UINT32(offset, out, blob);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_UINT32_s(UINT64* offset,
                                               UINT32* out,
                                               BYTE* blob,
                                               UINT64 capacity) {
    return Trspi_UnloadBlob_UINT32_s(offset, out, blob, capacity);
  }
  virtual void Orspi_UnloadBlob_UINT16(UINT64* offset,
                                       UINT16* out,
                                       BYTE* blob) {
    return Trspi_UnloadBlob_UINT16(offset, out, blob);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_UINT16_s(UINT64* offset,
                                               UINT16* out,
                                               BYTE* blob,
                                               UINT64 capacity) {
    return Trspi_UnloadBlob_UINT16_s(offset, out, blob, capacity);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_RSA_KEY_PARMS_s(
      UINT64* offset, BYTE* blob, UINT64 capacity, TCPA_RSA_KEY_PARMS* parms) {
    return Trspi_UnloadBlob_RSA_KEY_PARMS_s(offset, blob, capacity, parms);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_PCR_SELECTION(UINT64* offset,
                                                    BYTE* blob,
                                                    TCPA_PCR_SELECTION* pcr) {
    return Trspi_UnloadBlob_PCR_SELECTION(offset, blob, pcr);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_PUBKEY_s(UINT64* offset,
                                               BYTE* blob,
                                               UINT64 capacity,
                                               TCPA_PUBKEY* pubKey) {
    return Trspi_UnloadBlob_PUBKEY_s(offset, blob, capacity, pubKey);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_KEY12_s(UINT64* offset,
                                              BYTE* blob,
                                              UINT64 capacity,
                                              TPM_KEY12* key) {
    return Trspi_UnloadBlob_KEY12_s(offset, blob, capacity, key);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_SYMMETRIC_KEY(UINT64* offset,
                                                    BYTE* blob,
                                                    TCPA_SYMMETRIC_KEY* key) {
    return Trspi_UnloadBlob_SYMMETRIC_KEY(offset, blob, key);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_IDENTITY_REQ(UINT64* offset,
                                                   BYTE* blob,
                                                   TCPA_IDENTITY_REQ* req) {
    return Trspi_UnloadBlob_IDENTITY_REQ(offset, blob, req);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_IDENTITY_PROOF(
      UINT64* offset, BYTE* blob, TCPA_IDENTITY_PROOF* proof) {
    return Trspi_UnloadBlob_IDENTITY_PROOF(offset, blob, proof);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_CERTIFY_INFO(UINT64* offset,
                                                   BYTE* blob,
                                                   TPM_CERTIFY_INFO* c) {
    return Trspi_UnloadBlob_CERTIFY_INFO(offset, blob, c);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_TPM_DELEGATE_OWNER_BLOB(
      UINT64* offset, BYTE* blob, TPM_DELEGATE_OWNER_BLOB* owner) {
    return Trspi_UnloadBlob_TPM_DELEGATE_OWNER_BLOB(offset, blob, owner);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_TPM_DELEGATE_OWNER_BLOB_s(
      UINT64* offset,
      BYTE* blob,
      UINT64 capacity,
      TPM_DELEGATE_OWNER_BLOB* owner) {
    return Trspi_UnloadBlob_TPM_DELEGATE_OWNER_BLOB_s(offset, blob, capacity,
                                                      owner);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_CAP_VERSION_INFO_s(
      UINT64* offset, BYTE* blob, UINT64 capacity, TPM_CAP_VERSION_INFO* v) {
    return Trspi_UnloadBlob_CAP_VERSION_INFO_s(offset, blob, capacity, v);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_NV_DATA_PUBLIC(UINT64* offset,
                                                     BYTE* blob,
                                                     TPM_NV_DATA_PUBLIC* v) {
    return Trspi_UnloadBlob_NV_DATA_PUBLIC(offset, blob, v);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_NV_DATA_PUBLIC_s(UINT64* offset,
                                                       BYTE* blob,
                                                       UINT64 capacity,
                                                       TPM_NV_DATA_PUBLIC* v) {
    return Trspi_UnloadBlob_NV_DATA_PUBLIC_s(offset, blob, capacity, v);
  }
  virtual TSS_RESULT Orspi_UnloadBlob_DA_INFO_s(UINT64* offset,
                                                BYTE* blob,
                                                UINT64 capacity,
                                                TPM_DA_INFO* info) {
    return Trspi_UnloadBlob_DA_INFO_s(offset, blob, capacity, info);
  }
  virtual void Orspi_LoadBlob_UINT32(UINT64* offset, UINT32 in, BYTE* blob) {
    return Trspi_LoadBlob_UINT32(offset, in, blob);
  }
  virtual void Orspi_LoadBlob_UINT16(UINT64* offset, UINT16 in, BYTE* blob) {
    return Trspi_LoadBlob_UINT16(offset, in, blob);
  }
  virtual void Orspi_LoadBlob_BYTE(UINT64* offset, BYTE data, BYTE* blob) {
    return Trspi_LoadBlob_BYTE(offset, data, blob);
  }
  virtual void Orspi_LoadBlob_RSA_KEY_PARMS(UINT64* offset,
                                            BYTE* blob,
                                            TCPA_RSA_KEY_PARMS* parms) {
    return Trspi_LoadBlob_RSA_KEY_PARMS(offset, blob, parms);
  }
  virtual void Orspi_LoadBlob_PCR_INFO_SHORT(UINT64* offset,
                                             BYTE* blob,
                                             TPM_PCR_INFO_SHORT* pcr) {
    return Trspi_LoadBlob_PCR_INFO_SHORT(offset, blob, pcr);
  }
  virtual void Orspi_LoadBlob_PUBKEY(UINT64* offset,
                                     BYTE* blob,
                                     TCPA_PUBKEY* pubKey) {
    return Trspi_LoadBlob_PUBKEY(offset, blob, pubKey);
  }
  virtual void Orspi_LoadBlob_KEY12(UINT64* offset,
                                    BYTE* blob,
                                    TPM_KEY12* key) {
    return Trspi_LoadBlob_KEY12(offset, blob, key);
  }
  virtual void Orspi_LoadBlob_SYM_CA_ATTESTATION(UINT64* offset,
                                                 BYTE* blob,
                                                 TCPA_SYM_CA_ATTESTATION* sym) {
    return Trspi_LoadBlob_SYM_CA_ATTESTATION(offset, blob, sym);
  }
  virtual void Orspi_LoadBlob_ASYM_CA_CONTENTS(UINT64* offset,
                                               BYTE* blob,
                                               TCPA_ASYM_CA_CONTENTS* asym) {
    return Trspi_LoadBlob_ASYM_CA_CONTENTS(offset, blob, asym);
  }
  virtual void Orspi_LoadBlob_MSA_COMPOSITE(UINT64* offset,
                                            BYTE* blob,
                                            TPM_MSA_COMPOSITE* msaComp) {
    return Trspi_LoadBlob_MSA_COMPOSITE(offset, blob, msaComp);
  }
  virtual TSS_RESULT Orspi_SymDecrypt(UINT16 alg,
                                      UINT16 mode,
                                      BYTE* key,
                                      BYTE* iv,
                                      BYTE* in,
                                      UINT32 in_len,
                                      BYTE* out,
                                      UINT32* out_len) {
    return Trspi_SymDecrypt(alg, mode, key, iv, in, in_len, out, out_len);
  }
  virtual TSS_RESULT Orspi_MGF1(
      UINT32 alg, UINT32 seedLen, BYTE* seed, UINT32 outLen, BYTE* out) {
    return Trspi_MGF1(alg, seedLen, seed, outLen, out);
  }
  virtual BYTE* Orspi_Native_To_UNICODE(BYTE* string, unsigned* len) {
    return Trspi_Native_To_UNICODE(string, len);
  }
  virtual char* Orspi_Error_String(TSS_RESULT arg0) {
    return Trspi_Error_String(arg0);
  }
  virtual TSS_RESULT Ospi_SetAttribUint32(TSS_HOBJECT hObject,
                                          TSS_FLAG attribFlag,
                                          TSS_FLAG subFlag,
                                          UINT32 ulAttrib) {
    return Tspi_SetAttribUint32(hObject, attribFlag, subFlag, ulAttrib);
  }
  virtual TSS_RESULT Ospi_GetAttribUint32(TSS_HOBJECT hObject,
                                          TSS_FLAG attribFlag,
                                          TSS_FLAG subFlag,
                                          UINT32* pulAttrib) {
    return Tspi_GetAttribUint32(hObject, attribFlag, subFlag, pulAttrib);
  }
  virtual TSS_RESULT Ospi_SetAttribData(TSS_HOBJECT hObject,
                                        TSS_FLAG attribFlag,
                                        TSS_FLAG subFlag,
                                        UINT32 ulAttribDataSize,
                                        BYTE* rgbAttribData) {
    return Tspi_SetAttribData(hObject, attribFlag, subFlag, ulAttribDataSize,
                              rgbAttribData);
  }
  virtual TSS_RESULT Ospi_GetAttribData(TSS_HOBJECT hObject,
                                        TSS_FLAG attribFlag,
                                        TSS_FLAG subFlag,
                                        UINT32* pulAttribDataSize,
                                        BYTE** prgbAttribData) {
    return Tspi_GetAttribData(hObject, attribFlag, subFlag, pulAttribDataSize,
                              prgbAttribData);
  }
  virtual TSS_RESULT Ospi_ChangeAuth(TSS_HOBJECT hObjectToChange,
                                     TSS_HOBJECT hParentObject,
                                     TSS_HPOLICY hNewPolicy) {
    return Tspi_ChangeAuth(hObjectToChange, hParentObject, hNewPolicy);
  }
  virtual TSS_RESULT Ospi_GetPolicyObject(TSS_HOBJECT hObject,
                                          TSS_FLAG policyType,
                                          TSS_HPOLICY* phPolicy) {
    return Tspi_GetPolicyObject(hObject, policyType, phPolicy);
  }
  virtual TSS_RESULT Ospi_Context_Create(TSS_HCONTEXT* phContext) {
    return Tspi_Context_Create(phContext);
  }
  virtual TSS_RESULT Ospi_Context_Close(TSS_HCONTEXT hContext) {
    return Tspi_Context_Close(hContext);
  }
  virtual TSS_RESULT Ospi_Context_Connect(TSS_HCONTEXT hContext,
                                          TSS_UNICODE* wszDestination) {
    return Tspi_Context_Connect(hContext, wszDestination);
  }
  virtual TSS_RESULT Ospi_Context_FreeMemory(TSS_HCONTEXT hContext,
                                             BYTE* rgbMemory) {
    return Tspi_Context_FreeMemory(hContext, rgbMemory);
  }
  virtual TSS_RESULT Ospi_Context_GetDefaultPolicy(TSS_HCONTEXT hContext,
                                                   TSS_HPOLICY* phPolicy) {
    return Tspi_Context_GetDefaultPolicy(hContext, phPolicy);
  }
  virtual TSS_RESULT Ospi_Context_CreateObject(TSS_HCONTEXT hContext,
                                               TSS_FLAG objectType,
                                               TSS_FLAG initFlags,
                                               TSS_HOBJECT* phObject) {
    return Tspi_Context_CreateObject(hContext, objectType, initFlags, phObject);
  }
  virtual TSS_RESULT Ospi_Context_CloseObject(TSS_HCONTEXT hContext,
                                              TSS_HOBJECT hObject) {
    return Tspi_Context_CloseObject(hContext, hObject);
  }
  virtual TSS_RESULT Ospi_Context_GetTpmObject(TSS_HCONTEXT hContext,
                                               TSS_HTPM* phTPM) {
    return Tspi_Context_GetTpmObject(hContext, phTPM);
  }
  virtual TSS_RESULT Ospi_Context_LoadKeyByBlob(TSS_HCONTEXT hContext,
                                                TSS_HKEY hUnwrappingKey,
                                                UINT32 ulBlobLength,
                                                BYTE* rgbBlobData,
                                                TSS_HKEY* phKey) {
    return Tspi_Context_LoadKeyByBlob(hContext, hUnwrappingKey, ulBlobLength,
                                      rgbBlobData, phKey);
  }
  virtual TSS_RESULT Ospi_Context_LoadKeyByUUID(TSS_HCONTEXT hContext,
                                                TSS_FLAG persistentStorageType,
                                                TSS_UUID uuidData,
                                                TSS_HKEY* phKey) {
    return Tspi_Context_LoadKeyByUUID(hContext, persistentStorageType, uuidData,
                                      phKey);
  }
  virtual TSS_RESULT Ospi_Policy_SetSecret(TSS_HPOLICY hPolicy,
                                           TSS_FLAG secretMode,
                                           UINT32 ulSecretLength,
                                           BYTE* rgbSecret) {
    return Tspi_Policy_SetSecret(hPolicy, secretMode, ulSecretLength,
                                 rgbSecret);
  }
  virtual TSS_RESULT Ospi_Policy_AssignToObject(TSS_HPOLICY hPolicy,
                                                TSS_HOBJECT hObject) {
    return Tspi_Policy_AssignToObject(hPolicy, hObject);
  }
  virtual TSS_RESULT Ospi_TPM_CreateEndorsementKey(
      TSS_HTPM hTPM, TSS_HKEY hKey, TSS_VALIDATION* pValidationData) {
    return Tspi_TPM_CreateEndorsementKey(hTPM, hKey, pValidationData);
  }
  virtual TSS_RESULT Ospi_TPM_GetPubEndorsementKey(
      TSS_HTPM hTPM,
      TSS_BOOL fOwnerAuthorized,
      TSS_VALIDATION* pValidationData,
      TSS_HKEY* phEndorsementPubKey) {
    return Tspi_TPM_GetPubEndorsementKey(hTPM, fOwnerAuthorized,
                                         pValidationData, phEndorsementPubKey);
  }
  virtual TSS_RESULT Ospi_TPM_TakeOwnership(TSS_HTPM hTPM,
                                            TSS_HKEY hKeySRK,
                                            TSS_HKEY hEndorsementPubKey) {
    return Tspi_TPM_TakeOwnership(hTPM, hKeySRK, hEndorsementPubKey);
  }
  virtual TSS_RESULT Ospi_TPM_CollateIdentityRequest(
      TSS_HTPM hTPM,
      TSS_HKEY hKeySRK,
      TSS_HKEY hCAPubKey,
      UINT32 ulIdentityLabelLength,
      BYTE* rgbIdentityLabelData,
      TSS_HKEY hIdentityKey,
      TSS_ALGORITHM_ID algID,
      UINT32* pulTCPAIdentityReqLength,
      BYTE** prgbTCPAIdentityReq) {
    return Tspi_TPM_CollateIdentityRequest(
        hTPM, hKeySRK, hCAPubKey, ulIdentityLabelLength, rgbIdentityLabelData,
        hIdentityKey, algID, pulTCPAIdentityReqLength, prgbTCPAIdentityReq);
  }
  virtual TSS_RESULT Ospi_TPM_ActivateIdentity(
      TSS_HTPM hTPM,
      TSS_HKEY hIdentKey,
      UINT32 ulAsymCAContentsBlobLength,
      BYTE* rgbAsymCAContentsBlob,
      UINT32 ulSymCAAttestationBlobLength,
      BYTE* rgbSymCAAttestationBlob,
      UINT32* pulCredentialLength,
      BYTE** prgbCredential) {
    return Tspi_TPM_ActivateIdentity(
        hTPM, hIdentKey, ulAsymCAContentsBlobLength, rgbAsymCAContentsBlob,
        ulSymCAAttestationBlobLength, rgbSymCAAttestationBlob,
        pulCredentialLength, prgbCredential);
  }
  virtual TSS_RESULT Ospi_TPM_SetStatus(TSS_HTPM hTPM,
                                        TSS_FLAG statusFlag,
                                        TSS_BOOL fTpmState) {
    return Tspi_TPM_SetStatus(hTPM, statusFlag, fTpmState);
  }
  virtual TSS_RESULT Ospi_TPM_GetStatus(TSS_HTPM hTPM,
                                        TSS_FLAG statusFlag,
                                        TSS_BOOL* pfTpmState) {
    return Tspi_TPM_GetStatus(hTPM, statusFlag, pfTpmState);
  }
  virtual TSS_RESULT Ospi_TPM_FieldUpgrade(TSS_HTPM hTPM,
                                           UINT32 ulDataInLength,
                                           BYTE* rgbDataIn,
                                           UINT32* pulDataOutLength,
                                           BYTE** prgbDataOut) {
    return Tspi_TPM_FieldUpgrade(hTPM, ulDataInLength, rgbDataIn,
                                 pulDataOutLength, prgbDataOut);
  }
  virtual TSS_RESULT Ospi_TPM_GetCapability(TSS_HTPM hTPM,
                                            TSS_FLAG capArea,
                                            UINT32 ulSubCapLength,
                                            BYTE* rgbSubCap,
                                            UINT32* pulRespDataLength,
                                            BYTE** prgbRespData) {
    return Tspi_TPM_GetCapability(hTPM, capArea, ulSubCapLength, rgbSubCap,
                                  pulRespDataLength, prgbRespData);
  }
  virtual TSS_RESULT Ospi_TPM_GetRandom(TSS_HTPM hTPM,
                                        UINT32 ulRandomDataLength,
                                        BYTE** prgbRandomData) {
    return Tspi_TPM_GetRandom(hTPM, ulRandomDataLength, prgbRandomData);
  }
  virtual TSS_RESULT Ospi_TPM_StirRandom(TSS_HTPM hTPM,
                                         UINT32 ulEntropyDataLength,
                                         BYTE* rgbEntropyData) {
    return Tspi_TPM_StirRandom(hTPM, ulEntropyDataLength, rgbEntropyData);
  }
  virtual TSS_RESULT Ospi_TPM_Quote(TSS_HTPM hTPM,
                                    TSS_HKEY hIdentKey,
                                    TSS_HPCRS hPcrComposite,
                                    TSS_VALIDATION* pValidationData) {
    return Tspi_TPM_Quote(hTPM, hIdentKey, hPcrComposite, pValidationData);
  }
  virtual TSS_RESULT Ospi_TPM_PcrExtend(TSS_HTPM hTPM,
                                        UINT32 ulPcrIndex,
                                        UINT32 ulPcrDataLength,
                                        BYTE* pbPcrData,
                                        TSS_PCR_EVENT* pPcrEvent,
                                        UINT32* pulPcrValueLength,
                                        BYTE** prgbPcrValue) {
    return Tspi_TPM_PcrExtend(hTPM, ulPcrIndex, ulPcrDataLength, pbPcrData,
                              pPcrEvent, pulPcrValueLength, prgbPcrValue);
  }
  virtual TSS_RESULT Ospi_TPM_PcrRead(TSS_HTPM hTPM,
                                      UINT32 ulPcrIndex,
                                      UINT32* pulPcrValueLength,
                                      BYTE** prgbPcrValue) {
    return Tspi_TPM_PcrRead(hTPM, ulPcrIndex, pulPcrValueLength, prgbPcrValue);
  }
  virtual TSS_RESULT Ospi_TPM_AuthorizeMigrationTicket(
      TSS_HTPM hTPM,
      TSS_HKEY hMigrationKey,
      TSS_MIGRATE_SCHEME migrationScheme,
      UINT32* pulMigTicketLength,
      BYTE** prgbMigTicket) {
    return Tspi_TPM_AuthorizeMigrationTicket(hTPM, hMigrationKey,
                                             migrationScheme,
                                             pulMigTicketLength, prgbMigTicket);
  }
  virtual TSS_RESULT Ospi_TPM_CMKApproveMA(TSS_HTPM hTPM,
                                           TSS_HMIGDATA hMaAuthData) {
    return Tspi_TPM_CMKApproveMA(hTPM, hMaAuthData);
  }
  virtual TSS_RESULT Ospi_TPM_CMKCreateTicket(TSS_HTPM hTPM,
                                              TSS_HKEY hVerifyKey,
                                              TSS_HMIGDATA hSigData) {
    return Tspi_TPM_CMKCreateTicket(hTPM, hVerifyKey, hSigData);
  }
  virtual TSS_RESULT Ospi_TPM_Delegate_AddFamily(TSS_HTPM hTPM,
                                                 BYTE bLabel,
                                                 TSS_HDELFAMILY* phFamily) {
    return Tspi_TPM_Delegate_AddFamily(hTPM, bLabel, phFamily);
  }
  virtual TSS_RESULT Ospi_TPM_Delegate_CreateDelegation(
      TSS_HOBJECT hObject,
      BYTE bLabel,
      UINT32 ulFlags,
      TSS_HPCRS hPcr,
      TSS_HDELFAMILY hFamily,
      TSS_HPOLICY hDelegation) {
    return Tspi_TPM_Delegate_CreateDelegation(hObject, bLabel, ulFlags, hPcr,
                                              hFamily, hDelegation);
  }
  virtual TSS_RESULT Ospi_PcrComposite_SelectPcrIndex(TSS_HPCRS hPcrComposite,
                                                      UINT32 ulPcrIndex) {
    return Tspi_PcrComposite_SelectPcrIndex(hPcrComposite, ulPcrIndex);
  }
  virtual TSS_RESULT Ospi_PcrComposite_SetPcrValue(TSS_HPCRS hPcrComposite,
                                                   UINT32 ulPcrIndex,
                                                   UINT32 ulPcrValueLength,
                                                   BYTE* rgbPcrValue) {
    return Tspi_PcrComposite_SetPcrValue(hPcrComposite, ulPcrIndex,
                                         ulPcrValueLength, rgbPcrValue);
  }
  virtual TSS_RESULT Ospi_PcrComposite_GetPcrValue(TSS_HPCRS hPcrComposite,
                                                   UINT32 ulPcrIndex,
                                                   UINT32* pulPcrValueLength,
                                                   BYTE** prgbPcrValue) {
    return Tspi_PcrComposite_GetPcrValue(hPcrComposite, ulPcrIndex,
                                         pulPcrValueLength, prgbPcrValue);
  }
  virtual TSS_RESULT Ospi_PcrComposite_SetPcrLocality(TSS_HPCRS hPcrComposite,
                                                      UINT32 LocalityValue) {
    return Tspi_PcrComposite_SetPcrLocality(hPcrComposite, LocalityValue);
  }
  virtual TSS_RESULT Ospi_Key_LoadKey(TSS_HKEY hKey, TSS_HKEY hUnwrappingKey) {
    return Tspi_Key_LoadKey(hKey, hUnwrappingKey);
  }
  virtual TSS_RESULT Ospi_Key_UnloadKey(TSS_HKEY hKey) {
    return Tspi_Key_UnloadKey(hKey);
  }
  virtual TSS_RESULT Ospi_Key_GetPubKey(TSS_HKEY hKey,
                                        UINT32* pulPubKeyLength,
                                        BYTE** prgbPubKey) {
    return Tspi_Key_GetPubKey(hKey, pulPubKeyLength, prgbPubKey);
  }
  virtual TSS_RESULT Ospi_Key_CertifyKey(TSS_HKEY hKey,
                                         TSS_HKEY hCertifyingKey,
                                         TSS_VALIDATION* pValidationData) {
    return Tspi_Key_CertifyKey(hKey, hCertifyingKey, pValidationData);
  }
  virtual TSS_RESULT Ospi_Key_CreateKey(TSS_HKEY hKey,
                                        TSS_HKEY hWrappingKey,
                                        TSS_HPCRS hPcrComposite) {
    return Tspi_Key_CreateKey(hKey, hWrappingKey, hPcrComposite);
  }
  virtual TSS_RESULT Ospi_Key_WrapKey(TSS_HKEY hKey,
                                      TSS_HKEY hWrappingKey,
                                      TSS_HPCRS hPcrComposite) {
    return Tspi_Key_WrapKey(hKey, hWrappingKey, hPcrComposite);
  }
  virtual TSS_RESULT Ospi_Key_CMKCreateBlob(TSS_HKEY hKeyToMigrate,
                                            TSS_HKEY hParentKey,
                                            TSS_HMIGDATA hMigrationData,
                                            UINT32* pulRandomLength,
                                            BYTE** prgbRandom) {
    return Tspi_Key_CMKCreateBlob(hKeyToMigrate, hParentKey, hMigrationData,
                                  pulRandomLength, prgbRandom);
  }
  virtual TSS_RESULT Ospi_Hash_Sign(TSS_HHASH hHash,
                                    TSS_HKEY hKey,
                                    UINT32* pulSignatureLength,
                                    BYTE** prgbSignature) {
    return Tspi_Hash_Sign(hHash, hKey, pulSignatureLength, prgbSignature);
  }
  virtual TSS_RESULT Ospi_Hash_SetHashValue(TSS_HHASH hHash,
                                            UINT32 ulHashValueLength,
                                            BYTE* rgbHashValue) {
    return Tspi_Hash_SetHashValue(hHash, ulHashValueLength, rgbHashValue);
  }
  virtual TSS_RESULT Ospi_Data_Bind(TSS_HENCDATA hEncData,
                                    TSS_HKEY hEncKey,
                                    UINT32 ulDataLength,
                                    BYTE* rgbDataToBind) {
    return Tspi_Data_Bind(hEncData, hEncKey, ulDataLength, rgbDataToBind);
  }
  virtual TSS_RESULT Ospi_Data_Unbind(TSS_HENCDATA hEncData,
                                      TSS_HKEY hKey,
                                      UINT32* pulUnboundDataLength,
                                      BYTE** prgbUnboundData) {
    return Tspi_Data_Unbind(hEncData, hKey, pulUnboundDataLength,
                            prgbUnboundData);
  }
  virtual TSS_RESULT Ospi_Data_Seal(TSS_HENCDATA hEncData,
                                    TSS_HKEY hEncKey,
                                    UINT32 ulDataLength,
                                    BYTE* rgbDataToSeal,
                                    TSS_HPCRS hPcrComposite) {
    return Tspi_Data_Seal(hEncData, hEncKey, ulDataLength, rgbDataToSeal,
                          hPcrComposite);
  }
  virtual TSS_RESULT Ospi_Data_Unseal(TSS_HENCDATA hEncData,
                                      TSS_HKEY hKey,
                                      UINT32* pulUnsealedDataLength,
                                      BYTE** prgbUnsealedData) {
    return Tspi_Data_Unseal(hEncData, hKey, pulUnsealedDataLength,
                            prgbUnsealedData);
  }
  virtual TSS_RESULT Ospi_NV_DefineSpace(TSS_HNVSTORE hNVStore,
                                         TSS_HPCRS hReadPcrComposite,
                                         TSS_HPCRS hWritePcrComposite) {
    return Tspi_NV_DefineSpace(hNVStore, hReadPcrComposite, hWritePcrComposite);
  }
  virtual TSS_RESULT Ospi_NV_ReleaseSpace(TSS_HNVSTORE hNVStore) {
    return Tspi_NV_ReleaseSpace(hNVStore);
  }
  virtual TSS_RESULT Ospi_NV_WriteValue(TSS_HNVSTORE hNVStore,
                                        UINT32 offset,
                                        UINT32 ulDataLength,
                                        BYTE* rgbDataToWrite) {
    return Tspi_NV_WriteValue(hNVStore, offset, ulDataLength, rgbDataToWrite);
  }
  virtual TSS_RESULT Ospi_NV_ReadValue(TSS_HNVSTORE hNVStore,
                                       UINT32 offset,
                                       UINT32* ulDataLength,
                                       BYTE** rgbDataRead) {
    return Tspi_NV_ReadValue(hNVStore, offset, ulDataLength, rgbDataRead);
  }
  virtual TSS_RESULT Ospi_Context_SecureFreeMemory(TSS_HCONTEXT hContext,
                                                   BYTE* rgbMemory) {
    return Tspi_Context_SecureFreeMemory(hContext, rgbMemory);
  }
};

}  // namespace overalls
}  // namespace hwsec

#endif  // LIBHWSEC_OVERALLS_OVERALLS_H_
