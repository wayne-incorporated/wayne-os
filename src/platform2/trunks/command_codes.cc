// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/command_codes.h"

#include <string>

#include <absl/strings/str_format.h>
#include <base/check_op.h>
#include <base/notreached.h>

namespace trunks {

std::string GetCommandString(trunks::TPM_CC command_code) {
  switch (command_code) {
    case trunks::TPM_CC_NV_UndefineSpaceSpecial:
      return "TPM_CC_NV_UndefineSpaceSpecial";
    case trunks::TPM_CC_EvictControl:
      return "TPM_CC_EvictControl";
    case trunks::TPM_CC_HierarchyControl:
      return "TPM_CC_HierarchyControl";
    case trunks::TPM_CC_NV_UndefineSpace:
      return "TPM_CC_NV_UndefineSpace";
    case trunks::TPM_CC_ChangeEPS:
      return "TPM_CC_ChangeEPS";
    case trunks::TPM_CC_ChangePPS:
      return "TPM_CC_ChangePPS";
    case trunks::TPM_CC_Clear:
      return "TPM_CC_Clear";
    case trunks::TPM_CC_ClearControl:
      return "TPM_CC_ClearControl";
    case trunks::TPM_CC_ClockSet:
      return "TPM_CC_ClockSet";
    case trunks::TPM_CC_HierarchyChangeAuth:
      return "TPM_CC_HierarchyChangeAuth";
    case trunks::TPM_CC_NV_DefineSpace:
      return "TPM_CC_NV_DefineSpace";
    case trunks::TPM_CC_PCR_Allocate:
      return "TPM_CC_PCR_Allocate";
    case trunks::TPM_CC_PCR_SetAuthPolicy:
      return "TPM_CC_PCR_SetAuthPolicy";
    case trunks::TPM_CC_PP_Commands:
      return "TPM_CC_PP_Commands";
    case trunks::TPM_CC_SetPrimaryPolicy:
      return "TPM_CC_SetPrimaryPolicy";
    case trunks::TPM_CC_FieldUpgradeStart:
      return "TPM_CC_FieldUpgradeStart";
    case trunks::TPM_CC_ClockRateAdjust:
      return "TPM_CC_ClockRateAdjust";
    case trunks::TPM_CC_CreatePrimary:
      return "TPM_CC_CreatePrimary";
    case trunks::TPM_CC_NV_GlobalWriteLock:
      return "TPM_CC_NV_GlobalWriteLock";
    case trunks::TPM_CC_GetCommandAuditDigest:
      return "TPM_CC_GetCommandAuditDigest";
    case trunks::TPM_CC_NV_Increment:
      return "TPM_CC_NV_Increment";
    case trunks::TPM_CC_NV_SetBits:
      return "TPM_CC_NV_SetBits";
    case trunks::TPM_CC_NV_Extend:
      return "TPM_CC_NV_Extend";
    case trunks::TPM_CC_NV_Write:
      return "TPM_CC_NV_Write";
    case trunks::TPM_CC_NV_WriteLock:
      return "TPM_CC_NV_WriteLock";
    case trunks::TPM_CC_DictionaryAttackLockReset:
      return "TPM_CC_DictionaryAttackLockReset";
    case trunks::TPM_CC_DictionaryAttackParameters:
      return "TPM_CC_DictionaryAttackParameters";
    case trunks::TPM_CC_NV_ChangeAuth:
      return "TPM_CC_NV_ChangeAuth";
    case trunks::TPM_CC_PCR_Event:
      return "TPM_CC_PCR_Event";
    case trunks::TPM_CC_PCR_Reset:
      return "TPM_CC_PCR_Reset";
    case trunks::TPM_CC_SequenceComplete:
      return "TPM_CC_SequenceComplete";
    case trunks::TPM_CC_SetAlgorithmSet:
      return "TPM_CC_SetAlgorithmSet";
    case trunks::TPM_CC_SetCommandCodeAuditStatus:
      return "TPM_CC_SetCommandCodeAuditStatus";
    case trunks::TPM_CC_FieldUpgradeData:
      return "TPM_CC_FieldUpgradeData";
    case trunks::TPM_CC_IncrementalSelfTest:
      return "TPM_CC_IncrementalSelfTest";
    case trunks::TPM_CC_SelfTest:
      return "TPM_CC_SelfTest";
    case trunks::TPM_CC_Startup:
      return "TPM_CC_Startup";
    case trunks::TPM_CC_Shutdown:
      return "TPM_CC_Shutdown";
    case trunks::TPM_CC_StirRandom:
      return "TPM_CC_StirRandom";
    case trunks::TPM_CC_ActivateCredential:
      return "TPM_CC_ActivateCredential";
    case trunks::TPM_CC_Certify:
      return "TPM_CC_Certify";
    case trunks::TPM_CC_PolicyNV:
      return "TPM_CC_PolicyNV";
    case trunks::TPM_CC_CertifyCreation:
      return "TPM_CC_CertifyCreation";
    case trunks::TPM_CC_Duplicate:
      return "TPM_CC_Duplicate";
    case trunks::TPM_CC_GetTime:
      return "TPM_CC_GetTime";
    case trunks::TPM_CC_GetSessionAuditDigest:
      return "TPM_CC_GetSessionAuditDigest";
    case trunks::TPM_CC_NV_Read:
      return "TPM_CC_NV_Read";
    case trunks::TPM_CC_NV_ReadLock:
      return "TPM_CC_NV_ReadLock";
    case trunks::TPM_CC_ObjectChangeAuth:
      return "TPM_CC_ObjectChangeAuth";
    case trunks::TPM_CC_PolicySecret:
      return "TPM_CC_PolicySecret";
    case trunks::TPM_CC_Rewrap:
      return "TPM_CC_Rewrap";
    case trunks::TPM_CC_Create:
      return "TPM_CC_Create";
    case trunks::TPM_CC_ECDH_ZGen:
      return "TPM_CC_ECDH_ZGen";
    case trunks::TPM_CC_HMAC:
      return "TPM_CC_HMAC";
    case trunks::TPM_CC_Import:
      return "TPM_CC_Import";
    case trunks::TPM_CC_Load:
      return "TPM_CC_Load";
    case trunks::TPM_CC_Quote:
      return "TPM_CC_Quote";
    case trunks::TPM_CC_RSA_Decrypt:
      return "TPM_CC_RSA_Decrypt";
    case trunks::TPM_CC_HMAC_Start:
      return "TPM_CC_HMAC_Start";
    case trunks::TPM_CC_SequenceUpdate:
      return "TPM_CC_SequenceUpdate";
    case trunks::TPM_CC_Sign:
      return "TPM_CC_Sign";
    case trunks::TPM_CC_Unseal:
      return "TPM_CC_Unseal";
    case trunks::TPM_CC_PolicySigned:
      return "TPM_CC_PolicySigned";
    case trunks::TPM_CC_ContextLoad:
      return "TPM_CC_ContextLoad";
    case trunks::TPM_CC_ContextSave:
      return "TPM_CC_ContextSave";
    case trunks::TPM_CC_ECDH_KeyGen:
      return "TPM_CC_ECDH_KeyGen";
    case trunks::TPM_CC_EncryptDecrypt:
      return "TPM_CC_EncryptDecrypt";
    case trunks::TPM_CC_FlushContext:
      return "TPM_CC_FlushContext";
    case trunks::TPM_CC_LoadExternal:
      return "TPM_CC_LoadExternal";
    case trunks::TPM_CC_MakeCredential:
      return "TPM_CC_MakeCredential";
    case trunks::TPM_CC_NV_ReadPublic:
      return "TPM_CC_NV_ReadPublic";
    case trunks::TPM_CC_PolicyAuthorize:
      return "TPM_CC_PolicyAuthorize";
    case trunks::TPM_CC_PolicyAuthValue:
      return "TPM_CC_PolicyAuthValue";
    case trunks::TPM_CC_PolicyCommandCode:
      return "TPM_CC_PolicyCommandCode";
    case trunks::TPM_CC_PolicyCounterTimer:
      return "TPM_CC_PolicyCounterTimer";
    case trunks::TPM_CC_PolicyCpHash:
      return "TPM_CC_PolicyCpHash";
    case trunks::TPM_CC_PolicyLocality:
      return "TPM_CC_PolicyLocality";
    case trunks::TPM_CC_PolicyNameHash:
      return "TPM_CC_PolicyNameHash";
    case trunks::TPM_CC_PolicyOR:
      return "TPM_CC_PolicyOR";
    case trunks::TPM_CC_PolicyTicket:
      return "TPM_CC_PolicyTicket";
    case trunks::TPM_CC_ReadPublic:
      return "TPM_CC_ReadPublic";
    case trunks::TPM_CC_RSA_Encrypt:
      return "TPM_CC_RSA_Encrypt";
    case trunks::TPM_CC_StartAuthSession:
      return "TPM_CC_StartAuthSession";
    case trunks::TPM_CC_VerifySignature:
      return "TPM_CC_VerifySignature";
    case trunks::TPM_CC_ECC_Parameters:
      return "TPM_CC_ECC_Parameters";
    case trunks::TPM_CC_FirmwareRead:
      return "TPM_CC_FirmwareRead";
    case trunks::TPM_CC_GetCapability:
      return "TPM_CC_GetCapability";
    case trunks::TPM_CC_GetRandom:
      return "TPM_CC_GetRandom";
    case trunks::TPM_CC_GetTestResult:
      return "TPM_CC_GetTestResult";
    case trunks::TPM_CC_Hash:
      return "TPM_CC_Hash";
    case trunks::TPM_CC_PCR_Read:
      return "TPM_CC_PCR_Read";
    case trunks::TPM_CC_PolicyPCR:
      return "TPM_CC_PolicyPCR";
    case trunks::TPM_CC_PolicyRestart:
      return "TPM_CC_PolicyRestart";
    case trunks::TPM_CC_ReadClock:
      return "TPM_CC_ReadClock";
    case trunks::TPM_CC_PCR_Extend:
      return "TPM_CC_PCR_Extend";
    case trunks::TPM_CC_PCR_SetAuthValue:
      return "TPM_CC_PCR_SetAuthValue";
    case trunks::TPM_CC_NV_Certify:
      return "TPM_CC_NV_Certify";
    case trunks::TPM_CC_EventSequenceComplete:
      return "TPM_CC_EventSequenceComplete";
    case trunks::TPM_CC_HashSequenceStart:
      return "TPM_CC_HashSequenceStart";
    case trunks::TPM_CC_PolicyPhysicalPresence:
      return "TPM_CC_PolicyPhysicalPresence";
    case trunks::TPM_CC_PolicyDuplicationSelect:
      return "TPM_CC_PolicyDuplicationSelect";
    case trunks::TPM_CC_PolicyGetDigest:
      return "TPM_CC_PolicyGetDigest";
    case trunks::TPM_CC_TestParms:
      return "TPM_CC_TestParms";
    case trunks::TPM_CC_Commit:
      return "TPM_CC_Commit";
    case trunks::TPM_CC_PolicyPassword:
      return "TPM_CC_PolicyPassword";
    case trunks::TPM_CC_ZGen_2Phase:
      return "TPM_CC_ZGen_2Phase";
    case trunks::TPM_CC_EC_Ephemeral:
      return "TPM_CC_EC_Ephemeral";
    case trunks::TPM_CC_PolicyNvWritten:
      return "TPM_CC_PolicyNvWritten";
    case trunks::TPM_CCE_PolicyFidoSigned:
      return "TPM_CCE_PolicyFidoSigned";
    default:
      return absl::StrFormat("TPM_CC 0x%04x", command_code);
  }
  NOTREACHED();
  return std::string();
}

std::string CreateCommand(TPM_CC command_code) {
  // 2 bytes TPMI_ST_COMMAND_TAG + 4 bytes command size + 4 bytes command code.
  constexpr uint32_t kCommandSize = 10;
  std::string command;
  CHECK_EQ(Serialize_TPM_ST(TPM_ST_NO_SESSIONS, &command), TPM_RC_SUCCESS);
  CHECK_EQ(Serialize_UINT32(kCommandSize, &command), TPM_RC_SUCCESS);
  CHECK_EQ(Serialize_TPM_CC(command_code, &command), TPM_RC_SUCCESS);
  return command;
}

TPM_RC GetCommandCode(const std::string& command, TPM_CC& cc) {
  std::string buffer(command);
  TPM_ST tag;
  TPM_RC parse_rc = Parse_TPM_ST(&buffer, &tag, nullptr);
  if (parse_rc != TPM_RC_SUCCESS) {
    return parse_rc;
  }
  UINT32 response_size;
  parse_rc = Parse_UINT32(&buffer, &response_size, nullptr);
  if (parse_rc != TPM_RC_SUCCESS) {
    return parse_rc;
  }
  if (response_size != command.size()) {
    return TPM_RC_SIZE;
  }
  parse_rc = Parse_TPM_CC(&buffer, &cc, nullptr);
  if (parse_rc != TPM_RC_SUCCESS) {
    return parse_rc;
  }
  return TPM_RC_SUCCESS;
}

bool IsGenericTpmCommand(TPM_CC command_code) {
  return TPM_CC_FIRST <= command_code && command_code <= TPM_CC_LAST;
}

}  // namespace trunks
