# Chaps

Chaps is a PKCS #11 implementation for Chromium OS.  This document clarifies
how the PKCS #11 standard is supported for HWSec-backed tokens and what a
calling application can expect from Chaps.

## Token Initialization

Token initialization is performed on demand and does not need to be initiated by
any application.  If files associated with a token are corrupt that token will
be reinitialized automatically.

## Roles and Authentication

Chaps does not manage roles or authentication.  Rather, it integrates with other
parts of the Chromium OS system which manages the authentication of users.  A
user does not log in or log out of an inserted token; instead an inserted token
implies that a user has logged in and now their token is available.  Since users
are managed outside of Chaps, there is no need for a Security Officer (SO) role
and so Chaps has no notion of a SO.

This approach has the following implications for PKCS #11 applications:

- `C_GetTokenInfo` reports the flag `CKF_PROTECTED_AUTHENTICATION_PATH`.
- `C_InitToken` always returns `CKR_PIN_INCORRECT`.
- `C_InitPIN` always returns `CKR_USER_NOT_LOGGED_IN`.
- `C_SetPIN` always returns `CKR_PIN_INVALID`.
- `C_Login` will return success if the protected authentication path is used
  (i.e. the PIN argument is NULL).  It will also return success if the legacy
  PIN '111111' is used.  Otherwise, it will return `CKR_PIN_INCORRECT`.  In any
  case the call has no effect and the token remains logged in.  When the user
  actually logs out of the system, that user's token will be removed.
- `C_Logout` always returns success but has no effect.

## Operation State

Operation state cannot be saved and restored.  Operation state information is
never provided to calling applications.

- `C_GetOperationState` will return `CKR_STATE_UNSAVEABLE`.
- `C_SetOperationState` will return `CKR_SAVED_STATE_INVALID`.

## Unsupported Functions

The following functions are not supported and will always return
`CKR_FUNCTION_NOT_SUPPORTED`:

- `C_DigestKey`
- `C_SignRecoverInit`
- `C_SignRecover`
- `C_VerifyRecoverInit`
- `C_VerifyRecover`
- `C_DigestEncryptUpdate`
- `C_DecryptDigestUpdate`
- `C_SignEncryptUpdate`
- `C_DecryptVerifyUpdate`
- `C_WrapKey`
- `C_UnwrapKey`
- `C_DeriveKey`
