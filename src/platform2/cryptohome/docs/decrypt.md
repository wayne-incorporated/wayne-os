# Unlock

[TOC]

## Overview

Before the user's cryptohome can be used by the rest of the system, it should be
decrypted and mounted. Cryptohome encryption keys are stored on disk and are
encrypted themselves. There are multiple protection mechanisms employed for the
purpose, and they are also used as a secondary - offline - authentication
mechanism for the user supplied credentials/secrets/etc. Regardless of the
mechanism employed, the filesystem encryption keys are encrypted either though
TPM or through the use of ['scrypt'].

## VKK (current, to be deprecated)

The vault keyset (vault_keyset.cc/h) contains the file encryption key and file
name encryption key is used by filesystem encryption mechanisms. This keyset
encrypted and persisted to disk. Cryptohome may use either the TPM or [`scrypt`]
as the encryption/protection mechanism.

If the TPM is available, cryptohome will attempt to use it. If the TPM is not
available (either not present, not enabled, owned by another OS, or it is in the
middle of being owned), cryptohome will fall back to using scrypt-based
protection of the vault keyset. If the TPM becomes available at a later login,
cryptohome will transparently migrate a user's keyset to TPM-based protection.

The method when the TPM is enabled can be described using the decryption
workflow as an example:

```
  UP -
      |
      + AES decrypt (no padding) => IEVKK -
      |                                    |
EVKK -                                     |
                                           + RSA decrypt (in TPM) => VKK
                                           |
                                           |
                                  TPM_CHK -
```

Where:

*   `UP`: User Passkey
*   `EVKK`: Ecrypted vault keyset key (stored on disk)
*   `IEVKK`: Intermediate vault keyset key
*   `TPM_CHK`: TPM-wrapped system-wide Cryptohome Key
*   `VKK`: Vault Keyset Key

The end result, the Vault Keyset Key (VKK), is an AES key that is used to
decrypt the Vault Keyset, which holds the ecryptfs keys (filename encryption key
and file encryption key). The VKK, when using the TPM for protection, is a
randomly-generated key.

The User Passkey (UP) is used as an AES key to do an initial decrypt of the
Encrypted Vault Keyset Key (EVKK, or the "tpm_key" field in the
SerializedVaultKeyset, see vault_keyset.proto). This is done without padding as
the decryption is done in-place and the resulting buffer is the Intermediate
Vault Keyset Key (IEVKK), which is fed into an RSA decrypt on the TPM as the
cipher text. That RSA decrypt uses the system-wide TPM-wrapped cryptohome key.
In this manner, we can use a randomly-created system-wide key (the TPM has a
limited number of key slots), but still require the user's passkey during the
decryption phase. This also increases the brute-force cost of attacking the
SerializedVaultKeyset offline as it means that the attacker would have to do a
TPM cipher operation per password attempt (assuming that the wrapped key could
not be recovered).

After obtaining the VKK, it is used to recover the vault keyset by using it as
an AES key to decrypt the Encrypted Vault Keyset (EVK, or the "wrapped_keyset"
field in the SerializedVaultKeyset):

```
VKK -
     |
     + AES (PKCS#5 padding + SHA1 verification) => VK
     |
EVK -

Where:
  EVK - Encrypted vault keyset
  VK - Vault keyset

Presented another way:

+----------------------------------+
| EVKK (persisted as "tpm_key")    |
+----------------------------------+
                              \   /
                               \ /   Final 128-bits decrypted     +----------+
                                +--- in-place using the user's ---+ UP (mem) |
                               / \   passkey                      +----------+
                              /   \
+----------------------------------+
| IEVKK (mem)                      |
+----------------------------------+
 \                                 /
  \                               /
   \                             /
    -----------      ------------
                \   /
                 \ /                       +---------------------+
                  +--- Decrypted on-TPM ---+ TPM_CHK (persisted, |
                 / \                       | sealed by the TPM)  |
                /   \                      +---------------------+
               /     \
              /       \
             /         \            +-------------------------------------+
            /           \           | EVK (persisted as "wrapped_keyset") |
           /             \          +-------------------------------------+
          /               \          \                                   /
         /                 \          ----------------   ----------------
        +-------------------+                         \ /
        | VKK (mem)         +--- AES decrypt ----------+
        +-------------------+                         / \
                                      ----------------   ----------------
                                     /                                   \
                                    +-------------------------------------+
                                    | VK (mem)                            |
                                    +-------------------------------------+
```

Encryption of the Vault Keyset (VK) follows the above operations in reverse
(see WrapVaultKeyset in crypto.cc).

By comparison, when the TPM is not enabled, the UP is used as the password
supplied to scryptbuf_enc, which will use memory-bound key strengthening and AES
to encrypt the VK. The [`scrypt`] method is simpler because of the high-level
API that [`scrypt`] exposes for key strengthening and encryption in one function
call.

[`scrypt`]: http://www.tarsnap.com/scrypt.html

## AuthSession + USS (in development)

*TBD*
See [architecture.md](architecture.md)

## LockScreen

Offline login and screen unlock is processed through cryptohome using a test
decryption of the user's keyset using the passkey provided. If the user
currently has their cryptohome mounted, then the credentials may be verified
against their session object instead, which provides quick credentials
verification without access to the key material. This latter method uses the
UserSession object in user_session.cc. A user session is established during
mount attempt and preserved throughout the life time of the mount. The user
session is torn down upon unmount, or have the verifier changed upon key change.
If user session doesn't contain a valid verifier for the user, offline
credential test falls back to attempting to decrypt the user's stored vault
keyset. The session method is preferred because it does not attempt to decrypt
key material, and because it does not require a round-trip to the TPM when the
TPM is used for further protecting the keyset (which can be ~.7s, or close to 3s
if the RSA key was evicted from the TPM key slot it occupies).

## Vault creation and password change

A user's cryptohome is automatically created when the vault directory for the
user does not exist and the cryptohome service gets a call to mount the user's
home directory. This assumes that the call to MountCryptohome contains the
correct user password--no verification can be done if the vault keyset for the
user does not exist. TestCredentials should be used if implicit creation is not
desired (and of course, explicit mount).

Passkey change is implemented through a call to MigratePasskey. MigratePasskey
will attempt to decrypt the vault keyset using the old credentials supplied, and
if successful, will re-save the vault keyset using the new credentials.
MigratePasskey can be called regardless of whether a user's (any user)
cryptohome is mounted. However, it will always clear the current user's session
as described above.
