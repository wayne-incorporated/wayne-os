# Mount

[TOC]

## Overview

The mount attempt consists of two distinct phases: filesystem keys decryption
(see [decrypt.md]) and mounting the encrypted directories with the supplied
keys. There are multiple type of mounts and they have some distinction.

## Mount types

There are four distinct mount types:

### Regular persistent mount

The user's data is persisted on disk, protected by filesystem encryption keys,
which are wrapped with user supplied credentials.

### Ephemeral mount

Ramfs based vault, which is torn down upon session termination. Doesn't have any
persistently stored encryption/credentials data.

### Guest mount (public session)

The same with ephemeral, except it is not tied to a particular gaia id. Do not
confuse with 'public mount'

### Public mount (kiosk session)

This is a regular persistent mount with the difference, that the credentials for
it are not supplied, but derived from the user name (application id). This mode
is used for kiosk apps.

## Mount process

* If there is no vault for the user present and "create" flag is supplied, then
  create the vault
  * If it is a persistent vault, also create the keys on disk
  * If it is not a persistent vault, prepare ramdisk first.
* If the vault exists - verify passed credentials against the stored credentials
  (see [decrypt.md])
* Insert the decryted filesystem keys into the kernel keyring for persistent
  vault.
* Spawn a new process (out of process mounter), which performs the mount itself.
  * In case of ecryptfs/dmcrypt - the vault is mounted on top of
    `/home/.shadow/<s_h_o_u>/mount`.
  * In case of fscrypt, `/home/.shadow/<s_h_o_u>/mount` is the vault and the
    decrypted content overlays the directory.
* If this is the first mount of the vault - copy over the skeleton from
  /etc/skel
* Create managed directories (Cache/GCache/etc.)
* Create target mount points and perform bind mounts ([filesystem_layout.md])
* Initialize PKCS11 token
* Initialize lock screen verifier
* Initialize WebAuthn token

### Error conditions

* If decrypting the vault keyset fails because the call to decrypt
  in the TPM fails, it is assumed that the  user supplied password is incorrect.
  This may occur if the user changes their password, as the keyset
  would still be wrapped with the old password, but the call to Mount() would
  presumably use the current credentials. In this case, the system is given a
  chance to migrate the keys by having the user supply the old password.
* If the keys are considered undecryptable, then remove the vault and indicate
  that to the higher level system. This can happen in the following scenarious:
  * On disk data corruption (either due to physical events or code bugs).
  * TPM reset for TPM encrypted blobs - clearing tpm state changes necessary
    secrets used to encrypt the keyset and renders the decryption impossible.
* If the blob was protected using the TPM, and the TPM is unavailable,
  for example, it has been disabled, then the call returns an error
  code indicating that either there was a failure communicating with
  the TPM or that the TPM is in defend lock (a state where the TPM
  believes that a brute-force attack is happening, and so it
  temporarily blocks most API calls). Communications failures are
  usually transient, and can be fixed by calling the API a second
  time. (For example, some chips on resume from S3 require us to
  re-establish our long-lived session.) If the device allows manual
  disabling of the TPM, this error would not be transient, and the
  user would have to re-enable the TPM. Defend lock errors are always
  transient, but the back-off period is variable. While sometimes it
  may be seconds, other times it is best to reboot the system to clear
  this state.
* If the blob was protected using the TPM, and there is a failure in
  the TSS API (couldn't load the cryptohome TPM key, etc.) that
  doesn't correspond to a TPM clear, then a communications failure
  error is returned as described in the last section.
* If the following errors occur on creation, cryptohome returns an
  error and cannot remedy the problem:
  * If the TPM is unavailable, cryptohome falls back to
    scrypt-based protection, and the call to `scryptenc_buf`
    fails for any reason.
  * If writing the encrypted vault keyset to disk fails for any
    reason.
  * If creating the user's vault path fails for any reason.
  * If setting the ownership of the user's vault path fails for any
    reason.
  * If decrypting the vault keyset fails because the call to decrypt
    using scrypt fails, it is assumed that the password is
    incorrect, as with the TPM above.
  * If adding the decrypted keyset to the kernel keyring before
    ecryptfs mount fails, it is assumed that the key material was
    decrypted properly but some other problem exists outside of the
    control of cryptohome.
  * If the call to mount the user's cryptohome fails, it is assumed
    that some other problem exists outside of the control of
    cryptohome.
  * If the user's cryptohome must be deleted due to keys corruption,
    and the cryptohome cannot be removed, then some other problem
    exists outside of the control of cryptohome.

## Unmount

The session termination in ChromeOS is performed by restarting the session
manager. Its upstart script issues UnmountAll call before launching new prompt.
That call terminates all existing user vault mounts and takes down all tokens
and verifiers.
