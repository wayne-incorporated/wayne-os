# Filesystem layout

[TOC]

## Overview

Cryptohome manages directories as follows:

*   `/home/.shadow`: Location for the system salt and individual users'
    salt/key/vault

*   `/home/.shadow/<salted_hash_of_username>`: Each Chrome OS user gets a
    directory in the shadow root where their salts, keys, and vault are stored
    (s_h_o_u).

*   `/home/.shadow/<s_h_o_u>/vault`: The user's vault (the encrypted version of
    their home directory)

*   `/home/.shadow/<s_h_o_u>/master.0`: Vault keyset for the user. The vault
    keyset contains the encrypted file encryption key and encrypted filename
    encryption key. It also contains the salt used to convert the user's passkey
    to an AES key, and may contain the TPM-encrypted intermediate key when TPM
    protection is enabled (see tpm.h for details).

*   `/home/.shadow/<s_h_o_u>/mount`: On successful login, the user's vault
    directory is mounted here using the symmetric key decrypted from master.X by
    the user's passkey.

*   `/home/user/<s_h_o_u>`: bind mount of `/home/.shadow/<s_h_o_u>/mount/user`
    (applications should prefer this mount point for interacting with
    cryptohome)

*   `/home/root/<s_h_o_u>`: bind mount of `/home/.shadow/<s_h_o_u>/mount/root`

*   `/home/chronos/u-<s_h_o_u>`: bind mount of
    `/home/.shadow/<s_h_o_u>/mount/user` used for multi-user support.
    (deprecated)

*   `/home/chronos/user`: bind mount of the active user
    `/home/.shadow/<s_h_o_u>/mount/user`, for backward compatibility.
    (the usage of the mount point is discouraged)

The underlying filesystem mechanisms are using one of the following: `ecryptfs`
(deprecated, used on old kernels), fscrypt (current, v1 is used on 4.x boards
and v2 is used on 5.4+ boards) and lvm+dmcrypt (upcoming vault management and
encryption mechanism). The filesystem encryption keys are themselves encrypted
via various mechanisms (see [vkk.md]).
