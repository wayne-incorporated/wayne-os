# Low-Entropy (LE) Credential Protection

This feature enables us to protect low-entropy credentials, which allows the UI
to offer PIN codes as an authentication mechanism for sign-in.

[TOC]

## Overview

LE secrets that need brute force protection are mapped to high-entropy secrets
that can be obtained via a rate-limited lookup enforced by the security module.
The high-entropy secret is then plugged into the actual authentication mechanism
used to implement sign-in. In other words, the released high-entropy secret is
used as the key to protect a VaultKeyset, which contains further secrets such as
the actual file system encryption key protecting encrypted user data.

The low-entropy credentials and related metadata (including the number of
unsuccessful authentication attempts to this point) are stored in an encrypted
form on disk. This ensures that the security module can enforce retry limits
against a compromised OS or hardware-level attacks while minimizing the storage
footprint in security module flash. The security module manages a number of
credential slots which are referred to by labels.

Cryptohome communicates with the security module to verify that the credential
presented by a user in an authentication attempt is correct. On success, the
security module releases the corresponding high-entropy secret to cryptohome.

Brute forcing is prevented by enforcing a cryptohome-defined delay schedule in
the security module firmware. This only allows a limited number of
authentication attempts for a specified timeframe (the delay schedule can also
set a hard limit on the number of unsuccessful attempts). Each time a correct LE
credential is provided, the number of unsuccessful attempts is reset to 0.

An LE secret which has been locked out (i.e all attempts exhausted) may be reset
by providing a separate high entropy reset credential to the LECredentialManager
class (this reset credential is generated, encrypted to a conventional password
for that user, and supplied when the LE secret is being set up). Presenting the
reset credential to the security module resets the attempts counter for the
credential, thus clearing the lockout and allowing the LE credential to be used
in subsequent authentication attempts.

## Hash tree

A hash tree is used by the security module to ensure integrity and track the
state of all the credentials' metadata. Each credential has its own hash tree
leaf, which is addressed by an integer label corresponding to its position in
the tree.

Using the hash tree we can obtain a root hash of the entire tree, and store that
in the security module. This allows us to capture the entire state of the
on-disk tree, using a single hash.

This hash is then used to verify the integrity of the state passed to the
security module while performing authentication/insert/reset operations. Since
it is stored in the NVRAM of the security module, it can't be manipulated by the
OS or attackers. Hardware attacks are hard since they will require decapping the
chip.

For more information on hash trees, see
https://en.wikipedia.org/wiki/Merkle_tree .

## Relevant classes

A diagram can be used to illustrate the various classes and their relation.

```


                             LECredentialManager
                                  /     \
                                 /       \
                                /         \
                               /           \
                      SignInHashTree    LECredentialBackend
                              |
                              |
                              |
                              |
                     PersistentLookupTable
```

### PersistentLookupTable

This class provides a key-value like storage. The key is a uint64_t, and the
value is a binary blob which contains data in a caller-determined format. The
class aims to provide an atomic storage solution for its entries; updates to the
table will either be correctly recorded or will have no effect. So, the table
will always be in a valid state (without partial updates).

It provides an API that allows values to be Stored, Retrieved and Removed, and
is used by the SignInHashTree.

### SignInHashTree

This class stores and manages the various credentials and labels used by the
LECredentialManager on disk. As the implementation of the hash tree concept, it
not only represents the leaf nodes of the hash tree, but also keeps track of all
the inner-nodes' hash values.

Using PersistentLookupTable, it stores an encrypted blob containing the metadata
associated with an LE credential. It also stores alongside it a MAC which has
been calculated on the metadata. The MACs are used during root hash
calculations. Both of these are expected to be provided by the caller.
Logically, the PersistentLookupTable can be thought of as storing all the leaf
nodes of the hash tree.

The hash tree is defined by two parameters:

-   The fan-out, i.e the number of children of a node.
-   The length (in terms of bits) of a leaf node label.

These two parameters can be used to determine the layout of the hash tree. This
helps to understand:

-   How a root hash is calculated.
-   What are the hash values that are required, given a particular leaf node, to
    recalculate a root hash.

The SignInHashTree also contains a HashCache file. This file stores the inner
node hash values, and helps avoid recalculation of these values with each
authentication attempt. The HashCache file is redundant, and should be
regenerated if there is any discrepancy detected between it and the leaf nodes
and/or the state on security module.

### LECredentialBackend

This is an interface used to communicate with the security module to perform the
LE Credential operations. The LECredentialBackend will expose the following
functionality provided by the security module:

-   Validate a credential.
-   Enforce the delay schedule provided during credential creation.
-   Encrypt and return the credential metadata.
-   Store, update and provide an operation log, to be used in case of state
    mis-match with on-disk state.

### LECredentialManager

This class uses both the SignInHashTree and LeCredentialBackend to provide an
interface that cryptohome can use to Add, Check, Reset and Remove an LE
Credential.

It provides support for the following operations:

-   InsertCredential: Provided an LE Secret, the high-entropy secret it is
    guarding, a reset credential which is used to unlock a locked-out LE secret
    and a delay schedule, it stores the resulting credential and returns a
    uint64_t label which can be used by cryptohome to reference the credential.

-   CheckCredential: Attempts authentication of a user. It is provided the label
    of the credential to verify, and the user-supplied secret, and on success
    returns the corresponding high entropy secret.

-   RemoveCredential: Given a label, removes that credential from the hash tree,
    and updates the security module's state to reflect that.

-   ResetCredential: TODO(https://crbug.com/809723)

## Key derivation

### LE secret

The generation of the LE secret which is stored by the LE Credential manager can
be best illustrated by the following diagram:

Definitions:

-   `VKK`: VaultKeyset Key
-   `VKK IV`: VKK Initialization Vector
-   `VK`: VaultKeyset

```
         LE Salt (randomly generated)  +  User PIN
                          |
                          |
                          |
                       Scrypt
                          |
                          |
                         \|/
              VKK IV   +   SKeyKDF   + LE Secret


    VKK Seed (randomly generated high entropy secret)
                          |
                          |
                (guarded by LE secret)
                          |
                          |
                         \|/
            Stored in LECredentialManager


                       VKK Seed
                          |
                          |
                    HMAC256(SKeyKDF)
                          |
                          |
                         \|/
                         VKK


                 VKK IV + VK(Vault Key)
                          |
                          |
                 AES Encryption(VKK)
                          |
                          |
                         \|/
                    Encrypted VK
```

Per the above scheme, the SerializedVaultKeyset will store the LE Salt, so that
it can be used to regenerate the LE secret used during CheckCredential().

### Reset secret

TODO(https://crbug.com/809723)

## Resynchronization

TODO(https://crbug.com/809710)
