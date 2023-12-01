# Lockbox

Cryptohome manages a tamper-evident file which is meant to contain
install-lifetime system attributes.

[TOC]

## Overview

Tamper-evident storage can be accessed by consumers over D-Bus using the
InstallAttributes* calls. Essentially, this provides a name-value storage
interface for Get()ing and Set()ing values during install. The datastore is made
tamper-evident by serializing it to a bytestream and persisting it to the
filesystem via the Lockbox class. This is done when
InstallAttributes::Finalize() is called. After finalization, the data becomes
read-only.

The Lockbox class provides a clear interface for implemented TPM NVRAM-backed,
tamper-evident data storage. It allows for the creation, destruction, storage,
and retrieval of tamper-evident data. InstallAttributes stores its serialized
data via this mechanism and reloads it similarly to ensure data integrity.

Each lockbox assures tamper-evidence cryptographically by storing a SHA256
digest of the supplied data blob in a TPM NVRAM space. The space itself is
logically defined as follows:

```c
struct {
  uint32_t data_size;
  uint8_t flags;
  uint8_t salt[SHA256_DIGEST_LENGTH];
  uint8_t hash[SHA256_DIGEST_LENGTH];
} __attribute__((packed));
```

The data size is the expected size of the "locked" data. This provides a simple
validity check and ensures collision attacks against the stored data are
size-limited.

Flags is reserved for future use, primarily in anticipation of future digest
changes or data serialization changes (encrypted versus not). At present, flags
is always 0.

The salt is 32 bytes of randomly generated data sourced from the TPM itself.
This also aids in collision attack deterrence. Many devices will likely share
the same file. If a collision is found for the hash of that file, arbitrary
replacement attacks would be feasible. The added salt serves to increase the
difficulty of these forms of attack.

The hash is computed as `SHA256(data||salt)`.

Once the struct is filled, it is written to the NVRAM space. A subsequent 0 byte
write locks the NVRAM space (bWriteDefine) from future modification without
redefinition using the TPM Owner passphrase or by asserting physical presence.

See cryptohome.xml for the exact D-Bus API calls. See lockbox.h and
install_attributes.h for more information on what each provides.

## Device integration

InstallAttributes and Lockbox are initialized by default whenever the
cryptohomed service is started. On any system that is upgraded to support
InstallAttributes, it will treat the InstallAttributes as an empty-locked store
by observing that no NVRAM space was defined nor backing lockbox file created.

On a fresh installation, cryptohomed will start and immediately begin the TPM
ownership process. Upon completion, InstallAttributes will perform one-time
initialization that creates its Lockbox and destroys any existing Lockbox data.
cryptohomed will then "forget" the TPM owner password when told to by Chrome
(such as at the end of the EULA view or at the login screen). Chrome will
populate the InstallAttributes during the system's first boot and call
Finalize() upon completion. In addition, cryptohomed will call Finalize() any
time a (Async)Mount request is received over D-Bus. This is to ensure that the
InstallAttributes are fully populated prior to the system going into general
use. On first login, a very fast user may perform the first Mount call prior to
the TPM being owned. In that case, the InstallAttributes will remain freshly
initialized and unlocked until the next Mount attempt occurs (after TPM
ownership has completed).

Recovery from a corrupt Lockbox requires the TPM to be cleared of a TPM owner.
This can be triggered by toggling the developer mode switch and rebooting, or by
going through the system recovery flow.

## NVRAM Index Selection

This value was picked by reviewing the related specification documents. The
index is a managed namespace as laid out below:

```
    3                   2                   1
 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|T|P|U|D| resvd |   Purview      |         Index                |
(T=TPM, P=platform maker, U=platform user, D=pre-defined)
```

(from TCG TPM Structures rev 103)

Some ranges have been declared reserved in other specs:

*   `0xFFFFFFFF` is the NVRAM lock (permanent).
*   `0x50010000` is reserved for BIOS use.
*   `0x0000Fxxx` preallocated/reserved by for locality use.
*   `0x0001xxxx` are a handful of TSS reserved ranges.
*   `0x10000001` is the deprecated NV_INDEX_DIR.
*   `0x00000000` is the bGlobalLock index.

In addition, there is at least one other major user. For tboot, Intel uses:

*   `0x20000001`: `00100000000000000000000000000001`
*   `0x20000002`: `00100000000000000000000000000010`

in the Platform User range. It's unclear if they'll expand further out in the
future, so we leave room for them to add a single space.

*   `0x20000004`: `00100000000000000000000000000100`

Arguably, we could use a 'P' space, but that would complicate Chromium OS use on
non-Chrome hardware.
