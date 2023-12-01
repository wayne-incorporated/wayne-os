# Firmware Management Parameters

Cryptohome manages a TPM space which holds management parameters for the
firmware.

[TOC]

## Overview

Firmware Management Parameters (FWMP) control the rewritable (RW) firmware boot
process. They can be used to disable developer mode on enterprise devices. If
developer mode is enabled, they can limit which kernel key can be used to sign
developer images, and/or enable developer features such as booting from USB or
legacy OS.

The FWMP is stored in a TPM NVRAM space. The space is logically defined as
follows:

```c
struct FirmwareManagementParametersRawV1_0 {
  uint8_t crc;
  uint8_t struct_size;
  uint8_t struct_version;
  uint8_t reserved0;
  uint32_t flags;
  uint8_t developer_key_hash[SHA256_DIGEST_LENGTH];
} __attribute__((packed));
```

The crc is a CRC8 over the struct_version...hash fields.

The struct_size is the size of the entire structure in bytes.

The struct_version contains the major version in the high nibble and the minor
version in the low nibble. Current structure is version 0x10 = 1.0. Minor
version changes are backwards-compatible; a 1.0 reader can parse any 1.x data,
though there may be new fields following hash[]. Major version changes are not
backwards-compatible; a 1.0 reader cannot parse any 2.x data.

The reserved0 field is written 0 by current writers and ignored by current
readers. It is for padding the flags to a 32-bit boundary. Future 1.x versions
of the struct may use it.

The flags field contains several bitflags. Unused flags bits are set to 0 by
current writers.

```c
DEVELOPER_DISABLE_BOOT = 1;
DEVELOPER_DISABLE_RECOVERY_INSTALL = 2;
DEVELOPER_DISABLE_RECOVERY_ROOTFS = 4;
DEVELOPER_ENABLE_USB = 8;
DEVELOPER_ENABLE_LEGACY = 16;
DEVELOPER_USE_KEY_HASH = 32;
DEVELOPER_DISABLE_CASE_CLOSED_DEBUGGING_UNLOCK = 64;
```

The developer_key_hash is a SHA-256 hash of the developer key data
(vb2_packed_key.key_size bytes at offset vb2_packed_key.key_offset from the
start of a vb2_packed_key).

Once the struct is filled, it is written to the NVRAM space. A subsequent 0 byte
write locks the NVRAM space (bWriteDefine) from future modification without
redefinition using the TPM Owner passphrase or by asserting physical presence.

See cryptohome.xml for the exact D-Bus API calls. See
firmware_management_parameters.h for more information. See
src/platform/vboot_reference/ for the firmware implementation. Note that the
contents of the space and the NVRAM index must be consistent with
src/platform/vboot_reference/firmware/lib/include/rollback_index.h.

## Device integration

FWMP is an optional space. If it is not present, the firmware behaves in a
default manner, as if FWMP were present with flags=0.

On a fresh installation, enterprise enrollment or a developer may create a FWMP
while the TPM owner password is still known:

```bash
cryptohome --action=set_firmware_management_parameters \
  --flags=XXX [--developer_key_hash=YYY]
```

Where `XXX` is the flags as a 32-bit value, and `YYY` is the optional SHA-256
developer key hash digest as a 64-character hexadecimal string.

If the device is de-enrolled, or a developer wants to remove a FWMP they
previously created:

```bash
cryptohome --action=remove_firmware_management_parameters
```

Note that still requires the TPM owner password to be known, or the TPM owner to
have been reset by toggling developer mode off and back on using the firmware or
by issuing:

```bash
crossystem clear_tpm_owner_request=1
```

and then rebooting.

On subsequent boots, the TPM owner password is no longer known, preventing the
space from being reset or removed. The current settings can still be read back
via:

```bash
cryptohome --action=get_firmware_management_parameters
```

## NVRAM Index Selection

The NVRAM space index 0x100A was picked to follow the other spaces used by the
firmware (0x1007 - 0x1009).
