# Pinweaver_provision

This document is meant to show how to provision the salting key for
**pinweaver-csme** with the new executable `pinweaver_provision`.

## Background

Pinweaver-csme is a project that implements Pinweaver with CSME and a TPM 2.0
chip. Provisioning the TPM salting key dedicated to serving the purpose of this
work is a key component of security.

The provisioning process for pinweaver-csme is, in brief, to provision a salting
key that is exclusively for CSME's use. Specifically it computes the (ECC)
salting key hash ( sha256 of concat X coordinate and Y coordinate of the salting
key), sends it to CSME, and asks CSME for committing the value. In the future,
CSME can verify the salting key that is returned by TPM in the future by
comparing the hash value.

## Supported subcommands

## `pinweaver_provision --provision`

it provisions the salting key for **pinweaver-csme**. Specifically, it persists
the salting key in TPM to a persistent object handle that is well-known to CSME
; then, it calls CSME to set and commit the hash of that salting key hash to
fuses so CSME can verify the salting key in the future. If the device has
built-in pinweaver support by GSC (e.g., cr50), the content to provision is
all 0s, in order to disable the pinweaver functionality by CSME.

If the salting key is persisted already, it skips the persisting process.

If the salting key hash is already committed, the tool compares the salting key
hash against what is read back from CSME. In case of a mismatched result it
raises an error and returns a non-zero value. Once the provisioning is done
once, calling this subcommand should also return success (i.e. returning 0).

## `pinweaver_provision --init_owner`

It asks CSME to initialize the resources after TPM clear. In particular, the
necessary NV spaces in TPM are allocated per request by CSME. Note that if the
device is provisioned w/ all-0s, this command will fail.

## Default subcommand

There is no default subcommand if none is given. One has to specify the
subcommand explicitly. It prints the usage and returns a non-zero value if the
subcommand is wrong, or none is given.

### Pre-condition

Both subcommands are required to be run w/ empty TPM passwords; otherwise the
operations should fail. Here are the rationales:

*   CSME allocates the NV space with empty owner password authorization. Thus,
    `--init_owner` requires the owner password to be empty.

*   Attempts of creating salting key with empty endorsement password
    authorization, and persisting the key with empty owner password
    authorization. Thus, `--provision` requires the empty owner/endorsement
    password to be empty.

Note that the `tpm_managerd` sets the owner password automatically at first boot
after TPM clear. In order to stop `tpm_managerd` from setting the password, one
will needs to use a factory image or push the factory tools to the device before
clearing the TPM. See [Google Chromium OS Factory Software Platform] for the
instruction. W/o the factory toolkit, one can also somehow touch the flag file
`/run/tpm_manager/no_preinit` before `tpm_managerd` starts up, but there is no
official support for a non-factory test image to do that.

In addition to the empty authorization values, `pinweaver_provision
--init_owner` works only if the salting key hash is provisioned. Even w/ empty
owner/endorsement authorization, CSME fails to initialize due to failed
verification against committed salting key hash.

## Recommended provisioning flow

The following series of operations is one way of performing the key
provisioning.

*   TPM clear and reboot. This is mandatory so the TPM authorization values are
empty.
*   Run `pinweaver_provision --provision` to provision the salting key. This
persists the salting key of interest in TPM and persists its hash in CSME in a
write-once manner. This is mandatory so the key is provisioned.
*   Run `pinweaver_provision --init_owner`. This is strongly recommended as a
verification that the initialization process by CSME with the provisioned
salting key.
*   Run `pinweaver_client selftest`. This is an existing tool that exercises
most of pinweaver operations. Hopefully it can help us catch SW bugs and an
end-to-end integration of CSME+TPM after provisioning.

[Google Chromium OS Factory Software Platform](https://chromium.googlesource.com/chromiumos/platform/factory/+/main/README.md)
