# Encrypted Reboot Vault

Encrypted reboot vault provides an encrypted store for files across reboots in
absence of the TPM (or if the TPM is going to get cleared on the next reboot).
The encrypted reboot vault uses pmsg to store a random key that will be used to
encrypt an fscrypt directory on the stateful partition.

From https://lore.kernel.org/patchwork/patch/532737/:

```
A secured user-space accessible pstore object. Writes
to /dev/pmsg0 are appended to the buffer, on reboot
the persistent contents are available in
/sys/fs/pstore/pmsg-ramoops-[ID].
```

The encrypted reboot vault takes advantage of this utility to transiently
encrypt data across reboots without using a persistent memory store for the
encryption key. On ChromeOS, since all devices are configured with a RAM-based
pstore, the encryption key is never stored on a storage device. In case the
device shuts down or loses power, we lose the encryption key permanently, so
data stored in the encrypted reboot vault will not be recoverable.

The encrypted reboot vault is not a replacement for the encrypted stateful
partition: its primary function is to provide a transient encrypted store for
files in absence of the encrypted stateful partition. An example of this is
during clobber on mount failure: since the TPM is set to be cleared on the
next boot, there isn't a persistent store for the encryption key.

## Expected consumers
The encrypted reboot vault is useful for log/crash data in absence of more
persistent encrypted storage: consider using the encrypted stateful partition
unless it is expected that the encrypted stateful partition may not be
available. Since the encrypted reboot vault is setup with a per-system key, it
should not be used for storing user data under any circumstance.

## Vault lifecycle
The lifetime of the vault encryption key (and by extension, the vault itself)
is tied to when the device is shut down/loses power. Since the encryption key is
maintained exclusively in memory, any loss of power renders the encryption key
irretrievable: on the next boot, the encrypted reboot vault would fail to
retrieve the key from pstore, purge the existing vault and setup a new vault.

## Command line usage
The encrypted reboot vault is set up during startup, either by unlocking an
existing vault:
```
$ encrypted-reboot-vault --action=unlock
```

Alternately, if an existing reboot vault does not exist (or fails to unlock),
a new encrypted reboot vault is created:
```
$ encrypted-reboot-vault --action=create
```

Additionally, the encrypted reboot vault can be removed at any point:
```
$ encrypted-reboot-vault --action=purge
```
