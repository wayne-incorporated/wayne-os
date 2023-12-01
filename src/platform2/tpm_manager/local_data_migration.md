# Local data migration

The document of the local data migration of the important secrets that used to
maintained by **cryptohome**.

# Background

Until M84, tpm manager only worked for TPM2.0 case. For TPM1.2 cryptohome
used to maintain the following auth values instead of tpm_manager:

1. Owner password.
2. Owner auth delegate.

Starting M84, tpm manager is launched for TPM1.2 as well, and the secrets
listed above are migrated to the same file where auth values were stored for
TPM2.0, which is manipulated by the object `LocalDataStore`.

The term "local data" is used for consistency with the object name, which in
cryptohome used to be "TPM status" referring to the same thing.

# Applicability

Since tpm manager works for TPM2.0 since ever, the local data migration is only
applicable to TPM1.2. For TPM2.0, local data migration is a no-op.

# Sources

*   [The implementation of local_data_migration]
*   [The definition of tpm manager local data]
*   [The definition of legacy tpm status]

[The implementation of local_data_migration]: ./server/local_data_migration.cc
[The definition of tpm manager local data]: ../system_api/dbus/tpm_manager/tpm_manager.proto
[The definition of legacy tpm status]: https://chromium.googlesource.com/chromiumos/platform2/+/refs/heads/release-R84-13099.B/cryptohome/tpm_status.proto
