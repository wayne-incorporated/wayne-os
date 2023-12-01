# CryptohomeError

[TOC]

## TL;DR

If you need to return `StatusChain<CryptohomeError>` or
`StatusChain<Cryptohome*Error>`, then you should:

-   Use `MakeStatus<>` to create the error, check existing usage in codebase for
    examples.
-   Use `.Wrap()` to wrap errors from lower levels, if any.
-   Add new enum used in `CRYPTOHOME_ERR_LOC` to `cryptohome/error/locations.h`.

## Overview & Goals

For login-related UserDataAuth DBus APIs, we use a set of error
handling/reporting mechanisms known as the `CryptohomeError`.

The goals are: * Better Visibility for Users: Surfacing the above distinct
errors to Chrome so that users have more information and visibility when
something goes wrong, including the ability to redirect them to help center page
specific to the error that they’re receiving. * Put Users in Control: Surfacing
the handling of these errors (such as giving recommendations on how to handle
the error) to Chrome so that users have more control over errors, especially
those that might cause them to lose their data. * Effective Monitoring: A more
fine-grained and systematic error monitoring so that we can better find new
errors or trends within the UMA.

## Representing Error

For errors that are represented by `CryptohomeError`, there are 2 key
concepts: - Recommended Actions, it details what can the caller or user do to
resolve the situation or error. - Error ID - An identifier that identifies the
exact error. It is fine grained

### Recommended Actions -- PrimaryAction vs PossibleAction

There are 2 types of recommended actions:

One of them is `PrimaryAction`, in which cryptohome is sure about the cause of
the error or situation. For instance, Mount() failed because the vault migration
is incomplete.

Meanwhile, `PossibleAction` is when cryptohome is unsure about what caused the
error, however, it has reasons to believe that certain action could clear those
conditions. For instance, if `Mount()` failed because the mount point is busy,
then cryptohome could recommend the user to reboot.

Therefore, when raising an error in cryptohomed, we can either list a several
possible actions that we believe to be relevant, or list one primary action
when we are sure about the root cause. When the errors propagate up the
callstack to the DBus/UserDataAuth layer, a single `PrimaryAction` or a set
of `PossibleAction`s will be determined and transmitted as part of the
DBus reply.

### Cross Version, Unique Identifier

The error ID aims to be: - Relatively stable across version (as compared to file
and line number). - Not confusing to the user when displayed. - Stackable so
that there's context. - Fine grained, i.e. tied to that specific error.

This is implemented as a dash-seperated series of integers. For example:
"42-2-17".

Each of the integers in the ID is called a node. Each node usually corresponds
to a frame in the C++ callstack. Every time `MakeStatus<>` is called, a node is
generated. Also, TPM errors are appended to the ID as a node.

The numerical value of the node is the enum that is passed through
`CRYPTOHOME_ERR_LOC()` to `MakeStatus<>`, and they should be unique and managed
either manually or automatically in `cryptohome/error/locations.h`. Each of the
enums should be named in a way that briefly descripts what happened and its
value should not conflict with any values that was used previously. Enum that
was previously in use can remain in the file and not be removed. There's a tool
that can check that each of the enum is not used multiple times.

Also, a special range of numerical value is defined for errors from TPM, to
separate them from the enums coming from `locations.h`.

To map the numerical value reported back to the enum or TPM error, see the
section on Error Location tool.

## Basic Concepts on CryptohomeError

### Stackable Error and Error ID

The `CryptohomeError` is stackable, and if there's an error, the
`CryptohomeError` stack will contain recommended actions that will advise the
caller on what the situation is or what actions might resolve the issue.
Furthermore, the stack of `CryptohomeError` can be extracted to produce an error
ID mentioned above that is unique to the error and behaves like a "smart
stacktrace", so that we've more insights into how the error occurred.

### Transition from legacy CryptohomeErrorCode enum

During the transition period, the `CryptohomeError` and related classes will
take the `CryptohomeErrorCode` and when constructing the DBus reply, the related
utility methods will insert the legacy `CryptohomeErrorCode` into the reply as
previous. Thus, there will be a period in which both the legacy
`CryptohomeErrorCode` and the new information from `CryptohomeError` class will
be present in the DBus reply.

## Practical Guide to raising CryptohomeError

### Raising an error

If an error occurred, we can create it with:

```
  return MakeStatus<CryptohomeError>(
      CRYPTOHOME_ERR_LOC(kLocClassNameAndShortDescriptionOfError),
      ErrorActionSet({PossibleAction::kReboot}),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY);

  return MakeStatus<CryptohomeError>(
      CRYPTOHOME_ERR_LOC(kLocClassNameAndShortDescriptionOfError),
      ErrorActionSet(PrimaryAction::kIncorrectAuth),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY);
```

In which `kLocClassNameAndShortDescriptionOfError` is a project wide unique
location ID. Callers can name and use the identifier directly in the call site,
then invoke the following command before compiling to generate the declaration
in cryptohome/error/locations.h:

```
(cros_sdk) /mnt/host/source/src/platform2 $ ./cryptohome/error/tool/location_db.py --update
```

The second parameter is a literal initializer list for the set of actions that
cryptohomed recommends. For possible values of recommended actions, check out
`cryptohome/error/action.h`. The initializer list should be wrapped in
`ErrorActionSet()` so that the template can deduce its type. If the initializer
list is empty, we can use `NoErrorAction()` as well.

Lastly, we supply the legacy `CryptohomeErrorCode` to the error so that the same
error will be present in the DBus reply.

### Wrapping an error

If an error occurred in a function that we've called and we want to wrap the
error for it to bubble up the callstack, we can:

```
  StatusChain<CryptohomeError> error = ActionThatMightResultInAnError();
  if (error) {
    // Logging and etc...
    return MakeStatus<CryptohomeError>(CRYPTOHOME_ERR_LOC(kLocXXX), NoErrorAction(),
        std::nullopt).Wrap(std::move(error));
  }
```

In which `kLocXXX` is the location ID that is the same as above. The
`NoErrorAction()` can be replaced with any recommended actions that the current
layer feels appropriate, and `std::nullopt` can be replaced with any
CryptohomeErrorCode if the layer original intends to return any legacy
CryptohomeErrorCode.

### Custom Error

In the case when the error needs to carry more information than that the
`CryptohomeError` can hold, custom errors can be used. For instance, if we need
to check the reason why something failed halfway when the error is bubbling up
the stack, so that we can consider retrying it immediately in cryptohomed, we'll
need a field that notes these information.

In these scenarios, it is recommended to implement a custom error class that
inherits off the CryptohomeErrorObj. For an example on how it's done, see
`MountError` in `cryptohome/error/cryptohome_mount_error.h`.

### TPM Error

We need special care when dealing with TPM-related errors. Currently, we've an
existing implementation for `TPMErrorBase` and it is generic, belonging to
libhwsec. Therefore, it does not make sense to have `TPMErrorBase` as a derived
class of `CryptohomeError`, thus forbidding the `TPMErrorBase` as part of the
chain/stack of error in this design.

To deal with that, we've a `CryptohomeTPMError` that contains the exact set of
information that the TPMError contains. Furthermore, the CryptohomeTPMError is a
derived class of the `CryptohomeError`, and thus can be part of the error chain.
Note that we should only use `CryptohomeTPMError` to wrap `TPMErrorBase` into
a cryptohome error, and shouldn't construct a `CryptohomeTPMError` ourselves
because it doesn't make sense to do so. In addition, you can't specify the
location or error actions when constructing a `CryptohomeTPMError` because
those info will be derived from the `TPMErrorBase`.

In practice, to wrap a `TPMErrorBase` that we've received from libhwsec (or
other classes that produces such error) as a `CryptohomeError` so that it can
bubble up the call stack, we can:

```
  StatusChain<TPMErrorBase> err = SomethingThatProduceTPMErrorBase();
  if (err) {
    auto converted = MakeStatus<CryptohomeTPMError>(err);
    return MakeStatus<CryptohomeError>(CRYPTOHOME_ERR_LOC(kLocXXX))
            .Wrap(std::move(converted));
  }
```

### Unit testing

The error location is treated more akin to logging as it is more of a diagnostic
tool, and therefore it is generally not expected to test it in unit test.
However, for scenarios that matter to the end users, we should test that the
error actions returned are correct.

This can be done through using the `PrimaryActionIs`
and `PossibleActionsInclude` utility functions:

```
  EXPECT_TRUE(PrimaryActionIs(PrimaryAction::kIncorrectAuth));
  EXPECT_TRUE(PossibleActionsInclude(PossibleAction::kReboot));
```

### Disposing of Expected Errors or Retries

Sometimes we'll have a StatusChain that will be disposed because there's a retry that followed, if the error is working as intended, or if we have fallback actions for that error.
In those situations, we should dispose of the said StatusChain with the Reap*() functions instead of simply letting it disappear.
In the case that we have fallback actions, we'll likely still want to monitor those errors as they're not intended.
Use `ReapAndReportError` for those errors.

For instance:

```
  // The action may fail and it is expected.
  CryptohomeStatus status = ...;
  // The WAI error should be disposed of properly.
  ReapWorkingAsIntendedError(std::move(status));
```

```
  CryptohomeStatus status = ...;
  if (!status.ok()) {
    // Failed, we'll retry.
    // The previous error should be disposed of properly.
    ReapRetryError(std::move(status));
    status = ...;
  }
```

```
  CryptohomeStatus migration_status = ...;
  if (!migration_status.ok()) {
    // We don't want to fail the operation, but the previous
    // error should be reported.
    ReapAndReportError(std::move(status), "PinMigrationError");
  }
  return pre_migration_status;
```

## Error Locations Tool

A tool is written to deal with the location enums used in
`CRYPTOHOME_ERR_LOC()`. The tool should run in cros_sdk.

The use of this tool is optional. Developer can choose to write the enums
manually and disregard this tool. However, this tool will still automatically
check that the use of enums are correct.

If you are using the tool to decode or lookup error code, it is recommended to
sync your repository to at least the version at which the error code is
generated. For instance, if you are debugging issues with logs from M100, it is
recommended to sync your source code to at least M100 or newer. It is OK to be
on version newer than the version on which the error code was generated.

### Update/generate declarations for location enums used

To generate the declarations for location enums used throughout the code base
and update `cryptohome/error/locations.h`, run the following command:

```
(cros_sdk) /mnt/host/source/src/platform2 $ ./cryptohome/error/tool/location_db.py --update
```

### Check that the usage of location enums are correct

The checks are ran with unit test builds, i.e. `FEATURES=test emerge-$BOARD
cryptohome`.

However, to run the checks manually:

```
(cros_sdk) /mnt/host/source/src/platform2 $ ./cryptohome/error/tool/location_db.py --check
```

### Lookup individual error location UMA value

If we have a location UMA value that is found in the UMA or error log, we can
look it up with the tool, for example:

```
(cros_sdk) /mnt/host/source/src/platform2 $ ./cryptohome/error/tool/location_db.py --lookup 5
INFO:root:Using cryptohome source at: /mnt/host/source/src/platform2/cryptohome
Value 5 is kLocChalCredDecryptSPKIPubKeyMismatch and can be found at:
./challenge_credentials/challenge_credentials_decrypt_operation.cc:94
```

### Decode an error location stack

If we have a stack of error location and wishes to decode it, we can run the
tool:

```
(cros_sdk) /mnt/host/source/src/platform2 $ ./cryptohome/error/tool/location_db.py --decode 5-6-7
INFO:root:Using cryptohome source at: /mnt/host/source/src/platform2/cryptohome
kLocChalCredDecryptSPKIPubKeyMismatch=5 @ ./challenge_credentials/challenge_credentials_decrypt_operation.cc:94
kLocChalCredDecryptSaltProcessingFailed=6 @ ./challenge_credentials/challenge_credentials_decrypt_operation.cc:99
kLocChalCredDecryptNoSalt=7 @ ./challenge_credentials/challenge_credentials_decrypt_operation.cc:112
```

## Tips and Tricks

### Merge conflict in error/locations.h

It is possible to get frequent merge conflicts in error/locations.h. To resolve
them, it is recommended to revert all changes in error/locations.h before the
rebase, then re-run the tools after the rebase. This can be done by:

Reverting changes in error/locations.h:

```
(cros_sdk) /mnt/host/source/src/platform2 $
  common_ancestor=`git merge-base cros/main HEAD`; \
  cl_count=`git rev-list --count "${common_ancestor}"...HEAD`; \
  for i in `seq $(expr ${cl_count} + 1) -1 2`; do \
    GIT_SEQUENCE_EDITOR="sed -i -e '${i}i x git checkout HEAD^ -- \
    cryptohome/error/locations.h && git add --all && git commit --amend \
    --no-edit'" \
    git rebase -i "${common_ancestor}"; \
  done;
```

Then rebase as usual.

Then re-apply the changes by re-running the tools:

```
(cros_sdk) /mnt/host/source/src/platform2 $
  common_ancestor=`git merge-base cros/main HEAD`; \
  cl_count=`git rev-list --count "${common_ancestor}"...HEAD`; \
  for i in `seq 2 $(expr ${cl_count} + 1)`; do \
    GIT_SEQUENCE_EDITOR="sed -i -e '${i}i x \
    /mnt/host/source/src/platform2/cryptohome/error/tool/location_db.py \
    --update && git add --all && git commit --amend --no-edit'" \
    git rebase -i "${common_ancestor}"; \
done;
```

Note that this technique should not be applied when cherry-picking across
branches. See the section on cherry-picking across branches.

### Decoding TPM Error with location_db.py

The location_db.py tool can also be used to decode numeric TPM error, for example:
```
(cros_sdk) /mnt/host/source/src/platform2 $ ./cryptohome/error/tool/location_db.py --decode-tpm 0x7004
(cros_sdk) /mnt/host/source/src/platform2 $ ./cryptohome/error/tool/location_db.py --decode-tpm 5
```
Both hexadecimals and decimals are supported.

## Other considerations

### Cherry-picking across branches

In order to ensure that the error location ID reported in all branches are the
same, when cherry-picking across branches, one should not run the location_db.py
tool, and instead should manually resolve any merge conflict, keeping the error
ID defined in locations.h consistent across branches.
