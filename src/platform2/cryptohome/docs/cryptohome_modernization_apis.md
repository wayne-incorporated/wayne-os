# Cryptohome Modernization APIs Reference

Authors: hardikgoyal@chromium.org, kerrnel@chromium.org

## Objective

This document describes the external behavior of the new APIs introduced for the
cryptohome modernization project. These APIs are being implemented as of
January 2022, and expected to be complete by June 2022.

## Background

These APIs cover three large areas of functionality.

1.  **Storage** - The storage APIs create a user's backing store on disk, and
    mount the decrypted files using supplied credentials.
2.  **AuthSessions** - AuthSessions represent a user in cryptohome, and allow
    multiple API calls to work with an authenticated user. Rather than passing
    the credentials to each API call, the credential is passed once to
    Authenticate, and the unique auth session ID is passed to each other call.
3.  **AuthFactors** - AuthFactors represent the various types of credentials
    used on Chrome OS. The simplest is the password. There are also smart cards,
    Android phones (SmartLock), PINs, etc.

### Backing Storage Information

There are two separate backing key stores on Chrome OS. VaultKeyset is the
legacy keystore, soon to be replaced by UserSecretStash. A user has a copy of a
VaultKeyset per credential, making it hard to scale these key stores.
UserSecretStash is a universal key store which each credential wraps.

## Storage APIs

The user storage APIs are now split into two operations: Create and Prepare,
with Create being available for persistent users. All the users (Guest,
Ephemeral and Persistent) will call Prepare&lt;type&gt;Vault. The Prepare&lt;type&gt; calls
used to be called Mount, but Prepare better reflects that the call is doing many
things (setting up device mappers, registering file system keys, bind mounting)
and not only a mount.

Here is more about the APIs:

1.  **PrepareGuestVault** - This request is intended to happen when a user wants
    to login to ChromeOS as a guest.
    -   *Input*: None
    -   *Reply*:
                  - CryptohomeErrorCode - Returns if any error occurred.
                  - sanitized_username: A hash of the username, which is part of
                    the path of the mounted homedir.
2.  **PrepareEphemeralVault** - This request is intended when a policy (either
    device or enterprise) has enabled ephemeral users. An ephemeral user is created
    in a memory filesystem only and is never actually persisted to disk.
    -   *Input*: auth_session_id
    -   *Reply*:
                  - CryptohomeErrorCode - Returns if any error occurred.
                  - sanitized_username: A hash of the username, which is part of
                    the path of the mounted homedir.
3.  **CreatePersistentUser** - This will create user directories needed to store
    keys and download policies. This will usually be called when a new user is
   registering.
    -   *Input*: auth_session_id
    -   *Reply*: CryptohomeErrorCode - Returns if any error occurred.
4.  **PreparePersistentVault** - This makes available user directories for them
    to use.
    -   *Input*:
        -   auth_sesion_id: AuthSession Id of an Authenticated AuthSession.
        -   block_ecryptfs: Whether ecryptfs mount should be prohibited.
        -   encryption_type - Expected encryption_type.
    -   *Reply*:
                  - CryptohomeErrorCode - Returns if any error occurred.
                  - sanitized_username: A hash of the username, which is part of
                    the path of the mounted homedir.
5.  **PrepareVaultForMigration** - Mounts vault in order to perform the
    migration of encryption. StartMigration can work only with the vault
    mounted with PrepareVaultForMigration.
    -   *Input*:
        -   auth_session_id: AuthSession Id of an Authenticated AuthSession.
    -   *Reply*:
        - CryptohomeErrorCode - Returns if any error occurred.
        - sanitized_username: A hash of the username, which is part of
          the path of the mounted homedir.

## AuthSession APIs

These are the APIs that AuthSession supports:

1. **StartAuthSession** - This will start an AuthSession for a given user.
    - *Input*: - Account_id - user’s username
      - flags - These determine how an AuthSession is configured. There is
  only one flag configured as of now, which is for ephemeral users.
    - *Reply*: - CryptohomeErrorCode - Returns if any error occurred.
      - Auth_session_id - This will be used to identify AuthSession after this
      call.
      - user_exists - Returns if the user exists.
      - map<string, cryptohome.KeyData> - Map to return label and public key
      data for the available keysets.
    - *Note*: - By default this AuthSession is valid for 5 minutes from the time the
      session reaches an Authenticated State. ExtendAuthSession can be called to extend
      the session or StartAuthSession to start over.
    - *Note*: - Running parallel operations on the same AuthSession auth_session_id is
       prohibited. This means that in order to run any dbus call on the session, you
       must wait for the previous call to finish.
    - *Note*: - However, while there are no restrictions on operations for AuthSessions
       with different auth_session_id’s, there is also no guarantee of synchronized user
       state for AuthSessions with the same user. This is a current grey area for
       cryptohome.
2. **InvalidateAuthSession** - This call is used to invalidate an AuthSession
once the need for one no longer exists.
    - *Input*: auth_session_id - AuthSession to invalidate.
    - *Reply*: CryptohomeErrorCode - Returns if there is any error.
3. **ExtendAuthSession** - This call is used to extend the duration of
AuthSession that it should be valid for.
    - *Input*:
      - auth_session_id - AuthSession that needs extending.
      - extend_duration - The number of seconds to extend the AuthSession by.
      If nothing is provided, this would default to 60 seconds.
    - *Reply*: Cryptohome Error Code

## AuthFactor APIs

Here are the APIs that are used to work with AuthFactors .
1. **AddAuthFactor** - This call adds an AuthFactor for a user. The call goes
through an authenticated AuthSession.
    - *Input*:
      - auth_session_id - AuthSession used to identify users.
    The AuthSession needs to be authenticated for this call to be a success.
      - auth_factor - AuthFactor information about the new factor to be added.
      - auth_input - This is set if any input is required for the AuthFactor,
      such as text for a Password AuthFactor.
    - *Reply*:
      - CryptohomeErrorCode - Returns if there is any error
      - AuthFactorWithStatus - Returns the newly updated AuthFactor with a
      list of intents the factor is available for.
2. **AuthenticateAuthFactor** - Authenticates an existing AuthFactor and sets
the AuthSession's authorized_for intents based on the type of authentication
that occurred. If the factor that is authenticated enables more intents than
requested, the AuthSession will be authorized for those intents. Calling
AuthenticateAuthFactor again on an already authenticated AuthSession will not
downgrade the intents, but it may upgrade the authorized_for intents based
on the factor used, and will reset timer for AuthSession to the default, five
minutes.
    - *Input*:
      - auth_session_id - AuthSession used to identify users. The AuthSession
      needs to be authenticated for this call to be a success.
      - auth_factor_label - The label that will be used to identify an
      AuthFactor to authenticate.
      - auth_input - This is set if any input is required for the AuthFactor,
      such as text for a PasswordAuthFactor.
    - *Reply*:
      - CryptohomeErrorCode - Returns if there is any error
3. **UpdateAuthFactor** - This call will be used in the case of a user wanting
to update an AuthFactor. (E.g. Changing pin or password).
    - *Input*:
      -auth_session_id - AuthSession used to identify users. The AuthSession
      needs to be authenticated for this call to be a success.
      - auth_factor_label - The label that will be used to identify an
      AuthFactor to update.
      - auth_factor - AuthFactor information about the new factor that will
      replace the existing.
      - auth_input - This is set if any input is required for the AuthFactor,
      such as text for a Password AuthFactor.
    - *Reply*:
      - CryptohomeErrorCode - Returns if there is any error.
      - AuthFactorWithStatus - Returns the newly updated AuthFactor with a
      list of intents the factor is available for.
4. **RemoveAuthFactor** - This is called when a user wants to remove an
AuthFactor.
    - *Input*:
      - auth_session_id - AuthSession used to identify users. The AuthSession
      needs to be authenticated for this call to be a success.
      - auth_factor_label - The label that will be used to identify an
      AuthFactor to remove.
    - *Reply*:
      - CryptohomeErrorCode - Returns if there is any error
5. **ListAuthFactor** - This call will list all of the configured AuthFactors
for a given user as well as the supported types of auth factors.
    - *Input*:
      - account_id - The username of the user.
    - *Reply*:
      - CryptohomeErrorCode - Returns if there is any error.
      - configured_auth_factors - The persistent auth factors that have
      currently been configured (e.g. by a prior AddAuthFactor call) for this
      user.
      - supported_auth_factors - The types of auth factors supported for this
      user. Should include all configured factor types as well as any additional
      types that could be added.
    - *Usage*:
      - The user specified does not have to be in an authenticated state.
      However, if the user does not exist (on-disk) or have an active session
      then this will report an INVALID_ARGUMENT error.
      - The configured factors reported will be all currently persisted factors.
      This list can be empty, for example if the user is emphemeral, or if a
      persistent user has been created but no factors have yet been added.
      - The supported factor types reported are based on the type of user
      (persistent or ephemeral), the local hardware available, and the set of
      existing configured factors. Some examples of how these factors could
      impact what is supported:
        - Support for PIN factors depends on having sufficiently advanced TPM
        hardware and firmware.
        - If the user has a Kiosk factor configured, all other types of factors
        will be unavailable.
        - Conversely, if the user has at least one non-Kiosk factor configured
        then a Kiosk factor will not be reported as a supported option.
6. **PrepareAuthFactor** - This call is required for specific types of
non-knowledge-based auth factors before AuthenticateAuthFactor or AddAuthFactor
is called with those auth factors. It usually stats a sensor session for the
specified auth factor type. It also initiates a signal sender broadcasting
a AuthScanResult signal, which contains the scan result for the specified auth
factor type.
    - *Input*:
      - auth_session_id - AuthSession used to identify users.
      - auth_factor_type - The type of AuthFactor that is being prepared.
      - purpose - A enum to identify the following action after this
      PrepareAuthFactor completes.
    - *Reply*
      - CryptohomeErrorCode - Returns if there is any error.
    - *Usage*:
      - Set the purpose to PURPOSE_ADD_AUTH_FACTOR, when we intend
      to have a follow up AddAuthFactor. The auth session should be
      already authenticated.
      - Set the purpose to PURPOSE_AUTHENTICATE_AUTH_FACTOR, when we intend
      to have a follow up AuthenticateAuthFactor. The auth session may not be
      already authenticated.

7. **TerminateAuthFactor** - This call is required after PrepareAuthFactor is
called with an auth factor type. It will shut down any underlying sensor sessions.
It will also shut down the signal sender associated with the auth factor type.
    - *Input*:
      - auth_session_id - AuthSession used to identify users.
      - auth_factor_type - The type of AuthFactor that is being prepared.
    - *Reply*
      - CryptohomeErrorCode - Returns if there is any error.
    - *Usage*:
      - Properly terminate the underlying sensor session.
8. **UpdateAuthFactorMetadata** - This call will be used in the case of a user wanting
to update an AuthFactor's metadata. (E.g. Changing FP Label).
    - *Input*:
      -auth_session_id - AuthSession used to identify users. The AuthSession
      needs to be authenticated for this call to be a success.
      - auth_factor_label - The label that will be used to identify an
      AuthFactor to update.
      - auth_factor - AuthFactor information about the existing factor that will
      replace the existing. Note: No new AuthFactor will be created here and no
      secrets are modified.
    - *Reply*:
      - CryptohomeErrorCode - Returns if there is any error.
      - AuthFactorWithStatus - Returns the newly updated AuthFactor with a
      list of intents the factor is available for.

## Order of Operations

### Add New User to Chromebook

1.  `StartAuthSession` – Chrome initiates an AuthSession.
2.  `CreatePersistentUser` – Creates on-disk user representation and put the
    AuthSession into authenticated state.
3.  `PreparePersistentVault` - At this point it is safe to fetch any userpolicy.
4.  `AddAuthFactor`
    -   Upon adding the first AuthFactor, cryptohome will save the USS to disk.
        If there is a crash before this call is successful, the user is not
        persisted.
    -   This can be called multiple times. If there is a need
        `ExtendAuthSession` should be used.
5.  `InvalidateAuthSession`

### Chrome Sign in an Existing User

1.  `StartAuthSession` – Chrome initiates an AuthSession. This time
    `user_exists` should return `true` and AuthSession will not start in an
    authenticated state.
2.  `AuthenticateAuthFactor`
    - If this call is a success, then move to the next step.
3.  `PreparePersistentVault`
    - At this point it is safe to fetch any userpolicy.
4.  `InvalidateAuthSession`

### Chrome Adds an AuthFactor for an Existing User

1.  `StartAuthSession` – Chrome initiates an AuthSession. This time
    `user_exists` should return `true` and AuthSession will not start in an
    authenticated state.
2.  `AuthenticateAuthFactor`
    -   If this call is a success, then move to the next step.
3.  `AddAuthFactor`
    -   This can be called multiple times. If there is a need
        `ExtendAuthSession` should be used.
4.  `InvalidateAuthSession`

### Chrome Removes a user

This case can happen when a user forgets their password and chooses to start
as a fresh user.

1.  `StartAuthSession` – Chrome initiates an AuthSession. This time
    `user_exists` should return `true` and AuthSession will not start in an
    authenticated state.
2.  `Remove`
    -   This call will take AuthSessionId as input. Upon successful completion,
    it will invalidate AuthSession to ensure a clean removal of user.


### Chrome starts a Guest Session
There will not be any requirement for AuthSession here as this account is totally temporary.

1.  `PrepareGuestVault`

### Chrome starts an Ephemeral User Session

1.  `StartAuthSession` – Chrome initiates an AuthSession.
2.  `PrepareEpehemeralVault`
3.  `AddAuthFactor`
    -   This is in case of managed guest session (adding a temporary pin).
4.  `InvalidateAuthSession`

Note that if the global ephemeral policy is enabled, Chrome will need to remove
any persistent users present.

### Chrome wants to migrate eCryptfs to DirCrypto encryption scheme

1.  `StartAuthSession` – Chrome initiates an AuthSession.
2.  `AuthenticateAuthFactor`
3.  `PrepareVaultForMigration`
4.  `StartMigrateToDircrypto`
    -   Ensure that this is called with the ```auth_session_id``` field set.
5.  `InvalidateAuthSession`

### Chrome wants to do fingerprint screen unlock

1.  `StartAuthSession` - Chrome initiates an AuthSession with AuthIntent
    Verify.
2.  `PrepareAuthFactor`
    - PrepareAuthFactorRequest expects to contain an auth factor type of
    LegacyFingerprint.
    - An fingerprint sensor session is started to collect a fingerprint press.
    - A success response indicates an fingerprint session has started.
    - A failure response means the session start has failed.
    - Upon a successful invocation, a signal sender that broadcasts signal
    AuthScanResult for legacy fingerprint is initialized.
3.  Listen on crypthome signal AuthScanResult.
    - It is a success. Chrome should proceed to call AuthenticationAuthFactor
      to find out the authentication result.
    - It is a failure and indicating fingerprint auth has been locked out.
    Chrome should tell the user the fingerprint auth has failed for the current
    AuthSession. No fingerprint attempt will be accepted in the current
    fingerprint sensor session.
4.  `AuthenticateAuthFactor`
    - It is a auth success, the fingerprint is matched.
    - It is a auth failure. Chrome should continue listen for another
    fingerprint scan attempt.
    - Chrome should ask the user to make another fingerprint attempt.
    - It is a auth failure and indicating fingerprint retry limit has been
    reached, Chrome should tell the user the fingerprint auth has failed for
    the current AuthSession. No further fingerprint attempt will be accepted
    in the current fingerprint sensor session.
5.  `TerminateAuthFactor`
    - End the active fingerprint sensor session.
    - The sender that broadcasts AuthScanResult for legacy fingerprint is
    terminated.
6.  `InvalidateAuthSession`
    - If there are any outstanding snesor sessions, they will  be ended
    automatically, similar to what `TerminateAuthFactor` has done.

### Chrome wants to do fingerprint WebAuthn

1.  `StartAuthSession` - Chrome initiates an AuthSession with AuthIntent
    WebAuthn.
2.  `PrepareAuthFactor`
    - An fingerprint sensor session is started to collect a fingerprint press.
    - The fingerprint session is ended after a fingerprint image is captured.
3.  `AuthenticateAuthFactor`
    - It is a success, the fingerprint is matched and WebAuthn is fulfilled.
    - It is a failure and indicating another auth retry is possible, Chrome
    should repeat from Step 2 PrepareAuthFactor for another attempt.
    - It is a failure and indicating fingerprint retry limit has been reached,
    Chrome should not further attempt fingerprint auth in the same AuthSession.
4.  `TerminateAuthFactor`
    - The completion of PrepareAuthFactor (receiving error or successful
    result) should ensure no further signals will be emitted and fingerprint
    sensor session ended. However, in case Chrome wants to abort the session
    early, TerminateAuthFactor has to be called. Also, it's a good idea to
    always call TerminateAuthFactor when the WebAuthn dialog is destructed.
5.  `InvalidateAuthSession`
    - Now the prepared WebAuthn secret resides outside the auth session, so
    it's safe for Chrome to call InvalidateAuthSession here. In the future
    when we move WebAuthn secret into auth session, Chrome shouldn't process
    this step, but return the auth session ID to u2fd in a successful response
    of WebAuthn verification, then let u2fd do the InvalidateAuthSession.

### Chrome wants to do PIN/password WebAuthn

1.  `StartAuthSession` - Chrome initiates an AuthSession with AuthIntent
    WebAuthn.
2.  `AuthenticateAuthFactor`
    - It is a success, WebAuthn is fulfilled.
    - It is a failure, retry using password or PIN if not locked out yet.
3.  `InvalidateAuthSession`
    - Now the prepared WebAuthn secret resides outside the auth session, so
    it's safe for Chrome to call InvalidateAuthSession here. In the future
    when we move WebAuthn secret into auth session, Chrome shouldn't process
    this step, but return the auth session ID to u2fd in a successful response
    of WebAuthn verification, then let u2fd do the InvalidateAuthSession.

### Chrome wants to do UpdateAuthFactorMetata for Any Factor

1.  `StartAuthSession` - Chrome initiates an AuthSession with
 `AUTH_INTENT_DECRYPT` AuthIntent.
2.  `AuthenticateAuthFactor`
3.  `UpdateAuthFactorMetadata` -
    - Ensure that AuthFactor provided has all information, existing and any
    new information that needs to be updated.
    - Any metadata field that is updated by cryptohome will be ignored.
4.  `InvalidateAuthSession`
