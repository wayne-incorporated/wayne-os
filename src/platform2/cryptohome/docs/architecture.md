# Cryptohome Architecture

**Authors**: kerrnel@chromium.org, apronin@chromium.org

Cryptohome is one of Chrome OS’s largest and oldest code bases. It is
a gateway to user data on the system, authenticating user credentials,
deriving those credentials into file encryption keys, and mounting the
encrypted filesystem. This document describes the high level architectural
principles of cryptohome.

## Secret Wrapping on Disk

Users’ encryption secrets, such as filesystem encryption keys, are
wrapped by a combination of user input (for example, a password) and a
hardware security element (TPM, or GSC). These wrapped secrets must be
persisted to disk, and there are two formats which do this (both of which
are stored as protobufs).

### SerializedVaultKeyset

SerializedVaultKeysets are the soon to be deprecated, as of March
2021, format used to hold file encryption keys and other necessary
data (IVs, timestamps, etc). Some secrets stored there are repeated
in each SerializedVaultKeyset file. The primary reason to deprecate
SerializedVaultKeysets and replace them with UserSecretStash (defined
below) is seamless management of multiple credentials. Currently there is
a separate SerializedVaultKeyset file per credential, which has scaling
issues and makes it impossible for a user to update shared data duplicated
across all VaultKeyset files without knowing all credentials at once.

### UserSecretStash

The UserSecretStash (USS) is a future container of the user’s file system
keys. There is one USS per user, and one main key which encrypts the
USS. Each credential wraps the main key, as a series of intermediate keys,
which allows all credentials to modify the same filesystem keys and data.

## D-Bus API Concepts

Cryptohome exposes a D-Bus interface which callers, mainly Chrome, use
to interact with cryptohome. UserDataAuth is the name of the entire dbus
interface that cryptohome exposes, with AuthSessions and AuthFactors being
object oriented concepts implemented by the interface.

### UserDataAuth

UserDataAuth (UDA) is the dbus interface exposed by cryptohome. UDA was
rolled out in 2020 as a replacement of the old glib-dbus interface. UDA
allows cryptohome to use modern dbus bindings and event loops, and
uses protobufs for the message and reply data structures to simplify
versioning. The dbus messages consume and output byte arrays, which are
the serialized protobufs. In the past, changing the data fields passed
in messages and responses was time consuming and brittle as it had to be
changed in cryptohome daemon and all its clients, which have independent
releases. Now the dbus method always stays the same, and the protobuf
passed may change.

### AuthSessions

AuthSession is an API exposed by Cryptohome via UserDataAuth. The session
serves as a place for users to provide their credentials and request
operations such as mounting, which require the credentials. The session will
be established before any action that requires credential validation such
as mount, updating keys, adding keys, etc. The AuthSession is controlled by
states, and it starts by default in kAuthStatusFurtherFactorRequired. Each
AuthSession is identified with a base::UnguessableToken. Authsession works
in two steps to validate a set of credentials. These are:

#### StartAuthSession

StartAuthSession starts a new AuthSession with a given username. It
also starts a timer, after which the AuthSession becomes invalid.The
timer ensures that the credentials do not stay in the memory indefinitely.

### AuthFactors

AuthFactors abstract credentials to represent the many credentials used
for Chrome OS authentication. Historically passwords were used to sign
in, but in the future users may use: security keys, smart cards, PINs,
trusted phones, remotely stored escrow keys, etc.

AuthFactor is a purely virtual interface in C++. Each supported
authentication form will have a concrete implementation of the AuthFactor
class.

The default mapping from an authFactor to authBlock is determined by
cryptohome and may differ from OS revision to OS revision or from board
to board. E.g. a password authFactor can match to cryptohome_key-based
authBlock for TPM1.2 devices and old OS revisions, but to Pinweaver
authBlock for TPM2.0 devices and old OS revisions.

Once set, though, the authBlock used for a particular authFactor doesn't
change, even if the default mapping for the authFactors of that type
changes. Once set to a cryptohome_key authBlock, authMethod will continue
verifying user credentials that way, even if the default mapping for
"password" changes to Pinweaver in future OS versions. A migration to
Pinweaver authBlock would require a specific request from upper layers -
likely, creating a new authFactor and then deleting the old one.

## Internal Architecture

Cryptohome organzies code internally into object oriented interfaces to
support the myriad of code paths in a scalable manner. Two key interfaces
are AuthMethods and AuthBlocks.

### AuthMethods

AuthMethod is a specific combination of authFactors that may authenticate
a given user account.

As an example, based on enterprise policies or personal preferences,
a user account may be set up to allow authentication through either of
the following methods: (a) entering a password (1FA authMethod with
password-based authFactor); (b) inserting a smart card and verifying
the fingerprint (2FA authMethod with smartcard and FP authFactors); (c)
entering a PIN and verifying the fingerprint (2FA authMethod with PIN and
FP authFactors, where FP authFactor is the same as for method (b)).

When authMethod is created, specific authFactor(s) are selected for
it. I.e. even if multiple "password" authFactors exist for a user, an
authMethod will allow only one specific password from this known list. And
when an authMethod is included in a set (see below), only that specific
password will be allowed for authentication for the purposes covered by
the set. To avoid requiring the user to authenticate all factors when
credentials are created, the AuthFactor secrets must be stored in the USS.

#### Sets of authMethods

There are two sets of authMethods associated with a user account:
LoginMethodsSet (methods accepted during user login), and UnlockMethodsSet
(methods accepted for screen unlock for an already signed-in user). An
account may allow the same sets of authMethods for login and unlock, or have
different sets for them - e.g. requiring 2FA including password/PIN and FP
for login, but allowing any of the factors as a single factor for unlock:
LoginMethodsSet = {Password+FP, PIN+FP}, UnlockMethodsSet = {Password,
PIN, FP}. In practice, all authMethods are registered in UnlockMethodsSet.

### AuthBlocks

AuthBlock is a pure virtual C++ interface found in the file
auth_block.h. Each authentication method (password, security key, 2FA with
password and security key), has a concrete AuthBlock implementation. The
AuthBlock has two methods: Create() and Derive().

#### AuthBlockState

AuthBlockState contains per auth block metadata which is used to derive the
keys produced by the AuthBlock. An example of this metadata is the IVs. The
metadata is stored to disk in plaintext, output by the AuthBlock’s Create()
method, and loaded by the Derive() method.

#### Create()

Create() consumes an AuthFactor, which will reveal its underlying secret
to the AuthBlock. For example, SecurityKeyAuthFactor will talk to the
security key over DBUS, and ultimately present the AuthBlock with a high
entropy secret that can only be reconstructed with the physical security
key present. In a simpler case, PasswordAuthFactor will reveal the hashed
password sent from Chrome.

Create() then derives a high entropy key from the AuthFactor's secret,
and uses the derived key to wrap either the USS main key, or the
VaultKeyset. Create() outputs the high entropy keys in the KeyBlobs object,
which is secret and should never be persisted. Create() also outputs the
public metadata to re-create those keys in the AuthBlockState. AuthBlockState
is serialized to disk as a protobuf.

#### Derive()

Derive consumes an AuthBlockState instance, and generates the keys previously
created in Create(). For example, derive will run the user’s password
through scrypt, and then give it to the TPM to unseal the USS main
wrapping key.

## Secret Storage in Memory
Cryptohome should store user specific secrets, such as key material derived
from the password, in memory only when the user authenticates. As soon as
possible key material should be overwritten in memory and deallocated.

### brillo::SecureBlob
To support this property, cryptohome uses brillo::SecureBlob instead of
std::string or std::vector. SecureBlob uses an allocator that pins the pages to
physical memory, and overwrites the memory on deallocation, among other
properties.

### Note on Serialization Methods
Cryptohome must serialize objects to a byte array before encrypting them and
persisting to storage. Many serialization libraries, such as protobuf or
JSON parsers, will make their own heap allocations, copying class members
to intermediate objects.  This will cancel any benefit of SecureBlob, so
cryptohome must use a serialization library that allows a custom allocator
to be specified. The current plan is to use Flatbuffers for future serialization
format, such as UserSecretStash and AuthBlockState. protobuf is currently used
for SerializedVaultKeyset and will remain in cryptohome until
SerializedVaultKeyset is removed.
