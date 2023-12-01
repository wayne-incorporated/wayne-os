# Virtual TPM service

***vtpm*** is the system service that provides virtualized TPM interface. It
provides a D-Bus interface like a TPM daemon while the backend of the TPM

implementation is virtualized, and can be backed by SW or the real TPM.

This document below provides the top view of the behavior of vtpm.

## Persistent keys

Vpm supports pre-defined persistent keys. It is implemented using a loadable
transient key in the storage hierarchy. When a virtual persistent key is being
used, vtpm loads the key to the host TPM, and the loaded transient key handle
replaces the virtual persistent key handle value.

So far there are 2 pre-defined keys: storage root key (vSRK) and endorsement key
(vEK).

## Authorization & sessions

Vptm provides a very limited support for authorization and sessions:

*   Password authorization is supported.
*   HMAC is not supported due to a command not always sent to the host TPM as
    is. In fact, most of time, a command is handled in the vtpm daemon directly,
    sent to with replacement of handles or authorization values, or compose a
    series of host TPM commands. Those cases make HMAC sessions incompatible
    with any existing use of HMAC sessions (because obviously the integrity
    checking of the HMAC values won’t add up).
*   Policy session is supported, though the only policy command vtpm supports
    are currently **PolicySecret**.

## Predefined NVRAM spaces

Vtpm supports pre-defined, read-only NVRAM spaces. A typical (and currently the
only) use is to store a virtual endorsement key certificate.

For now, only the vEK certificate is supported.

## Supported key type and algorithm

All the key types and algorithm inputs/outputs are passed through to/from the
host TPM.

Note that, though it implies that what is supported by the host TPM should work
with vtpm, during the development, the testing of the vtpm implementation is ECC
focused.

## Unsupported commands & error handling

If vtpm receives a command that is not supported, it returns
**TPM\_RC\_COMMAND\_CODE**.

If any system error occurs, usually it might return **TPM\_RC\_FAILURE**. (For
example, A dependent daemon service is down and a certain operation cannot be
performed.)

## Supported commands & arguments

### TPM2\_GetCapability

It supports to list **TPM\_CAP\_HANDLES** with **persistent key handles**.

For development purposes, transient key handles and policy session handles are
also supported, but they are not tested in production logic.

### TPM2\_NV\_Read

It supports reading the data from a predefined NV space.

Despite only vEK certificate being the only one that is supported, different
indice can be implemented in different ways by design ; there is no unified way
to maintain the NV space like what a real TPM does.

### TPM2\_NV\_ReadPublic

It supports reading the public area of a predefined NV space.

Like **TPM2\_NV\_Read**, the public information can be implemented differently
index by index.

### Forwarding a command to the host TPM

#### Forwarding rules

The following virtual objects are transferred to the ones the host TPM
recognizes:

1.  Persistent key handles. When a virtual persistent key handle, e.g. a virtual
    storage root key or a virtual endorsement key is used, it is loaded as a
    transient key on the host TPM, and the transient key handle then replaces
    the virtual key handle.
2.  Endorsement password. When the virtual endorsement password is used, vtpm
    replaces it with the endorsement password for the host TPM.

#### Supported command

The following commands are forwarded to the host TPM with the rule mentioned
above. Additional notes to a specific command is also documented below:

*   TPM2\_Create
*   TPM2\_Load
*   TPM2\_ReadPublic
*   TPM2\_FlushContext
*   TPM2\_StartAuthSession
    *   Note that, as documented in the previous section, only policy session is
        supported.
*   TPM2\_PolicySecret
    *   Note that only password authorization is supported as other policy
        commands are not supported.
*   TPM2\_MakeCredential
*   TPM2\_ActivateCredential
*   TPM2\_Hash
*   TPM2\_Sign
*   TPM2\_VerifySignature
*   TPM2\_Certify

## gLinux profile

Below the important constants and parameters for gLinux use are listed below:

*   ECC SRK (handle **0x81000002**)
    *   Decrypt key.
    *   curve id: TPM\_ECC\_NIST\_P256.
    *   Password authorization: empty password.
    *   Policy digest: empty.
    *   PCR: not bound.
*   ECC EK (handle **0x81010002**)
    *   Decrypt key.
    *   curve id: TPM\_ECC\_NIST\_P256.
    *   Password authorization: empty password.
    *   Policy digest: As recommended in ECC EK template for TCG Credential
        Profile EK 2.0.
    *   PCR: not bound.
*   ECC EK certificate (index **0x01C0000a**)
*   RSA SRK & EK: not provided.
*   Endorsement password: empty.
*   Owner password & lockout password: the values are not defined because the
    authorization with them are not supported.
