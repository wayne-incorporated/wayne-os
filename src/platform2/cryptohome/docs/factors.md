# Auth Factors

[TOC]

## Overview

This document outlines the relative security strengths of the different types of
auth factor supported by Cryptohome. For more basic information about "what is
an auth factor?" see the [general architecture document](architecture.md).

## Terminology

Here are some descriptions of specific terms this document uses.

### Credential

A credential is something you present to ChromeOS (and Cryptohome) to attempt to
prove you are who you say you are. It could be "something you know" such as a
password, or a PIN. It could be "something you have" like a smart card. It could
be "something you are" like a fingerprint.

### Auth Factor

A credential, or set of credentials, that Cryptohome accepts to prove your
identity. When referring to a specific type of auth factor this document will
generally use bold all-caps such as **PASSWORD** to refer to a password-based
auth factor. The type of credentials involved are specified by the type of the
auth factor, and Cryptohome's policies are all defined in terms of auth factors.

### Capability

Cryptohome will grant different capabilities based on the type of auth factor
presented for authorization. An example of a capability would be "decrypt and
mount the home directory".

### Enforcement

In the context of Cryptohome, there are two levels of enforcement for policies
regarding capabilities that are relevant. The first is **soft** enforcement:
this means that the capability is enforced purely by the cryptohome daemon. The
second is **hard** enforcement: this means that the capability is enforced by
some combination of hardware and cryptography.

Obviously, hard enforcement is generally stronger than soft enforcement because
breaking through hard enforcement can require work that is very expensive (or
sometimes even impossible) in terms of time and compute resources. However, even
soft enforcement is significant, because breaking it effectively requires root
access to a device.

Note that there are also security policies which are enforced by layers of the
software stack above Cryptohome (generally, Chrome). Most commercial security
policies fall into this category. For the most part a full enumeration of these
policies is out of the scope of cryptohome and this document, but some
particularly relevant ones are defined here. Generally this level of enforcement
is referred to as "Chrome-only".

### Tier

This document categorizes auth factors by dividing them into different tiers.
The capability policies are then defined in terms of tiers of factors; for
example, one capability may require a tier 1 credential while another only
requires a tier 2 credential. This means the strength of a factor is defined
solely by the tier that it is in.

Nevertheless, within a tier we do also provide some subdivision into subtiers of
relative strength. This is done to provide additional background on the
reasoning for why these tiers are structured the way they are, and to help
inform future decisions regarding factors and tiers (e.g. moving a factor up or
down a tier, or breaking a tier up into two separate tiers).

## Credential and Auth Factor strength

When comparing the relative strength of credentials, it can be difficult to
produce a strict ordering because there are several different dimensions to
compare them along. To make this clearer the strength of a credential is for
each type of credential is explained first, then the ordering of the different
type of credentials is given.

### "Thing you know" credentials

For credentials based around a secret value that you know (e.g. password, PIN,
secret handshake, etc.) the general strength is based on how difficult it would
be for an attacker to compromise it with a brute force search. A reasonable
measure of this is to assume that an attacker has physical access to your
Chromebook and is trying to decrypt your home directory; how much time and
effort will it take to brute-force a secret-based credential?

The primary measures of this are how much entropy the credential has, and the
maximum rate at which unlock attempts can be made. In general a factor with less
entropy is weaker than one with more entropy, but if the attempt rate on the low
entropy factor is much lower then this weakness could be mitigated or even
canceled out. For example, consider a 6-digit PIN (1 million possible values)
which is rate limited by hardware to at most 100 attempts per day; on average
this would take more than 10 years to brute force. This could end up being much
slower than brute forcing a higher entropy credential like a password if that
credential allowed millions of attempts per second! One can be even more
aggressive and even do a hard lockout (no more attempts allowed) but such a
credential cannot be used as the only credential as it opens you up to
denial-of-service attacks where an attacker deliberately uses up all of your
attempts.

One additional note regarding entropy: Cryptohome does not directly enforce any
randomness in credential values supplied by users. In fact, with passwords it
never even sees your "real" plaintext password as Chrome only supplies a hash of
it, and so enforcing password restrictions below the Chrome layer is not
currently possible. This does mean that in practice we do assume that other
external systems and layers are providing some level of "passwords are actually
high entropy" enforcement.

### "Things you have" credentials

For credentials based around a physical thing you have in your possession the
general strength is based around how difficult it is to copy or steal, in
combination with how easy they are to invalidate if they are stolen or lost.

In practice Cryptohome does not currently support any standalone "thing you
have" type credentials; instead they're used in combination with "thing you
know" credentials to strengthen the overall factor. Therefore, at this time
doing precise comparisons of relative strength is not necessary.

Note that because "things you have" credentials may be entirely third-party
devices or equipment, barring some mechanism to be able to verify the quality or
robustness of a particular type of device such credentials may not actually be
considered particularly secure.

### "Things you are" credentials

These credentials are basically biometrics: you present something of yourself to
a scanner (e.g. a finger to a fingerprint reader, your face to a camera) and
that result is matched against a stored record.

These credentials have some similarity to "things you have" credentials, in that
their relative strength can be defined based on how hard they are to steal or
copy. While we generally consider actually stealing body parts to be very
difficult, there are other ways to copy biometrics: for example, how easy it is
to "steal" your face by taking a picture of it.

However, there is an added weakness that's more unique to these credentials,
which is a non-zero false positive rate. Most biometric credentials are "fuzzy"
in the sense that you can't really do an exact match (e.g. you can't just do a
pixel-precise match of two images). The higher this rate, the weaker the
credential is; however, this can also be ameliorated via rate limiting like with
a low-entropy credential.

Finally, there is one added weakness to things you are credentials in that
they're also usually impractical to change. While this doesn't make the
credential itself easier to compromise, it does restrict the usability somewhat
as it can only be disabled.

## Auth Factor tiers

The auth factors are divided into tiers, where for practical purposes all that
matters about a factor is what tier it falls into. What tier a factor is in
defines how much we trust it: is this a factor that can be used to decrypt a
user's home directory, or only one that is trusted to unlock a device, or
something else?

Within a tier we also provide a partial ordering of factors, but this is
informational and not something that actions are taken upon.

### Tier 1: Strong auth factors

These are auth factors that we consider to be sufficient to use as your only
factor, providing full access to your device without any reservations.

1.  **CRYPTOHOME_RECOVERY**
1.  **PASSWORD**

#### Justification

At this time we consider **PASSWORD** to be the "standard" strong auth factor.
Having it is sufficient to secure full access to a device, and it's long been
acceptable to have a password-only system. That may change in the future but for
now it's useful to continue using it as the starting point, measuring other
types of factors against it.

The **CRYPTOHOME_RECOVERY** auth factor is considered similarly stronger than
**PASSWORD**. It combines requiring a password-level credential (for an owner
account) with device access and tamper-resistant logging of the authentication
occurring.

### Tier 2: Strong-ish auth factors

These are auth factors that we consider sufficient to provide full access to
your device, but where we implement some additional restrictions at the UI
level.

1.  **SMART_CARD**
1.  **PIN**

#### Justification

The **PIN** auth factor is weaker than the strong factors because a PIN is a
password with an enforced smaller character set and length. This means that PINs
provide the same properties as passwords but much lower entropy. This is
mitigated by requiring cryptographically enforced rate limiting on PIN attempts
that put a bound on how easily they can be forced. This is sufficient for the
factor to be considered tier 2 and allowed full access.

On paper the **SMART_CARD** auth factor is clearly stronger than the **PIN**
factor because it's composed of both a PIN and a physical card, both of which
have to be presented in order to authenticate. In fact one could argue that it's
even stronger than some of our other tier 1 factors such as **PASSWORD**.
However, the problem is that smart cards are all third party products which we
have no way of verifying the overall quality of. To account for this uncertainty
we still consider **SMART_CARD** to be stronger than our first party **PIN**
implementation but we don't count it as part of the *ideal* tier 1 factors.

### Tier 3: Weak auth factors

These are auth factors that can be used to unlock a locked device, but which
cannot be used to login in a device which is not already logged in.

1.  **LEGACY_FINGERPRINT**

#### Justification

The **LEGACY_FINGERPRINT** authentication mechanism does not provide any way to
securely store a key that gets released by the auth process; instead it only
provides a yes/no result. This makes it impossible to use with any capability
other than unlock.

### Tier ∞: Not allowed

With a regular account, these factors cannot be used at all. This tier is
generally reserved for factors that are only intended to be used in special
contexts.

1.  **KIOSK**

#### Justification

The **KIOSK** auth factor provides no actual security, since in practice its
credential is equivalent to a **PASSWORD** with a pre-set, well-known password.
Thus, they should never be used with an actual normal account.

### Special: Kiosk Accounts

For persistent kiosk accounts on a device we use different rules: the **KIOSK**
auth factor is treated as being tier 1 and all other types of auth factor are
tier ∞ (not allowed). Cryptohome enforces this restriction.
