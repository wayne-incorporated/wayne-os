# Kerberos

This directory contains the Kerberos service, which provides functionality for
getting and managing Kerberos tickets. It is used by Chrome to provide Kerberos
Single-SignOn (SSO). Think of it as a fancy wrapper around kinit, kpasswd and
klist.

The service is started by Chrome on demand, e.g. when the user navigates to the
Kerberos Accounts settings page or when accounts are added by the
KerberosAccounts policy. Note that in any case the kerberos.enabled pref has to
be enabled. The KerberosEnabled policy maps to that pref.

The service is conceptually similar to the AuthPolicy service, with partly
overlapping responsibilities like getting Kerberos tickets for users and auto-
renewing tickets. There are many differences, though:

- The AuthPolicy service is used on Active Directory managed devices. The
  Kerberos Service is used on cloud managed devices and possibly in the future
  on consumer devices.

- AuthPolicy is started on the login screen since online authentication means
  getting a Kerberos ticket. The Kerberos service runs within a user session
  only.

- AuthPolicy has many more responsibilities like joining the device to an Active
  Directory domain and fetching user and device policy.
