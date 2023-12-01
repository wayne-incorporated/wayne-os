# libpasswordprovider

This directory contains the Password Provider library, which is used to store
and retrieve the user's password. The password is stored using kernel keyrings.

To retrieve the password, a process must be running as a user in the
password-viewers group.

The password storage is shared among all processes using it, meaning that one
process calling DiscardKey will cause it to be discarded for all other
processes.
