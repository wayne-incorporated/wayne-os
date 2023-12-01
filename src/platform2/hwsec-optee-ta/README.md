# Hwsec-related optee plugin

This package will produce an OP-TEE trusted application.

It will calculate the TPM HMAC session to verify the NV data is coming
from user space, and provide an interface to let the other trusted
application get the correct NV data that cannot be compromised.
