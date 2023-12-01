# Certificates

As mentioned in the main README, communication between the eUICC and the
SM-DP+ or SM-DS uses HTTPS, as mandated by the relevant standards. The GSMA
root certificates were created specifically for TLS certificate verification of
such communication. These certificates are placed in the certs/ directory along
with the root certificates of specific SM-DP+s that use their own chain of trust
(having done so prior to GSMA creating the standard root CI). Hermes exclusively
uses these root certificates for HTTPS communication between remote SIM
provisioning entities.

The certificates currently used by Hermes are:
*   prod/gsma-ci: [GSMA root certificate], which is used as the primary root
    certificate for communication with non-test SM-DP+ and SM-DS entities.
*   prod/gd-smdp: The root certificate used for communication with non-test G+D
    SM-DP+ servers (which predates the creation of GSMA's root certificates).
*   test/gsma-ci: The primary root certificate for communication with test
    SM-DP+ and SM-DS entities.
*   test/gd-smdp: The root certificate used for communication with test G+D
    SM-DP+ servers (which predates the creation of GSMA's root certificates).

[GSMA root certificate]: https://www.gsma.com/esim/ceritificateissuer
