OpenSSL ebuild notes
====================

The Chrome OS openssl ebuild carries the following modifications vs. upstream:

 * ${P}-blocklist.patch - a code change that allows blocklisting of certificates
   by serial or hash. This is useful for quickly blocking known-bad
   certificates. The patch for this isn't exactly ideal (it checks each cert in
   a chain against the file system), so ideally this would be cleaned up to use
   a better implementation and/or upstream facilities (this was implemented
   years ago, it's possible that there's a better-supported way available now).

 * ${P}-chromium-compatibility.patch - allows relaxing certificate validation to
   match earlier OpenSSL versions, controlled via environment variables. We
   should really drop this - see b/172208472.

 * cros_optimize_package_for_speed - what it says on the label... ;-)

 * files/openssl.cnf.compat - Similar to chromium-compatibility.patch, this
   makes OpenSSL behavior match previous versions more closely by disabling
   support for crypto (notably TLS 1.3 since it no longer supports RSA with
   PKCS#1 padding, which is the only option since the chaps integration doesn't
   work with RSA-PSS) and drops the OpenSSL security level to 0 to keep outdated
   crypto working (namely MD5 in certificate validation, sigh). All this should
   get dropped, see b/172208472.

 * append-lfs-flags - Enables large file support on ARM.
