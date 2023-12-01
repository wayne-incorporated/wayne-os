This package (samba) has been modified from upstream Gentoo due to multiple
changes necessary for use in Chrome OS. These changes include:
- Various cross-compilation fixes needed for aarch64 and lld linking,
  including the addition of samba.bashrc to ensure WAF is called with the
  appropriate cross-compilation answers file
- Features disabled and conditional dependencies (i.e. perl) to
  minimise files installed in the rootfs and avoid unnecessary build-time
  dependencies
- Remove Python dependencies, these are mainly for bindings used to interface
  with the Samba server which we don't use on ChromeOS.
- Linking against chrome-base/chrome-icu, which is the canonical way to get
  libicu on Chrome OS
- Disabling installation of systemd units / services as no service components
  from Samba are run on Chrome OS
- Trimming empty directories under /var so that they're not created on the
  host
- Adding environment variables to help WAF find Parse-Yapp and the yapp
  binary during the configure and build phase (required for Samba's IDL
  generation)
- Removed liburing as a dependency. This was used in the VFS backend for Samba
  (specifically to use the io_uring vfs module) however this causes build
  failures. Given we don't have any of the VFS functionality, this is safe to
  remove.

Although some of these changes could be upstreamed, such as cross-compilation
fixes, it is unlikely that all changes necessary for Chrome OS could be
submitted to upstream Gentoo. Therefore it is unliklely this package could be
moved back to portage-stable.

Cross-compilation Answers
-------------------------

When uprevving Samba things may have changed enough that a new cross-compile
will fail (eg. emerge-kevin or emerge-kevin64 for ARM / ARM64 ends up failing
where the x86_64 build does not) because the existing answers file
(files/arm*_waf_config_answers) does not contain sufficient information. This
is normally discovered because the build will fail with an error from the
Portage sandbox that open_wr() on the answers file has failed.

If this occurs, rerun emerge, but prefix the command with:

FEATURES="-usersandbox" emerge-<board> samba

This will allow WAF to write the (new, unanswered) config options into the
answers file at which point you can go and find answers for them (instructions
for that in the file itself).

Once nothing remains unanswered the FEATURES="" prefix is no longer required as
WAF can simply read the file instead of appending to it.

Some of the Samba packages also use the cross-compilation answers, however,
these do not deviate from their upstream other than the
{arm,arm64}_waf_config_answers. To facilitate this they are spread across both
portage-stable and chromiumos-overlay, such that the WAF answers exist in
chromiumos-overlay and the ebuild (and related patches) exist in portage-stable.
This applies currently to sys-libs/ldb and sys-libs/tdb. This is required to
ensure the WAF build system can read the patches, if they are in the same
directory (i.e. both in portage-stable) this will manifest itself in failing the
small C program configuration step.
