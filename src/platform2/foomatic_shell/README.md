# foomatic_shell: simple shell used by foomatic-rip

This is a simple shell that is used by foomatic-rip to execute small scripts
included in some PPD files. This shell is supposed to be used instead of
the default shell for security reason.
This project is not completed yet.

## Appendix: FOOMATIC_VERIFY_MODE

When the environment variable `FOOMATIC_VERIFY_MODE` is set,
`foomatic_shell` goes into no-op mode. It carries out command
verification as normal but does not run the overall pipeline. For
example, [this environment variable is set in the printer.TestPPDs tast
test.][tast-foomatic-verify-mode].

[tast-foomatic-verify-mode]: https://chromium.googlesource.com/chromiumos/platform/tast-tests/+/HEAD/src/chromiumos/tast/local/bundles/cros/printer/test_ppds.go
