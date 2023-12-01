# CrOS TPM2 Simulator

This project is the front end for a software TPM 2.0. It exposes [libtpm2]
as two file descriptors to accept commands from a client.

The main loop waits for requests on `/dev/tpm-req`, and writes responses to
`/dev/tpm-resp`. All reads and writes are synchronous. A client should read and
write to these file descriptors with the read() and write() syscalls. Multiple
clients using the simulator simultaneously is undefined behavior. The main loop
only exits when it receives an erroneous command.

Execute `tpm2-simulator` as root to inialize the software TPM and wait for
commands.

An example of how a client can use `tpm2-simulator` is in [trunks](../trunks).
See `trunks::TpmSimulatorHandle`. To use trunks with the software TPM, start
the trunks daemon as root with the `--simulator` flag.

## Notes

*   Because [tpm2] builds a static library, if a change is made to any file in
    that repo, `tpm2-simulator` must be forcibly rebuilt to refect this change.

*   If the simulator ever goes into lockout, failure, or other erroneous mode,
    remove NVChip.

[libtpm2]: https://chromium.googlesource.com/chromiumos/third_party/tpm2
[tpm2]: https://chromium.googlesource.com/chromiumos/third_party/tpm2
