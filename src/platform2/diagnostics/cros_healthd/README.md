# cros_healthd: Telemetry and Diagnostics Daemon

cros_healthd provides the universal one-stop telemetry and diagnostics API
support for the ChromeOS system.

## Design

[go/cros_healthd](https://goto.google.com/cros_healthd)

## Manual Testing

Because the telem and diag utilities are currently unable to test cros_healthd,
manual testing of cros_healthd in a sandbox is necessary. If any new sources of
telemetry data or diagnostic routines are added before the automation framework
is complete, the new functionality must be manually tested by the developer
prior to code review.

TODO(crbug.com/1023933): Update these instructions once telem can talk to
cros_healthd and cherry-picking a test CL is no longer necessary.

### Procedure

*   Make sure both ChromeOS and Chrome sources are up to date. This is
    necessary because there are a number of dependencies between ChromeOS and
    Chrome, and trying to deploy a recent Chrome image onto an older ChromeOS
    image (or vice versa) will likely fail in a manner unrelated to the code
    under test.

*   Enterprise-enroll the DUT. Make sure that the DUT is running a recent
    ChromeOS image, preferably by running:
    ```bash
    (cros-sdk) cros flash ${DUT_IP} xbuddy://remote/${BOARD}/latest-dev/test
    ```

*   Build and deploy the diagnostics package with the local changes under
    test:
    ```bash
    (cros-sdk) USE="-cros-debug" ~/trunk/src/scripts/build_packages --board=${BOARD}
    (cros-sdk) cros_workon-${BOARD} start diagnostics
    (cros-sdk) USE="-cros-debug" emerge-${BOARD} diagnostics
    (cros-sdk) cros deploy ${DUT_IP} diagnostics
    ```
    Note that build_packages is necessary to rebuild all dependencies with the
    correct USE flags.

*   Cherry-pick https://crrev.com/c/1779132 to use as a starting point for
    testing. Extend the CL to log any new data reported by cros_healthd in
    `status_uploader.cc`.

*   Build and deploy Chrome to the DUT using simple Chrome:
    https://chromium.googlesource.com/chromiumos/docs/+/HEAD/simple_chrome_workflow.md

*   Restart the DUT, and check that the fields are being reported properly:
    ```bash
    (DUT) grep status_uploader /var/log/chrome/chrome
    ```
