# Fingerprint System Performance Analysis and Qualification

This document gives a high level overview of what is required to analyze the
performance of a fingerprint system for Chrome OS. In this document, the
*fingerprint system* is the combination of the fingerprint sensor, fingerprint
MCU (FPMCU), and matching library that runs on the FPMCU.

## Requirements

1.  An **FPMCU firmware** that is approved by the Chrome OS Fingerprint Team

    This should include the matching library and any relevant changes necessary
    to enable full fingerprint functionality within the Chrome OS User
    Interface.

    *Although the fingerprint study tool will collect "raw" fingerprint captures
    from the sensor [bypassing the matching library], it is important for the
    study participants to familiarize themselves with the fingerprint unlock
    feature on Chrome OS, before collecting samples for analysis. To achieve
    this, the participants will enroll their finger(s) on the Chromebook and use
    it to unlock the device multiple times.*

    The final firmware for a qualification must be built by the Chrome OS
    Fingerprint Team. If the matching library or any code that impacts the
    performance of the fingerprint system changes after qualification, a new
    qualification would be required.

2.  A **Chromebook** that is fitted with the fingerprint sensor and FPMCU

    The fingerprint sensor must be positioned in a natural location that is
    approved by Chrome OS.

    For qualification, the testing lab will require at least three identical
    Chromebook test devices to increase testing speed and redundancy.

3.  A **Chrome OS image** with the Fingerprint Study Tool enabled

    This is a Chrome OS image file that will be used to install Chrome OS on the
    Chromebook being tested. In particular, this image must include the
    [Fingerprint Study Tool]. This tool prompts the test participant to touch
    the sensor and aggregates the fingerprints collected. For qualifications,
    this image must be built by the Chrome OS Fingerprint Team.

    The following are some of the Fingerprint Study Tool configuration
    parameters to consider:

    -   The number of fingers to capture.
    -   The number of enrollment captures.
    -   The number of verification captures.

    See [Fingerprint Study Tool] for instructions on how to prepare the image.

4.  A **Performance Evaluation Tool**

    This is a tool that analyzes the offline raw fingerprint captures produced
    by the fingerprint study tool. It is expected to accurately identify whether
    the fingerprint system meets the [Chrome OS Fingerprint Requirements] for
    FRR/FAR as true to real world conditions as possible. In general, it should
    demonstrate the FAR/FRR performance throughout the range of possible
    matching thresholds and the FRR at predefined thresholds (corresponding to
    1/50k and 1/100k FAR).

    The tool itself must run on a standard amd64 GNU/Linux machine, but must
    invoke the same fingerprint matching library with the same parameters to the
    FPMCU matching library being qualified. This tool must accurately measure
    the performance of the provided FPMCU matching library being qualified.
    Again, there should be no difference in performance between the performance
    evaluation tool and the fingerprint systems being qualified.

    *If the FPMCU fingerprint matching library is provided by the vendor, the
    vendor is required to provide the Performance Evaluation Tool. This tool
    must be written in Python 3, but may invoke matching specific functions from
    a pre-compiled matching library. The Python 3 source must be committed to
    the [Chromium OS FP Study Repository]. Google reserves the right to have a
    third party auditor evaluate the accuracy of the provided Performance
    Evaluation Tool and its accompanying matching library. This includes
    source-level analysis of the pre-compiled matching library.*

    Considering errors can occur in the fingerprint capture/labeling process,
    additional diagnostics should be built into the tool to understand which
    participants contribute more negatively to the overall performance. Again,
    the tool may indicate which participants/captures are problematic, but may
    not exclude these from the overall analysis.

    At a minimum, the tool should present the following:

    -   Plot of FAR vs. matching threshold (threshold on x-axis)
    -   Plot of FRR vs. matching threshold (threshold on x-axis)
    -   Plot of [Detection Error Tradeoff] (FAR on x-axis, FRR on y-axis)
    -   The FRR statistics at 1/50k and 1/100k FAR
    -   Any Failure to Enrolls (FTE) that occurred

    If enrolled template updating is used, the before and after values/plots
    must be provided.

## Process

1.  Capture participant fingerprint samples using the [Fingerprint Study Tool].

    For qualification, the [Fingerprint Sensor FAR/FRR Test Procedure] must be
    followed.

2.  Run the analysis tool on the captured fingerprint samples to determine if
    the fingerprint matching performance meets
    [Chrome OS Fingerprint Requirements].

    For qualifications, no fingerprint samples may be excluded/filtered. If a
    truly unique and unnatural fingerprint capturing situation arises, the
    Chrome OS Fingerprint Team can assess and correct the discrepancy on a case
    by case basis.

3.  Further manual testing must be done to ensure that on-chip matching times
    meet [Chrome OS Fingerprint Requirements].

[Fingerprint Study Tool]: README.md

<!-- TODO(hesling): The following test procedure needs to be published for all. -->

[Fingerprint Sensor FAR/FRR Test Procedure]: https://chromeos.google.com/partner/dlm/docs/hardware-specs/fingerprintsensor.html
[Chrome OS Fingerprint Requirements]: https://chromeos.google.com/partner/dlm/docs/latest-requirements/chromebook.html#fingerprint
[Detection error tradeoff]: https://en.wikipedia.org/wiki/Detection_error_tradeoff
[Chromium OS FP Study Repository]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/biod/study/
