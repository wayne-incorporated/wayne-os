# Power code reviews

This document contains guidelines for reviewers and contributors of changes to
power_manager and related code. These guidelines are in addition to the
[Chromium code guidelines](
https://chromium.googlesource.com/chromium/src/+/main/docs/contributing.md#code-guidelines)
and the style guidelines in the [ChromiumOS Development Basics](
https://chromium.googlesource.com/chromiumos/docs/+/HEAD/development_basics.md#Programming-languages-and-style) document.

## Why Power Reviews are A Bit Different

Even the simplest seeming power reviews can take a while as the author and
reviewer come to agree on an acceptable approach. Some of the reasons for this
are:

1.  Necessary complexity: power_manager solves a range of complex problems.
1.  Emergent behavior: power_manager interacts with a wide variety of devices
    and subsystems, through many different mechanisms and there are some
    non-obvious dependencies between the various components that must be taken
    into account so that bugs are avoided.
1.  Technical debt from the past: The code base is more than ten years old and
    has been built by dozens of contributors, to deal with hundreds of device
    types and configurations. Not every part is well designed and thought out.
    Additionally, the codebase uses some old approaches because they are
    written before new technologies were adopted by the wider system.
1.  Avoiding future technical debt: the combination of eight year AUE and the
    continuous stream of new devices means that "small hacks" can easily
    accumulate into a tangle of special cases.
1.  Lack of familiarity: power_manager is a large codebase and parts of it
    have not been worked on for a long time. It may be that the reviewer is not
    familiar with the part of the code being modified. It may be that no one
    has expertise with the code being modified.

## Guidelines for Contributions

1.  _"One way":_ Leave code in such a state that there is one way to do
    something, rather than an "an old way" and "a new way".
    1.  Where appropriate, use existing mechanisms and conform to existing
        design.
    1.  Where it is desirable to introduce a new mechanism, update existing
        code to use the new mechanism and remove the old mechanism.
1.  _Clarity for Future Readers:_ write code in such a way that it expresses its
    purpose and implementation clearly to the SWEs who will be reading this code
    in four or five years' time.
    1.  When choosing names, balance consistency with clarity. Unique concepts
        should have unique names.
    1.  Follow the [Chromium OS style guides](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/development_basics.md#Programming-languages-and-style).
    1.  Fix all lint messages, including those from clang-tidy. These messages
        will appear in gerrit when you upload a review, or they can be
        [triggered manually](https://g3doc.corp.google.com/company/teams/chromeos/subteams/toolchain/linting-chromeos.md?cl=head).
1.  _Unit testing:_
    1.  Simplicity - write code in such a way that unit tests can be small and
        involve minimal set up.
    1.  Coverage - Ensure coverage of all important functionality so that
        regressions are caught early. This is related to, but not the same as,
        percentage of lines covered by test cases.
    1.  Robustness - structure tests so that small changes to code will cause
        only small changes to tests. Clearly defined interfaces will help make
        tests more robust to changes in implementation.
1.  _Tast tests:_ Where the scope of a change goes beyond unit tests, and
    especially if it involves per-device configuration, ensure that there are
    Tast tests that cover the functionality. If not, the contributor should
    update existing Tast tests or provide new ones.
1.  _Documentation:_ Update the [documentation directory](https://crsrc.org/o/src/platform2/power_manager/docs/) to ensure it matches
    and properly describes new behavior. If your contribution contains new
    functionality, a new document may be required.
1.  _Each commit does one thing:_ Split complex changes into multiple
    commits.
    1.  It's easier to review ten commits, each of which changes one thing, than
        it is to review one commit that changes ten things.
    1.  Rollbacks / reverts will be easier.
    1.  Small commits make it easier for our future selves reading old commits
        to understand how changes happened.
    1.  These kinds of changes should go into their own commit:
        1.  whitespace and formatting
        1.  minor cleanups
        1.  restructuring code prior to adding the new functionality
1.  _Correctness_: Correctness is important, but it might be the last thing your
    reviewer is looking for. If the codebase is well tested and easy to work
    with, then bugs can always be found and fixed.
