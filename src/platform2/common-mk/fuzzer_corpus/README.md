# fuzzer_corpus: A corpus of files to be tested against all fuzzer targets

## Overview

`fuzzer_corpus` is a centralized directory with files that are used for testing
fuzzer targets during unittest phase.

## Warning

Be careful when adding large number of files here. This is in the platform2
repository and is checked out with many projects. So the larger it gets, the
heavier checking out the platform2 repository will be. If decided to add many
files (specially large ones), we have to plan to move this into a separate
repository of its own.
