# Chrome OS Build codelab

This codelab walks through an example for
- modifying code in a userspace program,
- running unit tests,
- deploying it to a device,
- and uploading the change for review.

Make sure that you already have a Chromebook, and know how to build an image
and flash it to your device. Instructions are at:
* [Building Chromium OS]
* [Installing Chromium OS on your Device]

Ensure that you have built a test image on your workstation and flashed it onto
your DUT before proceeding. If using an official image, you will get confusing
errors when deploying. See https://crbug.com/693192 for details.

## Sync and create a new branch

First, sync your local repository so that it's up to date.
```
$ cd ~/chromiumos/
$ repo sync

# Build packages again after performing repo sync to avoid build issues
$ ./build_packages --board=${BOARD}
```

Start a new branch, called `codelab` in the `platform2` git repository.
```
$ cd src/platform2
$ repo start codelab
```

## Build your code

Build commands must be run [inside the
chroot](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md#Enter-the-chroot).
Like the developer guide, we annotate commands that run inside the chroot
with (inside).

Then, use cros_workon to "start" working on the package. This will force the
build system to build from source instead of using a prebuilt result. Without
making this change, emerge may use a prebuilt version of the package, and
you'll never see your change applied.
```
(inside)$ cros_workon --board=${BOARD} start chromeos-base/codelab
```

Now, you are able to make builds that use your local changes. Feel free to edit
`codelab.cc` or the corresponding test. Once you've made changes, you can build
your package one of two ways:
```
# Faster, skips emerge build system
(inside)$ cros_workon_make --board=${BOARD} chromeos-base/codelab

# Same flow as build_packages
(inside)$ emerge-${BOARD} chromeos-base/codelab
```

After emerge, you can see that the binary is built on your workstation:
```
(inside)$ ls -l /build/${BOARD}/usr/bin/codelab
```

## Test your code

Again, two options:
```
# Faster, skips emerge build system
(inside)$ cros_workon_make --board=${BOARD} chromeos-base/codelab --test

# Using emerge to build files
(inside)$ FEATURES=test emerge-${BOARD} chromeos-base/codelab
```

Currently all tests pass, but one is disabled. If you edit
`codelab/codelab_test.cc`, you can see that there is a multiply test
with a `DISABLED_` prefix. Remove that prefix to enable the test, and fix the
code in `codelab.cc` so that the test passes.

## Deploy binary to a Chromebook

To deploy this binary to your DUT (device under test), you can use the
`cros deploy` command. Once deployed, you can run it on your local system.

For more information regarding deploy, please see [Cros Deploy].

```
# If you've been using cros_workon_make to iterate, now you have to "install".
# Emerge does this step automatically.
(inside)$ cros_workon_make --board=${BOARD} chromeos-base/codelab --install

(inside)$ cros deploy ${DUT_IP_ADDRESS} chromeos-base/codelab
$ ssh ${DUT_IP_ADDRESS}
(on dut)$ /usr/bin/codelab
```
Hooray! You've built a package and run it locally on your Chromebook.

## Creating a commit and uploading to gerrit

Now that you've tested your change, and it looks good, create a git commit with
containing the edits that you made.
```
$ git add codelab/codelab.cc codelab/codelab_test.cc
$ git commit
$ repo upload . --cbr
```

The first two git commands create a commit in your local git repository. The
"repo upload" step uploads the commit to Gerrit for code review.

Make sure to run commit hooks when prompted. If you need to update the commit
with the required fields, run `git commit --amend` command.

## Cleaning up

At this point, you'd typically add a reviewer, and then submit your change
through the commit queue. However, to keep the codelab reusable, you can just
abandon the commit that you've uploaded to gerrit by clicking "Abandon" in the
gerrit UI.

To clean up your local changes, please see [Chromium OS Contributing Guide].

[Building Chromium OS]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md#Building-Chromium-OS

[Installing Chromium OS on your Device]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md#Installing-Chromium-OS-on-your-Device

[Chromium OS Contributing Guide]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md#clean-up

[Cros Deploy]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/cros_deploy.md
