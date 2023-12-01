# NNAPI Updating Instructions

## Quick Note

If you're just updating code within `platform2/nnapi`, skip down to
[Uprev the ebuild](#uprev-the-ebuild).

## Background

To fully update the NNAPI dependencies, the following repos need
to be addressed:

* `aosp/platform/frameworks/native`
* `aosp/platform/system/core/libcutils`
* `aosp/platform/system/core/libutils`
* `aosp/platform/system/libbase`
* `aosp/platform/system/libfmq`
* `aosp/platform/system/libhidl`
* `aosp/platform/system/logging`

Most of these can be updated by merging the `upstream` branch of the
repo into the `master` branch. There are however, two cases where this
does not apply.

### The Two Copybara Cases

The NNAPI package depends on some repo's that are copybara'd from another
repo.

Specifically, the following repos:

* `aosp/system/core/libcutils`
* `aosp/system/core/libutils`

Are updated by a copybara process from `aosp/platform/system/core`.

You can see the status of this process on the [Copybara dashboard](https://copybara.corp.google.com/list-jobs?piperConfigPath=%2F%2Fdepot%2Fgoogle3%2Fthird_party%2Fcopybara-gsubtreed%2Faosp%2Fcopy.bara.sky).

In short, whenever the `master` branch of `aosp/platform/system/core` is
updated, the copybara process will (at some point in the future), propagate
those changes into `aosp/system/core/libcutils` and
`aosp/system/core/libutils`.

This means that we can't directly control when the downstream repo
will get updated by the copybara process. It is possible that builds of
NNAPI will start failing if the infrastructure tries to uprev NNAPI to
use updated versions of `libcutils` and `libutils` that are possibly
incompatible.

Due avoid this, and ensure we have explicit control over which version of
these copybara'd directories is built, we have introduced
CROS_WORKON_MANUAL_UPREV to the NNAPI package which means we need to
manually update the commit and tree id's of the non-9999 ebuild.
This decouples the updating of `aosp/platform/system/core` from the NNAPI
package.

## Process

### Update the forked repositories

| Repo | Local Dir | Upstream Branch |
| ---- | --------- | --------------- |
| `aosp/platform/frameworks/native` | `aosp/frameworks/native` | `cros/upstream/master` |
| `aosp/platform/system/libbase`    | `aosp/system/libbase` | `cros/upstream/master` |
| `aosp/platform/system/libfmq`     | `aosp/system/libfmq` | `cros/upstream/master` |
| `aosp/platform/system/libhidl`    | `aosp/system/libhidl` | `cros/upstream/master` |
| `aosp/platform/system/logging`    | `aosp/system/logging` | `cros/upstream/master` |

Steps:

1.  Change into the repo local directory
1.  Create a merge branch from `master`
1.  Do a non-ff git merge from the upstream branch into `master`
1.  `repo upload` to gerrit and process the CL as normal
1.  At this stage you don't need to make any code changes due to
    CROS_WORKON_MANUAL_UPREV. The package won't use this updated
    code yet.

Example:

```bash
cd src/aosp/system/libbase
git checkout -b merge cros/master
# This will ask for an appropriate commit msg
git merge cros/upstream/master --no-ff
# This may give you a scary warning about the number of commits. Say 'y'.
repo upload --cbr . --no-verify
```

### Update the aosp/system/core repo

As described earlier, `aosp/system/core/libcutils` and
`aosp/system/core/libutils` are updated by merging upstream into the master
of `aosp/platform/system/core`. This is a bit more involved than the previous
cases, since this repo isn't mapped into the ChromeOS tree. It's quite
similar though...

Steps:

1.  Check out the core repo.
1.  Create a merge branch from `origin/master`.
1.  Do a non-ff git merge from `origin/upstream`.
1.  Upload to gerrit.
1.  Force submit / 'chump' the change since CQ won't process it.
2.  If you do not have owner permissions then reach out to the [oncall sheriff](go/cros-oncall) and politely ask them for an owners override on your CL.
1.  Within a few minutes, copybara should update `libcutils` and `libutils`.
1.  Check the [Copybara dashboard](https://copybara.corp.google.com/list-jobs?piperConfigPath=%2F%2Fdepot%2Fgoogle3%2Fthird_party%2Fcopybara-gsubtreed%2Faosp%2Fcopy.bara.sky).

```bash
cd /tmp
git clone https://chromium.googlesource.com/aosp/platform/system/core
# Set up the commit hooks
cd core
f=`git rev-parse --git-dir`/hooks/commit-msg
mkdir -p $(dirname $f)
curl -Lo $f https://gerrit-review.googlesource.com/tools/hooks/commit-msg
chmod +x $f
# Done setting up the repo
git checkout -b merge
git merge origin/upstream --no-ff
# This will ask for an appropriate commit msg
git commit
# This will upload to gerrit
git push origin HEAD:refs/for/master
```

### Uprev the ebuild

Once you have any code changes and dependencies submitted via CQ, do a
`repo sync` and you'll be able to uprev the ebuild. This is important, since
you will not be able to get the git commit id's you need until this is done.

There is a script in this directory, `get_git_ids.sh` that will print out the
two lines you need to replace.

Steps:

1.  Run `get_git_ids.sh`.
1.  Rename `nnapi-0.0.2-r<N>.ebuild` to `nnapi-0.0.2-r<N+1>.ebuild`.
1.  Replace CROS_WORKON_COMMIT and CROS_WORKON_TREE in that ebuild with the
    output of the `get_gid_ids.sh` script.
1.  Fix any build issues by creating ebuild patches (see the `files` dir).
1.  Upload to gerrit and review as normal.

### Uprev aosp-frameworks-ml-nn

The majority of times someone will be following this documentation the ultimate goal is
to update the aosp-framework-ml-nn package from the upstream branch. If this is the case
continue on with the following instructions.

First, up-rev the neuralnetworks package on which aosp-frameworks-ml-nn depends:
```bash
cd src/aosp/hardware/interfaces/neuralnetworks
git checkout -b merge cros/main
git merge cros/upstream/master --no-ff
```
This may result in a few merge conflicts that can not be automatically resolved. Manually
fix any conflicts. The correct way to merge any conflicts may only become apparent after
trying to build and test the aosp-frameworks-ml-nn package. Be prepared to redo the merge
if you inadvetently leave in/remove the wrong parts.

Now, lets up-rev the aosp-frameworks-ml-nn package:
```bash
cd src/aosp/frameworks/ml
git checkout -b merge cros/main
git merge cros/upstream/master --no-ff
```
The last command will likely generate a bunch of conflicts. Manually resolve them, taking
note of any comments that exist around the point of conflict which perhaps indicates why
the previous developer intentionally changed things.

When all files have been merged we need to build and test the nnapi package and the
aosp-frameworks-ml-nn package. Run
```bash
FEATURES=test emerge-$BOARD nnapi
```
Resolve any test failures or linking errors that may be reported. Linking errors may require
edits to the BUILD.gn file to include newly added files, or update paths for files that
have been moved around. Once NNAPI is passing, do the same things for aosp-frameworks-ml-nn
```bash
FEATURES=test emerge-$BOARD aosp-frameworks-ml-nn
```
You are quite likely to see build and test failures after this step. Inspect the updates
for the symbols which the linker may be complaining about and update the BUILD.gn file.
Some tests may fail if trying to use anything related to Telemetry or Hardware buffers.
These tests should either be disabled; some code removed which uses these constructs; or
wrapped in macros which are turned on only if `__ANDROID__` is defined.
