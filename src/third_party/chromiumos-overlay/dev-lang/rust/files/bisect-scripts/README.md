# Rust Bisection

It's sometimes necessary to bisect upstream Rust revisions in order to resolve
problems we're seeing in ChromeOS. To this end, `cros-rustc.eclass` has built-in
support for building arbitrary Rust sources. The scripts in this directory
try to make use of that support in order to make bisection easier.

## Quickstart

NOTE: Rust bisection modifies `cros-rustc.eclass`. If you have local changes,
please save them somehow before continuing.

Setting up for Rust bisection is relatively straightforward:

1. Enter the chroot.
2. Run `./setup_rust_for_bisection.sh`.
3. Modify `./run_bisection_step.sh` to reproduce the issue you're interested in.
4. `cd your/path/to/dev-lang/rust/files/rust`.
5. Run `git bisect start --first-parent`, being sure to provide old/new SHAs to
   `git bisect`. `--first-parent` is highly recommended due to the structure of
   some Rust merge commits; `git bisect` without `--first-parent` can end up
   checking out a Clippy repository instead of `rustc` (see [first-parent
   comments]), which is not what we want in general.
6. Run `git bisect run /your/path/to/run_bisection_step.sh`.

Wait for `git bisect` to discover where things started breaking.

## How does bisection work?

As referenced, `cros-rustc.eclass` has support for using an arbitrary Rust
source directory. This support is intended for local debugging only, so the only
way to access it is by modifying the eclass itself. Once this support is
enabled, we clone a full Rust repository to `dev-lang/rust/files/rust`, which is
where `cros-rustc.eclass` expects Rust sources to be located.
`./setup_rust_for_bisection.sh` takes care of all of this.

To prepare this checkout to be built by `emerge dev-lang/rust{,-host}`, we run
`./clean_and_sync_rust_root.sh` to clean up any changes that've been made to the
source tree, and ensure that all of Rust's submodules are synced appropriately,
given the current HEAD of the main Rust checkout. Further, we run
`./prepare_rust_for_offline_build.sh` to download the correct bootstrap
compiler, and update all files in Rust's `vendor/` directory. These tools are
**intentionally kept separate**, since it's expected that users may be
interested in making changes to a clean source tree before we run `cargo
vendor`.

After all of the above setup is done, our Rust checkout at
`dev-lang/rust/files/rust` can be successfully built offline, which is necessary
to keep `emerge` happy. At this point, `emerge dev-lang/rust{,-host}` is run.
This command installs the Rust version that was checked out by the user in
`dev-lang/rust/files/rust`, rather than the version advertised by our Rust
ebuild.

Since the above establishes an environment where `emerge dev-lang/rust{,-host}`
can build Rust at arbitrary commits of a Git repository, bisection proceeds as
one might expect -- you simply run something that boils down to:

```
git -C dev-lang/rust/files/rust bisect run bash -c '
  ../bisect-scripts/clean_and_sync_rust_root.sh || exit 128
  ../bisect-scripts/prepare_rust_for_offline_build.sh || exit 128
  # `git bisect run` needs the working tree to be sufficiently clean. If
  # e.g., portage applied patches, those need to be unapplied in many cases for
  # bisection to continue.
  trap '../bisect-scripts/clean_and_sync_rust_root.sh || :' EXIT
  emerge dev-lang/rust{,-host} || exit 125
  ## Your test case goes here, setting $exit_status ##
'
```

For convenience, `./run_bisection_step.sh` is available as a substitute for the
`bash -c '...'` part of the above. It's written to be a stub that anyone can
extend for their specific bisection needs; use of it is encouraged, since `git
bisect run` has sharp corners when e.g., bisection setup commands unexpectedly
fail.

[first-parent comments]: https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/3733996/comments/e6e47a5d_41c282e8
