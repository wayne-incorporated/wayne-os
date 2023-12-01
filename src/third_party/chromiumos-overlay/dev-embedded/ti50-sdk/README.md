# ti50-sdk

This package is the toolchain for the ti50 effort (go/ti50). It's composed of a
riscv-enabled C/C++ toolchain, and a riscv-enabled Rust toolchain. It's
currently supported by the ti50 team.

# Upgrading

`dev-embedded/ti50-sdk` is logically composed of three parts: clang, newlib, and
rust. It's possible to upgrade each of these independently.

That said, a common point between all of these is how sources are stored: a dev
uses `files/pack_git_tarball.py` to pack a source tarball, then uploads said
tarball to `gs://chromeos-localmirror/distfiles`.

Example per-project invocations of `files/pack_git_tarball.py` are available
below. It's important to keep in mind that **once you upload a new tarball and
point the ti50-sdk ebuild at it, you need to run `FEATURES=-force-mirror ebuild
$(equery w dev-embedded/ti50-sdk) manifest`**. Otherwise, when you try to
download these files from `gs://chromeos-localmirror`, you'll get file integrity
errors.

It's important to note that `chromeos-localmirror` is a large, shared bucket.
Things uploaded to it aren't "final" (e.g., feel free to update them) until a
commit depending on them is landed. After such a commit lands, files aren't to
be changed. You can read more
[here](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/archive_mirrors.md).

Additionally, any patches done to upstream sources should be done *explicitly*
in the ebuild. Tarballs uploaded to chromeos-localmirror are expected to be
clean and true mirrors of the sets of sources available upstream.

## Upgrading clang

In order to upgrade clang, you'll need a tarball of [clang's and LLVM's
sources](https://github.com/llvm/llvm-project) at the SHA you're interested in.
Once you have that at `${dir}`, you can create a git tarball:

```
files/pack_git_tarball.py --git-dir "${dir}" --output-prefix /tmp/llvm
```

This should give you a path that looks like `/tmp/llvm-${sha}-src.tar.xz`. You
can now upload that to gs:

```
gsutil cp -n -a public-read /tmp/llvm-${sha}-src.tar.xz \
    gs://chromeos-localmirror/distfiles/llvm-${sha}-src.tar.xz
```

Update the LLVM_SHA variable in the ebuild file to ${sha}.

After running `ebuild manifest` as described in the section above, you should be
able to start testing these changes via `sudo emerge dev-embedded/ti50-sdk`.

## Upgrading rust

First, determine which build of rust you wish to use. Stable versions can be
found at [build tags](https://github.com/rust-lang/rust/tags). This is a preferred
way to go, as the nightly channel can be enabled in `config.toml` created by a build script.

Another approach is to visit https://static.rust-lang.org/dist/ {build_date},
download `rust-{channel}-i686-unknown-linux-gnu.tar.xz`, and use its
git-commit-hash file's content.

Check [How to Build and Run the Rust Compiler](https://rustc-dev-guide.rust-lang.org/building/how-to-build-and-run.html)
for more details about the process.

`{build_date}` is in the format yyyy-mm-dd and `{channel}` will be one of
`stable|beta|nightly`.  They are related to rustup's `RUST_TOOLCHAIN_VERSION`
variable via `{channel}-{build_date}`.

In order to upgrade rust, you'll need to pull it from [its upstream
repo](https://github.com/rust-lang/rust). With that at
`{dir}`, you can create a git tarball.

### Upgrading ChromeOS patches for Rust
Check http://cs/chromeos_public/src/third_party/chromiumos-overlay/dev-lang/rust/files/
for potential updates for `rustc`.

### Preparing `rustc` source code package

**Note** that our Rust toolchainmakes use of two things that add complexity here:

- Submodules
- Vendored dependencies

To get all the submodules (primarily llvm) and vendored deps, do the following:

```
git clone https://github.com/rust-lang/rust rustc
cd rustc
git checkout ${git-commit-hash}
mkdir vendor

# Download stage0/bin/cargo
./x.py help

# This downloads the llvm-project submodule and also verifies a successful build, but
# build will most likely fail due to incomplete configuration options.
CXX=clang++ ./x.py build

# Optionally check vendor deps work.
build/x86_64-unknown-linux-gnu/stage0/bin/cargo vendor --manifest-path ./Cargo.toml \
-s ./src/bootstrap/Cargo.toml -s ./src/tools/build-manifest/Cargo.toml -s ./src/tools/bump-stage0/Cargo.toml
```

Dependency vendoring is handled by passing an extra flag to
`files/pack_git_tarball.py`. Your invocation should look something like:

```
files/pack_git_tarball.py --git-dir ./rustc --output-prefix /tmp/rustc \
--post-copy-command "$(realpath ./rustc/build/x86_64-unknown-linux-gnu/stage0/bin/cargo) vendor \
--manifest-path ./Cargo.toml -s ./src/tools/rust-analyzer/Cargo.toml -s ./src/bootstrap/Cargo.toml \
-s ./src/tools/build-manifest/Cargo.toml -s ./src/rustdoc-json-types/Cargo.toml \
-s ./compiler/rustc_llvm/Cargo.toml -s ./src/tools/rust-analyzer/Cargo.toml \
-s ./src/tools/rust-analyzer/crates/proc-macro-srv/Cargo.toml  \
-s ./src/tools/build-manifest/Cargo.toml -s ./src/tools/cargotest/Cargo.toml \
-s ./src/tools/rust-analyzer/xtask/Cargo.toml -s ./src/tools/rust-installer/Cargo.toml \
-s ./src/tools/cargo/crates/cargo-test-support/Cargo.toml -s ./src/tools/cargo/Cargo.toml \
-s ./src/tools/bump-stage0/Cargo.toml"
```

(Emphasis on "please ensure `--post-copy-command 'cargo vendor'` is specified."
Your build will break otherwise. :).  This is because even though vendor was
already performed, the pack script only copies files known to git.)

This should give you a path that looks like `/tmp/rustc-${sha}-src.tar.xz`. You
can now upload that to gs:

```
gsutil cp -n -a public-read /tmp/rustc-${sha}-src.tar.xz \
    gs://chromeos-localmirror/distfiles/rust-${sha}-rustc-${sha}-src.tar.xz
```

### Updating .ebuild script

In `rustc/src/stage0.json` check for data required to set `RUST_STAGE0_DATE` and
`RUST_STAGE0_VERSION` in ebuild file. For example in [Rust 1.66.1]
(https://github.com/rust-lang/rust/blob/90743e7298aca107ddaa0c202a4d3604e29bfeb6/src/stage0.json#L19)
you can find:

```
   "compiler": {
    "date": "2022-11-03",
    "version": "1.65.0"
  },
```

Update RUST_SHA to ${sha}, RUST_STAGE0_DATE and RUST_STAGE0_VERSION to the date and version as in src/stage0.json
in the ebuild file.

Additional dependencies for build are partially downloaded in to `rustc/build/cache/${RUST_STAGE0_DATE}`
and can also be downloaded from https://static.rust-lang.org/dist/${RUST_STAGE0_DATE}.

Upload the remaining artifacts to gs:

```
cd rustc/build/cache/${RUST_STAGE0_DATE}

gsutil cp -n -a public-read rustc-${RUST_STAGE0_VERSION}-x86_64-unknown-linux-gnu.tar.xz \
    gs://chromeos-localmirror/distfiles/rust-${sha}-rustc-${RUST_STAGE0_VERSION}-x86_64-unknown-linux-gnu.tar.xz

gsutil cp -n -a public-read cargo-${RUST_STAGE0_VERSION}-x86_64-unknown-linux-gnu.tar.xz \
    gs://chromeos-localmirror/distfiles/rust-${sha}-cargo-${RUST_STAGE0_VERSION}-x86_64-unknown-linux-gnu.tar.xz

gsutil cp -n -a public-read  rust-std-${RUST_STAGE0_VERSION}-x86_64-unknown-linux-gnu.tar.xz \
    gs://chromeos-localmirror/distfiles/rust-${sha}-rust-std-${RUST_STAGE0_VERSION}-x86_64-unknown-linux-gnu.tar.xz

gsutil cp -n -a public-read  rustfmt-${RUST_STAGE0_VERSION}-x86_64-unknown-linux-gnu.tar.xz \
    gs://chromeos-localmirror/distfiles/rust-${sha}-rustfmt-${RUST_STAGE0_VERSION}-x86_64-unknown-linux-gnu.tar.xz

```

After running `ebuild ${ti50-sdk.ebuild} manifest` as described in the section above, you should be
able to start testing these changes via `sudo emerge dev-embedded/ti50-sdk`.

Test out the emerge again by first clearing the cache:
```
rm -f /var/cache/chromeos-cache/distfiles/rust-${sha}-*
sudo emerge dev-embedded/ti50-sdk
```

Once this is complete, you can submit a CL with these changes to update
the CQ builder. Unfortunately, this update is not atomic: once your CL
lands, a builder must pick up the change, which then causes the CQ builder's
chroots to be updated. This means that in order to update the rust toolchain,
you must first get the ti50 build into a state where builds pass for both the
old and new compiler version. Then, once the new compiler version has been
made available to the CQ builders, you can submit followup changes that require
the new compiler. Getting the ti50 code into a state where builds pass with
multiple compiler versions can be challenging. One option for achieveing this
is to use https://github.com/dtolnay/rustversion, which allows conditional compilation
based on the specific compiler version in use. Another option is temporarily allowing
warnings during the transition period, though this risks other breakages during the
transition due to code producing warnings being allowed into main.
The final option is to merge the original CL, thereby breaking the CQ
for all other outstanding ti50 CLs, and then quickly attempting to merge
the actual updates to use the new toolchain, thereby fixing the build
for other outstanding CLs.

## Iterative development

Standard ebuild development practices apply here: `sudo emerge
dev-embedded/ti50-sdk` will clean everything up and start all builds from
scratch. This is desirable in many cases, but not so much when trying to iterate
with a broken toolchain.

The flow the author (gbiv@) used boiled down to `sudo ebuild $(equery w
dev-embedded/ti50-sdk) compile`, which is much more lightweight when e.g.,
trying to figure out why Rust is broken, since it doesn't require a full, fresh
build of LLVM + newlib on every iteration.
