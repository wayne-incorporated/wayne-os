# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit cros-rust

DESCRIPTION="Project Oxide - documenting Lattice's 28nm \"Nexus\" FPGA parts"
HOMEPAGE="https://github.com/gatecat/prjoxide"

GIT_REV="ea89720449915ab73afdb6f1f2f48939dae6a9e7"

# 'database' submodule.
DB_GIT_REV="56009be1ca77a7123ffdb50a813216302a42ac27"

# '3rdparty/fpga-interchange-schema' submodule.
SCHEMA_GIT_REV="c985b4648e66414b250261c1ba4cbe45a2971b1c"

SRC_URI="
	https://github.com/gatecat/prjoxide/archive/${GIT_REV}.tar.gz -> prjoxide-${GIT_REV}.tar.gz
	https://github.com/gatecat/prjoxide-db/archive/${DB_GIT_REV}.tar.gz -> prjoxide-db-${DB_GIT_REV}.tar.gz
	https://github.com/SymbiFlow/fpga-interchange-schema/archive/${SCHEMA_GIT_REV}.tar.gz -> fpga-interchange-schema-${SCHEMA_GIT_REV}.tar.gz
"

LICENSE="ISC"
SLOT="0"
KEYWORDS="*"

DEPEND="dev-rust/third-party-crates-src:="
RDEPEND="
	${DEPEND}
	sci-electronics/yosys
"

PRJOXIDE_ROOT_DIR="${WORKDIR}/${PN}-${GIT_REV}"
S="${PRJOXIDE_ROOT_DIR}/libprjoxide/prjoxide"

src_unpack() {
	cros-rust_src_unpack

	cd "${PRJOXIDE_ROOT_DIR}" || die
	mv -T ../prjoxide-db-* database || die
	mv -T ../fpga-interchange-schema-* 3rdparty/fpga-interchange-schema || die

	# Remove to build only the prjoxide binary (with prjoxide/Cargo.toml).
	rm libprjoxide/Cargo.toml || die
}

src_prepare() {
	default
	cd "${PRJOXIDE_ROOT_DIR}/database" || die
	eapply "${FILESDIR}/timing-updates.patch"
	eapply "${FILESDIR}/lram-registered-output-timing.patch"
}

src_compile() {
	ecargo_build
}

src_test() {
	ebegin "Testing 'prjoxide --help'"
	"$(cros-rust_get_build_dir)/prjoxide" --help &>/dev/null \
		|| die "The binary hasn't been correctly built!"
	eend
}

src_install() {
	dobin "$(cros-rust_get_build_dir)/prjoxide"

	dodoc "${PRJOXIDE_ROOT_DIR}/README.md"

	insinto /usr/share/${PN}
	doins -r "${PRJOXIDE_ROOT_DIR}/examples"
}
