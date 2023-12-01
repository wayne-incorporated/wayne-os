# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2
#
# shellcheck disable=SC2034


EAPI=7

DESCRIPTION="Fast, dense and secure container management"
HOMEPAGE="https://linuxcontainers.org/lxd/introduction/ https://github.com/lxc/lxd"


LXD_VENDOR_PACKAGES=(
	"github.com/Rican7/retry"
	"github.com/Rican7/retry/backoff"
	"github.com/Rican7/retry/jitter"
	"github.com/Rican7/retry/strategy"
	"github.com/canonical/go-dqlite"
	"github.com/canonical/go-dqlite/client"
	"github.com/canonical/go-dqlite/driver"
	"github.com/canonical/go-dqlite/internal/bindings"
	"github.com/canonical/go-dqlite/internal/protocol"
	"github.com/canonical/go-dqlite/logging"
	"github.com/flosch/pongo2"
	"github.com/ghodss/yaml"
	"github.com/google/renameio"
	"github.com/gosexy/gettext"
	"github.com/go-macaroon-bakery/macaroonpb"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/..."
	"github.com/juju/errors"
	"github.com/juju/loggo"
	"github.com/juju/schema"
	"github.com/juju/webbrowser"
	"github.com/kballard/go-shellquote"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/mattn/go-sqlite3"
	"github.com/pborman/uuid"
	"github.com/pkg/xattr"
	"github.com/robfig/cron/v3"
	"github.com/rogpeppe/fastuuid"
	"github.com/sirupsen/logrus/..."
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"
	"gopkg.in/juju/environschema.v1/..."
	"gopkg.in/macaroon.v2"
)

LXD_CLIENT_PACKAGES=(
	"github.com/lxc/lxd/client"
	"github.com/lxc/lxd/lxd/db"
	"github.com/lxc/lxd/lxd/db/cluster"
	"github.com/lxc/lxd/lxd/db/node"
	"github.com/lxc/lxd/lxd/db/operationtype"
	"github.com/lxc/lxd/lxd/db/query"
	"github.com/lxc/lxd/lxd/db/schema"
	"github.com/lxc/lxd/lxd/db/warningtype"
	"github.com/lxc/lxd/lxd/device/config"
	"github.com/lxc/lxd/lxd/include"
	"github.com/lxc/lxd/lxd/instance/instancetype"
	"github.com/lxc/lxd/lxd/revert"
	"github.com/lxc/lxd/lxd/storage/filesystem"
	"github.com/lxc/lxd/lxd/util"
	"github.com/lxc/lxd/shared/..."
)

CROS_GO_PACKAGES=(
	"${LXD_CLIENT_PACKAGES[@]}"
	"${LXD_VENDOR_PACKAGES[@]/#/github.com/lxc/lxd/vendor/}"
)

CROS_GO_WORKSPACE=(
	"${S}/_dist"
)

EGO_PN="github.com/lxc/lxd"
BIN_PATH="/opt/google/lxd-next/usr/bin"
CROS_GO_BINARIES=(
	"${EGO_PN}/lxd:${BIN_PATH}/lxd"
	"${EGO_PN}/fuidshift:${BIN_PATH}/fuidshift"
	"${EGO_PN}/lxd-agent:${BIN_PATH}/lxd-agent"
	"${EGO_PN}/lxd-benchmark:${BIN_PATH}/lxd-benchmark"
	"${EGO_PN}/lxd-migrate:${BIN_PATH}/lxd-migrate"
	"${EGO_PN}/lxc:${BIN_PATH}/lxc"
	"${EGO_PN}/lxc-to-lxd:${BIN_PATH}/lxc-to-lxd"
)

# Needs to include licenses for all bundled programs and libraries.
LICENSE="Apache-2.0 BSD BSD-2 LGPL-3 MIT MPL-2.0"
SLOT="5"
KEYWORDS="*"

IUSE="apparmor ipv6 nls verify-sig"

RESTRICT="test"

inherit autotools bash-completion-r1 linux-info optfeature systemd verify-sig cros-go user

SRC_URI="https://linuxcontainers.org/downloads/lxd/${P}.tar.gz
	verify-sig? ( https://linuxcontainers.org/downloads/lxd/${P}.tar.gz.asc )"

DEPEND="app-arch/xz-utils
	>=app-emulation/lxc-5.0.0:5[apparmor?,seccomp(+)]
	dev-db/sqlite
	dev-go/errors
	dev-go/httprouter
	dev-go/websocket
	dev-libs/libuv
	app-arch/lz4
	dev-libs/lzo
	sys-libs/libcap:=
	net-dns/dnsmasq[dhcp,ipv6?]
	virtual/libudev"
RDEPEND="${DEPEND}
	net-firewall/ebtables
	net-firewall/iptables[ipv6?]
	net-misc/rsync[xattr]
	sys-apps/iproute2[ipv6?]
	sys-fs/fuse:0=
	sys-fs/lxcfs:5
	sys-fs/squashfs-tools[lzma]
	virtual/acl"
BDEPEND="dev-lang/go
	nls? ( sys-devel/gettext )
	verify-sig? ( app-crypt/openpgp-keys-linuxcontainers )"

CONFIG_CHECK="
	~CGROUPS
	~IPC_NS
	~NET_NS
	~PID_NS

	~SECCOMP
	~USER_NS
	~UTS_NS
"

ERROR_IPC_NS="CONFIG_IPC_NS is required."
ERROR_NET_NS="CONFIG_NET_NS is required."
ERROR_PID_NS="CONFIG_PID_NS is required."
ERROR_SECCOMP="CONFIG_SECCOMP is required."
ERROR_UTS_NS="CONFIG_UTS_NS is required."

VERIFY_SIG_OPENPGP_KEY_PATH=${BROOT}/usr/share/openpgp-keys/linuxcontainers.asc

src_unpack() {
	unpack "${A}"
	cd "${S}" || die

	# Instead of using the lxd symlink in the dist directory, move the lxd
	# source into that directory. Otherwise, the cros-go_src_install stage
	# will fail since it won't traverse symlinks.
	rm "${S}/_dist/src/${EGO_PN}"
	mkdir -p "${S}/_dist/src/${EGO_PN}"
	find "${S}"/* -maxdepth 0 \
				-type d \
				! -name "_dist" \
				-exec mv {} "${S}/_dist/src/${EGO_PN}" \;
}

src_prepare() {
	cd "${S}/_dist/src/${EGO_PN}/vendor/raft" || die
	eapply_user
}

src_configure() {
	DEPS="${S}/_dist/src/${EGO_PN}/vendor"

	cd "${DEPS}/raft" || die "Can't cd to raft dir"
	eautoreconf
	econf --enable-static=no

	cd "${DEPS}/dqlite" || die "Can't cd to dqlite dir"
	export RAFT_CFLAGS="-I${DEPS}/raft/include/"
	export RAFT_LIBS="${DEPS}/raft/.libs"
	eautoreconf
	econf --enable-static=no
}

src_compile() {
	DEPS="${S}/_dist/src/${EGO_PN}/vendor"

	cd "${DEPS}/raft" || die "Can't cd to raft dir"
	emake

	cd "${DEPS}/dqlite" || die "Can't cd to dqlite dir"
	emake

	cd "${S}" || die

	# Taken from the output of make deps
	export CGO_CFLAGS="-I${DEPS}/raft/include/ -I${DEPS}/dqlite/include/"
	export CGO_LDFLAGS="-L${DEPS}/raft/.libs -L${DEPS}/dqlite/.libs/"
	export LD_LIBRARY_PATH="${DEPS}/raft/.libs/:${DEPS}/dqlite/.libs/"
	export CGO_LDFLAGS_ALLOW="(-Wl,-wrap,pthread_create)|(-Wl,-z,now)"

	# TODO(b/277003404) Because we're installing everything to different
	# paths, we need to tell pkg-config and cgo where to find it. This can
	# be removed when we commit to LXD 5.0
	install_root="${SYSROOT}/opt/google/lxd-next"
	export PKG_CONFIG_LIBDIR="${install_root}/$(get_libdir)/pkgconfig:${SYSROOT}/usr/$(get_libdir)/pkgconfig"
	export PKG_CONFIG_SYSROOT_DIR="${SYSROOT}"
	export PKG_CONFIG="/usr/bin/pkg-config"
	export CGO_CFLAGS="${CGO_CFLAGS} -I${install_root}/include -Wno-ignored-attributes"
	export CGO_LDFLAGS="${CGO_LDFLAGS} -L${install_root}/$(get_libdir)"
	export GOPROXY=off

	cros-go_src_compile

	if use nls; then
		cd "${S}/_dist/src/${EGO_PN}" || die
		emake -f "${S}/Makefile" build-mo
	fi
}

src_test() {
	local DEPS="${S}/_dist/src/${EGO_PN}/vendor"

	# Taken from the output of make deps
	export CGO_CFLAGS="-I${DEPS}/raft/include/ -I${DEPS}/dqlite/include/"
	export CGO_LDFLAGS="-L${DEPS}/raft/.libs -L${DEPS}/dqlite/.libs/"
	local install_root="${SYSROOT}/opt/google/lxd-next"
	export LD_LIBRARY_PATH="${DEPS}/raft/.libs/:${DEPS}/dqlite/.libs/:${install_root}/$(get_libdir)/:${SYSROOT}/usr/$(get_libdir)"
	export CGO_LDFLAGS_ALLOW="(-Wl,-wrap,pthread_create)|(-Wl,-z,now)"

	# TODO(sidereal) would be nice to enable more tests here
	#cros_go test -v "${EGO_PN}/lxd" || die
	elog "uncomment the above line to run tests, but some are flat out broken"
}

src_install() {
	cros-go_src_install

	DEPS="${S}/_dist/src/${EGO_PN}/vendor"

	cd "${DEPS}/raft" || die
	emake DESTDIR="${D}/opt/google/lxd-next" install

	cd "${DEPS}/dqlite" || die
	emake DESTDIR="${D}/opt/google/lxd-next" install

	cd "${S}" || die
	newbashcomp "${S}/_dist/src/${EGO_PN}/scripts/bash/lxd-client" lxc

	dodoc AUTHORS _dist/src/${EGO_PN}/doc/*.md
	dodoc AUTHORS _dist/src/${EGO_PN}/doc/*/*.md
	use nls && domo "${S}/_dist/src/${EGO_PN}/po/"*.mo

	# TODO(b/277003404) Remove this once we no longer need to do weird
	# things with PATH
	insinto /etc/bash/bashrc.d
	newins "${FILESDIR}/set-path.sh" ".set-path-for-lxd-next.sh"
	newins "$(mktemp)" "set-path-for-lxd-next.sh"
}

pkg_postinst() {
	cros-go_pkg_postinst

	# The control socket will be owned by (and writeable by) this group.
	enewgroup lxd

	elog
	elog "Consult https://wiki.gentoo.org/wiki/LXD for more information,"
	elog "including a Quick Start."
	elog
	elog "Please run 'lxc-checkconfig' to see all optional kernel features."
	elog
	elog "Optional features:"
	optfeature "btrfs storage backend" sys-fs/btrfs-progs
	optfeature "lvm2 storage backend" sys-fs/lvm2
	optfeature "zfs storage backend" sys-fs/zfs
	elog
	elog "Be sure to add your local user to the lxd group."
}
