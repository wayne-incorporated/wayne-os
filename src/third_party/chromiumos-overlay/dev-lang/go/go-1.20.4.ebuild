# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

inherit eutils toolchain-funcs

# Version used to bootstrap the build.
BOOTSTRAP="go1.17.13-bootstrap-20230206"

DESCRIPTION="An expressive, concurrent, garbage-collected programming language"
HOMEPAGE="http://golang.org/"
SRC_URI="https://storage.googleapis.com/golang/go${PV}.src.tar.gz
	https://storage.googleapis.com/golang/${BOOTSTRAP}.tar.gz"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks"

BDEPEND="dev-lang/go"

is_cross() {
	[[ "${CATEGORY}" == cross-* ]]
}

DEPEND=""
if is_cross ; then
	DEPEND="${CATEGORY}/gcc"
fi
RDEPEND="${DEPEND}"

export CTARGET="${CTARGET:-${CHOST}}"
if [[ "${CTARGET}" == "${CHOST}" ]] ; then
	if is_cross ; then
		CTARGET="${CATEGORY#cross-}"
	fi
fi

get_goroot() {
	if is_cross ; then
		echo "/usr/lib/go/${CTARGET}"
	else
		echo "/usr/lib/go"
	fi
}

get_goarch() {
	case "$(tc-arch "$1")" in
		amd64) echo "amd64" ;;
		x86) echo "386" ;;
		arm) echo "arm" ;;
		arm64) echo "arm64" ;;
	esac
}

src_unpack() {
	unpack "go${PV}.src.tar.gz"
	mv go "go-${PV}"
	unpack "${BOOTSTRAP}.tar.gz"
	mv go "${BOOTSTRAP}"
}

src_configure() {
	export GOROOT_BOOTSTRAP="${WORKDIR}/${BOOTSTRAP}"
	export GOROOT_FINAL="${EPREFIX}$(get_goroot)"
}

src_compile() {
	einfo "Building the bootstrap compiler."
	cd "${GOROOT_BOOTSTRAP}/src" || die
	./make.bash || die

	cd "${S}/src" || die
	einfo "Building the cross compiler for ${CTARGET}."
	local go_target_cc="$(tc-getTARGET_CC)"
	local go_target_cxx="$(tc-getTARGET_CXX)"
	if [[ "$(tc-arch "${CBUILD}")" == "$(tc-arch "${CTARGET}")" ]]; then
		go_target_cc="$(tc-getBUILD_CC)"
		go_target_cxx="$(tc-getBUILD_CXX)"
	fi
	GOOS="linux" GOARCH="$(get_goarch "${CTARGET}")" CGO_ENABLED="1" \
		CC_FOR_TARGET="${go_target_cc}" \
		CXX_FOR_TARGET="${go_target_cxx}" \
		./make.bash || die

	if is_cross ; then
		einfo "Building the standard library with -buildmode=pie."
		GOOS="linux" GOARCH="$(get_goarch "${CTARGET}")" CGO_ENABLED="1" \
			CC="$(tc-getTARGET_CC)" \
			CXX="$(tc-getTARGET_CXX)" \
			GOROOT="${S}" \
			"${S}/bin/go" install -v -buildmode=pie std || die
	fi

	# CHROMIUM (b/269512291): Workaround to install the standard library
	# archives into ${goroot}
	#
	# Starting from Go 1.20, the distribution stops shipping the
	# pre-compiled archives for the standard library, and we found that
	# tools in /usr/lib/go/pkg/tool/ may break because of that.
	# See https://tip.golang.org/doc/go1.20#go-command for details.
	#
	# To address that, we build and install the blobs into ${goroot} to
	# restore the environment.
	einfo "Building the standard library archives."
	GOOS="linux" GOARCH="$(get_goarch "${CBUILD}")" GOROOT="${S}" \
		GODEBUG=installgoroot=all \
		"${S}/bin/go" install std || die
}

src_install() {
	local goroot="$(get_goroot)"
	local tooldir="pkg/tool/linux_$(get_goarch "${CBUILD}")"

	insinto "${goroot}"
	doins -r src lib

	exeinto "${goroot}/bin"
	doexe bin/{go,gofmt}

	insinto "${goroot}/pkg"
	doins -r "pkg/include"
	doins -r "pkg/linux_$(get_goarch "${CBUILD}")"

	exeinto "${goroot}/${tooldir}"
	doexe "${tooldir}/"{asm,cgo,compile,link,pack}
	doexe "${tooldir}/"{doc,fix,vet}
	doexe "${tooldir}/"{cover,pprof,trace}
	doexe "${tooldir}/"{addr2line,buildid,nm,objdump,test2json}

	if is_cross ; then
		# Setup the wrapper for invoking the cross compiler.
		# See "files/pie_wrapper.py" for details.
		newbin "${FILESDIR}/pie_wrapper.py" "${CTARGET}-go"
	else
		dosym "${goroot}/bin/go" /usr/bin/go
		dosym "${goroot}/bin/gofmt" /usr/bin/gofmt
		# Setup the wrapper for invoking the host compiler.
		# See "files/host_wrapper.py" for details.
		newbin "${FILESDIR}/host_wrapper.py" "${CTARGET}-go"
	fi

	# Fill in variable values in the compiler wrapper.
	sed -e "s:@GOARCH@:$(get_goarch "${CTARGET}"):" \
		-e "s:@CC@:$(tc-getTARGET_CC):" \
		-e "s:@CXX@:$(tc-getTARGET_CXX):" \
		-e "s:@GOTOOL@:${GOROOT_FINAL}/bin/go:" \
		-i "${D}/usr/bin/${CTARGET}-go" || die
}
