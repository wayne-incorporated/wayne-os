# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

PYTHON_COMPAT=( python3_{6..9} )
DISTUTILS_USE_SETUPTOOLS=rdepend

inherit distutils-r1

DESCRIPTION="command line tool for interacting with cloud storage services"
HOMEPAGE="https://github.com/GoogleCloudPlatform/gsutil"
BOTO_REV="9d356f922fcd27be141cda576571c3c4002b1b4d"
OAUTH2CLIENT_REV="350c1fc5ff81dec26777789c1764c420469c6b67"
SRC_URI="http://commondatastorage.googleapis.com/pub/${PN}-${PV}.tar.gz
https://github.com/gsutil-mirrors/boto/archive/${BOTO_REV}.tar.gz -> ${PN}-${PV}-boto.tar.gz
https://github.com/gsutil-mirrors/oauth2client/archive/${OAUTH2CLIENT_REV}.tar.gz -> ${PN}-${PV}-oauth2client.tar.gz"

LICENSE="Apache-2.0"
SLOT="0/${PVR}"
KEYWORDS="*"

RDEPEND="${PYTHON_DEPS}
	>=dev-python/argcomplete-1.9.4[${PYTHON_USEDEP}]
	>=dev-python/crcmod-1.7[${PYTHON_USEDEP}]
	>=dev-python/fasteners-0.14.1[${PYTHON_USEDEP}]
	>=dev-python/gcs-oauth2-boto-plugin-2.7[${PYTHON_USEDEP}]
	>=dev-python/google-apitools-0.5.32[${PYTHON_USEDEP}]
	>=dev-python/google-reauth-python-0.1.0[${PYTHON_USEDEP}]
	>=dev-python/httplib2-0.18[${PYTHON_USEDEP}]
	>=dev-python/mock-2.0.0[${PYTHON_USEDEP}]
	>=dev-python/monotonic-1.4[${PYTHON_USEDEP}]
	>=dev-python/pyopenssl-0.13[${PYTHON_USEDEP}]
	>=dev-python/retry-decorator-1.0.0[${PYTHON_USEDEP}]
	>=dev-python/six-1.12.0[${PYTHON_USEDEP}]"
DEPEND="${RDEPEND}"

DOCS=( README.md CHANGES.md )

src_unpack() {
	default

	S="${WORKDIR}/${PN}-${PV}"
	rm -rf "${S}/gslib/vendored/boto"
	mv "${WORKDIR}/boto-${BOTO_REV}" "${S}/gslib/vendored/boto"
	rm -rf "${S}/gslib/vendored/oauth2client"
	mv "${WORKDIR}/oauth2client-${OAUTH2CLIENT_REV}" "${S}/gslib/vendored/oauth2client"
}

python_prepare_all() {
	distutils-r1_python_prepare_all

	sed -i \
		-e 's/mock==/mock>=/' \
		setup.py || die
	# Sanity check we didn't miss any updates.
	grep '==' setup.py && die "Need to update version requirements"

	# For debugging purposes, show hidden tracebacks.
	sed -e 's/^  except OSError as e:$/&\n    raise/' \
		-e 's/def _HandleUnknownFailure(e):/&\n  raise/' \
		-i gslib/__main__.py || die

	sed -i -E -e 's/(executable_prefix =).*/\1 [sys.executable]/' \
		gslib/commands/test.py || die

	# IOError: close() called during concurrent operation on the same file object.
	sed -i -e 's/sys.stderr.close()/#&/' \
		gslib/tests/testcase/unit_testcase.py || die

	# Don't install the 'test' module.
	rm test/__init__.py
}

python_compile() {
	2to3 --write --nobackups --no-diffs -j "$(makeopts_jobs "${MAKEOPTS}" INF)" \
		gslib/vendored/boto/tests || die "2to3 on boto tests failed"

	distutils-r1_python_compile
}
