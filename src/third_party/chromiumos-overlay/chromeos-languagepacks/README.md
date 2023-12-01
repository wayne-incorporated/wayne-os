This directory contains all the packages used by Language Packs.

Each DLC corresponds to a Portage package (ebuild). These are usually simple
packages where the files inside the source archive are extracted and installed
into the DLC path.

For information on how to create and use Language Packs, refer to
go/languagepack-client.

The ebuilds in this directory are required to have the following:

# Source archive format
SRC_URI="gs://chromeos-localmirror/distfiles/languagepack-<FEATURE>-<LANGUAGE>-${PV}.tar.xz"

# Variables
DLC_SCALED=true
IUSE="dlc"
REQUIRED_USE="dlc"
