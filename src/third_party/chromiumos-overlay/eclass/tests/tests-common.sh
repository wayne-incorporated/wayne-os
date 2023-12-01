source ../../../portage-stable/eclass/tests/tests-common.sh

# inherit should look into chromiumos-overlay/eclass then in
# portage-stable/eclass.
TESTS_ECLASS_SEARCH_PATHS+=( ../../../portage-stable/eclass )
