# Canon Inkjet Filter

This directory contains source code for a CUPS filter for Canon Inkjet Type A
printers.  More information about CUPS filters can be found in the
[cups documentation](https://www.cups.org/doc/api-filter.html).

This filter in particular is expecting input in the form of PWG raster
(different than CUPS raster).  This filter will read the PWG raster and output
this same raster data along with XML headers.  The PPDs used with this filter
should have a line similar to the following:

*cupsFilter: "image/pwg-raster 0 pwgtocanonij"
