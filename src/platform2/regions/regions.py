#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Authoritative source for Chromium OS region/locale configuration.

Run this module to display all known regions (use --help to see options).
"""

from __future__ import print_function

import argparse
import collections.abc
import json
import re
import sys

import yaml  # pylint: disable=import-error


# The regular expression to check values in Region.keyboards and Region.locales.
# Keyboards should come with xkb: protocol, or the input methods (ime:, m17n:).
# Examples: xkb:us:intl:eng, ime:ime:zh-t:cangjie, xkb:us:altgr-intl:eng
KEYBOARD_PATTERN = re.compile(
    r"^xkb:\w+:[\w-]*:\w+$|" r"^(ime|m17n|t13n):[\w:-]+$"
)
# Locale should be a combination of language and location.
# Examples: en-US, ja.
LOCALE_PATTERN = re.compile(r"^(\w+)(-[A-Z0-9]+)?$")


class Enum(frozenset):
    """An enumeration type.

    Examples:
      To create a enum object:
        dummy_enum = Enum(['A', 'B', 'C'])

      To access a enum object, use:
        dummy_enum.A
        dummy_enum.B
    """

    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError


class RegionException(Exception):
    """Exception in Region handling."""


def MakeList(value):
    """Converts the given value to a list.

    Returns:
      A list of elements from "value" if it is iterable (except string);
      otherwise, a list contains only one element.
    """
    if isinstance(value, collections.abc.Iterable) and not isinstance(
        value, str
    ):
        return list(value)
    return [value]


class Region(object):
    """Comprehensive, standard locale configuration per country/region.

    See :ref:`regions-values` for detailed information on how to set
    these values.
    """

    # pylint gets confused by some of the docstrings.

    # ANSI = US-like
    # ISO = UK-like
    # JIS = Japanese
    # KS = Korean (see http://crosbug.com/p/50753 for why this is not used yet)
    # ABNT2 = Brazilian (like ISO but with an extra key to the left of the
    #   right shift key)
    KeyboardMechanicalLayout = Enum(["ANSI", "ISO", "JIS", "KS", "ABNT2"])

    region_code = None
    """A unique identifier for the region.  This may be a lower-case
    `ISO 3166-1 alpha-2 code
    <http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2>`_ (e.g., ``us``),
    a variant within an alpha-2 entity (e.g., ``ca.fr``), or an
    identifier for a collection of countries or entities (e.g.,
    ``latam-es-419`` or ``nordic``).  See :ref:`region-codes`.

    Note that ``uk`` is not a valid identifier; ``gb`` is used as it is
    the real alpha-2 code for the UK."""

    keyboards = None
    """A list of keyboard layout identifiers (e.g., ``xkb:us:intl:eng``
    or ``m17n:ar``). This field was designed to be the physical keyboard layout
    in the beginning, and then becomes a list of OOBE keyboard selection, which
    then includes non-physical layout elements like input methods (``ime:``).
    To avoid confusion, physical layout is now defined by
    :py:attr:`keyboard_mechanical_layout`, and this is reserved for logical
    layouts.

    This is identical to the legacy VPD ``keyboard_layout`` value."""

    time_zones = None
    """A list of default `tz database time zone
    <http://en.wikipedia.org/wiki/List_of_tz_database_time_zones>`_
    identifiers (e.g., ``America/Los_Angeles``). See
    `timezone_settings.cc <http://goo.gl/WSVUeE>`_ for supported time
    zones.

    This is identical to the legacy VPD ``initial_timezone`` value."""

    locales = None
    """A list of default locale codes (e.g., ``en-US``); see
    `l10n_util.cc <http://goo.gl/kVkht>`_ for supported locales.

    This is identital to the legacy VPD ``initial_locale`` field."""

    keyboard_mechanical_layout = None
    """The keyboard's mechanical layout (``ANSI`` [US-like], ``ISO``
    [UK-like], ``JIS`` [Japanese], ``ABNT2`` [Brazilian] or ``KS`` [Korean])."""

    description = None
    """A human-readable description of the region.
    This defaults to :py:attr:`region_code` if not set."""

    notes = None
    """Implementation notes about the region.  This may be None."""

    regulatory_domain = None
    """An ISO 3166-1 alpha 2 upper-cased two-letter region code for setting
    Wireless regulatory. See crosbug.com/p/38745 for more details.

    When omitted, this will derive from region_code."""

    confirmed = None
    """An optional boolean flag to indicate if the region data is confirmed."""

    FIELDS = [
        "region_code",
        "description",
        "keyboards",
        "time_zones",
        "locales",
        "keyboard_mechanical_layout",
        "regulatory_domain",
    ]
    """Names of fields that define the region."""

    def __init__(
        self,
        region_code,
        keyboards,
        time_zones,
        locales,
        keyboard_mechanical_layout,
        description=None,
        notes=None,
        regdomain=None,
    ):
        """Constructor.

        Args:
          region_code: See :py:attr:`region_code`.
          keyboards: See :py:attr:`keyboards`.  A single string is accepted for
            backward compatibility.
          time_zones: See :py:attr:`time_zones`.
          locales: See :py:attr:`locales`.  A single string is accepted
            for backward compatibility.
          keyboard_mechanical_layout: See :py:attr:`keyboard_mechanical_layout`.
          description: See :py:attr:`description`.
          notes: See :py:attr:`notes`.
          regdomain: See :py:attr:`regulatory_domain`.
        """

        def regdomain_from_region(region):
            if region.find(".") >= 0:
                region = region[: region.index(".")]
            if len(region) == 2:
                return region.upper()
            return None

        # Quick check: should be 'gb', not 'uk'
        if region_code == "uk":
            raise RegionException("'uk' is not a valid region code (use 'gb')")

        self.region_code = region_code
        self.keyboards = MakeList(keyboards)
        self.time_zones = MakeList(time_zones)
        self.locales = MakeList(locales)
        self.keyboard_mechanical_layout = keyboard_mechanical_layout
        self.description = description or region_code
        self.notes = notes
        self.regulatory_domain = regdomain or regdomain_from_region(region_code)
        self.confirmed = None

        for f in (self.keyboards, self.locales):
            assert all(isinstance(x, str) for x in f), (
                "Expected a list of strings, not %r" % f
            )
        for f in self.keyboards:
            assert KEYBOARD_PATTERN.match(
                f
            ), "Keyboard pattern %r does not match %r" % (
                f,
                KEYBOARD_PATTERN.pattern,
            )
        for f in self.locales:
            assert LOCALE_PATTERN.match(f), "Locale %r does not match %r" % (
                f,
                LOCALE_PATTERN.pattern,
            )
        assert (
            self.regulatory_domain
            and len(self.regulatory_domain) == 2
            and self.regulatory_domain.upper() == self.regulatory_domain
        ), ("Regulatory domain settings error for region %s" % region_code)

    def __repr__(self):
        return "Region(%s)" % (
            ", ".join([getattr(self, x) for x in self.FIELDS])
        )

    def GetFieldsDict(self):
        """Returns a dict of all substantive fields.

        notes and description are excluded.
        """
        return dict((k, getattr(self, k)) for k in self.FIELDS)


KML = Region.KeyboardMechanicalLayout
PSEUDOLOCALE_REGIONS_LIST = [
    Region(
        "ar.xb",
        "xkb:us::eng",
        "America/Los_Angeles",
        "ar-XB",
        KML.ANSI,
        "Pseudolocale (RTL)",
    ),
    Region(
        "en.xa",
        "xkb:us::eng",
        "America/Los_Angeles",
        "en-XA",
        KML.ANSI,
        "Pseudolocale (long strings)",
    ),
]
REGIONS_LIST = [
    Region(
        "au", "xkb:us::eng", "Australia/Sydney", "en-AU", KML.ANSI, "Australia"
    ),
    Region(
        "be",
        "xkb:be::nld",
        "Europe/Brussels",
        "en-GB",
        KML.ISO,
        "Belgium",
        (
            "Flemish (Belgian Dutch) keyboard; British English language for "
            "neutrality"
        ),
    ),
    Region(
        "br",
        "xkb:br::por",
        "America/Sao_Paulo",
        "pt-BR",
        KML.ABNT2,
        "Brazil (ABNT2)",
        (
            "ABNT2 = ABNT NBR 10346 variant 2. This is the preferred layout "
            "for Brazil. ABNT2 is mostly an ISO layout, but it 12 keys between "
            "the shift keys; see http://goo.gl/twA5tq"
        ),
    ),
    Region(
        "br.abnt",
        "xkb:br::por",
        "America/Sao_Paulo",
        "pt-BR",
        KML.ISO,
        "Brazil (ABNT)",
        (
            "Like ABNT2, but lacking the extra key to the left of the right "
            'shift key found in that layout. ABNT2 (the "br" region) is '
            "preferred to this layout"
        ),
    ),
    Region(
        "br.usintl",
        "xkb:us:intl:eng",
        "America/Sao_Paulo",
        "pt-BR",
        KML.ANSI,
        "Brazil (US Intl)",
        (
            'Brazil with US International keyboard layout. ABNT2 ("br") and '
            'ABNT1 ("br.abnt1 ") are both preferred to this.'
        ),
    ),
    Region(
        "ca.ansi",
        "xkb:us::eng",
        "America/Toronto",
        "en-CA",
        KML.ANSI,
        "Canada (US keyboard)",
        (
            "Canada with US (ANSI) keyboard. Only allowed if there are "
            "separate US English, Canadian English, and French SKUs. "
            "Not for en/fr hybrid ANSI keyboards; for that you would want "
            "ca.hybridansi. See http://goto/cros-canada"
        ),
    ),
    Region(
        "ca.fr",
        "xkb:ca::fra",
        "America/Toronto",
        "fr-CA",
        KML.ISO,
        "Canada (French keyboard)",
        (
            "Canadian French (ISO) keyboard. The most common configuration for "
            "Canadian French SKUs.  See http://goto/cros-canada"
        ),
    ),
    Region(
        "ca.hybrid",
        "xkb:ca:eng:eng",
        "America/Toronto",
        "en-CA",
        KML.ISO,
        "Canada (hybrid ISO)",
        (
            "Canada with hybrid (ISO) xkb:ca:eng:eng + xkb:ca::fra keyboard, "
            "defaulting to English language and keyboard.  Used only if there "
            "needs to be a single SKU for all of Canada.  See "
            "http://goto/cros-canada"
        ),
    ),
    Region(
        "ca.hybridansi",
        "xkb:ca:eng:eng",
        "America/Toronto",
        "en-CA",
        KML.ANSI,
        "Canada (hybrid ANSI)",
        (
            "Canada with hybrid (ANSI) xkb:ca:eng:eng + xkb:ca::fra keyboard, "
            "defaulting to English language and keyboard.  Used only if there "
            "needs to be a single SKU for all of Canada.  See "
            "http://goto/cros-canada"
        ),
    ),
    Region(
        "ca.multix",
        "xkb:ca:multix:fra",
        "America/Toronto",
        "fr-CA",
        KML.ISO,
        "Canada (multilingual)",
        (
            "Canadian Multilingual keyboard; you probably don't want this. See "
            "http://goto/cros-canada"
        ),
    ),
    Region(
        "ch",
        "xkb:ch::ger",
        "Europe/Zurich",
        "de-CH",
        KML.ISO,
        "Switzerland",
        ("German keyboard"),
    ),
    Region("de", "xkb:de::ger", "Europe/Berlin", "de", KML.ISO, "Germany"),
    Region("es", "xkb:es::spa", "Europe/Madrid", "es", KML.ISO, "Spain"),
    Region("fi", "xkb:fi::fin", "Europe/Helsinki", "fi", KML.ISO, "Finland"),
    Region("fr", "xkb:fr::fra", "Europe/Paris", "fr", KML.ISO, "France"),
    Region("gb", "xkb:gb:extd:eng", "Europe/London", "en-GB", KML.ISO, "UK"),
    Region(
        "ie", "xkb:gb:extd:eng", "Europe/Dublin", "en-GB", KML.ISO, "Ireland"
    ),
    Region("in", "xkb:us::eng", "Asia/Calcutta", "en-US", KML.ANSI, "India"),
    Region("it", "xkb:it::ita", "Europe/Rome", "it", KML.ISO, "Italy"),
    Region(
        "latam-es-419",
        "xkb:es::spa",
        "America/Mexico_City",
        "es-419",
        KML.ISO,
        "Hispanophone Latin America",
        (
            "Spanish-speaking countries in Latin America, using the Iberian "
            "(Spain) Spanish keyboard, which is increasingly dominant in "
            "Latin America. Known to be correct for "
            "Chile, Colombia, Mexico, Peru; "
            "still unconfirmed for other es-419 countries. The old Latin "
            "American layout (xkb:latam::spa) has not been approved; before "
            "using that you must seek review through http://goto/vpdsettings. "
            "See also http://goo.gl/Iffuqh. Note that 419 is the UN M.49 "
            "region code for Latin America"
        ),
        "MX",
    ),
    Region(
        "my", "xkb:us::eng", "Asia/Kuala_Lumpur", "ms", KML.ANSI, "Malaysia"
    ),
    Region(
        "nl",
        "xkb:us:intl:eng",
        "Europe/Amsterdam",
        "nl",
        KML.ANSI,
        "Netherlands",
    ),
    Region(
        "nordic",
        "xkb:se::swe",
        "Europe/Stockholm",
        "en-US",
        KML.ISO,
        "Nordics",
        (
            "Unified SKU for Sweden, Norway, and Denmark.  This defaults "
            "to Swedish keyboard layout, but starts with US English language "
            "for neutrality.  Use if there is a single combined SKU for Nordic "
            "countries."
        ),
        "SE",
    ),
    Region(
        "nz",
        "xkb:us::eng",
        "Pacific/Auckland",
        "en-NZ",
        KML.ANSI,
        "New Zealand",
    ),
    Region(
        "ph", "xkb:us::eng", "Asia/Manila", "en-US", KML.ANSI, "Philippines"
    ),
    Region(
        "ru",
        ["xkb:us::eng", "xkb:ru::rus"],
        "Europe/Moscow",
        "ru",
        KML.ANSI,
        "Russia",
        ("For R31+ only; R30 and earlier must use US keyboard for login"),
    ),
    Region(
        "se",
        "xkb:se::swe",
        "Europe/Stockholm",
        "sv",
        KML.ISO,
        "Sweden",
        (
            "Use this if there separate SKUs for Nordic countries (Sweden, "
            "Norway, and Denmark), or the device is only shipping to Sweden. "
            "If there is a single unified SKU, use 'nordic' instead."
        ),
    ),
    Region(
        "sg", "xkb:us::eng", "Asia/Singapore", "en-GB", KML.ANSI, "Singapore"
    ),
    Region(
        "us",
        "xkb:us::eng",
        "America/Los_Angeles",
        "en-US",
        KML.ANSI,
        "United States",
    ),
    Region(
        "jp",
        ["xkb:jp::jpn", "ime:jp:mozc_jp"],
        "Asia/Tokyo",
        "ja",
        KML.JIS,
        "Japan",
    ),
    Region(
        "za",
        "xkb:za:gb:eng",
        "Africa/Johannesburg",
        "en-ZA",
        KML.ISO,
        "South Africa",
    ),
    Region(
        "ng", "xkb:us:intl:eng", "Africa/Lagos", "en-GB", KML.ANSI, "Nigeria"
    ),
    Region(
        "hk",
        [
            "xkb:us::eng",
            "ime:zh-t:cangjie",
            "ime:zh-t:quick",
            "ime:zh-t:array",
            "ime:zh-t:dayi",
            "ime:zh-t:zhuyin",
            "ime:zh-t:pinyin",
        ],
        "Asia/Hong_Kong",
        ["zh-TW", "en-GB", "zh-CN"],
        KML.ANSI,
        "Hong Kong",
    ),
    Region(
        "gcc",
        ["xkb:us::eng", "m17n:ar", "t13n:ar"],
        "Asia/Riyadh",
        ["ar", "en-GB"],
        KML.ANSI,
        "Gulf Cooperation Council (GCC)",
        (
            "GCC is a regional intergovernmental political and economic "
            "union consisting of all Arab states of the Persian Gulf except "
            "for Iraq. Its member states are the Islamic monarchies of "
            "Bahrain, Kuwait, Oman, Qatar, Saudi Arabia, and the United Arab "
            "Emirates."
        ),
        "SA",
    ),
    Region(
        "cz",
        ["xkb:cz::cze", "xkb:cz:qwerty:cze"],
        "Europe/Prague",
        ["cs", "en-GB"],
        KML.ISO,
        "Czech Republic",
    ),
    Region(
        "th",
        ["xkb:us::eng", "m17n:th", "m17n:th_pattajoti", "m17n:th_tis"],
        "Asia/Bangkok",
        ["th", "en-GB"],
        KML.ANSI,
        "Thailand",
    ),
    Region(
        "id",
        "xkb:us::ind",
        "Asia/Jakarta",
        ["id", "en-GB"],
        KML.ANSI,
        "Indonesia",
    ),
    Region(
        "tw",
        [
            "xkb:us::eng",
            "ime:zh-t:zhuyin",
            "ime:zh-t:array",
            "ime:zh-t:dayi",
            "ime:zh-t:cangjie",
            "ime:zh-t:quick",
            "ime:zh-t:pinyin",
        ],
        "Asia/Taipei",
        ["zh-TW", "en-US"],
        KML.ANSI,
        "Taiwan",
    ),
    Region(
        "pl",
        "xkb:pl::pol",
        "Europe/Warsaw",
        ["pl", "en-GB"],
        KML.ANSI,
        "Poland",
    ),
    Region(
        "gr",
        ["xkb:us::eng", "xkb:gr::gre", "t13n:el"],
        "Europe/Athens",
        ["el", "en-GB"],
        KML.ANSI,
        "Greece",
    ),
    Region(
        "il",
        ["xkb:us::eng", "xkb:il::heb", "t13n:he"],
        "Asia/Jerusalem",
        ["he", "en-US", "ar"],
        KML.ANSI,
        "Israel",
    ),
    Region(
        "pt",
        "xkb:pt::por",
        "Europe/Lisbon",
        ["pt-PT", "en-GB"],
        KML.ISO,
        "Portugal",
    ),
    Region(
        "ro",
        ["xkb:us::eng", "xkb:ro::rum"],
        "Europe/Bucharest",
        ["ro", "hu", "de", "en-GB"],
        KML.ISO,
        "Romania",
    ),
    Region(
        "kr",
        ["xkb:us::eng", "ime:ko:hangul"],
        "Asia/Seoul",
        ["ko", "en-US"],
        KML.ANSI,
        "South Korea",
    ),
    Region("ae", "xkb:us::eng", "Asia/Dubai", "ar", KML.ANSI, "UAE"),
    Region(
        "za.us",
        "xkb:us::eng",
        "Africa/Johannesburg",
        "en-ZA",
        KML.ANSI,
        "South Africa",
    ),
    Region(
        "vn",
        [
            "xkb:us::eng",
            "m17n:vi_telex",
            "m17n:vi_vni",
            "m17n:vi_viqr",
            "m17n:vi_tcvn",
        ],
        "Asia/Ho_Chi_Minh",
        ["vi", "en-GB", "en-US", "fr", "zh-TW"],
        KML.ANSI,
        "Vietnam",
    ),
    Region(
        "at",
        ["xkb:de::ger", "xkb:de:neo:ger"],
        "Europe/Vienna",
        ["de", "en-GB"],
        KML.ISO,
        "Austria",
    ),
    Region(
        "sk",
        ["xkb:us::eng", "xkb:sk::slo"],
        "Europe/Bratislava",
        ["sk", "hu", "cs", "en-GB"],
        KML.ISO,
        "Slovakia",
    ),
    Region(
        "ch.usintl",
        "xkb:us:intl:eng",
        "Europe/Zurich",
        "en-US",
        KML.ANSI,
        "Switzerland (US Intl)",
        ("Switzerland with US International keyboard layout."),
    ),
    Region("pe", "xkb:latam::spa", "America/Lima", "es-419", KML.ANSI, "Peru"),
    Region(
        "sa",
        "xkb:us::eng",
        "Asia/Riyadh",
        ["ar", "en"],
        KML.ANSI,
        "Saudi Arabia",
    ),
    Region(
        "mx",
        "xkb:latam::spa",
        "America/Mexico_City",
        "es-MX",
        KML.ANSI,
        "Mexico",
    ),
    Region(
        "cl", "xkb:latam::spa", "America/Santiago", "es-419", KML.ANSI, "Chile"
    ),
    Region(
        "kw",
        ["xkb:us::eng", "m17n:ar", "t13n:ar"],
        "Asia/Kuwait",
        ["ar", "en"],
        KML.ANSI,
        "Kuwait",
    ),
    Region(
        "uy",
        "xkb:latam::spa",
        "America/Montevideo",
        "es-419",
        KML.ANSI,
        "Uruguay",
    ),
    Region(
        "tr",
        ["xkb:tr::tur", "xkb:tr:f:tur"],
        "Europe/Istanbul",
        ["tr", "en-GB"],
        KML.ISO,
        "Turkey",
    ),
    Region(
        "ar",
        "xkb:latam::spa",
        "America/Argentina/Buenos_Aires",
        [
            "es-AR",
        ],
        KML.ISO,
        "Argentina",
    ),
    Region(
        "gb.usext",
        "xkb:us:altgr-intl:eng",
        "Europe/London",
        "en-GB",
        KML.ISO,
        "UK (US extended keyboard)",
        ("GB with US extended keyboard"),
    ),
    Region(
        "bg",
        ["xkb:bg::bul", "xkb:bg:phonetic:bul"],
        "Europe/Sofia",
        ["bg", "tr", "en-US"],
        KML.ANSI,
        "Bulgaria",
    ),
    Region(
        "jp.us",
        ["xkb:us::eng", "ime:jp:mozc_us"],
        "Asia/Tokyo",
        "ja",
        KML.ANSI,
        "Japan with US keyboard",
    ),
    Region(
        "is",
        "xkb:is::ice",
        "Atlantic/Reykjavik",
        ["is", "en-GB"],
        KML.ISO,
        "Iceland",
    ),
    Region(
        "us.intl",
        "xkb:us:intl:eng",
        "America/Los_Angeles",
        "en-US",
        KML.ANSI,
        "US (English Intl)",
    ),
    Region(
        "co", "xkb:latam::spa", "America/Bogota", "es-CO", KML.ANSI, "Colombia"
    ),
    Region(
        "hr",
        "xkb:hr::scr",
        "Europe/Zagreb",
        ["hr", "en-GB"],
        KML.ISO,
        "Croatia",
    ),
    Region(
        "kz",
        ["xkb:us::eng", "xkb:kz::kaz", "xkb:ru::rus"],
        ["Asia/Almaty", "Asia/Aqtobe"],
        ["kk", "ru"],
        KML.ANSI,
        "Kazakhstan",
    ),
    Region(
        "ee",
        "xkb:ee::est",
        "Europe/Tallinn",
        ["et", "ru", "en-GB"],
        KML.ISO,
        "Estonia",
    ),
    Region(
        "ro.us",
        ["xkb:us::eng", "xkb:ro::rum"],
        "Europe/Bucharest",
        ["ro", "hu", "de", "en-GB"],
        KML.ANSI,
        "Romania with US keyboard",
    ),
    Region(
        "ua",
        ["xkb:us::eng", "xkb:ua::ukr"],
        ["Europe/Kiev"],
        # "uk" is Ukraine, not United Kingdom.
        ["uk", "en-US"],
        KML.ANSI,
        "Ukraine",
    ),
    Region(
        "ro.usintl",
        ["xkb:us:intl:eng"],
        ["Europe/Bucharest"],
        ["ro", "hu", "de", "en-GB"],
        KML.ANSI,
        "Romania with US International keyboard layout",
    ),
    Region(
        "in.hybrid",
        ["xkb:in::eng", "xkb:us::eng"],
        "Asia/Calcutta",
        ["en-IN", "en-US"],
        KML.ANSI,
        "India with Indian keyboard"
    ),
]

"""A list of :py:class:`regions.Region` objects for
all **confirmed** regions.  A confirmed region is a region whose
properties are known to be correct and valid: all contents (locale / timezone /
keyboards) are supported by Chrome.

NOTE: This list is NOT alpha-sorted. New entries MUST be appended to the end of
the list to retain relative order of existing entries. For backward
compatibility, legacy entries need to stay in the same order because they used
to have numeric mappings.
"""


UNCONFIRMED_REGIONS_LIST = [
    Region(
        "bd",
        "xkb:bd::ben",
        "Asia/Dhaka",
        ["bn-BD", "en"],
        KML.ANSI,
        "Bangladesh",
    ),
    Region(
        "bf",
        "xkb:bf::fra",
        "Africa/Ouagadougou",
        "fr-BF",
        KML.ANSI,
        "Burkina Faso",
    ),
    Region(
        "ba",
        "xkb:ba::bos",
        "Europe/Sarajevo",
        "bs",
        KML.ANSI,
        "Bosnia and Herzegovina",
    ),
    Region(
        "bb", "xkb:bb::eng", "America/Barbados", "en-BB", KML.ANSI, "Barbados"
    ),
    Region(
        "wf",
        "xkb:us::eng",
        "Pacific/Wallis",
        ["wls", "fud"],
        KML.ANSI,
        "Wallis and Futuna",
    ),
    Region(
        "bl",
        "xkb:bl::fra",
        "America/St_Barthelemy",
        "fr",
        KML.ANSI,
        "Saint Barthelemy",
    ),
    Region(
        "bm",
        "xkb:bm::eng",
        "Atlantic/Bermuda",
        ["en-BM", "pt"],
        KML.ANSI,
        "Bermuda",
    ),
    Region(
        "bn",
        "xkb:bn::msa",
        "Asia/Brunei",
        ["ms-BN", "en-BN"],
        KML.ANSI,
        "Brunei",
    ),
    Region(
        "bo",
        "xkb:latam::spa",
        "America/La_Paz",
        ["es-419", "qu"],
        KML.ANSI,
        "Bolivia",
    ),
    Region(
        "bh",
        "xkb:bh::ara",
        "Asia/Bahrain",
        ["ar", "en", "fa", "ru"],
        KML.ANSI,
        "Bahrain",
    ),
    Region(
        "bi",
        "xkb:bi::fra",
        "Africa/Bujumbura",
        ["fr-BI", "rn"],
        KML.ANSI,
        "Burundi",
    ),
    Region(
        "bj", "xkb:bj::fra", "Africa/Porto-Novo", "fr-BJ", KML.ANSI, "Benin"
    ),
    Region("bt", "xkb:bt::dzo", "Asia/Thimphu", "dz", KML.ANSI, "Bhutan"),
    Region(
        "jm", "xkb:jm::eng", "America/Jamaica", "en-JM", KML.ANSI, "Jamaica"
    ),
    Region(
        "bw",
        "xkb:bw::eng",
        "Africa/Gaborone",
        ["en-BW", "tn-BW"],
        KML.ANSI,
        "Botswana",
    ),
    Region(
        "ws", "xkb:ws::smo", "Pacific/Apia", ["sm", "en-WS"], KML.ANSI, "Samoa"
    ),
    Region(
        "bq",
        "xkb:bq::nld",
        "America/Kralendijk",
        ["nl", "en"],
        KML.ANSI,
        "Bonaire, Saint Eustatius and Saba ",
    ),
    Region("bs", "xkb:bs::eng", "America/Nassau", "en-BS", KML.ANSI, "Bahamas"),
    Region(
        "je", "xkb:je::eng", "Europe/Jersey", ["en", "pt"], KML.ANSI, "Jersey"
    ),
    Region(
        "by", "xkb:by::bel", "Europe/Minsk", ["be", "ru"], KML.ANSI, "Belarus"
    ),
    Region(
        "bz",
        "xkb:bz::eng",
        "America/Belize",
        ["en-BZ", "es"],
        KML.ANSI,
        "Belize",
    ),
    Region(
        "rw",
        "xkb:rw::kin",
        "Africa/Kigali",
        ["rw", "en-RW"],
        KML.ANSI,
        "Rwanda",
    ),
    Region(
        "rs",
        "xkb:rs::srp",
        "Europe/Belgrade",
        ["sr", "hu", "bs"],
        KML.ANSI,
        "Serbia",
    ),
    Region(
        "tl",
        "xkb:us::eng",
        "Asia/Dili",
        ["tet", "pt-TL", "en"],
        KML.ANSI,
        "East Timor",
    ),
    Region("re", "xkb:re::fra", "Indian/Reunion", "fr-RE", KML.ANSI, "Reunion"),
    Region(
        "tm",
        "xkb:tm::tuk",
        "Asia/Ashgabat",
        ["tk", "ru", "uz"],
        KML.ANSI,
        "Turkmenistan",
    ),
    Region(
        "tj",
        "xkb:tj::tgk",
        "Asia/Dushanbe",
        ["tg", "ru"],
        KML.ANSI,
        "Tajikistan",
    ),
    Region(
        "tk",
        "xkb:us::eng",
        "Pacific/Fakaofo",
        ["tkl", "en-TK"],
        KML.ANSI,
        "Tokelau",
    ),
    Region(
        "gw",
        "xkb:gw::por",
        "Africa/Bissau",
        ["pt-GW", "pov"],
        KML.ANSI,
        "Guinea-Bissau",
    ),
    Region(
        "gu",
        "xkb:gu::eng",
        "Pacific/Guam",
        ["en-GU", "ch-GU"],
        KML.ANSI,
        "Guam",
    ),
    Region(
        "gt",
        "xkb:latam::spa",
        "America/Guatemala",
        "es-419",
        KML.ANSI,
        "Guatemala",
    ),
    Region(
        "gs",
        "xkb:gs::eng",
        "Atlantic/South_Georgia",
        "en",
        KML.ANSI,
        "South Georgia and the South Sandwich Islands",
    ),
    Region(
        "gq",
        "xkb:gq::spa",
        "Africa/Malabo",
        ["es-419", "fr"],
        KML.ANSI,
        "Equatorial Guinea",
    ),
    Region(
        "gp",
        "xkb:gp::fra",
        "America/Guadeloupe",
        "fr-GP",
        KML.ANSI,
        "Guadeloupe",
    ),
    Region("gy", "xkb:gy::eng", "America/Guyana", "en-GY", KML.ANSI, "Guyana"),
    Region(
        "gg",
        "xkb:gg::eng",
        "Europe/Guernsey",
        ["en", "fr"],
        KML.ANSI,
        "Guernsey",
    ),
    Region(
        "gf",
        "xkb:gf::fra",
        "America/Cayenne",
        "fr-GF",
        KML.ANSI,
        "French Guiana",
    ),
    Region("ge", "xkb:ge::geo", "Asia/Tbilisi", "ka", KML.ANSI, "Georgia"),
    Region(
        "gd", "xkb:gd::eng", "America/Grenada", "en-GD", KML.ANSI, "Grenada"
    ),
    Region(
        "ga", "xkb:ga::fra", "Africa/Libreville", "fr-GA", KML.ANSI, "Gabon"
    ),
    Region(
        "sv",
        "xkb:latam::spa",
        "America/El_Salvador",
        "es-419",
        KML.ANSI,
        "El Salvador",
    ),
    Region("gn", "xkb:gn::fra", "Africa/Conakry", "fr-GN", KML.ANSI, "Guinea"),
    Region(
        "gm",
        "xkb:gm::eng",
        "Africa/Banjul",
        ["en-GM", "mnk", "wof"],
        KML.ANSI,
        "Gambia",
    ),
    Region(
        "gl",
        "xkb:gl::kal",
        [
            "America/Godthab",
            "America/Danmarkshavn",
            "America/Scoresbysund",
            "America/Thule",
        ],
        ["kl", "da-GL", "en"],
        KML.ANSI,
        "Greenland",
    ),
    Region(
        "gi",
        "xkb:gi::eng",
        "Europe/Gibraltar",
        ["en-GI", "es"],
        KML.ANSI,
        "Gibraltar",
    ),
    Region(
        "gh",
        "xkb:gh::eng",
        "Africa/Accra",
        ["en-GH", "ak", "ee"],
        KML.ANSI,
        "Ghana",
    ),
    Region(
        "om",
        "xkb:om::ara",
        "Asia/Muscat",
        ["ar", "en", "bal"],
        KML.ANSI,
        "Oman",
    ),
    Region(
        "tn", "xkb:tn::ara", "Africa/Tunis", ["ar", "fr"], KML.ANSI, "Tunisia"
    ),
    Region("jo", "xkb:jo::ara", "Asia/Amman", ["ar", "en"], KML.ANSI, "Jordan"),
    Region(
        "hn",
        "xkb:latam::spa",
        "America/Tegucigalpa",
        "es-HN",
        KML.ANSI,
        "Honduras",
    ),
    Region(
        "ht", "xkb:ht::hat", "America/Port-au-Prince", ["ht"], KML.ANSI, "Haiti"
    ),
    Region(
        "hu",
        ["xkb:us::eng", "xkb:hu::hun"],
        "Europe/Budapest",
        ["hu", "en-GB"],
        KML.ISO,
        "Hungary",
    ),
    Region(
        "ve",
        "xkb:latam::spa",
        "America/Caracas",
        "es-419",
        KML.ANSI,
        "Venezuela",
    ),
    Region(
        "pr",
        "xkb:pr::eng",
        "America/Puerto_Rico",
        ["en-PR"],
        KML.ANSI,
        "Puerto Rico",
    ),
    Region(
        "ps",
        "xkb:ps::ara",
        ["Asia/Gaza", "Asia/Hebron"],
        "ar",
        KML.ANSI,
        "Palestinian Territory",
    ),
    Region(
        "pw",
        "xkb:us::eng",
        "Pacific/Palau",
        ["pau", "sov", "en-PW", "tox", "ja", "fil", "zh"],
        KML.ANSI,
        "Palau",
    ),
    Region(
        "sj",
        "xkb:sj::nor",
        "Arctic/Longyearbyen",
        ["no", "ru"],
        KML.ANSI,
        "Svalbard and Jan Mayen",
    ),
    Region(
        "py",
        "xkb:latam::spa",
        "America/Asuncion",
        ["es-419", "gn"],
        KML.ANSI,
        "Paraguay",
    ),
    Region(
        "iq",
        "xkb:iq::ara",
        "Asia/Baghdad",
        ["ar", "ku", "hy"],
        KML.ANSI,
        "Iraq",
    ),
    Region(
        "pa",
        "xkb:latam::spa",
        "America/Panama",
        ["es-419", "en"],
        KML.ANSI,
        "Panama",
    ),
    Region(
        "pf",
        "xkb:pf::fra",
        ["Pacific/Tahiti", "Pacific/Marquesas", "Pacific/Gambier"],
        ["fr-PF", "ty"],
        KML.ANSI,
        "French Polynesia",
    ),
    Region(
        "pg",
        "xkb:pg::eng",
        ["Pacific/Port_Moresby", "Pacific/Bougainville"],
        ["en-PG", "ho", "meu", "tpi"],
        KML.ANSI,
        "Papua New Guinea",
    ),
    Region(
        "pk",
        "xkb:pk::urd",
        "Asia/Karachi",
        ["ur-PK", "en-PK", "pa", "sd", "ps", "brh"],
        KML.ANSI,
        "Pakistan",
    ),
    Region(
        "pn", "xkb:pn::eng", "Pacific/Pitcairn", "en-PN", KML.ANSI, "Pitcairn"
    ),
    Region(
        "pm",
        "xkb:pm::fra",
        "America/Miquelon",
        "fr-PM",
        KML.ANSI,
        "Saint Pierre and Miquelon",
    ),
    Region(
        "zm",
        "xkb:zm::eng",
        "Africa/Lusaka",
        ["en-ZM", "bem", "loz", "lun", "lue", "ny", "toi"],
        KML.ANSI,
        "Zambia",
    ),
    Region(
        "eh",
        "xkb:eh::ara",
        "Africa/El_Aaiun",
        ["ar", "mey"],
        KML.ANSI,
        "Western Sahara",
    ),
    Region(
        "eg",
        "xkb:eg::ara",
        "Africa/Cairo",
        ["ar", "en", "fr"],
        KML.ANSI,
        "Egypt",
    ),
    Region(
        "ec",
        "xkb:latam::spa",
        ["America/Guayaquil"],
        "es-419",
        KML.ANSI,
        "Ecuador",
    ),
    Region(
        "sb",
        "xkb:sb::eng",
        "Pacific/Guadalcanal",
        ["en-SB", "tpi"],
        KML.ANSI,
        "Solomon Islands",
    ),
    Region(
        "et",
        "xkb:et::amh",
        "Africa/Addis_Ababa",
        ["am", "en-ET", "om-ET", "ti-ET"],
        KML.ANSI,
        "Ethiopia",
    ),
    Region(
        "so",
        "xkb:so::som",
        "Africa/Mogadishu",
        ["so-SO", "ar"],
        KML.ANSI,
        "Somalia",
    ),
    Region(
        "zw",
        "xkb:zw::eng",
        "Africa/Harare",
        ["en-ZW", "sn", "nr"],
        KML.ANSI,
        "Zimbabwe",
    ),
    Region(
        "er",
        "xkb:er::aar",
        "Africa/Asmara",
        ["aa-ER", "ar", "tig", "kun", "ti-ER"],
        KML.ANSI,
        "Eritrea",
    ),
    Region(
        "me",
        "xkb:me::srp",
        "Europe/Podgorica",
        ["sr", "hu", "bs", "sq", "hr", "rom"],
        KML.ANSI,
        "Montenegro",
    ),
    Region(
        "md",
        "xkb:md::ron",
        "Europe/Chisinau",
        ["ro", "ru", "gag"],
        KML.ANSI,
        "Moldova",
    ),
    Region(
        "mg",
        "xkb:mg::fra",
        "Indian/Antananarivo",
        ["fr-MG", "mg"],
        KML.ANSI,
        "Madagascar",
    ),
    Region(
        "mf", "xkb:mf::fra", "America/Marigot", "fr", KML.ANSI, "Saint Martin"
    ),
    Region(
        "ma",
        "xkb:ma::ara",
        "Africa/Casablanca",
        ["ar", "fr"],
        KML.ANSI,
        "Morocco",
    ),
    Region(
        "mc",
        "xkb:mc::fra",
        "Europe/Monaco",
        ["fr-MC", "en", "it"],
        KML.ANSI,
        "Monaco",
    ),
    Region(
        "uz",
        "xkb:uz::uzb",
        ["Asia/Samarkand", "Asia/Tashkent"],
        ["uz", "ru", "tg"],
        KML.ANSI,
        "Uzbekistan",
    ),
    Region(
        "mm", "xkb:mm::mya", "Asia/Rangoon", "my", KML.ANSI, "Myanmar", None
    ),
    Region(
        "ml", "xkb:ml::fra", "Africa/Bamako", ["fr-ML", "bm"], KML.ANSI, "Mali"
    ),
    Region(
        "mo",
        "xkb:mo::zho",
        "Asia/Macau",
        ["zh", "zh-MO", "pt"],
        KML.ANSI,
        "Macao",
    ),
    Region(
        "mn",
        "xkb:mn::mon",
        ["Asia/Ulaanbaatar", "Asia/Hovd", "Asia/Choibalsan"],
        ["mn", "ru"],
        KML.ANSI,
        "Mongolia",
    ),
    Region(
        "mh",
        "xkb:mh::mah",
        ["Pacific/Majuro"],
        ["mh", "en-MH"],
        KML.ANSI,
        "Marshall Islands",
    ),
    Region(
        "mk",
        "xkb:mk::mkd",
        "Europe/Skopje",
        ["mk", "sq", "tr"],
        KML.ANSI,
        "Macedonia",
    ),
    Region(
        "mu",
        "xkb:mu::eng",
        "Indian/Mauritius",
        ["en-MU", "bho"],
        KML.ANSI,
        "Mauritius",
    ),
    Region(
        "mt", ["xkb:us::eng"], "Europe/Malta", ["mt", "en-GB"], KML.ISO, "Malta"
    ),
    Region(
        "mw",
        "xkb:mw::nya",
        "Africa/Blantyre",
        ["ny", "yao", "tum"],
        KML.ANSI,
        "Malawi",
    ),
    Region(
        "mv",
        "xkb:mv::div",
        "Indian/Maldives",
        ["dv", "en"],
        KML.ANSI,
        "Maldives",
    ),
    Region(
        "mq",
        "xkb:mq::fra",
        "America/Martinique",
        "fr-MQ",
        KML.ANSI,
        "Martinique",
    ),
    Region(
        "mp",
        "xkb:us::eng",
        "Pacific/Saipan",
        ["fil", "tl", "zh", "ch-MP", "en-MP"],
        KML.ANSI,
        "Northern Mariana Islands",
    ),
    Region(
        "ms",
        "xkb:ms::eng",
        "America/Montserrat",
        "en-MS",
        KML.ANSI,
        "Montserrat",
    ),
    Region(
        "mr",
        "xkb:mr::ara",
        "Africa/Nouakchott",
        ["ar", "fuc", "snk", "fr", "mey", "wo"],
        KML.ANSI,
        "Mauritania",
    ),
    Region(
        "im",
        "xkb:im::eng",
        "Europe/Isle_of_Man",
        ["en", "gv"],
        KML.ANSI,
        "Isle of Man",
    ),
    Region(
        "ug",
        "xkb:ug::eng",
        "Africa/Kampala",
        ["en-UG", "lg", "ar"],
        KML.ANSI,
        "Uganda",
    ),
    Region(
        "tz",
        "xkb:tz::swa",
        "Africa/Dar_es_Salaam",
        ["sw-TZ", "en"],
        KML.ANSI,
        "Tanzania",
    ),
    Region(
        "io",
        "xkb:io::eng",
        "Indian/Chagos",
        "en-IO",
        KML.ANSI,
        "British Indian Ocean Territory",
    ),
    Region(
        "sh",
        "xkb:sh::eng",
        "Atlantic/St_Helena",
        "en-SH",
        KML.ANSI,
        "Saint Helena",
    ),
    Region(
        "fj", "xkb:fj::eng", "Pacific/Fiji", ["en-FJ", "fj"], KML.ANSI, "Fiji"
    ),
    Region(
        "fk",
        "xkb:fk::eng",
        "Atlantic/Stanley",
        "en-FK",
        KML.ANSI,
        "Falkland Islands",
    ),
    Region(
        "fm",
        "xkb:fm::eng",
        ["Pacific/Chuuk", "Pacific/Pohnpei", "Pacific/Kosrae"],
        ["en-FM", "chk", "pon", "yap", "kos", "uli", "woe", "nkr", "kpg"],
        KML.ANSI,
        "Micronesia",
    ),
    Region(
        "fo",
        "xkb:fo::fao",
        "Atlantic/Faroe",
        ["fo", "da-FO"],
        KML.ANSI,
        "Faroe Islands",
    ),
    Region(
        "ni",
        "xkb:latam::spa",
        "America/Managua",
        ["es-419", "en"],
        KML.ANSI,
        "Nicaragua",
    ),
    Region(
        "no",
        "xkb:no::nor",
        "Europe/Oslo",
        ["no", "nb", "nn", "se"],
        KML.ISO,
        "Norway",
    ),
    Region(
        "na",
        "xkb:na::eng",
        "Africa/Windhoek",
        ["en-NA", "af", "de", "hz", "naq"],
        KML.ANSI,
        "Namibia",
    ),
    Region(
        "vu",
        "xkb:vu::bis",
        "Pacific/Efate",
        ["bi", "en-VU"],
        KML.ANSI,
        "Vanuatu",
    ),
    Region(
        "nc",
        "xkb:nc::fra",
        "Pacific/Noumea",
        "fr-NC",
        KML.ANSI,
        "New Caledonia",
    ),
    Region(
        "ne",
        "xkb:ne::fra",
        "Africa/Niamey",
        ["fr-NE", "ha", "kr"],
        KML.ANSI,
        "Niger",
    ),
    Region(
        "nf",
        "xkb:nf::eng",
        "Pacific/Norfolk",
        "en-NF",
        KML.ANSI,
        "Norfolk Island",
    ),
    Region(
        "np", "xkb:np::nep", "Asia/Kathmandu", ["ne", "en"], KML.ANSI, "Nepal"
    ),
    Region(
        "nr", "xkb:nr::nau", "Pacific/Nauru", ["na", "en-NR"], KML.ANSI, "Nauru"
    ),
    Region(
        "nu", "xkb:us::eng", "Pacific/Niue", ["niu", "en-NU"], KML.ANSI, "Niue"
    ),
    Region(
        "ck",
        "xkb:ck::eng",
        "Pacific/Rarotonga",
        ["en-CK", "mi"],
        KML.ANSI,
        "Cook Islands",
    ),
    Region(
        "ci", "xkb:ci::fra", "Africa/Abidjan", "fr-CI", KML.ANSI, "Ivory Coast"
    ),
    Region("cn", "xkb:us::eng", "Asia/Shanghai", "zh-CN", KML.ANSI, "China"),
    Region(
        "cm",
        "xkb:cm::eng",
        "Africa/Douala",
        ["en-CM", "fr-CM"],
        KML.ANSI,
        "Cameroon",
    ),
    Region(
        "cc",
        "xkb:cc::msa",
        "Indian/Cocos",
        ["ms-CC", "en"],
        KML.ANSI,
        "Cocos Islands",
    ),
    Region(
        "cg",
        "xkb:cg::fra",
        "Africa/Brazzaville",
        ["fr-CG", "kg"],
        KML.ANSI,
        "Republic of the Congo",
    ),
    Region(
        "cf",
        "xkb:cf::fra",
        "Africa/Bangui",
        ["fr-CF", "sg", "ln"],
        KML.ANSI,
        "Central African Republic",
    ),
    Region(
        "cd",
        "xkb:cd::fra",
        ["Africa/Kinshasa", "Africa/Lubumbashi"],
        ["fr-CD", "ln", "kg"],
        KML.ANSI,
        "Democratic Republic of the Congo",
    ),
    Region(
        "cy",
        "xkb:cy::ell",
        "Asia/Nicosia",
        ["el-CY", "tr-CY"],
        KML.ANSI,
        "Cyprus",
    ),
    Region(
        "cx",
        "xkb:cx::eng",
        "Indian/Christmas",
        ["en", "zh"],
        KML.ANSI,
        "Christmas Island",
    ),
    Region(
        "cr",
        "xkb:latam::spa",
        "America/Costa_Rica",
        ["es-419"],
        KML.ANSI,
        "Costa Rica",
    ),
    Region("cw", "xkb:cw::nld", "America/Curacao", ["nl"], KML.ANSI, "Curacao"),
    Region(
        "cv",
        "xkb:cv::por",
        "Atlantic/Cape_Verde",
        "pt-CV",
        KML.ANSI,
        "Cape Verde",
    ),
    Region(
        "cu", "xkb:latam::spa", "America/Havana", "es-419", KML.ANSI, "Cuba"
    ),
    Region(
        "sz",
        "xkb:sz::eng",
        "Africa/Mbabane",
        ["en-SZ", "ss-SZ"],
        KML.ANSI,
        "Swaziland",
    ),
    Region(
        "sy",
        "xkb:sy::ara",
        "Asia/Damascus",
        ["ar", "ku", "hy", "arc", "fr", "en"],
        KML.ANSI,
        "Syria",
    ),
    Region(
        "sx",
        "xkb:sx::nld",
        "America/Lower_Princes",
        ["nl", "en"],
        KML.ANSI,
        "Sint Maarten",
    ),
    Region(
        "kg",
        "xkb:kg::kir",
        "Asia/Bishkek",
        ["ky", "uz", "ru"],
        KML.ANSI,
        "Kyrgyzstan",
    ),
    Region(
        "ke",
        "xkb:ke::eng",
        "Africa/Nairobi",
        ["en-KE", "sw-KE"],
        KML.ANSI,
        "Kenya",
    ),
    Region("ss", "xkb:ss::eng", "Africa/Juba", "en", KML.ANSI, "South Sudan"),
    Region(
        "sr",
        "xkb:sr::nld",
        "America/Paramaribo",
        ["nl-SR", "en", "srn", "hns", "jv"],
        KML.ANSI,
        "Suriname",
    ),
    Region(
        "ki",
        "xkb:ki::eng",
        ["Pacific/Tarawa", "Pacific/Enderbury", "Pacific/Kiritimati"],
        ["en-KI", "gil"],
        KML.ANSI,
        "Kiribati",
    ),
    Region(
        "kh",
        "xkb:kh::khm",
        "Asia/Phnom_Penh",
        ["km", "fr", "en"],
        KML.ANSI,
        "Cambodia",
    ),
    Region(
        "kn",
        "xkb:kn::eng",
        "America/St_Kitts",
        "en-KN",
        KML.ANSI,
        "Saint Kitts and Nevis",
    ),
    Region(
        "km",
        "xkb:km::ara",
        "Indian/Comoro",
        ["ar", "fr-KM"],
        KML.ANSI,
        "Comoros",
    ),
    Region(
        "st",
        "xkb:st::por",
        "Africa/Sao_Tome",
        "pt-ST",
        KML.ANSI,
        "Sao Tome and Principe",
    ),
    Region(
        "si",
        "xkb:si::slv",
        "Europe/Ljubljana",
        ["sl", "hu", "it", "sr", "de", "hr", "en-GB"],
        KML.ISO,
        "Slovenia",
    ),
    Region(
        "kp", "xkb:kp::kor", "Asia/Pyongyang", "ko-KP", KML.ANSI, "North Korea"
    ),
    Region(
        "sn",
        "xkb:sn::fra",
        "Africa/Dakar",
        ["fr-SN", "wo", "fuc"],
        KML.ANSI,
        "Senegal",
    ),
    Region(
        "sm",
        "xkb:sm::ita",
        "Europe/San_Marino",
        "it-SM",
        KML.ANSI,
        "San Marino",
    ),
    Region(
        "sl",
        "xkb:sl::eng",
        "Africa/Freetown",
        ["en-SL", "men"],
        KML.ANSI,
        "Sierra Leone",
    ),
    Region(
        "sc",
        "xkb:sc::eng",
        "Indian/Mahe",
        ["en-SC", "fr-SC"],
        KML.ANSI,
        "Seychelles",
    ),
    Region(
        "ky",
        "xkb:ky::eng",
        "America/Cayman",
        "en-KY",
        KML.ANSI,
        "Cayman Islands",
    ),
    Region(
        "sd",
        "xkb:sd::ara",
        "Africa/Khartoum",
        ["ar", "en", "fia"],
        KML.ANSI,
        "Sudan",
    ),
    Region(
        "do",
        "xkb:latam::spa",
        "America/Santo_Domingo",
        "es-419",
        KML.ANSI,
        "Dominican Republic",
    ),
    Region(
        "dm", "xkb:dm::eng", "America/Dominica", "en-DM", KML.ANSI, "Dominica"
    ),
    Region(
        "dj",
        "xkb:dj::fra",
        "Africa/Djibouti",
        ["fr-DJ", "ar"],
        KML.ANSI,
        "Djibouti",
    ),
    Region(
        "dk",
        "xkb:dk::dan",
        "Europe/Copenhagen",
        ["da-DK", "en", "fo", "de-DK"],
        KML.ISO,
        "Denmark",
    ),
    Region(
        "vg",
        "xkb:vg::eng",
        "America/Tortola",
        "en-VG",
        KML.ANSI,
        "British Virgin Islands",
    ),
    Region("ye", "xkb:ye::ara", "Asia/Aden", "ar", KML.ANSI, "Yemen"),
    Region("dz", "xkb:dz::ara", "Africa/Algiers", "ar", KML.ANSI, "Algeria"),
    Region("yt", "xkb:yt::fra", "Indian/Mayotte", "fr-YT", KML.ANSI, "Mayotte"),
    Region(
        "um",
        "xkb:um::eng",
        ["Pacific/Johnston", "Pacific/Midway", "Pacific/Wake"],
        "en-UM",
        KML.ANSI,
        "United States Minor Outlying Islands",
    ),
    Region(
        "lb",
        "xkb:lb::ara",
        "Asia/Beirut",
        ["ar", "fr-LB", "en"],
        KML.ANSI,
        "Lebanon",
    ),
    Region(
        "lc",
        "xkb:lc::eng",
        "America/St_Lucia",
        "en-LC",
        KML.ANSI,
        "Saint Lucia",
    ),
    Region(
        "la",
        "xkb:la::lao",
        "Asia/Vientiane",
        ["lo", "fr", "en"],
        KML.ANSI,
        "Laos",
    ),
    Region(
        "tv",
        "xkb:us::eng",
        "Pacific/Funafuti",
        ["tvl", "en", "sm"],
        KML.ANSI,
        "Tuvalu",
    ),
    Region(
        "tt",
        "xkb:tt::eng",
        "America/Port_of_Spain",
        ["en-TT", "hns", "fr", "es", "zh"],
        KML.ANSI,
        "Trinidad and Tobago",
    ),
    Region(
        "lk",
        "xkb:lk::sin",
        "Asia/Colombo",
        ["si", "ta", "en"],
        KML.ANSI,
        "Sri Lanka",
    ),
    Region(
        "li",
        "xkb:ch::ger",
        "Europe/Vaduz",
        ["de", "en-GB"],
        KML.ISO,
        "Liechtenstein",
    ),
    Region(
        "lv",
        "xkb:lv:apostrophe:lav",
        "Europe/Riga",
        ["lv", "lt", "ru", "en-GB"],
        KML.ISO,
        "Latvia",
    ),
    Region(
        "to",
        "xkb:to::ton",
        "Pacific/Tongatapu",
        ["to", "en-TO"],
        KML.ANSI,
        "Tonga",
    ),
    Region(
        "lt",
        "xkb:lt::lit",
        "Europe/Vilnius",
        ["lt", "ru", "pl"],
        KML.ISO,
        "Lithuania",
    ),
    Region(
        "lu",
        "xkb:lu::ltz",
        "Europe/Luxembourg",
        ["lb", "de-LU"],
        KML.ANSI,
        "Luxembourg",
    ),
    Region(
        "lr", "xkb:lr::eng", "Africa/Monrovia", "en-LR", KML.ANSI, "Liberia"
    ),
    Region(
        "ls",
        "xkb:ls::eng",
        "Africa/Maseru",
        ["en-LS", "st", "zu"],
        KML.ANSI,
        "Lesotho",
    ),
    Region(
        "tf",
        "xkb:tf::fra",
        "Indian/Kerguelen",
        "fr",
        KML.ANSI,
        "French Southern Territories",
    ),
    Region(
        "tg",
        "xkb:tg::fra",
        "Africa/Lome",
        ["fr-TG", "ee", "hna"],
        KML.ANSI,
        "Togo",
    ),
    Region(
        "td",
        "xkb:td::fra",
        "Africa/Ndjamena",
        ["fr-TD", "ar"],
        KML.ANSI,
        "Chad",
    ),
    Region(
        "tc",
        "xkb:tc::eng",
        "America/Grand_Turk",
        "en-TC",
        KML.ANSI,
        "Turks and Caicos Islands",
    ),
    Region(
        "ly",
        "xkb:ly::ara",
        "Africa/Tripoli",
        ["ar", "it", "en"],
        KML.ANSI,
        "Libya",
    ),
    Region(
        "va",
        "xkb:va::lat",
        "Europe/Vatican",
        ["la", "it", "fr"],
        KML.ANSI,
        "Vatican",
    ),
    Region(
        "vc",
        "xkb:vc::eng",
        "America/St_Vincent",
        ["en-VC", "fr"],
        KML.ANSI,
        "Saint Vincent and the Grenadines",
    ),
    Region("ad", "xkb:ad::cat", "Europe/Andorra", "ca", KML.ANSI, "Andorra"),
    Region(
        "ag",
        "xkb:ag::eng",
        "America/Antigua",
        "en-AG",
        KML.ANSI,
        "Antigua and Barbuda",
    ),
    Region(
        "af",
        "xkb:af::fas",
        "Asia/Kabul",
        ["fa-AF", "ps"],
        KML.ANSI,
        "Afghanistan",
    ),
    Region(
        "ai", "xkb:ai::eng", "America/Anguilla", "en-AI", KML.ANSI, "Anguilla"
    ),
    Region(
        "vi",
        "xkb:vi::eng",
        "America/St_Thomas",
        "en-VI",
        KML.ANSI,
        "U.S. Virgin Islands",
    ),
    Region(
        "ir", "xkb:ir::fas", "Asia/Tehran", ["fa-IR", "ku"], KML.ANSI, "Iran"
    ),
    Region("am", "xkb:am::hye", "Asia/Yerevan", "hy", KML.ANSI, "Armenia"),
    Region(
        "al", "xkb:al::sqi", "Europe/Tirane", ["sq", "el"], KML.ANSI, "Albania"
    ),
    Region("ao", "xkb:ao::por", "Africa/Luanda", "pt-AO", KML.ANSI, "Angola"),
    Region(
        "as",
        "xkb:as::eng",
        "Pacific/Pago_Pago",
        ["en-AS", "sm"],
        KML.ANSI,
        "American Samoa",
    ),
    Region(
        "aw",
        "xkb:aw::nld",
        "America/Aruba",
        ["nl-AW", "es", "en"],
        KML.ANSI,
        "Aruba",
    ),
    Region(
        "ax",
        "xkb:ax::swe",
        "Europe/Mariehamn",
        "sv-AX",
        KML.ANSI,
        "Aland Islands",
    ),
    Region(
        "az",
        "xkb:az::aze",
        "Asia/Baku",
        ["az", "ru", "hy"],
        KML.ANSI,
        "Azerbaijan",
    ),
    Region(
        "qa", "xkb:qa::ara", "Asia/Bahrain", ["ar", "en"], KML.ANSI, "Qatar"
    ),
    Region(
        "mz",
        "xkb:mz::por",
        "Africa/Maputo",
        ["pt-MZ", "vmw"],
        KML.ANSI,
        "Mozambique",
    ),
]
"""A list of :py:class:`regions.Region` objects for
**unconfirmed** regions. These may contain incorrect information (or not
supported by Chrome browser yet), and all fields must be reviewed before launch.
See http://goto/vpdsettings.

Currently, non-Latin keyboards must use an underlying Latin keyboard
for VPD. (This assumption should be revisited when moving items to
:py:data:`regions.Region.REGIONS_LIST`.)  This is
currently being discussed on <http://crbug.com/325389>.

Some timezones or locales may be missing from ``timezone_settings.cc`` (see
http://crosbug.com/p/23902).  This must be rectified before moving
items to :py:data:`regions.Region.REGIONS_LIST`.
"""


def ConsolidateRegions(regions):
    """Consolidates a list of regions into a dict.

    Args:
      regions: A list of Region objects.  All objects for any given
        region code must be identical or we will throw an exception.
        (We allow duplicates in case identical region objects are
        defined in both regions.py and the overlay, e.g., when moving
        items to the public overlay.)

    Returns:
      A dict from region code to Region.

    Raises:
      RegionException: If there are multiple regions defined for a given
        region, and the values for those regions differ.
    """
    # Build a dict from region_code to the first Region with that code.
    region_dict = {}
    for r in regions:
        existing_region = region_dict.get(r.region_code)
        if existing_region:
            if existing_region.GetFieldsDict() != r.GetFieldsDict():
                raise RegionException(
                    "Conflicting definitions for region %r: %r, %r"
                    % (
                        r.region_code,
                        existing_region.GetFieldsDict(),
                        r.GetFieldsDict(),
                    )
                )
        else:
            region_dict[r.region_code] = r

    return region_dict


def BuildRegionsDict(include_all=False, include_pseudolocales=False):
    """Builds a dictionary mapping from code to :py:class:`regions.Region` object.

    ``include_pseudolocales`` should never be true for production builds.

    The regions include:

    * :py:data:`regions.REGIONS_LIST`
    * :py:data:`regions_overlay.REGIONS_LIST`
    * Only if ``include_all`` is true:
      * :py:data:`regions.UNCONFIRMED_REGIONS_LIST`
      * :py:data:`regions.INCOMPLETE_REGIONS_LIST`
    * Only if ``include_pseudolocales`` is true:
      * :py:data:`regions.PSEUDOLOCALE_REGIONS_LIST`

    A region may only appear in one of the above lists, or this function
    will (deliberately) fail.
    """
    regions = list(REGIONS_LIST)
    if include_all:
        known_codes = [r.region_code for r in regions]
        regions += [
            r
            for r in UNCONFIRMED_REGIONS_LIST
            if r.region_code not in known_codes
        ]
    if include_pseudolocales:
        regions += PSEUDOLOCALE_REGIONS_LIST

    # Build dictionary of region code to list of regions with that
    # region code.  Check manually for duplicates, since the region may
    # be present both in the overlay and the public repo.
    return ConsolidateRegions(regions)


REGIONS = BuildRegionsDict()


def main(args=None, out=None):
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=("Display all known regions and their parameters. ")
    )
    parser.add_argument(
        "--format",
        choices=("human-readable", "csv", "json", "yaml"),
        default="human-readable",
        help="Output format (default=%(default)s)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Include unconfirmed and incomplete regions",
    )
    parser.add_argument(
        "--notes", action="store_true", help="Include notes in output"
    )
    parser.add_argument(
        "--include_pseudolocales",
        action="store_true",
        help="Include pseudolocales in output",
    )
    parser.add_argument("--output", default=None, help="Specify output file")
    parser.add_argument(
        "--overlay",
        default=None,
        help="Specify a Python file to overlay extra data",
    )
    args = parser.parse_args(args)

    if args.overlay is not None:
        with open(args.overlay) as f:
            exec(f.read())  # pylint: disable=exec-used

    if args.all:
        # Add an additional 'confirmed' property to help identifying region status,
        # for autotests, unit tests and factory module.
        Region.FIELDS.insert(1, "confirmed")
        for r in REGIONS_LIST:
            r.confirmed = True
        for r in UNCONFIRMED_REGIONS_LIST:
            r.confirmed = False

    regions_dict = BuildRegionsDict(args.all, args.include_pseudolocales)

    if out is None:
        if args.output is None:
            out = sys.stdout
        else:
            out = open(args.output, "w")  # pylint: disable=consider-using-with

    if args.notes or args.format == "csv":
        Region.FIELDS += ["notes"]

    # Handle YAML and JSON output.
    if args.format == "yaml" or args.format == "json":
        data = {}
        for region in regions_dict.values():
            item = {}
            for field in Region.FIELDS:
                item[field] = getattr(region, field)
            data[region.region_code] = item
        if args.format == "yaml":
            yaml.dump(data, out)
        else:
            json.dump(data, out)
        return

    # Handle CSV or plain-text output: build a list of lines to print.
    lines = [Region.FIELDS]

    def CoerceToString(value):
        """Returns the arguments in simple string type.

        If value is a list, concatenate its values with commas.  Otherwise, just
        return value.
        """
        if isinstance(value, list):
            return ",".join(value)
        else:
            return str(value)

    for region in sorted(regions_dict.values(), key=lambda v: v.region_code):
        lines.append(
            [CoerceToString(getattr(region, field)) for field in Region.FIELDS]
        )

    if args.format == "csv":
        # Just print the lines in CSV format. Note the values may
        # include ',' so the separator must be tab.
        for l in lines:
            print("\t".join(l))
    elif args.format == "human-readable":
        num_columns = len(lines[0])

        # Calculate maximum length of each column.
        max_lengths = []
        for column_no in range(num_columns):
            max_lengths.append(max(len(line[column_no]) for line in lines))

        # Print each line, padding as necessary to the max column length.
        for line in lines:
            for column_no in range(num_columns):
                out.write(line[column_no].ljust(max_lengths[column_no] + 2))
            out.write("\n")
    else:
        sys.exit("Sorry, unknown format specified: %s" % args.format)


if __name__ == "__main__":
    main()
