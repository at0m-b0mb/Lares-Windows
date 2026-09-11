"""Every text pairing in the interface, checked against WCAG AA in both themes.

This is not ceremony. Judging contrast by eye fails reliably for exactly the
colours this palette leans on - a deep brass looks fine on white until it is
measured, and muted greys on a warm ground are consistently worse than they
appear. A test is the only way to know, and it has to cover both themes because
a palette that works in light and fails in dark is the normal outcome.

AA is 4.5:1 for body text and 3:1 for large text (18pt, or 14pt bold). Where a
token is only ever used at display size, it is asserted against the large-text
threshold and the test says so.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PyQt6", reason="the desktop application's theme needs PyQt6")

from lares.gui import theme  # noqa: E402
from lares.gui.theme import Mode, Pair  # noqa: E402

AA_BODY = 4.5
AA_LARGE = 3.0

MODES = [Mode.LIGHT, Mode.DARK]


# --------------------------------------------------------------------------
# WCAG maths
# --------------------------------------------------------------------------

def _channel(value: int) -> float:
    v = value / 255
    return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    raw = hex_colour.lstrip("#")
    r, g, b = (int(raw[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast(fg: str, bg: str) -> float:
    a, b = luminance(fg), luminance(bg)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def test_contrast_maths_is_right():
    assert contrast("#000000", "#FFFFFF") == pytest.approx(21.0, abs=0.01)
    assert contrast("#FFFFFF", "#FFFFFF") == pytest.approx(1.0, abs=0.01)


# --------------------------------------------------------------------------
# Body text
# --------------------------------------------------------------------------

GROUNDS = [("paper", theme.PAPER), ("card", theme.CARD), ("card_alt", theme.CARD_ALT)]

BODY_TEXT = [
    ("ink", theme.INK),
    ("ink_soft", theme.INK_SOFT),
    ("muted", theme.MUTED),
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("ground_name,ground", GROUNDS)
@pytest.mark.parametrize("text_name,text", BODY_TEXT)
def test_body_text_meets_aa(mode, ground_name, ground, text_name, text):
    ratio = contrast(text.of(mode), ground.of(mode))
    assert ratio >= AA_BODY, (
        f"{text_name} on {ground_name} in {mode.value} is {ratio:.2f}:1, "
        f"below the {AA_BODY}:1 needed for body text"
    )


# --------------------------------------------------------------------------
# The accent
# --------------------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("ground_name,ground", GROUNDS + [("wash", theme.GOLD_WASH)])
def test_brass_is_readable_as_small_text(mode, ground_name, ground):
    """BRASS carries section headings and active nav, so it must pass body AA.

    This is the whole reason there are two gold tokens instead of one.
    """
    ratio = contrast(theme.BRASS.of(mode), ground.of(mode))
    assert ratio >= AA_BODY, (
        f"brass on {ground_name} in {mode.value} is {ratio:.2f}:1. "
        "Darken BRASS, or use SHINE for a mark that carries no words."
    )


@pytest.mark.parametrize("mode", MODES)
def test_primary_button_label_is_readable(mode):
    """White-on-brass is the one place a gold is used as a fill behind text."""
    ratio = contrast(theme.CARD.of(mode), theme.BRASS.of(mode))
    assert ratio >= AA_BODY, (
        f"the primary button label is {ratio:.2f}:1 in {mode.value}"
    )


@pytest.mark.parametrize("mode", MODES)
def test_shine_is_visible_as_a_mark(mode):
    """SHINE never carries text, so it only needs to be visible against the ground."""
    for name, ground in GROUNDS:
        ratio = contrast(theme.SHINE.of(mode), ground.of(mode))
        assert ratio >= AA_LARGE, (
            f"shine on {name} in {mode.value} is {ratio:.2f}:1 and will not be seen"
        )


# --------------------------------------------------------------------------
# Severity and outcome
# --------------------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", sorted(theme.SEVERITY))
def test_severity_colours_meet_aa_on_cards(mode, name):
    ratio = contrast(theme.SEVERITY[name].of(mode), theme.CARD.of(mode))
    assert ratio >= AA_BODY, f"severity '{name}' in {mode.value} is {ratio:.2f}:1"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", sorted(theme.STATUS))
def test_status_colours_meet_aa_on_cards(mode, name):
    ratio = contrast(theme.STATUS[name].of(mode), theme.CARD.of(mode))
    assert ratio >= AA_BODY, f"status '{name}' in {mode.value} is {ratio:.2f}:1"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", sorted(theme.RISK))
def test_risk_colours_meet_aa_on_cards(mode, name):
    ratio = contrast(theme.RISK[name].of(mode), theme.CARD.of(mode))
    assert ratio >= AA_BODY, f"risk '{name}' in {mode.value} is {ratio:.2f}:1"


@pytest.mark.parametrize("mode", MODES)
def test_severity_levels_are_distinguishable_from_each_other(mode):
    """Critical must not look like high at a glance."""
    critical = theme.CRITICAL.of(mode)
    high = theme.HIGH.of(mode)
    assert contrast(critical, high) >= 1.2, (
        f"critical and high are {contrast(critical, high):.2f}:1 apart in "
        f"{mode.value} and will read as the same colour"
    )


# --------------------------------------------------------------------------
# Structure
# --------------------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
def test_rules_are_visible_but_not_loud(mode):
    ratio = contrast(theme.RULE.of(mode), theme.CARD.of(mode))
    assert 1.08 <= ratio <= 3.0, (
        f"hairlines are {ratio:.2f}:1 in {mode.value}; they should be visible "
        "without drawing the eye"
    )


def test_dark_theme_is_true_black_and_carries_no_blue():
    """The dark theme was specified as true black, explicitly not navy."""
    assert theme.PAPER.dark == "#000000"

    for name in dir(theme):
        pair = getattr(theme, name)
        if not isinstance(pair, Pair) or name.startswith("_"):
            continue
        raw = pair.dark.lstrip("#")
        r, g, b = (int(raw[i:i + 2], 16) for i in (0, 2, 4))
        # A neutral or warm colour never has blue as its strongest channel by a
        # margin. This is what stops the dark theme drifting towards navy.
        assert b <= max(r, g) + 8, (
            f"{name} dark value {pair.dark} is blue-dominant; the dark theme is "
            "neutral and warm by specification"
        )


def test_every_colour_declares_both_themes():
    """The structural guarantee: there is nowhere to put a single value."""
    pairs = [(n, getattr(theme, n)) for n in dir(theme)
             if isinstance(getattr(theme, n), Pair)]
    assert len(pairs) >= 15
    for name, pair in pairs:
        assert pair.light.startswith("#") and len(pair.light) == 7, name
        assert pair.dark.startswith("#") and len(pair.dark) == 7, name
        assert pair.light != pair.dark, (
            f"{name} is the same in both themes, which is almost always a mistake"
        )


# --------------------------------------------------------------------------
# Rhythm
# --------------------------------------------------------------------------

def test_spacing_is_on_a_four_point_rhythm():
    assert theme.UNIT == 4
    for n in range(1, 13):
        assert theme.space(n) % 4 == 0


def test_stylesheet_builds_for_both_themes(qt_app):
    for mode in MODES:
        sheet = theme.stylesheet(mode)
        assert "QWidget" in sheet
        assert theme.PAPER.of(mode) in sheet
        # No colour may be hard-coded into the stylesheet outside the palette.
        assert "#F3F1EC" not in sheet or mode is Mode.LIGHT
