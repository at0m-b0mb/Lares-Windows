"""The banner, the icon, and the claim that they match the product.

tools/make_banner.py holds its colours as literals so it can draw without
starting Qt, and its docstring said a test asserted they still matched the real
theme. No such test existed. That is a small lie of exactly the kind this
project keeps telling other people not to tell, so here it is.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from lares.gui import theme

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"


@pytest.fixture(scope="module")
def banner_module(qt_app):
    """Import the generator. It needs PIL, which is a dev-only dependency."""
    pytest.importorskip("PIL")
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "make_banner", ROOT / "tools" / "make_banner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PAIRS = [
    ("paper", "PAPER"), ("card", "CARD"), ("ink", "INK"),
    ("ink_soft", "INK_SOFT"), ("muted", "MUTED"), ("rule", "RULE"),
    ("brass", "BRASS"), ("shine", "SHINE"),
]


@pytest.mark.parametrize("attr,token", PAIRS)
def test_the_banner_uses_the_products_real_colours(banner_module, attr, token):
    """A banner that has drifted advertises a product that no longer exists."""
    pair = getattr(theme, token)
    assert getattr(banner_module.LIGHT, attr) == pair.light, f"{token} light"
    assert getattr(banner_module.DARK, attr) == pair.dark, f"{token} dark"


def test_the_dark_banner_is_true_black(banner_module):
    """The house style rejects navy explicitly. Nothing may read as blue."""
    assert banner_module.DARK.paper == "#000000"
    for attr, _ in PAIRS:
        red, green, blue = (int(getattr(banner_module.DARK, attr)[i:i + 2], 16)
                            for i in (1, 3, 5))
        assert blue <= max(red, green) + 8, f"{attr} leans blue"


def test_both_banners_are_published_and_differ():
    light, dark = ASSETS / "banner.png", ASSETS / "banner-dark.png"
    assert light.is_file() and dark.is_file()
    assert light.read_bytes() != dark.read_bytes(), "one file served as both"


def test_the_readme_offers_the_dark_banner_to_dark_readers():
    """GitHub renders in the reader's scheme; a light-only banner is a slab."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "prefers-color-scheme: dark" in readme
    assert "assets/banner-dark.png" in readme


def prose_only(markdown: str) -> str:
    """The README with code removed.

    A path inside backticks or a fenced block is an example being shown, not a
    reference being made - this test tripped on an <img src> quoted inside a
    sentence explaining an attack.
    """
    without_blocks = re.sub(r"```.*?```", "", markdown, flags=re.S)
    return re.sub(r"`[^`\n]*`", "", without_blocks)


def test_every_file_the_readme_points_at_exists():
    readme = prose_only((ROOT / "README.md").read_text(encoding="utf-8"))
    refs = (set(re.findall(r"\]\(([^)#][^)]*)\)", readme))
            | set(re.findall(r'srcset="([^"]+)"', readme))
            | set(re.findall(r'src="([^"]+)"', readme)))
    for ref in refs:
        if ref.startswith(("http", "mailto")):
            continue
        assert (ROOT / ref.split("#")[0]).exists(), f"README points at {ref}"


def test_every_anchor_in_the_nav_resolves():
    """A table of contents with dead links is worse than none."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    headings = {
        re.sub(r"[^a-z0-9 -]", "", h.lower()).replace(" ", "-")
        for h in re.findall(r"^#{2,3} (.+)$", readme, re.M)
    }
    for anchor in re.findall(r"\]\(#([a-z0-9-]+)\)", readme[:2500]):
        assert anchor in headings, f"nav links to a missing #{anchor}"


def test_the_icon_set_is_complete():
    """lares.spec names these; a missing one fails the Windows build, not here."""
    for name in ("icon.png", "icon-256.png", "icon-128.png", "icon-64.png",
                 "icon-32.png", "lares.ico"):
        assert (ASSETS / name).is_file(), name


def test_the_watch_story_actually_flattens_at_the_floor(banner_module):
    """The caption says the floor is what needs a person. It has to be true."""
    tail = [open_count for open_count, _ in banner_module.STORY[-4:]]
    assert set(tail) == {banner_module.FLOOR}
    assert banner_module.STORY[0][0] > banner_module.FLOOR
