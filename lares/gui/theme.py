"""Design tokens for the desktop application.

The house style, stated once so no widget has to invent it:

* **Warm paper, not white.** A light ground with a little yellow in it, white
  cards sitting on top, hairline rules. Flat pure white reads as unfinished.
* **Gold is the only accent**, used sparingly. There are two gold tokens rather
  than one, because a single gold cannot simultaneously be a fill behind white
  text, a bright mark, and small text on paper. ``brass`` is dark enough to read
  as text; ``shine`` is bright and only ever marks something that carries no
  words.
* **Dark mode is true black.** Not navy, not charcoal-blue. Nothing in the dark
  palette may read as blue.
* **Three typefaces doing three jobs**: a serif for identity and for figures, a
  neutral sans for controls, a mono for anything the machine itself said.

Every colour is declared as a ``(light, dark)`` pair at the point of definition.
That is the mechanism that makes it impossible to add a colour and forget the
dark theme - there is nowhere to put a single value.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from PyQt6.QtGui import QColor, QFont, QFontDatabase


class Mode(str, Enum):
    LIGHT = "light"
    DARK = "dark"


@dataclass(frozen=True)
class Pair:
    """One colour, in both themes. There is no way to define only one."""

    light: str
    dark: str

    def of(self, mode: Mode) -> str:
        return self.light if mode is Mode.LIGHT else self.dark

    def q(self, mode: Mode) -> QColor:
        return QColor(self.of(mode))


# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------

PAPER      = Pair("#F3F1EC", "#000000")   # the window ground
CARD       = Pair("#FFFFFF", "#121212")   # raised surfaces
CARD_ALT   = Pair("#FAF8F3", "#1A1A1A")   # zebra rows, inset panels
RULE       = Pair("#DDD8CD", "#2A2A2A")   # hairlines
RULE_SOFT  = Pair("#EBE7DE", "#1F1F1F")

INK        = Pair("#1A1916", "#ECEAE4")   # primary text
INK_SOFT   = Pair("#4A463D", "#B8B3A9")   # secondary text
MUTED      = Pair("#6B6558", "#8A857B")   # tertiary, labels, timestamps

#: Deep brass. Readable as small text on every ground in both themes, which is
#: why it is this dark - a gold light enough to look like gold on white cannot
#: carry text on white. Use it for anything gold that has words in it: section
#: headings, active navigation, key figures.
#: Measured: 5.3:1 on paper, 6.0:1 on card, 5.1:1 on the gold wash.
BRASS      = Pair("#7C5F10", "#D4A73A")
#: The brightest gold that is still *visible* against its own ground, which is a
#: different colour in each theme - genuinely bright on black, necessarily
#: deeper on paper. Never carries text; it marks things that have no words.
#: Measured: 3.3:1 on paper in light, 11.2:1 on card in dark.
SHINE      = Pair("#A0811F", "#E8C468")
GOLD_WASH  = Pair("#F4EDD9", "#241E10")   # tinted panel behind brass text

#: Severity. Muted rather than alarm-bright: a list where four rows are
#: screaming red communicates less than one where the worst row is clearly the
#: worst.
CRITICAL   = Pair("#8C1D18", "#E0776E")
HIGH       = Pair("#A8471C", "#E09A62")
MEDIUM     = Pair("#8A6D1F", "#D9BC63")
# Warm greys, not blue-greys. Nothing in this palette may drift towards navy,
# in either theme.
LOW        = Pair("#5F5A52", "#A39C92")
INFO       = Pair("#5F5A52", "#A39C92")

#: Outcome.
GOOD       = Pair("#2F6B4F", "#72C79C")
WARNING    = Pair("#8A6D1F", "#D9BC63")
BAD        = Pair("#8C1D18", "#E0776E")
NEUTRAL    = Pair("#6B6558", "#8A857B")

SEVERITY = {
    "critical": CRITICAL, "high": HIGH, "medium": MEDIUM,
    "low": LOW, "info": INFO,
}

STATUS = {
    "verified": GOOD, "unverified": WARNING, "simulated": NEUTRAL,
    "skipped": NEUTRAL, "refused": NEUTRAL, "rolled_back": WARNING,
    "failed": BAD,
}

RISK = {"safe": GOOD, "caution": WARNING, "intrusive": BAD}


# --------------------------------------------------------------------------
# Type
#
# Windows ships Georgia and Segoe UI, and Consolas is on every install since
# Vista. The fallbacks cover development on macOS and Linux.
# --------------------------------------------------------------------------

#: Concrete family names only. A CSS generic like "sans-serif" is not a Qt
#: family, so leaving one at the end of a stack makes Qt walk its entire alias
#: table before giving up - visible as a startup delay and a console warning.
SERIF_STACK = ["Georgia", "Iowan Old Style", "Palatino", "Times New Roman", "Times"]
SANS_STACK = ["Segoe UI", "Inter", "SF Pro Text", "Helvetica Neue", "Helvetica", "Arial"]
MONO_STACK = ["Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "Courier New"]


def _first_available(stack: list[str]) -> str:
    """The first family actually installed, falling back to Qt's own default.

    Asking for a family that does not exist is not an error in Qt - it silently
    substitutes something, which is how an application ends up rendering in a
    font nobody chose.
    """
    families = set(QFontDatabase.families())
    for name in stack:
        if name in families:
            return name
    return QFont().defaultFamily() or stack[-1]


#: Four-point rhythm. Every margin and gap in the application is a multiple.
UNIT = 4


def space(n: int) -> int:
    return UNIT * n


@dataclass(frozen=True)
class Type:
    family: str
    size: int
    weight: QFont.Weight = QFont.Weight.Normal
    letter_spacing: float = 0.0
    caps: bool = False

    def font(self) -> QFont:
        f = QFont(self.family, self.size)
        f.setWeight(self.weight)
        if self.letter_spacing:
            f.setLetterSpacing(QFont.SpacingType.PercentageSpacing,
                               100 + self.letter_spacing)
        if self.caps:
            f.setCapitalization(QFont.Capitalization.AllUppercase)
        return f


def build_type() -> dict[str, Type]:
    serif = _first_available(SERIF_STACK)
    sans = _first_available(SANS_STACK)
    mono = _first_available(MONO_STACK)
    return {
        # Identity and figures carry the serif. This is most of what makes the
        # application read as authored rather than generated.
        "wordmark":  Type(serif, 22, QFont.Weight.Medium),
        "display":   Type(serif, 34, QFont.Weight.Medium),
        "figure":    Type(serif, 27, QFont.Weight.Medium),
        "title":     Type(serif, 16, QFont.Weight.Medium),

        # Controls and body take the neutral sans.
        "body":      Type(sans, 10),
        "body_soft": Type(sans, 10),
        "label":     Type(sans, 8, QFont.Weight.DemiBold, letter_spacing=8, caps=True),
        "button":    Type(sans, 10, QFont.Weight.Medium),
        "nav":       Type(sans, 11),
        "small":     Type(sans, 9),

        # Anything the machine said keeps the mono, so evidence is visibly
        # distinct from our prose about it.
        "mono":      Type(mono, 9),
        "mono_small": Type(mono, 8),
    }


# --------------------------------------------------------------------------
# Stylesheet
# --------------------------------------------------------------------------

def stylesheet(mode: Mode) -> str:
    """Application-wide Qt stylesheet for one theme."""
    c = lambda pair: pair.of(mode)  # noqa: E731 - local shorthand, used heavily

    return f"""
    /* No font here on purpose. A font declared in a Qt stylesheet beats any
       later setFont() call, which would silently flatten the serif headings and
       the letter-spaced labels back to the body face. The base font is set once
       in code with QApplication.setFont, and individual roles set their own. */
    QWidget {{
        background: {c(PAPER)};
        color: {c(INK)};
    }}
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; border: none; }}

    QFrame#card {{
        background: {c(CARD)};
        border: 1px solid {c(RULE)};
        border-radius: 3px;
    }}
    QFrame#cardAccent {{
        background: {c(CARD)};
        border: 1px solid {c(RULE)};
        border-left: 3px solid {c(BRASS)};
        border-radius: 3px;
    }}
    QFrame#wash {{
        background: {c(GOLD_WASH)};
        border: 1px solid {c(SHINE)};
        border-radius: 3px;
    }}
    QFrame#rule {{ background: {c(RULE)}; border: none; max-height: 1px; }}

    QFrame#sidebar {{
        background: {c(CARD_ALT)};
        border: none;
        border-right: 1px solid {c(RULE)};
    }}

    QPushButton#nav {{
        background: transparent;
        border: none;
        border-left: 2px solid transparent;
        padding: 9px 16px;
        text-align: left;
        color: {c(INK_SOFT)};
    }}
    QPushButton#nav:hover {{ background: {c(RULE_SOFT)}; color: {c(INK)}; }}
    QPushButton#nav:checked {{
        border-left: 2px solid {c(BRASS)};
        color: {c(BRASS)};
        font-weight: 600;
    }}

    QPushButton {{
        background: {c(CARD)};
        border: 1px solid {c(RULE)};
        border-radius: 3px;
        padding: 6px 14px;
        color: {c(INK)};
    }}
    QPushButton:hover {{ border-color: {c(BRASS)}; }}
    QPushButton:disabled {{ color: {c(MUTED)}; border-color: {c(RULE_SOFT)}; }}

    QPushButton#primary {{
        background: {c(BRASS)};
        border: 1px solid {c(BRASS)};
        color: {c(CARD)};
        font-weight: 600;
    }}
    QPushButton#primary:hover {{ background: {c(SHINE)}; border-color: {c(SHINE)};
                                 color: {c(INK) if mode is Mode.DARK else '#FFFFFF'}; }}
    QPushButton#primary:disabled {{ background: {c(RULE)}; border-color: {c(RULE)};
                                    color: {c(MUTED)}; }}

    QTableWidget {{
        background: {c(CARD)};
        alternate-background-color: {c(CARD_ALT)};
        gridline-color: {c(RULE_SOFT)};
        border: 1px solid {c(RULE)};
        border-radius: 3px;
        selection-background-color: {c(GOLD_WASH)};
        selection-color: {c(INK)};
    }}
    QHeaderView::section {{
        background: {c(CARD)};
        color: {c(MUTED)};
        border: none;
        border-bottom: 1px solid {c(RULE)};
        padding: 7px 8px;
        font-size: 8pt;
        font-weight: 600;
    }}
    QTableWidget::item {{ padding: 5px 8px; border: none; }}

    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {c(RULE)}; border-radius: 5px; min-height: 30px; }}
    QScrollBar::handle:vertical:hover {{ background: {c(MUTED)}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

    QComboBox, QSpinBox, QLineEdit {{
        background: {c(CARD)};
        border: 1px solid {c(RULE)};
        border-radius: 3px;
        padding: 5px 8px;
        color: {c(INK)};
    }}
    QComboBox:focus, QSpinBox:focus, QLineEdit:focus {{ border-color: {c(BRASS)}; }}
    QComboBox QAbstractItemView {{
        background: {c(CARD)};
        border: 1px solid {c(RULE)};
        selection-background-color: {c(GOLD_WASH)};
        selection-color: {c(INK)};
    }}

    QCheckBox {{ spacing: 8px; }}
    QCheckBox::indicator {{
        width: 15px; height: 15px;
        border: 1px solid {c(RULE)};
        border-radius: 2px;
        background: {c(CARD)};
    }}
    QCheckBox::indicator:checked {{ background: {c(BRASS)}; border-color: {c(BRASS)}; }}

    QTextEdit, QPlainTextEdit {{
        background: {c(CARD_ALT)};
        border: 1px solid {c(RULE)};
        border-radius: 3px;
        color: {c(INK_SOFT)};
        selection-background-color: {c(GOLD_WASH)};
        selection-color: {c(INK)};
    }}

    QToolTip {{
        background: {c(INK)};
        color: {c(PAPER)};
        border: none;
        padding: 5px 8px;
    }}

    QProgressBar {{
        background: {c(RULE_SOFT)};
        border: none;
        border-radius: 2px;
        height: 4px;
        text-align: center;
    }}
    QProgressBar::chunk {{ background: {c(BRASS)}; border-radius: 2px; }}
    """


def app_font() -> QFont:
    """The base font for the whole application.

    Set through QApplication.setFont rather than the stylesheet, so that widgets
    which need a different role can still override it with setFont.
    """
    return build_type()["body"].font()


def resolve(choice: str) -> Mode:
    """Turn a stored preference into a mode.

    The user's *choice* is stored, never the resolved value, so that a machine
    set to Auto follows the OS when the OS changes rather than freezing at
    whatever it happened to be the first time.
    """
    if choice == "light":
        return Mode.LIGHT
    if choice == "dark":
        return Mode.DARK
    return _system_mode()


def _system_mode() -> Mode:
    try:
        from PyQt6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is not None:
            scheme = app.styleHints().colorScheme()
            from PyQt6.QtCore import Qt
            if scheme == Qt.ColorScheme.Dark:
                return Mode.DARK
            if scheme == Qt.ColorScheme.Light:
                return Mode.LIGHT
    except Exception:  # noqa: BLE001 - older Qt without colorScheme()
        pass
    return Mode.LIGHT
