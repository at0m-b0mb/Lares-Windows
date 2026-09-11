"""The parts the pages are built from.

Two rules run through all of it. Everything takes its colours and its type from
``theme``, never from a literal - so a palette change is one edit and the
contrast test still means something. And no emoji anywhere: words where a word
will do, and a drawn mark where it will not.

The Watch, at the bottom of this file, is the piece that could only belong to
this application. It draws every cycle the machine has been through: how many
findings were open, how many were closed, and where something had to be undone.
Read left to right it is the backlog coming down, which is the only evidence
that matters for a tool that runs when nobody is looking.
"""

from __future__ import annotations

from PyQt6.QtCore import QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFontMetrics, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .theme import Mode, Pair, space


# --------------------------------------------------------------------------
# Text
# --------------------------------------------------------------------------

class Text(QLabel):
    """A label that knows which type role and colour token it is."""

    def __init__(self, text: str = "", role: str = "body", colour: Pair | None = None,
                 mode: Mode = Mode.LIGHT, wrap: bool = False, parent=None) -> None:
        super().__init__(text, parent)
        self._role = role
        self._colour = colour or theme.INK
        self.setWordWrap(wrap)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.apply(mode)

    def apply(self, mode: Mode) -> None:
        # The font goes through setFont, not the stylesheet: only QFont can
        # express letter spacing and small caps, and a stylesheet font would
        # win over it anyway.
        types = theme.build_type()
        self.setFont(types[self._role].font())
        self.setStyleSheet(f"color: {self._colour.of(mode)}; background: transparent;")

    def recolour(self, colour: Pair, mode: Mode) -> None:
        self._colour = colour
        self.apply(mode)


def heading(text: str, mode: Mode) -> Text:
    """A small caps label in brass. The only section marker in the interface."""
    return Text(text, "label", theme.BRASS, mode)


def body(text: str, mode: Mode, soft: bool = False) -> Text:
    return Text(text, "body", theme.INK_SOFT if soft else theme.INK, mode, wrap=True)


def mono(text: str, mode: Mode) -> Text:
    return Text(text, "mono", theme.INK_SOFT, mode)


# --------------------------------------------------------------------------
# Containers
# --------------------------------------------------------------------------

class Card(QFrame):
    """A white surface on the paper ground."""

    def __init__(self, mode: Mode = Mode.LIGHT, accent: bool = False,
                 wash: bool = False, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("wash" if wash else ("cardAccent" if accent else "card"))
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(space(5), space(4), space(5), space(4))
        self.body.setSpacing(space(2))

    def add(self, widget: QWidget) -> QWidget:
        self.body.addWidget(widget)
        return widget


class Row(QWidget):
    def __init__(self, gap: int = 3, parent=None) -> None:
        super().__init__(parent)
        self.body = QHBoxLayout(self)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(space(gap))

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.body.addWidget(widget, stretch)
        return widget

    def spacer(self) -> None:
        self.body.addStretch(1)


class Column(QWidget):
    def __init__(self, gap: int = 3, parent=None) -> None:
        super().__init__(parent)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(space(gap))

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.body.addWidget(widget, stretch)
        return widget

    def spacer(self) -> None:
        self.body.addStretch(1)


class Rule(QFrame):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("rule")
        self.setFixedHeight(1)


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------

class Tile(QWidget):
    """A number in the serif, with a caps label under it.

    The serif on the figure is most of what stops a row of these looking like
    every other dashboard.
    """

    def __init__(self, value: str, label: str, colour: Pair | None = None,
                 mode: Mode = Mode.LIGHT, parent=None) -> None:
        super().__init__(parent)
        self._mode = mode
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self.value = Text(value, "figure", colour or theme.INK, mode)
        self.label = Text(label, "label", theme.MUTED, mode)
        layout.addWidget(self.value)
        layout.addWidget(self.label)

    def set_value(self, value: str) -> None:
        self.value.setText(value)

    def apply(self, mode: Mode) -> None:
        self._mode = mode
        self.value.apply(mode)
        self.label.apply(mode)


class Field(QWidget):
    """A label and a value on one line, aligned in a column of them."""

    def __init__(self, label: str, value: str, mode: Mode = Mode.LIGHT,
                 width: int = 168, parent=None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(space(3))
        self.key = Text(label, "body", theme.MUTED, mode)
        self.key.setFixedWidth(width)
        self.key.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.val = Text(value, "body", theme.INK, mode, wrap=True)
        layout.addWidget(self.key)
        layout.addWidget(self.val, 1)

    def set_value(self, value: str) -> None:
        self.val.setText(value)


# --------------------------------------------------------------------------
# Navigation
# --------------------------------------------------------------------------

class NavButton(QPushButton):
    def __init__(self, label: str, mode: Mode = Mode.LIGHT, parent=None) -> None:
        # Qt reads a single ampersand in a button label as a mnemonic marker and
        # swallows it, so it has to be doubled to survive.
        super().__init__(label.replace("&", "&&"), parent)
        self.setObjectName("nav")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFont(theme.build_type()["nav"].font())
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)


# --------------------------------------------------------------------------
# Severity bar
# --------------------------------------------------------------------------

class SeverityBar(QWidget):
    """One stacked bar of the open findings, worst on the left."""

    def __init__(self, mode: Mode = Mode.LIGHT, parent=None) -> None:
        super().__init__(parent)
        self._mode = mode
        self._counts: dict[str, int] = {}
        self.setFixedHeight(8)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_counts(self, counts: dict[str, int]) -> None:
        self._counts = counts
        self.update()

    def apply(self, mode: Mode) -> None:
        self._mode = mode
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)

        total = sum(self._counts.values())
        w, h = self.width(), self.height()
        radius = h / 2

        if not total:
            painter.setBrush(theme.RULE_SOFT.q(self._mode))
            painter.drawRoundedRect(QRectF(0, 0, w, h), radius, radius)
            return

        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, w, h), radius, radius)
        painter.setClipPath(path)

        x = 0.0
        for name in ("critical", "high", "medium", "low", "info"):
            count = self._counts.get(name, 0)
            if not count:
                continue
            width = w * count / total
            painter.setBrush(theme.SEVERITY[name].q(self._mode))
            painter.drawRect(QRectF(x, 0, width + 0.5, h))
            x += width


# --------------------------------------------------------------------------
# The Watch - the signature element
# --------------------------------------------------------------------------

class Watch(QWidget):
    """Every cycle this machine has been through, drawn left to right.

    Each column is one cycle. Its full height is how many findings were open at
    the start; the gold portion at the base is how many were closed during it. A
    cycle where something had to be undone is marked underneath, because that is
    the event a person most needs to notice and it must not be possible to miss
    it among the good ones.

    The shape that matters is the top edge. On a machine Lares is looking after,
    it descends and then flattens at the handful of findings that need a person.
    """

    hovered = pyqtSignal(str)

    def __init__(self, mode: Mode = Mode.LIGHT, parent=None) -> None:
        super().__init__(parent)
        self._mode = mode
        self._cycles: list[dict] = []
        self.setMinimumHeight(88)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMouseTracking(True)

    def set_cycles(self, cycles: list[dict]) -> None:
        self._cycles = list(cycles)[-40:]
        self.update()

    def apply(self, mode: Mode) -> None:
        self._mode = mode
        self.update()

    def _geometry(self) -> tuple[float, float, float, int]:
        pad = space(2)
        base = self.height() - space(5)
        usable = self.width() - pad * 2
        n = max(1, len(self._cycles))
        # Cap the slot width so three cycles read as the start of a sequence
        # rather than three lonely bars stretched across the whole card.
        slot = min(usable / n, 30.0)
        return pad, base, slot, n

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        mode = self._mode

        if not self._cycles:
            painter.setPen(QPen(theme.MUTED.q(mode)))
            painter.setFont(theme.build_type()["small"].font())
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "No cycles recorded yet")
            return

        pad, base, slot, n = self._geometry()
        peak = max(max(c.get("open", 0) for c in self._cycles), 1)
        bar_w = max(3.0, min(slot - space(1), 22.0))

        # Baseline, so a run of empty cycles still reads as a sequence.
        painter.setPen(QPen(theme.RULE.q(mode), 1))
        painter.drawLine(int(pad), int(base), int(self.width() - pad), int(base))

        for index, cycle in enumerate(self._cycles):
            x = pad + slot * index + (slot - bar_w) / 2
            open_count = cycle.get("open", 0)
            fixed = cycle.get("fixed", 0)
            height = (base - space(2)) * (open_count / peak)

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(theme.RULE.q(mode))
            painter.drawRect(QRectF(x, base - height, bar_w, height))

            if fixed and open_count:
                closed = height * min(1.0, fixed / open_count)
                painter.setBrush(theme.SHINE.q(mode))
                painter.drawRect(QRectF(x, base - closed, bar_w, closed))

            if cycle.get("reverted") or cycle.get("failed"):
                painter.setBrush(theme.BAD.q(mode))
                painter.drawRect(QRectF(x, base + 3, bar_w, 3))

        # The peak, labelled once so the height means something - on the right,
        # where the columns are not, since the bars grow from the left.
        painter.setPen(QPen(theme.MUTED.q(mode)))
        painter.setFont(theme.build_type()["mono_small"].font())
        metrics = QFontMetrics(painter.font())
        peak_label = f"{peak} open at the highest"
        painter.drawText(
            int(self.width() - pad - metrics.horizontalAdvance(peak_label)),
            int(space(3)), peak_label)

        first = self._cycles[0].get("at", "")[:10]
        last = self._cycles[-1].get("at", "")[:10]
        painter.drawText(int(pad), int(self.height() - 2), first)
        painter.drawText(int(self.width() - pad - metrics.horizontalAdvance(last)),
                         int(self.height() - 2), last)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if not self._cycles:
            return
        pad, _, slot, _ = self._geometry()
        index = int((event.position().x() - pad) / slot) if slot else 0
        if 0 <= index < len(self._cycles):
            cycle = self._cycles[index]
            self.setToolTip(
                f"{cycle.get('at', '')[:19].replace('T', ' ')}\n"
                f"{cycle.get('open', 0)} open, {cycle.get('fixed', 0)} fixed"
                + (f", {cycle['reverted']} undone" if cycle.get("reverted") else "")
            )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def dot(colour: QColor, size: int = 8) -> QWidget:
    """A small filled circle, for legends. Carries no text by definition."""

    class _Dot(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.setFixedSize(size, size)

        def paintEvent(self, event) -> None:  # noqa: N802
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(colour)
            painter.drawEllipse(0, 0, size, size)

    return _Dot()
