"""The desktop application.

It starts, it begins working, and it keeps working. There is no Scan button that
has to be pressed before anything happens and no dialog asking permission to fix
something - the agent runs on its schedule whether the window is open or not,
and this is the window onto it.

The pages are named in the product's own vocabulary rather than the usual
Dashboard/Settings/Advanced, because those names tell you nothing about which
one you want:

    Hearth     what this machine looks like right now, and the record of it
    Findings   everything open, worst first
    Ledger     every change Lares has made, and the button that undoes one
    Chronicle  the activity log, the failures, and the model conversation
    Catalogue  the thirty controls, including the ones it will not touch
    Model      which model is running and why that one
    Colophon   how it is built, and what it deliberately does not claim
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PyQt6.QtCore import QObject, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QHeaderView,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import config as config_mod
from .. import logs
from ..act.execute import Executor
from ..act.guard import Context
from ..act.journal import Journal
from ..autonomy.loop import Agent, Event, build
from ..brain import models
from ..catalog import loader
from ..core import Cycle, RiskTier, Scan
from ..report import write_report
from ..sense import scanner
from ..version import ETYMOLOGY, NAME, VERSION
from ..winsys import current_user, is_demo, is_elevated
from . import theme, widgets
from .theme import Mode, space
from .widgets import Card, Column, Field, NavButton, Row, Rule, SeverityBar, Text, Tile, Watch

PAGES = ["Hearth", "Findings", "Ledger", "Chronicle", "Catalogue", "Model", "Colophon"]


# --------------------------------------------------------------------------
# Worker
# --------------------------------------------------------------------------

class Worker(QObject):
    """Runs the agent off the interface thread.

    Qt objects may only be touched from the thread that made them, so nothing
    here calls into a widget. It emits, the window renders.
    """

    progressed = pyqtSignal(object)     # Event
    cycle_done = pyqtSignal(object)     # Cycle
    stopped = pyqtSignal()

    def __init__(self, agent: Agent) -> None:
        super().__init__()
        self.agent = agent
        self.agent._listener = self.progressed.emit

    def run_once(self) -> None:
        cycle = self.agent.run_cycle()
        self.cycle_done.emit(cycle)

    def run_forever(self) -> None:
        try:
            self.agent.run_forever()
        finally:
            self.stopped.emit()


# --------------------------------------------------------------------------
# Window
# --------------------------------------------------------------------------

class Window(QMainWindow):
    def __init__(self, settings: config_mod.Settings, autostart: bool = True) -> None:
        super().__init__()
        self.settings = settings
        self.mode = theme.resolve(settings.theme)
        self.catalog = loader.load()
        self.journal = Journal()
        self.scan: Scan | None = None
        self.cycle: Cycle | None = None

        self.agent, self.model_note = build(settings, self.catalog)
        self.thread: QThread | None = None
        self.worker: Worker | None = None
        self._running = False

        self.setWindowTitle(NAME)
        self.resize(1120, 760)
        self.setMinimumSize(940, 620)

        self._build()
        self.apply_theme()
        self._show_page(0)

        if autostart:
            # The application does its job without being asked. A short delay
            # lets the window paint first, so it does not appear already busy.
            QTimer.singleShot(600, self.start_agent)

    # -- construction ---------------------------------------------------

    def _build(self) -> None:
        root = QWidget()
        layout = Row(0)
        layout.body.setContentsMargins(0, 0, 0, 0)

        self.sidebar = self._build_sidebar()
        layout.add(self.sidebar)

        self.pages = QStackedWidget()
        self.page_hearth = HearthPage(self)
        self.page_findings = FindingsPage(self)
        self.page_ledger = LedgerPage(self)
        self.page_chronicle = ChroniclePage(self)
        self.page_catalogue = CataloguePage(self)
        self.page_model = ModelPage(self)
        self.page_colophon = ColophonPage(self)
        # The order here must match PAGES, since the sidebar selects by index.
        for page in (self.page_hearth, self.page_findings, self.page_ledger,
                     self.page_chronicle, self.page_catalogue, self.page_model,
                     self.page_colophon):
            self.pages.addWidget(_scrolled(page))
        layout.add(self.pages, 1)

        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(layout)
        self.setCentralWidget(root)

    def _build_sidebar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("sidebar")
        bar.setFixedWidth(212)
        column = QVBoxLayout(bar)
        column.setContentsMargins(0, space(7), 0, space(4))
        column.setSpacing(0)

        mark = Text(NAME, "wordmark", theme.INK, self.mode)
        mark.setContentsMargins(space(4), 0, 0, 0)
        column.addWidget(mark)
        sub = Text("household guardian", "small", theme.MUTED, self.mode)
        sub.setContentsMargins(space(4), 0, 0, space(6))
        column.addWidget(sub)
        self._wordmark, self._wordmark_sub = mark, sub

        self.nav: list[NavButton] = []
        for index, name in enumerate(PAGES):
            button = NavButton(name, self.mode)
            button.clicked.connect(lambda _, i=index: self._show_page(i))
            column.addWidget(button)
            self.nav.append(button)

        column.addStretch(1)

        self.state_label = Text("Starting", "small", theme.BRASS, self.mode, wrap=True)
        self.state_label.setContentsMargins(space(4), 0, space(4), space(1))
        column.addWidget(self.state_label)

        self.state_detail = Text("", "small", theme.MUTED, self.mode, wrap=True)
        self.state_detail.setContentsMargins(space(4), 0, space(4), space(3))
        column.addWidget(self.state_detail)

        self.pause_button = QPushButton("Pause")
        self.pause_button.clicked.connect(self.toggle_agent)
        holder = QWidget()
        holder_layout = QVBoxLayout(holder)
        holder_layout.setContentsMargins(space(4), 0, space(4), 0)
        holder_layout.addWidget(self.pause_button)
        column.addWidget(holder)

        return bar

    def _show_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        for i, button in enumerate(self.nav):
            button.setChecked(i == index)

    # -- theme ----------------------------------------------------------

    def apply_theme(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setFont(theme.app_font())
            app.setStyleSheet(theme.stylesheet(self.mode))
        for widget in self.findChildren(Text):
            widget.apply(self.mode)
        for widget in self.findChildren(SeverityBar):
            widget.apply(self.mode)
        for widget in self.findChildren(Watch):
            widget.apply(self.mode)
        for widget in self.findChildren(Tile):
            widget.apply(self.mode)
        for page in (self.page_hearth, self.page_findings, self.page_ledger,
                     self.page_chronicle, self.page_catalogue, self.page_model,
                     self.page_colophon):
            if hasattr(page, "retheme"):
                page.retheme(self.mode)

    def set_theme(self, choice: str) -> None:
        self.settings.theme = choice
        config_mod.save(self.settings)
        self.mode = theme.resolve(choice)
        self.apply_theme()

    # -- the agent ------------------------------------------------------

    def start_agent(self) -> None:
        if self._running:
            return
        self._running = True
        self.pause_button.setText("Pause")

        self.thread = QThread(self)
        self.worker = Worker(self.agent)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run_forever)
        self.worker.progressed.connect(self.on_event)
        self.worker.cycle_done.connect(self.on_cycle)
        self.worker.stopped.connect(self.on_stopped)
        self.thread.start()

    def toggle_agent(self) -> None:
        if self._running:
            self.agent.stop()
            self.pause_button.setText("Stopping")
            self.pause_button.setEnabled(False)
        else:
            self.agent._stop.clear()
            self.start_agent()

    def on_stopped(self) -> None:
        self._running = False
        self.pause_button.setText("Resume")
        self.pause_button.setEnabled(True)
        self._set_state("Paused", "No cycles will run until this is resumed.")
        if self.thread:
            self.thread.quit()
            self.thread.wait(3000)
            self.thread = None

    def on_event(self, event: Event) -> None:
        if event.kind == "scan":
            done, total = event.progress or (0, 0)
            self._set_state("Checking the machine",
                            f"{event.message}  ({done}/{total})" if total else event.message)
        elif event.kind == "plan":
            self._set_state("Deciding", event.message)
        elif event.kind == "action":
            self._set_state("Working", event.message)
            self.page_hearth.log(event.message, event.detail, self.mode)
        elif event.kind == "wait":
            self._set_state("Watching", event.message)
        elif event.kind == "error":
            self._set_state("Stopped", event.message)

    def on_cycle(self, cycle: Cycle) -> None:
        self.cycle = cycle
        self.scan = cycle.scan
        self.page_hearth.refresh()
        self.page_findings.refresh()
        self.page_ledger.refresh()
        self.page_chronicle.refresh()

    def _set_state(self, state: str, detail: str = "") -> None:
        self.state_label.setText(state)
        self.state_detail.setText(" ".join(detail.split())[:110])

    # -- shutdown -------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt naming
        self.agent.stop()
        if self.thread is not None:
            self.thread.quit()
            self.thread.wait(4000)
        event.accept()


def _scrolled(widget: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setWidget(widget)
    area.setWidgetResizable(True)
    area.setFrameShape(QScrollArea.Shape.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    return area


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

class Page(QWidget):
    """Common page chrome: a serif title, a line of context, then content."""

    def __init__(self, window: Window, title: str, standfirst: str) -> None:
        super().__init__()
        self.window_ref = window
        mode = window.mode
        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(space(10), space(9), space(10), space(10))
        self.outer.setSpacing(space(4))

        self.title = Text(title, "display", theme.INK, mode)
        self.standfirst = Text(standfirst, "body", theme.MUTED, mode, wrap=True)
        self.standfirst.setMaximumWidth(640)
        self.outer.addWidget(self.title)
        self.outer.addWidget(self.standfirst)
        self.outer.addSpacing(space(2))

    def retheme(self, mode: Mode) -> None:
        for widget in self.findChildren(Text):
            widget.apply(mode)


class HearthPage(Page):
    def __init__(self, window: Window) -> None:
        super().__init__(window, "Hearth",
                         "What this machine looks like now, and the record of every "
                         "time Lares has looked at it.")
        mode = window.mode

        self.verdict_card = Card(mode, accent=True)
        self.verdict = Text("Starting the first check", "title", theme.INK, mode, wrap=True)
        self.verdict_detail = Text("", "body", theme.INK_SOFT, mode, wrap=True)
        self.verdict_card.add(self.verdict)
        self.verdict_card.add(self.verdict_detail)
        self.outer.addWidget(self.verdict_card)

        tiles = Card(mode)
        row = Row(9)
        self.t_open = Tile("-", "open", theme.INK, mode)
        self.t_fixed = Tile("-", "fixed", theme.GOOD, mode)
        self.t_manual = Tile("-", "needs a person", theme.MEDIUM, mode)
        self.t_undone = Tile("-", "undone", theme.WARNING, mode)
        for tile in (self.t_open, self.t_fixed, self.t_manual, self.t_undone):
            row.add(tile)
        row.spacer()
        tiles.add(row)
        self.bar = SeverityBar(mode)
        tiles.add(self.bar)
        self.outer.addWidget(tiles)

        watch_card = Card(mode)
        watch_card.add(widgets.heading("The Watch", mode))
        self.watch = Watch(mode)
        watch_card.add(self.watch)
        watch_card.add(Text(
            "One column per cycle. The column is how many findings were open; "
            "the gold is how many were closed. A mark underneath means something "
            "had to be undone.", "small", theme.MUTED, mode, wrap=True))
        self.outer.addWidget(watch_card)

        activity = Card(mode)
        activity.add(widgets.heading("Now", mode))
        self.activity = Column(1)
        activity.add(self.activity)
        self.idle = Text("Nothing is happening. Lares checks this machine on its "
                         "schedule and will say here what it is doing.",
                         "body", theme.MUTED, mode, wrap=True)
        activity.add(self.idle)
        self.outer.addWidget(activity)

        self.outer.addStretch(1)
        self._log_lines = 0

    def log(self, message: str, detail: str, mode: Mode) -> None:
        self.idle.setVisible(False)
        if self._log_lines > 14:
            item = self.activity.body.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()
            self._log_lines -= 1
        line = Text(message, "small", theme.INK_SOFT, mode, wrap=True)
        self.activity.add(line)
        self._log_lines += 1

    def refresh(self) -> None:
        window = self.window_ref
        scan, cycle = window.scan, window.cycle
        if scan is None:
            return

        verdict, detail = scanner.posture(scan)
        self.verdict.setText(verdict)
        self.verdict_detail.setText(detail)

        counts = {s.value: n for s, n in scan.counts().items()}
        self.bar.set_counts(counts)

        fixed = len(cycle.fixed) if cycle else 0
        undone = len(cycle.reverted) if cycle else 0
        manual = sum(1 for f in scan.findings
                     if (c := window.catalog.get(f.control_id)) and not c.autonomy_eligible)

        self.t_open.set_value(str(len(scan.findings)))
        self.t_fixed.set_value(str(fixed))
        self.t_manual.set_value(str(manual))
        self.t_undone.set_value(str(undone))

        self.watch.set_cycles(window.agent.breaker.state.cycles)


class FindingsPage(Page):
    def __init__(self, window: Window) -> None:
        super().__init__(window, "Findings",
                         "Everything open on this machine, worst first. The last "
                         "column says whether Lares will deal with it by itself.")
        mode = window.mode
        card = Card(mode)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Severity", "Control", "What was found", "Fix", "Effect"])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for col in (0, 1, 3, 4):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        # A fixed height keeps the table from ballooning inside the scroll area.
        self.table.setFixedHeight(460)
        card.add(self.table)
        self.outer.addWidget(card)
        self.outer.addStretch(1)

    def refresh(self) -> None:
        window = self.window_ref
        scan, mode = window.scan, window.mode
        if scan is None:
            return
        findings = scan.by_severity()
        self.table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            control = window.catalog.get(finding.control_id)
            how = ("automatic" if control and control.autonomy_eligible
                   else "report only" if control and not control.has_remediation
                   else "needs a person")
            cells = [
                finding.severity.value,
                finding.control_id,
                finding.observed or finding.title,
                how,
                control.effective if control else "",
            ]
            for col, value in enumerate(cells):
                item = QTableWidgetItem(value)
                if col == 0:
                    item.setForeground(theme.SEVERITY[finding.severity.value].q(mode))
                if col in (3, 4):
                    item.setForeground(theme.MUTED.q(mode))
                self.table.setItem(row, col, item)


class LedgerPage(Page):
    def __init__(self, window: Window) -> None:
        super().__init__(window, "Ledger",
                         "Every change Lares has made to this machine, newest first. "
                         "Anything still in place can be put back.")
        mode = window.mode

        controls = Row()
        self.undo_button = QPushButton("Undo the selected change")
        self.undo_button.clicked.connect(self.undo_selected)
        controls.add(self.undo_button)
        self.export_button = QPushButton("Write a report")
        self.export_button.clicked.connect(self.export)
        controls.add(self.export_button)
        controls.spacer()
        self.outer.addWidget(controls)

        card = Card(mode)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["When", "Outcome", "Control", "What happened"])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for col in (0, 1, 2):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setFixedHeight(480)
        card.add(self.table)
        self.outer.addWidget(card)
        self.outer.addStretch(1)
        self._entries: list = []

    def refresh(self) -> None:
        window = self.window_ref
        mode = window.mode
        self._entries = window.journal.recent(200)
        self.table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            outcome = entry.outcome
            cells = [
                entry.at[:19].replace("T", " "),
                outcome.status.value.replace("_", " "),
                outcome.control_id,
                " ".join(outcome.message.split()),
            ]
            for col, value in enumerate(cells):
                item = QTableWidgetItem(value)
                if col == 1:
                    item.setForeground(theme.STATUS.get(
                        outcome.status.value, theme.NEUTRAL).q(mode))
                if col == 0:
                    item.setForeground(theme.MUTED.q(mode))
                self.table.setItem(row, col, item)

    def undo_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._entries):
            return
        entry = self._entries[row]
        window = self.window_ref

        if not entry.undoable:
            QMessageBox.information(
                self, "Nothing to undo",
                f"{entry.outcome.control_id} did not leave a change in place, so "
                "there is nothing to put back.")
            return

        executor = Executor(window.catalog,
                            Context(elevated=is_elevated(), autonomous=False))
        outcome = executor.undo_recorded(entry.outcome.rollback_script,
                                         entry.outcome.control_id)
        window.journal.record(outcome, control_title=entry.control_title,
                              rationale=f"undo of {entry.outcome.action_id}")
        self.refresh()
        QMessageBox.information(self, "Undo", outcome.message)

    def export(self) -> None:
        window = self.window_ref
        if window.scan is None:
            return
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(
            self, "Write a report", "lares-report.html",
            "Report (*.html *.json *.txt)")
        if path:
            written = write_report(window.scan, window.cycle, path)
            QMessageBox.information(self, "Report", f"Written to {written}")


class ChroniclePage(Page):
    """What Lares did, what broke, and what it said to the model.

    Three records on one page because they are read together. When something
    went wrong at four in the morning the question is never "show me the log" -
    it is "what happened, did it fail, and what was the model thinking".
    """

    def __init__(self, window: Window) -> None:
        super().__init__(window, "Chronicle",
                         "The running account of what Lares has been doing, the "
                         "failures it recorded, and every exchange with the model.")
        mode = window.mode

        controls = Row()
        self.filter = QComboBox()
        self.filter.addItems(["Everything", "Warnings and errors", "Errors only"])
        self.filter.currentIndexChanged.connect(lambda _: self.refresh())
        controls.add(Text("Show", "label", theme.MUTED, mode))
        controls.add(self.filter)
        self.open_button = QPushButton("Open the log folder")
        self.open_button.clicked.connect(self.open_folder)
        controls.add(self.open_button)
        self.export_button = QPushButton("Export the conversation")
        self.export_button.clicked.connect(self.export_transcript)
        controls.add(self.export_button)
        controls.spacer()
        self.outer.addWidget(controls)

        # -- activity ---------------------------------------------------
        activity = Card(mode)
        activity.add(widgets.heading("Activity", mode))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["When", "Level", "Area", "What happened"])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        head = self.table.horizontalHeader()
        head.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for col in (0, 1, 2):
            head.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setFixedHeight(300)
        activity.add(self.table)
        self.outer.addWidget(activity)

        # -- errors -----------------------------------------------------
        self.errors_card = Card(mode)
        self.errors_card.add(widgets.heading("Failures", mode))
        self.errors_body = Column()
        self.errors_card.add(self.errors_body)
        self.outer.addWidget(self.errors_card)

        # -- the model conversation -------------------------------------
        talk = Card(mode)
        talk.add(widgets.heading("Conversation with the model", mode))
        talk.add(Text(
            "Each exchange records what Lares asked, what the model answered, "
            "and which of its choices the guard accepted or refused.",
            "body", theme.INK_SOFT, mode, wrap=True))
        self.talk_body = Column()
        talk.add(self.talk_body)
        self.outer.addWidget(talk)
        self.outer.addStretch(1)

    # -- data -----------------------------------------------------------

    def refresh(self) -> None:
        mode = self.window_ref.mode
        log = logs.get()

        level = {1: logs.Level.WARN, 2: logs.Level.ERROR}.get(self.filter.currentIndex())
        records = log.tail(limit=200, level=level)[::-1]

        self.table.setRowCount(len(records))
        for row, record in enumerate(records):
            cells = [record.local_time, record.level.value, record.area,
                     record.message + (f"  [{record.error_id}]" if record.error_id else "")]
            for col, value in enumerate(cells):
                item = QTableWidgetItem(value)
                if col == 1:
                    item.setForeground(_level_colour(record.level).q(mode))
                elif col in (0, 2):
                    item.setForeground(theme.MUTED.q(mode))
                self.table.setItem(row, col, item)

        self._fill_errors(log, mode)
        self._fill_talk(mode)

    def _fill_errors(self, log: logs.Log, mode: Mode) -> None:
        self.errors_body.clear()
        reports = log.errors(limit=10)
        if not reports:
            self.errors_body.add(Text(
                "Nothing has failed. Failures are written here with a full "
                "traceback and a reference you can quote.",
                "body", theme.INK_SOFT, mode, wrap=True))
            return
        for report in reports:
            self.errors_body.add(Field(report.error_id, report.message, mode))
            detail = report.at.replace("T", " ").replace("Z", " UTC")
            if report.exception_type:
                detail += f"  -  {report.exception_type}: {report.exception_text[:120]}"
            self.errors_body.add(Text(detail, "small", theme.MUTED, mode, wrap=True))
            self.errors_body.add(Rule())

    def _fill_talk(self, mode: Mode) -> None:
        self.talk_body.clear()
        exchanges = logs.transcript().recent(limit=8)
        if not exchanges:
            self.talk_body.add(Text(
                "No exchanges yet. With no model installed the built-in planner "
                "decides instead, and there is no conversation to record - the "
                "Model page says which is happening here.",
                "body", theme.INK_SOFT, mode, wrap=True))
            return

        for exchange in exchanges:
            self.talk_body.add(Field(
                exchange.at.replace("T", " ").replace("Z", ""), exchange.headline(), mode))
            if exchange.model:
                self.talk_body.add(Text(exchange.model, "small", theme.MUTED, mode))
            if exchange.accepted:
                self.talk_body.add(Text(
                    "Accepted: " + ", ".join(exchange.accepted),
                    "small", theme.MUTED, mode, wrap=True))
            for control_id, why in list(exchange.rejected.items())[:4]:
                self.talk_body.add(Text(f"Refused {control_id} - {why}", "small", theme.MUTED, mode, wrap=True))
            self.talk_body.add(Rule())

    # -- actions --------------------------------------------------------

    def open_folder(self) -> None:
        path = logs.get().dir
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", str(path)], check=False)
            else:
                subprocess.run(["xdg-open", str(path)], check=False)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.information(self, "Log folder", f"The log is at {path}\n\n{exc}")

    def export_transcript(self) -> None:
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(
            self, "Export the conversation", "lares-conversation.md", "Markdown (*.md)")
        if not path:
            return
        try:
            Path(path).write_text(logs.transcript().as_markdown(limit=50), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Export", f"Could not write {path}: {exc}")
            return
        QMessageBox.information(self, "Export", f"Written to {path}")


def _level_colour(level: logs.Level):
    return {
        logs.Level.ERROR: theme.STATUS.get("failed", theme.NEUTRAL),
        logs.Level.WARN: theme.STATUS.get("rolled_back", theme.NEUTRAL),
    }.get(level, theme.MUTED)


class CataloguePage(Page):
    def __init__(self, window: Window) -> None:
        super().__init__(window, "Catalogue",
                         "Everything Lares is able to do, written and reviewed by "
                         "hand. The model chooses from this list; it cannot add to it.")
        mode = window.mode
        card = Card(mode)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Control", "Domain", "Severity", "Risk of the fix", "Unattended", "Title"])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.currentCellChanged.connect(lambda *_: self.show_detail())
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        for col in range(5):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setFixedHeight(330)
        card.add(self.table)
        self.outer.addWidget(card)

        self.detail = Card(mode)
        self.detail_title = Text("", "title", theme.INK, mode, wrap=True)
        self.detail_why = Text("", "body", theme.INK_SOFT, mode, wrap=True)
        self.detail_cost_label = widgets.heading("What it costs", mode)
        self.detail_cost = Text("", "body", theme.INK_SOFT, mode, wrap=True)
        self.detail.add(self.detail_title)
        self.detail.add(self.detail_why)
        self.detail.add(self.detail_cost_label)
        self.detail.add(self.detail_cost)
        self.outer.addWidget(self.detail)
        self.outer.addStretch(1)

        self.fill()

    def fill(self) -> None:
        window = self.window_ref
        mode = window.mode
        controls = [c for d in window.catalog.domains for c in window.catalog.in_domain(d)]
        self._controls = controls
        self.table.setRowCount(len(controls))
        for row, control in enumerate(controls):
            unattended = ("yes" if control.autonomy_eligible
                          else "no, report only" if not control.has_remediation
                          else "no, needs a person")
            cells = [control.id, control.domain, control.severity.value,
                     control.risk.value, unattended, control.title]
            for col, value in enumerate(cells):
                item = QTableWidgetItem(value)
                if col == 2:
                    item.setForeground(theme.SEVERITY[control.severity.value].q(mode))
                if col == 3:
                    item.setForeground(theme.RISK[control.risk.value].q(mode))
                if col == 4:
                    item.setForeground(theme.MUTED.q(mode))
                self.table.setItem(row, col, item)
        if controls:
            self.table.setCurrentCell(0, 0)

    def show_detail(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._controls):
            return
        control = self._controls[row]
        self.detail_title.setText(f"{control.id} - {control.title}")
        self.detail_why.setText(" ".join(control.rationale.split()))
        cost = " ".join(control.blast_radius.split())
        self.detail_cost.setText(cost or "No change is made by this control.")


class ModelPage(Page):
    def __init__(self, window: Window) -> None:
        super().__init__(window, "Model",
                         "The model runs on this machine, on the processor, with no "
                         "network involved. Which one depends on what the machine can carry.")
        mode = window.mode

        status = Card(mode, accent=True)
        status.add(widgets.heading("Running now", mode))
        self.status_text = Text(window.model_note, "body", theme.INK, mode, wrap=True)
        status.add(self.status_text)
        hardware = models.measure()
        status.add(Field("This machine", hardware.describe(), mode))
        status.add(Field("Threads", str(hardware.threads), mode))
        self.outer.addWidget(status)

        ladder = Card(mode)
        ladder.add(widgets.heading("The ladder", mode))
        for spec in models.LADDER:
            row = Row()
            row.add(Text(spec.name, "body", theme.INK, mode))
            row.spacer()
            state = "installed" if spec.path.exists() else f"{spec.size_mb} MB"
            row.add(Text(state, "small", theme.MUTED, mode))
            row.add(Text(spec.expect_tps, "small", theme.MUTED, mode))
            ladder.add(row)
            ladder.add(Text(spec.note, "small", theme.MUTED, mode, wrap=True))
            ladder.add(Rule())
        self.outer.addWidget(ladder)

        prefs = Card(mode)
        prefs.add(widgets.heading("Settings", mode))

        row = Row()
        row.add(Text("Autonomy ceiling", "body", theme.INK, mode))
        row.spacer()
        self.ceiling = QComboBox()
        self.ceiling.addItems([t.value for t in RiskTier])
        self.ceiling.setCurrentText(window.settings.ceiling)
        self.ceiling.currentTextChanged.connect(self._save_ceiling)
        row.add(self.ceiling)
        prefs.add(row)
        prefs.add(Text(
            "'caution' is the default. 'intrusive' also lets Lares change how the "
            "machine is reached - remote access, the accounts that can sign in - "
            "which a health check cannot always tell has gone wrong.",
            "small", theme.MUTED, mode, wrap=True))

        row = Row()
        row.add(Text("Minutes between checks", "body", theme.INK, mode))
        row.spacer()
        self.interval = QSpinBox()
        self.interval.setRange(5, 10080)
        self.interval.setValue(window.settings.interval_minutes)
        self.interval.valueChanged.connect(self._save_interval)
        row.add(self.interval)
        prefs.add(row)

        row = Row()
        row.add(Text("Appearance", "body", theme.INK, mode))
        row.spacer()
        self.theme_box = QComboBox()
        self.theme_box.addItems(["auto", "light", "dark"])
        self.theme_box.setCurrentText(window.settings.theme)
        self.theme_box.currentTextChanged.connect(window.set_theme)
        row.add(self.theme_box)
        prefs.add(row)

        self.outer.addWidget(prefs)
        self.outer.addStretch(1)

    def _save_ceiling(self, value: str) -> None:
        self.window_ref.settings.ceiling = value
        config_mod.save(self.window_ref.settings)

    def _save_interval(self, value: int) -> None:
        self.window_ref.settings.interval_minutes = value
        config_mod.save(self.window_ref.settings)


class ColophonPage(Page):
    def __init__(self, window: Window) -> None:
        super().__init__(window, "Colophon",
                         "How this was built, and what it does not claim.")
        mode = window.mode
        types = theme.build_type()

        limits = Card(mode, wash=True)
        limits.add(widgets.heading("What Lares does not tell you", mode))
        limits.add(Text(
            "It will never say this machine is secure. It checks "
            f"{len(window.catalog)} specific things, and when they all pass what "
            "that means is that those {0} things pass. There are settings it does "
            "not look at, software it cannot see inside, and whole categories of "
            "attack that no configuration check would catch.".format(len(window.catalog)),
            "body", theme.INK, mode, wrap=True))
        limits.add(Text(
            "It also leaves some findings alone on purpose. Encrypting the disk, "
            "removing an administrator, installing updates - those are decisions "
            "with consequences a health check cannot measure, so it reports them "
            "and stops.", "body", theme.INK, mode, wrap=True))
        self.outer.addWidget(limits)

        build_card = Card(mode)
        build_card.add(widgets.heading("The name", mode))
        build_card.add(Text(ETYMOLOGY, "body", theme.INK_SOFT, mode, wrap=True))
        build_card.add(Rule())
        build_card.add(widgets.heading("Typefaces", mode))
        build_card.add(Text(
            f"{types['display'].family} for the headings and figures, "
            f"{types['body'].family} for the controls, "
            f"{types['mono'].family} for anything the machine itself said. "
            "The accent is a deep brass, dark enough to be read as small text on "
            "paper; a second, brighter gold marks things that carry no words.",
            "body", theme.INK_SOFT, mode, wrap=True))
        build_card.add(Rule())
        build_card.add(widgets.heading("Build", mode))
        build_card.add(Field("Version", VERSION, mode))
        build_card.add(Field("Catalogue", f"{len(window.catalog)} controls, "
                                          f"digest {window.catalog.digest[:12]}", mode))
        build_card.add(Field("Signed in as", current_user(), mode))
        build_card.add(Field("Elevated", "yes" if is_elevated() else "no", mode))
        build_card.add(Field("Mode", "demo, nothing is changed" if is_demo()
                             else "live", mode))
        self.outer.addWidget(build_card)
        self.outer.addStretch(1)
