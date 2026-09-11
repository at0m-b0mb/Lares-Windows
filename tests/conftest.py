"""Shared test setup.

The theme resolves real font families, which needs a Qt application to exist
before ``QFontDatabase`` will answer. Creating one offscreen lets the whole
desktop layer - tokens, widgets, window construction - be tested in CI with no
display attached, which is also how the screenshots are taken.
"""

from __future__ import annotations

import os

import pytest

# Must be set before Qt is imported anywhere.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Every test runs against the synthetic machine rather than whatever the host
# happens to be, so results do not depend on where the suite is run.
os.environ.setdefault("LARES_DEMO", "1")


@pytest.fixture(scope="session")
def qt_app():
    """One offscreen QApplication for the whole session.

    Qt does not support creating a second QApplication in a process, so this is
    session-scoped and reused rather than built per test.
    """
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    yield app


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """Keep tests from reading or writing the real journal and settings."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    from lares import demo_data
    demo_data.reset_fixed()
    yield
    demo_data.reset_fixed()
