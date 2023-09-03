import sys

import icupy.icu as icu
import pytest


def pytest_html_report_title(report):
    package = "urlstd"
    title = "web-platform-tests: " + package
    if sys.version_info[:2] >= (3, 8):
        from importlib.metadata import version

        title += " " + version(package)
    title += " with ICU " + icu.U_ICU_VERSION
    report.title = title


def pytest_html_results_table_header(cells):
    cells.insert(2, "<th>Description</th>")
    cells.pop()


def pytest_html_results_table_row(report, cells):
    cells.insert(2, f"<td>{report.description}</td>")
    cells.pop()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    del call
    outcome = yield
    report = outcome.get_result()
    report.description = item.function.__doc__ or ""
