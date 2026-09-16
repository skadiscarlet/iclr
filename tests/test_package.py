import tomllib
from pathlib import Path

from egsi import __version__
from egsi.cli import app


def test_package_version():
    assert __version__ == "0.1.0"


def test_cli_app_is_callable():
    assert callable(app)


def test_project_version_matches_package_version():
    pyproject = tomllib.loads(Path("pyproject.toml").read_text())
    assert pyproject["project"]["version"] == __version__
