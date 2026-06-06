from pathlib import Path

from sentinel.match.sbom import (
    parse_package_json,
    parse_requirements_txt,
    parse_sbom,
)


def test_requirements_pinned():
    out = parse_requirements_txt("django==3.2.0\nflask>=1.0\n# comment\n\nrequests==2.20.0")
    by_name = {c.name: c for c in out}
    assert by_name["django"].version == "3.2.0"
    assert by_name["flask"].version is None  # only `==` is captured
    assert by_name["requests"].version == "2.20.0"
    assert all(c.ecosystem == "PyPI" for c in out)
    assert all(c.purl.startswith("pkg:pypi/") for c in out)


def test_package_json_extracts_versions():
    text = '{"dependencies": {"express": "^4.16.0", "lodash": "4.17.10"}, "devDependencies": {"webpack": "^4.0.0"}}'
    out = parse_package_json(text)
    by_name = {c.name: c for c in out}
    assert by_name["express"].version == "4.16.0"
    assert by_name["lodash"].version == "4.17.10"
    assert by_name["webpack"].version == "4.0.0"
    assert all(c.ecosystem == "npm" for c in out)


def test_parse_sbom_dispatches_by_filename(tmp_path: Path):
    rt = tmp_path / "requirements.txt"
    rt.write_text("django==3.2.0\n")
    items = parse_sbom(rt)
    assert items[0].ecosystem == "PyPI" and items[0].name == "django"

    pj = tmp_path / "package.json"
    pj.write_text('{"dependencies": {"express": "4.16.0"}}')
    items = parse_sbom(pj)
    assert items[0].ecosystem == "npm" and items[0].name == "express"
