"""SBOM parsers — produce a list of (ecosystem, name, version, purl).

Supported inputs:
  - Python `requirements.txt` (PEP 508 — best-effort)
  - npm `package.json` (deps + devDeps)
  - CycloneDX JSON (`bomFormat == "CycloneDX"`)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from packageurl import PackageURL


@dataclass
class SBOMComponent:
    ecosystem: str
    name: str
    version: str | None
    purl: str

    @classmethod
    def make(cls, ecosystem: str, name: str, version: str | None) -> "SBOMComponent":
        ptype = {"PyPI": "pypi", "npm": "npm"}.get(ecosystem, ecosystem.lower())
        purl = PackageURL(type=ptype, name=name.lower(), version=version).to_string()
        return cls(ecosystem=ecosystem, name=name.lower(), version=version, purl=purl)


_REQ_RE = re.compile(
    r"""^
    \s*
    (?P<name>[A-Za-z0-9_.\-]+)
    (?:\s*\[[^\]]*\])?
    \s*
    (?:
        (?P<op>==|>=|<=|~=|!=|>|<)
        \s*
        (?P<version>[A-Za-z0-9_.\-+!*]+)
    )?
    """,
    re.VERBOSE,
)


def parse_requirements_txt(text: str) -> list[SBOMComponent]:
    out: list[SBOMComponent] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "#")):
            continue
        if line.startswith(("git+", "http://", "https://", "file:")):
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        name = m.group("name")
        op = m.group("op")
        version = m.group("version") if op == "==" else None
        out.append(SBOMComponent.make("PyPI", name, version))
    return out


def parse_package_json(text: str) -> list[SBOMComponent]:
    obj = json.loads(text)
    out: list[SBOMComponent] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = obj.get(key) or {}
        for name, spec in deps.items():
            version: str | None = None
            if isinstance(spec, str):
                # Strip range operators for an approximate matched version
                m = re.search(r"\d+(\.\d+){0,3}", spec)
                if m:
                    version = m.group(0)
            out.append(SBOMComponent.make("npm", name, version))
    return out


def parse_cyclonedx(text: str) -> list[SBOMComponent]:
    obj = json.loads(text)
    if obj.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX SBOM")
    out: list[SBOMComponent] = []
    for c in obj.get("components", []) or []:
        purl = c.get("purl")
        if purl:
            try:
                pu = PackageURL.from_string(purl)
                eco = {"pypi": "PyPI", "npm": "npm"}.get(pu.type, pu.type)
                out.append(SBOMComponent(ecosystem=eco, name=pu.name, version=pu.version, purl=purl))
                continue
            except ValueError:
                pass
        name = c.get("name")
        version = c.get("version")
        eco = c.get("group") or "generic"
        if name:
            out.append(SBOMComponent.make(eco, name, version))
    return out


def parse_sbom(path: str | Path) -> list[SBOMComponent]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    name = p.name.lower()
    if name.endswith("requirements.txt") or name == "requirements.txt":
        return parse_requirements_txt(text)
    if name == "package.json":
        return parse_package_json(text)
    # Try CycloneDX, then fall back to requirements heuristics
    try:
        return parse_cyclonedx(text)
    except (ValueError, json.JSONDecodeError):
        pass
    return parse_requirements_txt(text)
