"""Curated list of high-traffic Python + npm packages we probe OSV with.

Replace with the union of all WatchlistComponents at runtime to cover every
package the user actually cares about — for Week 1 we ship a sensible default.
"""

from __future__ import annotations

PYPI = [
    "django", "flask", "fastapi", "requests", "urllib3", "cryptography",
    "pyyaml", "jinja2", "werkzeug", "sqlalchemy", "pillow", "numpy", "pandas",
    "tornado", "twisted", "lxml", "pyjwt", "pycryptodome", "boto3", "celery",
    "scikit-learn", "tensorflow", "torch", "transformers", "openai", "anthropic",
    "httpx", "aiohttp", "starlette", "pydantic", "ansible", "paramiko",
]

NPM = [
    "express", "react", "next", "vue", "angular", "axios", "lodash", "underscore",
    "moment", "jsonwebtoken", "passport", "socket.io", "ws", "node-fetch",
    "request", "minimist", "yargs", "commander", "webpack", "vite", "esbuild",
    "typescript", "babel-core", "rollup", "browserify", "graphql", "apollo-server",
    "mongoose", "sequelize", "prisma", "puppeteer", "playwright",
]

PROBE_PACKAGES: list[tuple[str, str]] = [
    *(("PyPI", n) for n in PYPI),
    *(("npm", n) for n in NPM),
]
