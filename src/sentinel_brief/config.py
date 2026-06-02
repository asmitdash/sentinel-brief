from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    db_url: str
    nvd_api_key: str | None
    github_token: str | None
    aws_region: str
    bedrock_model_id: str
    log_level: str
    data_dir: Path

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.getenv("SENTINEL_DATA_DIR", "./data")).resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            db_url=os.getenv("SENTINEL_DB_URL", f"sqlite+pysqlite:///{data_dir / 'sentinel.db'}"),
            nvd_api_key=os.getenv("NVD_API_KEY") or None,
            github_token=os.getenv("GITHUB_TOKEN") or None,
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            bedrock_model_id=os.getenv(
                "BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0"
            ),
            log_level=os.getenv("SENTINEL_LOG_LEVEL", "INFO"),
            data_dir=data_dir,
        )


settings = Settings.from_env()
