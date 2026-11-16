"""Small, dependency-free reader for DR4C's documented default YAML subset."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Config:
    http_timeout_seconds: int = 10
    http_max_concurrency: int = 10
    http_max_response_bytes: int = 1_048_576
    http_max_requests: int = 500


def load_config(path: str | Path) -> Config:
    """Parse the scalar nested YAML used by configs/default.yaml; reject unknown keys."""
    values: dict[str, int] = {}
    section = ""
    for number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0 and line.endswith(":"):
            section = line[:-1]
            if section not in ("http", "dns"):
                raise ValueError(f"unknown config section on line {number}: {section}")
            continue
        if indent != 2 or ":" not in line:
            raise ValueError(f"invalid config syntax on line {number}")
        key, raw_value = (part.strip() for part in line.split(":", 1))
        full_key = f"{section}_{key}"
        if full_key not in Config.__dataclass_fields__:
            raise ValueError(f"unknown config key on line {number}: {full_key}")
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise ValueError(f"config value must be an integer on line {number}") from exc
        values[full_key] = value
    config = Config(**values)
    if not 1 <= config.http_timeout_seconds <= 120:
        raise ValueError("http.timeout_seconds must be between 1 and 120")
    if not 1 <= config.http_max_concurrency <= 100:
        raise ValueError("http.max_concurrency must be between 1 and 100")
    if not 1024 <= config.http_max_response_bytes <= 16 * 1024 * 1024:
        raise ValueError("http.max_response_bytes must be between 1 KiB and 16 MiB")
    if not 1 <= config.http_max_requests <= 5_000:
        raise ValueError("http.max_requests must be between 1 and 5000")
    return config
