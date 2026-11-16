"""Certificate Transparency discovery through the public crt.sh endpoint."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from dr4c.core.scope import normalize_domain


def crtsh(domain: str, timeout: int = 10) -> tuple[list[str], str | None]:
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    request = urllib.request.Request(
        f"https://crt.sh/?{query}", headers={"User-Agent": "DR4C/0.1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            rows = json.loads(response.read(5_000_001))
        names = set()
        for row in rows:
            for raw in row.get("name_value", "").splitlines():
                name = raw.strip().lower().removeprefix("*.").rstrip(".")
                try:
                    normalized = normalize_domain(name)
                except ValueError:
                    continue
                if normalized == domain or normalized.endswith("." + domain):
                    names.add(normalized)
        return sorted(names), None
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        return [], f"crt.sh unavailable: {exc}"
