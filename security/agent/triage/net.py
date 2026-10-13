"""Petit client HTTP JSON (bibliothèque standard uniquement)."""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request

MAX_RESPONSE_BYTES = 2_000_000


class HttpError(Exception):
    """Message volontairement court : ni URL, ni en-têtes, ni corps (ils peuvent contenir un token)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Une redirection renverrait le token vers un autre hôte : on les refuse toutes."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def request_json(method: str, url: str, headers: dict, body: dict | None = None, timeout: int = 30):
    if not url.startswith("https://"):
        raise HttpError("URL refusée : HTTPS obligatoire")
    request = urllib.request.Request(
        url,
        data=None if body is None else json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method=method,
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return json.loads(response.read(MAX_RESPONSE_BYTES))
    except urllib.error.HTTPError as exc:
        raise HttpError(f"HTTP {exc.code}") from None
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        raise HttpError(f"appel impossible ({type(exc).__name__})") from None
