import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class APIError(RuntimeError):
    """An HTTP error from the TRAPSIG API, carrying the server's ``detail``."""

    def __init__(self, status: int, detail: str, url: str) -> None:
        super().__init__(f"HTTP {status} from {url}: {detail}")
        self.status, self.detail = status, detail


def request_json(url: str, method: str = "GET", data: dict | None = None):
    body = json.dumps(data).encode() if data is not None else None
    request = Request(url, data=body, method=method, headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=90) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        text = exc.read().decode("utf-8", "replace")
        try:
            detail = json.loads(text).get("detail", text)
        except (ValueError, AttributeError):
            detail = text
        raise APIError(exc.code, str(detail)[:500], url) from exc


def request_text(url: str) -> str:
    with urlopen(url, timeout=90) as response:
        return response.read().decode()
