import time

import httpx


class RetryingClient:
    def __init__(self, client: httpx.Client, max_retries: int = 3, base_delay: float = 1.0):
        self._client = client
        self._max_retries = max_retries
        self._base_delay = base_delay

    def get(self, url: str, **kwargs) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = self._client.get(url, **kwargs)
                if response.status_code == 429:
                    time.sleep(self._base_delay * (2**attempt))
                    continue
                response.raise_for_status()
                return response
            except httpx.HTTPError as exc:
                last_exc = exc
                time.sleep(self._base_delay * (2**attempt))
        raise RuntimeError(f"GET {url} failed after {self._max_retries} retries") from last_exc
