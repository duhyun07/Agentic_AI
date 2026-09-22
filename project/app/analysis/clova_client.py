import json

import httpx

from app.config import get_settings


class ClovaStudioClient:
    """CLOVA Studio HCX-005 chat-completions / embedding v2 API 래퍼.

    엔드포인트는 실제 발급받은 테스트 API 키로 검증되었다: chat-completions는
    v1이 아닌 v3 경로("/testapp/v3/chat-completions/HCX-005")를 사용해야
    200을 반환한다(v1 경로는 "Unsupported API for model" 40084 에러).
    embedding v2 경로("/testapp/v1/api-tools/embedding/v2")는 문서에 적힌
    그대로 동작하며, 반환 벡터 길이는 EMBEDDING_DIM(1024)과 일치한다.
    """

    def __init__(self, base_url: str, api_key: str, request_id: str, http_client: httpx.Client):
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "X-NCP-CLOVASTUDIO-REQUEST-ID": request_id,
            "Content-Type": "application/json",
        }
        self._client = http_client

    def classify_crash(self, raw_log: str) -> dict:
        url = f"{self._base_url}/testapp/v3/chat-completions/HCX-005"
        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a Linux kernel crash triage assistant. "
                        "Given a crash log, respond ONLY with JSON: "
                        '{"bug_type": str, "summary": str, "severity": "low"|"medium"|"high"}'
                    ),
                },
                {"role": "user", "content": raw_log},
            ]
        }
        response = self._client.post(url, headers=self._headers, json=payload)
        response.raise_for_status()
        content = response.json()["result"]["message"]["content"]
        return json.loads(content)

    def embed(self, text: str) -> list[float]:
        url = f"{self._base_url}/testapp/v1/api-tools/embedding/v2"
        response = self._client.post(url, headers=self._headers, json={"text": text})
        response.raise_for_status()
        vector = response.json()["result"]["embedding"]
        expected_dim = get_settings().embedding_dim
        if len(vector) != expected_dim:
            raise ValueError(
                f"CLOVA embedding API returned a {len(vector)}-dim vector, "
                f"expected {expected_dim} (EMBEDDING_DIM); refusing to store a mismatched vector"
            )
        return vector
