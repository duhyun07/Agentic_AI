import httpx
import pytest

from app.analysis.clova_client import ClovaStudioClient

CHAT_RESPONSE = {
    "result": {
        "message": {
            "content": '{"bug_type": "use-after-free", "summary": "ext4 UAF on unmount", "severity": "high"}'
        }
    }
}

EMBEDDING_RESPONSE = {"result": {"embedding": [0.1] * 1024}}


def test_classify_crash_parses_json_response(httpx_mock):
    httpx_mock.add_response(
        url="https://clovastudio.stream.ntruss.com/testapp/v3/chat-completions/HCX-005",
        json=CHAT_RESPONSE,
    )
    client = ClovaStudioClient(
        base_url="https://clovastudio.stream.ntruss.com",
        api_key="test-key",
        request_id="test-req",
        http_client=httpx.Client(),
    )

    result = client.classify_crash("BUG: KASAN: use-after-free in ext4_put_super")

    assert result["bug_type"] == "use-after-free"
    assert result["severity"] == "high"


def test_embed_returns_vector_of_configured_dim(httpx_mock):
    httpx_mock.add_response(
        url="https://clovastudio.stream.ntruss.com/testapp/v1/api-tools/embedding/v2",
        json=EMBEDDING_RESPONSE,
    )
    client = ClovaStudioClient(
        base_url="https://clovastudio.stream.ntruss.com",
        api_key="test-key",
        request_id="test-req",
        http_client=httpx.Client(),
    )

    vector = client.embed("ext4 use-after-free")

    assert len(vector) == 1024
