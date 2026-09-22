import pytest
from pydantic import ValidationError

from app.config import Settings


def test_settings_default_embedding_dim():
    s = Settings()
    assert s.embedding_dim == 1024


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("EMBEDDING_DIM", "2048")
    s = Settings()
    assert s.embedding_dim == 2048


@pytest.mark.parametrize("field", ["clova_api_key", "github_token", "nvd_api_key"])
def test_settings_rejects_placeholder_credential(field):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: "changeme"})
