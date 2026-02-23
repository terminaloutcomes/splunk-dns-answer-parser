from __future__ import annotations

import pytest


@pytest.fixture(name="sample_dns_b64")
def fixture_sample_dns_b64() -> str:
    return (
        "K5uBgAABAAAAAQAACGFjY291bnRzBmdvb2dsZQNjb20AAEEAAcAVAAYAAQAAADYAJgNuczHAFQlkbnMt"
        "YWRtaW7AFTQNRnMAAAOEAAADhAAABwgAAAA8"
    )
