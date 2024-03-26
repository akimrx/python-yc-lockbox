import pytest
import requests_mock
from typing import Any, Generator

from yc_lockbox import YandexLockboxClient


@pytest.fixture
def lockbox_client() -> YandexLockboxClient:
    return YandexLockboxClient(
        "t1.9exxlZrHlpKalJKVkM-.IvgNiLOPTh7FkZC3n6oi_y2lIc27gOByJ4QfVZKtccYso8U6MKeIZxe4LIyRosTSKEwYiZdV28C8zAIMaKcsAA"  # fake, don't get your hopes up
    )


@pytest.fixture
def requests_mocker() -> Generator[Any, Any, requests_mock.Mocker]:
    with requests_mock.Mocker() as m:
        yield m
