import pytest
from aioresponses import aioresponses

from yc_lockbox import AsyncYandexLockboxClient


@pytest.fixture
def lockbox_client() -> AsyncYandexLockboxClient:
    return AsyncYandexLockboxClient(
        "t1.9exxlZrHlpKalJKVkM-.IvgNiLOPTh7FkZC3n6oi_y2lIc27gOByJ4QfVZKtccYso8U6MKeIZxe4LIyRosTSKEwYiZdV28C8zAIMaKcsAA"  # fake, don't get your hopes up
    )


@pytest.fixture
def aio_requests_mocker():
    with aioresponses() as m:
        yield m
