from typing import Any, AsyncGenerator, Coroutine, Iterator, TypeAlias, TypeVar, TYPE_CHECKING, Union
from pydantic import BaseModel

if TYPE_CHECKING:  # pragma: no cover
    from yc_lockbox._models import Operation, SecretVersion, SecretVersionsList, YandexCloudError

T = TypeVar("T", bound=BaseModel)

YandexCloudGenericResponse: TypeAlias = (
    Union["Operation", "YandexCloudError"] | Coroutine[Any, Any, Union["Operation", "YandexCloudError"]]
)  # pragma: no cover


SecretVersionsResponse = Union[
    "SecretVersionsList", Iterator["SecretVersion"], AsyncGenerator[Any, "SecretVersion"], "YandexCloudError"
]  # pragma: no cover
