from typing import Any, Coroutine, TypeAlias, TypeVar, TYPE_CHECKING, Union
from pydantic import BaseModel

if TYPE_CHECKING:
    from yc_lockbox._models import YandexLockboxResponse, YandexLockboxError

T = TypeVar("T", bound=BaseModel)

YandexCloudGenericResponse: TypeAlias = (
    Coroutine[Any, Any, Union["YandexLockboxResponse", "YandexLockboxError"]]
    | Union["YandexLockboxResponse", "YandexLockboxError"]
)
