import jwt
import time
import json
import enum
import yc_lockbox._constants as C

from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Any, TypeVar
from yc_lockbox._exceptions import InvalidCredentials

T = TypeVar("T")


@enum.unique
class CredentialsType(str, enum.Enum):
    IAM_TOKEN = "IAM_TOKEN"  # nosec B105
    OAUTH_TOKEN = "OAUTH_TOKEN"  # nosec B105
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"  # nosec B105

    @staticmethod
    def allowed_types(stringify: bool = False) -> list | str:
        """
        Returns allowed credentials types.

        :param stringify: Return as string instead list.
        """
        types_ = [name for name, _ in CredentialsType.__members__.items()]

        if stringify:
            return ", ".join(types_)
        return types_


class AbstractHTTPAdapter(ABC):
    """An abstract adapter for make HTTP requests to Yandex Cloud."""

    @staticmethod
    @abstractmethod
    def request(
        method: str,
        url: str,
        data: str | bytes | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        response_model: T | None = None,
        raise_for_status: bool = True,
        **kwargs,
    ) -> Any:
        raise NotImplementedError  # pragma: no cover


class AbstractYandexLockboxClient(ABC):
    """An abstract class for operate with Yandex Lockbox service."""

    def __init__(
        self,
        lockbox_base_url: str | None = None,
        payload_lockbox_base_url: str | None = None,
        **kwargs,
    ) -> None:
        self.lockbox_base_url = lockbox_base_url or C.YC_LOCKBOX_BASE_URL
        self.payload_lockbox_base_url = payload_lockbox_base_url or C.YC_LOCKBOX_PAYLOAD_BASE_URL

    @abstractmethod
    def activate_secret(self, *args, **kwargs) -> T | Any:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def add_secret_version(self, *args, **kwargs) -> T | Any:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def create_secret(self, *args, **kwargs) -> T:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def cancel_secret_version_destruction(self, *args, **kwargs) -> T | Any:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def deactivate_secret(self, *args, **kwargs) -> T | Any:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def delete_secret(self, *args, **kwargs) -> Any:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def get_secret(self, secret_id: str, *args, **kwargs) -> T:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def get_secret_payload(self, *args, **kwargs) -> T:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def list_secrets(self, *args, **kwargs) -> list[T]:
        raise NotImplementedError

    @abstractmethod
    def list_secret_access_bindings(self, *args, **kwargs) -> T | Any:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def list_secret_operations(self, *args, **kwargs) -> list[T] | list[Any]:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def list_secret_versions(self, *args, **kwargs) -> list[T] | list[Any]:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def schedule_secret_version_destruction(self, *args, **kwargs) -> T | Any:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def set_secret_access_bindings(self, *args, **kwargs) -> T | Any:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def update_secret(self, *args, **kwargs) -> T:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def update_secret_access_bindings(self, *args, **kwargs) -> T | Any:
        raise NotImplementedError  # pragma: no cover


class AbstractYandexAuthClient(ABC):
    """An abstract class for authenticate requests for the Yandex.Cloud."""

    def __init__(
        self,
        credentials: str | dict[str, str],
        *,
        auth_base_url: str | None = None,
        **kwargs,
    ) -> None:
        self.credentials = credentials
        self.auth_base_url = auth_base_url or C.YC_IAM_BASE_URL

        self.iam_token: str | None = None
        self._credentials_type: CredentialsType = self._detect_credentials_type()

    @property
    @abstractmethod
    def adapter(self) -> AbstractHTTPAdapter:
        """An abstract property that returns sync or async adapter for HTTP requests."""
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def get_iam_token(self) -> str:
        """An abstract method for get IAM token from Yandex.Cloud."""
        raise NotImplementedError  # pragma: no cover

    def get_auth_headers(self) -> dict[str, str]:
        """Returns auth headers as dict."""
        token = self.get_iam_token()
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    def is_sa_key(credentials: Any) -> bool:
        """
        A predicate that tells whether the credentials is a service account key.

        :param credentials: Credentials to verify.
        """
        mandatory_attributes = (
            "id",
            "service_account_id",
            "created_at",
            "key_algorithm",
            "public_key",
            "private_key",
        )
        if isinstance(credentials, str):
            try:
                credentials = json.loads(credentials)
            except json.JSONDecodeError:
                credentials = {}

        if isinstance(credentials, dict):
            return all([credentials.get(field) for field in mandatory_attributes])

        return False

    @staticmethod
    def is_iam_token(credentials: Any) -> bool:
        """
        A predicate that tells whether the credentials is a IAM token.

        :param credentials: Credentials to verify.
        """
        if not isinstance(credentials, str):
            return False

        return C.IAM_TOKEN_REGEX.match(credentials)

    @staticmethod
    def is_oauth_token(credentials: Any) -> bool:
        """
        A predicate that tells whether the credentials is a OAuth token.

        :param credentials: Credentials to verify.
        """
        if not isinstance(credentials, str):
            return False

        return C.OAUTH_TOKEN_REGEX.match(credentials) or C.LEGACY_OAUTH_TOKEN_REGEX.match(credentials)

    def _detect_credentials_type(self) -> CredentialsType:
        """Detect and verify credentials type."""
        if self.is_iam_token(self.credentials):
            return CredentialsType.IAM_TOKEN
        elif self.is_sa_key(self.credentials):
            return CredentialsType.SERVICE_ACCOUNT
        elif self.is_oauth_token(self.credentials):
            return CredentialsType.OAUTH_TOKEN

        raise InvalidCredentials(
            f"Invalid credentials. Allowed types: {CredentialsType.allowed_types(stringify=True)}"
        )

    @lru_cache(maxsize=1)
    def _generate_jwt_for_sa(self, aud_path: str = "/iam/v1/tokens") -> str:
        """
        Prepare JWT for request IAM token from service account key.

        :param aud_path: URL path for JWT payload ``aud``.
        """

        if self._credentials_type != CredentialsType.SERVICE_ACCOUNT or not isinstance(self.credentials, dict):
            raise InvalidCredentials(f"Can't generate JWT, invalid credentials type: {self._credentials_type}")

        now = int(time.time())
        sa_id = self.credentials.get("service_account_id")
        key_id = self.credentials.get("id")
        private_key = self.credentials.get("private_key")

        payload = {
            "iss": sa_id,
            "aud": self.auth_base_url + aud_path,
            "iat": now,
            "exp": now + 360,
        }

        headers = {
            "typ": "JWT",
            "alg": C.JWT_ALGORITHM,
            "kid": key_id,
        }

        return jwt.encode(payload, private_key, algorithm=C.JWT_ALGORITHM, headers=headers)
