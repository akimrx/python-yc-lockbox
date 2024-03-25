import logging
from functools import cached_property
from datetime import datetime

from yc_lockbox._abc import AbstractYandexAuthClient, CredentialsType
from yc_lockbox._exceptions import BadCredentials
from yc_lockbox._adapters import HTTPAdapter
from yc_lockbox._models import IamTokenResponse

logger = logging.getLogger(__name__)


class YandexAuthClient(AbstractYandexAuthClient):
    """
    This is a simple client that allows you to get an up-to-date IAM token
    to make authenticated requests to Yandex Cloud.
    If you pass a IAM token as credentials, you need to take care
    of the freshness of the token yourself.

    :param credentials: Credentials for authenticate requests.
        Allowed types: service account key, OAuth token, IAM token.
    :param auth_base_url: Base IAM url without resource path URL.

    .. note::

        Important.
        This client works only in synchronous mode for backward compatibility.
    """

    def __init__(
        self,
        credentials: str | dict[str, str],
        *,
        auth_base_url: str | None = None,
        **kwargs,
    ) -> None:
        super().__init__(credentials, auth_base_url=auth_base_url, **kwargs)
        self.iam_expires_at = 0.0
        self.iam_token_url_path = self.auth_base_url + "/iam/v1/tokens"

    @cached_property
    def adapter(self) -> HTTPAdapter:
        """Returns HTTP adapter for communicate with Yandex Cloud."""
        return HTTPAdapter

    def get_iam_token(self) -> str:
        """Cacheable (in-memory, per instance) method for get IAM token from Yandex Cloud."""
        if self._credentials_type == CredentialsType.IAM_TOKEN:
            return self.credentials

        if self.iam_token is not None and self.iam_expires_at >= datetime.now().timestamp():
            # returns cached token
            return self.iam_token

        try:
            if self._credentials_type == CredentialsType.SERVICE_ACCOUNT:
                body = {"jwt": self._generate_jwt_for_sa()}
                response = self.adapter.request(
                    "POST", self.iam_token_url_path, json=body, response_model=IamTokenResponse
                )
                self.iam_token = response.token
                self.iam_expires_at = response.expires_at.timestamp()
                return self.iam_token

            elif self._credentials_type == CredentialsType.OAUTH_TOKEN:
                body = {"yandexPassportOauthToken": self.credentials}
                response = self.adapter.request(
                    "POST", self.iam_token_url_path, json=body, response_model=IamTokenResponse
                )
                self.iam_token = response.token
                self.iam_expires_at = response.expires_at.timestamp()
                return self.iam_token

        except Exception:
            raise BadCredentials("Bad credentials, can't issue IAM token.")
