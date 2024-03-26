import logging
from typing import Type, Optional, Callable, Iterator

from yc_lockbox._abc import AbstractYandexAuthClient, AbstractYandexLockboxClient, AbstractHTTPAdapter
from yc_lockbox._adapters import HTTPAdapter
from yc_lockbox._auth import YandexAuthClient
from yc_lockbox._models import (
    Secret,
    SecretPayload,
    SecretVersion,
    SecretsList,
    SecretVersionsList,
    Operation,
    YandexCloudError,
    INewSecret,
    IUpdateSecret,
    INewSecretVersion,
    BasePaginatedResponse,
)
from yc_lockbox._types import T

logger = logging.getLogger(__name__)


class YandexLockboxClient(AbstractYandexLockboxClient):
    """
    Yandex Lockbox secrets vault client.

    :param credentials: Credentials for authenticate requests.
        Allowed types: service account key, OAuth token, IAM token.
    :param auth_client: Optional client implementation for authenticate requests.
        Defaults to ``YandexAuthClient``.
    :param adapter: HTTP adapter for communicate with Yandex Cloud API.
    :param lockbox_base_url: Lockbox base URL without resource path.
    :param payload_lockbox_base_url: Lockbox payload base URL without resource path.
    :param auth_base_url: IAM base URL without resource path.

    .. note::

        All the values of the secrets are masked, i.e. looks like ``***********``.
        To get the real value of the secret, you need to call the injected methods
        :func:`reveal_text_value()` or :func:`reveal_binary_value()`.

    Usage::

        from yc_lockbox import YandexLockboxClient, Secret

        lockbox = YandexLockboxClient("y0_AgAEXXXXXXXXXXXXXXXXXXXXXXXXX")  # OAuth or IAM token

        secret: Secret = lockbox.get_secret("e6xxxxxxxxxxxxxxxx")
        print(secret.name, secret.status, secret.description)

        payload = secret.payload()

        try:
            value = payload["mykey"]
            print(value.reveal_text_value())
        except KeyError:
            print("Invalid key!")

        print(payload.get("foo"))  # None if not exists without raising exception
        entry = payload[0]  # similar to payload.entries[0]

    Authenticate via service account key::

        import json

        # generate json key for your SA
        # yc iam key create --service-account-name my-sa --output key.json

        with open("./key.json", "r") as infile:
            credentials = json.load(infile)

        lockbox = YandexLockboxClient(credentials)

    """

    def __init__(
        self,
        credentials,
        *,
        auth_client: Optional[Type[AbstractYandexAuthClient]] = YandexAuthClient,
        adapter: Optional[Type[AbstractHTTPAdapter]] = HTTPAdapter,
        lockbox_base_url: str | None = None,
        payload_lockbox_base_url: str | None = None,
    ) -> None:
        super().__init__(
            lockbox_base_url=lockbox_base_url,
            payload_lockbox_base_url=payload_lockbox_base_url,
        )
        self.auth: AbstractYandexAuthClient = auth_client(credentials)
        self.adapter: AbstractHTTPAdapter = adapter

    @property
    def auth_headers(self) -> dict[str, str]:
        """Returns headers for authenticate."""
        return self.auth.get_auth_headers()

    def _inject_client_to_items(self, items: list[T]) -> list[T]:
        """Inject this client to each response model."""
        return list(map(lambda item: item.inject_client(self), items))

    def _seekable_response(
        self, func: Callable[..., BasePaginatedResponse], entrypoint: str, *args, **kwargs
    ) -> Iterator[T]:
        """
        Requests all data from the API using the generators, instead of a page-by-page response.
        This method does not works with dict. Be careful.
        Returns list of objects from model entrypoint.

        :param func: Adapter func to get data from API.
        :param entrypoint: Response attribute that contains list of useful data items.
        :param args: Arguments for func. Will be passed when called inside.
        :param kwargs: Keyword arguments for func. Similar to ``args``.
        """

        if kwargs.get("params") is None:
            raise TypeError(
                "This method works only with query string parameters. Check keyword arguments to resolve it."
            )

        next_token = ""  # nosec B105

        while next_token is not None:
            # There could potentially be a problem if some request doesn't have a 'pageToken' in query string params.
            # However, this is already a question for a non-consistent API, I think.
            # An unlikely story, but worth keeping in mind.
            kwargs["params"]["pageToken"] = next_token

            response = func(*args, **kwargs)
            next_token = response.next_page_token  # None or a new token from the API

            if not hasattr(response, entrypoint):
                raise AttributeError(f"Entrypoint {entrypoint} not exists in response model.")

            for item in getattr(response, entrypoint):
                if not hasattr(item, "inject_client"):
                    raise AttributeError(
                        f"Incorrect item. Method 'inject_client' is not exists in {item.__class__} {type(item)}"
                    )
                item.inject_client(self)
                yield item

    def activate_secret(self, secret_id: str, raise_for_status: bool = True) -> Operation | YandexCloudError:
        """
        Activates the specified secret.

        :param secret_id: Secret indentifier.
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        url = f"{self.lockbox_base_url}/secrets/{secret_id}:activate"
        response = self.adapter.request(
            "POST",
            url,
            headers=self.auth_headers,
            response_model=Operation,
            raise_for_status=raise_for_status,
        )
        response.inject_client(self)
        return response

    def add_secret_version(
        self, secret_id: str, version: INewSecretVersion, raise_for_status: bool = True
    ) -> Operation | YandexCloudError:
        """
        Adds new version based on a previous one.

        :param secret_id: Secret indentifier.
        :param version: A new version object.
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        url = f"{self.lockbox_base_url}/secrets/{secret_id}:addVersion"
        payload = version.model_dump_json(by_alias=True, exclude_none=True)
        response = self.adapter.request(
            "POST",
            url,
            headers=self.auth_headers,
            data=payload,
            response_model=Operation,
            raise_for_status=raise_for_status,
        )
        response.inject_client(self)
        return response

    def create_secret(self, secret: INewSecret, raise_for_status: bool = True) -> Operation | YandexCloudError:
        """
        Creates a secret in the specified folder.

        :param secret: A new secret object.
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        url = f"{self.lockbox_base_url}/secrets"
        payload = secret.model_dump_json(by_alias=True, exclude_none=True)
        response = self.adapter.request(
            "POST",
            url,
            headers=self.auth_headers,
            data=payload,
            response_model=Operation,
            raise_for_status=raise_for_status,
        )
        response.inject_client(self)
        return response

    def cancel_secret_version_destruction(
        self, secret_id: str, version_id: str, raise_for_status: bool = True
    ) -> Operation | YandexCloudError:
        """
        Cancels previously scheduled version destruction, if the version hasn't been destroyed yet.

        :param secret_id: Secret indentifier.
        :param version_id: Secret version id to cancel destruction.
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        url = f"{self.lockbox_base_url}/secrets/{secret_id}:cancelVersionDestruction"
        payload = {"versionId": version_id}
        response = self.adapter.request(
            "POST",
            url,
            headers=self.auth_headers,
            json=payload,
            response_model=Operation,
            raise_for_status=raise_for_status,
        )
        response.inject_client(self)
        return response

    def deactivate_secret(self, secret_id: str, raise_for_status: bool = True) -> Operation | YandexCloudError:
        """
        Deactivate a secret.

        :param secret_id: Secret indentifier.
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        url = f"{self.lockbox_base_url}/secrets/{secret_id}:deactivate"
        response = self.adapter.request(
            "POST",
            url,
            headers=self.auth_headers,
            response_model=Operation,
            raise_for_status=raise_for_status,
        )
        response.inject_client(self)
        return response

    def delete_secret(self, secret_id: str, raise_for_status: bool = True) -> Operation | YandexCloudError:
        """
        Deletes the specified secret.

        :param secret_id: Secret indentifier.
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        url = f"{self.lockbox_base_url}/secrets/{secret_id}"
        response = self.adapter.request(
            "DELETE",
            url,
            headers=self.auth_headers,
            response_model=Operation,
            raise_for_status=raise_for_status,
        )
        response.inject_client(self)
        return response

    def get_secret(self, secret_id: str, raise_for_status: bool = True) -> Secret | YandexCloudError:
        """
        Get lockbox secret by ID.

        :param secret_id: Secret identifier.
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        url = f"{self.lockbox_base_url}/secrets/{secret_id}"
        response = self.adapter.request(
            "GET",
            url,
            headers=self.auth_headers,
            response_model=Secret,
            raise_for_status=raise_for_status,
        )
        response.inject_client(self)
        return response

    def get_secret_payload(
        self,
        secret_id: str,
        version_id: str | None = None,
        raise_for_status: bool = True,
    ) -> SecretPayload | YandexCloudError:
        """
        Get lockbox secret payload by ID and optional version.

        :param secret_id: Secret identifier.
        :param version_id: Secret version. Optional.
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        url = f"{self.payload_lockbox_base_url}/secrets/{secret_id}/payload"
        params = {"version_id": version_id} if version_id else None
        return self.adapter.request(
            "GET",
            url,
            headers=self.auth_headers,
            response_model=SecretPayload,
            raise_for_status=raise_for_status,
            params=params,
        )

    def list_secrets(
        self,
        folder_id: str,
        page_size: int = 100,
        page_token: str | None = None,
        raise_for_status: bool = True,
        iterator: bool = False,
    ) -> SecretsList | Iterator[Secret] | YandexCloudError:
        """
        Retrieves the list of secrets in the specified folder.

        :param folder_id: ID of the folder to list secrets in.
        :param page_size: The maximum number of results per page to return.
            If the number of available results is larger than ``page_size``,
            the service returns a ``next_page_token`` that can be used to get
            the next page of results in subsequent list requests.
            Default value: ``100``.
            The maximum value is ``1000``.
        :param page_token: Page token. To get the next page of results, set ``page_token``
            to the ``next_page_token`` returned by a previous list request.
        :param iterator: Returns all data as iterator (generator) instead paginated result.
        """
        args = (
            "GET",
            f"{self.lockbox_base_url}/secrets",
        )
        kwargs = {
            "headers": self.auth_headers,
            "params": {"folderId": folder_id, "pageSize": page_size, "pageToken": page_token},
            "response_model": SecretsList,
            "raise_for_status": raise_for_status,
        }

        if iterator:
            return self._seekable_response(self.adapter.request, "secrets", *args, **kwargs)

        response = self.adapter.request(*args, **kwargs)
        self._inject_client_to_items(response.secrets)
        return response

    # TODO: implement
    def list_secret_access_bindings(self, *args, **kwargs):
        """Not ready yet."""
        raise NotImplementedError

    # TODO: implement
    def list_secret_operations(self, *args, **kwargs):
        """Not ready yet."""
        raise NotImplementedError

    def list_secret_versions(
        self,
        secret_id: str,
        page_size: int = 100,
        page_token: str | None = None,
        raise_for_status: bool = True,
        iterator: bool = False,
    ) -> SecretVersionsList | Iterator[SecretVersion] | YandexCloudError:
        """
        Retrieves the list of versions of the specified secret.

        :param secret_id: Secret identifier.
        :param page_size: The maximum number of results per page to return.
            If the number of available results is larger than ``page_size``,
            the service returns a ``next_page_token`` that can be used to get
            the next page of results in subsequent list requests.
            Default value: ``100``.
            The maximum value is ``1000``.
        :param page_token: Page token. To get the next page of results, set ``page_token``
            to the ``next_page_token`` returned by a previous list request.
        :param iterator: Returns all data as iterator (generator) instead paginated result.
        """
        args = (
            "GET",
            f"{self.lockbox_base_url}/secrets/{secret_id}/versions",
        )
        kwargs = {
            "headers": self.auth_headers,
            "params": {"pageSize": page_size, "pageToken": page_token},
            "response_model": SecretVersionsList,
            "raise_for_status": raise_for_status,
        }

        if iterator:
            return self._seekable_response(self.adapter.request, "versions", *args, **kwargs)

        response = self.adapter.request(*args, **kwargs)
        self._inject_client_to_items(response.versions)
        return response

    def schedule_secret_version_destruction(
        self, secret_id: str, version_id: str, pending_period: int = 604800, raise_for_status: bool = True
    ) -> Operation | YandexCloudError:
        """
        Schedules the specified version for destruction.
        Scheduled destruction can be cancelled with the :func:`cancel_secret_version_destruction()` method.

        :param secret_id: Secret indentifier.
        :param version_id: ID of the version to be destroyed.
        :param pending_period: Time interval in seconds between the version destruction request and actual destruction.
            Default value: ``604800`` (i.e. 7 days).
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        if isinstance(pending_period, int):
            if pending_period <= 0:
                raise ValueError("The ``pending_period`` value must be greater than 0.")
            # protobuf duration compat
            # https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/duration.proto
            pending_period = str(pending_period) + "s"
        else:
            raise ValueError("The ``pending_period`` value must be integer.")

        url = f"{self.lockbox_base_url}/secrets/{secret_id}:scheduleVersionDestruction"
        payload = {"versionId": version_id, "pendingPeriod": pending_period}
        response = self.adapter.request(
            "POST",
            url,
            headers=self.auth_headers,
            json=payload,
            response_model=Operation,
            raise_for_status=raise_for_status,
        )
        response.inject_client(self)
        return response

    # TODO: implement
    def set_secret_access_bindings(self, *args, **kwargs):
        """Not ready yet."""
        raise NotImplementedError

    def update_secret(
        self, secret_id: str, data: IUpdateSecret, raise_for_status: bool = True
    ) -> Operation | YandexCloudError:
        """
        Updates the specified secret.

        :param secret_id: Secret identifier.
        :param data: A new data for the secret as object.
            Important. Field mask that specifies which attributes of the secret are going to be updated.
            A comma-separated names off ALL fields to be updated. Only the specified fields will be changed.
            The others will be left untouched. If the field is specified in updateMask and no value for
            that field was sent in the request, the field's value will be reset to the default.
            The default value for most fields is null or 0.
            If ``updateMask`` is not sent in the request, all fields values will be updated.
            Fields specified in the request will be updated to provided values. The rest of the fields will be reset to the default.
        :param raise_for_status: If set to ``False`` returns :class:`YandexCloudError` instead throw exception.
            Defaults to ``True``.
        """
        url = f"{self.lockbox_base_url}/secrets/{secret_id}"
        payload = data.model_dump_json(by_alias=True)
        response = self.adapter.request(
            "PATCH",
            url,
            headers=self.auth_headers,
            data=payload,
            response_model=Operation,
            raise_for_status=raise_for_status,
        )
        response.inject_client(self)
        return response

    # TODO: implement
    def update_secret_access_bindings(self, *args, **kwargs):
        """Not ready yet."""
        raise NotImplementedError


# TODO: implement
class AsyncYandexLockboxClient(AbstractYandexLockboxClient):
    """The same as :class:`YandexLockboxClient` but async."""

    def __init__(self, *args, **kwargs) -> None:
        raise NotImplementedError  # pragma: no cover


# TODO: implement
class YandexLockbox:
    """
    A facade for encapsulating the logic of synchronous and asynchronous client operations,
    providing uniform methods.
    """

    def __init__(self) -> None:
        raise NotImplementedError  # pragma: no cover


__all__ = ["AsyncYandexLockboxClient", "YandexLockboxClient", "YandexLockbox"]
