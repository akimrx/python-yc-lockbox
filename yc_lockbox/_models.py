import logging
from typing import Any, Iterator, Union
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, SecretStr, SecretBytes, computed_field

from yc_lockbox._constants import RpcError
from yc_lockbox._abc import AbstractYandexLockboxClient
from yc_lockbox._types import T
from yc_lockbox._exceptions import LockboxError


logger = logging.getLogger(__name__)


class BaseDomainModel(BaseModel):
    client: AbstractYandexLockboxClient | None = Field(
        None, description="Injected lockbox client for call model commands."
    )
    model_config: ConfigDict = ConfigDict(extra="ignore", arbitrary_types_allowed=True)  # type: ignore[union-attr]

    def inject_client(self, client: AbstractYandexLockboxClient) -> None:
        """
        Inject initialized client for make operations via domain model.

        :param inject_client: An initialized instance of :class:`AbstractYandexLockboxClient`.
        """
        self.client = client

    def _raise_when_empty_client(self) -> None:
        if self.client is None:  # pragma: no cover
            raise LockboxError("Lockbox client didn't injected to this resource.")


class BaseUpsertModel(BaseModel):
    model_config: ConfigDict = ConfigDict(extra="forbid", populate_by_name=True)  # type: ignore[union-attr]


class IamTokenResponse(BaseDomainModel):
    token: str = Field(..., alias="iamToken")
    expires_at: datetime = Field(..., alias="expiresAt")


class SecretPayloadEntry(BaseDomainModel):
    """
    Domain object that represents an entry in the :class:`SecretPayload`.
    """

    key: str
    text_value: SecretStr | None = Field(None, alias="textValue")
    binary_value: SecretStr | SecretBytes | None = Field(None, alias="binaryValue")

    def reveal_text_value(self) -> str:
        """Reveal a text value."""
        if self.text_value is None:
            return None

        return self.text_value.get_secret_value()

    def reveal_binary_value(self) -> bytes:
        """Reveal a binary value."""
        if self.binary_value is None:
            return None

        return self.binary_value.get_secret_value()


class INewSecretPayloadEntry(BaseUpsertModel):
    key: str
    text_value: str | None = Field(None, alias="textValue")
    binary_value: str | None = Field(None, alias="binaryValue")


class INewSecret(BaseUpsertModel):
    folder_id: str = Field(..., alias="folderId")
    name: str | None = None
    description: str | None = None
    labels: dict[str, str] | None = {}
    kms_key_id: str | None = Field(None, alias="kmsKeyId")
    version_description: str | None = Field(None, alias="versionDescription")
    version_payload_entries: list[INewSecretPayloadEntry] = Field(..., alias="versionPayloadEntries")
    deletion_protection: bool = Field(False, alias="deletionProtection")


class IUpdateSecret(BaseUpsertModel):
    update_mask: str = Field(..., alias="updateMask", description="Comma-separated model field names to be updated.")
    name: str | None = None
    description: str | None = None
    labels: dict[str, str] | None = None
    deletion_protection: bool | None = Field(None, alias="deletionProtection")


class INewSecretVersion(BaseUpsertModel):
    description: str | None = None
    base_version_id: str | None = Field(None, alias="baseVersionId")
    payload_entries: list[INewSecretPayloadEntry] = Field(..., alias="payloadEntries")

    model_config: ConfigDict = ConfigDict(extra="forbid", populate_by_name=True)


class SecretPayload(BaseDomainModel):
    """
    Domain object that represents a payload for :class:`Secret`.
    """

    version_id: str = Field(..., alias="versionId")
    entries: list[SecretPayloadEntry]  # todo: dynamic object with entry-attributes instead list?

    def __getitem__(self, key: str | int) -> SecretPayloadEntry | None:
        """
        Get entry by key. Dictionary like. Also, list index available.

        :param key: Entry key or index.
        :raises KeyError: When key not exists in entries.
        :raises IndexError: When index out of range.
        """
        if isinstance(key, int):
            return self.entries[key]

        value: SecretPayloadEntry | None = self.get(key, default=None)

        if value is None:
            entries = ", ".join(map(lambda entry: entry.key, self.entries))
            raise KeyError(f"Entry with name {key} not exists. Available entries: {entries}")

        return value

    def get(self, key: str, default: Any = None) -> SecretPayloadEntry | None:
        """
        Get entry object from payload.

        :param key: Entry key (name).
        :param default: Default return value if key not exists.
        """
        return next(filter(lambda entry: entry.key == key, self.entries), default)


class SecretVersion(BaseDomainModel):
    """
    Domain object that represents a version from :class:`Secret`.
    This object contains methods for call version commands.

    """

    id: str
    status: str = "UNKNOWN"  # todo: enum
    description: str | None = None
    secret_id: str = Field(..., alias="secretId")
    created_at: datetime = Field(..., alias="createdAt")
    destroy_at: datetime | None = Field(None, alias="destroyAt")
    payload_entry_keys: list[str] | None = Field(None, alias="payloadEntryKeys")

    # TODO: implement ``is_current`` property if possible
    # there may be compatibility issues with the subquery
    # in different modes (synchronous, asynchronous)

    def cancel_version_destruction(self, **kwargs) -> Union["Operation", "YandexCloudError"]:
        """Shortcut for cancel destruction for this version."""
        self._raise_when_empty_client()
        return self.client.cancel_secret_version_destruction(self.secret_id, self.id, **kwargs)

    def payload(self, **kwargs) -> Union["SecretPayload", "YandexCloudError"]:
        """Get payload from the current secret.."""
        self._raise_when_empty_client()
        return self.client.get_secret_payload(self.secret_id, self.id, **kwargs)

    def schedule_version_destruction(
        self, pending_period: int = 604800, **kwargs
    ) -> Union["Operation", "YandexCloudError"]:
        """Shortcut for schedule descruction for this version."""
        self._raise_when_empty_client()
        return self.client.schedule_secret_version_destruction(self.secret_id, self.id, pending_period, **kwargs)


class Secret(BaseDomainModel):
    """
    A root domain model that represents Lockbox Secret.
    This model contains commands (methods) for secret manipulate.

    Usage::

        # basic commands
        secret.deactivate()
        secret.activate()
        secret.delete()

        # get payload from Secret
        secret_payload = secret.payload()
        print(secret_payload["my_entry"])  # by default secret values is masked like ******
        print(secret_payload["my_entry"].reveal_text_value())  # show real value

        # get all secret versions and destruct olds
        for version in secret.list_versions(iterator=True):
            print(version)
            if version.id != secret.current_version.id:
                version.schedule_version_destruction()

        # update a secret
        new_data = IUpdateSecret(
            update_mask="name,description",
            name="new-secret-name",
            description="My secret"
        )
        update_operation = secret.update(new_data)

        if update_operation.done:  # or use secret.refresh()
            print(update_operation.resource.name, update_operation.resource.description)

    """

    id: str
    status: str = "UNKNOWN"  # todo: enum
    name: str | None = None
    folder_id: str = Field(..., alias="folderId")
    created_at: datetime = Field(..., alias="createdAt")
    description: str | None = None
    kms_key_id: str | None = Field(None, alias="kmsKeyId")
    current_version: SecretVersion = Field(..., alias="currentVersion")
    deletion_protection: bool = Field(..., alias="deletionProtection")
    labels: dict[str, str] | None = None

    def activate(self, **kwargs) -> Union["Operation", "YandexCloudError"]:
        """Shortcut for activate the current secret."""
        self._raise_when_empty_client()
        return self.client.activate_secret(self.id, **kwargs)

    def add_version(self, version: INewSecretVersion, **kwargs) -> Union["Operation", "YandexCloudError"]:
        """Shortcut for add a new version to the current secret."""
        self._raise_when_empty_client()
        return self.client.add_secret_version(self.id, version, **kwargs)

    def cancel_version_destruction(self, version_id: str, **kwargs) -> Union["Operation", "YandexCloudError"]:
        """Shortcut for cancel destruction specified version of the current secret."""
        self._raise_when_empty_client()
        return self.client.cancel_secret_version_destruction(self.id, version_id, **kwargs)

    def deactivate(self, **kwargs) -> Union["Operation", "YandexCloudError"]:
        """Shortcut for deactivate the current secret."""
        self._raise_when_empty_client()
        return self.client.deactivate_secret(self.id, **kwargs)

    def delete(self, **kwargs) -> Union["Operation", "YandexCloudError"]:
        """Shortcut for delete the current secret."""
        self._raise_when_empty_client()
        return self.client.delete_secret(self.id, **kwargs)

    def refresh(self, **kwargs) -> "Secret":
        """Shortcut for refresh attributes for this secret."""
        self._raise_when_empty_client()
        data = self.client.get_secret(self.id, **kwargs)

        for attr, value in data.model_dump().items():
            if value != getattr(self, attr):
                setattr(self, attr, value)

        return data

    def payload(self, version_id: str | None = None, **kwargs) -> Union["Operation", "YandexCloudError"]:
        self._raise_when_empty_client()
        return self.client.get_secret_payload(self.id, version_id, **kwargs)

    def list_versions(
        self, page_size: int = 100, page_token: str | None = None, iterator: bool = False, **kwargs
    ) -> Union["SecretVersionsList", Iterator["SecretVersion"], "YandexCloudError"]:
        """Shortcut for list all available versions of the current secret."""
        self._raise_when_empty_client()
        return self.client.list_secret_versions(
            self.id, page_size=page_size, page_token=page_token, iterator=iterator, **kwargs
        )

    def schedule_version_destruction(
        self, version_id: str, pending_period: int = 604800, **kwargs
    ) -> Union["Operation", "YandexCloudError"]:
        """Shortcut for schedule destruction for specified version of the current secret."""
        self._raise_when_empty_client()
        return self.client.schedule_secret_version_destruction(self.id, version_id, pending_period, **kwargs)

    def update(self, data: IUpdateSecret, **kwargs) -> Union["Operation", "YandexCloudError"]:
        """Shortcut for update current secret."""
        self._raise_when_empty_client()
        return self.client.update_secret(self.id, data, **kwargs)


class BasePaginatedResponse(BaseDomainModel):
    next_page_token: str | None = Field(None, alias="nextPageToken")


class SecretsList(BasePaginatedResponse):
    secrets: list[Secret] = []


class SecretVersionsList(BasePaginatedResponse):
    versions: list[SecretVersion] = []


class YandexCloudError(BaseDomainModel):
    code: int
    message: str | None = None
    details: Any = None

    @computed_field
    @property
    def error_type(self) -> RpcError:
        try:
            value = RpcError(self.code)
        except ValueError:
            value = None

        return value


class Operation(BaseDomainModel):
    id: str
    done: bool = False
    description: str | None = None
    created_by: str | None = Field(None, alias="createdBy")
    created_at: datetime | None = Field(None, alias="createdAt")
    modified_at: datetime | None = Field(None, alias="modifiedAt")
    metadata: dict[str, str] | Any = None
    response: Any = None
    error: Any = None

    @computed_field
    @property
    def resource(self) -> T | None:
        """
        Returns response from operation if possible.
        Otherwise returns None.
        """
        if not self.done or not isinstance(self.response, dict):
            return None

        try:
            resource_type = self.response["@type"]
        except KeyError:
            return None

        match resource_type.split("/")[-1]:
            case "yandex.cloud.lockbox.v1.Secret":
                resource = Secret(**self.response)
            case "yandex.cloud.lockbox.v1.Version":
                resource = SecretVersion(**self.response)
            case "yandex.cloud.lockbox.v1.Payload":
                resource = SecretPayload(**self.response)
            case _:
                return None

        if self.client is not None:
            resource.inject_client(self.client)
        return resource
