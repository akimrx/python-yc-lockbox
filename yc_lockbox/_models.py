import logging
from typing import Any, Iterator
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, SecretStr, SecretBytes

from yc_lockbox._abc import AbstractYandexLockboxClient


logger = logging.getLogger(__name__)


class BaseDomainModel(BaseModel):
    client: AbstractYandexLockboxClient | None = None
    model_config: ConfigDict = ConfigDict(extra="ignore", arbitrary_types_allowed=True)

    def inject_client(self, client: AbstractYandexLockboxClient) -> None:
        """
        Inject initialized client for make operations via domain model.

        :param inject_client: An initialized instance of :class:`AbstractYandexLockboxClient`.
        """
        self.client = client


class BaseUpsertModel(BaseModel):
    model_config: ConfigDict = ConfigDict(extra="forbid", populate_by_name=True)


class BasePaginatedResponse(BaseDomainModel):
    next_page_token: str | None = Field(None, alias="nextPageToken")


class YandexLockboxError(BaseDomainModel):
    code: int
    message: str | None = None
    details: Any = None


class YandexLockboxResponse(BaseDomainModel):
    id: str | None = None
    done: bool = False
    description: str | None = None
    created_by: str | None = Field(None, alias="createdBy")
    created_at: datetime | None = Field(None, alias="createdAt")
    modified_at: datetime | None = Field(None, alias="modifiedAt")
    metadata: dict[str, str] | None = None


class IamTokenResponse(BaseDomainModel):
    token: str = Field(..., alias="iamToken")
    expires_at: datetime = Field(..., alias="expiresAt")


class SecretPayloadEntry(BaseDomainModel):
    key: str
    text_value: SecretStr | None = Field(None, alias="textValue")
    binary_value: SecretBytes | None = Field(None, alias="binaryValue")

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


class INewSecret(BaseUpsertModel):
    folder_id: str = Field(..., alias="folderId")
    name: str | None = None
    description: str | None = None
    labels: dict[str, str] | None = {}
    kms_key_id: str | None = Field(None, alias="kmsKeyId")
    version_description: str | None = Field(None, alias="versionDescription")
    version_payload_entries: list[SecretPayloadEntry] = Field(..., alias="versionPayloadEntries")
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
    payload_entries: list[SecretPayloadEntry] = Field(..., alias="payloadEntries")

    model_config: ConfigDict = ConfigDict(extra="forbid", populate_by_name=True)


class SecretPayload(BaseDomainModel):
    version_id: str = Field(..., alias="versionId")
    entries: list[SecretPayloadEntry]

    def get_entry(self, key: str) -> SecretPayloadEntry | None:
        """
        Get entry object from payload.

        :param key: Entry key (name).
        :raises KeyError: When key not exists in payload.
        """
        found = next(filter(lambda entry: entry.key == key, self.entries), None)

        if found is None:
            entries = ", ".join(map(lambda entry: entry.key, self.entries))
            raise KeyError(f"Entry with name {key} not exists. Available entries: {entries}")

        return found


class SecretVersion(BaseDomainModel):
    id: str
    status: str  # todo: enum
    description: str | None = None
    secret_id: str = Field(..., alias="secretId")
    created_at: datetime = Field(..., alias="createdAt")
    destroy_at: datetime | None = Field(None, alias="destroyAt")
    payload_entry_keys: list[str] | None = Field(None, alias="payloadEntryKeys")

    # TODO: implement ``is_current`` property if possible
    # there may be compatibility issues with the subquery
    # in different modes (synchronous, asynchronous)

    def cancel_version_destruction(self, **kwargs) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.cancel_secret_version_destruction(self.secret_id, self.id, **kwargs)

    def payload(self, **kwargs) -> SecretPayload | YandexLockboxError:
        return self.client.get_secret_payload(self.secret_id, self.id, **kwargs)

    def schedule_version_destruction(
        self, pending_period: int = 604800, **kwargs
    ) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.schedule_secret_version_destruction(self.secret_id, self.id, pending_period, **kwargs)


class Secret(BaseDomainModel):
    id: str
    status: str  # todo: enum
    name: str | None = None
    folder_id: str = Field(..., alias="folderId")
    created_at: datetime = Field(..., alias="createdAt")
    description: str | None = None
    kms_key_id: str | None = Field(None, alias="kmsKeyId")
    current_version: SecretVersion = Field(..., alias="currentVersion")
    deletion_protection: bool = Field(..., alias="deletionProtection")
    labels: dict[str, str] | None = None

    def activate(self, **kwargs) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.activate_secret(self.id, **kwargs)

    def add_version(self, version: INewSecretVersion, **kwargs) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.add_secret_version(self.id, version, **kwargs)

    def cancel_version_destruction(self, version_id: str, **kwargs) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.cancel_secret_version_destruction(self.id, version_id, **kwargs)

    def deactivate(self, **kwargs) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.deactivate_secret(self.id, **kwargs)

    def delete(self, **kwargs) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.delete_secret(self.id, **kwargs)

    def refresh(self, **kwargs) -> "Secret":
        return self.client.get_secret(self.id, **kwargs)

    def payload(self, version_id: str | None = None, **kwargs) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.get_secret_payload(self.id, version_id, **kwargs)

    def list_versions(
        self, page_size: int = 100, page_token: str | None = None, iterator: bool = False, **kwargs
    ) -> "SecretVersionsList" | Iterator[SecretVersion] | YandexLockboxError:
        return self.client.list_secret_versions(
            self.id, page_size=page_size, page_token=page_token, iterator=iterator, **kwargs
        )

    def schedule_version_destruction(
        self, version_id: str, pending_period: int = 604800, **kwargs
    ) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.schedule_secret_version_destruction(self.id, version_id, pending_period, **kwargs)

    def update(self, data: IUpdateSecret, **kwargs) -> YandexLockboxResponse | YandexLockboxError:
        return self.client.update_secret(self.id, data, **kwargs)


class SecretsList(BasePaginatedResponse):
    secrets: list[Secret] = []


class SecretVersionsList(BasePaginatedResponse):
    versions: list[SecretVersion] = []
