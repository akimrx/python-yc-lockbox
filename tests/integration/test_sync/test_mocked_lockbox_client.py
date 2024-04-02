import pytest
from typing import Any, Generator, Iterator
from requests_mock import Mocker

from yc_lockbox._constants import YC_LOCKBOX_BASE_URL, YC_LOCKBOX_PAYLOAD_BASE_URL
from yc_lockbox._models import (
    Operation,
    Secret,
    SecretVersion,
    SecretPayload,
    SecretPayloadEntry,
    SecretsList,
    SecretVersionsList,
    YandexCloudError,
    INewSecret,
    INewSecretVersion,
    INewSecretPayloadEntry,
    IUpdateSecret,
)
from yc_lockbox._lockbox import YandexLockboxClient


@pytest.mark.parametrize(
    "secret_id, url, mock_response",
    [
        (
            "e6qh3v0mgnmiq995h1v9",
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6qh3v0mgnmiq995h1v9:activate",
            {
                "done": True,
                "metadata": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.ActivateSecretMetadata",
                    "secretId": "e6qh3v0mgnmiq995h1v9",
                },
                "response": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.Secret",
                    "currentVersion": {
                        "payloadEntryKeys": ["key1", "key2"],
                        "id": "e6qii1ovrs7suo5oroe8",
                        "secretId": "e6qh3v0mgnmiq995h1v9",
                        "createdAt": "2024-03-26T07:38:41.908Z",
                        "status": "ACTIVE",
                    },
                    "deletionProtection": False,
                    "id": "e6qh3v0mgnmiq995h1v9",
                    "folderId": "b1gjpj7bq52xxxxxx7t6",
                    "createdAt": "2024-03-26T07:38:41.908Z",
                    "name": "test-key",
                    "status": "ACTIVE",
                },
                "id": "e6qdrk237rdpt8sibbng",
                "description": "Activate secret",
                "createdAt": "2024-03-26T07:38:42.189024661Z",
                "createdBy": "aje884de7xxxxxxq3joj",
                "modifiedAt": "2024-03-26T07:38:42.189056725Z",
            },
        )
    ],
)
def test_mocked_activate_secret(
    secret_id: str,
    url: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:
    requests_mocker.post(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: Operation | YandexCloudError = lockbox_client.activate_secret(secret_id)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, Operation)
    assert result.done
    assert result.id == mock_response["id"]
    assert result.metadata["secretId"] == secret_id

    assert isinstance(result.resource, Secret)
    assert isinstance(result.resource.client, YandexLockboxClient)
    assert result.resource.id == secret_id


@pytest.mark.parametrize(
    "secret_id, url, mock_response, version",
    [
        (
            "e6qgq6gaei7ejteotjge",
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6qgq6gaei7ejteotjge:addVersion",
            {
                "done": True,
                "metadata": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.AddVersionMetadata",
                    "secretId": "e6qgq6gaei7ejteotjge",
                    "versionId": "e6qetl2mu52s8gvq0ccj",
                },
                "response": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.Version",
                    "payloadEntryKeys": ["key1", "key2", "test_key"],
                    "id": "e6qetl2mu52s8gvq0ccj",
                    "secretId": "e6qgq6gaei7ejteotjge",
                    "createdAt": "2024-03-26T07:59:23.172Z",
                    "status": "ACTIVE",
                },
                "id": "e6q67tu8pet2328ktemr",
                "description": "Add version",
                "createdAt": "2024-03-26T07:59:23.172687854Z",
                "createdBy": "aje884de7xxxxxxq3joj",
                "modifiedAt": "2024-03-26T07:59:23.172723443Z",
            },
            INewSecretVersion(payloadEntries=[INewSecretPayloadEntry(key="test_key", textValue="test_value")]),
        )
    ],
)
def test_mocked_add_secret_version(
    secret_id: str,
    url: str,
    mock_response: dict[str, Any],
    version: INewSecretVersion,
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:

    requests_mocker.post(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: Operation | YandexCloudError = lockbox_client.add_secret_version(secret_id, version)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, Operation)
    assert result.done
    assert result.id == mock_response["id"]
    assert result.metadata["secretId"] == secret_id

    assert isinstance(result.resource, SecretVersion)
    assert isinstance(result.resource.client, YandexLockboxClient)
    assert result.resource.secret_id == secret_id


@pytest.mark.parametrize(
    "url, mock_response, secret",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets",
            {
                "done": False,
                "metadata": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.CreateSecretMetadata",
                    "secretId": "e6qgq6gaei7ejteotjge",
                    "versionId": "e6qfcrpioij83qbka9lo",
                },
                "id": "e6qe3dc7j2d0555pt9ak",
                "description": "Create secret",
                "createdAt": "2024-03-26T07:59:22.709848334Z",
                "createdBy": "aje884de7xxxxxxq3joj",
                "modifiedAt": "2024-03-26T07:59:22.709848334Z",
            },
            INewSecret(
                folder_id="b1gjpj7bq22qqqqqq7t6",
                name="test-key",
                version_payload_entries=[
                    INewSecretPayloadEntry(key="key1", textValue="value1"),
                    INewSecretPayloadEntry(key="key2", binaryValue="value2".encode()),
                ],
            ),
        )
    ],
)
def test_mocked_create_secret(
    url: str,
    mock_response: dict[str, Any],
    secret: INewSecret,
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:

    requests_mocker.post(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: Operation | YandexCloudError = lockbox_client.create_secret(secret)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, Operation)
    assert not result.done
    assert result.id == mock_response["id"]
    assert result.metadata["secretId"] is not None

    assert result.resource is None


@pytest.mark.parametrize(
    "url, secret_id, version_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6qqg8aq7jum59ivv560:cancelVersionDestruction",
            "e6qqg8aq7jum59ivv560",
            "e6qo0aqmflbl0o00mlmd",
            {
                "done": True,
                "metadata": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.CancelVersionDestructionMetadata",
                    "secretId": "e6qqg8aq7jum59ivv560",
                    "versionId": "e6qo0aqmflbl0o00mlmd",
                },
                "response": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.Version",
                    "payloadEntryKeys": ["key1", "key2"],
                    "id": "e6qo0aqmflbl0o00mlmd",
                    "secretId": "e6qqg8aq7jum59ivv560",
                    "createdAt": "2024-03-26T08:33:33.625Z",
                    "status": "ACTIVE",
                },
                "id": "e6qe0uqinjvu5j2pmj33",
                "description": "Cancel version destruction",
                "createdAt": "2024-03-26T08:33:34.912533615Z",
                "createdBy": "aje884de7xxxxxxq3joj",
                "modifiedAt": "2024-03-26T08:33:34.912558579Z",
            },
        )
    ],
)
def test_mocked_cancel_version_descruction(
    url: str,
    secret_id: str,
    version_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:

    requests_mocker.post(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: Operation | YandexCloudError = lockbox_client.cancel_secret_version_destruction(secret_id, version_id)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, Operation)
    assert result.done
    assert result.id == mock_response["id"]
    assert result.metadata["secretId"] == secret_id
    assert result.metadata["versionId"] == version_id

    assert isinstance(result.resource, SecretVersion)
    assert isinstance(result.resource.client, YandexLockboxClient)
    assert result.resource.id == version_id
    assert result.resource.secret_id == secret_id


@pytest.mark.parametrize(
    "url, secret_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6q4d0nd2nto737ak1f0:deactivate",
            "e6q4d0nd2nto737ak1f0",
            {
                "done": True,
                "metadata": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.DeactivateSecretMetadata",
                    "secretId": "e6q4d0nd2nto737ak1f0",
                },
                "response": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.Secret",
                    "currentVersion": {
                        "payloadEntryKeys": ["key1", "key2"],
                        "id": "e6qcc4gft2aik6bmg65m",
                        "secretId": "e6q4d0nd2nto737ak1f0",
                        "createdAt": "2024-03-26T08:45:51.825Z",
                        "status": "ACTIVE",
                    },
                    "deletionProtection": False,
                    "id": "e6q4d0nd2nto737ak1f0",
                    "folderId": "b1gjpj7bq52xxxxxx7t6",
                    "createdAt": "2024-03-26T08:45:51.825Z",
                    "name": "test-key",
                    "status": "INACTIVE",
                },
                "id": "e6qsntgq23adl058gmh9",
                "description": "Deactivate secret",
                "createdAt": "2024-03-26T08:45:52.049278552Z",
                "createdBy": "aje884de7xxxxxxq3joj",
                "modifiedAt": "2024-03-26T08:45:52.049314259Z",
            },
        )
    ],
)
def test_mocked_deactivate_secret(
    url: str,
    secret_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:

    requests_mocker.post(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: Operation | YandexCloudError = lockbox_client.deactivate_secret(secret_id)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, Operation)
    assert result.done
    assert result.id == mock_response["id"]
    assert result.metadata["secretId"] == secret_id

    assert isinstance(result.resource, Secret)
    assert isinstance(result.resource.client, YandexLockboxClient)
    assert result.resource.id == secret_id
    assert result.resource.status == "INACTIVE"


@pytest.mark.parametrize(
    "url, secret_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6q8ccgvcp685ef0o85m",
            "e6q8ccgvcp685ef0o85m",
            {
                "done": True,
                "metadata": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.DeleteSecretMetadata",
                    "secretId": "e6q8ccgvcp685ef0o85m",
                },
                "response": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.Secret",
                    "currentVersion": {
                        "payloadEntryKeys": ["key1", "key2"],
                        "id": "e6qa0570t64ao8gbjr5g",
                        "secretId": "e6q8ccgvcp685ef0o85m",
                        "createdAt": "2024-03-26T09:02:32.090Z",
                        "status": "ACTIVE",
                    },
                    "deletionProtection": False,
                    "id": "e6q8ccgvcp685ef0o85m",
                    "folderId": "b1gjpj7bq52xxxxxx7t6",
                    "createdAt": "2024-03-26T09:02:32.090Z",
                    "name": "test-key",
                },
                "id": "e6qtmcjfshj46tup03qh",
                "description": "Delete secret",
                "createdAt": "2024-03-26T09:02:32.811030090Z",
                "createdBy": "aje884de7xxxxxxq3joj",
                "modifiedAt": "2024-03-26T09:02:32.811066746Z",
            },
        )
    ],
)
def test_mocked_delete_secret(
    url: str,
    secret_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:

    requests_mocker.delete(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: Operation | YandexCloudError = lockbox_client.delete_secret(secret_id)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, Operation)
    assert result.done
    assert result.id == mock_response["id"]
    assert result.metadata["secretId"] == secret_id

    assert isinstance(result.resource, Secret)
    assert isinstance(result.resource.client, YandexLockboxClient)
    assert result.resource.id == secret_id


@pytest.mark.parametrize(
    "url, secret_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6qj7gpvimsi1igs228r",
            "e6qj7gpvimsi1igs228r",
            {
                "currentVersion": {
                    "payloadEntryKeys": ["key1", "key2"],
                    "id": "e6qfnqdkb105a4seprsn",
                    "secretId": "e6qj7gpvimsi1igs228r",
                    "createdAt": "2024-03-26T09:07:50.981Z",
                    "status": "ACTIVE",
                },
                "deletionProtection": True,
                "id": "e6qj7gpvimsi1igs228r",
                "folderId": "b1gjpj7bq52xxxxxx7t6",
                "createdAt": "2024-03-26T09:07:50.981Z",
                "name": "test-key",
                "status": "ACTIVE",
            },
        )
    ],
)
def test_mocked_get_secret(
    url: str,
    secret_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:

    requests_mocker.get(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: Secret = lockbox_client.get_secret(secret_id)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, Secret)
    assert isinstance(result.current_version, SecretVersion)
    assert isinstance(result.client, YandexLockboxClient)
    assert result.id == secret_id
    assert result.status == "ACTIVE"
    assert result.deletion_protection


@pytest.mark.parametrize(
    "url, secret_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_PAYLOAD_BASE_URL}/secrets/e6qj7gpvimsi1igs228r/payload",
            "e6qj7gpvimsi1igs228r",
            {
                "entries": [{"key": "key1", "textValue": "value1"}, {"key": "key2", "binaryValue": "value2"}],
                "versionId": "e6qck9fs0ue4dotveirb",
            },
        )
    ],
)
def test_mocked_get_secret_payload(
    url: str,
    secret_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:

    requests_mocker.get(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: SecretPayload = lockbox_client.get_secret_payload(secret_id)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, SecretPayload)
    assert isinstance(result.entries, list)
    assert isinstance(result.entries[0], SecretPayloadEntry)
    assert result.client is None

    assert str(result[0].text_value) == "**********"
    assert result[0].reveal_text_value() == "value1"
    assert result[0].reveal_binary_value() is None

    assert str(result.get("key1").text_value) == "**********"
    assert result["key1"].reveal_text_value() == "value1"
    assert result["key1"].reveal_binary_value() is None

    assert str(result.get("key2").binary_value) == "**********"
    assert result["key2"].reveal_text_value() is None
    assert result["key2"].reveal_binary_value() == "value2"

    with pytest.raises(KeyError) as key_excinfo:
        result["key3"]
    assert "not exists" in str(key_excinfo.value)

    with pytest.raises(IndexError) as index_excinfo:
        result[10]
    assert "out of range" in str(index_excinfo.value)

    assert result.get("key5") is None
    assert result.get("key6", default="foo") == "foo"


@pytest.mark.parametrize(
    "url, folder_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets",
            "b1gjpj7bq52xxxxxx7t6",
            {
                "secrets": [
                    {
                        "currentVersion": {
                            "payloadEntryKeys": ["key1", "key2"],
                            "id": "e6qs8nc5427jv25l98i6",
                            "secretId": "e6qlkppt9rc0saulbfjh",
                            "createdAt": "2024-03-26T09:28:19.259Z",
                            "status": "ACTIVE",
                        },
                        "deletionProtection": False,
                        "id": "e6qlkppt9rc0saulbfjh",
                        "folderId": "b1gjpj7bq52xxxxxx7t6",
                        "createdAt": "2024-03-26T09:28:19.259Z",
                        "name": "test-secret-1",
                        "status": "ACTIVE",
                    },
                    {
                        "currentVersion": {
                            "payloadEntryKeys": ["test-key"],
                            "id": "e6q1kclhp4jdnfms9bal",
                            "secretId": "e6qndtc3gtcnti2jb0iq",
                            "createdAt": "2024-03-26T09:23:50.004Z",
                            "status": "INACTIVE",
                        },
                        "deletionProtection": True,
                        "id": "e6qndtc3gtcnti2jb0iq",
                        "folderId": "b1gjpj7bq52xxxxxx7t6",
                        "createdAt": "2024-03-26T09:23:50.004Z",
                        "name": "test-secret-2",
                        "status": "ACTIVE",
                    },
                ],
                "nextPageToken": "e6qndtc4gtcnti3jb0ix",
            },
        )
    ],
)
def test_mocked_paginated_list_secrets(
    url: str,
    folder_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:
    requests_mocker.get(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: SecretsList = lockbox_client.list_secrets(folder_id, page_size=2)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, SecretsList)
    assert hasattr(result, "secrets")
    assert isinstance(result.secrets, list)
    assert result.next_page_token is not None

    for secret in result.secrets:
        assert isinstance(secret, Secret)
        assert isinstance(secret.current_version, SecretVersion)
        assert isinstance(secret.client, YandexLockboxClient)


@pytest.mark.parametrize(
    "url, folder_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets",
            "b1gjpj7bq52xxxxxx7t6",
            {
                "secrets": [
                    {
                        "currentVersion": {
                            "payloadEntryKeys": ["key1", "key2"],
                            "id": "e6qs8nc5427jv25l98i6",
                            "secretId": "e6qlkppt9rc0saulbfjh",
                            "createdAt": "2024-03-26T09:28:19.259Z",
                            "status": "ACTIVE",
                        },
                        "deletionProtection": False,
                        "id": "e6qlkppt9rc0saulbfjh",
                        "folderId": "b1gjpj7bq52xxxxxx7t6",
                        "createdAt": "2024-03-26T09:28:19.259Z",
                        "name": "test-secret-1",
                        "status": "ACTIVE",
                    },
                    {
                        "currentVersion": {
                            "payloadEntryKeys": ["test-key"],
                            "id": "e6q1kclhp4jdnfms9bal",
                            "secretId": "e6qndtc3gtcnti2jb0iq",
                            "createdAt": "2024-03-26T09:23:50.004Z",
                            "status": "INACTIVE",
                        },
                        "deletionProtection": True,
                        "id": "e6qndtc3gtcnti2jb0iq",
                        "folderId": "b1gjpj7bq52xxxxxx7t6",
                        "createdAt": "2024-03-26T09:23:50.004Z",
                        "name": "test-secret-2",
                        "status": "ACTIVE",
                    },
                ],
                "nextPageToken": None,
            },
        )
    ],
)
def test_mocked_iterable_list_secrets(
    url: str,
    folder_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:
    requests_mocker.get(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result = lockbox_client.list_secrets(folder_id, iterator=True)

    assert not requests_mocker.called
    assert requests_mocker.call_count == 0

    assert isinstance(result, Generator) or isinstance(result, Iterator)
    assert not hasattr(result, "next_page_token")

    for secret in result:
        assert isinstance(secret, Secret)
        assert isinstance(secret.current_version, SecretVersion)
        assert isinstance(secret.client, YandexLockboxClient)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1


@pytest.mark.parametrize(
    "url, secret_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6qr4ra9qh9thdnhrh7s/versions",
            "e6qr4ra9qh9thdnhrh7s",
            {
                "versions": [
                    {
                        "payloadEntryKeys": ["key1", "key2"],
                        "id": "e6q2fbgrmuc3tmh8yyy3",
                        "secretId": "e6qr4ra9qh9thdnhrh7s",
                        "createdAt": "2024-03-26T10:15:37.400Z",
                        "status": "ACTIVE",
                    },
                    {
                        "payloadEntryKeys": ["key1", "key2"],
                        "id": "e6q2fbgrmuc3tmh8xxx3",
                        "secretId": "e6qr4ra9qh9thdnhrh7s",
                        "createdAt": "2024-03-26T10:15:37.400Z",
                        "status": "ACTIVE",
                    },
                ],
                "nextPageToken": "e6q2fbgrmuc3tmh8yyy3",
            },
        )
    ],
)
def test_mocked_paginated_list_secret_versions(
    url: str,
    secret_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:
    requests_mocker.get(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: SecretsList = lockbox_client.list_secret_versions(secret_id, page_size=2)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, SecretVersionsList)
    assert hasattr(result, "versions")
    assert isinstance(result.versions, list)
    assert result.next_page_token is not None

    for version in result.versions:
        assert isinstance(version, SecretVersion)
        assert isinstance(version.client, YandexLockboxClient)


@pytest.mark.parametrize(
    "url, secret_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6qr4ra9qh9thdnhrh7s/versions",
            "e6qr4ra9qh9thdnhrh7s",
            {
                "versions": [
                    {
                        "payloadEntryKeys": ["key1", "key2"],
                        "id": "e6q2fbgrmuc3tmh8yyy3",
                        "secretId": "e6qr4ra9qh9thdnhrh7s",
                        "createdAt": "2024-03-26T10:15:37.400Z",
                        "status": "ACTIVE",
                    },
                    {
                        "payloadEntryKeys": ["key1", "key2"],
                        "id": "e6q2fbgrmuc3tmh8xxx3",
                        "secretId": "e6qr4ra9qh9thdnhrh7s",
                        "createdAt": "2024-03-26T10:15:37.400Z",
                        "status": "ACTIVE",
                    },
                ],
            },
        )
    ],
)
def test_mocked_iterable_list_secret_versions(
    url: str,
    secret_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:
    requests_mocker.get(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result = lockbox_client.list_secret_versions(secret_id, iterator=True)

    assert not requests_mocker.called
    assert requests_mocker.call_count == 0

    assert isinstance(result, Generator) or isinstance(result, Iterator)
    assert not hasattr(result, "next_page_token")

    for version in result:
        assert isinstance(version, SecretVersion)
        assert isinstance(version.client, YandexLockboxClient)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1


@pytest.mark.parametrize(
    "url, secret_id, version_id, mock_response",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6qqg8aq7jum59ivv560:scheduleVersionDestruction",
            "e6qqg8aq7jum59ivv560",
            "e6qo0aqmflbl0o00mlmd",
            {
                "done": True,
                "metadata": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.ScheduleVersionDestructionMetadata",
                    "secretId": "e6qqg8aq7jum59ivv560",
                    "versionId": "e6qo0aqmflbl0o00mlmd",
                    "destroyAt": "2024-04-02T08:33:34.641Z",
                },
                "response": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.Version",
                    "payloadEntryKeys": ["mykey", "everybody"],
                    "id": "e6qo0aqmflbl0o00mlmd",
                    "secretId": "e6qqg8aq7jum59ivv560",
                    "createdAt": "2024-03-26T08:33:33.625Z",
                    "destroyAt": "2024-04-02T08:33:34.641Z",
                    "status": "SCHEDULED_FOR_DESTRUCTION",
                },
                "id": "e6qdb9sm2tut6econ95c",
                "description": "Schedule version destruction",
                "createdAt": "2024-03-26T08:33:34.654233229Z",
                "createdBy": "aje884de7xxxxxxq3joj",
                "modifiedAt": "2024-03-26T08:33:34.654258874Z",
            },
        )
    ],
)
def test_mocked_schedule_secret_version_destruction(
    url: str,
    secret_id: str,
    version_id: str,
    mock_response: dict[str, Any],
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:

    requests_mocker.post(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: Operation | YandexCloudError = lockbox_client.schedule_secret_version_destruction(secret_id, version_id)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, Operation)
    assert result.done
    assert result.id == mock_response["id"]
    assert result.metadata["secretId"] == secret_id
    assert result.metadata["versionId"] == version_id

    assert isinstance(result.resource, SecretVersion)
    assert isinstance(result.resource.client, YandexLockboxClient)
    assert result.resource.id == version_id
    assert result.resource.secret_id == secret_id
    assert result.resource.status == "SCHEDULED_FOR_DESTRUCTION"


@pytest.mark.parametrize(
    "url, secret_id, mock_response, data",
    [
        (
            f"{YC_LOCKBOX_BASE_URL}/secrets/e6qq26njrboiglh9nfkq",
            "e6qq26njrboiglh9nfkq",
            {
                "done": True,
                "metadata": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.UpdateSecretMetadata",
                    "secretId": "e6qq26njrboiglh9nfkq",
                },
                "response": {
                    "@type": "type.googleapis.com/yandex.cloud.lockbox.v1.Secret",
                    "currentVersion": {
                        "payloadEntryKeys": ["key1", "key2"],
                        "id": "e6qsmqo0svqdcgjlted7",
                        "secretId": "e6qq26njrboiglh9nfkq",
                        "createdAt": "2024-03-26T10:31:56.563Z",
                        "status": "ACTIVE",
                    },
                    "deletionProtection": False,
                    "id": "e6qq26njrboiglh9nfkq",
                    "folderId": "b1gjpj7bq52xxxxxx7t6",
                    "createdAt": "2024-03-26T10:31:56.563Z",
                    "name": "updated-secret",
                    "description": "has been updated",
                    "status": "ACTIVE",
                },
                "id": "e6qhnt68r89usttisc14",
                "description": "Update secret",
                "createdAt": "2024-03-26T10:31:56.934095604Z",
                "createdBy": "aje884de4fxxxxxx3joj",
                "modifiedAt": "2024-03-26T10:31:56.934138749Z",
            },
            IUpdateSecret(updateMask="name,description", name="updated-secret", description="has been updated"),
        )
    ],
)
def test_mocked_update_secret(
    url: str,
    secret_id: str,
    mock_response: dict[str, Any],
    data: IUpdateSecret,
    requests_mocker: Mocker,
    lockbox_client: YandexLockboxClient,
) -> None:

    requests_mocker.patch(
        url,
        headers={"Content-Type": "application/json"},
        json=mock_response,
        status_code=200,
    )

    result: Operation | YandexCloudError = lockbox_client.update_secret(secret_id, data)

    assert requests_mocker.called
    assert requests_mocker.call_count == 1

    assert isinstance(result, Operation)
    assert result.done
    assert result.id == mock_response["id"]
    assert result.metadata["secretId"] is not None

    assert isinstance(result.resource, Secret)
    assert isinstance(result.resource.current_version, SecretVersion)
    assert isinstance(result.client, YandexLockboxClient)


# Not implemented methods test


def test_mocked_list_secret_access_bindings(lockbox_client) -> None:
    with pytest.raises(NotImplementedError) as excinfo:
        lockbox_client.list_secret_access_bindings()
    assert str(excinfo.value) == ""


def test_mocked_list_secret_operations(lockbox_client) -> None:
    with pytest.raises(NotImplementedError) as excinfo:
        lockbox_client.list_secret_operations()
    assert str(excinfo.value) == ""


def test_mocked_set_secret_access_bindings(lockbox_client) -> None:
    with pytest.raises(NotImplementedError) as excinfo:
        lockbox_client.set_secret_access_bindings()
    assert str(excinfo.value) == ""


def test_mocked_update_secret_access_bindings(lockbox_client) -> None:
    with pytest.raises(NotImplementedError) as excinfo:
        lockbox_client.update_secret_access_bindings()
    assert str(excinfo.value) == ""
