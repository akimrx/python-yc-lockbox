
Models & objects
=====================

Domain models
-------------

Domain models provide complete information about the resource, similar to aggregates, and also have commands (methods) for managing the resource.

.. autopydantic_model:: yc_lockbox._models.Secret

.. autopydantic_model:: yc_lockbox._models.SecretVersion

.. autopydantic_model:: yc_lockbox._models.SecretPayload

.. autopydantic_model:: yc_lockbox._models.SecretPayloadEntry


Paginated models
^^^^^^^^^^^^^^^^

Used when ``iterator=False``.

.. autopydantic_model:: yc_lockbox._models.SecretsList

.. autopydantic_model:: yc_lockbox._models.SecretVersionsList



Upsert models
-------------

Upsert models (interfaces) are designed for operations of creating new resources or updating objects inside an existing resource.

.. autopydantic_model:: yc_lockbox._models.INewSecret

.. autopydantic_model:: yc_lockbox._models.INewSecretVersion

.. autopydantic_model:: yc_lockbox._models.INewSecretPayloadEntry

.. autopydantic_model:: yc_lockbox._models.IUpdateSecret


Common models
-------------

Other Yandex Cloud models related to Lockbox.

.. autopydantic_model:: yc_lockbox._models.Operation

.. autopydantic_model:: yc_lockbox._models.YandexCloudError

.. autopydantic_model:: yc_lockbox._models.IamTokenResponse