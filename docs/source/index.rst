.. yc-lockbox documentation master file, created by
   sphinx-quickstart on Sun Mar 24 11:23:54 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Yandex Lockbox Python client documentation
==========================================

Release v\ |release|

This library is a simple client for working with `Yandex Lockbox <https://cloud.yandex.ru/en/docs/lockbox/>`_ over `REST API <https://cloud.yandex.ru/en/docs/lockbox/api-ref/>`_, simplifying work with secrets and allowing you to work with them in the OOP paradigm.

------------------------------

**Supported Python versions**:

* 3.10

* 3.11

* 3.12

**Dependencies:**

* `PydanticV2 <https://github.com/pydantic/pydantic>`_

* `Crypthography <https://github.com/pyca/cryptography>`_

* `PyJWT <https://github.com/jpadilla/pyjwt>`_

* `Requests <https://github.com/psf/requests>`_


**Currently, the following operations are not supported by the library:**

* List secret access bindings

* Set secret access bindings

* Update secret access bindings

* List secret operations


Installation
------------

Installing with pip:

.. code-block:: shell

   pip install yc-lockbox


Also, you can install from source with:

.. code-block:: shell

   git clone https://github.com/akimrx/python-yc-lockbox
   cd python-yc-lockbox 
   make install



Quick start
------------


* Authenticate via your OAuth token

.. code-block:: python

   from yc_lockbox import YandexLockboxClient

   lockbox = YandexLockboxClient("y0_xxxxxxxxxxxx")


* Authenticate via `IAM token <https://cloud.yandex.com/en/docs/iam/operations/iam-token/create>`_

.. note::

   If you pass a IAM token as credentials, you need to take care of the freshness of the token yourself.


.. code-block:: python

   from yc_lockbox import YandexLockboxClient

   lockbox = YandexLockboxClient("t1.xxxxxx.xxxxxxx")


* Authenticate using `service account key <https://cloud.yandex.com/en/docs/iam/operations/authorized-key/create#cli_1>`_

.. code-block:: python

   import json
   from yc_lockbox import YandexLockboxClient

   with open("/path/to/key.json", "r") as keyfile:
      credentials = keyfile.read()

   lockbox = YandexLockboxClient(credentials)



Create a new secret
^^^^^^^^^^^^^^^^^^^


.. code-block:: python

   from yc_lockbox import YandexLockboxClient, INewSecret, INewSecretPayloadEntry

   lockbox = YandexLockboxClient("oauth_or_iam_token")

   create_secret_operation = lockbox.create_secret(
      INewSecret(
      folder_id="b1xxxxxxxxxxxxxx",
      name="my-secret",
      version_payload_entries=[
         INewSecretPayloadEntry(key="secret_entry_1", text_value="secret_entry_text_value"),
         INewSecretPayloadEntry(key="secret_entry_2", binary_value="secret_entry_binary_value".encode()),
      ],
      )
   )

   if create_secret_operation.done:
      new_secret = create_secret_operation.resource
      print(new_secret.id)
      new_secret.deactivate()



Get secret from Lockbox
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from yc_lockbox import YandexLockboxClient, Secret

   lockbox = YandexLockboxClient("oauth_or_iam_token")

   secret: Secret = lockbox.get_secret("e6qxxxxxxxxxx")
   print(secret.status, secret.name)

   payload = secret.payload(version_id=secret.current_version.id)  # id is optional, by default using current version
   print(payload.entries)  # list of SecretPayloadEntry objects

   # Direct access

   entry = payload["secret_entry_1"]  # or payload.get("secret_entry_1")

   print(entry.text_value)  # return MASKED value like ***********
   print(entry.reveal_text_value())  # similar to entry.text_value.get_secret_value()



Add new version of secret
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from yc_lockbox import YandexLockboxClient, Secret, INewSecretVersion, INewSecretPayloadEntry

   lockbox = YandexLockboxClient("oauth_or_iam_token")

   secret: Secret = lockbox.get_secret("e6qxxxxxxxxxxxx")

   secret.add_version(
      INewSecretVersion(
         description="a new version",
         base_version_id=secret.current_version.id,
         payload_entries= [
               INewSecretPayloadEntry(key="secret_entry_1", text_value="secret_entry_text_value"),
               INewSecretPayloadEntry(key="secret_entry_2", binary_value="secret_entry_binary_value"),
         ]
      )
   )

   # alternative
   lockbox.add_secret_version(
      "secret_id",
      version=INewSecretVersion(
         description="a new version",
         base_version_id=secret.current_version.id,
         payload_entries=[INewSecretPayloadEntry(...), INewSecretPayloadEntry(...)]
      )
   )



Other operations with secret
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from yc_lockbox import YandexLockboxClient

   lockbox = YandexLockboxClient("oauth_or_iam_token")


   for secret in lockbox.list_secrets(folder_id="b1xxxxxxxxxx", iterator=True):
      print(secret.name, secret.status)

      secret.deactivate()
      secret.activate()

      for version in secret.list_versions(iterator=True):
         if version.id != secret.current_version.id:
               version.schedule_version_destruction()
               version.cancel_version_destruction()




Modules
-------

.. toctree::
   :maxdepth: 3
   :caption: Content:

   pages/clients.rst
   pages/models.rst
   pages/exceptions.rst
   pages/adapters.rst
   pages/abstracts.rst



Indices and tables
------------------

* :ref:`genindex`
