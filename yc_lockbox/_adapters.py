import logging
import requests
from typing import Any, Type

from yc_lockbox._abc import AbstractHTTPAdapter
from yc_lockbox._models import YandexCloudError
from yc_lockbox._types import T

logger = logging.getLogger(__name__)


class HTTPAdapter(AbstractHTTPAdapter):
    """
    An basic adapter for HTTP requests to origin.
    """

    @staticmethod
    def parse_response(
        response: requests.Response,
        response_model: Type[T] | None = None,
    ) -> T | Any:
        """
        Parse response from Origin.

        :param response: A HTTP-response object.
        :param response_model: Python object that will be used for transform response from origin.
        """
        match response.headers.get("Content-Type"):
            case "application/json":
                result = response.json()

                if response_model is not None:
                    if isinstance(result, list):
                        result = [response_model(**i) for i in result]
                        return result
                    return response_model(**result)

                return result
            case "text/plain":
                return response.text
            case _:
                return response.content

    @staticmethod
    def request(
        method: str,
        url: str,
        data: str | bytes | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        response_model: Type[T] | None = None,
        raise_for_status: bool = True,
        **kwargs,
    ) -> T | Any:
        """
        Method for make HTTP-requests.

        :param method: HTTP-method for request. Example: ``GET``, ``POST``.
        :param url: Request URL. Example ``https://api.example.com/users``.
        :param params: Dictionary request parameters to be sent in the query string.
        :param data: Dictionary, bytes, or file-like object to send in the body of the request.
        :param json: Any json compatible python object.
        :param headers: Dictionary of HTTP Headers to send with the request.
        :param response_model: Python object that will be used for transform response from origin.
        :param raise_client_errors: If set to ``True``, any client error (``4xx`` status code)
            will be throw exception.

        """

        response = requests.request(
            method=method, url=url, data=data, json=json, headers=headers, params=params, **kwargs
        )

        if response.status_code >= 400:
            logger.error(f"HTTP request failed with status {response.status_code}: {response.content.decode()}")

            if raise_for_status:
                response.raise_for_status()

            return __class__.parse_response(response, response_model=YandexCloudError)

        return __class__.parse_response(response, response_model=response_model)


class AsyncHTTPAdapter(AbstractHTTPAdapter):
    """
    Another adapter for HTTP requests to origin.
    Similar to :class:`HTTPAdapter` but async.
    """

    @staticmethod
    async def parse_response(response: requests.Response, response_model: Type[T] | None = None) -> T | Any:
        """
        Parse response from Origin.

        :param response: A HTTP-response object.
        :param response_model: Python object that will be used for transform response from origin.
        """

        match response.headers.get("Content-Type"):
            case "application/json":
                result = await response.json()

                if response_model is not None:
                    if isinstance(result, list):
                        result = [response_model(**i) for i in result]
                        return result
                    return response_model(**result)

                return result
            case "text/plain":
                return await response.text()
            case _:
                return await response.read()

    @staticmethod
    async def request(
        method: str,
        url: str,
        data: str | bytes | None = None,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        response_model: Type[T] | None = None,
        raise_for_status: bool = True,
        **kwargs,
    ) -> T | Any:
        """
        Method for asynchronous make HTTP-requests.

        :param method: HTTP-method for request. Example: ``GET``, ``POST``.
        :param url: Request URL. Example ``https://api.example.com/users``.
        :param params: Dictionary request parameters to be sent in the query string.
        :param data: Dictionary, bytes, or file-like object to send in the body of the request.
        :param json: Any json compatible python object.
        :param headers: Dictionary of HTTP Headers to send with the request.
        :param response_model: Python object that will be used for transform response from origin.
        :param raise_client_errors: If set to ``True``, any client error (``4xx`` status code)
            will be throw exception.

        """
        try:
            import aiohttp
        except ImportError:
            raise ImportError(
                "Async mode is unavailable cause mandatory library ``aiohttp`` is not installed. "
                "Install ``aiohttp`` directly ``pip install aiohttp`` "
                "or use ``pip install yc-lockbox[aio]`` for resolve it."
            )

        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=method, url=url, data=data, json=json, headers=headers, params=params, **kwargs
            ) as response:

                if response.status >= 400:
                    response_message = await response.read()
                    logger.error(f"HTTP request failed with status {response.status}: {response_message.decode()}")

                    if raise_for_status:
                        response.raise_for_status()

                    return await __class__.parse_response(response, response_model=YandexCloudError)

                return await __class__.parse_response(response, response_model=response_model)
