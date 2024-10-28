from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from typing import Any
from re import Match

import requests
from requests.compat import urljoin
from requests.models import Response

from .utils.version import get_version


requests.packages.urllib3.disable_warnings()  # type: ignore


def prepare_url(key: Match[str]) -> str:
    """Replaces capital letters to lower one with dash prefix."""
    char_elem = key.group(0)
    if char_elem.isupper():
        return "-" + char_elem.lower()
    return ""


class Config:
    DEFAULT_API_URL: str = "https://api.mailjet.com/"
    API_REF: str = "http://dev.mailjet.com/email-api/v3/"
    version: str = "v3"
    user_agent: str = "mailjet-apiv3-python/v" + get_version()

    def __init__(self, version: str | None = None, api_url: str | None = None) -> None:
        if version is not None:
            self.version = version
        self.api_url = api_url or self.DEFAULT_API_URL

    def __getitem__(self, key: str) -> tuple[str, dict[str, str]]:
        # Append version to URL.
        # Forward slash is ignored if present in self.version.
        url = urljoin(self.api_url, self.version + "/")
        headers: dict[str, str] = {"Content-type": "application/json", "User-agent": self.user_agent}
        if key.lower() == "contactslist_csvdata":
            url = urljoin(url, "DATA/")
            headers["Content-type"] = "text/plain"
        elif key.lower() == "batchjob_csverror":
            url = urljoin(url, "DATA/")
            headers["Content-type"] = "text/csv"
        elif key.lower() != "send" and self.version != "v4":
            url = urljoin(url, "REST/")
        url += key.split("_")[0].lower()
        return url, headers


class Endpoint:
    def __init__(self, url: str, headers: dict[str, str], auth: tuple[str, str] | None, action: str | None =None) -> None:
        self._url, self.headers, self._auth, self.action = url, headers, auth, action

    def _get(
        self,
        filters: Mapping[str, str | Any] | None = None,
        action_id: str | None = None,
        id: str | None = None,
        **kwargs: Any,
    ) -> Response:
        return api_call(
            self._auth,
            "get",
            self._url,
            headers=self.headers,
            action=self.action,
            action_id=action_id,
            filters=filters,
            resource_id=id,
            **kwargs,
        )

    def get_many(
        self,
        filters: Mapping[str, str | Any] | None = None,
        action_id: str | None = None,
        **kwargs: Any,
    ) -> Response:
        return self._get(filters=filters, action_id=action_id, **kwargs)

    def get(
        self,
        id: str | None = None,
        filters: Mapping[str, str | Any] | None = None,
        action_id: str | None = None,
        **kwargs: Any,
    ) -> Response:
        return self._get(id=id, filters=filters, action_id=action_id, **kwargs)

    def create(
        self,
        data: dict | None = None,
        filters: Mapping[str, str | Any] | None = None,
        id: str | None = None,
        action_id: str | None = None,
        ensure_ascii: bool = True,
        data_encoding: str = "utf-8",
        **kwargs: Any,
    ) -> Response:
        json_data: str | bytes | None = None
        if self.headers.get("Content-type") == "application/json" and data is not None:
            json_data = json.dumps(data, ensure_ascii=ensure_ascii)
            if not ensure_ascii:
                json_data = json_data.encode(data_encoding)
        return api_call(
            self._auth,
            "post",
            self._url,
            headers=self.headers,
            resource_id=id,
            data=json_data,
            action=self.action,
            action_id=action_id,
            filters=filters,
            **kwargs,
        )

    def update(
        self,
        id: str | None,
        data: dict | None = None,
        filters: Mapping[str, str | Any] | None = None,
        action_id: str | None = None,
        ensure_ascii: bool = True,
        data_encoding: str = "utf-8",
        **kwargs: Any,
    ) -> Response:
        json_data: str | bytes | None = None
        if self.headers.get("Content-type") == "application/json" and data is not None:
            json_data = json.dumps(data, ensure_ascii=ensure_ascii)
            if not ensure_ascii:
                json_data = json_data.encode(data_encoding)
        return api_call(
            self._auth,
            "put",
            self._url,
            resource_id=id,
            headers=self.headers,
            data=json_data,
            action=self.action,
            action_id=action_id,
            filters=filters,
            **kwargs,
        )

    def delete(self, id: str | None, **kwargs: Any) -> Response:
        return api_call(
            self._auth,
            "delete",
            self._url,
            action=self.action,
            headers=self.headers,
            resource_id=id,
            **kwargs,
        )


class Client:
    def __init__(self, auth: tuple[str, str] | None=None, **kwargs: Any) -> None:
        self.auth = auth
        version: str | None = kwargs.get("version")
        api_url: str | None = kwargs.get("api_url")
        self.config = Config(version=version, api_url=api_url)

    def __getattr__(self, name: str) -> Any:
        name_regex: str = re.sub(r"[A-Z]", prepare_url, name)
        split: list[str] = name_regex.split("_")
        # identify the resource
        fname: str = split[0]
        action: str | None = None
        if len(split) > 1:
            # identify the sub resource (action)
            action = split[1]
            if action == "csvdata":
                action = "csvdata/text:plain"
            if action == "csverror":
                action = "csverror/text:csv"
        url, headers = self.config[name]
        return type(fname, (Endpoint,), {})(
            url=url, headers=headers, action=action, auth=self.auth
        )


def api_call(
    auth: tuple[str, str] | None,
    method: str,
    url: str,
    headers: dict[str, str],
    data: str| bytes | None = None,
    filters: Mapping[str, str | Any] | None = None,
    resource_id: str | None = None,
    timeout: int = 60,
    debug: bool = False,
    action: str | None = None,
    action_id: str | None = None,
    **kwargs: Any,
) -> Response | Any:
    url = build_url(
        url, method=method, action=action, resource_id=resource_id, action_id=action_id
    )
    req_method = getattr(requests, method)

    try:
        filters_str: str | None = None
        if filters:
            filters_str = "&".join("%s=%s" % (k, v) for k, v in filters.items())
        response = req_method(
            url,
            data=data,
            params=filters_str,
            headers=headers,
            auth=auth,
            timeout=timeout,
            verify=True,
            stream=False,
        )

    except requests.exceptions.Timeout:
        raise TimeoutError
    except requests.RequestException as e:
        raise ApiError(e)
    except Exception:
        raise
    else:
        return response


def build_headers(
    resource: str, action: str, extra_headers: dict[str, str] | None = None
) -> dict[str, str]:
    """Build headers based on resource and action."""
    headers: dict[str, str] = {"Content-type": "application/json"}

    if resource.lower() == "contactslist" and action.lower() == "csvdata":
        headers = {"Content-type": "text/plain"}
    elif resource.lower() == "batchjob" and action.lower() == "csverror":
        headers = {"Content-type": "text/csv"}

    if extra_headers:
        headers.update(extra_headers)

    return headers


def build_url(
    url: str,
    method: str | None,
    action: str | None = None,
    resource_id: str | None = None,
    action_id: str | None = None,
) -> str:
    if resource_id:
        url += f"/{resource_id}"
    if action:
        url += f"/{action}"
        if action_id:
            url += f"/{action_id}"
    return url


def parse_response(response: Response, debug: bool = False) -> Any:
    data = response.json()

    if debug:
        logging.debug("REQUEST: %s", response.request.url)
        logging.debug("REQUEST_HEADERS: %s", response.request.headers)
        logging.debug("REQUEST_CONTENT: %s", response.request.body)

        logging.debug("RESPONSE: %s", response.content)
        logging.debug("RESP_HEADERS: %s", response.headers)
        logging.debug("RESP_CODE: %s", response.status_code)

    return data


class ApiError(Exception):
    pass


class AuthorizationError(ApiError):
    pass


class ActionDeniedError(ApiError):
    pass


class CriticalApiError(ApiError):
    pass


class ApiRateLimitError(ApiError):
    pass


class TimeoutError(ApiError):
    pass


class DoesNotExistError(ApiError):
    pass


class ValidationError(ApiError):
    pass
