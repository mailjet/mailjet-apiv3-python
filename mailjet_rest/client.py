import json
import logging
import re

import requests
from requests.compat import urljoin

from .utils.version import get_version


requests.packages.urllib3.disable_warnings()


def prepare_url(key):
    """Replaces capital letters to lower one with dash prefix."""
    char_elem = key.group(0)
    if char_elem.isupper():
        return "-" + char_elem.lower()
    return ""


class Config:
    DEFAULT_API_URL = "https://api.mailjet.com/"
    API_REF = "http://dev.mailjet.com/email-api/v3/"
    version = "v3"
    user_agent = "mailjet-apiv3-python/v" + get_version()

    def __init__(self, version=None, api_url=None):
        if version is not None:
            self.version = version
        self.api_url = api_url or self.DEFAULT_API_URL

    def __getitem__(self, key):
        # Append version to URL.
        # Forward slash is ignored if present in self.version.
        url = urljoin(self.api_url, self.version + "/")
        headers = {"Content-type": "application/json", "User-agent": self.user_agent}
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
    def __init__(self, url, headers, auth, action=None):
        self._url, self.headers, self._auth, self.action = url, headers, auth, action

    def _get(self, filters=None, action_id=None, id=None, **kwargs):
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

    def get_many(self, filters=None, action_id=None, **kwargs):
        return self._get(filters=filters, action_id=action_id, **kwargs)

    def get(self, id=None, filters=None, action_id=None, **kwargs):
        return self._get(id=id, filters=filters, action_id=action_id, **kwargs)

    def create(
        self,
        data=None,
        filters=None,
        id=None,
        action_id=None,
        ensure_ascii=True,
        data_encoding="utf-8",
        **kwargs,
    ):
        if self.headers["Content-type"] == "application/json":
            if ensure_ascii:
                data = json.dumps(data)
            else:
                data = json.dumps(data, ensure_ascii=False).encode(data_encoding)
        return api_call(
            self._auth,
            "post",
            self._url,
            headers=self.headers,
            resource_id=id,
            data=data,
            action=self.action,
            action_id=action_id,
            filters=filters,
            **kwargs,
        )

    def update(
        self,
        id,
        data,
        filters=None,
        action_id=None,
        ensure_ascii=True,
        data_encoding="utf-8",
        **kwargs,
    ):
        if self.headers["Content-type"] == "application/json":
            if ensure_ascii:
                data = json.dumps(data)
            else:
                data = json.dumps(data, ensure_ascii=False).encode(data_encoding)
        return api_call(
            self._auth,
            "put",
            self._url,
            resource_id=id,
            headers=self.headers,
            data=data,
            action=self.action,
            action_id=action_id,
            filters=filters,
            **kwargs,
        )

    def delete(self, id, **kwargs):
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
    def __init__(self, auth=None, **kwargs):
        self.auth = auth
        version = kwargs.get("version")
        api_url = kwargs.get("api_url")
        self.config = Config(version=version, api_url=api_url)

    def __getattr__(self, name):
        name = re.sub(r"[A-Z]", prepare_url, name)
        split = name.split("_")
        # identify the resource
        fname = split[0]
        action = None
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
    auth,
    method,
    url,
    headers,
    data=None,
    filters=None,
    resource_id=None,
    timeout=60,
    debug=False,
    action=None,
    action_id=None,
    **kwargs,
):
    url = build_url(
        url, method=method, action=action, resource_id=resource_id, action_id=action_id
    )
    req_method = getattr(requests, method)

    try:
        filters_str = None
        if filters:
            filters_str = "&".join(f"{k}={v}" for k, v in filters.items())
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


def build_headers(resource, action=None, extra_headers=None):
    headers = {"Content-type": "application/json"}

    if resource.lower() == "contactslist" and action.lower() == "csvdata":
        headers = {"Content-type": "text/plain"}
    elif resource.lower() == "batchjob" and action.lower() == "csverror":
        headers = {"Content-type": "text/csv"}

    if extra_headers:
        headers.update(extra_headers)

    return headers


def build_url(url, method, action=None, resource_id=None, action_id=None):
    if resource_id:
        url += f"/{resource_id}"
    if action:
        url += f"/{action}"
        if action_id:
            url += f"/{action_id}"
    return url


def parse_response(response, debug=False):
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
