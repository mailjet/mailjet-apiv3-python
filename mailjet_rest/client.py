#!/usr/bin/env python
# coding=utf-8

import json
import logging

import requests
from requests.compat import urljoin

requests.packages.urllib3.disable_warnings()

class Config(object):
    API_URL = 'https://api.mailjet.com/'
    API_DOC = 'http://dev.mailjet.com/email-api/'
    VERSION = 'v3'
    MAKE_API_CALL = True # ???

    def __getitem__(self, key):
        url = self.API_URL[0:]
        version = self.VERSION
        headers = {'Content-type': 'application/json', 'User-agent': 'mailjet-apiv3-python'}
        if key.lower() == 'contactslist_csvdata':
            url = urljoin(url, 'DATA/')
            headers['Content-type'] = 'text/plain'
        elif key.lower() == 'batchjob_csverror':
            url = urljoin(url, 'DATA/')
            headers['Content-type'] = 'text/csv'
        elif key.lower() != 'send':
            url = urljoin(url, 'REST/')
        url = url + key.split('_')[0].lower()
        return url, headers


class Endpoint(object):

    def __init__(self, url, headers, auth, action=None, version=None, make_api_call=None):
        self._url, self.headers, self._auth, self.action, self._version, self._make_api_call = url, headers, auth, action, version, make_api_call

    def __doc__(self):
        return self._doc

    def _get(self, filters=None, action_id=None, id=None, options=None, **kwargs):
        url, make_api_call = handle_options(options=options)
        return api_call(self._auth, 'get', url, headers=self.headers, action=self.action, action_id=action_id, filters=filters, resource_id=id, make_api_call=make_api_call, **kwargs)

    def get_many(self, filters=None, action_id=None, options=None, **kwargs):
        return self._get(filters=filters, options=options, **kwargs)

    def get(self, id=None, filters=None, action_id=None, options=None, **kwargs):
        return self._get(id=id, filters=filters, options=options, **kwargs)

    def create(self, data=None, filters=None, id=None, action_id=None, options=None, make_api_call=make_api_call, **kwargs):
        url, make_api_call = handle_options(options=options)
        if self.headers['Content-type'] == 'application/json':
            data = json.dumps(data)
        return api_call(self._auth, 'post', self._url, headers=self.headers, resource_id=id, data=data, action=self.action, action_id=action_id, filters=filters, make_api_call=make_api_call, **kwargs)

    def update(self, id, data, filters=None, action_id=None, options=None, **kwargs):
        url, make_api_call = handle_options(options=options)
        if self.headers['Content-type'] == 'application/json':
            data = json.dumps(data)
        return api_call(self._auth, 'put', url, resource_id=id, headers=self.headers, data=data, action=self.action, action_id=action_id, filters=filters, make_api_call=make_api_call, **kwargs)

    def delete(self, id, options=None, **kwargs):
        url, make_api_call = handle_options(options=options)
        return api_call(self._auth, 'delete', self._url, action=self.action, headers=self.headers, resource_id=id, make_api_call=make_api_call, **kwargs)
    
    def handle_options(self, options=None):
        if 'url' in options:
            url = options['url']
        else:
            url = self._url
        if 'version' in options:
            url = url + '/' + options['version']
        else:
            url = url + '/' + self._version
        if 'make_api_call' in options:
            make_api_call = options['make_api_call']
        else:
            make_api_call = self._make_api_call
        
        return url, make_api_call

class Client(object):

    def __init__(self, auth=None, config=Config(), options=None):
        self.auth, self.config = auth, config
        if 'url' in options:
            self.url = options['url']
        else:
            self.url = config['url']
        if 'version' in options:
            self.version = options['version']
        else:
            self.version = config['version']
        if 'make_api_call' in options:
            self.make_api_call = options['make_api_call']
        else:
            self.make_api_call = config['make_api_call']

    def __getattr__(self, name):
        split = name.split('_')
        fname = split[0]
        action = None
        if (len(split) > 1):
            action = split[1]
            if action == 'csvdata':
                action = 'csvdata/text:plain'
            if action == 'csverror':
                action = 'csverror/text:csv'
        url, headers = self.config[name]
        return type(fname, (Endpoint,), {})(url=self.url, headers=headers, action=action, auth=self.auth, version=self.version, make_api_call=self.make_api_call)


def api_call(auth, method, url, headers, data=None, filters=None, resource_id=None,
             timeout=60, debug=False, action=None, action_id=None, **kwargs):
    url = build_url(url, method=method, action=action, resource_id=resource_id, action_id=action_id)
    req_method = getattr(requests, method)

    try:
        response = req_method(url, data=data, params=filters, headers=headers, auth=auth,
                              timeout=timeout, verify=False, stream=False)
        return response

    except requests.exceptions.Timeout:
        raise TimeoutError
    except requests.RequestException as e:
        raise ApiError(e)
    except Exception as e:
        raise


def build_headers(resource, action=None, extra_headers=None):
    headers = {'Content-type': 'application/json'}

    if resource.lower() == 'contactslist' and action.lower() == 'csvdata':
        headers = {'Content-type': 'text/plain'}
    elif resource.lower() == 'batchjob' and action.lower() == 'csverror':
        headers = {'Content-type': 'text/csv'}

    if extra_headers:
        headers.update(extra_headers)

    return headers


def build_url(url, method, action=None, resource_id=None, action_id=None):
    if resource_id:
        url += '/%s' % str(resource_id)
    if action:
        url += '/%s' % action
        if action_id:
            url += '/%d' % action_id

    return url


def parse_response(response, debug=False):
    data = response.json()

    if debug:
        logging.debug('REQUEST: %s' % response.request.url)
        logging.debug('REQUEST_HEADERS: %s' % response.request.headers)
        logging.debug('REQUEST_CONTENT: %s' % response.request.body)

        logging.debug('RESPONSE: %s' % response.content)
        logging.debug('RESP_HEADERS: %s' % response.headers)
        logging.debug('RESP_CODE: %s' % response.status_code)

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
