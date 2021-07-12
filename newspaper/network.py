# -*- coding: utf-8 -*-
"""
All code involving requests and responses over the http network
must be abstracted in this file.
"""
__title__ = 'newspaper'
__author__ = 'Lucas Ou-Yang'
__license__ = 'MIT'
__copyright__ = 'Copyright 2014, Lucas Ou-Yang'

import logging
import requests
import dns.resolver

from requests.adapters import HTTPAdapter

from .configuration import Configuration
from .mthreading import ThreadPool
from .settings import cj

log = logging.getLogger(__name__)

FAIL_ENCODING = 'ISO-8859-1'


class HostHeaderSSLAdapterWithDnsCache(HTTPAdapter):
    def __init__(self, name_servers):
        self.name_servers = name_servers
        super().__init__()

    def resolve(self, host_name, record_type):
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = self.name_servers
        answers = dns_resolver.query(host_name, record_type)
        for rdata in answers:
            return str(rdata)

    def send(self, request, **kwargs):
        from urllib.parse import urlparse

        connection_pool_kwargs = self.poolmanager.connection_pool_kw

        result = urlparse(request.url)
        resolved_ip = self.resolve(result.hostname, 'A')
        # print("A record: {}".format(resolved_ip))

        if result.scheme == 'https' and resolved_ip:
            request.url = request.url.replace(
                'https://' + result.hostname,
                'https://' + resolved_ip,
            )
            connection_pool_kwargs['server_hostname'] = result.hostname  # SNI
            connection_pool_kwargs['assert_hostname'] = result.hostname

            # overwrite the host header
            request.headers['Host'] = result.hostname
        else:
            # theses headers from a previous request may have been left
            connection_pool_kwargs.pop('server_hostname', None)
            connection_pool_kwargs.pop('assert_hostname', None)

        # print("Resolved URL: {}".format(request.url))
        return super(HostHeaderSSLAdapterWithDnsCache, self).send(request, **kwargs)


def get_request_mode(with_dns_cache, dns_name_servers, url: str):
    if not with_dns_cache:
        return requests

    nameservers = dns_name_servers
    session = requests.Session()
    session.mount(url, HostHeaderSSLAdapterWithDnsCache(nameservers))

    return session


def get_request_kwargs(timeout, useragent, proxies, headers):
    """This Wrapper method exists b/c some values in req_kwargs dict
    are methods which need to be called every time we make a request
    """
    return {
        'headers': headers if headers else {'User-Agent': useragent},
        'cookies': cj(),
        'timeout': timeout,
        'allow_redirects': True,
        'proxies': proxies
    }


def get_html(url, config=None, response=None):
    """HTTP response code agnostic
    """
    try:
        return get_html_2XX_only(url, config, response)
    except requests.exceptions.RequestException as e:
        log.debug('get_html() error. %s on URL: %s' % (e, url))
        return ''


def get_html_2XX_only(url, config=None, response=None):
    """Consolidated logic for http requests from newspaper. We handle error cases:
    - Attempt to find encoding of the html by using HTTP header. Fallback to
      'ISO-8859-1' if not provided.
    - Error out if a non 2XX HTTP response code is returned.
    """
    config = config or Configuration()
    useragent = config.browser_user_agent
    timeout = config.request_timeout
    proxies = config.proxies
    headers = config.headers
    with_dns_cache = config.with_dns_cache
    dns_name_servers = config.dns_name_servers

    if response is not None:
        return _get_html_from_response(response)

    response = get_request_mode(
        with_dns_cache=with_dns_cache,
        dns_name_servers=dns_name_servers,
        url=url
    ).get(url=url, **get_request_kwargs(timeout, useragent, proxies, headers))

    html = _get_html_from_response(response)

    if config.http_success_only:
        # fail if HTTP sends a non 2XX response
        response.raise_for_status()

    return html


def _get_html_from_response(response):
    if response.encoding != FAIL_ENCODING:
        # return response as a unicode string
        html = response.text
    else:
        html = response.content
        if 'charset' not in response.headers.get('content-type'):
            encodings = requests.utils.get_encodings_from_content(response.text)
            if len(encodings) > 0:
                response.encoding = encodings[0]
                html = response.text
    return html or ''


class MRequest(object):
    """Wrapper for request object for multithreading. If the domain we are
    crawling is under heavy load, the self.resp will be left as None.
    If this is the case, we still want to report the url which has failed
    so (perhaps) we can try again later.
    """

    def __init__(self, url, config=None):
        self.url = url
        self.config = config
        config = config or Configuration()
        self.useragent = config.browser_user_agent
        self.timeout = config.request_timeout
        self.proxies = config.proxies
        self.headers = config.headers
        self.with_dns_cache = config.with_dns_cache
        self.dns_name_servers = config.dns_name_servers

        self.resp = None

    def send(self):
        try:
            self.resp = get_request_mode(
                with_dns_cache=self.with_dns_cache,
                dns_name_servers=self.dns_name_servers,
                url=url
            ).get(self.url, **get_request_kwargs(self.timeout, self.useragent, self.proxies, self.headers))
            if self.config.http_success_only:
                self.resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            log.critical('[REQUEST FAILED] ' + str(e))


def multithread_request(urls, config=None):
    """Request multiple urls via mthreading, order of urls & requests is stable
    returns same requests but with response variables filled.
    """
    config = config or Configuration()
    num_threads = config.number_threads
    timeout = config.thread_timeout_seconds

    pool = ThreadPool(num_threads, timeout)

    m_requests = []
    for url in urls:
        m_requests.append(MRequest(url, config))

    for req in m_requests:
        pool.add_task(req.send)

    pool.wait_completion()
    return m_requests
