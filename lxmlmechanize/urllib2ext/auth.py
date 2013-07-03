import urllib2
from urllib import quote
from urlparse import urljoin, urlparse, urlunparse
from warnings import warn
import itertools
import base64
import time
import re
import hashlib
import logging

logger = logging.getLogger(__name__)

SCHEME_TO_PORT_MAP = {
    'http': 80,
    'https': 443,
    'ftp': 21,
    }

def urldirname(url):
    u = urlparse(url)
    path = u[2]
    if path:
        comps = path.split('/')
        if len(comps) >= 2:
            if comps[-1] != '':
                comps.pop()
        path = '/'.join(comps)
    urlunparse((u[0], u[1], path, u[3], u[4], u[5]))

def comm_len(a, b):
    l = min(len(a), len(b))
    i = 0
    while i < l:
        if a[i] != b[i]:
            break
        i += 1
    return i

def scheme_to_port(scheme):
    return SCHEME_TO_PORT_MAP.get(scheme)

def make_scheme_and_host(parsed_url):
    x = parsed_url[1].split('@', 1)
    if len(x) == 2:
        host_and_port = x[1]
    else:
        host_and_port = x[0]
    if not ':' in host_and_port:
        port = scheme_to_port(host_and_port)
        if port is not None:
            host_and_port += ':' + port
    return parsed_url[0] + '://' + host_and_port

class RadixTrie(object):
    def __init__(self):
        self.root = ['', None, []]

    def add(self, key, value):
        o = 0
        n = self.root
        while True:
            mi = -1
            mcl = 0
            i = 0
            l = len(n[2])
            while i < l:
                cn = n[2][i]
                cl = comm_len(key[o:], cn[0])
                if cl == len(cn[0]):
                    # continue to traverse
                    o += len(cn[0])
                    n = cn
                    break
                # keep the node of the longest match
                if mcl < cl:
                    mi = i
                    mcl = cl
                i += 1
            else:
                if mi >= 0:
                    # split the node
                    mn = n[2][mi]
                    n[2][mi] = n = [mn[0][:mcl], None, [(mn[0][mcl:], mn[1], mn[2])]]
                    o += mcl

                if o < len(key):
                    n[2].append([key[o:], value, []])
                    return True
                else:
                    n[1] = value
                    return False

    def remove(self, key):
        o = 0
        n = self.root
        bn = None
        bi = -1
        while True:
            i = 0
            l = len(n[2])
            while i < l:
                cn = n[2][i]
                cl = comm_len(key[o:], cn[0])
                if cl == len(cn[0]):
                    # continue to traverse
                    o += len(cn[0])
                    bi = i
                    bn = n
                    n = cn
                    break
                i += 1
            else:
                if o == len(key):
                    if len(n[2]) == 0:
                        # remove the leaf
                        del bn[2][bi]
                        return True
                    elif len(n[2]) == 1:
                        # merge
                        bn[2][bi] = [n[0] + n[2][0][0], n[2][0][1], n[2][0][2]]
                        return True
                    else:
                        if bn[1] is None:
                            return False
                        bn[1] = None
                else:
                    return False

    def find(self, key):
        o = 0
        n = self.root
        r = ''
        while True:
            r += n[0]
            mi = -1
            mcl = 0
            i = 0
            l = len(n[2])
            while i < l:
                cn = n[2][i]
                cl = comm_len(key[o:], cn[0])
                if cl == len(cn[0]):
                    # continue to traverse
                    o += len(cn[0])
                    n = cn
                    break
                # keep the node of the longest match
                if mcl < cl:
                    mi = i
                    mcl = cl
                i += 1
            else:
                if mi >= 0:
                    r += n[2][mi][0][:mcl]
                return o, r, n[1]

    def traverse(self, key):
        o = 0
        n = self.root
        r = ''
        while True:
            r += n[0]
            i = 0
            l = len(n[2])

            if n[1] is not None:
                yield r, n[1]

            while i < l:
                cn = n[2][i]
                cl = comm_len(key[o:], cn[0])
                if cl == len(cn[0]):
                    # continue to traverse
                    o += len(cn[0])
                    n = cn
                    break
                i += 1
            else:
                break

class HTTPClientWarning(Warning):
    pass

class HTTPClientAuthWarning(HTTPClientWarning):
    pass 

class AuthAttributeParseError(ValueError):
    pass

class Credentials(object):
    @property
    def url(self):
        return self._url

    @property
    def realm(self):
        return self._realm

    @property
    def user(self):
        return self._user

    @property
    def password(self):
        return self._password

    def digest_by(self, algorithm):
        return self._digests and self._digests.get(algorithm.lower())

    def __init__(self, url, realm=None, user=None, password=None, digests=None):
        if digests is not None and password is not None:
            raise ValueError('digests given with non-empty password')
        self._url = url
        self._realm = realm
        self._user = user
        self._password = password
        self._digests = digests

class KeyChain(object):
    def __init__(self):
        self.keys = {}

    def add(self, credentials):
        canonicalized_url = self.canonicalize_url(credentials.url)
        _canonizalized_url = urlparse(canonicalized_url)
        scheme_and_host = make_scheme_and_host(_canonizalized_url)

        trie = self.keys.get(scheme_and_host)
        if trie is None:
            trie = self.keys[scheme_and_host] = RadixTrie()

        request_uri = _canonizalized_url[2]

        l, r, n = trie.find(request_uri)
        if l == len(request_uri) and n:
            keys_for_url = n
        else:
            keys_for_url = []
            trie.add(request_uri, keys_for_url)
        keys_for_url.append(credentials)

    def keys_for(self, url, canonicalize=True):
        if canonicalize:
            url = self.canonicalize_url(url)
        _url = urlparse(url)

        scheme_and_host = make_scheme_and_host(_url)
        trie = self.keys.get(scheme_and_host)

        if trie is None:
            return ()

        request_uri = _url[2]

        credentials_set = list(v for r, v in trie.traverse(request_uri))
        credentials_set.reverse()
        return itertools.chain(*credentials_set)

    def canonicalize_url(self, url):
        return url

class AuthRequestResponse(object):
    @property
    def headers(self):
        return self._headers 

    @property
    def scope(self):
        return self._scope

    def __init__(self, headers, scope):
        self._headers = headers
        self._scope = scope

class HasherRegistry(object):
    def __init__(self, **handlers):
        self.handlers = handlers

    def __getitem__(self, type):
        type = type.lower()
        retval = self.handlers.get(type)
        if retval is None:
            raise KeyError("Unsupported hashing algorithm '%s'" % type)
        return retval

    def __len__(self):
        return len(self.handlers)

    def __iter__(self):
        return iter(self.handlers)

    def items(self):
        return self.handlers.items()

    def add(self, handler):
        if handler.type in self.handlers:
            raise KeyError("Hasher is already registered for '%s'" % handler.type)
        self.handlers[handler.type] = handler

class AuthRequestResponder(object):
    authorization_header = 'Authorization'
    def __call__(self, host, request_uri, method, scheme, args, key):
        pass

class AuthRequestResponderRegistry(object):
    def __init__(self, **handlers):
        self.handlers = handlers

    def __getitem__(self, type):
        type = type.lower()
        retval = self.handlers.get(type)
        if retval is None:
            raise KeyError("Unsupported authentication type '%s'" % type)
        return retval

    def __len__(self):
        return len(self.handlers)

    def __iter__(self):
        return iter(self.handlers)

    def items(self):
        return self.handlers.items()

    def add(self, handler):
        if handler.type in self.handlers:
            raise KeyError("Handler is already registered for '%s'" % handler.type)
        self.handlers[handler.type] = handler

class BasicAuthRequestResponder(AuthRequestResponder):
    scheme = 'basic'

    def __call__(self, host,  request_uri, method, scheme, args, key):
        assert scheme == self.scheme
        realm = args.get('realm')
        if realm is None:
            warn(HTTPClientAuthWarning("'realm' is not specified in the basic authentication challenge"))
            return None
        if key.realm is not None and key.realm != realm:
            logger.debug('realms does not match; expected %s, got %s' % (key.realm, realm))
            return None
        return AuthRequestResponse(
            headers={
                self.authorization_header: \
                    'Basic ' + base64.b64encode(key.user + ':' + key.password)
                },
            scope=[
                request_uri,
                urldirname(request_uri)
                ]
            )

def escape_quoted_mime_header_param_value(value):
    return value.replace('\\', '\\\\').replace('"', '\\"')

def generate_cnonce():
    return str(time.time())

class SensibleRequest(urllib2.Request):
    def get_host(self):
        self._populate_userinfo_and_host()
        return self.host

    def get_userinfo(self):
        self._populate_userinfo_and_host()
        return self.userinfo

    def _populate_userinfo_and_host(self):
        if self.host is None or self.userinfo is None:
            userinfo_and_host, self._Request__r_host = urllib.splithost(self._Request__r_type)
            x = userinfo_and_host.split('@', 1)
            if len(x) == 1:
                x = (None, x[0])
            userinfo = x[0].split(':', 1)
            if len(userinfo) == 1:
                userinfo = (userinfo[0], None)
            self.host = x[1]
            self.userinfo = userinfo

    def __init__(self, *args, **kwargs):
        # XXX: old style class!
        urllib2.Request.__init__(self, *args, **kwargs)
        self.userinfo = None

class BasicAuthSensibleRequest(SensibleRequest):
    def __init__(self, *args, **kwargs):
        SensibleRequest.__init__(self, *args, **kwargs)
        userinfo = self.get_userinfo()
        if userinfo is not None:
            self.add_header(self.authorization_header, 'basic %s' % base64.b64encode(':'.join(userinfo)))

class DigestAuthRequestResponder(AuthRequestResponder):
    scheme = 'digest'
    algorithm_map = {
        'md5': 'md5',
        'sha1': 'sha1',
        'md5sess': 'md5'
        }

    def __init__(self, hasher_registry, cnonce_generator=generate_cnonce):
        self.hasher_registry = hasher_registry
        self.cnonce_generator = cnonce_generator
        self.nonce_count_for_host = {}

    def gen_cnonce(self):
        return self.cnonce_generator()

    def __call__(self, host, request_uri, method, scheme, args, key):
        assert scheme == self.scheme
        realm = args.get('realm')
        domain = args.get('domain')
        algorithm = args.get('algorithm', 'md5').strip().lower()
        nonce = args.get('nonce')
        opaque = args.get('opaque')
        stale = args.get('stale')
        qop = args.get('qop', '').strip().lower().split(',')

        logger.debug('digest challenge: realm=%s, domain=%s, algorithm=%s, nonce=%s, opaque=%s, stale=%s, qop=%s (method=%s, request_uri=%s)' % (realm, domain, algorithm, nonce, opaque, stale, qop, method, request_uri))

        if realm is None:
            warn(HTTPClientAuthWarning("'realm' is not specified in the basic authentication challenge"))
            return None

        nonce_count_for_host = self.nonce_count_for_host.get(host)

        if nonce_count_for_host is None:
            nonce_count_for_host = self.nonce_count_for_host[host] = {}
        if nonce is not None:
            nonce_count = nonce_count_for_host.get(nonce, 0)
            nonce_count += 1
            nonce_count_for_host[nonce] = nonce_count

        if key.realm is not None and key.realm != realm:
            logger.debug('realms does not match; expected %s, got %s' % (key.realm, realm))
            return None

        try:
            hash_algorithm = self.algorithm_map[algorithm]
            hasher = self.hasher_registry[hash_algorithm]
        except KeyError:
            warn(HTTPClientAuthWarning("algorithm '%s' is not supported" % algorithm))
            return None

        cnonce = self.gen_cnonce()

        h_a1 = key.digest_by(algorithm)
        if h_a1 is None:
            if key.password is None:
                warn(HTTPClientAuthWarning("password is not specified where no digests given" % algorithm))
                return None
            if algorithm.endswith('-sess'):
                if nonce is None:
                    warn(HTTPClientAuthWarning("nonce is not specified"))
                    return None
                a1 = key.user + ':' + realm + ':' + key.password + ':' + nonce + ':' + cnonce
            else:
                a1 = key.user + ':' + realm + ':' + key.password

        qop_chosen = None
        if qop:
            if nonce is None:
                warn(HTTPClientAuthWarning("nonce is not specified"))
                return None
            if 'auth' in qop:
                a2 = method + ':' + request_uri
                qop_chosen = 'auth'
            elif 'auth-int' in qop:
                a2 = method + ':' + request_uri + ':' + hasher(request.data)
                qop_chosen = 'auth-int'

        if qop_chosen:
            digest = hasher(hasher(a1) + ':' + nonce + ':' + ('%08x' % nonce_count) + ':' + cnonce + ':' + qop_chosen + ':' + hasher(a2))
        else:
            a2 = method + ':' + request_uri
            digest = hasher(hasher(a1) + ':' + nonce + ':' + hasher(a2))

        if qop_chosen:
            escape = escape_quoted_mime_header_param_value
            header_value = 'username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%08x, cnonce="%s", response="%s"' % (
                escape(key.user),
                escape(realm),
                escape(nonce),
                escape(request_uri),
                escape(qop_chosen),
                nonce_count,
                escape(cnonce),
                escape(digest))
        else:
            escape = escape_quoted_mime_header_param_value
            header_value = 'username="%s", realm="%s", nonce="%s", uri="%s", response="%s"' % (
                escape(key.user),
                escape(realm),
                escape(nonce),
                escape(request_uri),
                escape(digest))
        if opaque is not None:
            header_value += ', opaque="%s"' % escape(opaque)

        logger.debug('digest response: %s' % header_value)

        return AuthRequestResponse(
            headers={
                self.authorization_header: \
                    'digest ' + header_value
                },
            scope=[]
            )

hasher_registry = HasherRegistry(
    md5=lambda buf: hashlib.md5(buf).hexdigest()
    )

default_responders = AuthRequestResponderRegistry(
    basic=BasicAuthRequestResponder(),
    digest=DigestAuthRequestResponder(hasher_registry)
    )

def parse_auth_attrs(v):
    i = 0
    retval = {}
    for m in re.finditer(r'\s*(?P<key>[a-zA-Z_-][a-zA-Z0-9_-]*)\s*=\s*(?P<value>"[^"]*"|[^",\s]*)\s*(?:,|$)', v):
        s, e = m.span()
        if s != i:
            raise AuthAttributeParseError('invalid token: %s', v[i:s])
        value = m.group('value')
        if len(value) >= 2 and value[0] == '"':
            value = value[1:-1]
        retval[m.group('key')] = value
        i = e 
    if i != len(v):
        raise AuthAttributeParseError('invalid token: %s', v[i:])
    return retval 

class KeyChainBackedAuthHandler(object, urllib2.BaseHandler):
    auth_challenge_header = 'WWW-Authenticate'

    def __init__(self, keychain, auth_responder_registry=default_responders, max_retry_count_per_url=5, max_retry_count=10):
        self.keychain = keychain
        self.auth_resp_cache = {}
        self.attempt_record_for_url = {}
        self.retry_count = 0
        self.max_retry_count = max_retry_count
        self.auth_responder_registry = auth_responder_registry

    def default_open(self, req):
        url = req.get_full_url()
        _url = urlparse(url)

        trie = self.auth_resp_cache.get(make_scheme_and_host(_url))
        if trie is not None:
            request_uri = _url[2]

            l, r, auth_resp = trie.find(request_uri)
            if auth_resp is not None:
                logger.debug('using cache for %s: %s' % (url, auth_resp))
                for k, v in auth_resp.headers.items():
                    req.add_unredirected_header(k, v)

    def http_error_401(self, req, fp, code, msg, headers):
        self.retry_count += 1
        url = req.get_full_url()
        if self.retry_count >= self.max_retry_count:
            raise urllib2.HTTPError(url, 401, "Basic authentication failed", headers, None)
        challenge = headers.get(self.auth_challenge_header)
        if challenge is None:
            warn(HTTPClientAuthWarning("HTTP Authentication requested, but necessary header is not given"))
            return None
        scheme, _, arg = challenge.partition(' ')
        if scheme is None:
            warn(HTTPClientAuthWarning("Authentication challenge cannot be parsed"))
            return None
        scheme = scheme.lower()
        try:
            auth_responder = self.auth_responder_registry[scheme]
        except KeyError:
            warn(HTTPClientAuthWarning('Unknown authentication scheme'))

        attempt_record_for_url = self.attempt_record_for_url.get(url)
        if attempt_record_for_url is not None:
            if len(attempt_record_for_url) == 0:
                raise urllib2.HTTPError(url, 401, "%s authentication failed" % scheme, headers, None)
        else:
            attempt_record_for_url = self.attempt_record_for_url[url] = list(self.keychain.keys_for(url))
            logger.debug('attempts for %s: %r' % (url, attempt_record_for_url))

        if attempt_record_for_url:
            key = attempt_record_for_url.pop(0)
            logger.debug('trying with %r' % key)
            args = parse_auth_attrs(arg)
            auth_resp = auth_responder(req.get_host(), req.get_selector(), req.get_method(), scheme, args, key)
            if auth_resp is not None:
                for k, v in auth_resp.headers.items():
                    req.add_unredirected_header(k, v)

                # Retry authentication with the specified request
                resp = self.parent.open(req, timeout=req.timeout) 
                if resp and resp.code != 401:
                    for scope_url in auth_resp.scope:
                        _scope_url = urlparse(urljoin(url, scope_url))
                        scheme_and_host = make_scheme_and_host(_scope_url)
                        trie = self.auth_resp_cache.get(scheme_and_host)
                        if trie is None:
                            trie = self.auth_resp_cache[scheme_and_host] = RadixTrie()
                        trie.add(_scope_url[2], auth_resp)
                    self.retry_count = 0
                    self.attempt_record_for_url[url] = None
                    return resp


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    print parse_auth_attrs('abc="def", ghi=jkl,e=,a123=456')
    keychain = KeyChain()
    keychain.add(Credentials(url='http://localhost:12345/', user='test', password='testtest'))
    keychain.add(Credentials(url='http://localhost:12345/abc', user='test2', password='test2'))
    opener = urllib2.build_opener(KeyChainBackedAuthHandler(keychain))
    print opener.open('http://localhost:12345/', data='a').read()
    print opener.open('http://localhost:12345/abc/', data='a').read()
