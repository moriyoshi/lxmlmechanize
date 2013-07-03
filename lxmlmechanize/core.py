import re
import logging
import urllib2
from urlparse import urljoin
from cookielib import CookieJar
from email.generator import _make_boundary
from lxml import etree
from .form import encode_mime_multipart_form_data, encode_urlencoded_form_data, find_form_elements, collect_form_values
from .parser import ParserFactory, OurHTMLElementClassLookup
from .mime import MimeType
from .urllib2ext import KeyChain, KeyChainBackedAuthHandler

FORM_URLENCODE_MIME_TYPE = u'application/x-www-form-urlencoded'
FORM_MULTIPART_MIME_TYPE = u'multipart/form-data'

logger = logging.getLogger(__name__)

default_keychain = KeyChain()

class MechanizeError(Exception):
    pass

class HtmlDocument(object):
    def __init__(self, root, encoding, parse_error_log=None):
        self._root = root

        # visit all nodes to make sure that the namespace translation
        # is applied to every element
        for n in root.iter():
            pass

        self.encoding = encoding
        self.parse_error_log = parse_error_log

    @property
    def root(self):
        return self._root

class Mechanize(object):
    def __init__(self, default_encoding='utf-8', handle_meta_refresh=True, opener=None, parser_factory=None):
        self.page = None
        self.location = None
        self.loader = None
        self.default_encoding = default_encoding
        self.handle_meta_refresh = handle_meta_refresh
        if opener is None:
            opener = urllib2.build_opener(
                KeyChainBackedAuthHandler(default_keychain),
                urllib2.HTTPCookieProcessor(CookieJar()))
        self.opener = opener
        if parser_factory is None:
            parser_factory = ParserFactory(OurHTMLElementClassLookup())
        self.parser_factory = parser_factory
    @property
    def encoding(self):
        if self.page is not None:
            return self.page.encoding
        else:
            return self.default_encoding

    def reload(self):
        if self.loader is None:
            return
        f = self.loader()
        next_url = f.url
        self.page = self._load_document(f, next_url)
        self.location = next_url
        meta_tags = self.page.root.findall('.//meta')
        for meta_tag in meta_tags:
            http_equiv = meta_tag.get('http-equiv', '').lower()
            if http_equiv == 'refresh':
                m = re.match(r'([0-9]*)\s*;\s*url\s*=\s*(.*)\s*$', meta_tag.get('content', ''), re.IGNORECASE)
                if m is not None:
                    next_url = m.group(2)
                    self.navigate(next_url)

    def _load_document(self, f, source_url=None):
        doc_str = f.read()
        logger.debug(doc_str)
        content_type_str = f.headers.get('Content-Type')
        if not content_type_str:
            content_type_str = 'text/html'
        content_type = MimeType.fromstring(content_type_str)
        parser_wrapper = self.parser_factory(content_type, doc_str, self.default_encoding)
        doc = etree.fromstring(doc_str, parser=parser_wrapper.impl, base_url=source_url)
        return HtmlDocument(doc, parser_wrapper.encoding, parser_wrapper.impl.error_log)

    def submit_form(self, form, submit=None):
        self.loader = self.fetch_form(form, submit)
        self.reload()

    def fetch_form(self, form, submit=None):
        values = []
        form_elements = find_form_elements(form)
        if submit is None:
            submits = [_submit for _submit in form_elements if _submit.get('type', '').lower() in ('submit', 'image')]
            if len(submits) == 1:
                submit = submits[0]
            elif submits:
                raise MechanizeError('multiple submit buttons exist. specify any one')
        collect_form_values(values, form_elements, submit)
        method = form.get('method').upper()
        enctype = form.get('enctype', FORM_URLENCODE_MIME_TYPE)
        url = urljoin(self.location, form.get('action'))

        logger.debug('submit_form: method=%s, url=%s, enctype=%s, values=%r' % (method, url, enctype, values))

        if method.upper() == 'GET':
            encoding = self.encoding
            queries = urlencoded_form_data(values)
            final_url = urljoin(url, '?' + queries)
            return lambda: self.opener.open(urllib2.Request(final_url))
        else:
            headers = None
            if enctype == FORM_URLENCODE_MIME_TYPE:
                data = encode_urlencoded_form_data(values, self.encoding)
                headers = {
                    'Content-Type': FORM_URLENCODE_MIME_TYPE
                    }
            else:
                boundary = _make_boundary()
                data = encode_mime_multipart_form_data(values, self.encoding, boundary)
                headers = {
                    'Content-Type': '%s; boundary=%s' % (FORM_MULTIPART_MIME_TYPE,
                                                       boundary)
                    }
            return lambda: self.opener.open(urllib2.Request(url, data=data, headers=headers))

    def navigate(self, url):
        self.loader = self.fetch(url)
        self.reload()

    def fetch(self, url):
        return lambda: self.opener.open(urljoin(self.location, url))

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    from .urllib2ext import Credentials
    m = Mechanize()
    default_keychain.add(Credentials('http://localhost:12345/', None, 'test', 'testtest'))
    m.navigate('http://localhost:12345/')
    form = m.page.root.xpath('body//form[@id="test"]')[0]
    form.xpath('input[@name="user"]')[0].set('value', 'user')
    form.xpath('input[@name="password"]')[0].set('value', 'password')
    m.submit_form(form)
    print html.tostring(m.page.root, encoding='utf-8')
