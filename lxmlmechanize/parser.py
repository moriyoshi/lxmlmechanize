import re
import logging
from lxml import etree, html, sax
from .mime import MimeType
from .html import dtdutil

logger = logging.getLogger(__name__)

XHTML_NAMESPACE = u'http://www.w3.org/1999/xhtml'

XHTML_PUBLIC_IDS = [
    u"-//W3C//DTD XHTML 1.0 Strict//EN" ,
    u"-//W3C//DTD XHTML 1.0 Transitional//EN",
    u"-//W3C//DTD XHTML 1.0 Frameset//EN",
    ]

class ParserWrapper(object):
    def __init__(self, impl, encoding):
        self.impl = impl
        self.encoding = encoding


RE_STR_ATTRS = r'([\x09\x0a\x0d\x20]+(?P<name>[0-9a-zA-Z_-]+)(?:[\x09\x0a\x0d\x20]*=[\x09\x0a\x0d\x20]*(?P<value>"[^"]*"|[^\x09\x0a\x0d\x20="<>]*))?)'
RE_META_PROLOGUE = re.compile(
    r'<meta(%s*)[\x09\x0a\x0d\x20]*/?>' % RE_STR_ATTRS,
    re.IGNORECASE
    )

def find_parse_meta(doc_str):
    retval = []
    for m in RE_META_PROLOGUE.finditer(doc_str):
        d = {}
        for kvm in re.finditer(RE_STR_ATTRS, m.group(1)):
            value = kvm.group('value')
            if value[0] == '"':
                value = value[1:-1]
            d[kvm.group('name').lower()] = value
        retval.append(d)
    return retval

def find_content_type_meta(doc_str):
    for meta in find_parse_meta(doc_str):
        if meta.get('http-equiv').lower() == 'content-type':
            return meta.get('content')
    return None

def detect_encoding_html(doc_str):
    m = re.search(
        '(?:'
        '(' '\x00\x00\x00<\x00\x00\x00[mM]\x00\x00\x00[eE]\x00\x00\x00[tT]\x00\x00\x00[aA]\x00\x00\x00[\x09\x0a\x0d\x20]' ')' '|' \
        '(' '<\x00\x00\x00[mM]\x00\x00\x00[eE]\x00\x00\x00[tT]\x00\x00\x00[aA]\x00\x00\x00[\x09\x0a\x0d\x20]\x00\x00\x00' ')' '|' \
        '(' '\x00<\x00[mM]\x00[eE]\x00[tT]\x00[aA]\x00[\x09\x0a\x0d\x20]' ')' '|' \
        '(' '<\x00[mM]\x00[eE]\x00[tT]\x00[aA]\x00[\x09\x0a\x0d\x20]\x00' ')' '|' \
        '(' '<[mM][eE][tT][aA][\x09\x0a\x0d\x20]' ')' \
        ')',
        doc_str,
        re.VERBOSE
        )
    if m is None:
        return None

    encoding_detected_from_byte_sequences = None
    if m.group(1) is not None:
        encoding_detected_from_byte_sequences = 'utf-32be'
    elif m.group(2) is not None:
        encoding_detected_from_byte_sequences = 'utf-32le'
    elif m.group(3) is not None:
        encoding_detected_from_byte_sequences = 'utf-16be'
    elif m.group(4) is not None:
        encoding_detected_from_byte_sequences = 'utf-16le'

    if encoding_detected_from_byte_sequences is not None:
        try:
            retval = MimeType.fromstring(find_content_type_meta(unicode(doc_str, encoding_detected_from_byte_sequences)))
        except:
            return None
        meta_charset = retval.get('charset')
        if meta_charset is not None and meta_charset.lower() != encoding_detected_from_byte_sequences:
            warn(Warning(
                'WTF? the document is encoded in %s while the contained meta-tag says it being encoded in %s' % (
                    encoding_detected_from_byte_sequences,
                    retval['charset']
                    )))
        return encoding_detected_from_byte_sequences
    elif m.group(5) is not None:
        # 8-bit encodings
        try:
            retval = MimeType.fromstring(find_content_type_meta(doc_str))
        except:
            return None
        return retval.get('charset')

    return None

def html_encoding_detector(doc_str, possible_encodings):
    for encoding in possible_encodings:
        try:
            enc_result = unicode(doc_str, encoding)
            return enc_result, encoding
        except:
            continue

    possible_encodings = []
    try:
        import chardet
        possible_encodings.append(chardet.detect(doc_str)['encoding'])
    except:
        # check for BOMs
        if doc_str[0:2] == '\xfe\xff':
            possible_encodings.append('utf-16be')
        elif doc_str[0:2] == '\xff\xfe':
            possible_encodings.append('utf-16le')
        elif doc_str[0:3] == '\xef\xbb\xbf':
            possible_encodings.append('utf-8')
        elif doc_str[0:4] == '\x00\x00\xfe\xff':
            possible_encodings.append('utf-32be')
        elif doc_str[0:4] == '\x00\x00\xff\xfe':
            possible_encodings.append('utf-32le')

    encoding_specified_in_payload = detect_encoding_html(doc_str)
    if encoding_specified_in_payload is not None:
        possible_encodings.append(encoding_specified_in_payload)

    for encoding in possible_encodings:
        try:
            enc_result = unicode(doc_str, encoding)
            return enc_result, encoding
        except:
            continue

class ParserFactory(object):
    def __init__(self, element_class_lookup, strict=False):
        self.element_class_lookup = element_class_lookup
        self.strict = strict

    def __call__(self, content_type, doc_str, default_encoding=None):
        parser = None
        doctype = None

        try:
            doctype = dtdutil.DocumentTypeDecl.fromstring(doc_str)
        except dtdutil.ParseError:
            pass

        possible_encodings = []
        _encoding = content_type.get('charset')
        if _encoding is not None:
            possible_encodings.append(_encoding)

        result = html_encoding_detector(doc_str, possible_encodings)
        if result is not None:
            doc_str = result[0]
            encoding = result[1]
        else:
            encoding = default_encoding
       
        logger.debug('content-type=%s' % content_type.type)
        if content_type.type == 'text/html':
            if doctype is not None and \
                    doctype.name.lower() == 'html':
                if doctype.extern_id is not None:
                    if isinstance(doctype.extern_id, dtdutil.DocumentTypeDecl.PublicIdentifier) and \
                            doctype.extern_id.public_identifier in XHTML_PUBLIC_IDS:
                        if self.strict:
                            parser = html.XHTMLParser(load_dtd=True, encoding=encoding)
                        else:
                            parser = html.HTMLParser(encoding=encoding)
                else:
                    parser = html.HTML5Parser(encoding=encoding)
        elif content_type.type == 'application/xhtml+xml':
            parser = html.XHTMLParser(load_dtd=False, encoding=encoding)

        if parser is None:
            parser = etree.HTMLParser(encoding=encoding)

        parser.set_element_class_lookup(self.element_class_lookup)
        return ParserWrapper(parser, encoding)

class OurHtmlElement(etree.ElementBase, html.HtmlMixin):
    HTML = True
    NAMESPACE = XHTML_NAMESPACE

class OurHTMLElementClassLookup(html.HtmlElementClassLookup):
    def lookup(self, type, doc, namespace, name):
        if type == 'element':
            return OurHtmlElement
        else:
            return super(OurHTMLElementClassLookup, self).lookup(type, doc, namespace, name)


