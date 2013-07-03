from urllib import quote

def pop_from_pairs(pairs, key, *args):
    i = 0
    found = False
    value = None
    while i < len(pairs):
        k, v = pairs[i]
        if k == key:
            del pairs[i]
            value = v
            found = True
        else:
            i += 1

    if not found:
        if len(args) > 0:
            return args[0]
        else:
            raise KeyError(key)

    return value

def iterpairs(dict_like):
    if hasattr(dict_like, 'iteritems'):
        return dict_like.iteritems()
    elif hasattr(dict_like, 'items'):
        return dict_like.items()
    else:
        return iter(dict_like)

def encode_urlencoded_form_data(values, encoding):
    buf = ''
    first = True
    for k, v in iterpairs(values):
        if k is None:
            continue
        if not first:
            buf += '&'
        else:
            first = False
        if not isinstance(k, basestring):
            raise TypeError('key must be of a string type: %s' % type(k))
        buf += quote(k.encode(encoding))
        if v is not None:
            buf += '='
            if isinstance(v, basestring):
                vb = v.encode(encoding)
            else:
                if hasattr(v, 'read'):
                    vb = v.read()
                else:
                    vb = str(v)
            buf += quote(vb)
    return buf

def enclosed_param_escape_webkit(value, encoding):
    # XXX: can you believe they really do this? yeah, they do!
    return value.replace('"', '%22').encode(encoding)

def enclosed_param_escape_mozilla(value, encoding):
    # XXX: can you believe they really do this? yeah, they do!
    return value.replace('"', '\\"').encode(encoding)

def enclosed_param_escape_ie(value, encoding):
    # XXX: Hmm... You'd be falling in love with them.
    return value.encode(encoding)

def enclosed_param_escape_opera(value, encoding):
    # XXX: I don't think they are the smartest, though I won't blame them
    return value.replace('"', '').encode(encoding)

enclosed_param_escapers = dict(
    WEBKIT=enclosed_param_escape_webkit,
    MOZILLA=enclosed_param_escape_mozilla,
    IE=enclosed_param_escape_ie,
    OPERA=enclosed_param_escape_opera
    )

def encode_mime_multipart_form_data(values, encoding, boundary, param_escape_style='WEBKIT'):
    enclosed_param_escape = enclosed_param_escapers[param_escape_style.upper()]

    buf = ''

    for k, v in iterpairs(values):
        if k is None:
            continue
        buf += '--' + boundary + '\r\n'

        if not isinstance(k, basestring):
            raise TypeError('key must be of a string type: %s' % type(k))

        buf += 'Content-Disposition: form-data; name="%s"\r\n\r\n' % enclosed_param_escape(k, encoding)
        if v is not None:
            if isinstance(v, basestring):
                vb = v.encode(encoding)
            else:
                if hasattr(v, 'read'):
                    vb = v.read()
                else:
                    vb = str(v)
            buf += v
        buf += '\r\n'

    buf += '--' + boundary + '--\r\n'

    return buf

def find_form_elements(n):
    retval = []
    for cn in n:
        if cn.tag == 'input':
            retval.append(cn)
        elif cn.tag == 'select':
            retval.append(cn)
        elif cn.tag == 'textarea':
            retval.append(cn)
        elif cn.tag != 'form':
            retval.extend(find_form_elements(cn))
    return retval

def collect_form_values(result, n, submit):
    for cn in n:
        if cn.tag == 'input':
            type = cn.get('type', '').lower()
            if type in ('radio', 'checkbox'):
                if cn.get('checked') is not None:
                    result.append((cn.get('name'), cn.get('value')))
            elif type in ('submit', 'image'):
                if cn == submit:
                    result.append((cn.get('name'), cn.get('value')))
            else:
                result.append((cn.get('name'), cn.get('value')))
        elif cn.tag == 'select':
            for n in cn.findall('.//option[@selected]'):
                result.append((cn.get('name'), n.get('value')))
        elif cn.tag == 'textarea':
            result.append((cn.get('name'), cn.text))
        elif cn.tag != 'form':
            collect_form_values(result, cn, submit)
