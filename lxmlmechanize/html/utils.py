import htmlentitydefs 

__all__ = [
    'unescape_html_entities',
    ]

def unescape_html_entities(s):
    def decode_one(m):
        try:
            v = m.group(1)
            if v is not None:
                if v[0] == 'x':
                    c = int(v[1:], 16)
                else:
                    c = int(v)
            else:
                v = m.group(2)
                c = htmlentitydefs.name2codepoint[v]
            return unichr(c)
        except:
            return m.group(0)

    return re.sub(ur'&(?:#([0-9]+|x[0-9a-fA-F]+)|([a-zA-Z-]+));', decode_one, s)
