from email.message import Message

__all__ = [
    'MimeType',
    ]

class MimeType(object):
    def __init__(self, type, params):
        self.type = type
        self.params = params

    def __getitem__(self, key):
        return self.params[key]

    def get(self, key):
        return self.params.get(key)

    @classmethod
    def fromstring(cls, value):
        m = Message()
        m['Content-Type'] = value
        params = m.get_params(header='content-type', unquote=True)
        type, _ = params.pop(0)
        return cls(type, dict(params))
