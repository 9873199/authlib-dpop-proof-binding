from collections import defaultdict

from ..rfc6749.requests import OAuth2Payload


class FrozenAuthorizationPayload(OAuth2Payload):
    """The immutable, validated parameters loaded from PAR storage.

    It replaces the front-channel payload instead of being merged with it, so
    extra browser parameters can never form a new, never-validated request.
    """

    def __init__(self, datalist):
        self._datalist = defaultdict(list)
        for name, values in datalist.items():
            self._datalist[name] = list(values)
        self._data = {
            name: values[0] for name, values in self._datalist.items() if values
        }

    @property
    def data(self):
        return self._data

    @property
    def datalist(self):
        return self._datalist
