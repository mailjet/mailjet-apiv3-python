from requests.auth import AuthBase


def _bearer_token_str(token):
    if not isinstance(token, str):
        token = str(token)
    authstr = 'Bearer {}'.format(token)
    return authstr


class HTTPBearerAuth(AuthBase):
    """Attaches HTTP Bearer Authentication to the given Request object."""

    def __init__(self, token):
        self.token = token

    def __eq__(self, other):
        return self.token == getattr(other, 'token', None)

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = _bearer_token_str(self.token)
        return r
