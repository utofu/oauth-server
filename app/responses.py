from six.moves.urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from copy import deepcopy
from flask import jsonify, redirect

class BaseResponseBuilder(object):
    def __init__(self):
        self.state = None
        self.error = None
        self.error_description = None
        self.error_uri = None
        self.response = None

    def set_state(self, state):
        # type: (str) -> None
        self.state = state

    def set_error(self, error):
        # type: (str) -> None
        self.error = error

    def set_response(self, response):
        # type: (Dict[str, str]) -> None
        self.response = response

    @property
    def error_params(self):
        # type: () -> Dict[str, str]
        params = {
            "state": self.state,
            "error": self.error,
            "error_description": self.error_description,
            "error_uri": self.error_uri
                }
        return {k: v for k, v in params.items() if v is not None}

    @property
    def params(self):
        # type: () -> Dict[str, str]
        response = deepcopy(self.response)
        response.update({"state": self.state})
        return {k: v for k, v in response.items() if v is not None}

    def make_error_response(self, error):
        # type: (str) -> flask.Response
        self.set_error(error)
        return self._make_response(self.error_params)

    def make_response(self, response):
        # type: (Dict[str, str]) -> flask.Response
        self.set_response(response)
        return self._make_response(self.params)

    def _make_response(self, params):
        # type: (Dict[str, str]) -> flask.Response
        return jsonify(params)


class RedirectResponseBuilder(BaseResponseBuilder):

    def __init__(self):
        self._redirect_uri = None

    def set_redirect_uri(self, redirect_uri):
        self._redirect_uri = list(urlparse(redirect_uri))

    @property
    def redirect_uri(self):
        redirect_uri = deepcopy(self._redirect_uri)
        params = dict(parse_qsl(redirect_uri[4]))
        if self.error is not None:
            params.update(self.error_params)
        else:
            params.update(self.params)
        redirect_uri[4] = urlencode(params)
        return urlunparse(redirect_uri)

    def _make_response(self, params):
       if self._redirect_uri is None:
          return jsonify(params)
       else:
          return redirect(self.redirect_uri, code=302)

class RedirectWithFlagmentResponseBuilder(RedirectResponseBuilder):

    @property
    def redirect_uri(self):
        redirect_uri = deepcopy(self.__redirect_uri)
        redirect_uri[5] = urlencode(self.params)
        return urlunparse(redirect_uri)
