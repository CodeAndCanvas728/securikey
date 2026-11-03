"""A small client for Paperclip's secrets API, on the standard library only.

Two callers use it: `skey sync paperclip` and `skey rotate` (a person with a board token, one
company) and `skey run --env-from-paperclip` (an agent, with the run-bound token Paperclip puts
in its environment). Nothing here prints or logs a value: errors carry the HTTP status and the
server's message, cut short and redacted against everything the keychain holds.

Routes (Paperclip server 2026.1023.0, server/skills/paperclip/references/api-reference.md):
  GET   /api/companies/:company/secrets          list, metadata only
  POST  /api/companies/:company/secrets          create {name, key, value}
  POST  /api/secrets/:id/rotate                  new version {value}
  POST  /api/agents/me/secrets/:key/value        fetch one granted value, empty body
"""
import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from securikey.redact import redact
from securikey.store import VaultError

URL_ENV = "SECURIKEY_PAPERCLIP_URL"
COMPANY_ENV = "SECURIKEY_PAPERCLIP_COMPANY"
TOKEN_ENV = "SECURIKEY_PAPERCLIP_TOKEN"
TOKEN_NAME = "paperclip_token"  # the keychain name a token is stored under; never synced to Paperclip
AGENT_URL_ENV = "PAPERCLIP_API_URL"  # set by Paperclip for a run
AGENT_TOKEN_ENV = "PAPERCLIP_API_KEY"
TIMEOUT = 15  # seconds
MAX_ERROR = 200  # characters of a server message shown
KEY_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,120}$")  # Paperclip's secret key rule
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def base_url(url):
    """The server root from what a person or Paperclip wrote: no trailing `/` or `/api`.

    The token and the values travel in these requests, so plain http is accepted for the
    local machine only.
    """
    parts = urllib.parse.urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise VaultError("the Paperclip URL must start with http:// or https://")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK:
        raise VaultError("the Paperclip URL must be https:// unless it is on this machine")
    path = parts.path.rstrip("/")
    if path.endswith("/api"):
        path = path[:-4]
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib copies the Authorization header onto a redirected request, so a redirect would hand the
    token (and a value in the body) to whatever host the answer names. Refuse them: the error carries
    the status, and the person fixes the configured URL."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class Client:
    def __init__(self, url, token, known=None):
        """known: {name: value} the error text is redacted against (the keychain's secrets)."""
        if not token:
            raise VaultError("no Paperclip token")
        self.url, self.token, self.known = base_url(url), token, dict(known or {})
        self.known["paperclip token"] = token

    def _request(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        try:
            with _OPENER.open(request, timeout=TIMEOUT) as response:  # scheme checked in base_url; no redirects
                raw = response.read()
        except urllib.error.HTTPError as exc:
            try:
                message = self._message(exc.read())
            finally:
                exc.close()
            if 300 <= exc.code < 400:
                message = ("redirects are not followed, so the token only goes to the configured address (%s)"
                           % message)
            raise VaultError("Paperclip answered %d: %s" % (exc.code, message)) from None
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            reason = getattr(exc, "reason", exc)
            raise VaultError("cannot reach Paperclip (%s)" % type(reason).__name__) from None
        except ValueError:  # http.client.InvalidURL, a URL with a control character
            raise VaultError("the Paperclip address is not a valid URL") from None
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError:  # not JSON, or not UTF-8 text
            raise VaultError("Paperclip sent a response that is not JSON") from None

    def _message(self, raw):
        """The server's error text, redacted and cut short. Never the raw body."""
        try:
            body = json.loads(raw)
            text = (body.get("error") or body.get("message") or "") if isinstance(body, dict) else ""
        except ValueError:  # not JSON, or not UTF-8 text
            text = ""
        if not isinstance(text, str):
            text = ""
        text, _ = redact(text, self.known)
        return text[:MAX_ERROR] or "no message"

    def list_secrets(self, company):
        """{name: id} of the company's secrets (metadata only; a value never comes back)."""
        body = self._request("GET", "/api/companies/%s/secrets" % urllib.parse.quote(company, safe=""))
        items = body.get("secrets", []) if isinstance(body, dict) else body
        out = {}
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict) and item.get("id"):
                for field in ("key", "name"):
                    if isinstance(item.get(field), str):
                        out.setdefault(item[field], item["id"])
        return out

    def create(self, company, name, value):
        """The id of a new company secret."""
        body = self._request("POST", "/api/companies/%s/secrets" % urllib.parse.quote(company, safe=""),
                             {"name": name, "key": name, "value": value})
        secret_id = body.get("id") if isinstance(body, dict) else None
        if not secret_id:
            raise VaultError("Paperclip created %s but did not return an id" % name)
        return secret_id

    def rotate(self, secret_id, value):
        """Store `value` as the secret's new version."""
        self._request("POST", "/api/secrets/%s/rotate" % urllib.parse.quote(str(secret_id), safe=""),
                      {"value": value})

    def agent_value(self, key):
        """The value of one secret granted to the current run."""
        if not KEY_RE.match(key):
            raise VaultError("a Paperclip secret key is letters, digits, `_`, `.` and `-`")
        body = self._request("POST", "/api/agents/me/secrets/%s/value" % urllib.parse.quote(key, safe=""))
        value = body.get("value") if isinstance(body, dict) else None
        if not isinstance(value, str) or not value:
            raise VaultError("Paperclip returned no value for %s" % key)
        return value


def configured(secrets, environ):
    """Whether the board settings are all there: URL, company and a token."""
    return bool(environ.get(URL_ENV) and environ.get(COMPANY_ENV)
                and (secrets.get(TOKEN_NAME) or environ.get(TOKEN_ENV)))


def in_use(secrets, environ):
    """Whether any Paperclip setting is present, even a partial set.

    A person with no setting at all does not use Paperclip and is told nothing about it; one with some
    settings but not all (a URL and no token) wants it and must hear that it was not updated.
    """
    return bool(environ.get(URL_ENV) or environ.get(COMPANY_ENV) or environ.get(TOKEN_ENV)
                or secrets.get(TOKEN_NAME))


def board_client(secrets, environ):
    """(Client, company id) for sync and rotate. Settings come from the environment and the
    keychain, never from arguments (they would land in shell history and `ps`)."""
    missing = [name for name, ok in ((URL_ENV, environ.get(URL_ENV)), (COMPANY_ENV, environ.get(COMPANY_ENV)),
                                     ("%s (or `skey add %s`)" % (TOKEN_ENV, TOKEN_NAME),
                                      secrets.get(TOKEN_NAME) or environ.get(TOKEN_ENV))) if not ok]
    if missing:
        raise VaultError("Paperclip is not configured: set %s" % ", ".join(missing))
    token = secrets.get(TOKEN_NAME) or environ[TOKEN_ENV]
    return Client(environ[URL_ENV], token, secrets), environ[COMPANY_ENV]


def agent_client(secrets, environ):
    """The Client for an agent run, from the variables Paperclip sets for it."""
    url, token = environ.get(AGENT_URL_ENV), environ.get(AGENT_TOKEN_ENV)
    if not url or not token:
        raise VaultError("not inside a Paperclip run: %s and %s are not set" % (AGENT_URL_ENV, AGENT_TOKEN_ENV))
    return Client(url, token, secrets)
