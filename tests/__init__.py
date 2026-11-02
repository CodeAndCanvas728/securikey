"""Make the tests hermetic: nothing here may read the developer's SECURIKEY_* settings or write to
their real cache directory (`skey run` appends to an audit log there)."""
import atexit
import os
import shutil
import tempfile

for _name in ("SECURIKEY_SERVICE", "SECURIKEY_WATCH_ENV", "SECURIKEY_HEADLESS", "SECURIKEY_HEADLESS_TIMEOUT",
              "SECURIKEY_PAPERCLIP_URL", "SECURIKEY_PAPERCLIP_COMPANY", "SECURIKEY_PAPERCLIP_TOKEN",
              "PAPERCLIP_API_URL", "PAPERCLIP_API_KEY", "TOKEN_VAULT_SERVICE"):
    os.environ.pop(_name, None)
_CACHE = tempfile.mkdtemp(prefix="skey-test-cache-")
os.environ["XDG_CACHE_HOME"] = _CACHE
atexit.register(shutil.rmtree, _CACHE, ignore_errors=True)
