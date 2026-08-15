"""Safe Salt rest_cherrypy client and curated action dispatcher."""

from __future__ import annotations

import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote, urlsplit

import requests

DEFAULT_CREDENTIAL_KEY = "salt.credentials"
DEFAULT_MAX_OUTPUT_BYTES = 2 * 1024 * 1024
HARD_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_REQUEST_BYTES = 512 * 1024
CLIENTS = {"local", "local_async", "runner", "runner_async", "wheel"}
LOCAL_CLIENTS = {"local", "local_async"}
EXPR_FORMS = {"glob", "list", "grain", "grain_pcre", "pillar", "pillar_pcre", "nodegroup", "compound", "ipcidr", "pcre"}
_FUNCTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")
_JID = re.compile(r"^[0-9]{14,24}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+~-]{0,127}$")
_SLS = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$")
_ENV = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")

# These functions turn generic dispatch into direct command execution, master-side
# arbitrary dispatch, event injection, or master configuration/file mutation.
_DENIED_MODULES = {
    "local": {"cmd", "cmdmod", "cp", "file", "pip", "pkg", "powershell", "ps", "publish", "saltutil", "script", "ssh", "state"},
    "runner": {"cmd", "event", "fileserver", "git_pillar", "http", "orchestrate", "reactor", "salt", "ssh", "state"},
    "wheel": {"config", "file_roots", "pillar_roots"},
}
_DENIED_FUNCTIONS = {
    "saltutil.cmd",
    "saltutil.cmd_iter",
    "saltutil.mmodule",
    "saltutil.runner",
    "saltutil.wheel",
    "sys.reload_modules",
}
_RESERVED_LOWSTATE = {"client", "fun", "tgt", "tgt_type", "arg", "kwarg", "token", "username", "password", "eauth"}


class SaltPackError(Exception):
    """An action-safe error that never includes credentials or response bodies."""


def fetch_key(key_ref: str) -> dict[str, Any]:
    key_ref = _key_ref(key_ref)
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(ref=key_ref, client=attune.context.client, decrypt=True)
    except Exception as exc:
        raise SaltPackError(f"could not read Salt credential Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise SaltPackError("Salt credential Key was not found")
        raise SaltPackError(f"could not read Salt credential Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise SaltPackError("Salt credential Key must contain a JSON object") from None
    if not isinstance(value, dict):
        raise SaltPackError("Salt credential Key must contain an object")
    return value


def _key_ref(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"salt\.[A-Za-z0-9_.-]{1,128}", value) is None:
        raise SaltPackError("credential_key must be a pack-owned Key ref beginning with 'salt.'")
    return value


def _bounded_integer(value: Any, name: str, default: int, minimum: int, maximum: int) -> int:
    value = default if value is None else value
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SaltPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(value: Any, name: str, default: bool = False) -> bool:
    value = default if value is None else value
    if not isinstance(value, bool):
        raise SaltPackError(f"{name} must be a boolean")
    return value


def _string(value: Any, name: str, *, maximum: int = 512, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(character) < 32 for character in value):
        raise SaltPackError(f"{name} must be a non-empty string of at most {maximum} characters without controls")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise SaltPackError(f"{name} has an invalid format")
    return value


def _settings(value: dict[str, Any]) -> dict[str, Any]:
    api_url = _string(value.get("api_url"), "api_url", maximum=2048)
    parsed = urlsplit(api_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SaltPackError("api_url must be an HTTPS URL without credentials, query, or fragment")
    verify_tls = value.get("verify_tls", True)
    if verify_tls is not True:
        raise SaltPackError("verify_tls must be true; use ca_cert for a private CA")
    token = value.get("token")
    username = value.get("username")
    password = value.get("password")
    if token is not None:
        token = _string(token, "token", maximum=4096)
        if username is not None or password is not None:
            raise SaltPackError("token cannot be combined with username or password")
    else:
        username = _string(username, "username", maximum=256)
        password = _string(password, "password", maximum=4096)
    eauth = value.get("eauth", "pam")
    if not isinstance(eauth, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", eauth) is None:
        raise SaltPackError("eauth has an invalid format")
    ca_cert = value.get("ca_cert")
    if ca_cert is not None and (not isinstance(ca_cert, str) or not ca_cert.strip() or len(ca_cert.encode()) > 1024 * 1024):
        raise SaltPackError("ca_cert must be a non-empty PEM string no larger than 1 MiB")
    return {
        "api_url": api_url.rstrip("/"),
        "token": token,
        "username": username,
        "password": password,
        "eauth": eauth,
        "ca_cert": ca_cert,
        "connect_timeout": _bounded_integer(value.get("connect_timeout_seconds"), "connect_timeout_seconds", 5, 1, 30),
        "read_timeout": _bounded_integer(value.get("read_timeout_seconds"), "read_timeout_seconds", 60, 1, 300),
        "max_output_bytes": _bounded_integer(value.get("max_output_bytes"), "max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES, 1024, HARD_MAX_OUTPUT_BYTES),
        "allow_broad_targets": _boolean(value.get("allow_broad_targets"), "allow_broad_targets"),
        "allow_privileged_dispatch": _boolean(value.get("allow_privileged_dispatch"), "allow_privileged_dispatch"),
    }


@contextmanager
def _ca_verification(settings: dict[str, Any]) -> Iterator[bool | str]:
    if not settings["ca_cert"]:
        yield True
        return
    with tempfile.TemporaryDirectory(prefix="attune-salt-") as directory:
        path = Path(directory, "ca.pem")
        path.write_text(settings["ca_cert"], encoding="utf-8")
        os.chmod(path, 0o600)
        yield str(path)


class SaltNetAPI:
    def __init__(self, settings: dict[str, Any]):
        self.settings = _settings(settings)
        self._token = self.settings["token"]
        self._verify: bool | str = True

    def _read_json(self, response: requests.Response) -> Any:
        length = response.headers.get("Content-Length")
        if length is not None and length.isdigit() and int(length) > self.settings["max_output_bytes"]:
            response.close()
            raise SaltPackError("Salt response exceeds max_output_bytes")
        chunks: list[bytes] = []
        size = 0
        try:
            for chunk in response.iter_content(chunk_size=65536):
                size += len(chunk)
                if size > self.settings["max_output_bytes"]:
                    raise SaltPackError("Salt response exceeds max_output_bytes")
                chunks.append(chunk)
        finally:
            response.close()
        try:
            return json.loads(b"".join(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SaltPackError("Salt API returned invalid JSON") from None

    def _request(self, method: str, path: str, *, payload: Any = None, authenticated: bool = True) -> Any:
        headers = {"Accept": "application/json", "User-Agent": "Attune-Salt/0.1"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if authenticated:
            headers["X-Auth-Token"] = self.token()
        try:
            response = requests.request(
                method,
                f"{self.settings['api_url']}{path}",
                headers=headers,
                json=payload,
                verify=self._verify,
                timeout=(self.settings["connect_timeout"], self.settings["read_timeout"]),
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            raise SaltPackError(f"Salt API request failed ({type(exc).__name__})") from None
        if not 200 <= response.status_code < 300:
            status = response.status_code
            response.close()
            raise SaltPackError(f"Salt API request failed with HTTP {status}")
        try:
            return self._read_json(response)
        except requests.RequestException as exc:
            response.close()
            raise SaltPackError(f"Salt API response failed ({type(exc).__name__})") from None

    def token(self) -> str:
        if self._token is not None:
            return self._token
        payload = {"username": self.settings["username"], "password": self.settings["password"], "eauth": self.settings["eauth"]}
        result = self._request("POST", "/login", payload=payload, authenticated=False)
        returned = result.get("return") if isinstance(result, dict) else None
        if isinstance(returned, list) and returned:
            returned = returned[0]
        token = returned.get("token") if isinstance(returned, dict) else None
        if not isinstance(token, str) or not token:
            raise SaltPackError("Salt API login did not return a token")
        self._token = token
        return token

    @contextmanager
    def tls(self) -> Iterator["SaltNetAPI"]:
        with _ca_verification(self.settings) as verify:
            self._verify = verify
            yield self

    def lowstate(self, payload: dict[str, Any]) -> Any:
        try:
            size = len(json.dumps([payload], separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            raise SaltPackError("Salt request payload must be JSON serializable") from None
        if size > MAX_REQUEST_BYTES:
            raise SaltPackError("Salt request payload exceeds 512 KiB")
        return self._request("POST", "/", payload=[payload])

    def get(self, path: str) -> Any:
        return self._request("GET", path)


def _target(params: dict[str, Any], settings: dict[str, Any]) -> tuple[str, str]:
    target = _string(params.get("target"), "target")
    expr_form = params.get("expr_form", "glob")
    if expr_form not in EXPR_FORMS:
        raise SaltPackError(f"expr_form must be one of {', '.join(sorted(EXPR_FORMS))}")
    broad = expr_form not in {"glob", "list"}
    if expr_form == "glob":
        broad = any(character in target for character in "*?[")
    elif expr_form == "list":
        members = [member.strip() for member in target.split(",")]
        if not members or len(members) > 100 or any(not member or any(character in member for character in "*?[") for member in members):
            raise SaltPackError("list targets must contain 1 to 100 exact comma-separated minion IDs")
    confirmed = _boolean(params.get("confirm_broad_target"), "confirm_broad_target")
    if broad and not (settings["allow_broad_targets"] and confirmed):
        raise SaltPackError("broad target requires Key allow_broad_targets=true and confirm_broad_target=true")
    return target, expr_form


def _local_payload(client: str, function: str, params: dict[str, Any], settings: dict[str, Any], *, args: list[Any] | None = None, kwargs: dict[str, Any] | None = None) -> dict[str, Any]:
    target, expr_form = _target(params, settings)
    timeout = _bounded_integer(params.get("salt_timeout_seconds"), "salt_timeout_seconds", 30, 1, 300)
    payload: dict[str, Any] = {"client": client, "fun": function, "tgt": target, "tgt_type": expr_form, "timeout": timeout}
    if args:
        payload["arg"] = args
    if kwargs:
        payload["kwarg"] = kwargs
    return payload


def _validate_function(client: str, function: Any) -> str:
    function = _string(function, "function", maximum=256, pattern=_FUNCTION)
    family = "local" if client in LOCAL_CLIENTS else client.removesuffix("_async")
    module = function.split(".", 1)[0]
    if module in _DENIED_MODULES[family] or function in _DENIED_FUNCTIONS:
        raise SaltPackError("function is denied by the generic dispatch safety policy")
    return function


def _generic_payload(params: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    if not settings["allow_privileged_dispatch"]:
        raise SaltPackError("generic dispatch is disabled; set allow_privileged_dispatch=true in the credential Key")
    client = params.get("client")
    if client not in CLIENTS:
        raise SaltPackError(f"client must be one of {', '.join(sorted(CLIENTS))}")
    function = _validate_function(client, params.get("function"))
    args = params.get("args", [])
    kwargs = params.get("kwargs", {})
    if not isinstance(args, list) or len(args) > 100:
        raise SaltPackError("args must be an array with at most 100 entries")
    if not isinstance(kwargs, dict) or len(kwargs) > 100 or any(not isinstance(key, str) for key in kwargs):
        raise SaltPackError("kwargs must be an object with at most 100 string keys")
    if any(key in _RESERVED_LOWSTATE for key in kwargs):
        raise SaltPackError("kwargs contains a reserved lowstate key")
    if client in LOCAL_CLIENTS:
        return _local_payload(client, function, params, settings, args=args, kwargs=kwargs)
    if args:
        raise SaltPackError("args is only supported by local and local_async clients")
    payload = {"client": client, "fun": function}
    payload.update(kwargs)
    if client in {"runner", "runner_async"}:
        payload["timeout"] = _bounded_integer(params.get("salt_timeout_seconds"), "salt_timeout_seconds", 30, 1, 300)
    return payload


def _async_mode(params: dict[str, Any], default: bool) -> str:
    return "local_async" if _boolean(params.get("async"), "async", default) else "local"


def _safe_names(value: Any, name: str, maximum_items: int = 100) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum_items:
        raise SaltPackError(f"{name} must contain 1 to {maximum_items} names")
    return [_string(item, name, maximum=128, pattern=_SAFE_NAME) for item in value]


def _curated_payload(operation: str, params: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    client = _async_mode(params, operation in {"state_apply", "state_highstate", "package", "service"})
    if operation == "test_ping":
        return _local_payload(client, "test.ping", params, settings)
    if operation == "grains_get":
        key = params.get("key")
        if key is None:
            return _local_payload(client, "grains.items", params, settings)
        return _local_payload(client, "grains.get", params, settings, kwargs={"key": _string(key, "key", maximum=256), "default": params.get("default")})
    if operation == "pillar_get":
        key = params.get("key")
        if key is None:
            return _local_payload(client, "pillar.items", params, settings)
        return _local_payload(client, "pillar.get", params, settings, kwargs={"key": _string(key, "key", maximum=256), "default": params.get("default")})
    if operation == "state_apply":
        mods = params.get("states")
        if not isinstance(mods, list) or not 1 <= len(mods) <= 100:
            raise SaltPackError("states must contain 1 to 100 SLS names")
        kwargs: dict[str, Any] = {"mods": [_string(item, "states", maximum=255, pattern=_SLS) for item in mods], "test": _boolean(params.get("test"), "test")}
        if params.get("saltenv") is not None:
            kwargs["saltenv"] = _string(params["saltenv"], "saltenv", maximum=64, pattern=_ENV)
        return _local_payload(client, "state.sls", params, settings, kwargs=kwargs)
    if operation == "state_highstate":
        kwargs = {"test": _boolean(params.get("test"), "test")}
        if params.get("saltenv") is not None:
            kwargs["saltenv"] = _string(params["saltenv"], "saltenv", maximum=64, pattern=_ENV)
        return _local_payload(client, "state.highstate", params, settings, kwargs=kwargs)
    if operation == "package":
        action = params.get("action")
        if action not in {"install", "remove"}:
            raise SaltPackError("action must be install or remove")
        return _local_payload(client, f"pkg.{action}", params, settings, kwargs={"pkgs": _safe_names(params.get("packages"), "packages")})
    if operation == "service":
        action = params.get("action")
        if action not in {"status", "start", "stop", "restart", "enable", "disable"}:
            raise SaltPackError("action is not a supported service operation")
        return _local_payload(client, f"service.{action}", params, settings, kwargs={"name": _string(params.get("name"), "name", maximum=128, pattern=_SAFE_NAME)})
    if operation == "file_inspect":
        action = params.get("action")
        functions = {"file_exists": "file.file_exists", "directory_exists": "file.directory_exists", "sha256": "file.get_hash"}
        if action not in functions:
            raise SaltPackError("action must be file_exists, directory_exists, or sha256")
        path = _string(params.get("path"), "path", maximum=4096)
        if not (path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", path)):
            raise SaltPackError("path must be absolute")
        kwargs = {"path": path}
        if action == "sha256":
            kwargs["form"] = "sha256"
        return _local_payload(client, functions[action], params, settings, kwargs=kwargs)
    if operation == "user_inspect":
        action = params.get("action")
        if action not in {"info", "list_groups"}:
            raise SaltPackError("action must be info or list_groups")
        return _local_payload(client, f"user.{action}", params, settings, kwargs={"name": _string(params.get("name"), "name", maximum=128, pattern=_SAFE_NAME)})
    raise SaltPackError("unknown curated operation")


def _unwrap(result: Any) -> Any:
    if isinstance(result, dict) and isinstance(result.get("return"), list) and len(result["return"]) == 1:
        return result["return"][0]
    return result


def _structured(operation: str, data: Any, *, client: str | None = None) -> dict[str, Any]:
    unwrapped = _unwrap(data)
    result: dict[str, Any] = {"operation": operation, "data": unwrapped, "meta": {"client": client, "async": client in {"local_async", "runner_async"}}}
    if client in {"local_async", "runner_async"}:
        jid = unwrapped.get("jid") if isinstance(unwrapped, dict) else None
        if not isinstance(jid, str) or _JID.fullmatch(jid) is None:
            raise SaltPackError("Salt asynchronous response did not contain a valid JID")
        result["jid"] = jid
        minions = unwrapped.get("minions")
        if isinstance(minions, list) and all(isinstance(item, str) for item in minions):
            result["minions"] = minions
    return result


_CURATED = {"test_ping", "grains_get", "pillar_get", "state_apply", "state_highstate", "package", "service", "file_inspect", "user_inspect"}


def execute_action(operation: str, params: dict[str, Any], *, key_loader=fetch_key) -> dict[str, Any]:
    key_ref = _key_ref(params.get("credential_key", DEFAULT_CREDENTIAL_KEY))
    api = SaltNetAPI(key_loader(key_ref))
    settings = api.settings
    with api.tls():
        if operation == "dispatch":
            payload = _generic_payload(params, settings)
            return _structured(operation, api.lowstate(payload), client=payload["client"])
        if operation in _CURATED:
            payload = _curated_payload(operation, params, settings)
            return _structured(operation, api.lowstate(payload), client=payload["client"])
        if operation == "jobs_list":
            return _structured(operation, api.get("/jobs"))
        if operation == "job_lookup":
            jid = _string(params.get("jid"), "jid", maximum=24, pattern=_JID)
            return _structured(operation, api.get(f"/jobs/{quote(jid, safe='')}"))
        if operation == "minions":
            minion_id = params.get("minion_id")
            path = "/minions" if minion_id is None else f"/minions/{quote(_string(minion_id, 'minion_id', maximum=256), safe='')}"
            return _structured(operation, api.get(path))
    raise SaltPackError("unknown action operation")
