from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

try:
    import requests
except ModuleNotFoundError:
    requests = types.ModuleType("requests")

    class RequestException(Exception):
        pass

    requests.RequestException = RequestException
    requests.Response = object
    requests.request = lambda *args, **kwargs: None
    sys.modules["requests"] = requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import salt_client as client  # noqa: E402


BASE_KEY = {
    "api_url": "https://salt.example.invalid:8000",
    "token": "synthetic-token",
    "verify_tls": True,
    "connect_timeout_seconds": 4,
    "read_timeout_seconds": 45,
    "max_output_bytes": 4096,
}


class Response:
    def __init__(self, value=None, status_code=200, headers=None, content=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = json.dumps(value).encode() if content is None else content
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]

    def close(self):
        self.closed = True


def exact_params(**extra):
    return {"target": "minion-01", "expr_form": "glob", **extra}


class MetadataTests(unittest.TestCase):
    def test_action_inventory_and_flat_json_contract(self):
        expected = {
            "dispatch", "test_ping", "grains_get", "pillar_get", "state_apply",
            "state_highstate", "package", "service", "file_inspect", "user_inspect",
            "jobs_list", "job_lookup", "minions",
        }
        actions = {path.stem: path.read_text(encoding="utf-8") for path in (ROOT / "actions").glob("*.yaml")}
        self.assertEqual(expected, set(actions))
        catalog = json.loads((ROOT / "metadata" / "actions.json").read_text(encoding="utf-8"))
        self.assertEqual({f"salt.{name}" for name in expected}, {item["ref"] for item in catalog})
        for name, text in actions.items():
            with self.subTest(name=name):
                self.assertIn(f"ref: salt.{name}", text)
                self.assertIn("runner_type: python", text)
                self.assertIn("entry_point: salt_action.py", text)
                self.assertIn("parameter_delivery: stdin", text)
                self.assertIn("parameter_format: json", text)
                self.assertIn("output_format: json", text)
                self.assertIn("credential_key:", text)
                self.assertNotIn("  token:", text)
                self.assertNotIn("  password:", text)
                for field in ("operation", "data", "meta"):
                    self.assertIn(f"  {field}: {{type:", text)
        self.assertIn("default_execution_permission_set_refs: [privileged]", actions["dispatch"])
        self.assertIn("default_execution_permission_set_refs: [privileged]", actions["pillar_get"])
        self.assertIn("default_execution_permission_set_refs: [privileged]", actions["jobs_list"])

    def test_source_license_and_current_api_metadata(self):
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        source = (ROOT / "SOURCE.md").read_text(encoding="utf-8")
        revision = "f053dcedea737c3632d88b7b7e7671ca93e81bd2"
        self.assertIn(f'source_revision: "{revision}"', pack)
        self.assertIn('source_version: "3.0.1"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn('salt_api_reviewed_version: "3008.1-2"', pack)
        self.assertIn(revision, source)
        self.assertIn(revision, (ROOT / "NOTICE").read_text(encoding="utf-8"))
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)

    def test_no_local_cli_or_unsafe_execution_primitives(self):
        code = "\n".join(path.read_text(encoding="utf-8") for path in [ROOT / "actions" / "salt_action.py", ROOT / "lib" / "salt_client.py"])
        forbidden = ["subprocess", "os.system", "shell=True", "eval(", "exec(", "pickle.loads", "verify=False"]
        for value in forbidden:
            self.assertNotIn(value, code)


class KeyAndSettingsTests(unittest.TestCase):
    def test_key_lookup_requests_decryption(self):
        calls = {}
        get_key = types.ModuleType("attune.api_client.api.secrets.get_key")
        get_key.sync_detailed = lambda **kwargs: calls.update(kwargs) or types.SimpleNamespace(
            status_code=200,
            parsed=types.SimpleNamespace(data=types.SimpleNamespace(value=BASE_KEY)),
        )
        secrets = types.ModuleType("attune.api_client.api.secrets")
        secrets.get_key = get_key
        modules = {
            "attune": types.SimpleNamespace(context=types.SimpleNamespace(client="execution-client")),
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            self.assertEqual(BASE_KEY, client.fetch_key("salt.credentials"))
        self.assertEqual({"ref": "salt.credentials", "client": "execution-client", "decrypt": True}, calls)
        with self.assertRaisesRegex(client.SaltPackError, "pack-owned"):
            client.fetch_key("shared.credentials")

    def test_settings_require_https_verification_and_one_auth_mode(self):
        invalid = [
            {**BASE_KEY, "api_url": "http://salt.invalid"},
            {**BASE_KEY, "api_url": "https://user:secret@salt.invalid"},
            {**BASE_KEY, "api_url": "https://salt.invalid?token=secret"},
            {**BASE_KEY, "verify_tls": False},
            {**BASE_KEY, "username": "user", "password": "secret"},
            {**BASE_KEY, "connect_timeout_seconds": 31},
            {**BASE_KEY, "max_output_bytes": client.HARD_MAX_OUTPUT_BYTES + 1},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(client.SaltPackError):
                client.SaltNetAPI(value)
        password = {"api_url": "https://salt.invalid", "username": "user", "password": "secret", "eauth": "pam"}
        self.assertEqual("user", client.SaltNetAPI(password).settings["username"])


class PolicyTests(unittest.TestCase):
    def test_target_blast_radius_requires_key_and_execution_confirmation(self):
        settings = client._settings(BASE_KEY)
        with self.assertRaisesRegex(client.SaltPackError, "broad target"):
            client._target({"target": "*", "expr_form": "glob", "confirm_broad_target": True}, settings)
        broad = client._settings({**BASE_KEY, "allow_broad_targets": True})
        with self.assertRaisesRegex(client.SaltPackError, "broad target"):
            client._target({"target": "*", "expr_form": "glob"}, broad)
        self.assertEqual(("*", "glob"), client._target({"target": "*", "expr_form": "glob", "confirm_broad_target": True}, broad))
        self.assertEqual(("one,two", "list"), client._target({"target": "one,two", "expr_form": "list"}, settings))
        with self.assertRaisesRegex(client.SaltPackError, "exact"):
            client._target({"target": "one,*", "expr_form": "list"}, broad)

    def test_generic_dispatch_requires_opt_in_and_denies_command_surfaces(self):
        disabled = client._settings(BASE_KEY)
        params = exact_params(client="local", function="test.ping")
        with self.assertRaisesRegex(client.SaltPackError, "disabled"):
            client._generic_payload(params, disabled)
        enabled = client._settings({**BASE_KEY, "allow_privileged_dispatch": True})
        for selected, function in [
            ("local", "cmd.run"),
            ("local_async", "saltutil.cmd"),
            ("local", "state.single"),
            ("local", "file.find"),
            ("local", "pkg.install"),
            ("runner", "salt.cmd"),
            ("runner", "state.orchestrate"),
            ("runner_async", "event.send"),
            ("wheel", "config.update_config"),
        ]:
            with self.subTest(client=selected, function=function), self.assertRaisesRegex(client.SaltPackError, "denied"):
                client._generic_payload({**params, "client": selected, "function": function}, enabled)

    def test_generic_payloads_cover_all_supported_clients(self):
        settings = client._settings({**BASE_KEY, "allow_privileged_dispatch": True})
        for selected in ("local", "local_async"):
            payload = client._generic_payload(exact_params(client=selected, function="test.echo", args=["hello"], kwargs={"text": "safe"}), settings)
            self.assertEqual(selected, payload["client"])
            self.assertEqual(["hello"], payload["arg"])
            self.assertEqual({"text": "safe"}, payload["kwarg"])
        for selected in ("runner", "runner_async", "wheel"):
            payload = client._generic_payload({"client": selected, "function": "jobs.list_jobs", "kwargs": {"ext_source": "cache"}}, settings)
            self.assertEqual(selected, payload["client"])
            self.assertEqual("cache", payload["ext_source"])
            self.assertNotIn("kwarg", payload)
            self.assertEqual(selected != "wheel", "timeout" in payload)
        with self.assertRaisesRegex(client.SaltPackError, "reserved"):
            client._generic_payload({"client": "runner", "function": "jobs.list_jobs", "kwargs": {"token": "injected"}}, settings)

    def test_curated_mutations_are_constrained(self):
        settings = client._settings(BASE_KEY)
        package = client._curated_payload("package", exact_params(action="install", packages=["nginx", "libssl3"]), settings)
        self.assertEqual("local_async", package["client"])
        self.assertEqual("pkg.install", package["fun"])
        self.assertEqual(["nginx", "libssl3"], package["kwarg"]["pkgs"])
        with self.assertRaises(client.SaltPackError):
            client._curated_payload("package", exact_params(action="install", packages=["nginx; reboot"]), settings)
        service = client._curated_payload("service", exact_params(action="restart", name="sshd.service"), settings)
        self.assertEqual("service.restart", service["fun"])
        with self.assertRaises(client.SaltPackError):
            client._curated_payload("service", exact_params(action="restart", name="$(id)"), settings)

    def test_file_and_user_actions_are_read_only_and_validated(self):
        settings = client._settings(BASE_KEY)
        file_payload = client._curated_payload("file_inspect", exact_params(action="sha256", path="/etc/hosts"), settings)
        self.assertEqual("file.get_hash", file_payload["fun"])
        self.assertEqual("sha256", file_payload["kwarg"]["form"])
        user_payload = client._curated_payload("user_inspect", exact_params(action="info", name="app-user"), settings)
        self.assertEqual("user.info", user_payload["fun"])
        for operation, params in [
            ("file_inspect", exact_params(action="remove", path="/etc/passwd")),
            ("file_inspect", exact_params(action="file_exists", path="relative/path")),
            ("user_inspect", exact_params(action="delete", name="root")),
        ]:
            with self.subTest(operation=operation), self.assertRaises(client.SaltPackError):
                client._curated_payload(operation, params, settings)


class HTTPTests(unittest.TestCase):
    @mock.patch("requests.request")
    def test_token_is_header_only_and_transport_is_bounded(self, request):
        request.return_value = Response({"return": [{"minion-01": True}]})
        api = client.SaltNetAPI(BASE_KEY)
        with api.tls():
            result = api.lowstate({"client": "local", "fun": "test.ping", "tgt": "minion-01"})
        self.assertEqual({"minion-01": True}, client._unwrap(result))
        args, kwargs = request.call_args
        self.assertEqual(("POST", "https://salt.example.invalid:8000/"), args)
        self.assertEqual("synthetic-token", kwargs["headers"]["X-Auth-Token"])
        self.assertNotIn("synthetic-token", args[1])
        self.assertEqual((4, 45), kwargs["timeout"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["stream"])
        self.assertTrue(kwargs["verify"])

    @mock.patch("requests.request")
    def test_login_uses_json_then_bearer_without_retry(self, request):
        request.side_effect = [
            Response({"return": [{"token": "session-token"}]}),
            Response({"return": [{"minion-01": True}]}),
        ]
        key = {"api_url": "https://salt.invalid", "username": "api-user", "password": "synthetic-password", "eauth": "pam"}
        api = client.SaltNetAPI(key)
        with api.tls():
            api.lowstate({"client": "local", "fun": "test.ping", "tgt": "minion-01"})
        self.assertEqual(2, request.call_count)
        login = request.call_args_list[0]
        self.assertEqual("https://salt.invalid/login", login.args[1])
        self.assertNotIn("X-Auth-Token", login.kwargs["headers"])
        self.assertEqual("synthetic-password", login.kwargs["json"]["password"])
        self.assertEqual("session-token", request.call_args_list[1].kwargs["headers"]["X-Auth-Token"])

    @mock.patch("requests.request")
    def test_output_limit_and_errors_do_not_leak_secrets_or_bodies(self, request):
        request.return_value = Response(status_code=401, content=b"synthetic-token synthetic-password secret body")
        api = client.SaltNetAPI(BASE_KEY)
        with api.tls(), self.assertRaises(client.SaltPackError) as raised:
            api.get("/jobs")
        self.assertEqual("Salt API request failed with HTTP 401", str(raised.exception))
        self.assertNotIn("synthetic", str(raised.exception))
        oversized = Response({}, headers={"Content-Length": "5000"})
        request.return_value = oversized
        with api.tls(), self.assertRaisesRegex(client.SaltPackError, "max_output_bytes"):
            api.get("/jobs")
        self.assertTrue(oversized.closed)

    def test_lowstate_rejects_oversized_or_non_json_payload_before_network(self):
        api = client.SaltNetAPI(BASE_KEY)
        with mock.patch("requests.request") as request, api.tls():
            with self.assertRaisesRegex(client.SaltPackError, "512 KiB"):
                api.lowstate({"client": "local", "fun": "test.echo", "arg": ["x" * client.MAX_REQUEST_BYTES]})
            with self.assertRaisesRegex(client.SaltPackError, "JSON serializable"):
                api.lowstate({"client": "local", "fun": "test.echo", "arg": [{1, 2}]})
        request.assert_not_called()

    def test_request_exception_text_is_redacted(self):
        secret_error = requests.RequestException("https://user:secret@salt.invalid token=synthetic-token")
        with mock.patch("requests.request", side_effect=secret_error):
            api = client.SaltNetAPI(BASE_KEY)
            with api.tls(), self.assertRaises(client.SaltPackError) as raised:
                api.get("/jobs")
        self.assertIn(type(secret_error).__name__, str(raised.exception))
        self.assertNotIn("secret", str(raised.exception))
        self.assertNotIn("token", str(raised.exception))

    def test_stream_exception_text_is_redacted(self):
        response = Response({})
        secret_error = requests.RequestException("response from https://secret-host token=synthetic-token")
        response.iter_content = mock.Mock(side_effect=secret_error)
        with mock.patch("requests.request", return_value=response):
            api = client.SaltNetAPI(BASE_KEY)
            with api.tls(), self.assertRaises(client.SaltPackError) as raised:
                api.get("/jobs")
        self.assertIn(type(secret_error).__name__, str(raised.exception))
        self.assertNotIn("secret-host", str(raised.exception))
        self.assertTrue(response.closed)


class ExecutionTests(unittest.TestCase):
    @mock.patch.object(client.SaltNetAPI, "lowstate")
    def test_async_result_requires_and_returns_valid_jid(self, lowstate):
        lowstate.return_value = {"return": [{"jid": "20260814010101000001", "minions": ["minion-01"]}]}
        result = client.execute_action("state_highstate", exact_params(), key_loader=lambda ref: BASE_KEY)
        self.assertEqual("20260814010101000001", result["jid"])
        self.assertEqual(["minion-01"], result["minions"])
        lowstate.return_value = {"return": [{"minions": ["minion-01"]}]}
        with self.assertRaisesRegex(client.SaltPackError, "valid JID"):
            client.execute_action("state_highstate", exact_params(), key_loader=lambda ref: BASE_KEY)

    @mock.patch.object(client.SaltNetAPI, "get")
    def test_jobs_and_minion_paths_are_validated_and_encoded(self, get):
        get.return_value = {"return": [{}]}
        client.execute_action("job_lookup", {"jid": "20260814010101000001"}, key_loader=lambda ref: BASE_KEY)
        get.assert_called_with("/jobs/20260814010101000001")
        client.execute_action("minions", {"minion_id": "node/a b"}, key_loader=lambda ref: BASE_KEY)
        get.assert_called_with("/minions/node%2Fa%20b")
        with self.assertRaises(client.SaltPackError):
            client.execute_action("job_lookup", {"jid": "../../events"}, key_loader=lambda ref: BASE_KEY)

    def test_entrypoint_does_not_echo_malformed_secret_input(self):
        import importlib.util

        path = ROOT / "actions" / "salt_action.py"
        spec = importlib.util.spec_from_file_location("salt_action_test", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO('{"token":"synthetic-secret"')), mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", stderr):
            self.assertEqual(1, module.main())
        self.assertEqual("", stdout.getvalue())
        self.assertNotIn("synthetic-secret", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
