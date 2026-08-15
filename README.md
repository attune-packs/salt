# Salt Attune Pack

Production-oriented Salt automation through the `rest_cherrypy` NetAPI. This
pack replaces the attributed StackStorm pack's repetitive generated actions
with one shared client and 13 intentional action contracts.

The pack does not execute a local `salt` CLI. All calls use JSON over HTTPS,
put the bearer token only in `X-Auth-Token`, disable redirects, enforce bounded
connect/read timeouts and response sizes, and never retry a mutation.

## Compatibility

The implementation was reviewed against current Salt `3008.1-2` documentation.
Salt 3006.0 and newer disables every NetAPI client unless it is explicitly
listed in the master configuration. Enable only what is needed, for example:

```yaml
netapi_enable_clients:
  - local
  - local_async
  - runner
  - runner_async
  - wheel
```

Most installations only need `local` and `local_async`. Do not enable runner or
wheel clients merely because `salt.dispatch` can name them. Salt eAuth ACLs are
the final server-side authorization boundary and should separately constrain
functions and targets.

## Authentication Key

Create an encrypted, pack-owned Attune Key named `salt.credentials`. Actions
accept another `salt.*` Key ref through `credential_key`, but never accept
credentials as action parameters. Use either a pre-issued eAuth token:

```json
{
  "api_url": "https://salt-master.example:8000",
  "token": "REDACTED",
  "verify_tls": true,
  "connect_timeout_seconds": 5,
  "read_timeout_seconds": 60,
  "max_output_bytes": 2097152,
  "allow_broad_targets": false,
  "allow_privileged_dispatch": false
}
```

Or credentials used once per action to obtain a session token from `/login`:

```json
{
  "api_url": "https://salt-master.example:8000",
  "username": "attune-salt",
  "password": "REDACTED",
  "eauth": "pam",
  "verify_tls": true
}
```

`verify_tls` cannot be disabled. For a private CA, set `ca_cert` to its PEM
certificate. The hard response cap is 16 MiB; the default is 2 MiB. HTTP URLs,
URL credentials, redirects, malformed JSON, oversized output, and unbounded
timeouts are rejected without returning response bodies or secret-bearing
exception text.

## Actions

| Action | Purpose | Default access |
| --- | --- | --- |
| `salt.test_ping` | Targeted `test.ping` | standard |
| `salt.grains_get` | One grain or `grains.items` | standard |
| `salt.pillar_get` | One pillar key or `pillar.items` | privileged |
| `salt.state_apply` | Bounded SLS list, async by default | privileged |
| `salt.state_highstate` | Highstate, async by default | privileged |
| `salt.package` | Install/remove validated package names | privileged |
| `salt.service` | Status/start/stop/restart/enable/disable one service | privileged |
| `salt.file_inspect` | Existence or SHA-256 only; no writes | standard |
| `salt.user_inspect` | User info/groups only; no writes | standard |
| `salt.jobs_list` | `GET /jobs`; arguments may be sensitive | privileged |
| `salt.job_lookup` | Validated `GET /jobs/<jid>`; returns may be sensitive | privileged |
| `salt.minions` | List or inspect an exact minion ID | standard |
| `salt.dispatch` | Generic local/runner/wheel dispatch | privileged |

File and user mutation actions are deliberately absent. Portable Salt schemas
cannot safely constrain arbitrary paths, account deletion semantics, provider
overrides, and platform-specific keyword arguments. Use reviewed states for
those changes. Package and service actions constrain names, operation enums,
argument counts, targets, and timeouts.

## Target Safety

Every local action requires a target and validates `expr_form`. Exact glob IDs
and lists of at most 100 exact IDs work by default. Wildcard globs, regular
expressions, grain/pillar/nodegroup/compound/IPCIDR targets require both:

1. `allow_broad_targets: true` in the encrypted Key policy.
2. `confirm_broad_target: true` on that execution.

This is a guardrail, not a minion-count guarantee. Salt eAuth target ACLs remain
mandatory for limiting blast radius.

## Async Jobs

Mutating curated actions use `local_async` by default and return a validated
numeric `jid` plus the minion list when Salt supplies it. Use
`salt.job_lookup jid=<jid>` to collect results. The pack does not treat an HTTP
response as job completion and does not retry submission when the outcome is
ambiguous.

All actions return JSON with `operation`, `data`, and `meta`. Async submissions
also return `jid` and optionally `minions`.

## Privileged Dispatch

`salt.dispatch` exposes generic module/function dispatch and therefore carries
an arbitrary-code-execution and infrastructure-control surface. It is disabled
unless the execution has the `privileged` permission set **and** the credential
Key contains `allow_privileged_dispatch: true`.

The opt-in cannot bypass the built-in denylist. Direct shell/PowerShell/script,
indirect state/file/package/utility execution, Salt publish/SSH, master
event/reactor/salt runners, and master config/file-root wheel modules are
rejected. Reserved lowstate and authentication keys cannot be injected through
`kwargs`. Continue to use narrow Salt eAuth ACLs; this local denylist is defense
in depth, not an authorization replacement.

## Testing

Tests are deterministic and mock every HTTP interaction. No live Salt master or
undeclared Python package is required:

```bash
attune pack check .
attune pack test . --detailed
python -m unittest discover -s tests -v
```

See [SOURCE.md](SOURCE.md) and [NOTICE](NOTICE) for attribution and verification
details.
