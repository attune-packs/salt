# Source Verification

## Attributed Source

- Repository: <https://github.com/StackStorm-Exchange/stackstorm-salt>
- Upstream pack version: `3.0.1`
- Git tag: `v3.0.1`
- Exact revision: `f053dcedea737c3632d88b7b7e7671ca93e81bd2`
- Revision date: 2024-04-07
- License: Apache License 2.0 (`Apache-2.0`)
- Upstream `LICENSE` SHA-256: `b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1`

The tag resolves directly to the revision above. GitHub exposes no release
object for this repository; `v3.0.1` is the newest verified tag and the
upstream `pack.yaml` declares version `3.0.1`.

This is a clean-room Attune implementation informed by the source pack's
integration intent and action inventory. It does not copy the generated action
set or Python implementation.

## Current API Review

Reviewed on 2026-08-14 against Salt's current documentation and latest published
Salt release `3008.1-2`:

- `rest_cherrypy` root lowstate POST and `/login` token authentication
- `local`, `local_async`, `runner`, `runner_async`, and `wheel` client semantics
- `/jobs`, `/jobs/<jid>`, and `/minions` convenience endpoints
- Salt 3006.0+ `netapi_enable_clients` requirement
- Current `pkg`, `service`, `file`, and `user` virtual execution modules

References:

- <https://docs.saltproject.io/en/latest/ref/netapi/all/salt.netapi.rest_cherrypy.html>
- <https://docs.saltproject.io/en/latest/topics/netapi/netapi-enable-clients.html>
- <https://github.com/saltstack/salt/releases/tag/v3008.1-2>
