# Changelog

## 0.8.0

- **`/agent-debug`** (ADR-010 phase 1 of the agent bus): a member of a team
  channel switches which categories of MCP debug the agents' servers show in
  that home: `on <category…>` adds, `off <category…>` removes, `off` turns all
  off, `full` turns all on, `set <category…>` replaces, `status` (or no argument)
  shows them and their end. Categories `wake`, `identity`, `sig`, `asks`,
  `calls`, `props` (`full` for all); an unknown word is refused. Each command
  sets one new end for the whole setting: an hour, or `for <duration>`, at least
  1 minute, at most 24 h. The registrar builds each setting from the previous
  one's categories and the command; an ended setting counts as off.
- **`GET /register/v1/debug/{channel_id}`** (public, own rate bucket of 120 per
  minute per IP, `Cache-Control: no-store`) returns the setting as a signed
  record, header typ `mm-agent-debug+jwt`, claims `channel_id`, `categories`,
  `set_by`, `set_by_id`, `set_at_ms`, `until_ms`, `iat`, `exp` (1 h, signed fresh
  per read, the signature's freshness only). `404` with `{"error":"no debug set"}`
  when none holds: never set, turned off, or ended.
- New env: `DEBUG_COMMAND_TOKEN` (needs the attestation key), `DEBUG_STORE`
  (default `/data/debug.json`, 0600, atomic; ended settings pruned at start and
  hourly). The startup log reports `debug_command`.
- No change to the ask mode, the mandates or the attestations.

## 0.7.2

- **The rate limiter forgets quiet addresses.** It kept every client address it
  had ever seen, so memory grew with the number of distinct addresses (an IPv6
  /64 holder has 2^64 of them). Keys without a request in the last minute are
  now dropped, checked at most once a minute; the table is rebuilt then, so the
  memory of a flood of distinct addresses is given back. No change to the limits.

## 0.7.1

- **Rate buckets count the client behind a proxy correctly.** `clientIP` took the
  first `X-Forwarded-For` entry, which the client sets itself (the gateway only
  appends), so a forged header gave every request a fresh bucket and bypassed
  the limits of registration, modes, mandates and attestations. New env
  `TRUSTED_PROXY_HOPS` (default `0`): the entry that many places from the right
  counts; without the header or with too few entries the peer address counts;
  `0` ignores the header. Peer addresses in IPv6 form are read correctly too.
- **Upgrade:** the default `0` trusts no header. Behind a proxy, set
  `TRUSTED_PROXY_HOPS` to its number of hops (`1` for one proxy); left at `0`, all
  clients share the bucket of the proxy's address and get `429` together.
- No change to the API, the keys, the modes or the mandates.

## 0.7.0

- **`GET /register/v1/attestations/{bot_id}`**: a bot's attestation for other
  agents, signed fresh for each read (public, own rate bucket of 120 per minute
  per IP, `Cache-Control: no-store`). Same header (`mm-agent-attestation+jwt`) and
  claims as the registration's; `iat` is now and `exp` one hour later. `404` with
  `{"error":"no attestation"}` means none (not recorded, or the bot is gone);
  `400` for an invalid id; `502` when the chat system cannot say whether the bot
  exists. Why: a bot cannot write its own user props (Mattermost answers 403), so
  the attestation never reached other agents.
- The registrar now keeps the claims of every bot it registers (enrollment token
  and shared secret alike) in `ATTESTATION_STORE` (default
  `/data/attestations.json`, mode 0600, atomic), and removes them with the bot
  (`DELETE /register/v1/agents/<name>` and the enrollment cleanup); a read never
  deletes. It checks that the bot exists, remembering a positive answer for 45 s
  per bot id. Bots registered before this version have no record and
  answer 404 until they are registered again. Mount `/data` as before.
- No change to the registration answer, the keys, the modes or the mandates.

## 0.6.0

- **`/agent-mandate`**: a trusted human types `/agent-mandate set ~<home> [until YYYY-MM-DD] [note]`
  in a project channel; the coordinator of `~<home>` then gives tasks and
  priorities for the agents in that channel. `off` removes it, no argument or
  `status` shows it. `~<home>` is a channel name resolved in the team of the
  invocation (new `ProviderPort.ChannelIDByName`, `Invocation.TeamID`); `until` is
  today to 30 days ahead; the note is one line, 200 characters at most.
- **`GET /register/v1/mandates/{channel_id}`** (public, own rate bucket of 120 per
  minute per IP) returns the mandate as a signed record, header typ
  `mm-agent-mandate+jwt`, claims `channel_id`, `home`, `set_by`, `set_by_id`,
  `set_at_ms`, `until`, `note`, `iat`, `exp` (1 h, signed fresh per read).
- New env: `MANDATE_COMMAND_TOKEN` (needs the attestation key), `MANDATE_STORE`
  (default `/data/mandates.json`). `/healthz`-style startup log reports
  `mandate_command` next to `mode_command`.
- The mode command and its record are unchanged.
- The home named in `/agent-mandate` must be a channel the human is a member of: the
  home's id goes into the public record, so a private channel's id is not handed out.
- An unknown home and a channel the human is not in are answered alike, so a
  stranger cannot tell whether a private channel of that name exists; the usage
  text says the mandate and its note are public.

## 0.5.2

- `GET /register/v1/version`: public, rate-limited like the keys, returns
  `{"version":"…"}` so operators and agents can tell which registrar is deployed.
  `/healthz` is unchanged.

## 0.5.1

- **The admin↔bot welcome DM is marked read**, at creation and again on
  unregister (`HIDE_BOT_DM`). The webapp always shows an unread DM, whatever
  `direct_channel_show` says, so the hidden DMs piled up in the admin's sidebar
  with 1 unread each. Unregister also cleans up bots registered by older versions.
- `scripts/mark-bot-dms-read.sh`: one-time cleanup of the existing pile (dry run
  by default, `--apply` marks read and hides; deletes nothing).
- README uses `/agent-ask-mode`, the agent bus' renamed slash command.

## 0.5.0

- **`/agent-mode`: the ask mode per channel, signed** (ADR-005 phase 2 of the
  agent bus). A member of a team channel sets `direct` or `coordinator` with a
  new slash command on `POST /register/v1/mode`, verified with its own
  `MODE_COMMAND_TOKEN`; `status` (or no argument) shows it, `delegated` answers
  "not available yet (ADR-005 phase 3)". Direct and group messages and
  non-members are refused; every answer is private, every change logged.
- **`GET /register/v1/modes/{channel_id}`.** Public, its own rate bucket (120/min
  per IP): `{"record":"<jws>"}`, signed fresh with the attestation key, header
  `typ` `mm-agent-mode+jwt`, claims `channel_id`, `mode`, `set_by`, `set_by_id`,
  `set_at_ms`, `iat`, `exp` (1 h). `404` when no mode is set, `400` for an
  invalid id. Only with an attestation key.
- Modes live in their own store, `MODE_STORE` (default `/data/modes.json`, 0600,
  atomic), and need no enrollment tokens. `MODE_COMMAND_TOKEN` without an
  attestation key is a startup error.
- Attestation and mode records share one signing helper; attestations are
  byte-identical to 0.4.0. The slash command refusal for bots and guests now says
  "can use this command" instead of naming enrollment tokens.

## 0.4.0

- **Signed owner attestation.** With `ATTESTATION_KEY` (or `ATTESTATION_KEY_FILE`)
  set, `POST /register/v1/agents` adds `attestation`: an EdDSA compact JWS naming
  the bot, the accepted owner (`responsible`), the written `trusted` list,
  `trusted_cut`, `kind`, and `via` (`enrollment`: owner checked; `secret`: the
  caller's claim). `ATTESTATION_TTL` (default `30d`) sets its lifetime.
- **`GET /register/v1/keys`.** Public, rate limited; the Ed25519 public key as an
  RFC 8037 JWK set, `{"keys":[]}` without a key.
- Without a key nothing changes. An invalid key or TTL, or both key settings, is a
  startup error; the key is never logged or returned, the `kid` is logged once.

## 0.3.0

- **Revoking a token unregisters its bots.** `/agent-token revoke <id|all>` now
  also removes every bot still registered with the revoked tokens, through the
  same provider path as `DELETE /register/v1/agents/{name}`, and says how many it
  removed. Failures are named in the reply, not fatal; the bot stays recorded and
  the same revoke retries it. A username that now belongs to another account is
  only forgotten. The bots come from the store's existing `agents` records
  (`user_id`, `token_id`), so 0.2.0 stores need no migration.
- **Pruning.** Revoked and expired tokens are dropped from the store after
  `ENROLLMENT_RETENTION` (default `30d`; `0` = at the next pass), at start and
  hourly, but never while a bot registered with them is still live.

## 0.2.0

- **Enrollment tokens.** A new slash command endpoint, `POST /register/v1/command`
  (`/agent-token create|list|revoke`), lets a human mint a scoped, expiring token.
  Mattermost names the caller; bots and guests are refused; every reply is ephemeral.
  Tokens are stored only as HMAC-SHA256 with `ENROLLMENT_PEPPER`, in a JSON file
  (`ENROLLMENT_STORE`).
- **Bound bots.** Registering with an enrollment token (same endpoint and `Bearer`
  header) binds the bot to the token's owner: native Mattermost owner via
  `assign_bot`, description `for @<owner> · …`. The registrar enforces the token's
  scope (live bots, kind, channels) and the owner's channel access; a different
  `responsible` is refused. The response carries `owner`.
- **Unbound bots.** The shared secret registers bots described as
  `unbound · claims @… · …`, never `for @…`, and assigns no owner.
  `ALLOW_SHARED_SECRET=false` switches it off; `REGISTRATION_SECRET` is now optional.
  See *Migration* in the README.
- **Cut trusted lists** are marked `+N` (`MAX_TRUSTED`, default 10).
- **Unregister** also accepts an enrollment token of the bot's owner.
- **Provider port.** The protocol (`internal/core`) talks to Mattermost only through
  `ProviderPort`; the Mattermost calls moved to `internal/mattermost`.
- CI runs gofmt, `go vet` and `go test -race`, and checks version, changelog and image tag.
- The image has a `/data` volume owned by the non-root user.

## 0.1.0

- Register and unregister agents with a shared secret; one bot and token per agent.
- The bot description says whom the agent answers to (`for @… · trusts @…`).
- The admin↔bot welcome DM is hidden (`HIDE_BOT_DM`).
