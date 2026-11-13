# mattermost-agent-registrar

Small HTTP service for **any Mattermost instance**: agents self-register and
unregister and each get their own bot token. The admin token stays inside the
registrar and never reaches an agent.

An agent registers with one of two credentials:

- an **enrollment token** a human minted with the `/agent-token` slash command:
  the bot is **bound** to that human (its native Mattermost owner and `for @…`
  in its profile), within the token's scope;
- the **shared registration secret** (optional fallback, can be switched off):
  the bot is **unbound**, its profile says so.

It is the server side of [mattermost-ai-agent-bus](https://github.com/dembaca/mattermost-ai-agent-bus),
which gives coding agents (Claude Code, Cursor, OpenCode, …) a Mattermost identity,
a work channel and an inbox.

## Why a registrar

Creating a bot and minting its token needs an admin (or bot-create) token. Without a
registrar every agent would need that token, and a leaked agent environment would be
a leaked admin.

| | Without registrar | With registrar |
|---|---|---|
| What an agent holds | A bot token you created by hand, or an admin token to create bots itself | An enrollment token or the shared secret, or nothing (a host hook holds it) |
| Who creates the bot | You, ahead of time, per agent | The registrar, per session, on demand |
| Cleanup | Manual | `DELETE` on exit revokes the token and disables the bot |
| A leak exposes | One bot token, or the whole instance if it is an admin token | An enrollment token: a few bots for its owner, in its channels, until it expires or is revoked ([threat model](#threat-model)). The shared secret: unbound bots, and unregistering any bot |
| Profile text (`for @alice · trusts @bob`) | Set by hand | Written by the registrar; the bot cannot change it. `for @…` only for a verified owner |

The bus plugin also runs without a registrar when `MM_BOT_TOKEN` is already set: it
treats the session as managed elsewhere and registers nothing. You then create each
bot yourself and hand it its token; see the
[plugin README](https://github.com/dembaca/mattermost-ai-agent-bus#registrar).

## API

### Register

```http
POST /register/v1/agents
Authorization: Bearer <enrollment token or shared registration secret>
Content-Type: application/json

{"name":"cursor-1","display_name":"Cursor 1",
 "responsible":"alice","trusted":["alice","bob"],"kind":"session",
 "channels":["agents"]}
```

All fields but `name` are optional. The response:

```json
{
  "url": "https://chat.example.com",
  "username": "agent-cursor-1",
  "bot_token": "...",
  "user_id": "...",
  "owner": "alice"
}
```

`owner` is present only for a bound bot. `attestation` is present only when
`ATTESTATION_KEY` is set (see [Owner attestation](#owner-attestation)).

**With an enrollment token** (starts with `mmenr_`) the registrar:

1. refuses an unknown, expired or revoked token (`401`), and a token whose owner
   is no longer an active user (`403`);
2. takes the owner from the token. `responsible` may be left out or name the
   owner; **a different `responsible` is refused** (`403`), so a token handed to
   the wrong agent fails loudly instead of registering a bot for someone else;
3. enforces the scope (`403`): at most `max-bots` live bots per token (an
   unregistered bot frees its slot), `kind` must be the token's kind (an absent
   `kind` takes it), and every channel in `channels` must be in the token's
   channel list. Without `channels` the bot joins all of the token's channels;
   a token without a channel list allows the default channel only;
4. checks that the owner can read every channel the bot joins: member of the
   channel, or member of the team and the channel is public;
5. creates the bot, mints its token, adds it to the team and channels, then makes
   the human its native owner (`POST /api/v4/bots/{bot_id}/assign/{user_id}`).
   If that binding fails, the bot is revoked again and the registration fails.

**With the shared secret** the bot is unbound: no owner is assigned, it joins the
default channel only, and `channels` is ignored. `ALLOW_SHARED_SECRET=false`
switches the shared secret off for registering and unregistering.

### Bot description

The registrar writes the description, shown in the bot's profile; the bot cannot
change it. The agent bus parses it (`for @…`, `trusts @…`, `+N`), so the format
is part of the interface:

| Bot | Description |
|---|---|
| Bound (enrollment token) | `for @alice · autonomous · trusts @alice, @bob +2 · via agent-registrar` |
| Unbound (shared secret) | `unbound · claims @alice · autonomous · trusts @alice, @bob · via agent-registrar` |
| Unbound, no fields | `unbound · via agent-registrar` |

- `for @<owner>` appears **only** for a bound bot; its owner is the human who
  minted the token. An unbound bot starts with `unbound` and records the caller's
  unchecked `responsible` as `claims @…`, never as `for @…`. Under the bus's owner
  split (ADR-001/003 there) a bot without `for @` is foreign.
- `autonomous` appears for that kind only.
- `trusts @a, @b` lists the trusted names that are existing human users, at most
  `MAX_TRUSTED`; bots and unknown names are left out. When more names were sent
  than the cap, the registrar stops checking and appends ` +N` (N further
  distinct names it did not write); with no name written that is `trusts @ +N`.
  The bus treats a cut list as foreign.

### Owner attestation

With an attestation key configured, a successful registration also returns
`"attestation": "<jws>"`: a statement, signed by the registrar, of who it accepted
as the bot's owner. A bus that pins the registrar's public key can verify it
instead of trusting the bot description alone.

`GET /register/v1/keys` (public, no auth, same rate limit) returns the public key
as an RFC 8037 JWK, with `Cache-Control: max-age=300`:

```json
{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"…","x":"<base64url public key>"}]}
```

Without a key it returns `{"keys":[]}` and the register response has no
`attestation` field.

**Reading a bot's attestation later (0.7.0).** The registration's attestation
reaches only the bot's own host. For other agents, `GET
/register/v1/attestations/{bot_id}` (public, no auth) returns the same claims as a
record signed for this request:

| Status | Body |
|--------|------|
| `200` | `{"record":"<jws>"}` |
| `404` | `{"error":"no attestation"}`: none is recorded, or the bot is gone |
| `400` | `{"error":"invalid bot id"}` |
| `502` | `{"error":"lookup failed"}`: the chat system could not say whether the bot exists |

The record has the same header (`typ` `mm-agent-attestation+jwt`) and claims as the
registration's, with `iat` now and `exp` one hour later (the registration's lives
`ATTESTATION_TTL`). The registrar keeps what it accepted for each bot it
registers with an attestation key set, by either way (enrollment token or shared
secret), in `ATTESTATION_STORE`, and signs it afresh for each read: nothing signed
is stored. `/register/v1/agents/<name>` and the enrollment cleanup remove the
claims with the bot. A read never deletes: it answers 404 for a bot the chat
system does not find, and keeps the record. It asks the chat system whether the
bot exists, and remembers a positive answer for 45 s per bot id, so reads cost it
one lookup per bot and 45 s at most.

The record shows what the registrar accepted when it registered the bot, not
the account's state in Mattermost now: a bot disabled outside the registrar
attests until it is unregistered. With the shared secret `responsible` is the
caller's unchecked claim; `via: secret` marks that. Bots registered before 0.7.0 have
no record and answer 404 until they are registered again. The route has its own
rate bucket (120 requests per minute per IP), sends `Cache-Control: no-store`, and
exists only with an attestation key. The rate bucket counts by client address
like the other buckets ([Behind a proxy](#behind-a-proxy)). The claims are
public to anyone who knows the bot id (26 characters, not guessable); they are the ones the bot's description
already shows.

The token is a compact JWS (RFC 7515, base64url without padding), signed with
EdDSA. The header is exactly
`{"alg":"EdDSA","typ":"mm-agent-attestation+jwt","kid":"<kid>"}`; `kid` is the
first 16 characters of base64url(sha256(raw 32-byte public key)). The payload
is compact JSON with these claims, in this order:

| Claim | Meaning |
|-------|---------|
| `bot_id` | Mattermost user id of the bot |
| `username` | the bot's username |
| `responsible` | the owner handle the registrar accepted. Enrollment token: the token's owner, also when the request left `responsible` out. Shared secret: the caller's `responsible` (normalised), or `""` |
| `trusted` | exactly the names written into the description's `trusts`, after the `MAX_TRUSTED` cut and the existing-human filter |
| `trusted_cut` | names left out by the cut; present only when greater than 0 |
| `kind` | `session` or `autonomous` |
| `via` | `enrollment`: an enrollment token was used, so the owner was checked. `secret`: the shared secret was used, and `responsible` is only the caller's claim |
| `iat`, `exp` | unix seconds; `exp` is `iat` + `ATTESTATION_TTL` |

A verifier must check the signature against a pinned key, the header, `exp`, and
trust `responsible` as checked only when `via` is `enrollment`.

### Unregister

```http
DELETE /register/v1/agents/cursor-1
Authorization: Bearer <bot_token | enrollment token of the bot's owner | shared secret>
```

Revokes the bot's access tokens and disables it. Idempotent (`204` if already
gone). An enrollment token may unregister the bots registered with any active
token of the same owner; the shared secret (operator cleanup) any bot.

### Enrollment tokens: `/agent-token`

A Mattermost slash command that calls `POST /register/v1/command` on the
registrar (only served when `SLASH_COMMAND_TOKEN` is set). Mattermost tells the
registrar who typed it (`user_id`); that human owns the token. Bots and guest
accounts are refused. Every answer is ephemeral: only the caller sees it.

```text
/agent-token create [--expires 30d] [--max-bots N] [--channels a,b] [--kind session|autonomous] [--label text]
/agent-token list
/agent-token revoke <id|all>
```

- `create` replies **once** with the token (`mmenr_…`, 256 random bits) and its
  id. Defaults: `ENROLLMENT_DEFAULT_TTL`, `ENROLLMENT_DEFAULT_MAX_BOTS`, kind
  `session`, the default channel. It refuses channels the caller cannot read, and
  more than `ENROLLMENT_MAX_TOKENS_PER_USER` active tokens.
- `list` shows the caller's active tokens: id, label, kind, live/max bots,
  channels, expiry, last use. Never the token itself.
- `revoke <id>` or `revoke all` revokes the caller's own tokens and unregisters
  every bot still registered with them, the same way `DELETE` does (token
  revoked, bot disabled). The reply says how many bots were removed; a bot that
  could not be removed is named and stays recorded, and running the same revoke
  again retries it. A bot whose username now belongs to another account (deleted
  and recreated outside the registrar) is only forgotten, never touched. An
  *expired* token's bots keep running until unregistered. Deactivating the
  owner in Mattermost disables their bots (`DisableBotsWhenOwnerIsDeactivated`,
  on by default) and stops their tokens.

The trigger word is the operator's choice; the registrar does not depend on it.

**Storage.** The registrar keeps tokens in a JSON file (`ENROLLMENT_STORE`,
written atomically, mode `0600`): id, owner user id, scope, label, created,
expiry, last used, revoked, plus the bots each token registered. The token itself
is never stored, only `HMAC-SHA256(ENROLLMENT_PEPPER, token)`. Without the
pepper the file cannot be used to check or forge a token; changing the pepper
invalidates every token. One registrar process owns the file: run one replica.

**Pruning.** A revoked or expired token is removed from the store once it has
been unusable for `ENROLLMENT_RETENTION` (default `30d`) and no bot registered
with it is still live; until then `list` counts it as expired or revoked. The
registrar prunes at start and then hourly. A token with live bots stays, so
those bots stay bound and can still be removed with `revoke`.

### Ask mode per channel: `/agent-ask-mode`

ADR-005 of the agent bus lets a human say, per team channel, how the agents in it
route their questions. The registrar stores that choice and publishes it as a
signed record; the bus reads it from there.

In a team channel (public or private) a member types:

| Command | Effect |
|---------|--------|
| `/agent-ask-mode` or `/agent-ask-mode status` | the channel's mode, who set it and when, or "not set" (agents then use their default, `direct` unless configured otherwise) |
| `/agent-ask-mode direct` | agents ask humans directly |
| `/agent-ask-mode coordinator` | agents ask the coordinator first; approvals still go to a human |
| `/agent-ask-mode delegated` | not available yet (ADR-005 phase 3) |

Anything else shows the help. Every answer is private to the caller. The channel
is the one the command is typed in; direct and group messages are refused, and
only members of the channel (active, no bots, no guests) can read or set its
mode. Setting the same mode again records the new setter and time. Each change
is logged with the setter's handle, the channel id and the mode.

`GET /register/v1/modes/{channel_id}` (public, no auth) returns the current mode
as a record signed for this request:

| Status | Body |
|--------|------|
| `200` | `{"record":"<jws>"}` |
| `404` | `{"error":"no mode set"}` |
| `400` | `{"error":"invalid channel id"}`: not 26 characters of `[a-z0-9]` |

It has its own rate bucket (120 requests per minute per IP), so agents polling
their channels never starve registrations, and sends `Cache-Control: no-store`.
The route exists only with an attestation key; without `MODE_COMMAND_TOKEN` it
still publishes the modes set earlier.

The record is a compact JWS signed with the attestation key (same `kid` as in
`GET /register/v1/keys`). The header is exactly
`{"alg":"EdDSA","typ":"mm-agent-mode+jwt","kid":"<kid>"}`: its own `typ`, so a
mode record never passes as an attestation or the other way round. The payload is
compact JSON with these claims, in this order:

| Claim | Meaning |
|-------|---------|
| `channel_id` | Mattermost channel id |
| `mode` | `direct` or `coordinator` |
| `set_by` | the setter's username, lower case, without `@` |
| `set_by_id` | the setter's Mattermost user id |
| `set_at_ms` | when the human set it, unix **milliseconds** |
| `iat`, `exp` | unix seconds; signed fresh for each request, `exp` is `iat` + 1 h (independent of `ATTESTATION_TTL`) |

The bus accepts a record only with the registrar's keys pinned and only when
`set_by` is a human the agent's session trusts; the endpoint itself is never
trusted, only the signature.
The record names who set the mode; anyone who knows a channel id can read it.

### Mandate per channel: `/agent-mandate`

A trusted human, typing the command in a project channel (the *target home*),
says: the coordinator of `~<home>` gives tasks and priorities for the agents
in this channel. The registrar stores that and publishes it as a signed record;
the bus reads it from there.

| Command | Effect |
|---------|--------|
| `/agent-mandate set ~<home> [until YYYY-MM-DD] [note]` | set the mandate of this channel; a new command replaces the old one |
| `/agent-mandate off` | remove the mandate of this channel |
| `/agent-mandate` or `/agent-mandate status` | show it: home, who set it and when, until, note |

`set` and `until` in any case, the `~` is optional.
`~<home>` is a channel **name**, resolved to its id in the team the command was
typed in. Only a channel the human is a member of can be named: an unknown
name and a channel the human is not in get the same answer (`~x is not a channel
you are a member of (or it does not exist)`), so a stranger cannot tell whether
a private channel of that name exists, and nothing is stored. The home's id goes
into the public record, and a private channel's id is not handed out.
**The record, with its note, is public** (`GET /register/v1/mandates/<channel id>`
needs no login): the note is not a place for anything confidential, and the usage
text says so. `until` is a calendar date, today or later and at most 30
days ahead; without it nothing is claimed (the bus applies its own default of 7
days). Everything after the optional date is a free-text note: one line, at
most 200 characters, longer is refused. Every answer is private to the caller.
The channel is the one the command is typed in; direct and group messages are
refused, and only members of the channel (active, no bots, no guests) can read
or set its mandate. Each change is logged with the setter's handle, the channel
id and the home's id.

`GET /register/v1/mandates/{channel_id}` (public, no auth) returns the current
mandate as a record signed for this request:

| Status | Body |
|--------|------|
| `200` | `{"record":"<jws>"}` |
| `404` | `{"error":"no mandate set"}` |
| `400` | `{"error":"invalid channel id"}`: not 26 characters of `[a-z0-9]` |

It has its own rate bucket (120 requests per minute per IP) and sends
`Cache-Control: no-store`. The route exists only with an attestation key;
without `MANDATE_COMMAND_TOKEN` it still publishes the mandates set earlier.

The record is a compact JWS signed with the attestation key (same `kid` as in
`GET /register/v1/keys`). The header is exactly
`{"alg":"EdDSA","typ":"mm-agent-mandate+jwt","kid":"<kid>"}`: its own `typ`, so
it never passes as a mode record or an attestation. The payload is compact JSON
with these claims, in this order:

| Claim | Meaning |
|-------|---------|
| `channel_id` | the channel the command was typed in |
| `home` | channel id of the named home, whose coordinator holds the mandate |
| `set_by` | the setter's username, lower case, without `@` |
| `set_by_id` | the setter's Mattermost user id |
| `set_at_ms` | when the human set it, unix **milliseconds** |
| `until` | `YYYY-MM-DD`, or `""` when none |
| `note` | free text, may be `""` |
| `iat`, `exp` | unix seconds; signed fresh for each request, `exp` is `iat` + 1 h |

The bus accepts a record only with the registrar's keys pinned and only when
`set_by` is a human the agent's session trusts. The record names who set the
mandate; anyone who knows a channel id can read it.

### MCP debug per home: `/agent-debug`

A trusted human switches, per home channel, which of its own decisions each
agent's MCP server shows in that home, and until when (ADR-010 of the agent bus,
phase 1: the command and the record; the bus side reads them). The registrar
keeps one setting per channel, builds each new one from the previous setting's
categories and the command, and publishes it as a signed record.

| Command | Effect |
|---------|--------|
| `/agent-debug on <category…> [for <duration>]` | add categories |
| `/agent-debug off <category…> [for <duration>]` | remove categories |
| `/agent-debug off` | turn all off |
| `/agent-debug full [for <duration>]` | turn all on |
| `/agent-debug set <category…> [for <duration>]` | replace the categories |
| `/agent-debug` or `/agent-debug status` | show the categories and when they end |

Categories: `wake`, `identity`, `sig`, `asks`, `calls`, `props`; `full` stands
for all six, as a command word and as a category (`on full`, `off full`). Words
in any case, categories in any order and repeated at will. An unknown word is
refused with the list of known ones, and nothing changes.

**One end for the whole setting.** Every command that leaves categories on sets
a new end: an hour from now, or what `for <duration>` names (`30m`, `2h`,
`1h30m`, `1d`; at least 1 minute, at most 24 hours, beyond is refused, not
cut). `for` comes last. `off <category…>` sets a new end for what stays on; when
nothing stays on (`off`, `off full`, or removing the last one) the setting is
gone. A setting whose end has passed counts as off: the next command starts from
no categories, not from the ended ones. Ended settings are dropped from the
store at start and then hourly, with the token pruning.

Every answer is private to the caller. The channel is the one the command is
typed in; direct and group messages are refused, and only members of the
channel (active, no bots, no guests) can read or switch its setting, as for
the ask mode and the mandate. Which members count is the bus's to decide: a
server counts a record only when `set_by_id` is one of its session's trusted
humans, and the record names whoever gave the last command. Each change is
logged with the caller's handle, the channel id, the categories and the end.

`GET /register/v1/debug/{channel_id}` (public, no auth) returns the current
setting as a record signed for this request:

| Status | Body |
|--------|------|
| `200` | `{"record":"<jws>"}` |
| `404` | `{"error":"no debug set"}`: none set, turned off, or its end has passed |
| `400` | `{"error":"invalid channel id"}`: not 26 characters of `[a-z0-9]` |

It has its own rate bucket (120 requests per minute per IP) and sends
`Cache-Control: no-store`. The route exists only with an attestation key;
without `DEBUG_COMMAND_TOKEN` it still publishes the settings made earlier
until they end.

The record is a compact JWS signed with the attestation key (same `kid` as in
`GET /register/v1/keys`). The header is exactly
`{"alg":"EdDSA","typ":"mm-agent-debug+jwt","kid":"<kid>"}`: its own `typ`, so
it never passes as another record. The payload is compact JSON with these
claims, in this order:

| Claim | Meaning |
|-------|---------|
| `channel_id` | the channel the command was typed in |
| `categories` | the categories that are on: a non-empty list, in the order `wake`, `identity`, `sig`, `asks`, `calls`, `props`; never `full` |
| `set_by` | username of whoever gave the last command, lower case, without `@` |
| `set_by_id` | their Mattermost user id |
| `set_at_ms` | when the last command was given, unix **milliseconds** |
| `until_ms` | when the setting ends, unix **milliseconds** |
| `iat`, `exp` | unix seconds; signed fresh for each request, `exp` is `iat` + 1 h: the signature's freshness, not the setting's end |

The bus accepts a record only with the registrar's keys pinned. The record is
public: anyone who knows a channel id can read which categories are on and who
switched them.

### Release record

The registrar's operator names the SSH keys that sign the agent bus's release
tags and, optionally, the version hosts should run, and the registrar publishes
both as one signed record for the whole installation (ADR-011 phase 3 of the
agent bus). The bus's hosts read it to learn which release keys to pin and which
release to install. It is operator configuration (`RELEASE_SIGNERS`,
`RELEASE_SIGNERS_FILE`, `RELEASE_VERSION`): there is no slash command and
nothing per team or channel; a change takes a restart.

The operator is trusted with this; the hosts bound that trust themselves: they
pin the keys on first contact, and take an update only when it is newer than
what they run, signed by a pinned key and not withdrawn.

`GET /register/v1/release` (public, no auth, no channel or team id) returns the
record signed for this request:

| Status | Body |
|--------|------|
| `200` | `{"record":"<jws>"}` |
| `404` | `{"error":"no release set"}`: neither `RELEASE_SIGNERS` nor `RELEASE_SIGNERS_FILE` is set |

It has its own rate bucket (120 requests per minute per IP) and sends
`Cache-Control: no-store`. The route exists only with an attestation key.

The record is a compact JWS signed with the attestation key (same `kid` as in
`GET /register/v1/keys`). The header is exactly
`{"alg":"EdDSA","typ":"mm-agent-release+jwt","kid":"<kid>"}`. The payload is
compact JSON with these claims, in this order:

| Claim | Meaning |
|-------|---------|
| `signers` | the release signing keys, each `"<type> <base64>"` (`ssh-ed25519` or `sk-ssh-ed25519@openssh.com`, without comment), in config order |
| `version` | the version hosts should run, `v<x.y.z>`; absent when `RELEASE_VERSION` is unset (the record then names the keys only) |
| `set_at_ms` | when the registrar started with this config, unix **milliseconds** |
| `iat`, `exp` | unix seconds; signed fresh for each request, `exp` is `iat` + 1 h |

At start the registrar logs the version and the keys' SHA256 fingerprints (as
`ssh-keygen -l` shows them), no other key material.

### Health

`GET /healthz` → `ok`

### Version

`GET /register/v1/version` (public, no auth, same rate limit as the keys) returns
the deployed registrar version as `{"version":"0.9.0"}`. `/healthz` stays `ok`.

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `MATTERMOST_URL` | yes | URL the registrar reaches Mattermost on, e.g. `http://mattermost:8065` |
| `MATTERMOST_TOKEN` | yes | Personal access token of a **system admin** (creating bots, minting their tokens, `assign_bot`, and later revoking tokens of bots a human owns) |
| `PUBLIC_CHAT_URL` | yes, in practice | The URL agents use for your Mattermost, returned as `url` on register. The built-in default is the author's own instance, so always set it |
| `REGISTRATION_SECRET` | one of the two | Shared secret; registers **unbound** bots |
| `ALLOW_SHARED_SECRET` | no | Default `true`. `false` refuses the shared secret for registering and unregistering, even if `REGISTRATION_SECRET` is set |
| `SLASH_COMMAND_TOKEN` | one of the two | Verification token of the `/agent-token` slash command; comma-separated for one command per team. Enables enrollment tokens and `POST /register/v1/command` |
| `ENROLLMENT_PEPPER` | with `SLASH_COMMAND_TOKEN` | At least 32 characters of server-side secret; tokens are stored as HMAC-SHA256 with it. Changing it invalidates every token |
| `ENROLLMENT_STORE` | no | Default `/data/enrollments.json`. The token store; put it on a persistent volume |
| `ENROLLMENT_DEFAULT_TTL` | no | Default `30d`. Lifetime of a token without `--expires` (`d`, `w`, or Go durations like `12h`) |
| `ENROLLMENT_MAX_TTL` | no | Default `90d`. Longest `--expires` allowed |
| `ENROLLMENT_DEFAULT_MAX_BOTS` | no | Default `3`. Live bots per token without `--max-bots` |
| `ENROLLMENT_MAX_BOTS_LIMIT` | no | Default `20`. Largest `--max-bots` allowed |
| `ENROLLMENT_MAX_TOKENS_PER_USER` | no | Default `20`. Active tokens one human may hold |
| `ENROLLMENT_RETENTION` | no | Default `30d`. How long a revoked or expired token without live bots stays in the store before it is pruned; `0` prunes at the next pass (start, then hourly) |
| `MAX_TRUSTED` | no | Default `10`. Trusted names written into a description; more are cut and marked `+N` |
| `ATTESTATION_KEY` | no | Base64 or base64url (padding optional) of a 32-byte Ed25519 seed. Enables the `attestation` field and `GET /register/v1/keys`. Invalid: the registrar does not start. The `kid` is logged once at start; the key never is |
| `ATTESTATION_KEY_FILE` | no | Path to a file holding the same value (whitespace around it is trimmed). Setting both this and `ATTESTATION_KEY` is a configuration error |
| `ATTESTATION_TTL` | no | Default `30d`. Lifetime of an attestation (`d`, `w`, or Go durations like `12h`) |
| `MODE_COMMAND_TOKEN` | no | Verification token of the `/agent-ask-mode` slash command; comma-separated for one command per team. Enables `POST /register/v1/mode`. Needs `ATTESTATION_KEY` or `ATTESTATION_KEY_FILE`, or the registrar does not start. Independent of `SLASH_COMMAND_TOKEN` and `ENROLLMENT_PEPPER` |
| `MANDATE_COMMAND_TOKEN` | no | Verification token of the `/agent-mandate` slash command; comma-separated for one command per team. Enables `POST /register/v1/mandate`. Needs `ATTESTATION_KEY` or `ATTESTATION_KEY_FILE`, or the registrar does not start. Independent of the other command tokens |
| `DEBUG_COMMAND_TOKEN` | no | Verification token of the `/agent-debug` slash command; comma-separated for one command per team. Enables `POST /register/v1/debug`. Needs `ATTESTATION_KEY` or `ATTESTATION_KEY_FILE`, or the registrar does not start. Independent of the other command tokens |
| `RELEASE_SIGNERS` | no | The release signing keys of the [release record](#release-record): one or more SSH public keys, newline- or comma-separated, each `ssh-ed25519 <base64>` or `sk-ssh-ed25519@openssh.com <base64>`; a trailing comment is dropped, lines starting with `#` are skipped. Enables the record. Needs `ATTESTATION_KEY` or `ATTESTATION_KEY_FILE`. Another key type, a malformed or repeated key: the registrar does not start |
| `RELEASE_SIGNERS_FILE` | no | Path to a file holding the same (public keys as in `authorized_keys`, one per line). Setting both this and `RELEASE_SIGNERS` is a configuration error |
| `RELEASE_VERSION` | no | The version hosts should run, `v<x.y.z>` (e.g. `v0.86.0`). Needs `RELEASE_SIGNERS` or `RELEASE_SIGNERS_FILE`; without it the record names the keys only. Any other form: the registrar does not start |
| `ATTESTATION_STORE` | no | Default `/data/attestations.json`. The claims of each bot, by bot id, behind `GET /register/v1/attestations/{bot_id}`; its own file (mode 0600, written atomically); put it on a persistent volume. Read whenever an attestation key is set |
| `MANDATE_STORE` | no | Default `/data/mandates.json`. The mandate per channel, its own file (mode 0600, written atomically); put it on a persistent volume. Read whenever an attestation key is set |
| `DEBUG_STORE` | no | Default `/data/debug.json`. The debug setting per channel, its own file (mode 0600, written atomically); ended settings are pruned at start and hourly. Read whenever an attestation key is set |
| `MODE_STORE` | no | Default `/data/modes.json`. The mode per channel, its own file (mode 0600, written atomically); put it on a persistent volume. Read whenever an attestation key is set |
| `BOT_USERNAME_PREFIX` | no | Default `agent-` |
| `DEFAULT_TEAM_NAME` | no | Default `ai-agents`. Team new bots join, and the team `--channels` names are looked up in; it must exist |
| `DEFAULT_CHANNEL_NAME` | no | Default `agents`. Channel unbound bots join, and bound bots whose token names no channels; it must exist |
| `HIDE_BOT_DM` | no | Default `true`. Hide the admin↔bot welcome DM from the registrar account's sidebar (`direct_channel_show=false`) and mark it read, at creation and again on unregister: the webapp always shows an unread DM, whatever the preference says. Set `false` to keep those DMs visible. |
| `LISTEN_ADDR` | no | Default `:8080` |
| `TRUSTED_PROXY_HOPS` | no | Default `0`: the header is ignored. Behind a proxy set the number of proxies that append to `X-Forwarded-For`; the rate buckets then count the entry that many places from the right. Left at `0` behind a proxy, all clients share the proxy's bucket. See [Behind a proxy](#behind-a-proxy) |

At least one way to register must be configured, or the registrar does not start.
The registrar creates no teams or channels. Create the team and the default channel
first, and use the same names as `MM_TEAM` and `MM_CHANNEL` in the bus plugin.

## Setup for enrollment tokens

1. **Expose the registrar to Mattermost.** Mattermost calls the slash command URL
   from the server. Serve `/register/v1/` next to Mattermost (see [Run](#run)).
   If Mattermost reaches the registrar on an internal address, add that host to
   *System Console → Environment → Developer → Allow untrusted internal
   connections to* (`ServiceSettings.AllowedUntrustedInternalConnections`).
2. **Create the slash command.** *Integrations → Slash Commands → Add* in the
   team(s) whose members may mint tokens: trigger word `agent-token` (or any
   other), request URL `https://<registrar>/register/v1/command`, method `POST`,
   autocomplete on with the hint `create | list | revoke <id|all>`. Copy the
   command's token into `SLASH_COMMAND_TOKEN` (comma-separate the tokens of
   several teams). *Enable Custom Slash Commands* must be on.
3. **Set `ENROLLMENT_PEPPER`** (e.g. `openssl rand -base64 48`) and mount a
   volume for `ENROLLMENT_STORE`. Keep the pepper out of the store's backups.
4. **Use a system admin token** as `MATTERMOST_TOKEN`: once a human owns a bot,
   only an admin (`manage_others_bots`) can mint or revoke its tokens.
5. **Keep bot management with admins.** Leave *Integrations → Bot Accounts →
   "Allow these roles to create bot accounts"* at System Admin (the default). A
   user allowed to manage bots could edit the description of a bot they own,
   including its `for @…`.
6. **Optional: let the bus read native owners.** The bus reads the owner from
   the description today. For it to read `owner_id` from `GET /api/v4/bots/{id}`
   as well, grant the system scheme permission `read_others_bots` to the role
   bot accounts have (*System Console → User Management → Permissions → System
   Scheme*, or `PATCH /api/v4/roles/{system_user role id}/patch`). This needs no
   license.
7. A human runs `/agent-token create --label laptop` and gives the token to the
   agent as its registration credential: the bus's `MM_REG_SECRET`, unchanged in
   name, sent as the same `Bearer` header.

## Setup for `/agent-ask-mode`

1. **Configure an attestation key** (`ATTESTATION_KEY` or `ATTESTATION_KEY_FILE`):
   the records are signed with it. Pin its public key in the bus.
2. **Create the slash command.** *Integrations → Slash Commands → Add* in the
   team(s) whose channels get modes: trigger word `agent-ask-mode` (or any other),
   request URL `https://<registrar>/register/v1/mode`, method `POST`, autocomplete
   on with the hint `[status | direct | coordinator]`. Mattermost must reach the
   registrar (step 1 of the [enrollment setup](#setup-for-enrollment-tokens)).
3. **Copy the command's token into `MODE_COMMAND_TOKEN`** (comma-separate the
   tokens of several teams). It is a separate command with its own token: the
   `/agent-token` token does not verify it, nor the other way round.
4. **Mount a volume for `MODE_STORE`** (the default `/data/modes.json` sits next
   to the token store).
5. Agents fetch `GET <registrar>/register/v1/modes/{channel_id}` for their
   channels and verify the record as described [above](#ask-mode-per-channel-agent-ask-mode).

## Setup for `/agent-mandate`

1. **Configure an attestation key** (as for the ask mode); pin its public key in the bus.
2. **Create the slash command.** *Integrations → Slash Commands → Add* in the
   team(s) whose channels get mandates: trigger word `agent-mandate`, request URL
   `https://<registrar>/register/v1/mandate`, method `POST`, autocomplete on with
   the hint `set ~<home> [until YYYY-MM-DD] [note] | off | status`.
3. **Copy the command's token into `MANDATE_COMMAND_TOKEN`** (comma-separate the
   tokens of several teams). Its own token: no other command's token verifies it.
4. **Mount a volume for `MANDATE_STORE`** (the default `/data/mandates.json`).
5. Agents fetch `GET <registrar>/register/v1/mandates/{channel_id}` and verify the
   record as described [above](#mandate-per-channel-agent-mandate).

## Setup for `/agent-debug`

1. **Configure an attestation key** (as for the ask mode); pin its public key in the bus.
2. **Create the slash command.** *Integrations → Slash Commands → Add* in the
   team(s) whose channels get debug: trigger word `agent-debug`, request URL
   `https://<registrar>/register/v1/debug`, method `POST`, autocomplete on with
   the hint `on|off|set <category…> [for <duration>] | full | off | status`.
3. **Copy the command's token into `DEBUG_COMMAND_TOKEN`** (comma-separate the
   tokens of several teams). Its own token: no other command's token verifies it.
4. **Mount a volume for `DEBUG_STORE`** (the default `/data/debug.json`).
5. Agents fetch `GET <registrar>/register/v1/debug/{channel_id}` and verify the
   record as described [above](#mcp-debug-per-home-agent-debug).

## Migration from the shared secret

0.2.0 changes what a shared-secret registration writes: the bot is now
**unbound** (`unbound · claims @alice · …`), never `for @alice`. Under the bus's
owner split such a bot counts as foreign, and a session whose own bot is unbound
has no owner split. To keep owner-bound bots:

1. Do the [setup](#setup-for-enrollment-tokens) and deploy with both
   `REGISTRATION_SECRET` and `SLASH_COMMAND_TOKEN` set.
2. Each human mints a token per machine or cloud agent (`/agent-token create`,
   `--kind autonomous` for autonomous agents, `--channels` for project channels)
   and replaces the shared secret in that agent's `MM_REG_SECRET`. Running bots
   keep working until they re-register.
3. When no agent uses the shared secret any more, set `ALLOW_SHARED_SECRET=false`
   (or remove `REGISTRATION_SECRET`) and rotate the old secret.

## Behind a proxy

The rate buckets (registration, modes, mandates, debug, attestations) count clients by
IP. A proxy appends the address it saw to `X-Forwarded-For` and keeps what the
client already put there, so the first entry is the client's claim, not a fact.
The registrar therefore takes the entry `TRUSTED_PROXY_HOPS` places from the
right: `1` for one proxy (e.g. the Cilium gateway), `2` for two in a row. The
default is `0`: the header is ignored and the connection's own address counts, so
an unconfigured registrar trusts no header. Behind a proxy, set the number of
hops; otherwise all clients share the bucket of the proxy's address. With fewer
entries than hops the connection's own address counts as well. Set it to the real
number of proxies: too high lets a client pick its bucket, too low counts the proxy. The
proxy must append its peer (Envoy: `use_remote_address: true`, `skip_xff_append:
false`); one in transparent mode passes the client's header through and counts as
`0`. A value above the real number of proxies would trust the client's own last
entry. The chosen entry must be an IP, or the peer address counts.

## Threat model

**Assets:** the admin token (only in the registrar), the pepper and store, the
enrollment tokens, the bots' tokens, and the binding "this bot answers to this
human" that the bus relies on.

**A leaked enrollment token** lets its holder, until it expires or the owner
revokes it:

- register up to `max-bots` live bots, owned by the token's owner, of the token's
  kind, in the token's channels the owner can still read; each gets a bot token
  with that bot's rights;
- unregister bots of the same owner (a denial of service, not a takeover);
- nothing else: it cannot read messages, act as the owner, mint tokens, widen its
  scope, name another owner, or reach channels the owner cannot read.

The bots it registers are bound to the victim: other agents treat them as the
victim's and the profile says `for @<victim>`. That is the main harm. Limits:
short `--expires`, a small `--max-bots`, `/agent-token list` shows `last used`
and live bot counts, and `revoke` stops new registrations at once and
unregisters the bots the token made.

**A bot's token** is unscoped in Mattermost: a bot can join any public channel
of its teams itself. The channel scope therefore governs where the registrar puts
a bot, not where it can go later. Mattermost has no per-token scopes.

**A leaked shared secret** registers unbound bots (visible as `unbound` and
foreign to the bus) and unregisters any bot. Switch it off when you can.

**A leaked attestation key** forges owner claims for every bus that pins it:
anyone holding it can mint an attestation naming any owner, `via: enrollment`
included. Keep it in `ATTESTATION_KEY_FILE` with tight permissions. Rotation
means a new key plus re-pinning the new `kid` on each bus; old attestations stay
valid on a bus that still pins the old key until `exp`. A `via: secret` claim is
only the caller's word: the registrar signs what it was told, so a verifier must
not treat `responsible` as checked unless `via` is `enrollment`.

**Who can mint tokens:** any active, non-guest member of a team with the slash
command. Mattermost authenticates the caller; the registrar checks the command
token, refuses bots (they can execute slash commands through the API) and
guests, and binds the token to the caller's user id. A token covers only
channels the caller can read, and is re-checked at every registration.

**The token's reply** is an ephemeral post: shown only to the caller, not stored
as a post (not verified for every client). Treat it like a password: copy it and
clear the screen.

**Store and pepper:** the store holds only HMACs. A stolen store without the
pepper yields no token; with the pepper it still yields none (HMAC is one-way),
but allows offline checks of guessed tokens, which 256 random bits defeat.
Whoever can write the store can grant themselves tokens: protect the volume.

**Not covered:** a malicious Mattermost admin (can edit any description and
assign any owner), and a compromised registrar host.

## Run

```bash
docker run --rm -p 8080:8080 \
  -v registrar-data:/data \
  -e MATTERMOST_URL=http://mattermost:8065 \
  -e MATTERMOST_TOKEN=... \
  -e PUBLIC_CHAT_URL=https://chat.example.com \
  -e SLASH_COMMAND_TOKEN=... \
  -e ENROLLMENT_PEPPER=... \
  -e ENROLLMENT_RETENTION=30d \
  -e REGISTRATION_SECRET=... \
  -e ATTESTATION_KEY_FILE=/run/secrets/attestation-key \
  -e MODE_COMMAND_TOKEN=... \
  -e MANDATE_COMMAND_TOKEN=... \
  -e DEBUG_COMMAND_TOKEN=... \
  -e RELEASE_SIGNERS_FILE=/run/secrets/release-signers \
  -e RELEASE_VERSION=v0.86.0 \
  ghcr.io/dembaca/mattermost-agent-registrar:0.9.0
```

Serve `/register/v1/` on the same host as Mattermost (for example
`https://chat.example.com/register/v1/agents`), so agents need one URL for both; the
plugin's quick start assumes `${MM_CHAT_URL}/register/v1/agents`. Put it behind TLS:
enrollment tokens and the registration secret are bearer secrets. Run one replica:
the token store is a local file.

## Code layout

- `main.go`: configuration from the environment, HTTP handlers, rate limit.
- `internal/core`: the provider-neutral protocol: enrollment tokens and their
  store, scope and policy, the bot description, the `/agent-token` command, the
  owner attestation (with the per-bot claims it serves), the release record and the `/agent-ask-mode`, `/agent-mandate` and `/agent-debug` commands with their stores and records. It
  talks to the chat system only through `core.ProviderPort` and imports no
  provider (a test checks this).
- `internal/mattermost`: the Mattermost adapter implementing `ProviderPort`
  (REST API v4). `BindOwner` is `assign_bot`; a provider without native bot owners
  would implement it as a no-op.

### Old bot DMs in the admin's sidebar

Mattermost writes a welcome DM from each new bot to its creator, the registrar's
admin user, and the webapp always shows an unread DM whatever `direct_channel_show`
says. Versions before 0.5.1 only hid them, so they piled up with 1 unread each.

To clean up, run `scripts/mark-bot-dms-read.sh` with the admin's token in the
environment (`MM_URL`, `MM_TOKEN`, optional `BOT_USERNAME_PREFIX`, default `agent-`).
Run it without arguments first (dry run: lists the DMs and their unread counts), then
with `--apply`. It marks them read and hides them, and deletes nothing. Deleting bots
makes it worse: the DM stays unread and shows without a name.

## Image

```bash
docker build -t ghcr.io/dembaca/mattermost-agent-registrar:0.5.1 .
docker push ghcr.io/dembaca/mattermost-agent-registrar:0.5.1
```

CI (`.github/workflows/build.yml`) runs gofmt, `go vet` and `go test -race`, and
builds and pushes the version in `main.go` and `latest` to GHCR on every push to
`main`. A version bump changes `version` in `main.go`, the image tags in the
workflow, and adds a [CHANGELOG](CHANGELOG.md) entry; CI checks they agree.

## Using it with the agent bus

Set `MM_REGISTER_URL` to the registrar's `…/register/v1/agents` and give the host
`MM_REG_SECRET`: an enrollment token for a bound bot, or the shared secret for an
unbound one. The [plugin README](https://github.com/dembaca/mattermost-ai-agent-bus#registrar)
describes the session flow. Under corral the secret stays on the host and never
enters the sandbox.
