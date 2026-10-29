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

`owner` is present only for a bound bot.

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

### Health

`GET /healthz` → `ok`

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
| `BOT_USERNAME_PREFIX` | no | Default `agent-` |
| `DEFAULT_TEAM_NAME` | no | Default `ai-agents`. Team new bots join, and the team `--channels` names are looked up in; it must exist |
| `DEFAULT_CHANNEL_NAME` | no | Default `agents`. Channel unbound bots join, and bound bots whose token names no channels; it must exist |
| `HIDE_BOT_DM` | no | Default `true`. Hide the admin↔bot welcome DM from the registrar account's sidebar (`direct_channel_show=false`). Set `false` to keep those DMs visible. |
| `LISTEN_ADDR` | no | Default `:8080` |

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
  ghcr.io/dembaca/mattermost-agent-registrar:0.3.0
```

Serve `/register/v1/` on the same host as Mattermost (for example
`https://chat.example.com/register/v1/agents`), so agents need one URL for both; the
plugin's quick start assumes `${MM_CHAT_URL}/register/v1/agents`. Put it behind TLS:
enrollment tokens and the registration secret are bearer secrets. Run one replica:
the token store is a local file.

## Code layout

- `main.go`: configuration from the environment, HTTP handlers, rate limit.
- `internal/core`: the provider-neutral protocol: enrollment tokens and their
  store, scope and policy, the bot description, the `/agent-token` command. It
  talks to the chat system only through `core.ProviderPort` and imports no
  provider (a test checks this).
- `internal/mattermost`: the Mattermost adapter implementing `ProviderPort`
  (REST API v4). `BindOwner` is `assign_bot`; a provider without native bot owners
  would implement it as a no-op.

## Image

```bash
docker build -t ghcr.io/dembaca/mattermost-agent-registrar:0.3.0 .
docker push ghcr.io/dembaca/mattermost-agent-registrar:0.3.0
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
