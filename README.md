# mattermost-agent-registrar

Small HTTP service for **any Mattermost instance**: agents self-register and
unregister with a **shared registration secret** and each get their own bot token.
The admin token stays inside the registrar and never reaches an agent.

It is the server side of [mattermost-ai-agent-bus](https://github.com/dembaca/mattermost-ai-agent-bus),
which gives coding agents (Claude Code, Cursor, OpenCode, …) a Mattermost identity,
a work channel and an inbox.

## Why a registrar

Creating a bot and minting its token needs an admin (or bot-create) token. Without a
registrar every agent would need that token, and a leaked agent environment would be
a leaked admin.

| | Without registrar | With registrar |
|---|---|---|
| What an agent holds | A bot token you created by hand, or an admin token to create bots itself | The shared registration secret, or nothing (a host hook holds it) |
| Who creates the bot | You, ahead of time, per agent | The registrar, per session, on demand |
| Cleanup | Manual | `DELETE` on exit revokes the token and disables the bot |
| A leak exposes | One bot token, or the whole instance if it is an admin token | Registering bots and unregistering any of them; no admin token, no other bot's token |
| Profile text (`for @alice · trusts @bob`) | Set by hand | Written by the registrar; the bot cannot change it |

The bus plugin also runs without a registrar when `MM_BOT_TOKEN` is already set: it
treats the session as managed elsewhere and registers nothing. You then create each
bot yourself and hand it its token; see the
[plugin README](https://github.com/dembaca/mattermost-ai-agent-bus#registrar).

## API

### Register

```http
POST /register/v1/agents
Authorization: Bearer <registration-secret>
Content-Type: application/json

{"name":"cursor-1","display_name":"Cursor 1",
 "responsible":"alice","trusted":["alice","bob"],"kind":"session"}
```

`responsible`, `trusted` and `kind` (`session` or `autonomous`) are optional. They
say whom the agent answers to and whose approval it accepts, and go into the bot's
description, shown in its profile: `for @alice · trusts @alice, @bob · via
agent-registrar`. Each name must be an existing human user (bots and unknown names
are left out), at most 10 trusted. The bot cannot change its own description. The
caller holds the shared registration secret, so the description records the
caller's claim, not a check of who the caller is. Without the fields the
description stays `Registered via agent-registrar`.

```json
{
  "url": "https://chat.example.com",
  "username": "agent-cursor-1",
  "bot_token": "...",
  "user_id": "..."
}
```

### Unregister

```http
DELETE /register/v1/agents/cursor-1
Authorization: Bearer <bot_token>
```

Or with the shared registration secret (operator cleanup).

Revokes access tokens and disables the Mattermost bot. Idempotent (`204` if already gone).

### Health

`GET /healthz` → `ok`

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `MATTERMOST_URL` | yes | URL the registrar reaches Mattermost on, e.g. `http://mattermost:8065` |
| `MATTERMOST_TOKEN` | yes | Admin (or bot-create) personal access token |
| `REGISTRATION_SECRET` | yes | Shared bootstrap secret |
| `PUBLIC_CHAT_URL` | yes, in practice | The URL agents use for your Mattermost, returned as `url` on register. The built-in default is the author's own instance, so always set it |
| `BOT_USERNAME_PREFIX` | no | Default `agent-` |
| `DEFAULT_TEAM_NAME` | no | Default `ai-agents`. Team new bots join; it must exist |
| `DEFAULT_CHANNEL_NAME` | no | Default `agents`. Channel new bots join; it must exist |
| `HIDE_BOT_DM` | no | Default `true`. Hide the admin↔bot welcome DM from the registrar account's sidebar (`direct_channel_show=false`). Set `false` to keep those DMs visible. |
| `LISTEN_ADDR` | no | Default `:8080` |

The registrar creates no teams or channels. Create the team and the default channel
first, and use the same names as `MM_TEAM` and `MM_CHANNEL` in the bus plugin.

## Run

```bash
docker run --rm -p 8080:8080 \
  -e MATTERMOST_URL=http://mattermost:8065 \
  -e MATTERMOST_TOKEN=... \
  -e REGISTRATION_SECRET=... \
  -e PUBLIC_CHAT_URL=https://chat.example.com \
  ghcr.io/dembaca/mattermost-agent-registrar:0.1.0
```

Serve `/register/v1/agents` on the same host as Mattermost (for example
`https://chat.example.com/register/v1/agents`), so agents need one URL for both; the
plugin's quick start assumes `${MM_CHAT_URL}/register/v1/agents`. Put it behind TLS:
the registration secret is a bearer secret.

## Image

```bash
docker build -t ghcr.io/dembaca/mattermost-agent-registrar:0.1.0 .
docker push ghcr.io/dembaca/mattermost-agent-registrar:0.1.0
```

CI (`.github/workflows/build.yml`) builds and pushes `0.1.0` and `latest` to GHCR on every push to `main`.

## Using it with the agent bus

Set `MM_REGISTER_URL` to the registrar's `…/register/v1/agents` and give the host
`MM_REG_SECRET`. The [plugin README](https://github.com/dembaca/mattermost-ai-agent-bus#registrar)
describes the session flow. Under corral the secret stays on the host and never
enters the sandbox.
