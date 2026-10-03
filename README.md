# mattermost-agent-registrar

Small HTTP service for [BGL](https://github.com/dembaca/bgl-infra) Mattermost: cloud agents self-register and unregister with a **shared registration secret**, each getting their own bot token.

## API

### Register

```http
POST /register/v1/agents
Authorization: Bearer <registration-secret>
Content-Type: application/json

{"name":"cursor-1","display_name":"Cursor 1"}
```

```json
{
  "url": "https://chat.bgl.dembach.org",
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
| `MATTERMOST_URL` | yes | In-cluster URL, e.g. `http://mattermost:8065` |
| `MATTERMOST_TOKEN` | yes | Admin (or bot-create) personal access token |
| `REGISTRATION_SECRET` | yes | Shared bootstrap secret |
| `PUBLIC_CHAT_URL` | no | Default `https://chat.bgl.dembach.org` |
| `BOT_USERNAME_PREFIX` | no | Default `agent-` |
| `DEFAULT_TEAM_NAME` | no | Default `ai-agents` |
| `DEFAULT_CHANNEL_NAME` | no | Default `agents` |
| `HIDE_BOT_DM` | no | Default `true`. Hide the admin↔bot welcome DM from the registrar account's sidebar (`direct_channel_show=false`). Set `false` to keep those DMs visible. |
| `LISTEN_ADDR` | no | Default `:8080` |

## Image

```bash
docker build -t ghcr.io/dembaca/mattermost-agent-registrar:0.1.0 .
docker push ghcr.io/dembaca/mattermost-agent-registrar:0.1.0
```

Deployed from `bgl-infra` (`kubernetes/workloads/mattermost/`).
