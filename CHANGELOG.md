# Changelog

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
