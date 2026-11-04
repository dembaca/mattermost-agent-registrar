#!/usr/bin/env bash
# One-time cleanup: mark the bot welcome DMs of the token's account read and hide
# them. Dry run by default; --apply changes things. Deletes nothing.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: MM_URL=https://chat.example.org MM_TOKEN=... mark-bot-dms-read.sh [--apply]

Finds the direct messages of the token's account with bots whose username starts
with BOT_USERNAME_PREFIX (default "agent-") or with permanently deleted users,
and lists their unread counts (dry run). With --apply it marks the unread ones
read and sets direct_channel_show=false for all of them. It deletes nothing.

Environment: MM_URL, MM_TOKEN (read from the environment only), BOT_USERNAME_PREFIX.
USAGE
}

apply=0
case "${1:-}" in
  "") ;;
  --apply) apply=1 ;;
  -h | --help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

: "${MM_URL:?MM_URL is not set}"
if [ -z "${MM_TOKEN:-}" ]; then
  echo "MM_TOKEN is not set (personal access token, read from the environment only)" >&2
  exit 2
fi
prefix="${BOT_USERNAME_PREFIX:-agent-}"
base="${MM_URL%/}/api/v4"

# The token goes to curl on stdin, never on its command line.
api() {
  local method=$1 path=$2 data=${3:-}
  local args=(-sS --fail-with-body -X "$method" -H @- -H 'Content-Type: application/json')
  [ -n "$data" ] && args+=(--data-binary "$data")
  curl "${args[@]}" "$base$path" <<<"Authorization: Bearer $MM_TOKEN"
}

me=$(api GET /users/me | jq -r .id)
[ -n "$me" ] && [ "$me" != null ] || { echo "cannot read /users/me" >&2; exit 1; }

# DM channels (type D) as "<channel id> <other user id>"; skip the self-DM.
dms=$(api GET '/users/me/channels?include_deleted=true' |
  jq -r --arg me "$me" '.[] | select(.type == "D")
    | .id as $id | (.name | split("__") | map(select(. != $me)))[0] // empty
    | "\($id) \(.)"')
if [ -z "$dms" ]; then
  echo "candidates: 0, unread: 0"
  exit 0
fi

ids=$(awk '{print $2}' <<<"$dms" | jq -R . | jq -sc .)
users=$(api POST /users/ids "$ids")

candidates=0
unread=0
others=()
while read -r cid uid; do
  found=$(jq -r --arg id "$uid" '[.[] | select(.id == $id)] | length' <<<"$users")
  if [ "$found" = 0 ]; then
    uname="<deleted user>"
  else
    uname=$(jq -r --arg id "$uid" --arg p "$prefix" '.[] | select(.id == $id)
      | select(.is_bot and (.username | startswith($p))) | .username' <<<"$users")
    [ -n "$uname" ] || continue
  fi
  n=$(api GET "/users/me/channels/$cid/unread" | jq -r '.msg_count // 0')
  candidates=$((candidates + 1))
  others+=("$uid")
  if [ "$n" -gt 0 ]; then
    unread=$((unread + 1))
    if [ "$apply" = 1 ]; then
      api POST /channels/members/me/view "$(jq -nc --arg c "$cid" '{channel_id: $c}')" >/dev/null
    fi
  fi
  echo "$cid $uname $n"
done <<<"$dms"

echo "candidates: $candidates, unread: $unread"

if [ "$apply" = 1 ] && [ "$candidates" -gt 0 ]; then
  printf '%s\n' "${others[@]}" | jq -R --arg me "$me" \
    '{user_id: $me, category: "direct_channel_show", name: ., value: "false"}' | jq -sc 'range(0; length; 100) as $i | .[$i:$i+100]' |
    while read -r batch; do
      api PUT /users/me/preferences "$batch" >/dev/null
    done
  echo "applied"
else
  [ "$apply" = 1 ] || echo "dry run: nothing changed, use --apply"
fi
