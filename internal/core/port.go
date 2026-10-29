// Package core is the registrar's provider-neutral protocol: enrollment
// tokens, their scope, the registration policy and the bot description. It
// talks to the chat system only through ProviderPort and never imports a
// provider's client (internal/mattermost is one adapter).
package core

import (
	"context"
	"net/http"
)

// Human is a person on the chat provider, never a bot.
type Human struct {
	ID     string // provider user id
	Handle string // username, lower case, without "@"
}

// Agent is a bot account the registrar created.
type Agent struct {
	ID       string // provider user id of the bot
	Username string
}

// Invocation is a verified call of the token command: the provider vouches
// for who typed it.
type Invocation struct {
	Human   Human
	Command string // the trigger as typed, e.g. "/agent-token"; used in help texts only
	Text    string // everything after the trigger
}

// ProviderPort is everything the protocol needs from a chat provider.
// Adapters: internal/mattermost. A provider without native bot owners
// implements BindOwner as a no-op; the description still names the owner.
type ProviderPort interface {
	// VerifyInvocation checks that r is a genuine command call from the
	// provider (e.g. the slash command's token) and that the caller is an
	// active human. It returns ErrUnauthorized or ErrForbidden otherwise.
	VerifyInvocation(r *http.Request) (Invocation, error)
	// ReplyPrivate answers an invocation so that only its caller sees it.
	ReplyPrivate(w http.ResponseWriter, inv Invocation, text string)
	// ResolveHuman finds an active human by handle; nil when there is none
	// (unknown, deactivated or a bot).
	ResolveHuman(ctx context.Context, handle string) (*Human, error)
	// HumanByID is ResolveHuman by provider user id.
	HumanByID(ctx context.Context, id string) (*Human, error)
	// HumanCanAccess says whether h may read channel (a channel name in the
	// registrar's team): member of it, or member of the team and the channel
	// is public. ErrNoSuchChannel when the channel does not exist.
	HumanCanAccess(ctx context.Context, h Human, channel string) (bool, error)
	// FindAgent finds an account by username; nil when there is none.
	FindAgent(ctx context.Context, username string) (*Agent, error)
	// AgentForCredential returns the account a credential (bot token) belongs to.
	AgentForCredential(ctx context.Context, credential string) (*Agent, error)
	// CreateAgent creates the bot account with its profile text.
	CreateAgent(ctx context.Context, username, display, profile string) (Agent, error)
	// BindOwner makes owner the agent's native owner where the provider has one.
	BindOwner(ctx context.Context, a Agent, owner Human) error
	// IssueCredential mints the agent's own credential (a bot token).
	IssueCredential(ctx context.Context, a Agent) (string, error)
	// JoinChannels adds the agent to the registrar's team and to channels.
	JoinChannels(ctx context.Context, a Agent, channels []string) error
	// RevokeAgent revokes the agent's credentials and disables the account.
	RevokeAgent(ctx context.Context, a Agent) error
}
