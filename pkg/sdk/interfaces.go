package sdk

import "context"

// Collector tails or reads a log source and emits raw lines.
type Collector interface {
	Run(ctx context.Context, out chan<- RawLine) error
}

// Parser converts a raw log line into zero or more Events.
type Parser interface {
	Parse(line RawLine) ([]Event, error)
	Matches(source string) bool // true if this parser handles the given source
}

// AIProvider is an LLM or AI service that can analyze aggregates and return verdicts.
// Implementations must wrap aggregates as structured data, never as instructions.
type AIProvider interface {
	Name() string
	Analyze(ctx context.Context, batch []Aggregate, budget TokenBudget) ([]Verdict, Usage, error)
}

// Enforcer applies or removes bans on a local firewall or an edge platform.
// Sync reconciles the enforcer's state with the desired target set; it must be
// called at startup and periodically to handle TTL expiry on platforms that lack
// native TTL support.
type Enforcer interface {
	Name() string
	Ban(ctx context.Context, t Target) error
	Unban(ctx context.Context, t Target) error
	Sync(ctx context.Context, want []Target) error
}

// Notifier sends alert messages to an external channel (Telegram, email, ...).
type Notifier interface {
	Name() string
	Send(ctx context.Context, msg Notification) error
}
