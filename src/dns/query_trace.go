package dns

import (
	"context"
	"net"
	"sync"

	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

// QueryTrace records how a single hostname lookup was answered, for the
// caller that attached the trace to the lookup's context. A direct outbound
// with its own nameserver list attaches one to each of its dials and copies
// the result into the connection's metadata: which nameserver answered the
// lookup, from which local address, and whether the answer came from the
// resolver's cache. Lookups without a trace behave exactly as before.
type QueryTrace struct {
	// Outbound is the name of the outbound the lookup is made for. It is
	// only used in log lines.
	Outbound string

	mu       sync.Mutex
	local    map[string]string // nameserver address -> local address of its latest exchange
	answer   queryAnswer
	answered bool // an answer was recorded
	fresh    bool // the answer came from an exchange of this lookup
	cached   bool // the answer came from the cache
}

// queryAnswer is how one lookup was answered. It is stored beside every
// cached message, so a cache hit can report the query that filled the entry.
type queryAnswer struct {
	server    string // nameserver address, as the client reports it
	localAddr string // local address the query left from, when the transport reports one
}

// cachedMsg is a cache entry: the answer of the query that filled the entry
// is kept beside the message, so hits can report it.
type cachedMsg struct {
	msg    *D.Msg
	answer queryAnswer
}

type queryTraceKey struct{}

// NewQueryTrace creates a trace for a lookup made for the named outbound. It
// returns nil for an empty name: a lookup not made for an outbound, such as
// a background cache refresh of the main resolver, is not traced.
func NewQueryTrace(outbound string) *QueryTrace {
	if outbound == "" {
		return nil
	}
	return &QueryTrace{Outbound: outbound}
}

// WithQueryTrace returns a context carrying trace, or ctx unchanged when
// trace is nil.
func WithQueryTrace(ctx context.Context, trace *QueryTrace) context.Context {
	if trace == nil {
		return ctx
	}
	return context.WithValue(ctx, queryTraceKey{}, trace)
}

func traceFromContext(ctx context.Context) *QueryTrace {
	if trace, ok := ctx.Value(queryTraceKey{}).(*QueryTrace); ok {
		return trace
	}
	return nil
}

// traceOutbound returns the name of the outbound a traced lookup is made
// for, or "" when the context carries no trace.
func traceOutbound(ctx context.Context) string {
	if trace := traceFromContext(ctx); trace != nil {
		return trace.Outbound
	}
	return ""
}

// exchangeDial records the local address of one exchange to server. Only the
// plain UDP and TCP transports report one.
func (t *QueryTrace) exchangeDial(server, localAddr string) {
	t.mu.Lock()
	if t.local == nil {
		t.local = make(map[string]string, 1)
	}
	t.local[server] = localAddr
	t.mu.Unlock()
}

// queryLocalAddr returns the address a query connection is bound to,
// looking through the custom addresses outbound wrappers put on their
// connections.
func queryLocalAddr(conn net.Conn) string {
	addr := conn.LocalAddr()
	for {
		raw, ok := addr.(interface{ RawAddr() net.Addr })
		if !ok {
			break
		}
		if rawAddr := raw.RawAddr(); rawAddr != nil {
			addr = rawAddr
			continue
		}
		break
	}
	if addr == nil {
		return ""
	}
	return addr.String()
}

// exchangeDone records the outcome of one exchange of the traced lookup:
// one debug line per query that actually left mihomo, and, for the first
// exchange that answered, the values reported to the caller. An exchange
// that answered replaces an answer taken from the cache; the cache never
// replaces an exchange.
func (t *QueryTrace) exchangeDone(server, domain string, msg *D.Msg, err error) {
	t.mu.Lock()
	local := t.local[server]
	if err == nil && !t.fresh {
		t.answer = queryAnswer{server: server, localAddr: local}
		t.answered, t.fresh, t.cached = true, true, false
	}
	t.mu.Unlock()

	localPart := ""
	if local != "" {
		localPart = " (local " + local + ")"
	}
	if err != nil {
		log.Debugln("[DNS] %s: %s queried via %s%s: %v", t.Outbound, domain, server, localPart, err)
		return
	}
	log.Debugln("[DNS] %s: %s queried via %s%s: %s", t.Outbound, domain, server, localPart, D.RcodeToString[msg.Rcode])
}

// cacheAnswered records a cache hit carrying answer, the values of the query
// that filled the entry. It never replaces an exchange of this lookup.
func (t *QueryTrace) cacheAnswered(answer queryAnswer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fresh {
		return
	}
	t.answer, t.answered, t.cached = answer, true, true
}

// mergedAnswered records an answer produced by an identical in-flight query
// that this lookup was merged into. Its values come from that query, but the
// answer did not come from the cache. It is not recorded when this lookup
// already has an answer of its own.
func (t *QueryTrace) mergedAnswered(answer queryAnswer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fresh || t.answered {
		return
	}
	t.answer, t.answered = answer, true
}

// Result reports how the traced lookup was answered. ok is false when no
// exchange answered and no answer was cached.
func (t *QueryTrace) Result() (server, localAddr string, cached, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.answer.server, t.answer.localAddr, t.cached, t.answered
}
