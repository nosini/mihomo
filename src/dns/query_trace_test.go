package dns

import (
	"context"
	"errors"
	"net"
	"testing"

	D "github.com/miekg/dns"
)

func TestQueryTraceExchangeWinsOverCache(t *testing.T) {
	trace := NewQueryTrace("exit-a")
	if traceFromContext(context.Background()) != nil {
		t.Fatal("an empty context carries a trace")
	}
	ctx := WithQueryTrace(context.Background(), trace)
	if traceFromContext(ctx) != trace {
		t.Fatal("WithQueryTrace did not attach the trace")
	}

	// A cache hit reports the query that filled the entry.
	trace.cacheAnswered(queryAnswer{server: "udp://10.0.0.53:53", localAddr: "10.0.0.5:40001"})
	server, localAddr, cached, ok := trace.Result()
	if !ok || !cached || server != "udp://10.0.0.53:53" || localAddr != "10.0.0.5:40001" {
		t.Fatalf("cache hit recorded %q %q cached=%v ok=%v", server, localAddr, cached, ok)
	}

	// An exchange that answered replaces the cached answer.
	msg := new(D.Msg)
	msg.SetRcode(msg, D.RcodeSuccess)
	trace.exchangeDial("tcp://10.0.0.53:53", "10.0.0.5:40002")
	trace.exchangeDone("tcp://10.0.0.53:53", "example.test", msg, nil)
	server, localAddr, cached, ok = trace.Result()
	if !ok || cached || server != "tcp://10.0.0.53:53" || localAddr != "10.0.0.5:40002" {
		t.Fatalf("exchange recorded %q %q cached=%v ok=%v", server, localAddr, cached, ok)
	}

	// The cache never replaces an exchange, and only the first exchange counts.
	trace.cacheAnswered(queryAnswer{server: "udp://10.0.0.53:53"})
	trace.exchangeDone("udp://10.0.0.53:53", "example.test", msg, nil)
	if server, _, _, _ = trace.Result(); server != "tcp://10.0.0.53:53" {
		t.Fatalf("later answer recorded %q", server)
	}
}

func TestQueryTraceNoAnswerWithoutExchange(t *testing.T) {
	trace := NewQueryTrace("exit-a")
	if _, _, _, ok := trace.Result(); ok {
		t.Fatal("a fresh trace reports an answer")
	}

	// A failing exchange does not record one either.
	trace.exchangeDone("udp://10.0.0.53:53", "example.test", nil, errors.New("all DNS requests failed"))
	if _, _, _, ok := trace.Result(); ok {
		t.Fatal("a failed exchange recorded an answer")
	}
}

func TestQueryTraceMergedAnswerIsNotCached(t *testing.T) {
	trace := NewQueryTrace("exit-a")
	trace.mergedAnswered(queryAnswer{server: "udp://10.0.0.53:53", localAddr: "10.0.0.5:40001"})
	server, _, cached, ok := trace.Result()
	if !ok || cached || server != "udp://10.0.0.53:53" {
		t.Fatalf("merged answer recorded server %q cached=%v ok=%v", server, cached, ok)
	}
}

func TestQueryTraceNilTraceChangesNothing(t *testing.T) {
	ctx := WithQueryTrace(context.Background(), nil)
	if ctx != context.Background() {
		t.Fatal("attaching a nil trace changed the context")
	}
}

func TestCacheKeepsQueryAnswer(t *testing.T) {
	cache := Config{}.newCache()
	q := D.Question{Name: "example.test.", Qtype: D.TypeA, Qclass: D.ClassINET}
	msg := new(D.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
		A:   net.IPv4(1, 2, 3, 4),
	}}

	// A traced lookup stores how it was answered beside the message.
	trace := NewQueryTrace("exit-a")
	trace.exchangeDone("udp://10.0.0.53:53", "example.test", msg, nil)
	putMsgToCache(WithQueryTrace(context.Background(), trace), cache, q, msg)

	got, answer, _, hit := getMsgFromCache(cache, q)
	if !hit || got == nil {
		t.Fatal("the message was not cached")
	}
	if answer.server != "udp://10.0.0.53:53" {
		t.Fatalf("cached answer is %v, want the exchange's", answer)
	}

	// Without a trace, entries are stored as before, without an answer.
	plain := new(D.Msg)
	plain.SetQuestion(q.Name, q.Qtype)
	plain.Answer = msg.Answer
	other := D.Question{Name: "plain.test.", Qtype: D.TypeA, Qclass: D.ClassINET}
	putMsgToCache(context.Background(), cache, other, plain)
	if _, answer, _, hit := getMsgFromCache(cache, other); !hit || answer.server != "" {
		t.Fatalf("untraced entry recorded %v", answer)
	}
}
