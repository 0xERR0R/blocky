package log

import (
	"context"
	"log/slog"
)

// contextHandler injects request-scoped attrs stored in the context into each
// emitted record. Because injection happens in Handle (after the level check),
// any slog.LogValuer attrs are resolved only when a record is actually emitted.
//
// If bound is non-nil, attrs are read from it instead of the per-call context.
// This lets WithContext return a logger that injects request fields even when
// the caller uses the non-Context emit methods (logger.Debug/Info/...), which
// slog dispatches with context.Background(). A bound handler replaces (rather
// than wraps) the unbound contextHandler so attrs are never injected twice.
//
// NOTE: WithGroup nests subsequently-added attrs, including the ctx attrs
// injected here, under the group. Do not call WithGroup on a context-aware
// logger if the request fields must stay top-level; none of blocky's hot paths
// do (the only WithGroup users are the handler chain itself).
type contextHandler struct {
	next slog.Handler
	//nolint:containedctx // intentional: holds the request ctx so non-Context emit methods still inject request attrs
	bound context.Context
}

func (h *contextHandler) attrCtx(ctx context.Context) context.Context {
	// A bound handler injects its bound ctx's attrs so the non-Context emit
	// methods (which slog dispatches with context.Background()) still carry the
	// request fields. But when the caller passes a context that itself carries
	// attrs, honor it — never let a stale bound ctx shadow a live request ctx.
	if h.bound != nil && len(attrsFromCtx(ctx)) == 0 {
		return h.bound
	}

	return ctx
}

func (h *contextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(h.attrCtx(ctx), level)
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	ctx = h.attrCtx(ctx)

	if attrs := attrsFromCtx(ctx); len(attrs) > 0 {
		r.AddAttrs(attrs...)
	}

	return h.next.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{next: h.next.WithAttrs(attrs), bound: h.bound}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{next: h.next.WithGroup(name), bound: h.bound}
}

// boundContextHandler returns a contextHandler that injects ctx's attrs, layered
// over h with any pre-existing contextHandler removed so the same attrs are never
// injected twice. It looks through an indentHandler wrapper (the only handler that
// can sit above a contextHandler), so the strip is robust to handler-chain order
// rather than assuming the contextHandler is outermost.
func boundContextHandler(ctx context.Context, h slog.Handler) slog.Handler {
	return &contextHandler{next: stripContextHandler(h), bound: ctx}
}

// stripContextHandler removes a contextHandler from the chain (recursing through a
// single indentHandler), returning the chain without its per-call ctx injection so
// a freshly-bound contextHandler placed above it cannot double-inject.
func stripContextHandler(h slog.Handler) slog.Handler {
	switch v := h.(type) {
	case *contextHandler:
		return v.next
	case *indentHandler:
		return &indentHandler{indent: v.indent, next: stripContextHandler(v.next)}
	default:
		return h
	}
}

// indentHandler prepends a fixed indent string to every record message. Used
// for the startup config dump; not on the hot path.
type indentHandler struct {
	indent string
	next   slog.Handler
}

func (h *indentHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *indentHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Message = h.indent + r.Message

	return h.next.Handle(ctx, r)
}

func (h *indentHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &indentHandler{indent: h.indent, next: h.next.WithAttrs(attrs)}
}

func (h *indentHandler) WithGroup(name string) slog.Handler {
	return &indentHandler{indent: h.indent, next: h.next.WithGroup(name)}
}
