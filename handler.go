package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/trace"

	tracepb2 "github.com/theoffensivecoder/traceproxy/internal/trace2proto"
	"github.com/theoffensivecoder/traceproxy/internal/tracetypes"

	"github.com/theoffensivecoder/traceproxy/internal/traceparser"
)

const (
	headerTraceVersion = "X-Encore-Trace-Version"
	headerTimeAnchor   = "X-Encore-Trace-TimeAnchor"
	headerAppID        = "X-Encore-App-ID"
	headerEnvID        = "X-Encore-Env-ID"
	headerDeployID     = "X-Encore-Deploy-ID"
	headerAppCommit    = "X-Encore-App-Commit"
)

// TraceMetadata contains metadata from the trace request headers.
type TraceMetadata struct {
	AppID     string
	EnvID     string
	DeployID  string
	AppCommit string
}

// Handler handles incoming trace requests.
type Handler struct {
	tracer    trace.Tracer
	converter *Converter
	logger    *slog.Logger
}

// NewHandler creates a new trace handler.
func NewHandler(tracer trace.Tracer, logger *slog.Logger) *Handler {
	return &Handler{
		tracer:    tracer,
		converter: NewConverter(tracer),
		logger:    logger,
	}
}

// ServeHTTP handles incoming trace POST requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse trace version
	version := r.Header.Get(headerTraceVersion)
	if version != "15" {
		h.logger.Warn("unsupported trace version", "version", version)
		http.Error(w, fmt.Sprintf("unsupported trace version: %s", version), http.StatusBadRequest)
		return
	}

	// Parse time anchor
	var ta tracetypes.TimeAnchor
	if anchor := r.Header.Get(headerTimeAnchor); anchor != "" {
		if err := ta.UnmarshalText([]byte(anchor)); err != nil {
			h.logger.Error("failed to parse time anchor", "error", err)
			http.Error(w, "invalid time anchor", http.StatusBadRequest)
			return
		}
	}

	// Extract metadata
	meta := TraceMetadata{
		AppID:     r.Header.Get(headerAppID),
		EnvID:     r.Header.Get(headerEnvID),
		DeployID:  r.Header.Get(headerDeployID),
		AppCommit: r.Header.Get(headerAppCommit),
	}

	// Process the trace
	if err := h.processTrace(r.Context(), r.Body, ta, meta); err != nil {
		h.logger.Error("failed to process trace", "error", err)
		http.Error(w, "failed to process trace", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// processTrace reads and converts trace events from the request body.
func (h *Handler) processTrace(ctx context.Context, body io.Reader, ta tracetypes.TimeAnchor, meta TraceMetadata) error {
	buf := bufio.NewReader(body)

	var events []*tracepb2.TraceEvent

	// Parse all events from the stream
	for {
		ev, err := traceparser.ParseEvent(buf, ta, tracetypes.CurrentVersion)
		if err == io.EOF {
			break
		}
		if err != nil {
			h.logger.Warn("failed to parse event", "error", err)
			// Continue parsing remaining events
			continue
		}
		events = append(events, ev)
	}

	h.logger.Info("received trace", "events", len(events), "app_id", meta.AppID)

	// Convert and export events
	if len(events) > 0 {
		if err := h.converter.ConvertTrace(ctx, events, meta); err != nil {
			return fmt.Errorf("convert trace: %w", err)
		}
	}

	return nil
}
