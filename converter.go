package main

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	tracepb2 "github.com/theoffensivecoder/traceproxy/internal/trace2proto"
)

// Converter converts Encore trace events to OTEL spans.
type Converter struct {
	tracer trace.Tracer
}

// NewConverter creates a new converter.
func NewConverter(tracer trace.Tracer) *Converter {
	return &Converter{tracer: tracer}
}

// spanState tracks the state of a span being built.
type spanState struct {
	ctx       context.Context
	span      trace.Span
	startTime time.Time
	traceID   trace.TraceID
	spanID    trace.SpanID
}

// ConvertTrace converts a batch of Encore trace events to OTEL spans.
func (c *Converter) ConvertTrace(ctx context.Context, events []*tracepb2.TraceEvent, meta TraceMetadata) error {
	// Track spans by their span ID for correlation
	spans := make(map[uint64]*spanState)

	// Track child span events by their correlation event ID
	childSpans := make(map[uint64]*spanState)

	// Resource attributes for all spans
	resourceAttrs := []attribute.KeyValue{
		attribute.String("encore.app_id", meta.AppID),
		attribute.String("encore.env_id", meta.EnvID),
		attribute.String("encore.deploy_id", meta.DeployID),
		attribute.String("service.version", meta.AppCommit),
	}

	for _, ev := range events {
		traceID := encoreTraceIDToOTEL(ev.TraceId)
		spanID := encoreSpanIDToOTEL(ev.SpanId)

		switch e := ev.Event.(type) {
		case *tracepb2.TraceEvent_SpanStart:
			state := c.handleSpanStart(ctx, ev, e.SpanStart, traceID, spanID, resourceAttrs)
			if state != nil {
				spans[ev.SpanId] = state
			}

		case *tracepb2.TraceEvent_SpanEnd:
			if state, ok := spans[ev.SpanId]; ok {
				c.handleSpanEnd(state, e.SpanEnd)
				delete(spans, ev.SpanId)
			}

		case *tracepb2.TraceEvent_SpanEvent:
			// Handle span events (child operations)
			parentState := spans[ev.SpanId]
			if parentState == nil {
				continue
			}
			c.handleSpanEvent(parentState, ev, e.SpanEvent, childSpans)
		}
	}

	// End any remaining open spans
	for _, state := range spans {
		state.span.End()
	}

	return nil
}

// handleSpanStart creates a new OTEL span for a span start event.
func (c *Converter) handleSpanStart(ctx context.Context, ev *tracepb2.TraceEvent, start *tracepb2.SpanStart, traceID trace.TraceID, spanID trace.SpanID, resourceAttrs []attribute.KeyValue) *spanState {
	var spanName string
	var spanKind trace.SpanKind
	var attrs []attribute.KeyValue

	// Add resource attributes
	attrs = append(attrs, resourceAttrs...)

	switch data := start.Data.(type) {
	case *tracepb2.SpanStart_Request:
		req := data.Request
		spanName = fmt.Sprintf("%s.%s", req.ServiceName, req.EndpointName)
		spanKind = trace.SpanKindServer
		attrs = append(attrs, requestSpanStartAttrs(req)...)

	case *tracepb2.SpanStart_Auth:
		auth := data.Auth
		spanName = fmt.Sprintf("%s.auth", auth.ServiceName)
		spanKind = trace.SpanKindInternal
		attrs = append(attrs, authSpanStartAttrs(auth)...)

	case *tracepb2.SpanStart_PubsubMessage:
		msg := data.PubsubMessage
		spanName = fmt.Sprintf("%s process", msg.TopicName)
		spanKind = trace.SpanKindConsumer
		attrs = append(attrs, pubsubMessageSpanStartAttrs(msg)...)

	case *tracepb2.SpanStart_Test:
		test := data.Test
		spanName = fmt.Sprintf("test::%s", test.TestName)
		spanKind = trace.SpanKindInternal
		attrs = append(attrs, testSpanStartAttrs(test)...)

	default:
		return nil
	}

	// Set up parent context
	// For root spans, we use a remote span context to establish the trace ID
	// without requiring an actual parent span to exist
	var parentCtx context.Context
	if start.ParentTraceId != nil && start.ParentSpanId != nil {
		// This span has a parent from Encore (e.g., cross-service call)
		parentTraceID := encoreTraceIDToOTEL(start.ParentTraceId)
		parentSpanID := encoreSpanIDToOTEL(*start.ParentSpanId)
		parentSpanCtx := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    parentTraceID,
			SpanID:     parentSpanID,
			TraceFlags: trace.FlagsSampled,
			Remote:     true, // Parent is from another service/trace
		})
		parentCtx = trace.ContextWithSpanContext(ctx, parentSpanCtx)
	} else {
		// Root span - create a remote context just to establish the trace ID
		// The span we create will be the actual root
		rootCtx := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			TraceFlags: trace.FlagsSampled,
			Remote:     true, // Marks this as a remote/virtual parent
		})
		parentCtx = trace.ContextWithSpanContext(ctx, rootCtx)
	}

	startTime := ev.EventTime.AsTime()
	spanCtx2, span := c.tracer.Start(
		parentCtx,
		spanName,
		trace.WithSpanKind(spanKind),
		trace.WithAttributes(attrs...),
		trace.WithTimestamp(startTime),
	)

	return &spanState{
		ctx:       spanCtx2,
		span:      span,
		startTime: startTime,
		traceID:   traceID,
		spanID:    spanID,
	}
}

// handleSpanEnd completes an OTEL span.
func (c *Converter) handleSpanEnd(state *spanState, end *tracepb2.SpanEnd) {
	var attrs []attribute.KeyValue

	switch data := end.Data.(type) {
	case *tracepb2.SpanEnd_Request:
		attrs = requestSpanEndAttrs(data.Request)
	case *tracepb2.SpanEnd_Auth:
		attrs = authSpanEndAttrs(data.Auth)
	case *tracepb2.SpanEnd_PubsubMessage:
		attrs = pubsubMessageSpanEndAttrs(data.PubsubMessage)
	case *tracepb2.SpanEnd_Test:
		attrs = testSpanEndAttrs(data.Test)
	}

	state.span.SetAttributes(attrs...)

	// Set error status if present
	if end.Error != nil {
		state.span.SetStatus(codes.Error, end.Error.Msg)
		state.span.RecordError(fmt.Errorf("%s", end.Error.Msg))
	}

	// End span with duration
	endTime := state.startTime.Add(time.Duration(end.DurationNanos))
	state.span.End(trace.WithTimestamp(endTime))
}

// handleSpanEvent handles span events (child operations within a span).
func (c *Converter) handleSpanEvent(parentState *spanState, ev *tracepb2.TraceEvent, spanEvent *tracepb2.SpanEvent, childSpans map[uint64]*spanState) {
	switch data := spanEvent.Data.(type) {
	case *tracepb2.SpanEvent_RpcCallStart:
		c.handleRPCCallStart(parentState, ev, data.RpcCallStart, childSpans)
	case *tracepb2.SpanEvent_RpcCallEnd:
		c.handleChildSpanEnd(ev, data.RpcCallEnd.Err, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_DbQueryStart:
		c.handleDBQueryStart(parentState, ev, data.DbQueryStart, childSpans)
	case *tracepb2.SpanEvent_DbQueryEnd:
		c.handleChildSpanEnd(ev, data.DbQueryEnd.Err, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_DbTransactionStart:
		c.handleDBTransactionStart(parentState, ev, data.DbTransactionStart, childSpans)
	case *tracepb2.SpanEvent_DbTransactionEnd:
		c.handleDBTransactionEnd(ev, data.DbTransactionEnd, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_HttpCallStart:
		c.handleHTTPCallStart(parentState, ev, data.HttpCallStart, childSpans)
	case *tracepb2.SpanEvent_HttpCallEnd:
		c.handleHTTPCallEnd(ev, data.HttpCallEnd, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_CacheCallStart:
		c.handleCacheCallStart(parentState, ev, data.CacheCallStart, childSpans)
	case *tracepb2.SpanEvent_CacheCallEnd:
		c.handleCacheCallEnd(ev, data.CacheCallEnd, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_PubsubPublishStart:
		c.handlePubsubPublishStart(parentState, ev, data.PubsubPublishStart, childSpans)
	case *tracepb2.SpanEvent_PubsubPublishEnd:
		c.handlePubsubPublishEnd(ev, data.PubsubPublishEnd, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_ServiceInitStart:
		c.handleServiceInitStart(parentState, ev, data.ServiceInitStart, childSpans)
	case *tracepb2.SpanEvent_ServiceInitEnd:
		c.handleChildSpanEnd(ev, data.ServiceInitEnd.Err, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_BucketObjectUploadStart:
		c.handleBucketUploadStart(parentState, ev, data.BucketObjectUploadStart, childSpans)
	case *tracepb2.SpanEvent_BucketObjectUploadEnd:
		c.handleChildSpanEnd(ev, data.BucketObjectUploadEnd.Err, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_BucketObjectDownloadStart:
		c.handleBucketDownloadStart(parentState, ev, data.BucketObjectDownloadStart, childSpans)
	case *tracepb2.SpanEvent_BucketObjectDownloadEnd:
		c.handleChildSpanEnd(ev, data.BucketObjectDownloadEnd.Err, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_BucketObjectGetAttrsStart:
		c.handleBucketGetAttrsStart(parentState, ev, data.BucketObjectGetAttrsStart, childSpans)
	case *tracepb2.SpanEvent_BucketObjectGetAttrsEnd:
		c.handleChildSpanEnd(ev, data.BucketObjectGetAttrsEnd.Err, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_BucketListObjectsStart:
		c.handleBucketListStart(parentState, ev, data.BucketListObjectsStart, childSpans)
	case *tracepb2.SpanEvent_BucketListObjectsEnd:
		c.handleChildSpanEnd(ev, data.BucketListObjectsEnd.Err, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_BucketDeleteObjectsStart:
		c.handleBucketDeleteStart(parentState, ev, data.BucketDeleteObjectsStart, childSpans)
	case *tracepb2.SpanEvent_BucketDeleteObjectsEnd:
		c.handleChildSpanEnd(ev, data.BucketDeleteObjectsEnd.Err, childSpans, spanEvent.CorrelationEventId)

	case *tracepb2.SpanEvent_LogMessage:
		c.handleLogMessage(parentState, ev, data.LogMessage)

	case *tracepb2.SpanEvent_BodyStream:
		c.handleBodyStream(parentState, ev, data.BodyStream)
	}
}

// Child span start handlers

func (c *Converter) handleRPCCallStart(parentState *spanState, ev *tracepb2.TraceEvent, rpc *tracepb2.RPCCallStart, childSpans map[uint64]*spanState) {
	spanName := fmt.Sprintf("%s.%s", rpc.TargetServiceName, rpc.TargetEndpointName)
	attrs := rpcCallStartAttrs(rpc)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

func (c *Converter) handleDBQueryStart(parentState *spanState, ev *tracepb2.TraceEvent, query *tracepb2.DBQueryStart, childSpans map[uint64]*spanState) {
	spanName := "db.query"
	attrs := dbQueryStartAttrs(query)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

func (c *Converter) handleDBTransactionStart(parentState *spanState, ev *tracepb2.TraceEvent, _ *tracepb2.DBTransactionStart, childSpans map[uint64]*spanState) {
	spanName := "db.transaction"
	attrs := []attribute.KeyValue{
		attribute.String("db.operation", "transaction"),
	}
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

func (c *Converter) handleHTTPCallStart(parentState *spanState, ev *tracepb2.TraceEvent, http *tracepb2.HTTPCallStart, childSpans map[uint64]*spanState) {
	spanName := fmt.Sprintf("HTTP %s", http.Method)
	attrs := httpCallStartAttrs(http)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

func (c *Converter) handleCacheCallStart(parentState *spanState, ev *tracepb2.TraceEvent, cache *tracepb2.CacheCallStart, childSpans map[uint64]*spanState) {
	spanName := fmt.Sprintf("cache.%s", cache.Operation)
	attrs := cacheCallStartAttrs(cache)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

func (c *Converter) handlePubsubPublishStart(parentState *spanState, ev *tracepb2.TraceEvent, pub *tracepb2.PubsubPublishStart, childSpans map[uint64]*spanState) {
	spanName := fmt.Sprintf("%s publish", pub.Topic)
	attrs := pubsubPublishStartAttrs(pub)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindProducer, attrs, childSpans)
}

func (c *Converter) handleServiceInitStart(parentState *spanState, ev *tracepb2.TraceEvent, init *tracepb2.ServiceInitStart, childSpans map[uint64]*spanState) {
	spanName := fmt.Sprintf("%s init", init.Service)
	attrs := []attribute.KeyValue{
		attribute.String("service.name", init.Service),
	}
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindInternal, attrs, childSpans)
}

func (c *Converter) handleBucketUploadStart(parentState *spanState, ev *tracepb2.TraceEvent, upload *tracepb2.BucketObjectUploadStart, childSpans map[uint64]*spanState) {
	spanName := "storage.upload"
	attrs := bucketUploadStartAttrs(upload)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

func (c *Converter) handleBucketDownloadStart(parentState *spanState, ev *tracepb2.TraceEvent, download *tracepb2.BucketObjectDownloadStart, childSpans map[uint64]*spanState) {
	spanName := "storage.download"
	attrs := bucketDownloadStartAttrs(download)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

func (c *Converter) handleBucketGetAttrsStart(parentState *spanState, ev *tracepb2.TraceEvent, getAttrs *tracepb2.BucketObjectGetAttrsStart, childSpans map[uint64]*spanState) {
	spanName := "storage.get_attrs"
	attrs := bucketGetAttrsStartAttrs(getAttrs)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

func (c *Converter) handleBucketListStart(parentState *spanState, ev *tracepb2.TraceEvent, list *tracepb2.BucketListObjectsStart, childSpans map[uint64]*spanState) {
	spanName := "storage.list"
	attrs := bucketListStartAttrs(list)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

func (c *Converter) handleBucketDeleteStart(parentState *spanState, ev *tracepb2.TraceEvent, del *tracepb2.BucketDeleteObjectsStart, childSpans map[uint64]*spanState) {
	spanName := "storage.delete"
	attrs := bucketDeleteStartAttrs(del)
	c.startChildSpan(parentState, ev, spanName, trace.SpanKindClient, attrs, childSpans)
}

// startChildSpan creates a child span.
func (c *Converter) startChildSpan(parentState *spanState, ev *tracepb2.TraceEvent, name string, kind trace.SpanKind, attrs []attribute.KeyValue, childSpans map[uint64]*spanState) {
	startTime := ev.EventTime.AsTime()
	_, span := c.tracer.Start(
		parentState.ctx,
		name,
		trace.WithSpanKind(kind),
		trace.WithAttributes(attrs...),
		trace.WithTimestamp(startTime),
	)

	childSpans[ev.EventId] = &spanState{
		span:      span,
		startTime: startTime,
	}
}

// handleChildSpanEnd ends a child span.
func (c *Converter) handleChildSpanEnd(ev *tracepb2.TraceEvent, err *tracepb2.Error, childSpans map[uint64]*spanState, correlationID *uint64) {
	if correlationID == nil {
		return
	}

	state, ok := childSpans[*correlationID]
	if !ok {
		return
	}

	if err != nil {
		state.span.SetStatus(codes.Error, err.Msg)
		state.span.RecordError(fmt.Errorf("%s", err.Msg))
	}

	state.span.End(trace.WithTimestamp(ev.EventTime.AsTime()))
	delete(childSpans, *correlationID)
}

// Specialized end handlers

func (c *Converter) handleDBTransactionEnd(ev *tracepb2.TraceEvent, txEnd *tracepb2.DBTransactionEnd, childSpans map[uint64]*spanState, correlationID *uint64) {
	if correlationID == nil {
		return
	}

	state, ok := childSpans[*correlationID]
	if !ok {
		return
	}

	completion := "rollback"
	if txEnd.Completion == tracepb2.DBTransactionEnd_COMMIT {
		completion = "commit"
	}
	state.span.SetAttributes(attribute.String("db.transaction.result", completion))

	if txEnd.Err != nil {
		state.span.SetStatus(codes.Error, txEnd.Err.Msg)
		state.span.RecordError(fmt.Errorf("%s", txEnd.Err.Msg))
	}

	state.span.End(trace.WithTimestamp(ev.EventTime.AsTime()))
	delete(childSpans, *correlationID)
}

func (c *Converter) handleHTTPCallEnd(ev *tracepb2.TraceEvent, httpEnd *tracepb2.HTTPCallEnd, childSpans map[uint64]*spanState, correlationID *uint64) {
	if correlationID == nil {
		return
	}

	state, ok := childSpans[*correlationID]
	if !ok {
		return
	}

	if httpEnd.StatusCode != nil {
		state.span.SetAttributes(attribute.Int("http.status_code", int(*httpEnd.StatusCode)))
	}

	if httpEnd.Err != nil {
		state.span.SetStatus(codes.Error, httpEnd.Err.Msg)
		state.span.RecordError(fmt.Errorf("%s", httpEnd.Err.Msg))
	}

	// Add HTTP trace events as span events
	for _, httpEv := range httpEnd.TraceEvents {
		c.addHTTPTraceEvent(state.span, httpEv)
	}

	state.span.End(trace.WithTimestamp(ev.EventTime.AsTime()))
	delete(childSpans, *correlationID)
}

func (c *Converter) handleCacheCallEnd(ev *tracepb2.TraceEvent, cacheEnd *tracepb2.CacheCallEnd, childSpans map[uint64]*spanState, correlationID *uint64) {
	if correlationID == nil {
		return
	}

	state, ok := childSpans[*correlationID]
	if !ok {
		return
	}

	result := cacheResultToString(cacheEnd.Result)
	state.span.SetAttributes(attribute.String("cache.result", result))

	if cacheEnd.Err != nil {
		state.span.SetStatus(codes.Error, cacheEnd.Err.Msg)
		state.span.RecordError(fmt.Errorf("%s", cacheEnd.Err.Msg))
	}

	state.span.End(trace.WithTimestamp(ev.EventTime.AsTime()))
	delete(childSpans, *correlationID)
}

func (c *Converter) handlePubsubPublishEnd(ev *tracepb2.TraceEvent, pubEnd *tracepb2.PubsubPublishEnd, childSpans map[uint64]*spanState, correlationID *uint64) {
	if correlationID == nil {
		return
	}

	state, ok := childSpans[*correlationID]
	if !ok {
		return
	}

	if pubEnd.MessageId != nil {
		state.span.SetAttributes(attribute.String("messaging.message_id", *pubEnd.MessageId))
	}

	if pubEnd.Err != nil {
		state.span.SetStatus(codes.Error, pubEnd.Err.Msg)
		state.span.RecordError(fmt.Errorf("%s", pubEnd.Err.Msg))
	}

	state.span.End(trace.WithTimestamp(ev.EventTime.AsTime()))
	delete(childSpans, *correlationID)
}

// handleLogMessage adds a log message as a span event.
func (c *Converter) handleLogMessage(parentState *spanState, ev *tracepb2.TraceEvent, log *tracepb2.LogMessage) {
	attrs := logMessageAttrs(log)
	parentState.span.AddEvent("log", trace.WithTimestamp(ev.EventTime.AsTime()), trace.WithAttributes(attrs...))
}

// handleBodyStream adds a body stream event.
func (c *Converter) handleBodyStream(parentState *spanState, ev *tracepb2.TraceEvent, body *tracepb2.BodyStream) {
	attrs := []attribute.KeyValue{
		attribute.Bool("http.body.is_response", body.IsResponse),
		attribute.Bool("http.body.overflowed", body.Overflowed),
		attribute.Int("http.body.size", len(body.Data)),
	}
	parentState.span.AddEvent("http.body", trace.WithTimestamp(ev.EventTime.AsTime()), trace.WithAttributes(attrs...))
}

// addHTTPTraceEvent adds detailed HTTP trace events as span events.
func (c *Converter) addHTTPTraceEvent(span trace.Span, ev *tracepb2.HTTPTraceEvent) {
	var name string
	var attrs []attribute.KeyValue

	switch data := ev.Data.(type) {
	case *tracepb2.HTTPTraceEvent_DnsStart:
		name = "http.dns.start"
		attrs = append(attrs, attribute.String("dns.host", data.DnsStart.Host))
	case *tracepb2.HTTPTraceEvent_DnsDone:
		name = "http.dns.done"
	case *tracepb2.HTTPTraceEvent_ConnectStart:
		name = "http.connect.start"
		attrs = append(attrs,
			attribute.String("network", data.ConnectStart.Network),
			attribute.String("addr", data.ConnectStart.Addr),
		)
	case *tracepb2.HTTPTraceEvent_ConnectDone:
		name = "http.connect.done"
	case *tracepb2.HTTPTraceEvent_TlsHandshakeStart:
		name = "http.tls.start"
	case *tracepb2.HTTPTraceEvent_TlsHandshakeDone:
		name = "http.tls.done"
		attrs = append(attrs,
			attribute.Int("tls.version", int(data.TlsHandshakeDone.TlsVersion)),
			attribute.String("tls.server_name", data.TlsHandshakeDone.ServerName),
		)
	case *tracepb2.HTTPTraceEvent_WroteHeaders:
		name = "http.wrote_headers"
	case *tracepb2.HTTPTraceEvent_WroteRequest:
		name = "http.wrote_request"
	case *tracepb2.HTTPTraceEvent_GotFirstResponseByte:
		name = "http.first_byte"
	default:
		return
	}

	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// ID conversion helpers

func encoreTraceIDToOTEL(id *tracepb2.TraceID) trace.TraceID {
	if id == nil {
		return trace.TraceID{}
	}
	var traceID trace.TraceID
	// High 8 bytes first (big-endian, most significant)
	for i := 0; i < 8; i++ {
		traceID[i] = byte(id.High >> (56 - i*8))
	}
	// Low 8 bytes (big-endian, least significant)
	for i := 0; i < 8; i++ {
		traceID[8+i] = byte(id.Low >> (56 - i*8))
	}
	return traceID
}

func encoreSpanIDToOTEL(id uint64) trace.SpanID {
	var spanID trace.SpanID
	for i := 0; i < 8; i++ {
		spanID[i] = byte(id >> (56 - i*8))
	}
	return spanID
}

func cacheResultToString(result tracepb2.CacheCallEnd_Result) string {
	switch result {
	case tracepb2.CacheCallEnd_OK:
		return "ok"
	case tracepb2.CacheCallEnd_NO_SUCH_KEY:
		return "no_such_key"
	case tracepb2.CacheCallEnd_CONFLICT:
		return "conflict"
	case tracepb2.CacheCallEnd_ERR:
		return "error"
	default:
		return "unknown"
	}
}
