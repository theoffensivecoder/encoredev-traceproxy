package main

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"

	tracepb2 "github.com/theoffensivecoder/traceproxy/internal/trace2proto"
)

// Request span attributes

func requestSpanStartAttrs(req *tracepb2.RequestSpanStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", req.ServiceName),
		attribute.String("http.route", req.EndpointName),
		attribute.String("http.method", req.HttpMethod),
		attribute.String("http.target", req.Path),
	}

	if len(req.PathParams) > 0 {
		attrs = append(attrs, attribute.StringSlice("http.path_params", req.PathParams))
	}

	if req.ExtCorrelationId != nil {
		attrs = append(attrs, attribute.String("trace.correlation_id", *req.ExtCorrelationId))
	}

	if req.Uid != nil && *req.Uid != "" {
		attrs = append(attrs, attribute.String("user.id", *req.Uid))
	}

	if req.Mocked {
		attrs = append(attrs, attribute.Bool("encore.mocked", true))
	}

	return attrs
}

func requestSpanEndAttrs(req *tracepb2.RequestSpanEnd) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Int("http.status_code", int(req.HttpStatusCode)),
	}
}

// Auth span attributes

func authSpanStartAttrs(auth *tracepb2.AuthSpanStart) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("service.name", auth.ServiceName),
		attribute.String("rpc.method", auth.EndpointName),
	}
}

func authSpanEndAttrs(auth *tracepb2.AuthSpanEnd) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", auth.ServiceName),
		attribute.String("rpc.method", auth.EndpointName),
	}
	if auth.Uid != "" {
		attrs = append(attrs, attribute.String("user.id", auth.Uid))
	}
	return attrs
}

// Pubsub message span attributes

func pubsubMessageSpanStartAttrs(msg *tracepb2.PubsubMessageSpanStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", msg.ServiceName),
		attribute.String("messaging.system", "pubsub"),
		attribute.String("messaging.destination", msg.TopicName),
		attribute.String("messaging.operation", "process"),
		attribute.String("messaging.consumer_group.name", msg.SubscriptionName),
		attribute.String("messaging.message_id", msg.MessageId),
		attribute.Int("messaging.message.attempt", int(msg.Attempt)),
	}
	if msg.PublishTime != nil {
		attrs = append(attrs, attribute.String("messaging.publish_time", msg.PublishTime.AsTime().String()))
	}
	return attrs
}

func pubsubMessageSpanEndAttrs(msg *tracepb2.PubsubMessageSpanEnd) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("service.name", msg.ServiceName),
		attribute.String("messaging.destination", msg.TopicName),
		attribute.String("messaging.consumer_group.name", msg.SubscriptionName),
	}
}

// Test span attributes

func testSpanStartAttrs(test *tracepb2.TestSpanStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("service.name", test.ServiceName),
		attribute.String("test.name", test.TestName),
	}
	if test.TestFile != "" {
		attrs = append(attrs, attribute.String("code.filepath", test.TestFile))
	}
	if test.TestLine != 0 {
		attrs = append(attrs, attribute.Int("code.lineno", int(test.TestLine)))
	}
	if test.Uid != "" {
		attrs = append(attrs, attribute.String("test.uid", test.Uid))
	}
	return attrs
}

func testSpanEndAttrs(test *tracepb2.TestSpanEnd) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("service.name", test.ServiceName),
		attribute.String("test.name", test.TestName),
		attribute.Bool("test.failed", test.Failed),
		attribute.Bool("test.skipped", test.Skipped),
	}
}

// RPC call attributes

func rpcCallStartAttrs(rpc *tracepb2.RPCCallStart) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("rpc.system", "encore"),
		attribute.String("rpc.service", rpc.TargetServiceName),
		attribute.String("rpc.method", rpc.TargetEndpointName),
	}
}

// DB query attributes

func dbQueryStartAttrs(query *tracepb2.DBQueryStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("db.system", "postgresql"),
		attribute.String("db.operation", "query"),
	}
	// Truncate long queries
	stmt := query.Query
	if len(stmt) > 1000 {
		stmt = stmt[:1000] + "..."
	}
	attrs = append(attrs, attribute.String("db.statement", stmt))
	return attrs
}

// HTTP call attributes

func httpCallStartAttrs(http *tracepb2.HTTPCallStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("http.method", http.Method),
		attribute.String("http.url", http.Url),
	}

	// Extract host from URL
	if host := extractHost(http.Url); host != "" {
		attrs = append(attrs, attribute.String("server.address", host))
	}

	return attrs
}

// Cache call attributes

func cacheCallStartAttrs(cache *tracepb2.CacheCallStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("db.system", "redis"),
		attribute.String("cache.operation", cache.Operation),
		attribute.Bool("cache.write", cache.Write),
	}
	if len(cache.Keys) > 0 {
		attrs = append(attrs, attribute.StringSlice("cache.keys", cache.Keys))
	}
	return attrs
}

// Pubsub publish attributes

func pubsubPublishStartAttrs(pub *tracepb2.PubsubPublishStart) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("messaging.system", "pubsub"),
		attribute.String("messaging.destination", pub.Topic),
		attribute.String("messaging.operation", "publish"),
	}
}

// Bucket operation attributes

func bucketUploadStartAttrs(upload *tracepb2.BucketObjectUploadStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("storage.bucket", upload.Bucket),
		attribute.String("storage.object", upload.Object),
		attribute.String("storage.operation", "upload"),
	}
	if upload.Attrs != nil {
		if upload.Attrs.Size != nil {
			attrs = append(attrs, attribute.Int64("storage.object.size", int64(*upload.Attrs.Size)))
		}
		if upload.Attrs.ContentType != nil {
			attrs = append(attrs, attribute.String("storage.object.content_type", *upload.Attrs.ContentType))
		}
	}
	return attrs
}

func bucketDownloadStartAttrs(download *tracepb2.BucketObjectDownloadStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("storage.bucket", download.Bucket),
		attribute.String("storage.object", download.Object),
		attribute.String("storage.operation", "download"),
	}
	if download.Version != nil {
		attrs = append(attrs, attribute.String("storage.object.version", *download.Version))
	}
	return attrs
}

func bucketGetAttrsStartAttrs(getAttrs *tracepb2.BucketObjectGetAttrsStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("storage.bucket", getAttrs.Bucket),
		attribute.String("storage.object", getAttrs.Object),
		attribute.String("storage.operation", "get_attrs"),
	}
	if getAttrs.Version != nil {
		attrs = append(attrs, attribute.String("storage.object.version", *getAttrs.Version))
	}
	return attrs
}

func bucketListStartAttrs(list *tracepb2.BucketListObjectsStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("storage.bucket", list.Bucket),
		attribute.String("storage.operation", "list"),
	}
	if list.Prefix != nil {
		attrs = append(attrs, attribute.String("storage.prefix", *list.Prefix))
	}
	return attrs
}

func bucketDeleteStartAttrs(del *tracepb2.BucketDeleteObjectsStart) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("storage.bucket", del.Bucket),
		attribute.String("storage.operation", "delete"),
		attribute.Int("storage.objects_count", len(del.Entries)),
	}
	return attrs
}

// Log message attributes

func logMessageAttrs(log *tracepb2.LogMessage) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("log.level", logLevelToString(log.Level)),
		attribute.String("log.message", log.Msg),
	}

	// Add log fields as attributes
	for _, field := range log.Fields {
		if attr := logFieldToAttribute(field); attr.Key != "" {
			attrs = append(attrs, attr)
		}
	}

	return attrs
}

func logLevelToString(level tracepb2.LogMessage_Level) string {
	switch level {
	case tracepb2.LogMessage_TRACE:
		return "TRACE"
	case tracepb2.LogMessage_DEBUG:
		return "DEBUG"
	case tracepb2.LogMessage_INFO:
		return "INFO"
	case tracepb2.LogMessage_WARN:
		return "WARN"
	case tracepb2.LogMessage_ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

func logFieldToAttribute(field *tracepb2.LogField) attribute.KeyValue {
	key := "log.field." + field.Key

	switch v := field.Value.(type) {
	case *tracepb2.LogField_Str:
		return attribute.String(key, v.Str)
	case *tracepb2.LogField_Bool:
		return attribute.Bool(key, v.Bool)
	case *tracepb2.LogField_Int:
		return attribute.Int64(key, v.Int)
	case *tracepb2.LogField_Uint:
		return attribute.Int64(key, int64(v.Uint))
	case *tracepb2.LogField_Float32:
		return attribute.Float64(key, float64(v.Float32))
	case *tracepb2.LogField_Float64:
		return attribute.Float64(key, v.Float64)
	case *tracepb2.LogField_Dur:
		return attribute.Int64(key, v.Dur)
	case *tracepb2.LogField_Error:
		if v.Error != nil {
			return attribute.String(key, v.Error.Msg)
		}
	case *tracepb2.LogField_Json:
		return attribute.String(key, string(v.Json))
	}

	return attribute.KeyValue{}
}

// Helper functions

func extractHost(url string) string {
	// Simple host extraction from URL
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	if idx := strings.Index(url, "/"); idx > 0 {
		url = url[:idx]
	}
	if idx := strings.Index(url, ":"); idx > 0 {
		url = url[:idx]
	}
	return url
}
