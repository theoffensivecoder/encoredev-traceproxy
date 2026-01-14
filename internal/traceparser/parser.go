package traceparser

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"runtime/debug"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/theoffensivecoder/traceproxy/internal/option"
	tracepb2 "github.com/theoffensivecoder/traceproxy/internal/trace2proto"
	"github.com/theoffensivecoder/traceproxy/internal/tracetypes"
)

// ParseEvent parses a single event from the buffer.
func ParseEvent(buf *bufio.Reader, ta tracetypes.TimeAnchor, version tracetypes.Version) (*tracepb2.TraceEvent, error) {
	tp := &traceParser{traceReader: traceReader{buf: buf, version: version}, ta: ta, log: &log.Logger}
	// If we already have an error, return it.
	if err := tp.Err(); err != nil {
		return nil, err
	}

	typ := tracetypes.EventType(tp.Byte())
	if err := tp.Err(); err != nil {
		return nil, err
	}
	h := header{
		Type:     typ,
		EventID:  tracetypes.EventID(tp.Uint64()),
		Nanotime: tp.Nanotime(),
		TraceID:  tp.traceID(),
		SpanID:   tp.Uint64(),
		Len:      tp.Uint32(),
	}
	if err := tp.Err(); err != nil {
		log.Error().Err(err).Any("header", h).Msgf("failed to parse event header")
		return nil, err
	}

	bytesReadAfterHeader := tp.bytesRead

	ev, err := tp.parseEvent(h)
	if err != nil {
		return nil, fmt.Errorf("parse event %v: %v", h.Type, err)
	}

	err = tp.Err()
	if err == io.EOF {
		// If we have an io.EOF and we've read exactly the right amount of bytes,
		// treat it as a non-error.
		if n := tp.bytesRead - bytesReadAfterHeader; n == int(h.Len) {
			err = io.EOF
		} else if n < int(h.Len) {
			err = io.ErrUnexpectedEOF
		} else {
			err = fmt.Errorf("parser of event %s overflowed event buffer", h.Type)
		}
	}

	if n := tp.bytesRead - bytesReadAfterHeader; n != int(h.Len) {
		log.Info().Msgf("event %s: read %d bytes, expected %d", h.Type, n, h.Len)
	}

	return ev, err
}

type spanStartEvent struct {
	Goid             uint32
	ParentTraceID    option.Option[*tracepb2.TraceID]
	ParentSpanID     option.Option[uint64]
	DefLoc           option.Option[uint32]
	CallerEventID    option.Option[tracetypes.EventID]
	ExtCorrelationID option.Option[string]
}

type spanEndEvent struct {
	DurationNanos uint64
	Err           *tracepb2.Error
	PanicStack    option.Option[*tracepb2.StackTrace]
	ParentTraceID option.Option[*tracepb2.TraceID]
	ParentSpanID  option.Option[uint64]
}

type traceParser struct {
	traceReader
	ta  tracetypes.TimeAnchor
	log *zerolog.Logger
}

type header struct {
	Type    tracetypes.EventType
	EventID tracetypes.EventID

	// TS is a monotonic timestamp in nanoseconds.
	// It can be converted to an actual timestamp using the trace stream's epoch.
	Nanotime int64

	TraceID *tracepb2.TraceID
	SpanID  uint64
	Len     uint32
}

var errUnknownEvent = errors.New("unknown event")

func (tp *traceParser) parseEvent(h header) (ev *tracepb2.TraceEvent, err error) {
	defer func() {
		if r := recover(); r != nil {
			if b, ok := r.(bailout); ok {
				err = b.err
			} else {
				err = fmt.Errorf("panic parsing event: %v\n%s", r, debug.Stack())
			}
		}
	}()

	ev = &tracepb2.TraceEvent{
		TraceId:   h.TraceID,
		SpanId:    h.SpanID,
		EventId:   uint64(h.EventID),
		EventTime: timestamppb.New(tp.ta.ToReal(h.Nanotime)),
	}

	switch h.Type {
	case tracetypes.RequestSpanStart:
		ev.Event = &tracepb2.TraceEvent_SpanStart{SpanStart: tp.requestSpanStart()}
	case tracetypes.RequestSpanEnd:
		ev.Event = &tracepb2.TraceEvent_SpanEnd{SpanEnd: tp.requestSpanEnd()}
	case tracetypes.AuthSpanStart:
		ev.Event = &tracepb2.TraceEvent_SpanStart{SpanStart: tp.authSpanStart()}
	case tracetypes.AuthSpanEnd:
		ev.Event = &tracepb2.TraceEvent_SpanEnd{SpanEnd: tp.authSpanEnd()}
	case tracetypes.PubsubMessageSpanStart:
		ev.Event = &tracepb2.TraceEvent_SpanStart{SpanStart: tp.pubsubMessageSpanStart()}
	case tracetypes.PubsubMessageSpanEnd:
		ev.Event = &tracepb2.TraceEvent_SpanEnd{SpanEnd: tp.pubsubMessageSpanEnd()}
	case tracetypes.TestStart:
		ev.Event = &tracepb2.TraceEvent_SpanStart{SpanStart: tp.testSpanStart()}
	case tracetypes.TestEnd:
		ev.Event = &tracepb2.TraceEvent_SpanEnd{SpanEnd: tp.testSpanEnd()}
	default:
		ev.Event = &tracepb2.TraceEvent_SpanEvent{SpanEvent: tp.spanEvent(h.Type)}
	}

	return ev, nil
}

func (tp *traceParser) spanStartEvent() spanStartEvent {
	goid := uint32(tp.UVarint())
	parentTraceID := tp.traceID()
	parentSpanID := tp.Uint64()
	defLoc := uint32(tp.UVarint())
	callerEventID := tracetypes.EventID(tp.UVarint())
	extCorrelationID := tp.String()

	ev := spanStartEvent{
		Goid:             goid,
		ParentSpanID:     option.AsOptional(parentSpanID),
		DefLoc:           option.AsOptional(defLoc),
		CallerEventID:    option.AsOptional(callerEventID),
		ExtCorrelationID: option.AsOptional(extCorrelationID),
	}
	if !parentTraceID.IsZero() {
		ev.ParentTraceID = option.Some(parentTraceID)
	}
	return ev
}

func (tp *traceParser) spanEndEvent() spanEndEvent {
	dur := tp.Duration()
	if dur < 0 {
		dur = 0
	}
	err := tp.errWithStack()
	panicStack := tp.formattedStack()
	parentTraceID := tp.traceID()
	parentSpanID := tp.Uint64()

	ev := spanEndEvent{
		DurationNanos: uint64(dur),
		Err:           err,
		PanicStack:    option.AsOptional(panicStack),
		ParentSpanID:  option.AsOptional(parentSpanID),
	}
	if !parentTraceID.IsZero() {
		ev.ParentTraceID = option.Some(parentTraceID)
	}
	return ev
}

func (tp *traceParser) spanEvent(eventType tracetypes.EventType) *tracepb2.SpanEvent {
	defLoc := uint32(tp.UVarint())
	goid := uint32(tp.UVarint())
	correlationEventID := tp.EventID()

	ev := &tracepb2.SpanEvent{Goid: goid}
	if defLoc > 0 {
		ev.DefLoc = &defLoc
	}
	if correlationEventID > 0 {
		ev.CorrelationEventId = (*uint64)(&correlationEventID)
	}

	switch eventType {
	case tracetypes.RPCCallStart:
		ev.Data = &tracepb2.SpanEvent_RpcCallStart{RpcCallStart: tp.rpcCallStart()}
	case tracetypes.RPCCallEnd:
		ev.Data = &tracepb2.SpanEvent_RpcCallEnd{RpcCallEnd: tp.rpcCallEnd()}
	case tracetypes.DBQueryStart:
		ev.Data = &tracepb2.SpanEvent_DbQueryStart{DbQueryStart: tp.dbQueryStart()}
	case tracetypes.DBQueryEnd:
		ev.Data = &tracepb2.SpanEvent_DbQueryEnd{DbQueryEnd: tp.dbQueryEnd()}
	case tracetypes.DBTransactionStart:
		ev.Data = &tracepb2.SpanEvent_DbTransactionStart{DbTransactionStart: tp.dbTransactionStart()}
	case tracetypes.DBTransactionEnd:
		ev.Data = &tracepb2.SpanEvent_DbTransactionEnd{DbTransactionEnd: tp.dbTransactionEnd()}
	case tracetypes.PubsubPublishStart:
		ev.Data = &tracepb2.SpanEvent_PubsubPublishStart{PubsubPublishStart: tp.pubsubPublishStart()}
	case tracetypes.PubsubPublishEnd:
		ev.Data = &tracepb2.SpanEvent_PubsubPublishEnd{PubsubPublishEnd: tp.pubsubPublishEnd()}
	case tracetypes.HTTPCallStart:
		ev.Data = &tracepb2.SpanEvent_HttpCallStart{HttpCallStart: tp.httpCallStart()}
	case tracetypes.HTTPCallEnd:
		ev.Data = &tracepb2.SpanEvent_HttpCallEnd{HttpCallEnd: tp.httpCallEnd()}
	case tracetypes.LogMessage:
		ev.Data = &tracepb2.SpanEvent_LogMessage{LogMessage: tp.logMessage()}
	case tracetypes.ServiceInitStart:
		ev.Data = &tracepb2.SpanEvent_ServiceInitStart{ServiceInitStart: tp.serviceInitStart()}
	case tracetypes.ServiceInitEnd:
		ev.Data = &tracepb2.SpanEvent_ServiceInitEnd{ServiceInitEnd: tp.serviceInitEnd()}
	case tracetypes.CacheCallStart:
		ev.Data = &tracepb2.SpanEvent_CacheCallStart{CacheCallStart: tp.cacheCallStart()}
	case tracetypes.CacheCallEnd:
		ev.Data = &tracepb2.SpanEvent_CacheCallEnd{CacheCallEnd: tp.cacheCallEnd()}
	case tracetypes.BodyStream:
		ev.Data = &tracepb2.SpanEvent_BodyStream{BodyStream: tp.bodyStream()}
	case tracetypes.BucketObjectUploadStart:
		ev.Data = &tracepb2.SpanEvent_BucketObjectUploadStart{BucketObjectUploadStart: tp.bucketObjectUploadStart()}
	case tracetypes.BucketObjectUploadEnd:
		ev.Data = &tracepb2.SpanEvent_BucketObjectUploadEnd{BucketObjectUploadEnd: tp.bucketObjectUploadEnd()}
	case tracetypes.BucketObjectDownloadStart:
		ev.Data = &tracepb2.SpanEvent_BucketObjectDownloadStart{BucketObjectDownloadStart: tp.bucketObjectDownloadStart()}
	case tracetypes.BucketObjectDownloadEnd:
		ev.Data = &tracepb2.SpanEvent_BucketObjectDownloadEnd{BucketObjectDownloadEnd: tp.bucketObjectDownloadEnd()}
	case tracetypes.BucketObjectGetAttrsStart:
		ev.Data = &tracepb2.SpanEvent_BucketObjectGetAttrsStart{BucketObjectGetAttrsStart: tp.bucketObjectGetAttrsStart()}
	case tracetypes.BucketObjectGetAttrsEnd:
		ev.Data = &tracepb2.SpanEvent_BucketObjectGetAttrsEnd{BucketObjectGetAttrsEnd: tp.bucketObjectGetAttrsEnd()}
	case tracetypes.BucketListObjectsStart:
		ev.Data = &tracepb2.SpanEvent_BucketListObjectsStart{BucketListObjectsStart: tp.bucketListObjectsStart()}
	case tracetypes.BucketListObjectsEnd:
		ev.Data = &tracepb2.SpanEvent_BucketListObjectsEnd{BucketListObjectsEnd: tp.bucketListObjectsEnd()}
	case tracetypes.BucketDeleteObjectsStart:
		ev.Data = &tracepb2.SpanEvent_BucketDeleteObjectsStart{BucketDeleteObjectsStart: tp.bucketDeleteObjectsStart()}
	case tracetypes.BucketDeleteObjectsEnd:
		ev.Data = &tracepb2.SpanEvent_BucketDeleteObjectsEnd{BucketDeleteObjectsEnd: tp.bucketDeleteObjectsEnd()}

	default:
		tp.bailout(fmt.Errorf("unknown event %v", eventType))
	}

	return ev
}

func (tp *traceParser) requestSpanStart() *tracepb2.SpanStart {
	spanStart := tp.spanStartEvent()

	start := &tracepb2.SpanStart{
		Goid:                  spanStart.Goid,
		ParentTraceId:         spanStart.ParentTraceID.GetOrElse(nil),
		ParentSpanId:          spanStart.ParentSpanID.PtrOrNil(),
		DefLoc:                spanStart.DefLoc.PtrOrNil(),
		CallerEventId:         (*uint64)(spanStart.CallerEventID.PtrOrNil()),
		ExternalCorrelationId: spanStart.ExtCorrelationID.PtrOrNil(),
		Data: &tracepb2.SpanStart_Request{
			Request: &tracepb2.RequestSpanStart{
				ServiceName:  tp.String(),
				EndpointName: tp.String(),
				HttpMethod:   tp.String(),
				Path:         tp.String(),
				PathParams: (func() []string {
					n := tp.UVarint()
					if n == 0 {
						return nil
					}
					params := make([]string, n)
					for i := 0; i < int(n); i++ {
						params[i] = tp.String()
					}
					return params
				})(),
				RequestHeaders:   tp.headers(),
				RequestPayload:   tp.ByteString(),
				ExtCorrelationId: ptrOrNil(tp.String()),
				Uid:              ptrOrNil(tp.String()),
				Mocked:           tp.FromVer(15).Bool(false),
			},
		},
	}

	return start
}

func (tp *traceParser) requestSpanEnd() *tracepb2.SpanEnd {
	spanEnd := tp.spanEndEvent()
	return &tracepb2.SpanEnd{
		DurationNanos: spanEnd.DurationNanos,
		Error:         spanEnd.Err,
		PanicStack:    spanEnd.PanicStack.GetOrElse(nil),
		ParentTraceId: spanEnd.ParentTraceID.GetOrElse(nil),
		ParentSpanId:  spanEnd.ParentSpanID.PtrOrNil(),
		Data: &tracepb2.SpanEnd_Request{
			Request: &tracepb2.RequestSpanEnd{
				ServiceName:     tp.String(),
				EndpointName:    tp.String(),
				HttpStatusCode:  uint32(tp.UVarint()),
				ResponseHeaders: tp.headers(),
				ResponsePayload: tp.ByteString(),
			},
		},
	}
}

func (tp *traceParser) authSpanStart() *tracepb2.SpanStart {
	spanStart := tp.spanStartEvent()

	return &tracepb2.SpanStart{
		Goid:                  spanStart.Goid,
		ParentTraceId:         spanStart.ParentTraceID.GetOrElse(nil),
		ParentSpanId:          spanStart.ParentSpanID.PtrOrNil(),
		DefLoc:                spanStart.DefLoc.PtrOrNil(),
		CallerEventId:         (*uint64)(spanStart.CallerEventID.PtrOrNil()),
		ExternalCorrelationId: spanStart.ExtCorrelationID.PtrOrNil(),
		Data: &tracepb2.SpanStart_Auth{
			Auth: &tracepb2.AuthSpanStart{
				ServiceName:  tp.String(),
				EndpointName: tp.String(),
				AuthPayload:  tp.ByteString(),
			},
		},
	}
}

func (tp *traceParser) authSpanEnd() *tracepb2.SpanEnd {
	spanEnd := tp.spanEndEvent()
	return &tracepb2.SpanEnd{
		DurationNanos: spanEnd.DurationNanos,
		Error:         spanEnd.Err,
		PanicStack:    spanEnd.PanicStack.GetOrElse(nil),
		ParentTraceId: spanEnd.ParentTraceID.GetOrElse(nil),
		ParentSpanId:  spanEnd.ParentSpanID.PtrOrNil(),
		Data: &tracepb2.SpanEnd_Auth{
			Auth: &tracepb2.AuthSpanEnd{
				ServiceName:  tp.String(),
				EndpointName: tp.String(),
				Uid:          tp.String(),
				UserData:     tp.ByteString(),
			},
		},
	}
}

func (tp *traceParser) pubsubMessageSpanStart() *tracepb2.SpanStart {
	spanStart := tp.spanStartEvent()

	return &tracepb2.SpanStart{
		Goid:                  spanStart.Goid,
		ParentTraceId:         spanStart.ParentTraceID.GetOrElse(nil),
		ParentSpanId:          spanStart.ParentSpanID.PtrOrNil(),
		DefLoc:                spanStart.DefLoc.PtrOrNil(),
		CallerEventId:         (*uint64)(spanStart.CallerEventID.PtrOrNil()),
		ExternalCorrelationId: spanStart.ExtCorrelationID.PtrOrNil(),
		Data: &tracepb2.SpanStart_PubsubMessage{
			PubsubMessage: &tracepb2.PubsubMessageSpanStart{
				ServiceName:      tp.String(),
				TopicName:        tp.String(),
				SubscriptionName: tp.String(),
				MessageId:        tp.String(),
				Attempt:          uint32(tp.UVarint()),
				PublishTime:      tp.Time(), // TODO use nanotime
				MessagePayload:   tp.ByteString(),
			},
		},
	}
}

func (tp *traceParser) pubsubMessageSpanEnd() *tracepb2.SpanEnd {
	spanEnd := tp.spanEndEvent()
	return &tracepb2.SpanEnd{
		DurationNanos: spanEnd.DurationNanos,
		Error:         spanEnd.Err,
		PanicStack:    spanEnd.PanicStack.GetOrElse(nil),
		ParentTraceId: spanEnd.ParentTraceID.GetOrElse(nil),
		ParentSpanId:  spanEnd.ParentSpanID.PtrOrNil(),
		Data: &tracepb2.SpanEnd_PubsubMessage{
			PubsubMessage: &tracepb2.PubsubMessageSpanEnd{
				ServiceName:      tp.String(),
				TopicName:        tp.String(),
				SubscriptionName: tp.String(),
			},
		},
	}
}

func (tp *traceParser) testSpanStart() *tracepb2.SpanStart {
	spanStart := tp.spanStartEvent()

	return &tracepb2.SpanStart{
		Goid:                  spanStart.Goid,
		ParentTraceId:         spanStart.ParentTraceID.GetOrElse(nil),
		ParentSpanId:          spanStart.ParentSpanID.PtrOrNil(),
		DefLoc:                spanStart.DefLoc.PtrOrNil(),
		CallerEventId:         (*uint64)(spanStart.CallerEventID.PtrOrNil()),
		ExternalCorrelationId: spanStart.ExtCorrelationID.PtrOrNil(),
		Data: &tracepb2.SpanStart_Test{
			Test: &tracepb2.TestSpanStart{
				ServiceName: tp.String(),
				TestName:    tp.String(),
				Uid:         tp.String(),
				TestFile:    tp.String(),
				TestLine:    tp.Uint32(),
			},
		},
	}
}

func (tp *traceParser) testSpanEnd() *tracepb2.SpanEnd {
	spanEnd := tp.spanEndEvent()
	return &tracepb2.SpanEnd{
		DurationNanos: spanEnd.DurationNanos,
		Error:         spanEnd.Err,
		PanicStack:    spanEnd.PanicStack.GetOrElse(nil),
		ParentTraceId: spanEnd.ParentTraceID.GetOrElse(nil),
		ParentSpanId:  spanEnd.ParentSpanID.PtrOrNil(),
		Data: &tracepb2.SpanEnd_Test{
			Test: &tracepb2.TestSpanEnd{
				ServiceName: tp.String(),
				TestName:    tp.String(),
				Failed:      tp.Bool(),
				Skipped:     tp.Bool(),
			},
		},
	}
}

func (tp *traceParser) rpcCallStart() *tracepb2.RPCCallStart {
	return &tracepb2.RPCCallStart{
		TargetServiceName:  tp.String(),
		TargetEndpointName: tp.String(),
		Stack:              tp.stack(),
	}
}

func (tp *traceParser) rpcCallEnd() *tracepb2.RPCCallEnd {
	return &tracepb2.RPCCallEnd{
		Err: tp.errWithStack(),
	}
}

func (tp *traceParser) dbQueryStart() *tracepb2.DBQueryStart {
	return &tracepb2.DBQueryStart{
		Query: tp.String(),
		Stack: tp.stack(),
	}
}

func (tp *traceParser) dbQueryEnd() *tracepb2.DBQueryEnd {
	return &tracepb2.DBQueryEnd{
		Err: tp.errWithStack(),
	}
}

func (tp *traceParser) dbTransactionStart() *tracepb2.DBTransactionStart {
	return &tracepb2.DBTransactionStart{
		Stack: tp.stack(),
	}
}

func (tp *traceParser) dbTransactionEnd() *tracepb2.DBTransactionEnd {
	return &tracepb2.DBTransactionEnd{
		Completion: (func() tracepb2.DBTransactionEnd_CompletionType {
			if commit := tp.Bool(); commit {
				return tracepb2.DBTransactionEnd_COMMIT
			} else {
				return tracepb2.DBTransactionEnd_ROLLBACK
			}
		})(),
		Stack: tp.stack(),
		Err:   tp.errWithStack(),
	}
}

func (tp *traceParser) pubsubPublishStart() *tracepb2.PubsubPublishStart {
	return &tracepb2.PubsubPublishStart{
		Topic:   tp.String(),
		Message: tp.ByteString(),
		Stack:   tp.stack(),
	}
}

func (tp *traceParser) pubsubPublishEnd() *tracepb2.PubsubPublishEnd {
	return &tracepb2.PubsubPublishEnd{
		MessageId: ptrOrNil(tp.String()),
		Err:       tp.errWithStack(),
	}
}

func (tp *traceParser) serviceInitStart() *tracepb2.ServiceInitStart {
	return &tracepb2.ServiceInitStart{
		Service: tp.String(),
	}
}

func (tp *traceParser) serviceInitEnd() *tracepb2.ServiceInitEnd {
	return &tracepb2.ServiceInitEnd{
		Err: tp.errWithStack(),
	}
}

func (tp *traceParser) httpCallStart() *tracepb2.HTTPCallStart {
	return &tracepb2.HTTPCallStart{
		CorrelationParentSpanId: tp.Uint64(),
		Method:                  tp.String(),
		Url:                     tp.String(),
		Stack:                   tp.stack(),
		StartNanotime:           tp.Int64(),
	}
}

func (tp *traceParser) httpCallEnd() *tracepb2.HTTPCallEnd {
	return &tracepb2.HTTPCallEnd{
		StatusCode: ptrOrNil(uint32(tp.UVarint())),
		Err:        tp.errWithStack(),
		TraceEvents: (func() []*tracepb2.HTTPTraceEvent {
			n := tp.UVarint()
			events := make([]*tracepb2.HTTPTraceEvent, 0, n)
			for i := 0; i < int(n); i++ {
				if ev := tp.httpEvent(); ev != nil {
					events = append(events, ev)
				}
			}
			return events
		})(),
	}
}

func (tp *traceParser) cacheCallStart() *tracepb2.CacheCallStart {
	return &tracepb2.CacheCallStart{
		Operation: tp.String(),
		Write:     tp.Bool(),
		Stack:     tp.stack(),
		Keys: (func() []string {
			n := tp.UVarint()
			keys := make([]string, n)
			for i := 0; i < int(n); i++ {
				keys[i] = tp.String()
			}
			return keys
		})(),
	}
}

func (tp *traceParser) cacheCallEnd() *tracepb2.CacheCallEnd {
	return &tracepb2.CacheCallEnd{
		Result: (func() tracepb2.CacheCallEnd_Result {
			res := tp.Byte()
			switch tracetypes.CacheCallResult(res) {
			case tracetypes.CacheOK:
				return tracepb2.CacheCallEnd_OK
			case tracetypes.CacheNoSuchKey:
				return tracepb2.CacheCallEnd_NO_SUCH_KEY
			case tracetypes.CacheConflict:
				return tracepb2.CacheCallEnd_CONFLICT
			case tracetypes.CacheErr:
				return tracepb2.CacheCallEnd_ERR
			default:
				return tracepb2.CacheCallEnd_UNKNOWN
			}
		})(),
		Err: tp.errWithStack(),
	}
}

func (tp *traceParser) bucketObjectUploadStart() *tracepb2.BucketObjectUploadStart {
	return &tracepb2.BucketObjectUploadStart{
		Bucket: tp.String(),
		Object: tp.String(),
		Attrs:  tp.bucketObjectAttrs(),
		Stack:  tp.stack(),
	}
}

func (tp *traceParser) bucketObjectAttrs() *tracepb2.BucketObjectAttributes {
	return &tracepb2.BucketObjectAttributes{
		Size:        tp.OptUVarint(),
		Version:     tp.OptString(),
		Etag:        tp.OptString(),
		ContentType: tp.OptString(),
	}
}

func (tp *traceParser) bucketObjectUploadEnd() *tracepb2.BucketObjectUploadEnd {
	return &tracepb2.BucketObjectUploadEnd{
		Size:    tp.OptUVarint(),
		Version: tp.OptString(),
		Err:     tp.errWithStack(),
	}
}

func (tp *traceParser) bucketObjectDownloadStart() *tracepb2.BucketObjectDownloadStart {
	return &tracepb2.BucketObjectDownloadStart{
		Bucket:  tp.String(),
		Object:  tp.String(),
		Version: tp.OptString(),
		Stack:   tp.stack(),
	}
}

func (tp *traceParser) bucketObjectDownloadEnd() *tracepb2.BucketObjectDownloadEnd {
	return &tracepb2.BucketObjectDownloadEnd{
		Size: tp.OptUVarint(),
		Err:  tp.errWithStack(),
	}
}

func (tp *traceParser) bucketDeleteObjectsStart() *tracepb2.BucketDeleteObjectsStart {
	ev := &tracepb2.BucketDeleteObjectsStart{
		Bucket: tp.String(),
		Stack:  tp.stack(),
	}

	num := tp.UVarint()
	for i := 0; i < int(num); i++ {
		ev.Entries = append(ev.Entries, &tracepb2.BucketDeleteObjectEntry{
			Object:  tp.String(),
			Version: tp.OptString(),
		})
	}

	return ev
}

func (tp *traceParser) bucketDeleteObjectsEnd() *tracepb2.BucketDeleteObjectsEnd {
	return &tracepb2.BucketDeleteObjectsEnd{
		Err: tp.errWithStack(),
	}
}

func (tp *traceParser) bucketListObjectsStart() *tracepb2.BucketListObjectsStart {
	return &tracepb2.BucketListObjectsStart{
		Bucket: tp.String(),
		Prefix: tp.OptString(),
		Stack:  tp.stack(),
	}
}

func (tp *traceParser) bucketListObjectsEnd() *tracepb2.BucketListObjectsEnd {
	return &tracepb2.BucketListObjectsEnd{
		Err:      tp.errWithStack(),
		Observed: tp.UVarint(),
		HasMore:  tp.Bool(),
	}
}

func (tp *traceParser) bucketObjectGetAttrsStart() *tracepb2.BucketObjectGetAttrsStart {
	return &tracepb2.BucketObjectGetAttrsStart{
		Bucket:  tp.String(),
		Object:  tp.String(),
		Version: tp.OptString(),
		Stack:   tp.stack(),
	}
}

func (tp *traceParser) bucketObjectGetAttrsEnd() *tracepb2.BucketObjectGetAttrsEnd {
	ev := &tracepb2.BucketObjectGetAttrsEnd{
		Err: tp.errWithStack(),
	}

	if ev.Err == nil {
		ev.Attrs = tp.bucketObjectAttrs()
	}

	return ev
}

func (tp *traceParser) bodyStream() *tracepb2.BodyStream {
	flags := tp.Byte()
	data := tp.ByteString()
	return &tracepb2.BodyStream{
		IsResponse: flags&0b01 == 0b01,
		Overflowed: flags&0b10 == 0b10,
		Data:       data,
	}
}

func (tp *traceParser) headers() map[string]string {
	n := tp.UVarint()
	if n == 0 {
		return nil
	}
	headers := make(map[string]string, n)
	for i := 0; i < int(n); i++ {
		headers[tp.String()] = tp.String()
	}
	return headers
}

func (tp *traceParser) httpEvent() *tracepb2.HTTPTraceEvent {
	code := tracetypes.HTTPEventCode(tp.Byte())
	ev := &tracepb2.HTTPTraceEvent{
		Nanotime: tp.Int64(),
	}

	switch code {
	case tracetypes.GetConn:
		ev.Data = &tracepb2.HTTPTraceEvent_GetConn{
			GetConn: &tracepb2.HTTPGetConn{
				HostPort: tp.String(),
			},
		}

	case tracetypes.GotConn:
		ev.Data = &tracepb2.HTTPTraceEvent_GotConn{
			GotConn: &tracepb2.HTTPGotConn{
				Reused:         tp.Bool(),
				WasIdle:        tp.Bool(),
				IdleDurationNs: tp.Int64(),
			},
		}

	case tracetypes.GotFirstResponseByte:
		ev.Data = &tracepb2.HTTPTraceEvent_GotFirstResponseByte{
			GotFirstResponseByte: &tracepb2.HTTPGotFirstResponseByte{
				// No data
			},
		}

	case tracetypes.Got1xxResponse:
		ev.Data = &tracepb2.HTTPTraceEvent_Got_1XxResponse{
			Got_1XxResponse: &tracepb2.HTTPGot1XxResponse{
				Code: int32(tp.Varint()),
			},
		}

	case tracetypes.DNSStart:
		ev.Data = &tracepb2.HTTPTraceEvent_DnsStart{
			DnsStart: &tracepb2.HTTPDNSStart{
				Host: tp.String(),
			},
		}

	case tracetypes.DNSDone:
		data := &tracepb2.HTTPDNSDone{
			Err: tp.ByteString(),
		}
		addrs := int(tp.UVarint())
		for j := 0; j < addrs; j++ {
			data.Addrs = append(data.Addrs, &tracepb2.DNSAddr{
				Ip: tp.ByteString(),
			})
		}
		ev.Data = &tracepb2.HTTPTraceEvent_DnsDone{DnsDone: data}

	case tracetypes.ConnectStart:
		ev.Data = &tracepb2.HTTPTraceEvent_ConnectStart{
			ConnectStart: &tracepb2.HTTPConnectStart{
				Network: tp.String(),
				Addr:    tp.String(),
			},
		}

	case tracetypes.ConnectDone:
		ev.Data = &tracepb2.HTTPTraceEvent_ConnectDone{
			ConnectDone: &tracepb2.HTTPConnectDone{
				Network: tp.String(),
				Addr:    tp.String(),
				Err:     tp.ByteString(),
			},
		}

	case tracetypes.TLSHandshakeStart:
		ev.Data = &tracepb2.HTTPTraceEvent_TlsHandshakeStart{
			TlsHandshakeStart: &tracepb2.HTTPTLSHandshakeStart{
				// No data
			},
		}

	case tracetypes.TLSHandshakeDone:
		ev.Data = &tracepb2.HTTPTraceEvent_TlsHandshakeDone{
			TlsHandshakeDone: &tracepb2.HTTPTLSHandshakeDone{
				Err:                tp.ByteString(),
				TlsVersion:         tp.Uint32(),
				CipherSuite:        tp.Uint32(),
				ServerName:         tp.String(),
				NegotiatedProtocol: tp.String(),
			},
		}

	case tracetypes.WroteHeaders:
		ev.Data = &tracepb2.HTTPTraceEvent_WroteHeaders{
			WroteHeaders: &tracepb2.HTTPWroteHeaders{
				// No data
			},
		}

	case tracetypes.WroteRequest:
		ev.Data = &tracepb2.HTTPTraceEvent_WroteRequest{
			WroteRequest: &tracepb2.HTTPWroteRequest{
				Err: tp.ByteString(),
			},
		}

	case tracetypes.Wait100Continue:
		// no data
		ev.Data = &tracepb2.HTTPTraceEvent_Wait_100Continue{
			Wait_100Continue: &tracepb2.HTTPWait100Continue{
				// No data
			},
		}

	case tracetypes.ClosedBody:
		ev.Data = &tracepb2.HTTPTraceEvent_ClosedBody{
			ClosedBody: &tracepb2.HTTPClosedBodyData{
				Err: tp.ByteString(),
			},
		}

	default:
		// TODO bailout
		tp.log.Error().Int32("code", int32(code)).Msg("unknown http event code")
		return nil
	}
	return ev
}

func (tp *traceParser) logMessage() *tracepb2.LogMessage {
	return &tracepb2.LogMessage{
		Level: (func() tracepb2.LogMessage_Level {
			switch tracetypes.LogLevel(tp.Byte()) {
			case tracetypes.LevelTrace:
				return tracepb2.LogMessage_TRACE
			case tracetypes.LevelDebug:
				return tracepb2.LogMessage_DEBUG
			case tracetypes.LevelInfo:
				return tracepb2.LogMessage_INFO
			case tracetypes.LevelWarn:
				return tracepb2.LogMessage_WARN
			case tracetypes.LevelError:
				return tracepb2.LogMessage_ERROR
			default:
				return tracepb2.LogMessage_TRACE
			}
		})(),
		Msg: tp.String(),
		Fields: (func() []*tracepb2.LogField {
			n := int(tp.UVarint())
			if n > 64 {
				// TODO bailout
			}
			fields := make([]*tracepb2.LogField, 0, n)
			for i := 0; i < n; i++ {
				fields = append(fields, tp.logField())
			}
			return fields
		})(),
		Stack: tp.stack(),
	}
}

func (tp *traceParser) logField() *tracepb2.LogField {
	typ := tracetypes.LogFieldType(tp.Byte())
	f := &tracepb2.LogField{
		Key: tp.String(),
	}
	switch typ {
	case tracetypes.ErrField:
		f.Value = &tracepb2.LogField_Error{Error: tp.errWithStack()}
	case tracetypes.StringField:
		f.Value = &tracepb2.LogField_Str{Str: tp.String()}
	case tracetypes.BoolField:
		f.Value = &tracepb2.LogField_Bool{Bool: tp.Bool()}
	case tracetypes.TimeField:
		f.Value = &tracepb2.LogField_Time{Time: tp.Time()}
	case tracetypes.DurationField:
		f.Value = &tracepb2.LogField_Dur{Dur: tp.Int64()}
	case tracetypes.UUIDField:
		b := make([]byte, 16)
		tp.Bytes(b)
		f.Value = &tracepb2.LogField_Uuid{Uuid: b}
	case tracetypes.JSONField:
		val := tp.ByteString()
		err := tp.errWithStack()
		if err != nil {
			f.Value = &tracepb2.LogField_Error{Error: err}
		} else {
			f.Value = &tracepb2.LogField_Json{Json: val}
		}
	case tracetypes.IntField:
		f.Value = &tracepb2.LogField_Int{Int: tp.Varint()}
	case tracetypes.UintField:
		f.Value = &tracepb2.LogField_Uint{Uint: tp.UVarint()}
	case tracetypes.Float32Field:
		f.Value = &tracepb2.LogField_Float32{Float32: tp.Float32()}
	case tracetypes.Float64Field:
		f.Value = &tracepb2.LogField_Float64{Float64: tp.Float64()}
	default:
		// TODO bailout
		tp.log.Error().Msgf("unknown log field type %v", typ)
		return nil
	}
	return f
}

func (tp *traceParser) stack() *tracepb2.StackTrace {
	n := int(tp.Byte())
	if n == 0 {
		return nil
	}

	tr := &tracepb2.StackTrace{}
	diffs := make([]int64, n)
	for i := 0; i < n; i++ {
		diff := tp.Varint()
		diffs[i] = diff
	}
	tr.Pcs = diffs

	prev := int64(0)

	pcs := make([]uint64, n)
	for i := 0; i < n; i++ {
		x := prev + diffs[i]
		prev = x
		pcs[i] = uint64(x)
	}

	return tr
}

func (tp *traceParser) formattedStack() *tracepb2.StackTrace {
	n := int(tp.Byte())
	if n == 0 {
		return nil
	}

	tr := &tracepb2.StackTrace{
		Frames: make([]*tracepb2.StackFrame, n),
	}

	for i := 0; i < n; i++ {
		tr.Frames[i] = &tracepb2.StackFrame{
			Filename: tp.String(),
			Line:     int32(tp.UVarint()),
			Func:     tp.String(),
		}
	}

	return tr
}

// errWithStack parses an error with stack information.
func (tp *traceParser) errWithStack() *tracepb2.Error {
	msg := tp.String()
	if len(msg) == 0 {
		return nil
	}
	stack := tp.stack()
	return &tracepb2.Error{
		Msg:   msg,
		Stack: stack,
	}
}

func (tp *traceParser) traceID() *tracepb2.TraceID {
	var traceID [16]byte
	tp.Bytes(traceID[:])
	return &tracepb2.TraceID{
		Low:  bin.Uint64(traceID[:8]),
		High: bin.Uint64(traceID[8:]),
	}
}

func (tp *traceParser) spanID() uint64 {
	var spanID [8]byte
	tp.Bytes(spanID[:])
	return bin.Uint64(spanID[:])
}

type bailout struct {
	err error
}

func (tp *traceParser) bailout(err error) {
	panic(bailout{err: err})
}
