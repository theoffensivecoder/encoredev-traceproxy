// Package tracetypes contains type definitions extracted from encore.dev
// for parsing Encore trace data. These are stable wire protocol types.
package tracetypes

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Version represents the trace protocol version.
type Version int

// CurrentVersion is the trace protocol version this package produces traces in.
const CurrentVersion Version = 15

// EventID is a unique identifier for a trace event within a trace.
type EventID uint64

// EventType represents the type of trace event.
type EventType byte

const (
	RequestSpanStart          EventType = 0x01
	RequestSpanEnd            EventType = 0x02
	AuthSpanStart             EventType = 0x03
	AuthSpanEnd               EventType = 0x04
	PubsubMessageSpanStart    EventType = 0x05
	PubsubMessageSpanEnd      EventType = 0x06
	DBTransactionStart        EventType = 0x07
	DBTransactionEnd          EventType = 0x08
	DBQueryStart              EventType = 0x09
	DBQueryEnd                EventType = 0x0A
	RPCCallStart              EventType = 0x0B
	RPCCallEnd                EventType = 0x0C
	HTTPCallStart             EventType = 0x0D
	HTTPCallEnd               EventType = 0x0E
	LogMessage                EventType = 0x0F
	PubsubPublishStart        EventType = 0x10
	PubsubPublishEnd          EventType = 0x11
	ServiceInitStart          EventType = 0x12
	ServiceInitEnd            EventType = 0x13
	CacheCallStart            EventType = 0x14
	CacheCallEnd              EventType = 0x15
	BodyStream                EventType = 0x16
	TestStart                 EventType = 0x17
	TestEnd                   EventType = 0x18
	BucketObjectUploadStart   EventType = 0x19
	BucketObjectUploadEnd     EventType = 0x1A
	BucketObjectDownloadStart EventType = 0x1B
	BucketObjectDownloadEnd   EventType = 0x1C
	BucketObjectGetAttrsStart EventType = 0x1D
	BucketObjectGetAttrsEnd   EventType = 0x1E
	BucketListObjectsStart    EventType = 0x1F
	BucketListObjectsEnd      EventType = 0x20
	BucketDeleteObjectsStart  EventType = 0x21
	BucketDeleteObjectsEnd    EventType = 0x22
)

func (te EventType) String() string {
	switch te {
	case RequestSpanStart:
		return "RequestSpanStart"
	case RequestSpanEnd:
		return "RequestSpanEnd"
	case AuthSpanStart:
		return "AuthSpanStart"
	case AuthSpanEnd:
		return "AuthSpanEnd"
	case PubsubMessageSpanStart:
		return "PubsubMessageSpanStart"
	case PubsubMessageSpanEnd:
		return "PubsubMessageSpanEnd"
	case DBTransactionStart:
		return "DBTransactionStart"
	case DBTransactionEnd:
		return "DBTransactionEnd"
	case DBQueryStart:
		return "QueryStart"
	case DBQueryEnd:
		return "QueryEnd"
	case RPCCallStart:
		return "RPCCallStart"
	case RPCCallEnd:
		return "RPCCallEnd"
	case HTTPCallStart:
		return "HTTPCallStart"
	case HTTPCallEnd:
		return "HTTPCallEnd"
	case LogMessage:
		return "LogMessage"
	case PubsubPublishStart:
		return "PubsubPublishStart"
	case PubsubPublishEnd:
		return "PubsubPublishEnd"
	case ServiceInitStart:
		return "ServiceInitStart"
	case ServiceInitEnd:
		return "ServiceInitEnd"
	case CacheCallStart:
		return "CacheCallStart"
	case CacheCallEnd:
		return "CacheCallEnd"
	case BodyStream:
		return "BodyStream"
	case TestStart:
		return "TestStart"
	case TestEnd:
		return "TestEnd"
	case BucketObjectUploadStart:
		return "BucketObjectUploadStart"
	case BucketObjectUploadEnd:
		return "BucketObjectUploadEnd"
	case BucketObjectDownloadStart:
		return "BucketObjectDownloadStart"
	case BucketObjectDownloadEnd:
		return "BucketObjectDownloadEnd"
	case BucketObjectGetAttrsStart:
		return "BucketObjectGetAttrsStart"
	case BucketObjectGetAttrsEnd:
		return "BucketObjectGetAttrsEnd"
	case BucketListObjectsStart:
		return "BucketListObjectsStart"
	case BucketListObjectsEnd:
		return "BucketListObjectsEnd"
	case BucketDeleteObjectsStart:
		return "BucketDeleteObjectsStart"
	case BucketDeleteObjectsEnd:
		return "BucketDeleteObjectsEnd"
	default:
		return fmt.Sprintf("Unknown(%x)", byte(te))
	}
}

// HTTPEventCode represents HTTP trace event codes.
type HTTPEventCode byte

const (
	GetConn              HTTPEventCode = 1
	GotConn              HTTPEventCode = 2
	GotFirstResponseByte HTTPEventCode = 3
	Got1xxResponse       HTTPEventCode = 4
	DNSStart             HTTPEventCode = 5
	DNSDone              HTTPEventCode = 6
	ConnectStart         HTTPEventCode = 7
	ConnectDone          HTTPEventCode = 8
	TLSHandshakeStart    HTTPEventCode = 9
	TLSHandshakeDone     HTTPEventCode = 10
	WroteHeaders         HTTPEventCode = 11
	WroteRequest         HTTPEventCode = 12
	Wait100Continue      HTTPEventCode = 13
	ClosedBody           HTTPEventCode = 14
)

// CacheCallResult represents the result of a cache operation.
type CacheCallResult uint8

const (
	CacheOK        CacheCallResult = 1
	CacheNoSuchKey CacheCallResult = 2
	CacheConflict  CacheCallResult = 3
	CacheErr       CacheCallResult = 4
)

// LogLevel represents log severity levels.
type LogLevel byte

const (
	LevelTrace LogLevel = 0
	LevelDebug LogLevel = 1
	LevelInfo  LogLevel = 2
	LevelWarn  LogLevel = 3
	LevelError LogLevel = 4
)

// LogFieldType represents the type of a log field.
type LogFieldType byte

const (
	ErrField      LogFieldType = 1
	StringField   LogFieldType = 2
	BoolField     LogFieldType = 3
	TimeField     LogFieldType = 4
	DurationField LogFieldType = 5
	UUIDField     LogFieldType = 6
	JSONField     LogFieldType = 7
	IntField      LogFieldType = 8
	UintField     LogFieldType = 9
	Float32Field  LogFieldType = 10
	Float64Field  LogFieldType = 11
)

// TimeAnchor represents a mapping between nanotime() timestamps
// and real-world time.Time instants.
type TimeAnchor struct {
	nano int64
	real time.Time
}

// NewTimeAnchor constructs a new TimeAnchor.
func NewTimeAnchor(nano int64, real time.Time) TimeAnchor {
	return TimeAnchor{nano: nano, real: real}
}

// ToReal converts a nanotime() timestamp to a real-world time.Time instant.
func (ta TimeAnchor) ToReal(nano int64) time.Time {
	return ta.real.Add(time.Duration(nano - ta.nano))
}

// MarshalText marshals the anchor as text. It never fails.
func (ta TimeAnchor) MarshalText() ([]byte, error) {
	nano := strconv.FormatInt(ta.nano, 10)
	return []byte(nano + " " + ta.real.Format(time.RFC3339Nano)), nil
}

// UnmarshalText unmarshals the anchor from text.
func (ta *TimeAnchor) UnmarshalText(text []byte) error {
	a, b, ok := strings.Cut(string(text), " ")
	if !ok {
		return fmt.Errorf("invalid time anchor format: %q", text)
	}
	nano, err := strconv.ParseInt(a, 10, 64)
	if err != nil {
		return err
	}
	real, err := time.Parse(time.RFC3339Nano, b)
	if err != nil {
		return err
	}

	ta.nano = nano
	ta.real = real
	return nil
}
