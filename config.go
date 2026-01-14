package main

import (
	"os"
)

// Config holds the configuration for the trace proxy.
type Config struct {
	// ListenAddr is the address to listen on for incoming traces.
	ListenAddr string

	// OTLPEndpoint is the OTLP collector endpoint to export traces to.
	OTLPEndpoint string

	// OTLPInsecure disables TLS for the OTLP connection.
	OTLPInsecure bool
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() Config {
	cfg := Config{
		ListenAddr:   ":4318",
		OTLPEndpoint: "localhost:4317",
		OTLPInsecure: true,
	}

	if addr := os.Getenv("TRACEPROXY_LISTEN_ADDR"); addr != "" {
		cfg.ListenAddr = addr
	}

	if endpoint := os.Getenv("TRACEPROXY_OTLP_ENDPOINT"); endpoint != "" {
		cfg.OTLPEndpoint = endpoint
	}

	if insecure := os.Getenv("TRACEPROXY_OTLP_INSECURE"); insecure == "false" {
		cfg.OTLPInsecure = false
	}

	return cfg
}
