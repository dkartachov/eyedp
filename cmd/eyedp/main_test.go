package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	addr := freeAddr(t)
	env := map[string]string{"EYEDP_ADDR": addr}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var logs bytes.Buffer
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, func(k string) string { return env[k] }, &logs) }()

	waitHealthy(t, "http://"+addr+"/healthz")

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run returned error after shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after context was cancelled")
	}

	for _, want := range []string{"msg=listening", "msg=request", "msg=\"shutting down\""} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs missing %q:\n%s", want, logs.String())
		}
	}
}

func TestRunInvalidAddr(t *testing.T) {
	env := map[string]string{"EYEDP_ADDR": "not-an-address"}

	err := run(t.Context(), func(k string) string { return env[k] }, &bytes.Buffer{})
	if err == nil {
		t.Fatal("run returned nil error for an invalid address")
	}
}

func TestEnvOr(t *testing.T) {
	env := map[string]string{"SET": "value", "EMPTY": ""}
	getenv := func(k string) string { return env[k] }

	tests := []struct {
		key, want string
	}{
		{"SET", "value"},
		{"EMPTY", "fallback"},
		{"MISSING", "fallback"},
	}
	for _, tt := range tests {
		if got := envOr(getenv, tt.key, "fallback"); got != tt.want {
			t.Errorf("envOr(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

// freeAddr returns a localhost address with a port that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return addr
}

// waitHealthy polls url until it returns 200 OK or the deadline passes.
func waitHealthy(t *testing.T, url string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become healthy", url)
}
