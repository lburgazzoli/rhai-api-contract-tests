package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func document(t *testing.T, schema map[string]any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"openapi": "3.0.3",
		"info":    map[string]any{"title": "Example", "version": "1"},
		"paths":   map[string]any{},
		"components": map[string]any{"schemas": map[string]any{
			"Value": schema,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidationPreservesPatternsAndSeverities(t *testing.T) {
	for _, tc := range []struct {
		name   string
		schema map[string]any
		code   int
		id     string
		level  int
	}{
		{"lookahead", map[string]any{"type": "string", "pattern": `^(?!private$)[a-z]+$`, "example": "public"}, 0, "", 0},
		{"backreference", map[string]any{"type": "string", "pattern": `^([a-z]+)-\1$`, "example": "ab-ab"}, 0, "", 0},
		{"malformed pattern", map[string]any{"type": "string", "pattern": "["}, 1, "schema-pattern-regex-invalid", 3},
		{"invalid schema", map[string]any{"type": "not-a-type", "pattern": `^(?!private$)[a-z]+$`}, 1, "schema-type-unsupported", 3},
		{"invalid example", map[string]any{"type": "string", "pattern": `^(?!private$)[a-z]+$`, "example": "private"}, 0, "example-violates-schema", 1},
		{"invalid default", map[string]any{"type": "string", "pattern": `^(?!private$)[a-z]+$`, "default": "private"}, 0, "default-violates-schema", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{document(t, tc.schema)}, &stdout, &stderr)
			if code != tc.code || stderr.Len() != 0 {
				t.Fatalf("code=%d want=%d stdout=%s stderr=%s", code, tc.code, &stdout, &stderr)
			}
			var records []finding
			if err := json.Unmarshal(stdout.Bytes(), &records); err != nil {
				t.Fatal(err)
			}
			if tc.id == "" {
				if len(records) != 0 {
					t.Fatalf("unexpected findings: %+v", records)
				}
				return
			}
			for _, record := range records {
				if record.ID == tc.id && record.Level == tc.level {
					return
				}
			}
			t.Fatalf("missing %s at level %d: %+v", tc.id, tc.level, records)
		})
	}
}

func TestExternalReferencesAreRejectedWithoutFetching(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	path := document(t, map[string]any{"$ref": server.URL + "/schema.json"})
	var stdout, stderr bytes.Buffer
	if code := run([]string{path}, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
	if requests != 0 {
		t.Fatalf("external reference was fetched %d times", requests)
	}
}

func TestRegexExecutionTimeoutIsRetainedAsAnError(t *testing.T) {
	owner := &compiler{}
	compiled, err := owner.compile(`^(a+)+$`)
	if err != nil {
		t.Fatal(err)
	}
	compiled.(matcher).pattern.MatchTimeout = time.Nanosecond
	compiled.MatchString(strings.Repeat("a", 64) + "!")
	if owner.matchError == nil {
		t.Fatal("regex timeout must be retained as a tool error")
	}
}

func TestMissingFileAndUsageAreToolErrors(t *testing.T) {
	for _, args := range [][]string{nil, {filepath.Join(t.TempDir(), "missing.json")}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
		}
	}
}
